package operon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/catalog"
)

// Interactions returns the cached interaction catalogue. It performs lazy
// initialisation if required and returns a copy so callers can mutate safely.
func (c *Client) Interactions(ctx context.Context) ([]InteractionSummary, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	if err := c.ensureReferenceData(ctx); err != nil {
		return nil, err
	}

	items := c.registry.Interactions()
	result := make([]InteractionSummary, 0, len(items))
	for _, item := range items {
		result = append(result, InteractionSummary{
			ID:                  item.ID,
			WorkstreamID:        item.WorkstreamID,
			SourceParticipantID: item.SourceParticipantID,
			TargetParticipantID: item.TargetParticipantID,
			SourceDID:           item.SourceDID,
			TargetDID:           item.TargetDID,
			Type:                InteractionType(item.Type),
			Actor:               InteractionActor(item.Actor),
			States:              append([]string(nil), item.States...),
			ROIClassification:   ROIClassification(item.ROIClassification),
			ROICost:             item.ROICost,
			ROITime:             item.ROITime,
		})
	}
	return result, nil
}

// Participants returns the cached participant directory (ID -> DID).
func (c *Client) Participants(ctx context.Context) ([]ParticipantSummary, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	if err := c.ensureReferenceData(ctx); err != nil {
		return nil, err
	}

	items := c.registry.Participants()
	result := make([]ParticipantSummary, 0, len(items))
	for _, item := range items {
		result = append(result, ParticipantSummary{
			ID:           item.ID,
			DID:          item.DID,
			Name:         item.Name,
			Status:       item.Status,
			CustomerID:   item.CustomerID,
			WorkstreamID: item.WorkstreamID,
		})
	}
	return result, nil
}

func (c *Client) ensureReferenceData(ctx context.Context) error {
	c.referenceMu.Lock()
	loaded := c.referenceLoaded
	c.referenceMu.Unlock()

	if loaded {
		log.Printf("[operon-sdk] reference data already loaded (cached)")
		return nil
	}

	log.Printf("[operon-sdk] reference data cache empty, reloading")
	return c.reloadReferenceData(ctx)
}

func (c *Client) reloadReferenceData(ctx context.Context) error {
	c.referenceMu.Lock()
	defer c.referenceMu.Unlock()

	log.Printf("[operon-sdk] refreshing reference data cache")
	if err := c.loadReferenceData(ctx); err != nil {
		log.Printf("[operon-sdk] failed to load reference data: %v", err)
		return err
	}
	c.referenceLoaded = true
	log.Printf("[operon-sdk] reference data cache populated")
	return nil
}

func (c *Client) populateInteractionFields(ctx context.Context, req *TransactionRequest) error {
	if strings.TrimSpace(req.WorkstreamID) == "" {
		if workstream := c.cachedWorkstreamID(); workstream != "" {
			req.WorkstreamID = workstream
		}
	}

	if strings.TrimSpace(req.InteractionID) == "" {
		if strings.TrimSpace(req.SourceDID) == "" {
			if did := c.cachedParticipantDID(); did != "" {
				req.SourceDID = did
			}
		}

		if strings.TrimSpace(req.WorkstreamID) == "" {
			if workstream := c.cachedWorkstreamID(); workstream != "" {
				req.WorkstreamID = workstream
			}
		}
		return nil
	}

	meta, ok := c.registry.Interaction(strings.TrimSpace(req.InteractionID))
	if !ok {
		log.Printf("[operon-sdk] interaction %s not found in cache; triggering reload", req.InteractionID)
		if err := c.reloadReferenceData(ctx); err != nil {
			return fmt.Errorf("refresh interaction cache: %w", err)
		}
		meta, ok = c.registry.Interaction(strings.TrimSpace(req.InteractionID))
		if !ok {
			log.Printf("[operon-sdk] interaction %s still missing after cache refresh", req.InteractionID)
			return fmt.Errorf("interaction %s not found", req.InteractionID)
		}
	}

	log.Printf("[operon-sdk] resolving interaction %s (workstream %s, sourceParticipant %s, targetParticipant %s)", req.InteractionID, meta.WorkstreamID, meta.SourceParticipantID, meta.TargetParticipantID)
	if strings.TrimSpace(req.WorkstreamID) == "" {
		if meta.WorkstreamID != "" {
			req.WorkstreamID = meta.WorkstreamID
		} else if workstream := c.cachedWorkstreamID(); workstream != "" {
			req.WorkstreamID = workstream
		}
	}
	if strings.TrimSpace(req.SourceDID) == "" {
		if meta.SourceDID == "" {
			return fmt.Errorf("interaction %s missing source DID", req.InteractionID)
		}
		req.SourceDID = meta.SourceDID
	}
	if strings.TrimSpace(req.TargetDID) == "" {
		if meta.TargetDID == "" {
			return fmt.Errorf("interaction %s missing target DID", req.InteractionID)
		}
		req.TargetDID = meta.TargetDID
	}

	if strings.TrimSpace(req.SourceDID) == "" {
		if did := c.cachedParticipantDID(); did != "" {
			req.SourceDID = did
		}
	}

	return nil
}

func (c *Client) loadReferenceData(ctx context.Context) error {
	token, err := c.tokenValue(ctx)
	if err != nil {
		return err
	}

	interactions, err := c.fetchInteractions(ctx, token)
	if err != nil {
		log.Printf("[operon-sdk] fetchInteractions failed: %v", err)
		return err
	}

	participants, err := c.fetchParticipants(ctx, token)
	if err != nil {
		log.Printf("[operon-sdk] fetchParticipants failed: %v", err)
		return err
	}

	if len(interactions) > 0 {
		details := make([]string, 0, len(interactions))
		for _, item := range interactions {
			details = append(details, fmt.Sprintf("%s(workstream=%s, sourceParticipant=%s, targetParticipant=%s)", item.ID, item.WorkstreamID, item.SourceParticipantID, item.TargetParticipantID))
		}
		log.Printf("[operon-sdk] fetched %d interactions: %s", len(interactions), strings.Join(details, "; "))
	} else {
		log.Printf("[operon-sdk] fetched 0 interactions")
	}

	if len(participants) > 0 {
		details := make([]string, 0, len(participants))
		for _, item := range participants {
			details = append(details, fmt.Sprintf("%s(%s)", item.ID, item.DID))
		}
		log.Printf("[operon-sdk] fetched %d participants: %s", len(participants), strings.Join(details, "; "))
	} else {
		log.Printf("[operon-sdk] fetched 0 participants")
	}
	dids := make(map[string]string, len(participants))
	for _, p := range participants {
		if p.ID != "" && p.DID != "" {
			dids[p.ID] = p.DID
		}
	}

	for idx := range interactions {
		if did, ok := dids[interactions[idx].SourceParticipantID]; ok {
			interactions[idx].SourceDID = did
		}
		if did, ok := dids[interactions[idx].TargetParticipantID]; ok {
			interactions[idx].TargetDID = did
		}
	}

	c.registry.ReplaceInteractions(interactions)
	c.registry.ReplaceParticipants(participants)
	log.Printf("[operon-sdk] registry populated with %d interactions, %d participants", len(interactions), len(participants))

	return nil
}

func (c *Client) fetchInteractions(ctx context.Context, token string) ([]catalog.Interaction, error) {
	log.Printf("[operon-sdk] requesting /v1/interactions")
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, "/v1/interactions", token, nil)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		log.Printf("[operon-sdk] /v1/interactions returned status %d", resp.StatusCode)
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var payload struct {
		Data []struct {
			ID                  string                    `json:"id"`
			WorkstreamID        string                    `json:"channelId"`
			SourceParticipantID string                    `json:"sourceParticipantId"`
			TargetParticipantID string                    `json:"targetParticipantId"`
			Type                catalog.InteractionType   `json:"type"`
			Actor               catalog.InteractionActor  `json:"actor"`
			States              []string                  `json:"states"`
			ROIClassification   catalog.ROIClassification `json:"roiClassification"`
			ROICost             int                       `json:"roiCost"`
			ROITime             int                       `json:"roiTime"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode interactions response: %w", err)
	}

	log.Printf("[operon-sdk] /v1/interactions returned %d records", len(payload.Data))
	result := make([]catalog.Interaction, 0, len(payload.Data))
	for _, item := range payload.Data {
		result = append(result, catalog.Interaction{
			ID:                  item.ID,
			WorkstreamID:        item.WorkstreamID,
			SourceParticipantID: item.SourceParticipantID,
			TargetParticipantID: item.TargetParticipantID,
			Type:                item.Type,
			Actor:               item.Actor,
			States:              append([]string(nil), item.States...),
			ROIClassification:   item.ROIClassification,
			ROICost:             item.ROICost,
			ROITime:             item.ROITime,
		})
	}
	return result, nil
}

func (c *Client) fetchParticipants(ctx context.Context, token string) ([]catalog.Participant, error) {
	log.Printf("[operon-sdk] requesting /v1/participants")
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, "/v1/participants", token, nil)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		log.Printf("[operon-sdk] /v1/participants returned status %d", resp.StatusCode)
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var payload struct {
		Data []struct {
			ID           string `json:"id"`
			DID          string `json:"did"`
			Name         string `json:"name"`
			Status       string `json:"status"`
			CustomerID   string `json:"customerId"`
			WorkstreamID string `json:"channelId"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode participants response: %w", err)
	}

	log.Printf("[operon-sdk] /v1/participants returned %d records", len(payload.Data))
	result := make([]catalog.Participant, 0, len(payload.Data))
	for _, item := range payload.Data {
		if item.ID == "" || item.DID == "" {
			continue
		}
		result = append(result, catalog.Participant{
			ID:           item.ID,
			DID:          item.DID,
			Name:         item.Name,
			Status:       item.Status,
			CustomerID:   item.CustomerID,
			WorkstreamID: item.WorkstreamID,
		})
	}
	return result, nil
}
