package operon

import (
    "context"
    "encoding/json"
    "fmt"
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

    items := c.registry.Interactions()
    result := make([]InteractionSummary, 0, len(items))
    for _, item := range items {
        result = append(result, InteractionSummary{
            ID:                  item.ID,
            ChannelID:           item.ChannelID,
            SourceParticipantID: item.SourceParticipantID,
            TargetParticipantID: item.TargetParticipantID,
            SourceDID:           item.SourceDID,
            TargetDID:           item.TargetDID,
        })
    }
    return result, nil
}

// Participants returns the cached participant directory (ID -> DID).
func (c *Client) Participants(ctx context.Context) ([]ParticipantSummary, error) {
    if err := c.ensureInitialized(ctx); err != nil {
        return nil, err
    }

    items := c.registry.Participants()
    result := make([]ParticipantSummary, 0, len(items))
    for _, item := range items {
        result = append(result, ParticipantSummary{ID: item.ID, DID: item.DID})
    }
    return result, nil
}

func (c *Client) populateInteractionFields(ctx context.Context, req *TransactionRequest) error {
    if strings.TrimSpace(req.InteractionID) == "" {
        if strings.TrimSpace(req.SourceDID) == "" {
            if did := c.cachedParticipantDID(); did != "" {
                req.SourceDID = did
            }
        }
        return nil
    }

    meta, ok := c.registry.Interaction(strings.TrimSpace(req.InteractionID))
    if !ok {
        if err := c.loadReferenceData(ctx); err != nil {
            return fmt.Errorf("refresh interaction cache: %w", err)
        }
        meta, ok = c.registry.Interaction(strings.TrimSpace(req.InteractionID))
        if !ok {
            return fmt.Errorf("interaction %s not found", req.InteractionID)
        }
    }

    if strings.TrimSpace(req.ChannelID) == "" {
        req.ChannelID = meta.ChannelID
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
        return err
    }

    participants, err := c.fetchParticipants(ctx, token)
    if err != nil {
        return err
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

    return nil
}

func (c *Client) fetchInteractions(ctx context.Context, token string) ([]catalog.Interaction, error) {
    resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, "/v1/interactions", token, nil)
    if err != nil {
        return nil, err
    }
    defer closeSilently(resp)

    if resp.StatusCode >= http.StatusBadRequest {
        apiErr, decodeErr := apierrors.Decode(resp)
        if decodeErr != nil {
            return nil, decodeErr
        }
        return nil, apiErr
    }

    var payload struct {
        Data []struct {
            ID                  string `json:"id"`
            ChannelID           string `json:"channelId"`
            SourceParticipantID string `json:"sourceParticipantId"`
            TargetParticipantID string `json:"targetParticipantId"`
        } `json:"data"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return nil, fmt.Errorf("decode interactions response: %w", err)
    }

    result := make([]catalog.Interaction, 0, len(payload.Data))
    for _, item := range payload.Data {
        result = append(result, catalog.Interaction{
            ID:                  item.ID,
            ChannelID:           item.ChannelID,
            SourceParticipantID: item.SourceParticipantID,
            TargetParticipantID: item.TargetParticipantID,
        })
    }
    return result, nil
}

func (c *Client) fetchParticipants(ctx context.Context, token string) ([]catalog.Participant, error) {
    resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, "/v1/participants", token, nil)
    if err != nil {
        return nil, err
    }
    defer closeSilently(resp)

    if resp.StatusCode >= http.StatusBadRequest {
        apiErr, decodeErr := apierrors.Decode(resp)
        if decodeErr != nil {
            return nil, decodeErr
        }
        return nil, apiErr
    }

    var payload struct {
        Data []struct {
            ID  string `json:"id"`
            DID string `json:"did"`
        } `json:"data"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return nil, fmt.Errorf("decode participants response: %w", err)
    }

    result := make([]catalog.Participant, 0, len(payload.Data))
    for _, item := range payload.Data {
        if item.ID == "" || item.DID == "" {
            continue
        }
        result = append(result, catalog.Participant{ID: item.ID, DID: item.DID})
    }
    return result, nil
}
