# Changelog

All notable SDK changes are documented in this file.

## v1.3.0 - 2026-02-09

### Go SDK

- Added end-to-end actor and assignee attribution tracking for transactions.
  - `TransactionRequest` now supports:
    - `actorExternalId`, `actorExternalDisplayName`, `actorExternalSource`
    - `assigneeExternalId`, `assigneeExternalDisplayName`, `assigneeExternalSource`
  - `Transaction` response model now exposes the same actor/assignee fields.
- Added legacy ROI compatibility fields to request/response handling:
  - `roiBaseCost`, `roiBaseTime`, `roiCostSaving`, `roiTimeSaving`
- Updated transaction submission payload serialization so all optional context fields are sent when provided:
  - actor/assignee metadata
  - legacy ROI compatibility fields
  - `customerId`, `workspaceId`, `createdBy`
- Added client-side validation:
  - actor source is required when actor id/display name is supplied
  - assignee source is required when assignee id/display name is supplied
  - legacy ROI values cannot be negative
- Refreshed Go documentation samples to align with current API behavior and fields.

### Python SDK

- Upgraded Python SDK to functional parity with Go `v1.3.0`.
- Added full transaction parity fields and validation:
  - actor/assignee attribution (`actorExternal*`, `assigneeExternal*`)
  - ROI compatibility fields (`roiBaseCost`, `roiBaseTime`, `roiCostSaving`, `roiTimeSaving`)
  - workstream/state/context fields (`state`, `stateId`, `stateLabel`, `customerId`, `workspaceId`, `createdBy`)
- Migrated transaction enrichment/caching flows to workstream-era APIs:
  - reference data now loads from `/v1/interactions` and `/v1/participants`
  - workstream APIs use `/v1/workstreams/{workstreamId}/...`
- Added signature utilities and headers parity:
  - `generate_signature_headers`, `validate_signature_headers`
  - PAT variants for signing and validation
- Added PAT helper parity:
  - `sign_hash_with_pat`, `submit_transaction_with_pat`
  - `fetch_workstream`, `fetch_workstream_interactions`, `fetch_workstream_participants`
- Added `validate_session` helper parity for PAT session validation flows.
- Updated Python docs and examples to reflect the current API surface.

### Java SDK

- Upgraded Java SDK to functional parity with Go `v1.3.0`.
- Migrated SDK terminology and endpoints to workstream-era APIs while preserving channel compatibility aliases:
  - reference catalogue now loads from `/v1/interactions` and `/v1/participants`
  - workstream APIs now support `/v1/workstreams/{workstreamId}/...`
- Expanded transaction request/response models with parity fields:
  - actor/assignee attribution (`actorExternal*`, `assigneeExternal*`)
  - state fields (`state`, `stateId`, `stateLabel`)
  - ROI compatibility fields (`roiBaseCost`, `roiBaseTime`, `roiCostSaving`, `roiTimeSaving`)
  - context fields (`customerId`, `workspaceId`, `createdBy`)
- Added client-side validation parity:
  - actor source required when actor id/display is provided
  - assignee source required when assignee id/display is provided
  - legacy ROI values cannot be negative
- Added client workstream and signature parity methods:
  - `getWorkstream`, `getWorkstreamInteractions`, `getWorkstreamParticipants`
  - `generateSignatureHeaders`, `validateSignatureHeaders`
- Added PAT/session parity helpers:
  - `PatHelpers.signHashWithPAT`, `submitTransactionWithPAT`, `validateSignatureWithPAT`
  - `PatHelpers.fetchWorkstream*` helpers
  - `SessionValidator.validateSession`
- Refreshed Java documentation and examples to match the current API behavior.

### Node.js SDK

- Upgraded Node SDK to functional parity with Go `v1.3.0`.
- Migrated transaction/catalog flows to workstream-era APIs while preserving channel aliases:
  - reference data now loads from `/v1/interactions` and `/v1/participants`
  - workstream APIs now support `/v1/workstreams/{workstreamId}/...`
  - `channelId` remains supported as a compatibility alias for `workstreamId`
- Expanded transaction request/response models with parity fields:
  - actor/assignee attribution (`actorExternal*`, `assigneeExternal*`)
  - state fields (`state`, `stateId`, `stateLabel`)
  - ROI compatibility fields (`roiBaseCost`, `roiBaseTime`, `roiCostSaving`, `roiTimeSaving`)
  - context fields (`customerId`, `workspaceId`, `createdBy`)
- Added client-side validation parity:
  - actor source required when actor id/display is provided
  - assignee source required when assignee id/display is provided
  - legacy ROI values cannot be negative
- Added client workstream/signature parity methods:
  - `getWorkstream`, `getWorkstreamInteractions`, `getWorkstreamParticipants`
  - `generateSignatureHeaders`, `validateSignatureHeaders`
- Added PAT/session parity helpers:
  - `signHashWithPAT`, `submitTransactionWithPAT`, `validateSignatureWithPAT`
  - `fetchWorkstream`, `fetchWorkstreamInteractions`, `fetchWorkstreamParticipants`
  - `validateSession`
- Added Node tests for parity surfaces and updated existing suites for workstream-first semantics.
