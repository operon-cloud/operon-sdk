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

