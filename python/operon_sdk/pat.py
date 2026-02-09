from __future__ import annotations

"""PAT-scoped helper functions for Operon client APIs."""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

from .auth.token_provider import decode_token_claims
from .client import (
    HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
    HEADER_OPERON_SIGNATURE,
    HEADER_OPERON_SIGNATURE_ALGO,
    HEADER_OPERON_SIGNATURE_KEY,
    OperonHeaders,
    _base64url_encode,
    _sanitize_operon_headers,
)
from .config import DEFAULT_BASE_URL, DEFAULT_HTTP_TIMEOUT
from .errors import ApiError, TransportError, ValidationError
from .models import (
    Signature,
    SignatureValidationResult,
    Transaction,
    TransactionRequest,
    Workstream,
    WorkstreamInteractionsResponse,
    WorkstreamParticipantsResponse,
    build_key_id,
    canonical_signing_algorithm,
    decode_payload_base64,
    validate_payload_hash_format,
)


@dataclass(slots=True)
class ClientAPIConfig:
    """Base configuration required for PAT-scoped client API calls."""

    base_url: str = DEFAULT_BASE_URL
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    http_client: Optional[httpx.AsyncClient] = None


@dataclass(slots=True)
class WorkstreamDataConfig:
    """Base configuration required for PAT-scoped workstream catalogue calls."""

    base_url: str = DEFAULT_BASE_URL
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    http_client: Optional[httpx.AsyncClient] = None


async def sign_hash_with_pat(
    cfg: ClientAPIConfig,
    pat: str,
    payload_hash: str,
    algorithm: str,
) -> Signature:
    """Sign a payload hash using a PAT and managed keys."""

    pat = pat.strip()
    if not pat:
        raise ValidationError("pat is required")

    payload_hash = payload_hash.strip()
    if not payload_hash:
        raise ValidationError("payload hash is required")
    try:
        validate_payload_hash_format(payload_hash)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    canonical = canonical_signing_algorithm(algorithm)
    if not canonical:
        raise ValidationError(f"unsupported signing algorithm {algorithm}")

    base_url, client, owns = _normalize_client_config(cfg)
    try:
        response = await _request_json(
            client,
            "POST",
            f"{base_url}/v1/dids/self/sign",
            token=pat,
            payload={
                "payloadHash": payload_hash,
                "hashAlgorithm": "SHA-256",
                "algorithm": canonical,
            },
        )

        payload = response.json()
        if not isinstance(payload, dict) or "signature" not in payload:
            raise ValidationError("self sign response missing signature")

        signature = Signature.model_validate(payload["signature"])
        if not signature.key_id.strip():
            claims = decode_token_claims(pat)
            if claims.participant_did:
                signature.key_id = build_key_id(claims.participant_did)
        return signature
    finally:
        if owns:
            await client.aclose()


async def submit_transaction_with_pat(
    cfg: ClientAPIConfig,
    pat: str,
    request: TransactionRequest,
) -> Transaction:
    """Submit a signed transaction using a PAT."""

    if not isinstance(request, TransactionRequest):
        raise ValidationError("request must be TransactionRequest")

    pat = pat.strip()
    if not pat:
        raise ValidationError("pat is required")

    claims = decode_token_claims(pat)
    if not request.workstream_id.strip() and claims.workstream_id:
        request.workstream_id = claims.workstream_id
    if not request.source_did.strip() and claims.participant_did:
        request.source_did = claims.participant_did

    _, payload_hash = request.resolve_payload()
    request.payload_hash = payload_hash

    try:
        request.validate_for_submit()
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    timestamp = request.timestamp or datetime.now(timezone.utc)
    submission: Dict[str, Any] = {
        "correlationId": request.correlation_id,
        "workstreamId": request.workstream_id,
        "interactionId": request.interaction_id,
        "timestamp": timestamp.isoformat(),
        "sourceDid": request.source_did,
        "targetDid": request.target_did,
        "roiClassification": request.roi_classification,
        "roiCost": request.roi_cost,
        "roiTime": request.roi_time,
        "state": request.state,
        "stateId": request.state_id,
        "stateLabel": request.state_label,
        "roiBaseCost": request.roi_base_cost,
        "roiBaseTime": request.roi_base_time,
        "roiCostSaving": request.roi_cost_saving,
        "roiTimeSaving": request.roi_time_saving,
        "signature": request.signature.model_dump(by_alias=True),
        "payloadHash": payload_hash,
        "actorExternalId": request.actor_external_id,
        "actorExternalDisplayName": request.actor_external_display_name,
        "actorExternalSource": request.actor_external_source,
        "assigneeExternalId": request.assignee_external_id,
        "assigneeExternalDisplayName": request.assignee_external_display_name,
        "assigneeExternalSource": request.assignee_external_source,
        "customerId": request.customer_id,
        "workspaceId": request.workspace_id,
        "createdBy": request.created_by,
    }

    if request.label.strip():
        submission["label"] = request.label.strip()

    if request.tags:
        cleaned_tags = [tag.strip() for tag in request.tags if tag.strip()]
        if cleaned_tags:
            submission["tags"] = cleaned_tags

    base_url, client, owns = _normalize_client_config(cfg)
    try:
        response = await _request_json(
            client,
            "POST",
            f"{base_url}/v1/transactions",
            token=pat,
            payload=submission,
        )
        return Transaction.model_validate(response.json())
    finally:
        if owns:
            await client.aclose()


async def validate_signature_with_pat(
    cfg: ClientAPIConfig,
    pat: str,
    payload: bytes,
    headers: OperonHeaders,
) -> SignatureValidationResult:
    """Validate Operon signature headers against payload bytes using PAT auth."""

    pat = pat.strip()
    if not pat:
        raise ValidationError("pat is required")

    sanitized = _sanitize_operon_headers(headers)

    digest = sha256(payload).digest()
    computed_hash = _base64url_encode(digest)
    expected_hash = sanitized[HEADER_OPERON_PAYLOAD_HASH]
    if computed_hash.lower() != expected_hash.lower():
        raise ValidationError(
            f"payload hash mismatch: expected {computed_hash}, got {expected_hash}"
        )

    did = sanitized[HEADER_OPERON_DID]

    base_url, client, owns = _normalize_client_config(cfg)
    try:
        request_headers = {"Authorization": f"Bearer {pat}"}
        request_headers.update(sanitized)
        try:
            response = await client.post(
                f"{base_url}/v1/dids/{quote(did, safe='')}/signature/verify",
                content=payload,
                headers=request_headers,
            )
        except httpx.HTTPError as exc:
            raise TransportError("perform signature validation request", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError.from_response(response)

        return SignatureValidationResult.model_validate(response.json())
    finally:
        if owns:
            await client.aclose()


async def validate_signature_with_pat_from_string(
    cfg: ClientAPIConfig,
    pat: str,
    payload: str,
    headers: OperonHeaders,
) -> SignatureValidationResult:
    """Convenience wrapper around validate_signature_with_pat for text payloads."""

    return await validate_signature_with_pat(cfg, pat, payload.encode(), headers)


async def fetch_workstream(
    cfg: WorkstreamDataConfig,
    pat: str,
    workstream_id: Optional[str] = None,
) -> Workstream:
    """Fetch workstream details using a PAT."""

    base_url, client, owns = _normalize_workstream_config(cfg)
    target_workstream = _resolve_workstream_id_from_pat(pat, workstream_id)

    try:
        response = await _request_json(
            client,
            "GET",
            f"{base_url}/v1/workstreams/{quote(target_workstream, safe='')}",
            token=pat,
        )
        return Workstream.model_validate(response.json())
    finally:
        if owns:
            await client.aclose()


async def fetch_workstream_interactions(
    cfg: WorkstreamDataConfig,
    pat: str,
    workstream_id: Optional[str] = None,
) -> WorkstreamInteractionsResponse:
    """Fetch workstream interactions using a PAT."""

    base_url, client, owns = _normalize_workstream_config(cfg)
    target_workstream = _resolve_workstream_id_from_pat(pat, workstream_id)

    try:
        response = await _request_json(
            client,
            "GET",
            f"{base_url}/v1/workstreams/{quote(target_workstream, safe='')}/interactions",
            token=pat,
        )
        return WorkstreamInteractionsResponse.model_validate(response.json())
    finally:
        if owns:
            await client.aclose()


async def fetch_workstream_participants(
    cfg: WorkstreamDataConfig,
    pat: str,
    workstream_id: Optional[str] = None,
) -> WorkstreamParticipantsResponse:
    """Fetch workstream participants using a PAT."""

    base_url, client, owns = _normalize_workstream_config(cfg)
    target_workstream = _resolve_workstream_id_from_pat(pat, workstream_id)

    try:
        response = await _request_json(
            client,
            "GET",
            f"{base_url}/v1/workstreams/{quote(target_workstream, safe='')}/participants",
            token=pat,
        )
        return WorkstreamParticipantsResponse.model_validate(response.json())
    finally:
        if owns:
            await client.aclose()


def _resolve_workstream_id_from_pat(pat: str, override: Optional[str] = None) -> str:
    pat = pat.strip()
    if not pat:
        raise ValidationError("pat is required")

    if override and override.strip():
        return override.strip()

    claims = decode_token_claims(pat)
    if claims.workstream_id:
        return claims.workstream_id

    raise ValidationError(
        "workstream ID is required: token not scoped to a workstream and no override provided"
    )


async def _request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    token: str,
    payload: Optional[Dict[str, Any]] = None,
) -> httpx.Response:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}

    try:
        response = await client.request(method, url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise TransportError(f"{method} {url}", original=exc) from exc

    if response.status_code >= 400:
        raise ApiError.from_response(response)

    return response


def _normalize_client_config(cfg: ClientAPIConfig) -> tuple[str, httpx.AsyncClient, bool]:
    base_url = (cfg.base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        raise ValidationError(f"invalid base URL: {cfg.base_url}")

    if cfg.http_client:
        return base_url, cfg.http_client, False

    return base_url, httpx.AsyncClient(timeout=cfg.http_timeout), True


def _normalize_workstream_config(cfg: WorkstreamDataConfig) -> tuple[str, httpx.AsyncClient, bool]:
    base_url = (cfg.base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        raise ValidationError(f"invalid base URL: {cfg.base_url}")

    if cfg.http_client:
        return base_url, cfg.http_client, False

    return base_url, httpx.AsyncClient(timeout=cfg.http_timeout), True


__all__ = [
    "ClientAPIConfig",
    "WorkstreamDataConfig",
    "decode_payload_base64",
    "fetch_workstream",
    "fetch_workstream_interactions",
    "fetch_workstream_participants",
    "sign_hash_with_pat",
    "submit_transaction_with_pat",
    "validate_signature_with_pat",
    "validate_signature_with_pat_from_string",
]
