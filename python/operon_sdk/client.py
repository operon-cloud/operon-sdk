from __future__ import annotations

"""High-level asynchronous client for interacting with Operon APIs."""

import asyncio
import logging
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from .auth.token_provider import AccessToken, ClientCredentialsTokenProvider
from .config import OperonConfig
from .errors import ApiError, TransportError, ValidationError
from .models import (
    InteractionSummary,
    ParticipantSummary,
    Signature,
    SignatureValidationResult,
    Transaction,
    TransactionRequest,
    Workstream,
    WorkstreamInteractionsResponse,
    WorkstreamParticipantsResponse,
    build_key_id,
    canonical_signing_algorithm,
)

HEADER_OPERON_DID = "X-Operon-DID"
HEADER_OPERON_PAYLOAD_HASH = "X-Operon-Payload-Hash"
HEADER_OPERON_SIGNATURE = "X-Operon-Signature"
HEADER_OPERON_SIGNATURE_KEY = "X-Operon-Signature-KeyId"
HEADER_OPERON_SIGNATURE_ALGO = "X-Operon-Signature-Alg"

SELF_SIGN_ENDPOINT = "/v1/dids/self/sign"
TRANSACTIONS_ENDPOINT = "/v1/transactions"
INTERACTIONS_ENDPOINT = "/v1/interactions"
PARTICIPANTS_ENDPOINT = "/v1/participants"

logger = logging.getLogger(__name__)

OperonHeaders = Dict[str, str]


class OperonClient:
    """Convenience wrapper that handles auth, catalog lookups, and transaction submission."""

    def __init__(
        self,
        config: OperonConfig,
        *,
        client: Optional[httpx.AsyncClient] = None,
        token_provider: Optional[ClientCredentialsTokenProvider] = None,
    ) -> None:
        self._config = config
        self._client = client or httpx.AsyncClient(timeout=config.http_timeout)
        self._owns_client = client is None
        self._token_provider = token_provider or ClientCredentialsTokenProvider(
            config, client=self._client
        )

        self._reference_lock = asyncio.Lock()
        self._reference_loaded = False
        self._interaction_by_id: Dict[str, InteractionSummary] = {}
        self._participants: List[ParticipantSummary] = []

        self._claims_lock = asyncio.Lock()
        self._participant_did = ""
        self._workstream_id = ""
        self._customer_id = ""
        self._workspace_id = ""
        self._email = ""
        self._name = ""
        self._tenant_ids: List[str] = []
        self._roles: List[str] = []
        self._member_id = ""
        self._session_id = ""
        self._org_id = ""

        self._heartbeat_task: Optional[asyncio.Task[None]] = None
        self._heartbeat_stop: Optional[asyncio.Event] = None

    async def init(self) -> None:
        """Eagerly fetch an access token so auth/config errors surface quickly."""

        await self._token_value()
        self._start_heartbeat()

    async def aclose(self) -> None:
        """Close background tasks and the underlying HTTP client."""

        await self._stop_heartbeat()
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "OperonClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def submit_transaction(self, request: TransactionRequest) -> Transaction:
        """Submit a transaction, auto-populating metadata and signatures when possible."""

        if not isinstance(request, TransactionRequest):
            raise ValidationError("request must be TransactionRequest")

        await self.init()

        await self._populate_interaction_fields(request)

        _, payload_hash = request.resolve_payload()
        request.payload_hash = payload_hash

        token = await self._token_value()

        signature = request.signature
        if not signature.value.strip():
            if self._config.disable_self_sign:
                raise ValidationError(
                    "automatic signing disabled: provide signature manually or enable self signing"
                )
            signature = await self._self_sign(token, payload_hash, self._config.signing_algorithm)

        if not signature.key_id.strip():
            source = request.source_did.strip() or self._participant_did.strip()
            if source:
                signature.key_id = build_key_id(source)

        request.signature = signature

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

        response = await self._authorized_json_request(
            method="POST",
            path=TRANSACTIONS_ENDPOINT,
            token=token,
            payload=submission,
        )

        return Transaction.model_validate(response.json())

    async def interactions(self) -> List[InteractionSummary]:
        """Return cached interaction catalogue (copy)."""

        await self.init()
        await self._ensure_reference_data()
        return [item.model_copy(deep=True) for item in self._interaction_by_id.values()]

    async def participants(self) -> List[ParticipantSummary]:
        """Return cached participants directory (copy)."""

        await self.init()
        await self._ensure_reference_data()
        return [item.model_copy(deep=True) for item in self._participants]

    async def get_workstream(self, workstream_id: Optional[str] = None) -> Workstream:
        """Return workstream details, defaulting to token-scoped workstream."""

        await self.init()
        token = await self._token_value()
        target_workstream = self._resolve_workstream_id(workstream_id)

        response = await self._authorized_json_request(
            method="GET",
            path=f"/v1/workstreams/{quote(target_workstream, safe='')}",
            token=token,
        )
        return Workstream.model_validate(response.json())

    async def get_workstream_interactions(
        self, workstream_id: Optional[str] = None
    ) -> WorkstreamInteractionsResponse:
        """Return interactions available to the target workstream."""

        await self.init()
        token = await self._token_value()
        target_workstream = self._resolve_workstream_id(workstream_id)

        response = await self._authorized_json_request(
            method="GET",
            path=f"/v1/workstreams/{quote(target_workstream, safe='')}/interactions",
            token=token,
        )
        return WorkstreamInteractionsResponse.model_validate(response.json())

    async def get_workstream_participants(
        self, workstream_id: Optional[str] = None
    ) -> WorkstreamParticipantsResponse:
        """Return participants available to the target workstream."""

        await self.init()
        token = await self._token_value()
        target_workstream = self._resolve_workstream_id(workstream_id)

        response = await self._authorized_json_request(
            method="GET",
            path=f"/v1/workstreams/{quote(target_workstream, safe='')}/participants",
            token=token,
        )
        return WorkstreamParticipantsResponse.model_validate(response.json())

    async def generate_signature_headers(
        self, payload: bytes, algorithm: str = ""
    ) -> OperonHeaders:
        """Generate Operon signature headers for the supplied payload bytes."""

        await self.init()

        selected_algorithm = algorithm.strip() or self._config.signing_algorithm
        canonical = canonical_signing_algorithm(selected_algorithm)
        if not canonical:
            raise ValidationError(f"unsupported signing algorithm {selected_algorithm}")

        digest = sha256(payload).digest()
        payload_hash = _base64url_encode(digest)

        token = await self._token_value()
        if self._config.disable_self_sign:
            raise ValidationError(
                "automatic signing disabled: enable self signing to generate headers"
            )

        signature = await self._self_sign(token, payload_hash, canonical)

        did = self._participant_did.strip()
        if not did:
            raise ValidationError("participant DID unavailable on access token")

        key_id = signature.key_id.strip() or build_key_id(did)
        signature_value = signature.value.strip()
        if not signature_value:
            raise ValidationError("signature value missing from signing response")

        signature_algorithm = signature.algorithm.strip() or canonical

        return {
            HEADER_OPERON_DID: did,
            HEADER_OPERON_PAYLOAD_HASH: payload_hash,
            HEADER_OPERON_SIGNATURE: signature_value,
            HEADER_OPERON_SIGNATURE_KEY: key_id,
            HEADER_OPERON_SIGNATURE_ALGO: signature_algorithm,
        }

    async def generate_signature_headers_from_string(
        self, payload: str, algorithm: str = ""
    ) -> OperonHeaders:
        """Convenience wrapper around generate_signature_headers for text payloads."""

        return await self.generate_signature_headers(payload.encode(), algorithm)

    async def validate_signature_headers(
        self, payload: bytes, headers: OperonHeaders
    ) -> SignatureValidationResult:
        """Validate incoming Operon signature headers against payload bytes."""

        await self.init()

        sanitized = _sanitize_operon_headers(headers)

        digest = sha256(payload).digest()
        computed_hash = _base64url_encode(digest)
        expected_hash = sanitized[HEADER_OPERON_PAYLOAD_HASH]
        if computed_hash.lower() != expected_hash.lower():
            raise ValidationError(
                f"payload hash mismatch: expected {computed_hash}, got {expected_hash}"
            )

        token = await self._token_value()
        did = sanitized[HEADER_OPERON_DID]
        path = f"/v1/dids/{quote(did, safe='')}/signature/verify"

        request_headers = {"Authorization": f"Bearer {token}"}
        request_headers.update(sanitized)

        try:
            response = await self._client.post(
                self._config.api_url(path),
                content=payload,
                headers=request_headers,
            )
        except httpx.HTTPError as exc:
            raise TransportError("perform signature validation request", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError.from_response(response)

        return SignatureValidationResult.model_validate(response.json())

    async def validate_signature_headers_from_string(
        self, payload: str, headers: OperonHeaders
    ) -> SignatureValidationResult:
        """Convenience wrapper around validate_signature_headers for text payloads."""

        return await self.validate_signature_headers(payload.encode(), headers)

    async def _token_value(self) -> str:
        token = await self._token_provider.get_token()

        async with self._claims_lock:
            self._participant_did = token.participant_did or self._participant_did
            self._workstream_id = token.workstream_id or self._workstream_id
            self._customer_id = token.customer_id or self._customer_id
            self._workspace_id = token.workspace_id or self._workspace_id
            self._email = token.email or self._email
            self._name = token.name or self._name
            self._tenant_ids = list(token.tenant_ids)
            self._roles = list(token.roles)
            self._member_id = token.member_id or self._member_id
            self._session_id = token.session_id or self._session_id
            self._org_id = token.org_id or self._org_id

        return token.value

    def _resolve_workstream_id(self, override: Optional[str] = None) -> str:
        if override and override.strip():
            return override.strip()
        if self._workstream_id.strip():
            return self._workstream_id.strip()
        raise ValidationError(
            "workstream ID is required: token not scoped to a workstream and no override provided"
        )

    async def _populate_interaction_fields(self, request: TransactionRequest) -> None:
        if not request.workstream_id.strip() and self._workstream_id.strip():
            request.workstream_id = self._workstream_id.strip()

        if not request.interaction_id.strip():
            if not request.source_did.strip() and self._participant_did.strip():
                request.source_did = self._participant_did.strip()
            if not request.workstream_id.strip() and self._workstream_id.strip():
                request.workstream_id = self._workstream_id.strip()
            return

        await self._ensure_reference_data()

        interaction = self._interaction_by_id.get(request.interaction_id.strip())
        if not interaction:
            await self._reload_reference_data()
            interaction = self._interaction_by_id.get(request.interaction_id.strip())

        if not interaction:
            raise ValidationError(f"interaction {request.interaction_id} not found")

        if not request.workstream_id.strip():
            if interaction.workstream_id.strip():
                request.workstream_id = interaction.workstream_id.strip()
            elif self._workstream_id.strip():
                request.workstream_id = self._workstream_id.strip()

        if not request.source_did.strip():
            if not interaction.source_did.strip():
                raise ValidationError(f"interaction {request.interaction_id} missing source DID")
            request.source_did = interaction.source_did.strip()

        if not request.target_did.strip():
            if not interaction.target_did.strip():
                raise ValidationError(f"interaction {request.interaction_id} missing target DID")
            request.target_did = interaction.target_did.strip()

        if not request.source_did.strip() and self._participant_did.strip():
            request.source_did = self._participant_did.strip()

    async def _ensure_reference_data(self) -> None:
        if self._reference_loaded:
            return
        await self._reload_reference_data()

    async def _reload_reference_data(self) -> None:
        async with self._reference_lock:
            token = await self._token_value()
            interactions = await self._fetch_interactions(token)
            participants = await self._fetch_participants(token)

            did_by_id = {item.id: item.did for item in participants if item.id and item.did}
            hydrated: Dict[str, InteractionSummary] = {}
            for interaction in interactions:
                interaction_copy = interaction.model_copy(deep=True)
                if not interaction_copy.source_did and interaction_copy.source_participant_id in did_by_id:
                    interaction_copy.source_did = did_by_id[interaction_copy.source_participant_id]
                if not interaction_copy.target_did and interaction_copy.target_participant_id in did_by_id:
                    interaction_copy.target_did = did_by_id[interaction_copy.target_participant_id]
                hydrated[interaction_copy.id] = interaction_copy

            self._interaction_by_id = hydrated
            self._participants = [item.model_copy(deep=True) for item in participants]
            self._reference_loaded = True

    async def _fetch_interactions(self, token: str) -> List[InteractionSummary]:
        response = await self._authorized_json_request(
            method="GET",
            path=INTERACTIONS_ENDPOINT,
            token=token,
        )

        payload = response.json()
        data = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(data, list):
            return []

        return [InteractionSummary.model_validate(item) for item in data]

    async def _fetch_participants(self, token: str) -> List[ParticipantSummary]:
        response = await self._authorized_json_request(
            method="GET",
            path=PARTICIPANTS_ENDPOINT,
            token=token,
        )

        payload = response.json()
        data = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(data, list):
            return []

        participants: List[ParticipantSummary] = []
        for item in data:
            participant = ParticipantSummary.model_validate(item)
            if participant.id and participant.did:
                participants.append(participant)
        return participants

    async def _self_sign(self, token: str, payload_hash: str, algorithm: str) -> Signature:
        body = {
            "payloadHash": payload_hash,
            "hashAlgorithm": "SHA-256",
            "algorithm": algorithm,
        }

        response = await self._authorized_json_request(
            method="POST",
            path=SELF_SIGN_ENDPOINT,
            token=token,
            payload=body,
        )

        payload = response.json()
        if not isinstance(payload, dict) or "signature" not in payload:
            raise ValidationError("self sign response missing signature")

        signature = Signature.model_validate(payload["signature"])
        if not signature.key_id.strip() and self._participant_did.strip():
            signature.key_id = build_key_id(self._participant_did)
        return signature

    async def _authorized_json_request(
        self,
        *,
        method: str,
        path: str,
        token: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            response = await self._client.request(
                method,
                self._config.api_url(path),
                json=payload,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise TransportError(f"{method} {path}", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError.from_response(response)

        return response

    def _start_heartbeat(self) -> None:
        if (
            self._config.session_heartbeat_interval <= 0
            or not self._config.session_heartbeat_url
            or self._heartbeat_task
        ):
            return

        self._heartbeat_stop = asyncio.Event()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def _stop_heartbeat(self) -> None:
        task = self._heartbeat_task
        if not task:
            return

        if self._heartbeat_stop:
            self._heartbeat_stop.set()

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            self._heartbeat_task = None
            self._heartbeat_stop = None

    async def _heartbeat_loop(self) -> None:
        assert self._heartbeat_stop is not None
        interval = self._config.session_heartbeat_interval

        try:
            while not self._heartbeat_stop.is_set():
                await self._perform_heartbeat()
                try:
                    await asyncio.wait_for(self._heartbeat_stop.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            raise

    async def _perform_heartbeat(self) -> None:
        url = self._config.session_heartbeat_url
        if not url:
            return

        try:
            token = await self._token_provider.get_token()
        except Exception as exc:  # noqa: BLE001
            logger.warning("session heartbeat failed to obtain token", exc_info=exc)
            return

        try:
            response = await self._client.get(
                url,
                headers={"Authorization": f"Bearer {token.value}"},
                timeout=self._config.session_heartbeat_timeout or None,
            )
        except httpx.HTTPError as exc:
            logger.warning("session heartbeat request failed", exc_info=exc)
            return

        if response.status_code == 401:
            logger.warning("session heartbeat returned 401; forcing token refresh")
            try:
                await self._token_provider.force_refresh()
            except Exception as exc:  # noqa: BLE001
                logger.warning("token refresh during heartbeat failed", exc_info=exc)
            return

        if response.status_code >= 400:
            logger.warning("session heartbeat unexpected status %s", response.status_code)


def _base64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sanitize_operon_headers(headers: OperonHeaders) -> Dict[str, str]:
    if not headers:
        raise ValidationError("operon headers cannot be nil")

    required = [
        HEADER_OPERON_DID,
        HEADER_OPERON_PAYLOAD_HASH,
        HEADER_OPERON_SIGNATURE,
        HEADER_OPERON_SIGNATURE_KEY,
        HEADER_OPERON_SIGNATURE_ALGO,
    ]

    sanitized: Dict[str, str] = {}
    for key in required:
        value = (headers.get(key) or "").strip()
        if not value:
            raise ValidationError(f"header {key} is required")
        sanitized[key] = value

    return sanitized


__all__ = [
    "HEADER_OPERON_DID",
    "HEADER_OPERON_PAYLOAD_HASH",
    "HEADER_OPERON_SIGNATURE",
    "HEADER_OPERON_SIGNATURE_ALGO",
    "HEADER_OPERON_SIGNATURE_KEY",
    "OperonClient",
    "OperonHeaders",
]
