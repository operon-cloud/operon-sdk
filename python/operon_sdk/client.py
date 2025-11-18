from __future__ import annotations

"""High-level asynchronous client for interacting with Operon APIs."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .auth.token_provider import AccessToken, ClientCredentialsTokenProvider
from .config import OperonConfig
from .errors import ApiError, OperonError, TransportError, ValidationError
from .models import (
    InteractionSummary,
    ParticipantSummary,
    Signature,
    Transaction,
    TransactionRequest,
)

SELF_SIGN_ENDPOINT = "v1/dids/self/sign"
TRANSACTIONS_ENDPOINT = "v1/transactions"
CHANNEL_INTERACTIONS_ENDPOINT = "v1/channels/{channel_id}/interactions"
CHANNEL_PARTICIPANTS_ENDPOINT = "v1/channels/{channel_id}/participants"
logger = logging.getLogger(__name__)


class OperonClient:
    """Convenience wrapper that handles auth, catalog lookups, and transaction submission."""

    def __init__(
        self,
        config: OperonConfig,
        *,
        client: Optional[httpx.AsyncClient] = None,
        token_provider: Optional[ClientCredentialsTokenProvider] = None,
    ) -> None:
        """Initialise the client with optional custom HTTP and token handling."""
        self._config = config
        self._client = client or httpx.AsyncClient(timeout=config.http_timeout)
        self._token_provider = token_provider or ClientCredentialsTokenProvider(
            config, client=self._client
        )
        self._interactions: Optional[List[InteractionSummary]] = None
        self._participants: Optional[List[ParticipantSummary]] = None
        self._catalog_channel_id: Optional[str] = None
        self._catalog_lock = asyncio.Lock()
        self._heartbeat_task: Optional[asyncio.Task[None]] = None
        self._heartbeat_stop: Optional[asyncio.Event] = None

    async def init(self) -> None:
        """Eagerly fetch an access token so authentication errors surface quickly."""
        await self._token_provider.get_token()
        self._start_heartbeat()

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._stop_heartbeat()
        await self._client.aclose()

    async def __aenter__(self) -> "OperonClient":
        """Support usage as an async context manager."""
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Ensure resources are released when the async context exits."""
        await self.aclose()

    async def submit_transaction(self, request: TransactionRequest) -> Transaction:
        """Submit a transaction, auto-populating metadata and signatures when possible."""
        if not isinstance(request, TransactionRequest):
            raise ValidationError("request must be TransactionRequest")

        token = await self._token_provider.get_token()
        self._populate_defaults(request, token)
        if request.interaction_id:
            await self._ensure_catalog(request, token)

        _, payload_hash = request.compute_payload()
        signature = await self._resolve_signature(request, payload_hash, token)
        request.signature = signature

        self._validate_request(request)

        body: Dict[str, Any] = {
            "correlationId": request.correlation_id,
            "channelId": request.channel_id,
            "interactionId": request.interaction_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceDid": request.source_did,
            "targetDid": request.target_did,
            "signature": request.signature.model_dump(by_alias=True),
            "payloadHash": payload_hash,
        }
        if request.label:
            body["label"] = request.label
        if request.tags:
            body["tags"] = request.tags

        try:
            response = await self._client.post(
                self._config.api_url(TRANSACTIONS_ENDPOINT),
                json=body,
                headers={"Authorization": f"Bearer {token.value}"},
            )
        except httpx.HTTPError as exc:
            raise TransportError("failed to submit transaction", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError(response.status_code, await self._extract_error(response))

        return Transaction.model_validate(response.json())

    async def _ensure_catalog(self, request: TransactionRequest, token: AccessToken) -> None:
        channel_id = request.channel_id or token.channel_id
        if not channel_id:
            raise ValidationError("channel_id required to load interaction catalogue")

        async with self._catalog_lock:
            requires_refresh = (
                self._interactions is None
                or self._participants is None
                or self._catalog_channel_id != channel_id
            )
            if requires_refresh:
                await self._refresh_catalog(token, channel_id)
            if self._interactions:
                match = next(
                    (item for item in self._interactions if item.id == request.interaction_id), None
                )
                if match:
                    request.channel_id = request.channel_id or match.channel_id
                    request.source_did = (
                        request.source_did or match.source_did or token.participant_did
                    )
                    request.target_did = request.target_did or match.target_did

    async def _refresh_catalog(self, token: AccessToken, channel_id: str) -> None:
        headers = {"Authorization": f"Bearer {token.value}"}
        interactions_path = CHANNEL_INTERACTIONS_ENDPOINT.format(channel_id=channel_id)
        participants_path = CHANNEL_PARTICIPANTS_ENDPOINT.format(channel_id=channel_id)

        interactions_task = self._client.get(self._config.api_url(interactions_path), headers=headers)
        participants_task = self._client.get(self._config.api_url(participants_path), headers=headers)
        interactions_response, participants_response = await asyncio.gather(
            interactions_task, participants_task
        )

        if interactions_response.status_code >= 400:
            raise ApiError(
                interactions_response.status_code, await self._extract_error(interactions_response)
            )
        if participants_response.status_code >= 400:
            raise ApiError(
                participants_response.status_code, await self._extract_error(participants_response)
            )

        envelope = interactions_response.json()
        participants_envelope = participants_response.json()
        interactions_payload = envelope.get("interactions", [])
        participants_payload = participants_envelope.get("participants", [])

        self._interactions = [
            InteractionSummary.model_validate(item) for item in interactions_payload
        ]
        participants = [
            ParticipantSummary.model_validate(item) for item in participants_payload
        ]
        mapping = {p.id: p.did for p in participants}
        for interaction in self._interactions:
            if interaction.source_participant_id in mapping:
                interaction.source_did = mapping[interaction.source_participant_id]
            if interaction.target_participant_id in mapping:
                interaction.target_did = mapping[interaction.target_participant_id]
        self._participants = participants
        self._catalog_channel_id = channel_id

    async def _resolve_signature(
        self, request: TransactionRequest, payload_hash: str, token: AccessToken
    ) -> Signature:
        if request.signature:
            signature = request.signature
            if not signature.value.strip():
                raise ValidationError("signature value is required")
            if not signature.algorithm.strip():
                signature.algorithm = "EdDSA"
            if not signature.key_id:
                signature.key_id = self._build_key_id(request.source_did or token.participant_did)
            return signature

        if self._config.disable_self_sign:
            raise ValidationError("signature required when self signing disabled")

        body = {
            "payloadHash": payload_hash,
            "hashAlgorithm": "SHA-256",
            "algorithm": "EdDSA",
        }
        try:
            response = await self._client.post(
                self._config.api_url(SELF_SIGN_ENDPOINT),
                json=body,
                headers={"Authorization": f"Bearer {token.value}"},
            )
        except httpx.HTTPError as exc:
            raise TransportError("failed to self sign payload", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError(response.status_code, await self._extract_error(response))

        payload = response.json()
        if "signature" not in payload:
            raise ValidationError("self sign response missing signature")
        signature = Signature.model_validate(payload["signature"])
        signature.key_id = signature.key_id or self._build_key_id(
            request.source_did or token.participant_did
        )
        return signature

    async def _extract_error(self, response: httpx.Response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, dict):
                message = payload.get("message")
                if message:
                    return message
                return json.dumps(payload)
            return str(payload)
        except ValueError:
            return response.text

    def _populate_defaults(self, request: TransactionRequest, token: AccessToken) -> None:
        if not request.channel_id:
            request.channel_id = token.channel_id
        if not request.source_did:
            request.source_did = token.participant_did

    def _validate_request(self, request: TransactionRequest) -> None:
        missing = []
        if not request.channel_id:
            missing.append("channel_id")
        if not request.source_did:
            missing.append("source_did")
        if not request.target_did:
            missing.append("target_did")
        if not request.signature or not request.signature.value:
            missing.append("signature")
        if missing:
            raise ValidationError("missing required fields: " + ", ".join(missing))

    def _build_key_id(self, did: Optional[str]) -> Optional[str]:
        if did and did.strip():
            return f"{did}#keys-1"
        return None

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
        except OperonError as exc:
            logger.warning("session heartbeat failed to obtain token", exc_info=exc)
            return

        try:
            response = await self._client.get(
                url,
                headers={"Authorization": f"Bearer {token.value}"},
                timeout=self._config.session_heartbeat_timeout,
            )
        except httpx.HTTPError as exc:
            logger.warning("session heartbeat request failed", exc_info=exc)
            return

        if response.status_code == 401:
            logger.warning("session heartbeat returned 401; forcing token refresh")
            try:
                await self._token_provider.force_refresh()
            except OperonError as exc:
                logger.warning("token refresh during heartbeat failed", exc_info=exc)
            return

        if response.status_code >= 400:
            logger.warning("session heartbeat unexpected status %s", response.status_code)


__all__ = ["OperonClient"]
