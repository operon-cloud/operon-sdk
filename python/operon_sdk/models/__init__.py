from __future__ import annotations

"""Pydantic models used throughout the Operon Python SDK."""

from base64 import urlsafe_b64encode
from hashlib import sha256
from typing import List, Optional

from pydantic import BaseModel, Field


class Signature(BaseModel):
    """Digital signature metadata attached to a transaction payload."""

    algorithm: str = Field(default="EdDSA")
    value: str
    key_id: Optional[str] = Field(default=None, alias="keyId")

    model_config = {
        "populate_by_name": True,
    }


class Transaction(BaseModel):
    """Transaction record returned by the Operon API."""

    id: str
    correlation_id: str = Field(alias="correlationId")
    channel_id: str = Field(alias="channelId")
    interaction_id: str = Field(alias="interactionId")
    timestamp: str
    source_did: str = Field(alias="sourceDid")
    target_did: str = Field(alias="targetDid")
    signature: Signature
    payload_hash: str = Field(alias="payloadHash")
    status: str
    label: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    model_config = {
        "populate_by_name": True,
    }


class InteractionSummary(BaseModel):
    """Lightweight description of a configured interaction."""

    id: str
    channel_id: str = Field(alias="channelId")
    source_participant_id: str = Field(alias="sourceParticipantId")
    target_participant_id: str = Field(alias="targetParticipantId")
    source_did: Optional[str] = Field(default=None, alias="sourceDid")
    target_did: Optional[str] = Field(default=None, alias="targetDid")

    model_config = {
        "populate_by_name": True,
    }


class ParticipantSummary(BaseModel):
    """Participant directory entry used when mapping IDs to DIDs."""

    id: str
    did: str


class TransactionRequest(BaseModel):
    """Composable request payload for creating a transaction."""

    correlation_id: str
    interaction_id: str
    channel_id: Optional[str] = None
    source_did: Optional[str] = None
    target_did: Optional[str] = None
    payload_hash: Optional[str] = None
    payload_bytes: Optional[bytes] = None
    signature: Optional[Signature] = None
    label: Optional[str] = None
    tags: Optional[List[str]] = None

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
    }

    @classmethod
    def new(cls, correlation_id: str, interaction_id: str) -> "TransactionRequest":
        """Construct a request with the required identifiers."""
        if not correlation_id.strip():
            raise ValueError("correlation_id is required")
        if not interaction_id.strip():
            raise ValueError("interaction_id is required")
        return cls(correlation_id=correlation_id.strip(), interaction_id=interaction_id.strip())

    def with_channel_id(self, channel_id: str) -> "TransactionRequest":
        self.channel_id = channel_id
        return self

    def with_source_did(self, did: str) -> "TransactionRequest":
        self.source_did = did
        return self

    def with_target_did(self, did: str) -> "TransactionRequest":
        self.target_did = did
        return self

    def with_payload_bytes(self, payload: bytes) -> "TransactionRequest":
        self.payload_bytes = payload
        return self

    def with_payload_hash(self, payload_hash: str) -> "TransactionRequest":
        self.payload_hash = payload_hash
        return self

    def with_signature(self, signature: Signature) -> "TransactionRequest":
        self.signature = signature
        return self

    def compute_payload(self) -> tuple[Optional[bytes], str]:
        """Return optional raw payload bytes and the deterministic hash."""
        if self.payload_bytes:
            digest = sha256(self.payload_bytes).digest()
            encoded_hash = urlsafe_b64encode(digest).decode().rstrip("=")
            if self.payload_hash and self.payload_hash != encoded_hash:
                raise ValueError("provided payload hash does not match payload bytes")
            return self.payload_bytes, encoded_hash
        if self.payload_hash:
            return None, self.payload_hash
        raise ValueError("payload bytes or payload hash must be provided")
