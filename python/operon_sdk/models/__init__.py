from __future__ import annotations

"""Pydantic models and validation helpers for the Operon Python SDK."""

from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

ALGORITHM_ED25519 = "EdDSA"
ALGORITHM_ES256 = "ES256"
ALGORITHM_ES256K = "ES256K"

ROI_CLASSIFICATION_BASELINE = "baseline"
ROI_CLASSIFICATION_INCREMENT = "increment"
ROI_CLASSIFICATION_SAVINGS = "savings"

INTERACTION_TYPE_TOUCH = "touch"
INTERACTION_TYPE_TRANSITION = "transition"
INTERACTION_TYPE_TRANSFER = "transfer"

INTERACTION_ACTOR_HUMAN = "human"
INTERACTION_ACTOR_AI = "ai"
INTERACTION_ACTOR_HYBRID = "hybrid"
INTERACTION_ACTOR_NON_AI = "non-ai"

WORKSTREAM_STATUS_DRAFT = "draft"
WORKSTREAM_STATUS_ACTIVE = "active"
WORKSTREAM_STATUS_INACTIVE = "inactive"
WORKSTREAM_STATUS_ARCHIVED = "archived"

WORKSTREAM_MODE_OFF = "off"
WORKSTREAM_MODE_ON = "on"

WORKSTREAM_TYPE_INTERNAL = "internal"
WORKSTREAM_TYPE_PRODUCTION = "production"

WORKSTREAM_STATE_STATUS_ACTIVE = "active"
WORKSTREAM_STATE_STATUS_INACTIVE = "inactive"

SIGNING_ALGORITHMS = [ALGORITHM_ED25519, ALGORITHM_ES256, ALGORITHM_ES256K]
ROI_CLASSIFICATIONS = [
    ROI_CLASSIFICATION_BASELINE,
    ROI_CLASSIFICATION_INCREMENT,
    ROI_CLASSIFICATION_SAVINGS,
]


class Signature(BaseModel):
    """Digital signature metadata attached to transaction and signing flows."""

    algorithm: str = Field(default="", alias="algorithm")
    value: str = Field(default="", alias="value")
    key_id: str = Field(default="", alias="keyId")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class Transaction(BaseModel):
    """Transaction record returned by Operon APIs."""

    id: str
    correlation_id: str = Field(alias="correlationId")
    workstream_id: str = Field(alias="workstreamId")
    workstream_name: str = Field(default="", alias="workstreamName")
    customer_id: str = Field(default="", alias="customerId")
    workspace_id: str = Field(default="", alias="workspaceId")
    interaction_id: str = Field(alias="interactionId")
    timestamp: Optional[datetime] = None
    source_did: str = Field(alias="sourceDid")
    target_did: str = Field(alias="targetDid")
    state: str = ""
    state_id: str = Field(default="", alias="stateId")
    state_label: str = Field(default="", alias="stateLabel")

    roi_classification: str = Field(default="", alias="roiClassification")
    roi_cost_increment: int = Field(default=0, alias="roiCostIncrement")
    roi_time_increment: int = Field(default=0, alias="roiTimeIncrement")
    roi_cost_savings: int = Field(default=0, alias="roiCostSavings")
    roi_time_savings: int = Field(default=0, alias="roiTimeSavings")

    roi_base_cost: int = Field(default=0, alias="roiBaseCost")
    roi_base_time: int = Field(default=0, alias="roiBaseTime")
    roi_cost_saving: int = Field(default=0, alias="roiCostSaving")
    roi_time_saving: int = Field(default=0, alias="roiTimeSaving")

    signature: Signature
    label: str = ""
    tags: List[str] = Field(default_factory=list)
    payload_hash: str = Field(alias="payloadHash")

    actor_external_id: str = Field(default="", alias="actorExternalId")
    actor_external_display_name: str = Field(default="", alias="actorExternalDisplayName")
    actor_external_source: str = Field(default="", alias="actorExternalSource")

    assignee_external_id: str = Field(default="", alias="assigneeExternalId")
    assignee_external_display_name: str = Field(default="", alias="assigneeExternalDisplayName")
    assignee_external_source: str = Field(default="", alias="assigneeExternalSource")

    status: str = ""
    hcs_topic_id: str = Field(default="", alias="hcsTopicId")
    hcs_sequence_number: int = Field(default=0, alias="hcsSequenceNumber")
    hcs_consensus_timestamp: str = Field(default="", alias="hcsConsensusTimestamp")
    hcs_transaction_id: str = Field(default="", alias="hcsTransactionId")
    hcs_running_hash: str = Field(default="", alias="hcsRunningHash")

    created_at: Optional[datetime] = Field(default=None, alias="createdAt")
    updated_at: Optional[datetime] = Field(default=None, alias="updatedAt")
    created_by: str = Field(default="", alias="createdBy")
    updated_by: str = Field(default="", alias="updatedBy")
    version: int = 0

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class TransactionRequest(BaseModel):
    """Composable request payload for creating a transaction."""

    correlation_id: str = Field(default="", alias="correlationId")
    workstream_id: str = Field(default="", alias="workstreamId")
    interaction_id: str = Field(default="", alias="interactionId")
    timestamp: Optional[datetime] = None
    source_did: str = Field(default="", alias="sourceDid")
    target_did: str = Field(default="", alias="targetDid")

    roi_classification: str = Field(default="", alias="roiClassification")
    roi_cost: int = Field(default=0, alias="roiCost")
    roi_time: int = Field(default=0, alias="roiTime")

    state: str = ""
    state_id: str = Field(default="", alias="stateId")
    state_label: str = Field(default="", alias="stateLabel")

    roi_base_cost: int = Field(default=0, alias="roiBaseCost")
    roi_base_time: int = Field(default=0, alias="roiBaseTime")
    roi_cost_saving: int = Field(default=0, alias="roiCostSaving")
    roi_time_saving: int = Field(default=0, alias="roiTimeSaving")

    signature: Signature = Field(default_factory=Signature)
    label: str = ""
    tags: List[str] = Field(default_factory=list)

    payload: bytes = Field(default=b"", exclude=True)
    payload_hash: str = Field(default="", alias="payloadHash")

    actor_external_id: str = Field(default="", alias="actorExternalId")
    actor_external_display_name: str = Field(default="", alias="actorExternalDisplayName")
    actor_external_source: str = Field(default="", alias="actorExternalSource")

    assignee_external_id: str = Field(default="", alias="assigneeExternalId")
    assignee_external_display_name: str = Field(default="", alias="assigneeExternalDisplayName")
    assignee_external_source: str = Field(default="", alias="assigneeExternalSource")

    customer_id: str = Field(default="", alias="customerId")
    workspace_id: str = Field(default="", alias="workspaceId")
    created_by: str = Field(default="", alias="createdBy")

    model_config = ConfigDict(populate_by_name=True, extra="ignore", arbitrary_types_allowed=True)

    @property
    def channel_id(self) -> str:
        """Backward-compatibility alias for legacy callers."""
        return self.workstream_id

    @channel_id.setter
    def channel_id(self, value: str) -> None:
        self.workstream_id = value

    @classmethod
    def new(cls, correlation_id: str, interaction_id: str) -> "TransactionRequest":
        if not correlation_id.strip():
            raise ValueError("correlation_id is required")
        if not interaction_id.strip():
            raise ValueError("interaction_id is required")
        return cls(correlation_id=correlation_id.strip(), interaction_id=interaction_id.strip())

    def with_workstream_id(self, workstream_id: str) -> "TransactionRequest":
        self.workstream_id = workstream_id
        return self

    def with_channel_id(self, channel_id: str) -> "TransactionRequest":
        self.workstream_id = channel_id
        return self

    def with_source_did(self, did: str) -> "TransactionRequest":
        self.source_did = did
        return self

    def with_target_did(self, did: str) -> "TransactionRequest":
        self.target_did = did
        return self

    def with_payload_bytes(self, payload: bytes) -> "TransactionRequest":
        self.payload = payload
        return self

    def with_payload_hash(self, payload_hash: str) -> "TransactionRequest":
        self.payload_hash = payload_hash
        return self

    def with_signature(self, signature: Signature) -> "TransactionRequest":
        self.signature = signature
        return self

    def compute_payload(self) -> Tuple[Optional[str], str]:
        """Return (base64 payload, payloadHash)."""
        return self.resolve_payload()

    def resolve_payload(self) -> Tuple[Optional[str], str]:
        payload_hash = self.payload_hash.strip()
        if self.payload:
            encoded_payload = b64encode(self.payload).decode("utf-8")
            digest = sha256(self.payload).digest()
            computed_hash = urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
            if payload_hash and payload_hash.lower() != computed_hash.lower():
                raise ValueError(
                    "provided payload hash does not match payload content: "
                    f"expected {computed_hash} got {payload_hash}"
                )
            return encoded_payload, computed_hash

        if not payload_hash:
            raise ValueError("payload bytes or payload hash is required")
        validate_payload_hash_format(payload_hash)
        return None, payload_hash

    def validate_for_submit(self) -> None:
        if not self.correlation_id.strip():
            raise ValueError("CorrelationID is required")
        if not self.workstream_id.strip():
            raise ValueError("WorkstreamID is required")
        if not self.interaction_id.strip():
            raise ValueError("InteractionID is required")
        if not self.source_did.strip():
            raise ValueError("SourceDID is required")
        if not self.source_did.strip().startswith("did:"):
            raise ValueError("SourceDID must be a valid DID")
        if not self.target_did.strip():
            raise ValueError("TargetDID is required")
        if not self.target_did.strip().startswith("did:"):
            raise ValueError("TargetDID must be a valid DID")

        if not self.payload and not self.payload_hash.strip():
            raise ValueError("payload bytes or payload hash is required")

        if not self.signature.algorithm.strip():
            raise ValueError("Signature algorithm is required")
        if not self.signature.value.strip():
            raise ValueError("Signature value is required")

        if self.roi_classification and not is_roi_classification(self.roi_classification):
            raise ValueError("ROIClassification must be one of baseline, increment, savings")

        if self.roi_base_cost < 0:
            raise ValueError("ROIBaseCost cannot be negative")
        if self.roi_base_time < 0:
            raise ValueError("ROIBaseTime cannot be negative")
        if self.roi_cost_saving < 0:
            raise ValueError("ROICostSaving cannot be negative")
        if self.roi_time_saving < 0:
            raise ValueError("ROITimeSaving cannot be negative")

        if (
            not self.actor_external_source.strip()
            and (self.actor_external_id.strip() or self.actor_external_display_name.strip())
        ):
            raise ValueError(
                "ActorExternalSource is required when ActorExternalID or ActorExternalDisplayName is set"
            )

        if (
            not self.assignee_external_source.strip()
            and (self.assignee_external_id.strip() or self.assignee_external_display_name.strip())
        ):
            raise ValueError(
                "AssigneeExternalSource is required when AssigneeExternalID or "
                "AssigneeExternalDisplayName is set"
            )


class WorkstreamState(BaseModel):
    id: str
    name: str
    status: str = ""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class Workstream(BaseModel):
    id: str
    created_at: Optional[datetime] = Field(default=None, alias="createdAt")
    updated_at: Optional[datetime] = Field(default=None, alias="updatedAt")
    created_by: str = Field(default="", alias="createdBy")
    updated_by: str = Field(default="", alias="updatedBy")
    version: int = 0
    customer_id: str = Field(default="", alias="customerId")
    workspace_id: str = Field(default="", alias="workspaceId")
    name: str = ""
    description: str = ""
    mode: str = ""
    type: str = ""
    status: str = ""
    states: List[WorkstreamState] = Field(default_factory=list)
    default_state_id: str = Field(default="", alias="defaultStateId")
    interaction_ids: List[str] = Field(default_factory=list, alias="interactionIds")
    hcs_test_topic_id: str = Field(default="", alias="hcsTestTopicId")
    hcs_live_topic_id: str = Field(default="", alias="hcsLiveTopicId")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class InteractionSummary(BaseModel):
    id: str
    workstream_id: str = Field(default="", alias="workstreamId")
    workstream_name: str = Field(default="", alias="workstreamName")
    name: str = ""
    description: str = ""
    status: str = ""
    source_participant_id: str = Field(default="", alias="sourceParticipantId")
    target_participant_id: str = Field(default="", alias="targetParticipantId")
    source_did: str = Field(default="", alias="sourceDid")
    target_did: str = Field(default="", alias="targetDid")
    type: str = ""
    actor: str = ""
    states: List[str] = Field(default_factory=list)
    roi_classification: str = Field(default="", alias="roiClassification")
    roi_cost: int = Field(default=0, alias="roiCost")
    roi_time: int = Field(default=0, alias="roiTime")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class ParticipantSummary(BaseModel):
    id: str
    did: str
    name: str = ""
    status: str = ""
    customer_id: str = Field(default="", alias="customerId")
    workstream_id: str = Field(default="", alias="workstreamId")
    workstream_name: str = Field(default="", alias="workstreamName")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class WorkstreamInteraction(BaseModel):
    id: str
    workstream_id: str = Field(alias="workstreamId")
    workstream_name: str = Field(default="", alias="workstreamName")
    name: str = ""
    description: str = ""
    status: str = ""
    source_participant_id: str = Field(default="", alias="sourceParticipantId")
    target_participant_id: str = Field(default="", alias="targetParticipantId")
    workstreams: List[str] = Field(default_factory=list)
    type: str = ""
    actor: str = ""
    states: List[str] = Field(default_factory=list)
    roi_classification: str = Field(default="", alias="roiClassification")
    roi_cost: int = Field(default=0, alias="roiCost")
    roi_time: int = Field(default=0, alias="roiTime")
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = Field(default=None, alias="createdAt")
    updated_at: Optional[datetime] = Field(default=None, alias="updatedAt")
    version: int = 0

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class WorkstreamInteractionsResponse(BaseModel):
    interactions: List[WorkstreamInteraction] = Field(default_factory=list)
    total_count: int = Field(default=0, alias="totalCount")
    page: int = 0
    page_size: int = Field(default=0, alias="pageSize")
    has_more: bool = Field(default=False, alias="hasMore")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class WorkstreamParticipant(BaseModel):
    id: str
    did: str
    name: str = ""
    description: str = ""
    url: str = ""
    status: str = ""
    type: str = ""
    customer_id: str = Field(default="", alias="customerId")
    workstream_id: str = Field(default="", alias="workstreamId")
    workstream_name: str = Field(default="", alias="workstreamName")
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = Field(default=None, alias="createdAt")
    updated_at: Optional[datetime] = Field(default=None, alias="updatedAt")
    version: int = 0

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class WorkstreamParticipantsResponse(BaseModel):
    participants: List[WorkstreamParticipant] = Field(default_factory=list)
    total_count: int = Field(default=0, alias="totalCount")
    page: int = 0
    page_size: int = Field(default=0, alias="pageSize")
    has_more: bool = Field(default=False, alias="hasMore")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class SignatureValidationResult(BaseModel):
    status: str = ""
    message: str = ""
    did: str = ""
    payload_hash: str = Field(default="", alias="payloadHash")
    algorithm: str = ""
    key_id: str = Field(default="", alias="keyId")

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


@dataclass(slots=True)
class SessionInfo:
    user_id: str
    email: str
    name: str
    customer_id: str
    roles: List[str]
    feature_flags: Dict[str, Any]
    workstream_id: str
    workspace_id: str
    participant_did: str
    participant_id: str
    client_id: str
    session_id: str
    expires_at: Optional[datetime]
    expires_in_seconds: int


def canonical_signing_algorithm(value: str) -> Optional[str]:
    trimmed = value.strip()
    if not trimmed:
        return None
    for candidate in SIGNING_ALGORITHMS:
        if trimmed.lower() == candidate.lower():
            return candidate
    return None


def is_roi_classification(value: str) -> bool:
    return value in ROI_CLASSIFICATIONS


def validate_payload_hash_format(payload_hash: str) -> None:
    if len(payload_hash) != 43:
        raise ValueError(f"payload hash must be 43 characters, got {len(payload_hash)}")
    padding = "=" * (-len(payload_hash) % 4)
    try:
        urlsafe_b64decode(payload_hash + padding)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"payload hash must be base64url encoded: {exc}") from exc


def decode_payload_base64(payload: str) -> bytes:
    encoded = payload.strip()
    if not encoded:
        return b""
    try:
        return b64decode(encoded)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("payloadData must be valid base64") from exc


def build_key_id(did: str) -> str:
    trimmed = did.strip()
    if not trimmed:
        return ""
    return f"{trimmed}#keys-1"


__all__ = [
    "ALGORITHM_ED25519",
    "ALGORITHM_ES256",
    "ALGORITHM_ES256K",
    "INTERACTION_ACTOR_AI",
    "INTERACTION_ACTOR_HUMAN",
    "INTERACTION_ACTOR_HYBRID",
    "INTERACTION_ACTOR_NON_AI",
    "INTERACTION_TYPE_TOUCH",
    "INTERACTION_TYPE_TRANSFER",
    "INTERACTION_TYPE_TRANSITION",
    "ROI_CLASSIFICATION_BASELINE",
    "ROI_CLASSIFICATION_INCREMENT",
    "ROI_CLASSIFICATION_SAVINGS",
    "SIGNING_ALGORITHMS",
    "SessionInfo",
    "Signature",
    "SignatureValidationResult",
    "Transaction",
    "TransactionRequest",
    "InteractionSummary",
    "ParticipantSummary",
    "Workstream",
    "WorkstreamState",
    "WorkstreamInteraction",
    "WorkstreamInteractionsResponse",
    "WorkstreamParticipant",
    "WorkstreamParticipantsResponse",
    "WORKSTREAM_MODE_OFF",
    "WORKSTREAM_MODE_ON",
    "WORKSTREAM_STATE_STATUS_ACTIVE",
    "WORKSTREAM_STATE_STATUS_INACTIVE",
    "WORKSTREAM_STATUS_ACTIVE",
    "WORKSTREAM_STATUS_ARCHIVED",
    "WORKSTREAM_STATUS_DRAFT",
    "WORKSTREAM_STATUS_INACTIVE",
    "WORKSTREAM_TYPE_INTERNAL",
    "WORKSTREAM_TYPE_PRODUCTION",
    "build_key_id",
    "canonical_signing_algorithm",
    "decode_payload_base64",
    "is_roi_classification",
    "validate_payload_hash_format",
]
