use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::OperonError;

pub const ALGORITHM_EDDSA: &str = "EdDSA";
pub const ALGORITHM_ES256: &str = "ES256";
pub const ALGORITHM_ES256K: &str = "ES256K";

pub const ROI_CLASSIFICATION_BASELINE: &str = "baseline";
pub const ROI_CLASSIFICATION_INCREMENT: &str = "increment";
pub const ROI_CLASSIFICATION_SAVINGS: &str = "savings";

pub const HEADER_OPERON_DID: &str = "X-Operon-DID";
pub const HEADER_OPERON_PAYLOAD_HASH: &str = "X-Operon-Payload-Hash";
pub const HEADER_OPERON_SIGNATURE: &str = "X-Operon-Signature";
pub const HEADER_OPERON_SIGNATURE_KEY: &str = "X-Operon-Signature-KeyId";
pub const HEADER_OPERON_SIGNATURE_ALGO: &str = "X-Operon-Signature-Alg";

pub const WORKSTREAM_STATUS_DRAFT: &str = "draft";
pub const WORKSTREAM_STATUS_ACTIVE: &str = "active";
pub const WORKSTREAM_STATUS_INACTIVE: &str = "inactive";
pub const WORKSTREAM_STATUS_ARCHIVED: &str = "archived";

pub const WORKSTREAM_MODE_OFF: &str = "off";
pub const WORKSTREAM_MODE_ON: &str = "on";

pub const WORKSTREAM_TYPE_INTERNAL: &str = "internal";
pub const WORKSTREAM_TYPE_PRODUCTION: &str = "production";

pub const WORKSTREAM_STATE_STATUS_ACTIVE: &str = "active";
pub const WORKSTREAM_STATE_STATUS_INACTIVE: &str = "inactive";

pub const DEFAULT_KEY_ID_SUFFIX: &str = "#keys-1";

pub type OperonHeaders = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(rename = "keyId", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub value: String,
}

fn default_algorithm() -> String {
    ALGORITHM_EDDSA.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: String,
    #[serde(rename = "workstreamId", default)]
    pub workstream_id: String,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(
        rename = "workstreamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_name: Option<String>,
    #[serde(
        rename = "customerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub customer_id: Option<String>,
    #[serde(
        rename = "workspaceId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workspace_id: Option<String>,
    #[serde(rename = "interactionId")]
    pub interaction_id: String,
    pub timestamp: String,
    #[serde(rename = "sourceDid")]
    pub source_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "stateId", default, skip_serializing_if = "Option::is_none")]
    pub state_id: Option<String>,
    #[serde(
        rename = "stateLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub state_label: Option<String>,
    #[serde(
        rename = "roiClassification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_classification: Option<String>,
    #[serde(
        rename = "roiCostIncrement",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_cost_increment: Option<i64>,
    #[serde(
        rename = "roiTimeIncrement",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_time_increment: Option<i64>,
    #[serde(
        rename = "roiCostSavings",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_cost_savings: Option<i64>,
    #[serde(
        rename = "roiTimeSavings",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_time_savings: Option<i64>,
    #[serde(
        rename = "roiBaseCost",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_base_cost: Option<i64>,
    #[serde(
        rename = "roiBaseTime",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_base_time: Option<i64>,
    #[serde(
        rename = "roiCostSaving",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_cost_saving: Option<i64>,
    #[serde(
        rename = "roiTimeSaving",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_time_saving: Option<i64>,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    #[serde(
        rename = "actorExternalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub actor_external_id: Option<String>,
    #[serde(
        rename = "actorExternalDisplayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub actor_external_display_name: Option<String>,
    #[serde(
        rename = "actorExternalSource",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub actor_external_source: Option<String>,
    #[serde(
        rename = "assigneeExternalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_external_id: Option<String>,
    #[serde(
        rename = "assigneeExternalDisplayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_external_display_name: Option<String>,
    #[serde(
        rename = "assigneeExternalSource",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_external_source: Option<String>,
    pub status: String,
    #[serde(
        rename = "hcsTopicId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_topic_id: Option<String>,
    #[serde(
        rename = "hcsSequenceNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_sequence_number: Option<i64>,
    #[serde(
        rename = "hcsConsensusTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_consensus_timestamp: Option<String>,
    #[serde(
        rename = "hcsTransactionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_transaction_id: Option<String>,
    #[serde(
        rename = "hcsRunningHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_running_hash: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "updatedBy", default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

impl Transaction {
    pub fn normalize_aliases(&mut self) {
        if self.workstream_id.trim().is_empty() {
            if let Some(channel) = trim_opt(self.channel_id.clone()) {
                self.workstream_id = channel;
            }
        }
        if trim_opt(self.channel_id.clone()).is_none() && !self.workstream_id.trim().is_empty() {
            self.channel_id = Some(self.workstream_id.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSummary {
    pub id: String,
    #[serde(rename = "workstreamId", default)]
    pub workstream_id: String,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(
        rename = "workstreamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "sourceParticipantId")]
    pub source_participant_id: String,
    #[serde(rename = "targetParticipantId")]
    pub target_participant_id: String,
    #[serde(rename = "sourceDid", default, skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    #[serde(rename = "targetDid", default, skip_serializing_if = "Option::is_none")]
    pub target_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<String>,
    #[serde(
        rename = "roiClassification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_classification: Option<String>,
    #[serde(rename = "roiCost", default, skip_serializing_if = "Option::is_none")]
    pub roi_cost: Option<i64>,
    #[serde(rename = "roiTime", default, skip_serializing_if = "Option::is_none")]
    pub roi_time: Option<i64>,
}

impl InteractionSummary {
    pub fn normalize_aliases(&mut self) {
        if self.workstream_id.trim().is_empty() {
            if let Some(channel) = trim_opt(self.channel_id.clone()) {
                self.workstream_id = channel;
            }
        }
        if trim_opt(self.channel_id.clone()).is_none() && !self.workstream_id.trim().is_empty() {
            self.channel_id = Some(self.workstream_id.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantSummary {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "customerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub customer_id: Option<String>,
    #[serde(
        rename = "workstreamId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_id: Option<String>,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(
        rename = "workstreamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_name: Option<String>,
}

impl ParticipantSummary {
    pub fn normalize_aliases(&mut self) {
        if trim_opt(self.workstream_id.clone()).is_none() {
            self.workstream_id = trim_opt(self.channel_id.clone());
        }
        if trim_opt(self.channel_id.clone()).is_none() {
            self.channel_id = trim_opt(self.workstream_id.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransactionRequest {
    pub correlation_id: String,
    pub workstream_id: Option<String>,
    pub channel_id: Option<String>,
    pub interaction_id: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub source_did: Option<String>,
    pub target_did: Option<String>,
    pub roi_classification: Option<String>,
    pub roi_cost: Option<i64>,
    pub roi_time: Option<i64>,
    pub state: Option<String>,
    pub state_id: Option<String>,
    pub state_label: Option<String>,
    pub roi_base_cost: Option<i64>,
    pub roi_base_time: Option<i64>,
    pub roi_cost_saving: Option<i64>,
    pub roi_time_saving: Option<i64>,
    pub signature: Option<Signature>,
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub payload_bytes: Option<Vec<u8>>,
    pub payload_hash: Option<String>,
    pub actor_external_id: Option<String>,
    pub actor_external_display_name: Option<String>,
    pub actor_external_source: Option<String>,
    pub assignee_external_id: Option<String>,
    pub assignee_external_display_name: Option<String>,
    pub assignee_external_source: Option<String>,
    pub customer_id: Option<String>,
    pub workspace_id: Option<String>,
    pub created_by: Option<String>,
}

impl TransactionRequest {
    pub fn new(
        correlation_id: impl Into<String>,
        interaction_id: impl Into<String>,
    ) -> Result<Self, OperonError> {
        let correlation = correlation_id.into();
        if correlation.trim().is_empty() {
            return Err(OperonError::validation("correlation_id required"));
        }

        let interaction = interaction_id.into();
        if interaction.trim().is_empty() {
            return Err(OperonError::validation("interaction_id required"));
        }

        Ok(Self {
            correlation_id: correlation,
            workstream_id: None,
            channel_id: None,
            interaction_id: interaction,
            timestamp: None,
            source_did: None,
            target_did: None,
            roi_classification: None,
            roi_cost: None,
            roi_time: None,
            state: None,
            state_id: None,
            state_label: None,
            roi_base_cost: None,
            roi_base_time: None,
            roi_cost_saving: None,
            roi_time_saving: None,
            signature: None,
            label: None,
            tags: None,
            payload_bytes: None,
            payload_hash: None,
            actor_external_id: None,
            actor_external_display_name: None,
            actor_external_source: None,
            assignee_external_id: None,
            assignee_external_display_name: None,
            assignee_external_source: None,
            customer_id: None,
            workspace_id: None,
            created_by: None,
        })
    }

    pub fn with_workstream_id(mut self, workstream_id: impl Into<String>) -> Self {
        self.workstream_id = Some(workstream_id.into());
        self
    }

    pub fn with_channel_id(mut self, channel_id: impl Into<String>) -> Self {
        self.channel_id = Some(channel_id.into());
        self
    }

    pub fn with_source_did(mut self, did: impl Into<String>) -> Self {
        self.source_did = Some(did.into());
        self
    }

    pub fn with_target_did(mut self, did: impl Into<String>) -> Self {
        self.target_did = Some(did.into());
        self
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_state_id(mut self, state_id: impl Into<String>) -> Self {
        self.state_id = Some(state_id.into());
        self
    }

    pub fn with_state_label(mut self, state_label: impl Into<String>) -> Self {
        self.state_label = Some(state_label.into());
        self
    }

    pub fn with_payload_bytes(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.payload_bytes = Some(payload.as_ref().to_vec());
        self
    }

    pub fn with_payload_hash(mut self, hash: impl Into<String>) -> Self {
        self.payload_hash = Some(hash.into());
        self
    }

    pub fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = Some(tags.into_iter().map(|item| item.into()).collect());
        self
    }

    pub fn with_actor_external(
        mut self,
        source: impl Into<String>,
        id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        self.actor_external_source = Some(source.into());
        self.actor_external_id = Some(id.into());
        self.actor_external_display_name = Some(display_name.into());
        self
    }

    pub fn with_assignee_external(
        mut self,
        source: impl Into<String>,
        id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        self.assignee_external_source = Some(source.into());
        self.assignee_external_id = Some(id.into());
        self.assignee_external_display_name = Some(display_name.into());
        self
    }

    pub fn with_customer_id(mut self, customer_id: impl Into<String>) -> Self {
        self.customer_id = Some(customer_id.into());
        self
    }

    pub fn with_workspace_id(mut self, workspace_id: impl Into<String>) -> Self {
        self.workspace_id = Some(workspace_id.into());
        self
    }

    pub fn with_created_by(mut self, created_by: impl Into<String>) -> Self {
        self.created_by = Some(created_by.into());
        self
    }

    pub fn normalize_aliases(&mut self) {
        if trim_opt(self.workstream_id.clone()).is_none() {
            self.workstream_id = trim_opt(self.channel_id.clone());
        }
        if trim_opt(self.channel_id.clone()).is_none() {
            self.channel_id = trim_opt(self.workstream_id.clone());
        }
    }

    pub fn validate_for_submit(&self) -> Result<(), OperonError> {
        let correlation = self.correlation_id.trim();
        if correlation.is_empty() {
            return Err(OperonError::validation("CorrelationID is required"));
        }

        let workstream = self.workstream_id.as_deref().unwrap_or("").trim();
        if workstream.is_empty() {
            return Err(OperonError::validation("WorkstreamID is required"));
        }

        if self.interaction_id.trim().is_empty() {
            return Err(OperonError::validation("InteractionID is required"));
        }

        let source_did = self.source_did.as_deref().unwrap_or("").trim();
        if source_did.is_empty() {
            return Err(OperonError::validation("SourceDID is required"));
        }
        if !source_did.starts_with("did:") {
            return Err(OperonError::validation("SourceDID must be a valid DID"));
        }

        let target_did = self.target_did.as_deref().unwrap_or("").trim();
        if target_did.is_empty() {
            return Err(OperonError::validation("TargetDID is required"));
        }
        if !target_did.starts_with("did:") {
            return Err(OperonError::validation("TargetDID must be a valid DID"));
        }

        let payload_hash = self.payload_hash.as_deref().unwrap_or("").trim();
        if payload_hash.is_empty() {
            return Err(OperonError::validation(
                "payload bytes or payload hash is required",
            ));
        }

        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| OperonError::validation("Signature algorithm is required"))?;
        if signature.algorithm.trim().is_empty() {
            return Err(OperonError::validation("Signature algorithm is required"));
        }
        if signature.value.trim().is_empty() {
            return Err(OperonError::validation("Signature value is required"));
        }

        if let Some(classification) = &self.roi_classification {
            if !is_roi_classification(classification.trim()) {
                return Err(OperonError::validation(
                    "ROIClassification must be one of baseline, increment, savings",
                ));
            }
        }

        if self.roi_base_cost.unwrap_or(0) < 0 {
            return Err(OperonError::validation("ROIBaseCost cannot be negative"));
        }
        if self.roi_base_time.unwrap_or(0) < 0 {
            return Err(OperonError::validation("ROIBaseTime cannot be negative"));
        }
        if self.roi_cost_saving.unwrap_or(0) < 0 {
            return Err(OperonError::validation("ROICostSaving cannot be negative"));
        }
        if self.roi_time_saving.unwrap_or(0) < 0 {
            return Err(OperonError::validation("ROITimeSaving cannot be negative"));
        }

        if trim_opt(self.actor_external_source.clone()).is_none()
            && (trim_opt(self.actor_external_id.clone()).is_some()
                || trim_opt(self.actor_external_display_name.clone()).is_some())
        {
            return Err(OperonError::validation(
                "ActorExternalSource is required when ActorExternalID or ActorExternalDisplayName is set",
            ));
        }

        if trim_opt(self.assignee_external_source.clone()).is_none()
            && (trim_opt(self.assignee_external_id.clone()).is_some()
                || trim_opt(self.assignee_external_display_name.clone()).is_some())
        {
            return Err(OperonError::validation(
                "AssigneeExternalSource is required when AssigneeExternalID or AssigneeExternalDisplayName is set",
            ));
        }

        Ok(())
    }

    pub fn resolve_payload(&self) -> Result<ResolvedPayload, OperonError> {
        if let Some(payload_bytes) = &self.payload_bytes {
            let payload_hash = hash_bytes(payload_bytes);
            if let Some(existing_hash) = trim_opt(self.payload_hash.clone()) {
                if !existing_hash.eq_ignore_ascii_case(&payload_hash) {
                    return Err(OperonError::validation(format!(
                        "provided payload hash does not match payload content: expected {payload_hash} got {existing_hash}"
                    )));
                }
            }
            return Ok(ResolvedPayload {
                payload_hash,
                payload_bytes: Some(payload_bytes.clone()),
            });
        }

        let payload_hash = trim_opt(self.payload_hash.clone())
            .ok_or_else(|| OperonError::validation("payload bytes or payload hash is required"))?;
        validate_payload_hash_format(&payload_hash)?;
        Ok(ResolvedPayload {
            payload_hash,
            payload_bytes: None,
        })
    }

    pub fn to_submission(
        &self,
        signature: Signature,
        payload_hash: String,
        timestamp: DateTime<Utc>,
    ) -> TransactionSubmission {
        let tags = self
            .tags
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| trim_opt(Some(entry)))
            .collect::<Vec<_>>();

        TransactionSubmission {
            correlation_id: self.correlation_id.trim().to_string(),
            workstream_id: self.workstream_id.clone().unwrap_or_default(),
            interaction_id: self.interaction_id.trim().to_string(),
            timestamp: timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            source_did: self.source_did.clone().unwrap_or_default(),
            target_did: self.target_did.clone().unwrap_or_default(),
            roi_classification: trim_opt(self.roi_classification.clone()),
            roi_cost: self.roi_cost,
            roi_time: self.roi_time,
            state: trim_opt(self.state.clone()),
            state_id: trim_opt(self.state_id.clone()),
            state_label: trim_opt(self.state_label.clone()),
            roi_base_cost: self.roi_base_cost,
            roi_base_time: self.roi_base_time,
            roi_cost_saving: self.roi_cost_saving,
            roi_time_saving: self.roi_time_saving,
            signature,
            payload_hash,
            label: trim_opt(self.label.clone()),
            tags: (!tags.is_empty()).then_some(tags),
            actor_external_id: trim_opt(self.actor_external_id.clone()),
            actor_external_display_name: trim_opt(self.actor_external_display_name.clone()),
            actor_external_source: trim_opt(self.actor_external_source.clone()),
            assignee_external_id: trim_opt(self.assignee_external_id.clone()),
            assignee_external_display_name: trim_opt(self.assignee_external_display_name.clone()),
            assignee_external_source: trim_opt(self.assignee_external_source.clone()),
            customer_id: trim_opt(self.customer_id.clone()),
            workspace_id: trim_opt(self.workspace_id.clone()),
            created_by: trim_opt(self.created_by.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedPayload {
    pub payload_hash: String,
    pub payload_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionSubmission {
    #[serde(rename = "correlationId")]
    pub correlation_id: String,
    #[serde(rename = "workstreamId")]
    pub workstream_id: String,
    #[serde(rename = "interactionId")]
    pub interaction_id: String,
    pub timestamp: String,
    #[serde(rename = "sourceDid")]
    pub source_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "roiClassification", skip_serializing_if = "Option::is_none")]
    pub roi_classification: Option<String>,
    #[serde(rename = "roiCost", skip_serializing_if = "Option::is_none")]
    pub roi_cost: Option<i64>,
    #[serde(rename = "roiTime", skip_serializing_if = "Option::is_none")]
    pub roi_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "stateId", skip_serializing_if = "Option::is_none")]
    pub state_id: Option<String>,
    #[serde(rename = "stateLabel", skip_serializing_if = "Option::is_none")]
    pub state_label: Option<String>,
    #[serde(rename = "roiBaseCost", skip_serializing_if = "Option::is_none")]
    pub roi_base_cost: Option<i64>,
    #[serde(rename = "roiBaseTime", skip_serializing_if = "Option::is_none")]
    pub roi_base_time: Option<i64>,
    #[serde(rename = "roiCostSaving", skip_serializing_if = "Option::is_none")]
    pub roi_cost_saving: Option<i64>,
    #[serde(rename = "roiTimeSaving", skip_serializing_if = "Option::is_none")]
    pub roi_time_saving: Option<i64>,
    pub signature: Signature,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "actorExternalId", skip_serializing_if = "Option::is_none")]
    pub actor_external_id: Option<String>,
    #[serde(
        rename = "actorExternalDisplayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub actor_external_display_name: Option<String>,
    #[serde(
        rename = "actorExternalSource",
        skip_serializing_if = "Option::is_none"
    )]
    pub actor_external_source: Option<String>,
    #[serde(rename = "assigneeExternalId", skip_serializing_if = "Option::is_none")]
    pub assignee_external_id: Option<String>,
    #[serde(
        rename = "assigneeExternalDisplayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_external_display_name: Option<String>,
    #[serde(
        rename = "assigneeExternalSource",
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_external_source: Option<String>,
    #[serde(rename = "customerId", skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(rename = "workspaceId", skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(rename = "createdBy", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureValidationResult {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub did: String,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    pub algorithm: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstreamState {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workstream {
    pub id: String,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "updatedBy", default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(
        rename = "customerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub customer_id: Option<String>,
    #[serde(
        rename = "workspaceId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<WorkstreamState>,
    #[serde(
        rename = "defaultStateId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_state_id: Option<String>,
    #[serde(
        rename = "interactionIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub interaction_ids: Vec<String>,
    #[serde(
        rename = "hcsTestTopicId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_test_topic_id: Option<String>,
    #[serde(
        rename = "hcsLiveTopicId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hcs_live_topic_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstreamInteraction {
    pub id: String,
    #[serde(rename = "workstreamId", default)]
    pub workstream_id: String,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(
        rename = "workstreamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "sourceParticipantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_participant_id: Option<String>,
    #[serde(
        rename = "targetParticipantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub target_participant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workstreams: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<String>,
    #[serde(
        rename = "roiClassification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub roi_classification: Option<String>,
    #[serde(rename = "roiCost", default, skip_serializing_if = "Option::is_none")]
    pub roi_cost: Option<i64>,
    #[serde(rename = "roiTime", default, skip_serializing_if = "Option::is_none")]
    pub roi_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

impl WorkstreamInteraction {
    pub fn normalize_aliases(&mut self) {
        if self.workstream_id.trim().is_empty() {
            if let Some(channel) = trim_opt(self.channel_id.clone()) {
                self.workstream_id = channel;
            }
        }
        if trim_opt(self.channel_id.clone()).is_none() && !self.workstream_id.trim().is_empty() {
            self.channel_id = Some(self.workstream_id.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstreamInteractionsResponse {
    #[serde(default)]
    pub interactions: Vec<WorkstreamInteraction>,
    #[serde(rename = "totalCount", default)]
    pub total_count: i64,
    #[serde(default)]
    pub page: i64,
    #[serde(rename = "pageSize", default)]
    pub page_size: i64,
    #[serde(rename = "hasMore", default)]
    pub has_more: bool,
}

impl WorkstreamInteractionsResponse {
    pub fn normalize_aliases(&mut self) {
        for interaction in &mut self.interactions {
            interaction.normalize_aliases();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstreamParticipant {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(
        rename = "customerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub customer_id: Option<String>,
    #[serde(
        rename = "workstreamId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_id: Option<String>,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(
        rename = "workstreamName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workstream_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

impl WorkstreamParticipant {
    pub fn normalize_aliases(&mut self) {
        if trim_opt(self.workstream_id.clone()).is_none() {
            self.workstream_id = trim_opt(self.channel_id.clone());
        }
        if trim_opt(self.channel_id.clone()).is_none() {
            self.channel_id = trim_opt(self.workstream_id.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkstreamParticipantsResponse {
    #[serde(default)]
    pub participants: Vec<WorkstreamParticipant>,
    #[serde(rename = "totalCount", default)]
    pub total_count: i64,
    #[serde(default)]
    pub page: i64,
    #[serde(rename = "pageSize", default)]
    pub page_size: i64,
    #[serde(rename = "hasMore", default)]
    pub has_more: bool,
}

impl WorkstreamParticipantsResponse {
    pub fn normalize_aliases(&mut self) {
        for participant in &mut self.participants {
            participant.normalize_aliases();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub feature_flags: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workstream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InteractionsEnvelope {
    #[serde(default)]
    pub data: Vec<InteractionSummary>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ParticipantsEnvelope {
    #[serde(default)]
    pub data: Vec<ParticipantSummary>,
}

pub fn canonical_signing_algorithm(value: &str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case(ALGORITHM_EDDSA) {
        return Some(ALGORITHM_EDDSA);
    }
    if trimmed.eq_ignore_ascii_case(ALGORITHM_ES256) {
        return Some(ALGORITHM_ES256);
    }
    if trimmed.eq_ignore_ascii_case(ALGORITHM_ES256K) {
        return Some(ALGORITHM_ES256K);
    }
    None
}

pub fn is_roi_classification(value: &str) -> bool {
    value == ROI_CLASSIFICATION_BASELINE
        || value == ROI_CLASSIFICATION_INCREMENT
        || value == ROI_CLASSIFICATION_SAVINGS
}

pub fn validate_payload_hash_format(hash: &str) -> Result<(), OperonError> {
    if hash.len() != 43 {
        return Err(OperonError::validation(format!(
            "payload hash must be 43 characters, got {}",
            hash.len()
        )));
    }

    URL_SAFE_NO_PAD.decode(hash).map_err(|error| {
        OperonError::validation(format!("payload hash must be base64url encoded: {error}"))
    })?;

    Ok(())
}

pub fn sanitize_operon_headers(headers: &OperonHeaders) -> Result<OperonHeaders, OperonError> {
    let required = [
        HEADER_OPERON_DID,
        HEADER_OPERON_PAYLOAD_HASH,
        HEADER_OPERON_SIGNATURE,
        HEADER_OPERON_SIGNATURE_KEY,
        HEADER_OPERON_SIGNATURE_ALGO,
    ];

    let mut sanitized = OperonHeaders::new();
    for key in required {
        let value = headers.get(key).map(|entry| entry.trim()).unwrap_or("");
        if value.is_empty() {
            return Err(OperonError::validation(format!("header {key} is required")));
        }
        sanitized.insert(key.to_string(), value.to_string());
    }

    Ok(sanitized)
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn decode_payload_base64(encoded: &str) -> Result<Option<Vec<u8>>, OperonError> {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    STANDARD
        .decode(trimmed)
        .map(Some)
        .map_err(|error| OperonError::validation(format!("invalid base64 payload: {error}")))
}

pub fn build_key_id(source_did: &str) -> String {
    format!("{}{}", source_did.trim(), DEFAULT_KEY_ID_SUFFIX)
}

pub(crate) fn trim_opt(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
