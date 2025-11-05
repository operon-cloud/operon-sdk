use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub value: String,
}

fn default_algorithm() -> String {
    "EdDSA".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: String,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(rename = "interactionId")]
    pub interaction_id: String,
    pub timestamp: String,
    #[serde(rename = "sourceDid")]
    pub source_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    pub signature: Signature,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    pub status: String,
    #[serde(default)]
    pub hcs_topic_id: Option<String>,
    #[serde(default)]
    pub hcs_sequence_number: Option<i64>,
    #[serde(default)]
    pub hcs_consensus_timestamp: Option<String>,
    #[serde(default)]
    pub hcs_transaction_id: Option<String>,
    #[serde(default)]
    pub hcs_running_hash: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSummary {
    pub id: String,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    #[serde(rename = "sourceParticipantId")]
    pub source_participant_id: String,
    #[serde(rename = "targetParticipantId")]
    pub target_participant_id: String,
    #[serde(rename = "sourceDid", default)]
    pub source_did: Option<String>,
    #[serde(rename = "targetDid", default)]
    pub target_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantSummary {
    pub id: String,
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct TransactionRequest {
    pub correlation_id: String,
    pub channel_id: Option<String>,
    pub interaction_id: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub source_did: Option<String>,
    pub target_did: Option<String>,
    pub signature: Option<Signature>,
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub payload_bytes: Option<Vec<u8>>,
    pub payload_hash: Option<String>,
}

impl TransactionRequest {
    pub fn new(
        correlation_id: impl Into<String>,
        interaction_id: impl Into<String>,
    ) -> Result<Self, crate::errors::OperonError> {
        let corr = correlation_id.into();
        if corr.trim().is_empty() {
            return Err(crate::errors::OperonError::validation(
                "correlation_id required",
            ));
        }
        let interaction = interaction_id.into();
        if interaction.trim().is_empty() {
            return Err(crate::errors::OperonError::validation(
                "interaction_id required",
            ));
        }
        Ok(Self {
            correlation_id: corr,
            channel_id: None,
            interaction_id: interaction,
            timestamp: None,
            source_did: None,
            target_did: None,
            signature: None,
            label: None,
            tags: None,
            payload_bytes: None,
            payload_hash: None,
        })
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

    pub fn with_payload_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.payload_bytes = Some(bytes.as_ref().to_vec());
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
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelInteractionsEnvelope {
    #[serde(default)]
    pub interactions: Vec<InteractionSummary>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelParticipantsEnvelope {
    #[serde(default)]
    pub participants: Vec<ParticipantSummary>,
}
