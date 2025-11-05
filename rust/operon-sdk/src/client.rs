use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde_json;
use tokio::sync::RwLock;
use urlencoding::encode;

use crate::auth::{AccessToken, ClientCredentialsTokenProvider};
use crate::config::{ConfigError, OperonConfig};
use crate::errors::OperonError;
use crate::models::{
    ChannelInteractionsEnvelope, ChannelParticipantsEnvelope, InteractionSummary,
    ParticipantSummary, Signature, Transaction, TransactionRequest,
};

const SELF_SIGN_PATH: &str = "v1/dids/self/sign";
const TRANSACTION_PATH: &str = "v1/transactions";

#[derive(Clone)]
pub struct OperonClient {
    config: OperonConfig,
    http: Client,
    token_provider: Arc<ClientCredentialsTokenProvider>,
    interactions: Arc<RwLock<Option<Vec<InteractionSummary>>>>,
    participants: Arc<RwLock<Option<Vec<ParticipantSummary>>>>,
}

impl OperonClient {
    pub fn new(config: OperonConfig) -> Result<Self, OperonError> {
        let http = Client::builder()
            .timeout(config.http_timeout)
            .build()
            .map_err(OperonError::Transport)?;
        let provider = ClientCredentialsTokenProvider::new(config.clone(), http.clone());
        Ok(Self {
            config,
            http,
            token_provider: Arc::new(provider),
            interactions: Arc::new(RwLock::new(None)),
            participants: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn init(&self) -> Result<(), OperonError> {
        let _ = self.token_provider.token().await?;
        Ok(())
    }

    pub async fn submit_transaction(
        &self,
        mut request: TransactionRequest,
    ) -> Result<Transaction, OperonError> {
        let token = self.token_provider.token().await?;
        populate_from_token(&mut request, &token);

        if !request.interaction_id.trim().is_empty() {
            self.ensure_catalog(&mut request, &token).await?;
        }

        let payload = resolve_payload(&request)?;
        let signature = self
            .resolve_signature(&request, &payload.payload_hash, &token)
            .await?;
        request.signature = Some(signature);

        validate_request(&request)?;

        let body = serde_json::json!({
            "correlationId": request.correlation_id,
            "channelId": request.channel_id.as_ref().unwrap(),
            "interactionId": request.interaction_id,
            "timestamp": request
                .timestamp
                .unwrap_or_else(|| DateTime::<Utc>::from(Utc::now()))
                .to_rfc3339(),
            "sourceDid": request.source_did.as_ref().unwrap(),
            "targetDid": request.target_did.as_ref().unwrap(),
            "signature": request.signature,
            "payloadHash": payload.payload_hash,
            "label": request.label,
            "tags": request.tags,
        });

        let url = self.join(TRANSACTION_PATH)?;
        let response = self
            .http
            .post(url)
            .bearer_auth(&token.value)
            .json(&body)
            .send()
            .await
            .map_err(OperonError::Transport)?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let txn = response
            .json::<Transaction>()
            .await
            .map_err(OperonError::Transport)?;
        Ok(txn)
    }

    async fn ensure_catalog(
        &self,
        request: &mut TransactionRequest,
        token: &AccessToken,
    ) -> Result<(), OperonError> {
        if request.target_did.is_some()
            && request.source_did.is_some()
            && request.channel_id.is_some()
        {
            return Ok(());
        }

        if self.interactions.read().await.is_none() || self.participants.read().await.is_none() {
            self.refresh_catalog(token).await?;
        }

        let interactions = self.interactions.read().await;
        if let Some(items) = interactions.as_ref() {
            if let Some(interaction) = items.iter().find(|i| i.id == request.interaction_id) {
                if request.channel_id.is_none() {
                    request.channel_id = Some(interaction.channel_id.clone());
                }
                if request.source_did.is_none() {
                    request.source_did = interaction
                        .source_did
                        .clone()
                        .or_else(|| token.participant_did.clone());
                }
                if request.target_did.is_none() {
                    request.target_did = interaction.target_did.clone();
                }
            }
        }
        Ok(())
    }

    async fn refresh_catalog(&self, token: &AccessToken) -> Result<(), OperonError> {
        let channel_id = token
            .channel_id
            .clone()
            .ok_or_else(|| OperonError::validation("channel_id missing from token"))?;

        let encoded_channel = encode(&channel_id);
        let interactions_path = format!("v1/channels/{}/interactions", encoded_channel);
        let participants_path = format!("v1/channels/{}/participants", encoded_channel);

        let interactions_resp = self
            .http
            .get(self.join(&interactions_path)?)
            .bearer_auth(&token.value)
            .send()
            .await
            .map_err(OperonError::Transport)?;
        if !interactions_resp.status().is_success() {
            return Err(decode_error(
                interactions_resp.status(),
                interactions_resp.text().await.ok(),
            ));
        }
        let mut interactions: ChannelInteractionsEnvelope = interactions_resp
            .json()
            .await
            .map_err(OperonError::Transport)?;

        let participants_resp = self
            .http
            .get(self.join(&participants_path)?)
            .bearer_auth(&token.value)
            .send()
            .await
            .map_err(OperonError::Transport)?;
        if !participants_resp.status().is_success() {
            return Err(decode_error(
                participants_resp.status(),
                participants_resp.text().await.ok(),
            ));
        }
        let participants: ChannelParticipantsEnvelope = participants_resp
            .json()
            .await
            .map_err(OperonError::Transport)?;

        let map: std::collections::HashMap<_, _> = participants
            .participants
            .iter()
            .map(|p| (p.id.clone(), p.did.clone()))
            .collect();

        for interaction in interactions.interactions.iter_mut() {
            if let Some(did) = map.get(&interaction.source_participant_id) {
                interaction.source_did = Some(did.clone());
            }
            if let Some(did) = map.get(&interaction.target_participant_id) {
                interaction.target_did = Some(did.clone());
            }
        }

        *self.participants.write().await = Some(participants.participants);
        *self.interactions.write().await = Some(interactions.interactions);
        Ok(())
    }

    async fn resolve_signature(
        &self,
        request: &TransactionRequest,
        payload_hash: &str,
        token: &AccessToken,
    ) -> Result<Signature, OperonError> {
        if let Some(signature) = &request.signature {
            if signature.value.trim().is_empty() {
                return Err(OperonError::validation("signature value required"));
            }
            let mut clone = signature.clone();
            if clone.algorithm.trim().is_empty() {
                clone.algorithm = "EdDSA".to_string();
            }
            if clone.key_id.is_none() {
                clone.key_id = request
                    .source_did
                    .clone()
                    .or_else(|| token.participant_did.clone())
                    .map(|did| format!("{did}#keys-1"));
            }
            return Ok(clone);
        }

        if self.config.disable_self_sign {
            return Err(OperonError::validation(
                "signature required when self signing disabled",
            ));
        }

        let body = serde_json::json!({
            "payloadHash": payload_hash,
            "hashAlgorithm": "SHA-256",
            "algorithm": "EdDSA"
        });
        let response = self
            .http
            .post(self.join(SELF_SIGN_PATH)?)
            .bearer_auth(&token.value)
            .json(&body)
            .send()
            .await
            .map_err(OperonError::Transport)?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut payload: serde_json::Value =
            response.json().await.map_err(OperonError::Transport)?;
        let signature = payload
            .get_mut("signature")
            .and_then(|sig| serde_json::from_value::<Signature>(sig.take()).ok())
            .ok_or_else(|| OperonError::validation("self sign response missing signature"))?;

        Ok(Signature {
            key_id: signature.key_id.or_else(|| {
                request
                    .source_did
                    .clone()
                    .or_else(|| token.participant_did.clone())
                    .map(|did| format!("{did}#keys-1"))
            }),
            ..signature
        })
    }

    fn join(&self, path: &str) -> Result<Url, ConfigError> {
        self.config
            .base_url
            .join(path)
            .map_err(|_| ConfigError::MissingField("base_url"))
    }
}

struct ResolvedPayload {
    payload_hash: String,
}

fn resolve_payload(request: &TransactionRequest) -> Result<ResolvedPayload, OperonError> {
    if let Some(bytes) = &request.payload_bytes {
        let hash = hash_bytes(bytes);
        if let Some(existing) = &request.payload_hash {
            if existing != &hash {
                return Err(OperonError::validation(
                    "provided payload hash does not match payload",
                ));
            }
        }
        return Ok(ResolvedPayload { payload_hash: hash });
    }

    if let Some(hash) = &request.payload_hash {
        if hash.trim().is_empty() {
            return Err(OperonError::validation("payload hash cannot be empty"));
        }
        return Ok(ResolvedPayload {
            payload_hash: hash.clone(),
        });
    }

    Err(OperonError::validation(
        "payload bytes or hash must be provided",
    ))
}

fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

fn populate_from_token(request: &mut TransactionRequest, token: &AccessToken) {
    if request.channel_id.is_none() {
        request.channel_id = token.channel_id.clone();
    }
    if request.source_did.is_none() {
        request.source_did = token.participant_did.clone();
    }
}

fn validate_request(request: &TransactionRequest) -> Result<(), OperonError> {
    if request
        .channel_id
        .as_deref()
        .map(|s| s.trim())
        .unwrap_or_default()
        .is_empty()
    {
        return Err(OperonError::validation("channel_id required"));
    }
    if request
        .source_did
        .as_deref()
        .map(|s| s.trim())
        .unwrap_or_default()
        .is_empty()
    {
        return Err(OperonError::validation("source_did required"));
    }
    if request
        .target_did
        .as_deref()
        .map(|s| s.trim())
        .unwrap_or_default()
        .is_empty()
    {
        return Err(OperonError::validation("target_did required"));
    }
    if request.signature.is_none() {
        return Err(OperonError::validation("signature required"));
    }
    if request.signature.as_ref().unwrap().value.trim().is_empty() {
        return Err(OperonError::validation("signature value required"));
    }
    Ok(())
}

fn decode_error(status: StatusCode, body: Option<String>) -> OperonError {
    if let Some(body) = body {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            let message = json
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or(status.as_str());
            let code = json
                .get("code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return OperonError::Api {
                status,
                code,
                message: message.to_string(),
            };
        }
        OperonError::Api {
            status,
            code: None,
            message: body,
        }
    } else {
        OperonError::Api {
            status,
            code: None,
            message: status.as_str().to_string(),
        }
    }
}
