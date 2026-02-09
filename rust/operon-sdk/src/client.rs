use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use tokio::sync::{watch, Mutex as AsyncMutex, RwLock};
use tokio::task::JoinHandle;
use urlencoding::encode;

use crate::auth::{AccessToken, ClientCredentialsTokenProvider};
use crate::config::{ConfigError, OperonConfig};
use crate::errors::OperonError;
use crate::models::{
    build_key_id, canonical_signing_algorithm, hash_bytes, sanitize_operon_headers, trim_opt,
    InteractionSummary, InteractionsEnvelope, OperonHeaders, ParticipantSummary,
    ParticipantsEnvelope, Signature, SignatureValidationResult, Transaction, TransactionRequest,
    Workstream, WorkstreamInteractionsResponse, WorkstreamParticipantsResponse, HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
};

const SELF_SIGN_PATH: &str = "v1/dids/self/sign";
const TRANSACTION_PATH: &str = "v1/transactions";
const WORKSTREAMS_PATH: &str = "v1/workstreams";
const INTERACTIONS_PATH: &str = "v1/interactions";
const PARTICIPANTS_PATH: &str = "v1/participants";

#[derive(Clone, Default)]
struct ClientContext {
    participant_did: Option<String>,
    workstream_id: Option<String>,
    customer_id: Option<String>,
    workspace_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    tenant_ids: Vec<String>,
    roles: Vec<String>,
    member_id: Option<String>,
    session_id: Option<String>,
    org_id: Option<String>,
    participant_id: Option<String>,
    client_id: Option<String>,
    authorized_party: Option<String>,
}

#[derive(Clone)]
pub struct OperonClient {
    config: OperonConfig,
    http: Client,
    token_provider: Arc<ClientCredentialsTokenProvider>,
    interactions: Arc<RwLock<Option<Vec<InteractionSummary>>>>,
    participants: Arc<RwLock<Option<Vec<ParticipantSummary>>>>,
    context: Arc<RwLock<ClientContext>>,
    reference_lock: Arc<AsyncMutex<()>>,
    heartbeat_tx: watch::Sender<bool>,
    heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl OperonClient {
    pub fn new(config: OperonConfig) -> Result<Self, OperonError> {
        let http = Client::builder()
            .timeout(config.http_timeout)
            .build()
            .map_err(OperonError::Transport)?;
        let provider = ClientCredentialsTokenProvider::new(config.clone(), http.clone());
        let (tx, _rx) = watch::channel(false);

        Ok(Self {
            config,
            http,
            token_provider: Arc::new(provider),
            interactions: Arc::new(RwLock::new(None)),
            participants: Arc::new(RwLock::new(None)),
            context: Arc::new(RwLock::new(ClientContext::default())),
            reference_lock: Arc::new(AsyncMutex::new(())),
            heartbeat_tx: tx,
            heartbeat_handle: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn init(&self) -> Result<(), OperonError> {
        let _ = self.token_with_context().await?;
        self.start_heartbeat();
        Ok(())
    }

    pub async fn close(&self) {
        let _ = self.heartbeat_tx.send(true);
        if let Some(handle) = self.heartbeat_handle.lock().unwrap().take() {
            handle.abort();
        }
        self.token_provider.clear().await;
    }

    pub async fn submit_transaction(
        &self,
        mut request: TransactionRequest,
    ) -> Result<Transaction, OperonError> {
        self.init().await?;

        request.normalize_aliases();

        let token = self.token_with_context().await?;
        self.populate_interaction_fields(&mut request, &token)
            .await?;

        let payload = request.resolve_payload()?;
        request.payload_hash = Some(payload.payload_hash.clone());

        let signature = self
            .resolve_signature(&request, &payload.payload_hash, &token)
            .await?;
        request.signature = Some(signature.clone());
        request.normalize_aliases();
        request.validate_for_submit()?;

        let timestamp = request.timestamp.unwrap_or_else(Utc::now);
        let submission = request.to_submission(signature, payload.payload_hash, timestamp);

        let response = self
            .authorized_json_request(
                Method::POST,
                TRANSACTION_PATH,
                &token.value,
                Some(&submission),
            )
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut transaction = response
            .json::<Transaction>()
            .await
            .map_err(OperonError::Transport)?;
        transaction.normalize_aliases();
        Ok(transaction)
    }

    pub async fn interactions(&self) -> Result<Vec<InteractionSummary>, OperonError> {
        self.init().await?;
        let token = self.token_with_context().await?;
        self.ensure_reference_data(&token).await?;

        let data = self.interactions.read().await;
        Ok(data.clone().unwrap_or_default())
    }

    pub async fn participants(&self) -> Result<Vec<ParticipantSummary>, OperonError> {
        self.init().await?;
        let token = self.token_with_context().await?;
        self.ensure_reference_data(&token).await?;

        let data = self.participants.read().await;
        Ok(data.clone().unwrap_or_default())
    }

    pub async fn get_workstream(
        &self,
        workstream_id_override: Option<&str>,
    ) -> Result<Workstream, OperonError> {
        self.init().await?;
        let token = self.token_with_context().await?;
        let workstream_id = self.resolve_workstream_id(workstream_id_override).await?;

        let path = format!("{}/{}", WORKSTREAMS_PATH, encode(&workstream_id));
        let response = self
            .authorized_json_request(Method::GET, &path, &token.value, Option::<&()>::None)
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        response
            .json::<Workstream>()
            .await
            .map_err(OperonError::Transport)
    }

    pub async fn get_workstream_interactions(
        &self,
        workstream_id_override: Option<&str>,
    ) -> Result<WorkstreamInteractionsResponse, OperonError> {
        self.init().await?;
        let token = self.token_with_context().await?;
        let workstream_id = self.resolve_workstream_id(workstream_id_override).await?;

        let path = format!(
            "{}/{}/interactions",
            WORKSTREAMS_PATH,
            encode(&workstream_id)
        );
        let response = self
            .authorized_json_request(Method::GET, &path, &token.value, Option::<&()>::None)
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut payload = response
            .json::<WorkstreamInteractionsResponse>()
            .await
            .map_err(OperonError::Transport)?;
        payload.normalize_aliases();
        Ok(payload)
    }

    pub async fn get_workstream_participants(
        &self,
        workstream_id_override: Option<&str>,
    ) -> Result<WorkstreamParticipantsResponse, OperonError> {
        self.init().await?;
        let token = self.token_with_context().await?;
        let workstream_id = self.resolve_workstream_id(workstream_id_override).await?;

        let path = format!(
            "{}/{}/participants",
            WORKSTREAMS_PATH,
            encode(&workstream_id)
        );
        let response = self
            .authorized_json_request(Method::GET, &path, &token.value, Option::<&()>::None)
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut payload = response
            .json::<WorkstreamParticipantsResponse>()
            .await
            .map_err(OperonError::Transport)?;
        payload.normalize_aliases();
        Ok(payload)
    }

    pub async fn generate_signature_headers(
        &self,
        payload: &[u8],
        algorithm: Option<&str>,
    ) -> Result<OperonHeaders, OperonError> {
        self.init().await?;

        let selected_algorithm = if let Some(value) = algorithm {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                canonical_signing_algorithm(&self.config.signing_algorithm)
            } else {
                canonical_signing_algorithm(trimmed)
            }
        } else {
            canonical_signing_algorithm(&self.config.signing_algorithm)
        }
        .ok_or_else(|| {
            OperonError::validation(format!(
                "unsupported signing algorithm {}",
                algorithm.unwrap_or(self.config.signing_algorithm.as_str())
            ))
        })?
        .to_string();

        if self.config.disable_self_sign {
            return Err(OperonError::validation(
                "automatic signing disabled: enable self signing to generate headers",
            ));
        }

        let payload_hash = hash_bytes(payload);
        let token = self.token_with_context().await?;
        let did = self.cached_participant_did().await.ok_or_else(|| {
            OperonError::validation("participant DID unavailable on access token")
        })?;

        let signature = self
            .sign_payload_hash(&token.value, &payload_hash, &selected_algorithm)
            .await?;

        let signature_value = signature.value.trim().to_string();
        if signature_value.is_empty() {
            return Err(OperonError::validation(
                "signature value missing from signing response",
            ));
        }

        let key_id = trim_opt(signature.key_id).unwrap_or_else(|| build_key_id(&did));
        let algorithm_value =
            trim_opt(Some(signature.algorithm)).unwrap_or_else(|| selected_algorithm.clone());

        let mut headers = HashMap::new();
        headers.insert(crate::models::HEADER_OPERON_DID.to_string(), did);
        headers.insert(
            crate::models::HEADER_OPERON_PAYLOAD_HASH.to_string(),
            payload_hash,
        );
        headers.insert(
            crate::models::HEADER_OPERON_SIGNATURE.to_string(),
            signature_value,
        );
        headers.insert(
            crate::models::HEADER_OPERON_SIGNATURE_KEY.to_string(),
            key_id,
        );
        headers.insert(
            crate::models::HEADER_OPERON_SIGNATURE_ALGO.to_string(),
            algorithm_value,
        );
        Ok(headers)
    }

    pub async fn generate_signature_headers_from_string(
        &self,
        payload: &str,
        algorithm: Option<&str>,
    ) -> Result<OperonHeaders, OperonError> {
        self.generate_signature_headers(payload.as_bytes(), algorithm)
            .await
    }

    pub async fn validate_signature_headers(
        &self,
        payload: &[u8],
        headers: &OperonHeaders,
    ) -> Result<SignatureValidationResult, OperonError> {
        self.init().await?;

        let sanitized = sanitize_operon_headers(headers)?;
        let computed_hash = hash_bytes(payload);
        let expected_hash = sanitized
            .get(HEADER_OPERON_PAYLOAD_HASH)
            .ok_or_else(|| OperonError::validation("header X-Operon-Payload-Hash is required"))?;

        if !computed_hash.eq_ignore_ascii_case(expected_hash) {
            return Err(OperonError::validation(format!(
                "payload hash mismatch: expected {computed_hash}, got {expected_hash}"
            )));
        }

        let token = self.token_with_context().await?;
        let did = sanitized
            .get(HEADER_OPERON_DID)
            .ok_or_else(|| OperonError::validation("header X-Operon-DID is required"))?;

        let path = format!("v1/dids/{}/signature/verify", encode(did));
        let response = self
            .authorized_raw_request(Method::POST, &path, &token.value, payload, Some(&sanitized))
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        response
            .json::<SignatureValidationResult>()
            .await
            .map_err(OperonError::Transport)
    }

    pub async fn validate_signature_headers_from_string(
        &self,
        payload: &str,
        headers: &OperonHeaders,
    ) -> Result<SignatureValidationResult, OperonError> {
        self.validate_signature_headers(payload.as_bytes(), headers)
            .await
    }

    async fn resolve_workstream_id(
        &self,
        override_id: Option<&str>,
    ) -> Result<String, OperonError> {
        if let Some(workstream_id) = override_id {
            let trimmed = workstream_id.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }

        if let Some(workstream) = self.cached_workstream_id().await {
            if !workstream.trim().is_empty() {
                return Ok(workstream);
            }
        }

        Err(OperonError::validation(
            "workstream ID is required: token not scoped to a workstream and no override provided",
        ))
    }

    async fn populate_interaction_fields(
        &self,
        request: &mut TransactionRequest,
        token: &AccessToken,
    ) -> Result<(), OperonError> {
        if trim_opt(request.workstream_id.clone()).is_none() {
            let cached_workstream = self.cached_workstream_id().await;
            request.workstream_id = trim_opt(token.workstream_id.clone()).or(cached_workstream);
        }

        if request.interaction_id.trim().is_empty() {
            if trim_opt(request.source_did.clone()).is_none() {
                let cached_participant = self.cached_participant_did().await;
                request.source_did = trim_opt(token.participant_did.clone()).or(cached_participant);
            }
            if trim_opt(request.workstream_id.clone()).is_none() {
                let cached_workstream = self.cached_workstream_id().await;
                request.workstream_id = trim_opt(token.workstream_id.clone()).or(cached_workstream);
            }
            request.normalize_aliases();
            return Ok(());
        }

        self.ensure_reference_data(token).await?;

        let interaction_id = request.interaction_id.trim().to_string();
        let mut interaction = self.find_interaction(&interaction_id).await;

        if interaction.is_none() {
            self.reload_reference_data(token).await?;
            interaction = self.find_interaction(&interaction_id).await;
        }

        let interaction = interaction.ok_or_else(|| {
            OperonError::validation(format!("interaction {interaction_id} not found"))
        })?;

        if trim_opt(request.workstream_id.clone()).is_none() {
            let cached_workstream = self.cached_workstream_id().await;
            request.workstream_id = trim_opt(Some(interaction.workstream_id.clone()))
                .or_else(|| trim_opt(token.workstream_id.clone()))
                .or(cached_workstream);
        }

        if trim_opt(request.source_did.clone()).is_none() {
            let source_did = trim_opt(interaction.source_did.clone()).ok_or_else(|| {
                OperonError::validation(format!(
                    "interaction {} missing source DID",
                    request.interaction_id
                ))
            })?;
            request.source_did = Some(source_did);
        }

        if trim_opt(request.target_did.clone()).is_none() {
            let target_did = trim_opt(interaction.target_did.clone()).ok_or_else(|| {
                OperonError::validation(format!(
                    "interaction {} missing target DID",
                    request.interaction_id
                ))
            })?;
            request.target_did = Some(target_did);
        }

        if trim_opt(request.source_did.clone()).is_none() {
            let cached_participant = self.cached_participant_did().await;
            request.source_did = trim_opt(token.participant_did.clone()).or(cached_participant);
        }

        request.normalize_aliases();
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
            if trim_opt(clone.key_id.clone()).is_none() {
                clone.key_id = trim_opt(request.source_did.clone())
                    .or_else(|| trim_opt(token.participant_did.clone()))
                    .map(|did| build_key_id(&did));
            }
            return Ok(clone);
        }

        if self.config.disable_self_sign {
            return Err(OperonError::validation(
                "signature required when self signing disabled",
            ));
        }

        let mut signed = self
            .sign_payload_hash(
                &token.value,
                payload_hash,
                self.config.signing_algorithm.as_str(),
            )
            .await?;

        if trim_opt(signed.key_id.clone()).is_none() {
            signed.key_id = trim_opt(request.source_did.clone())
                .or_else(|| trim_opt(token.participant_did.clone()))
                .map(|did| build_key_id(&did));
        }

        Ok(signed)
    }

    async fn sign_payload_hash(
        &self,
        token: &str,
        payload_hash: &str,
        algorithm: &str,
    ) -> Result<Signature, OperonError> {
        #[derive(Deserialize)]
        struct SelfSignResponse {
            signature: Option<Signature>,
        }

        let response = self
            .authorized_json_request(
                Method::POST,
                SELF_SIGN_PATH,
                token,
                Some(&serde_json::json!({
                    "payloadHash": payload_hash,
                    "hashAlgorithm": "SHA-256",
                    "algorithm": algorithm
                })),
            )
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let payload = response
            .json::<SelfSignResponse>()
            .await
            .map_err(OperonError::Transport)?;
        payload
            .signature
            .ok_or_else(|| OperonError::validation("self sign response missing signature"))
    }

    async fn ensure_reference_data(&self, token: &AccessToken) -> Result<(), OperonError> {
        let loaded =
            self.interactions.read().await.is_some() && self.participants.read().await.is_some();
        if loaded {
            return Ok(());
        }

        self.reload_reference_data(token).await
    }

    async fn reload_reference_data(&self, token: &AccessToken) -> Result<(), OperonError> {
        let _guard = self.reference_lock.lock().await;

        let loaded =
            self.interactions.read().await.is_some() && self.participants.read().await.is_some();
        if loaded {
            return Ok(());
        }

        let interactions = self.fetch_interactions(&token.value).await?;
        let participants = self.fetch_participants(&token.value).await?;

        let did_map = participants
            .iter()
            .filter_map(|participant| {
                if participant.id.trim().is_empty() || participant.did.trim().is_empty() {
                    None
                } else {
                    Some((participant.id.clone(), participant.did.clone()))
                }
            })
            .collect::<HashMap<_, _>>();

        let mut hydrated = interactions;
        for interaction in &mut hydrated {
            if trim_opt(interaction.source_did.clone()).is_none() {
                interaction.source_did = did_map.get(&interaction.source_participant_id).cloned();
            }
            if trim_opt(interaction.target_did.clone()).is_none() {
                interaction.target_did = did_map.get(&interaction.target_participant_id).cloned();
            }
            interaction.normalize_aliases();
        }

        *self.interactions.write().await = Some(hydrated);
        *self.participants.write().await = Some(participants);
        Ok(())
    }

    async fn fetch_interactions(
        &self,
        token: &str,
    ) -> Result<Vec<InteractionSummary>, OperonError> {
        let response = self
            .authorized_json_request(Method::GET, INTERACTIONS_PATH, token, Option::<&()>::None)
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut payload = response
            .json::<InteractionsEnvelope>()
            .await
            .map_err(OperonError::Transport)?;

        for item in &mut payload.data {
            item.normalize_aliases();
        }

        Ok(payload.data)
    }

    async fn fetch_participants(
        &self,
        token: &str,
    ) -> Result<Vec<ParticipantSummary>, OperonError> {
        let response = self
            .authorized_json_request(Method::GET, PARTICIPANTS_PATH, token, Option::<&()>::None)
            .await?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let mut payload = response
            .json::<ParticipantsEnvelope>()
            .await
            .map_err(OperonError::Transport)?;

        payload
            .data
            .retain(|entry| !entry.id.trim().is_empty() && !entry.did.trim().is_empty());

        for item in &mut payload.data {
            item.normalize_aliases();
        }

        Ok(payload.data)
    }

    async fn find_interaction(&self, interaction_id: &str) -> Option<InteractionSummary> {
        self.interactions.read().await.as_ref().and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.id == interaction_id)
                .cloned()
        })
    }

    async fn token_with_context(&self) -> Result<AccessToken, OperonError> {
        let token = self.token_provider.token().await?;
        {
            let mut context = self.context.write().await;
            if let Some(participant_did) = trim_opt(token.participant_did.clone()) {
                context.participant_did = Some(participant_did);
            }
            if let Some(workstream_id) = trim_opt(token.workstream_id.clone()) {
                context.workstream_id = Some(workstream_id);
            }
            if let Some(customer_id) = trim_opt(token.customer_id.clone()) {
                context.customer_id = Some(customer_id);
            }
            if let Some(workspace_id) = trim_opt(token.workspace_id.clone()) {
                context.workspace_id = Some(workspace_id);
            }
            if let Some(email) = trim_opt(token.email.clone()) {
                context.email = Some(email);
            }
            if let Some(name) = trim_opt(token.name.clone()) {
                context.name = Some(name);
            }
            context.tenant_ids = token.tenant_ids.clone();
            context.roles = token.roles.clone();
            if let Some(member_id) = trim_opt(token.member_id.clone()) {
                context.member_id = Some(member_id);
            }
            if let Some(session_id) = trim_opt(token.session_id.clone()) {
                context.session_id = Some(session_id);
            }
            if let Some(org_id) = trim_opt(token.org_id.clone()) {
                context.org_id = Some(org_id);
            }
            if let Some(participant_id) = trim_opt(token.participant_id.clone()) {
                context.participant_id = Some(participant_id);
            }
            if let Some(client_id) = trim_opt(token.client_id.clone()) {
                context.client_id = Some(client_id);
            }
            if let Some(authorized_party) = trim_opt(token.authorized_party.clone()) {
                context.authorized_party = Some(authorized_party);
            }
        }
        Ok(token)
    }

    async fn cached_participant_did(&self) -> Option<String> {
        self.context.read().await.participant_did.clone()
    }

    async fn cached_workstream_id(&self) -> Option<String> {
        self.context.read().await.workstream_id.clone()
    }

    async fn authorized_json_request<T>(
        &self,
        method: Method,
        path: &str,
        token: &str,
        payload: Option<&T>,
    ) -> Result<reqwest::Response, OperonError>
    where
        T: serde::Serialize + ?Sized,
    {
        let endpoint = self.join(path)?;
        let mut request = self
            .http
            .request(method, endpoint)
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/json");

        if let Some(body) = payload {
            request = request.json(body);
        }

        request.send().await.map_err(OperonError::Transport)
    }

    async fn authorized_raw_request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        payload: &[u8],
        headers: Option<&OperonHeaders>,
    ) -> Result<reqwest::Response, OperonError> {
        let endpoint = self.join(path)?;
        let mut request = self
            .http
            .request(method, endpoint)
            .bearer_auth(token)
            .body(payload.to_vec());

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        request.send().await.map_err(OperonError::Transport)
    }

    fn join(&self, path: &str) -> Result<Url, ConfigError> {
        self.config
            .base_url
            .join(path)
            .map_err(|_| ConfigError::MissingField("base_url"))
    }

    fn start_heartbeat(&self) {
        let Some(url) = self.config.session_heartbeat_url.clone() else {
            return;
        };
        if self.config.session_heartbeat_interval.is_zero() {
            return;
        }

        let mut guard = self.heartbeat_handle.lock().unwrap();
        if guard.is_some() {
            return;
        }

        let mut rx = self.heartbeat_tx.subscribe();
        let interval = self.config.session_heartbeat_interval;
        let timeout = self.config.session_heartbeat_timeout;
        let client = self.http.clone();
        let provider = self.token_provider.clone();

        *guard = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(interval) => {
                        if let Err(error) = heartbeat_once(&client, &provider, &url, timeout).await {
                            eprintln!("[operon-sdk] heartbeat error: {error}");
                        }
                    }
                }
            }
        }));
    }
}

impl Drop for OperonClient {
    fn drop(&mut self) {
        let _ = self.heartbeat_tx.send(true);
        if let Some(handle) = self.heartbeat_handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

async fn heartbeat_once(
    client: &Client,
    provider: &ClientCredentialsTokenProvider,
    url: &Url,
    timeout: Duration,
) -> Result<(), OperonError> {
    let token = provider.token().await?;
    let response = client
        .get(url.clone())
        .bearer_auth(&token.value)
        .timeout(timeout)
        .send()
        .await
        .map_err(OperonError::Transport)?;

    if response.status() == StatusCode::UNAUTHORIZED {
        provider.force_refresh().await?;
    }

    Ok(())
}

fn decode_error(status: StatusCode, body: Option<String>) -> OperonError {
    if let Some(body) = body {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            let message = json
                .get("message")
                .and_then(|value| value.as_str())
                .unwrap_or(status.as_str())
                .to_string();
            let code = json
                .get("code")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string());

            return OperonError::Api {
                status,
                code,
                message,
            };
        }

        return OperonError::Api {
            status,
            code: None,
            message: body,
        };
    }

    OperonError::Api {
        status,
        code: None,
        message: status.as_str().to_string(),
    }
}
