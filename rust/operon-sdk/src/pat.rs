use std::time::Duration;

use chrono::Utc;
use reqwest::{Client, Method, StatusCode, Url};

use crate::auth::decode_token_claims;
use crate::config::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT};
use crate::errors::OperonError;
use crate::models::{
    canonical_signing_algorithm, decode_payload_base64 as decode_payload_base64_impl, hash_bytes,
    sanitize_operon_headers, trim_opt, validate_payload_hash_format, OperonHeaders, Signature,
    SignatureValidationResult, Transaction, TransactionRequest, Workstream,
    WorkstreamInteractionsResponse, WorkstreamParticipantsResponse, HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
};

#[derive(Debug, Clone, Default)]
pub struct ClientApiConfig {
    pub base_url: Option<String>,
    pub http_timeout: Option<Duration>,
    pub http_client: Option<Client>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkstreamDataConfig {
    pub base_url: Option<String>,
    pub http_timeout: Option<Duration>,
    pub http_client: Option<Client>,
}

#[derive(Clone)]
struct NormalizedConfig {
    base_url: String,
    client: Client,
}

pub async fn sign_hash_with_pat(
    cfg: &ClientApiConfig,
    pat: &str,
    payload_hash: &str,
    algorithm: &str,
) -> Result<Signature, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let hash = payload_hash.trim();
    if hash.is_empty() {
        return Err(OperonError::validation("payload hash is required"));
    }
    validate_payload_hash_format(hash)?;

    let selected = canonical_signing_algorithm(algorithm)
        .ok_or_else(|| {
            OperonError::validation(format!("unsupported signing algorithm {algorithm}"))
        })?
        .to_string();

    let normalized = normalize_client_config(cfg)?;
    let response = request_json(
        &normalized,
        Method::POST,
        "/v1/dids/self/sign",
        token,
        Some(&serde_json::json!({
            "payloadHash": hash,
            "hashAlgorithm": "SHA-256",
            "algorithm": selected
        })),
    )
    .await?;

    if !response.status().is_success() {
        return Err(decode_error(response.status(), response.text().await.ok()));
    }

    #[derive(serde::Deserialize)]
    struct SelfSignResponse {
        signature: Option<Signature>,
    }

    let payload = response
        .json::<SelfSignResponse>()
        .await
        .map_err(OperonError::Transport)?;

    let mut signature = payload
        .signature
        .ok_or_else(|| OperonError::validation("self sign response missing signature"))?;

    if trim_opt(signature.key_id.clone()).is_none() {
        let claims = decode_token_claims(token);
        if let Some(participant_did) = trim_opt(claims.participant_did) {
            signature.key_id = Some(format!("{participant_did}#keys-1"));
        }
    }

    Ok(signature)
}

pub async fn submit_transaction_with_pat(
    cfg: &ClientApiConfig,
    pat: &str,
    mut request: TransactionRequest,
) -> Result<Transaction, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    request.normalize_aliases();

    let claims = decode_token_claims(token);
    if trim_opt(request.workstream_id.clone()).is_none() {
        request.workstream_id = claims.normalized_workstream_id();
    }
    if trim_opt(request.source_did.clone()).is_none() {
        request.source_did = trim_opt(claims.participant_did);
    }

    let payload = request.resolve_payload()?;
    request.payload_hash = Some(payload.payload_hash.clone());
    request.normalize_aliases();
    request.validate_for_submit()?;

    let signature = request
        .signature
        .clone()
        .ok_or_else(|| OperonError::validation("Signature algorithm is required"))?;
    let submission = request.to_submission(
        signature,
        payload.payload_hash,
        request.timestamp.unwrap_or_else(Utc::now),
    );

    let normalized = normalize_client_config(cfg)?;
    let response = request_json(
        &normalized,
        Method::POST,
        "/v1/transactions",
        token,
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

pub async fn validate_signature_with_pat(
    cfg: &ClientApiConfig,
    pat: &str,
    payload: &[u8],
    headers: &OperonHeaders,
) -> Result<SignatureValidationResult, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let sanitized = sanitize_operon_headers(headers)?;

    let computed = hash_bytes(payload);
    let expected = sanitized
        .get(HEADER_OPERON_PAYLOAD_HASH)
        .ok_or_else(|| OperonError::validation("header X-Operon-Payload-Hash is required"))?;

    if !computed.eq_ignore_ascii_case(expected) {
        return Err(OperonError::validation(format!(
            "payload hash mismatch: expected {computed}, got {expected}"
        )));
    }

    let did = sanitized
        .get(HEADER_OPERON_DID)
        .ok_or_else(|| OperonError::validation("header X-Operon-DID is required"))?;

    let normalized = normalize_client_config(cfg)?;
    let response = request_raw(
        &normalized,
        Method::POST,
        &format!("/v1/dids/{}/signature/verify", urlencoding::encode(did)),
        token,
        payload,
        Some(&sanitized),
    )
    .await?;

    if !response.status().is_success() {
        return Err(decode_error(response.status(), response.text().await.ok()));
    }

    response
        .json::<SignatureValidationResult>()
        .await
        .map_err(OperonError::Transport)
}

pub async fn validate_signature_with_pat_from_string(
    cfg: &ClientApiConfig,
    pat: &str,
    payload: &str,
    headers: &OperonHeaders,
) -> Result<SignatureValidationResult, OperonError> {
    validate_signature_with_pat(cfg, pat, payload.as_bytes(), headers).await
}

pub async fn fetch_workstream(
    cfg: &WorkstreamDataConfig,
    pat: &str,
    workstream_id_override: Option<&str>,
) -> Result<Workstream, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let workstream_id = resolve_workstream_id_from_pat(token, workstream_id_override)?;
    let normalized = normalize_workstream_config(cfg)?;

    let response = request_json(
        &normalized,
        Method::GET,
        &format!("/v1/workstreams/{}", urlencoding::encode(&workstream_id)),
        token,
        Option::<&()>::None,
    )
    .await?;

    if !response.status().is_success() {
        return Err(decode_error(response.status(), response.text().await.ok()));
    }

    response
        .json::<Workstream>()
        .await
        .map_err(OperonError::Transport)
}

pub async fn fetch_workstream_interactions(
    cfg: &WorkstreamDataConfig,
    pat: &str,
    workstream_id_override: Option<&str>,
) -> Result<WorkstreamInteractionsResponse, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let workstream_id = resolve_workstream_id_from_pat(token, workstream_id_override)?;
    let normalized = normalize_workstream_config(cfg)?;

    let response = request_json(
        &normalized,
        Method::GET,
        &format!(
            "/v1/workstreams/{}/interactions",
            urlencoding::encode(&workstream_id)
        ),
        token,
        Option::<&()>::None,
    )
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

pub async fn fetch_workstream_participants(
    cfg: &WorkstreamDataConfig,
    pat: &str,
    workstream_id_override: Option<&str>,
) -> Result<WorkstreamParticipantsResponse, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let workstream_id = resolve_workstream_id_from_pat(token, workstream_id_override)?;
    let normalized = normalize_workstream_config(cfg)?;

    let response = request_json(
        &normalized,
        Method::GET,
        &format!(
            "/v1/workstreams/{}/participants",
            urlencoding::encode(&workstream_id)
        ),
        token,
        Option::<&()>::None,
    )
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

pub fn decode_payload_base64(encoded: &str) -> Result<Option<Vec<u8>>, OperonError> {
    decode_payload_base64_impl(encoded)
}

fn normalize_client_config(cfg: &ClientApiConfig) -> Result<NormalizedConfig, OperonError> {
    normalize_config(
        cfg.base_url.clone(),
        cfg.http_timeout,
        cfg.http_client.clone(),
    )
}

fn normalize_workstream_config(
    cfg: &WorkstreamDataConfig,
) -> Result<NormalizedConfig, OperonError> {
    normalize_config(
        cfg.base_url.clone(),
        cfg.http_timeout,
        cfg.http_client.clone(),
    )
}

fn normalize_config(
    base_url: Option<String>,
    timeout: Option<Duration>,
    client: Option<Client>,
) -> Result<NormalizedConfig, OperonError> {
    let base_url = base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let parsed = Url::parse(base_url.trim())
        .map_err(|error| OperonError::validation(format!("invalid baseUrl: {error}")))?;
    let normalized_base_url = parsed.as_str().trim_end_matches('/').to_string();

    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
    let client = if let Some(existing) = client {
        existing
    } else {
        Client::builder()
            .timeout(timeout)
            .build()
            .map_err(OperonError::Transport)?
    };

    Ok(NormalizedConfig {
        base_url: normalized_base_url,
        client,
    })
}

fn resolve_workstream_id_from_pat(
    pat: &str,
    override_id: Option<&str>,
) -> Result<String, OperonError> {
    if let Some(value) = override_id {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let claims = decode_token_claims(pat);
    if let Some(workstream) = claims.normalized_workstream_id() {
        return Ok(workstream);
    }

    Err(OperonError::validation(
        "workstream ID is required: token not scoped to a workstream and no override provided",
    ))
}

async fn request_json<T>(
    normalized: &NormalizedConfig,
    method: Method,
    path: &str,
    token: &str,
    payload: Option<&T>,
) -> Result<reqwest::Response, OperonError>
where
    T: serde::Serialize + ?Sized,
{
    let endpoint = format!("{}{}", normalized.base_url, path);
    let mut request = normalized
        .client
        .request(method, endpoint)
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, "application/json");

    if let Some(body) = payload {
        request = request.json(body);
    }

    request.send().await.map_err(OperonError::Transport)
}

async fn request_raw(
    normalized: &NormalizedConfig,
    method: Method,
    path: &str,
    token: &str,
    payload: &[u8],
    headers: Option<&OperonHeaders>,
) -> Result<reqwest::Response, OperonError> {
    let endpoint = format!("{}{}", normalized.base_url, path);
    let mut request = normalized
        .client
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
