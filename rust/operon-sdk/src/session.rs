use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;

use crate::auth::decode_token_claims;
use crate::config::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT};
use crate::errors::OperonError;
use crate::models::SessionInfo;

#[derive(Debug, Clone, Default)]
pub struct SessionValidationConfig {
    pub base_url: Option<String>,
    pub http_timeout: Option<Duration>,
    pub http_client: Option<Client>,
}

#[derive(Clone)]
struct NormalizedConfig {
    base_url: String,
    client: Client,
}

pub async fn validate_session(
    cfg: &SessionValidationConfig,
    pat: &str,
) -> Result<SessionInfo, OperonError> {
    let token = pat.trim();
    if token.is_empty() {
        return Err(OperonError::validation("pat is required"));
    }

    let normalized = normalize_config(cfg)?;

    let response = normalized
        .client
        .request(
            Method::GET,
            format!("{}/v1/session/validate", normalized.base_url),
        )
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(OperonError::Transport)?;

    if !response.status().is_success() {
        return Err(decode_error(response.status(), response.text().await.ok()));
    }

    #[derive(Debug, Deserialize)]
    struct ValidatePayload {
        #[serde(default)]
        user_id: Option<String>,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        customer_id: Option<String>,
        #[serde(default)]
        roles: Vec<String>,
        #[serde(default)]
        feature_flags: HashMap<String, serde_json::Value>,
    }

    let payload = response
        .json::<ValidatePayload>()
        .await
        .map_err(OperonError::Transport)?;

    let claims = decode_token_claims(token);

    let expires_at = claims
        .exp
        .and_then(|value| Utc.timestamp_opt(value, 0).single());

    let expires_in_seconds = expires_at.map(|expiry| {
        let remaining = expiry.signed_duration_since(Utc::now()).num_seconds();
        if remaining < 0 {
            0
        } else {
            remaining
        }
    });

    let workstream_id = claims.normalized_workstream_id();

    Ok(SessionInfo {
        user_id: trim_opt(payload.user_id),
        email: trim_opt(payload.email),
        name: trim_opt(payload.name),
        customer_id: trim_opt(payload.customer_id),
        roles: normalize_values(payload.roles),
        feature_flags: payload.feature_flags,
        workstream_id: workstream_id.clone(),
        channel_id: workstream_id,
        workspace_id: trim_opt(claims.workspace_id),
        participant_did: trim_opt(claims.participant_did),
        participant_id: trim_opt(claims.participant_id),
        client_id: first_non_empty(
            trim_opt(claims.client_id),
            trim_opt(claims.authorized_party),
        ),
        session_id: trim_opt(claims.session_id),
        expires_at: expires_at.map(|value: DateTime<Utc>| value),
        expires_in_seconds,
    })
}

fn normalize_config(cfg: &SessionValidationConfig) -> Result<NormalizedConfig, OperonError> {
    let base_url = cfg
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let parsed = Url::parse(base_url.trim())
        .map_err(|error| OperonError::validation(format!("invalid baseUrl: {error}")))?;
    let normalized_base_url = parsed.as_str().trim_end_matches('/').to_string();

    let timeout = cfg.http_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let client = if let Some(existing) = cfg.http_client.clone() {
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

fn normalize_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|entry| trim_opt(Some(entry)))
        .collect()
}

fn first_non_empty(primary: Option<String>, fallback: Option<String>) -> Option<String> {
    primary.or(fallback)
}

fn trim_opt(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
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
