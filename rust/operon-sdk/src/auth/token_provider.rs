use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::OperonConfig;
use crate::errors::OperonError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenClaims {
    #[serde(rename = "participant_did", default)]
    pub participant_did: Option<String>,
    #[serde(rename = "workstream_id", default)]
    pub workstream_id: Option<String>,
    #[serde(rename = "channel_id", default)]
    pub channel_id: Option<String>,
    #[serde(rename = "customer_id", default)]
    pub customer_id: Option<String>,
    #[serde(rename = "workspace_id", default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "tenant_ids", default)]
    pub tenant_ids: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(rename = "member_id", default)]
    pub member_id: Option<String>,
    #[serde(rename = "session_id", default)]
    pub session_id: Option<String>,
    #[serde(rename = "org_id", default)]
    pub org_id: Option<String>,
    #[serde(rename = "participant_id", default)]
    pub participant_id: Option<String>,
    #[serde(rename = "client_id", default)]
    pub client_id: Option<String>,
    #[serde(rename = "azp", default)]
    pub authorized_party: Option<String>,
    #[serde(rename = "exp", default)]
    pub exp: Option<i64>,
}

impl TokenClaims {
    pub fn normalized_workstream_id(&self) -> Option<String> {
        first_non_empty(self.workstream_id.clone(), self.channel_id.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub participant_did: Option<String>,
    pub workstream_id: Option<String>,
    pub channel_id: Option<String>,
    pub customer_id: Option<String>,
    pub workspace_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub tenant_ids: Vec<String>,
    pub roles: Vec<String>,
    pub member_id: Option<String>,
    pub session_id: Option<String>,
    pub org_id: Option<String>,
    pub participant_id: Option<String>,
    pub client_id: Option<String>,
    pub authorized_party: Option<String>,
    pub exp: Option<i64>,
}

#[derive(Clone)]
pub struct ClientCredentialsTokenProvider {
    config: OperonConfig,
    client: Client,
    cache: Arc<Mutex<Option<AccessToken>>>,
}

impl ClientCredentialsTokenProvider {
    pub fn new(config: OperonConfig, client: Client) -> Self {
        Self {
            config,
            client,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn token(&self) -> Result<AccessToken, OperonError> {
        {
            let guard = self.cache.lock().await;
            if let Some(token) = guard.as_ref() {
                if token.expires_at
                    - chrono::Duration::from_std(self.config.token_leeway).unwrap_or_default()
                    > Utc::now()
                {
                    return Ok(token.clone());
                }
            }
        }

        let fresh = self.fetch_token().await?;
        let mut guard = self.cache.lock().await;
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    pub async fn clear(&self) {
        let mut guard = self.cache.lock().await;
        *guard = None;
    }

    pub async fn force_refresh(&self) -> Result<AccessToken, OperonError> {
        let fresh = self.fetch_token().await?;
        let mut guard = self.cache.lock().await;
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    async fn fetch_token(&self) -> Result<AccessToken, OperonError> {
        let request = self.build_request()?;
        let response = self
            .client
            .execute(request)
            .await
            .map_err(OperonError::Transport)?;

        if !response.status().is_success() {
            return Err(decode_error(response.status(), response.text().await.ok()));
        }

        let payload: TokenResponse = response.json().await.map_err(OperonError::Transport)?;

        let value = payload
            .access_token
            .ok_or_else(|| OperonError::validation("token response missing access_token"))?;

        let expires_in = if payload.expires_in <= 0 {
            60
        } else {
            payload.expires_in
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(expires_in);

        let claims = decode_token_claims(&value);
        let workstream_id = claims.normalized_workstream_id();

        Ok(AccessToken {
            value,
            expires_at,
            participant_did: trim_opt(claims.participant_did),
            workstream_id: workstream_id.clone(),
            channel_id: workstream_id,
            customer_id: trim_opt(claims.customer_id),
            workspace_id: trim_opt(claims.workspace_id),
            email: trim_opt(claims.email),
            name: trim_opt(claims.name),
            tenant_ids: normalize_values(claims.tenant_ids),
            roles: normalize_values(claims.roles),
            member_id: trim_opt(claims.member_id),
            session_id: trim_opt(claims.session_id),
            org_id: trim_opt(claims.org_id),
            participant_id: trim_opt(claims.participant_id),
            client_id: trim_opt(claims.client_id),
            authorized_party: trim_opt(claims.authorized_party),
            exp: claims.exp,
        })
    }

    fn build_request(&self) -> Result<reqwest::Request, OperonError> {
        let mut builder = self
            .client
            .request(Method::POST, self.config.token_url.clone());
        let is_legacy = self.config.token_url.path().contains("/v1/session/m2m");

        if is_legacy {
            let audience =
                (!self.config.audience.is_empty()).then_some(self.config.audience.clone());
            builder = builder.json(&LegacyBody {
                client_id: self.config.client_id.clone(),
                client_secret: self.config.client_secret.clone(),
                grant_type: "client_credentials".to_string(),
                scope: self.config.scope.clone(),
                audience,
            });
        } else {
            let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
            if let Some(scope) = &self.config.scope {
                form.push(("scope".to_string(), scope.clone()));
            }
            for audience in &self.config.audience {
                form.push(("audience".to_string(), audience.clone()));
            }

            let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
            builder = builder.form(&form).header(
                reqwest::header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(credentials)),
            );
        }

        builder
            .timeout(self.config.http_timeout)
            .header(reqwest::header::ACCEPT, "application/json")
            .build()
            .map_err(OperonError::Transport)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: i64,
}

#[derive(Serialize)]
struct LegacyBody {
    client_id: String,
    client_secret: String,
    grant_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<Vec<String>>,
}

pub fn decode_token_claims(token: &str) -> TokenClaims {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() < 2 {
        return TokenClaims::default();
    }

    let payload = decode_segment(segments[1]);
    let Ok(payload) = payload else {
        return TokenClaims::default();
    };

    let parsed = serde_json::from_slice::<TokenClaims>(&payload);
    let mut claims = parsed.unwrap_or_default();
    if claims.normalized_workstream_id().is_none() {
        claims.workstream_id = None;
        claims.channel_id = None;
    } else if claims.workstream_id.is_none() {
        claims.workstream_id = claims.channel_id.clone();
    }
    claims
}

pub fn claims_expiry(claims: &TokenClaims) -> Option<DateTime<Utc>> {
    claims
        .exp
        .and_then(|value| Utc.timestamp_opt(value, 0).single())
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| STANDARD.decode(segment))
}

fn normalize_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|entry| trim_opt(Some(entry)))
        .collect()
}

fn first_non_empty(primary: Option<String>, fallback: Option<String>) -> Option<String> {
    trim_opt(primary).or_else(|| trim_opt(fallback))
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
