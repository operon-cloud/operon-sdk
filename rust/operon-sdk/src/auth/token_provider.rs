use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::OperonConfig;
use crate::errors::OperonError;

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub participant_did: Option<String>,
    pub channel_id: Option<String>,
    pub customer_id: Option<String>,
    pub workspace_id: Option<String>,
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

        let token = payload
            .access_token
            .ok_or_else(|| OperonError::validation("token response missing access_token"))?;
        let expires_in = if payload.expires_in <= 0 {
            60
        } else {
            payload.expires_in
        };
        let expires_at = Utc::now() + chrono::Duration::seconds(expires_in.into());
        let claims = decode_claims(&token).unwrap_or_default();

        Ok(AccessToken {
            value: token,
            expires_at,
            participant_did: claims.get("participant_did").cloned(),
            channel_id: claims.get("channel_id").cloned(),
            customer_id: claims.get("customer_id").cloned(),
            workspace_id: claims.get("workspace_id").cloned(),
        })
    }

    fn build_request(&self) -> Result<reqwest::Request, OperonError> {
        let mut builder = self
            .client
            .request(Method::POST, self.config.token_url.clone());
        let is_legacy = self.config.token_url.path().contains("/v1/session/m2m");

        if is_legacy {
            let audience = if self.config.audience.is_empty() {
                None
            } else {
                Some(self.config.audience.clone())
            };
            builder = builder.json(&LegacyBody {
                client_id: self.config.client_id.clone(),
                client_secret: self.config.client_secret.clone(),
                grant_type: "client_credentials".to_string(),
                scope: self.config.scope.clone(),
                audience,
            });
        } else {
            let mut form: Vec<(String, String)> =
                vec![("grant_type".into(), "client_credentials".into())];
            if let Some(scope) = &self.config.scope {
                form.push(("scope".into(), scope.clone()));
            }
            for aud in &self.config.audience {
                form.push(("audience".into(), aud.clone()));
            }
            builder = builder.form(&form);
            let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
            builder = builder.header(
                reqwest::header::AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials)
                ),
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

fn decode_claims(token: &str) -> Option<HashMap<String, String>> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(segments[1]).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let mut map = HashMap::new();
    if let Some(obj) = json.as_object() {
        for (key, value) in obj.iter() {
            if let Some(s) = value.as_str() {
                map.insert(key.clone(), s.to_string());
            }
        }
    }
    Some(map)
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
