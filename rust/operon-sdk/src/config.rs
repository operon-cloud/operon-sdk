use std::time::Duration;

use reqwest::Url;
use thiserror::Error;

const DEFAULT_BASE_URL: &str = "https://api.operon.cloud/client-api/";
const DEFAULT_TOKEN_URL: &str = "https://auth.operon.cloud/oauth2/token";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_TOKEN_LEEWAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct OperonConfig {
    pub base_url: Url,
    pub token_url: Url,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
    pub audience: Vec<String>,
    pub http_timeout: Duration,
    pub token_leeway: Duration,
    pub disable_self_sign: bool,
}

impl OperonConfig {
    pub fn builder() -> OperonConfigBuilder {
        OperonConfigBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct OperonConfigBuilder {
    base_url: Option<Url>,
    token_url: Option<Url>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    audience: Vec<String>,
    http_timeout: Option<Duration>,
    token_leeway: Option<Duration>,
    disable_self_sign: bool,
}

impl OperonConfigBuilder {
    pub fn base_url(mut self, value: impl AsRef<str>) -> Self {
        self.base_url = Some(normalise_url(value));
        self
    }

    pub fn token_url(mut self, value: impl AsRef<str>) -> Self {
        self.token_url = Some(url(value));
        self
    }

    pub fn client_id(mut self, value: impl Into<String>) -> Self {
        self.client_id = Some(value.into());
        self
    }

    pub fn client_secret(mut self, value: impl Into<String>) -> Self {
        self.client_secret = Some(value.into());
        self
    }

    pub fn scope(mut self, value: impl Into<String>) -> Self {
        let scope = value.into();
        if scope.trim().is_empty() {
            self.scope = None;
        } else {
            self.scope = Some(scope.trim().to_owned());
        }
        self
    }

    pub fn audience<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audience = values
            .into_iter()
            .map(|s| s.into().trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    pub fn http_timeout(mut self, value: Duration) -> Self {
        self.http_timeout = Some(value);
        self
    }

    pub fn token_leeway(mut self, value: Duration) -> Self {
        self.token_leeway = Some(value);
        self
    }

    pub fn disable_self_sign(mut self, value: bool) -> Self {
        self.disable_self_sign = value;
        self
    }

    pub fn build(self) -> Result<OperonConfig, ConfigError> {
        let client_id = self
            .client_id
            .ok_or(ConfigError::MissingField("client_id"))?
            .trim()
            .to_owned();
        if client_id.is_empty() {
            return Err(ConfigError::MissingField("client_id"));
        }

        let client_secret = self
            .client_secret
            .ok_or(ConfigError::MissingField("client_secret"))?
            .trim()
            .to_owned();
        if client_secret.is_empty() {
            return Err(ConfigError::MissingField("client_secret"));
        }

        let base_url = self
            .base_url
            .unwrap_or_else(|| normalise_url(DEFAULT_BASE_URL));
        let token_url = self.token_url.unwrap_or_else(|| url(DEFAULT_TOKEN_URL));
        let http_timeout = self.http_timeout.unwrap_or(DEFAULT_TIMEOUT);
        let token_leeway = self.token_leeway.unwrap_or(DEFAULT_TOKEN_LEEWAY);

        Ok(OperonConfig {
            base_url,
            token_url,
            client_id,
            client_secret,
            scope: self.scope,
            audience: self.audience,
            http_timeout,
            token_leeway,
            disable_self_sign: self.disable_self_sign,
        })
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
}

fn normalise_url(value: impl AsRef<str>) -> Url {
    let mut url = url(value);
    if !url.as_str().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
}

fn url(value: impl AsRef<str>) -> Url {
    Url::parse(value.as_ref()).expect("invalid URL")
}
