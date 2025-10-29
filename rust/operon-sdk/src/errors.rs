use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperonError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("operon api error: {status} - {message}")]
    Api {
        status: StatusCode,
        code: Option<String>,
        message: String,
    },
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl OperonError {
    pub fn validation<T: Into<String>>(message: T) -> Self {
        OperonError::Validation(message.into())
    }
}
