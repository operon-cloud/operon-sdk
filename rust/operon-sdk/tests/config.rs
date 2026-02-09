use operon_sdk::config::OperonConfig;

#[test]
fn config_defaults() {
    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .build()
        .unwrap();

    assert_eq!(
        config.base_url.as_str(),
        "https://api.operon.cloud/client-api/"
    );
    assert_eq!(
        config.token_url.as_str(),
        "https://auth.operon.cloud/oauth2/token"
    );
    assert_eq!(config.http_timeout.as_secs(), 30);
    assert_eq!(config.token_leeway.as_secs(), 30);
    assert_eq!(config.signing_algorithm, "EdDSA");
    assert_eq!(config.session_heartbeat_interval.as_secs(), 0);
    assert_eq!(config.session_heartbeat_timeout.as_secs(), 0);
    assert!(config.session_heartbeat_url.is_none());
}

#[test]
fn config_requires_credentials() {
    let err = OperonConfig::builder()
        .client_secret("secret")
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        operon_sdk::config::ConfigError::MissingField("client_id")
    ));
}

#[test]
fn config_heartbeat_customisation() {
    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .session_heartbeat_interval(std::time::Duration::from_secs(60))
        .session_heartbeat_timeout(std::time::Duration::from_secs(5))
        .session_heartbeat_url("https://internal.example.com/hb")
        .build()
        .unwrap();

    assert_eq!(config.session_heartbeat_interval.as_secs(), 60);
    assert_eq!(config.session_heartbeat_timeout.as_secs(), 5);
    assert_eq!(
        config.session_heartbeat_url.unwrap().as_str(),
        "https://internal.example.com/hb"
    );
}

#[test]
fn config_rejects_unsupported_signing_algorithm() {
    let err = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .signing_algorithm("invalid")
        .build()
        .unwrap_err();

    assert!(matches!(
        err,
        operon_sdk::config::ConfigError::UnsupportedSigningAlgorithm(_)
    ));
}
