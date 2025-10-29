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
