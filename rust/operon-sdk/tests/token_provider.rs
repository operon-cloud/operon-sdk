use std::time::Duration;

use operon_sdk::auth::ClientCredentialsTokenProvider;
use operon_sdk::config::OperonConfig;
use reqwest::Client;
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

fn build_token(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn token_provider_caches_until_expiry() {
    let mock_server = MockServer::start().await;
    let token_url = mock_server.uri() + "/oauth/token";

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({"participant_did":"did:test:123","channel_id":"chnl"})),
            "expires_in": 120,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .token_url(token_url)
        .build()
        .unwrap();

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let provider = ClientCredentialsTokenProvider::new(config, client);

    let first = provider.token().await.unwrap();
    let second = provider.token().await.unwrap();

    assert_eq!(first.value, second.value);
    assert_eq!(first.participant_did.as_deref(), Some("did:test:123"));
}

#[tokio::test]
async fn token_provider_refreshes_when_expired() {
    let mock_server = MockServer::start().await;
    let token_url = mock_server.uri() + "/oauth/token";

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({})),
            "expires_in": 1,
            "token_type": "Bearer"
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .token_url(token_url)
        .token_leeway(Duration::from_secs(1))
        .build()
        .unwrap();

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let provider = ClientCredentialsTokenProvider::new(config, client);

    let _first = provider.token().await.unwrap();
    sleep(Duration::from_secs(2)).await;
    let _second = provider.token().await.unwrap();
}

#[tokio::test]
async fn token_provider_force_refresh_bypasses_cache() {
    let mock_server = MockServer::start().await;
    let token_url = mock_server.uri() + "/oauth/token";

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({"nonce":"one"})),
            "expires_in": 300,
            "token_type": "Bearer"
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .token_url(token_url)
        .build()
        .unwrap();

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let provider = ClientCredentialsTokenProvider::new(config, client);

    let _ = provider.token().await.unwrap();
    let _ = provider.force_refresh().await.unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    let hits = requests
        .iter()
        .filter(|req| req.url.path() == "/oauth/token")
        .count();
    assert!(hits >= 2);
}
