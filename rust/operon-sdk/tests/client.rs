use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use operon_sdk::models::{Signature, TransactionRequest};
use operon_sdk::{OperonClient, OperonConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_token(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn submit_transaction_self_sign() {
    let server = MockServer::start().await;

    // token
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({"participant_did":"did:test:123","channel_id":"chnl-1"})),
            "expires_in": 300
        })))
        .expect(1)
        .mount(&server)
        .await;

    // interactions
    Mock::given(method("GET"))
        .and(path("/v1/interactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": "int-123",
                "channelId": "chnl-1",
                "sourceParticipantId": "part-1",
                "targetParticipantId": "part-2"
            }]
        })))
        .mount(&server)
        .await;

    // participants
    Mock::given(method("GET"))
        .and(path("/v1/participants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                { "id": "part-1", "did": "did:test:123" },
                { "id": "part-2", "did": "did:test:456" }
            ]
        })))
        .mount(&server)
        .await;

    // self sign
    Mock::given(method("POST"))
        .and(path("/v1/dids/self/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": {
                "algorithm": "EdDSA",
                "value": "signed-value",
                "keyId": "did:test:123#keys-1"
            }
        })))
        .mount(&server)
        .await;

    // transaction submission
    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "txn-1",
            "correlationId": "corr-1",
            "channelId": "chnl-1",
            "interactionId": "int-123",
            "timestamp": "2025-01-01T00:00:00Z",
            "sourceDid": "did:test:123",
            "targetDid": "did:test:456",
            "signature": {
                "algorithm": "EdDSA",
                "value": "signed-value",
                "keyId": "did:test:123#keys-1"
            },
            "payloadHash": "hash",
            "status": "PENDING",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .base_url(server.uri())
        .token_url(server.uri() + "/oauth/token")
        .build()
        .unwrap();

    let client = OperonClient::new(config).unwrap();
    client.init().await.unwrap();

    let txn = client
        .submit_transaction(
            TransactionRequest::new("corr-1", "int-123")
                .unwrap()
                .with_payload_bytes(b"{ }"),
        )
        .await
        .unwrap();

    assert_eq!(txn.id, "txn-1");
    assert_eq!(txn.signature.value, "signed-value");
}

#[tokio::test]
async fn submit_transaction_manual_signature() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({"participant_did":"did:test:777"})),
            "expires_in": 300
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/interactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/participants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "txn-2",
            "correlationId": "corr-2",
            "channelId": "chnl-9",
            "interactionId": "int-999",
            "timestamp": "2025-01-01T00:00:00Z",
            "sourceDid": "did:test:777",
            "targetDid": "did:test:888",
            "signature": {
                "algorithm": "EdDSA",
                "value": "manual",
                "keyId": "did:test:777#keys-1"
            },
            "payloadHash": "hash",
            "status": "PENDING",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .base_url(server.uri())
        .token_url(server.uri() + "/oauth/token")
        .disable_self_sign(true)
        .build()
        .unwrap();

    let client = OperonClient::new(config).unwrap();

    let request = TransactionRequest::new("corr-2", "int-999")
        .unwrap()
        .with_channel_id("chnl-9")
        .with_source_did("did:test:777")
        .with_target_did("did:test:888")
        .with_payload_hash("hash")
        .with_signature(Signature {
            algorithm: "EdDSA".to_string(),
            key_id: None,
            value: "manual".to_string(),
        });

    let txn = client.submit_transaction(request).await.unwrap();
    assert_eq!(txn.signature.value, "manual");
}
