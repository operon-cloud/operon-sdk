use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use operon_sdk::models::{hash_bytes, Signature, TransactionRequest};
use operon_sdk::{
    fetch_workstream_interactions, sign_hash_with_pat, submit_transaction_with_pat,
    validate_signature_with_pat, ClientApiConfig, WorkstreamDataConfig,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_token(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn sign_hash_with_pat_sets_key_id_from_claims() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/dids/self/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": {
                "algorithm": "EdDSA",
                "value": "sig-value"
            }
        })))
        .mount(&server)
        .await;

    let pat = build_token(serde_json::json!({"participant_did":"did:test:pat-1"}));
    let signature = sign_hash_with_pat(
        &ClientApiConfig {
            base_url: Some(server.uri()),
            ..Default::default()
        },
        &pat,
        &hash_bytes(br#"{}"#),
        "EdDSA",
    )
    .await
    .unwrap();

    assert_eq!(signature.value, "sig-value");
    assert_eq!(signature.key_id.as_deref(), Some("did:test:pat-1#keys-1"));
}

#[tokio::test]
async fn submit_transaction_with_pat_uses_claim_workstream_and_source() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "txn-pat-1",
            "correlationId": "corr-pat-1",
            "workstreamId": "wrk-claims",
            "interactionId": "int-1",
            "timestamp": "2026-02-09T00:00:00Z",
            "sourceDid": "did:test:source",
            "targetDid": "did:test:target",
            "signature": {
                "algorithm": "EdDSA",
                "value": "manual",
                "keyId": "did:test:source#keys-1"
            },
            "payloadHash": "hash",
            "status": "PENDING",
            "createdAt": "2026-02-09T00:00:00Z",
            "updatedAt": "2026-02-09T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let pat = build_token(serde_json::json!({
        "participant_did":"did:test:source",
        "workstream_id":"wrk-claims"
    }));

    let request = TransactionRequest::new("corr-pat-1", "int-1")
        .unwrap()
        .with_target_did("did:test:target")
        .with_payload_hash(hash_bytes(br#"{"a":1}"#))
        .with_signature(Signature {
            algorithm: "EdDSA".to_string(),
            key_id: Some("did:test:source#keys-1".to_string()),
            value: "manual".to_string(),
        });

    let txn = submit_transaction_with_pat(
        &ClientApiConfig {
            base_url: Some(server.uri()),
            ..Default::default()
        },
        &pat,
        request,
    )
    .await
    .unwrap();

    assert_eq!(txn.id, "txn-pat-1");
    assert_eq!(txn.workstream_id, "wrk-claims");

    let requests = server.received_requests().await.unwrap();
    let submission = requests
        .iter()
        .find(|entry| entry.url.path() == "/v1/transactions")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&submission.body).unwrap();
    assert_eq!(body["workstreamId"], "wrk-claims");
    assert_eq!(body["sourceDid"], "did:test:source");
}

#[tokio::test]
async fn pat_helpers_validate_signature_and_fetch_workstream_interactions() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/dids/did%3Atest%3Averify/signature/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "valid",
            "did": "did:test:verify",
            "payloadHash": "hash",
            "algorithm": "EdDSA",
            "keyId": "did:test:verify#keys-1"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/workstreams/wrk-claims/interactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "interactions": [{
                "id": "int-1",
                "channelId": "wrk-claims"
            }],
            "totalCount": 1,
            "page": 1,
            "pageSize": 50,
            "hasMore": false
        })))
        .mount(&server)
        .await;

    let pat = build_token(serde_json::json!({"workstream_id":"wrk-claims"}));
    let payload = br#"{"x":1}"#;
    let payload_hash = hash_bytes(payload);
    let headers = std::collections::HashMap::from([
        ("X-Operon-DID".to_string(), "did:test:verify".to_string()),
        ("X-Operon-Payload-Hash".to_string(), payload_hash.clone()),
        ("X-Operon-Signature".to_string(), "sig".to_string()),
        (
            "X-Operon-Signature-KeyId".to_string(),
            "did:test:verify#keys-1".to_string(),
        ),
        ("X-Operon-Signature-Alg".to_string(), "EdDSA".to_string()),
    ]);

    let validation = validate_signature_with_pat(
        &ClientApiConfig {
            base_url: Some(server.uri()),
            ..Default::default()
        },
        &pat,
        payload,
        &headers,
    )
    .await
    .unwrap();
    assert_eq!(validation.status, "valid");

    let interactions = fetch_workstream_interactions(
        &WorkstreamDataConfig {
            base_url: Some(server.uri()),
            ..Default::default()
        },
        &pat,
        None,
    )
    .await
    .unwrap();

    assert_eq!(interactions.interactions.len(), 1);
    assert_eq!(interactions.interactions[0].workstream_id, "wrk-claims");
}
