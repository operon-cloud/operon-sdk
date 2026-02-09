use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use operon_sdk::models::TransactionRequest;
use operon_sdk::{OperonClient, OperonConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_token(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn heartbeat_forces_refresh_on_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({"tenant":"one"})),
            "expires_in": 300
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/session/heartbeat"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let config = OperonConfig::builder()
        .client_id("client")
        .client_secret("secret")
        .base_url(server.uri())
        .token_url(server.uri() + "/oauth/token")
        .session_heartbeat_interval(std::time::Duration::from_millis(50))
        .build()
        .unwrap();

    let client = OperonClient::new(config).unwrap();
    client.init().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    client.close().await;

    let requests = server.received_requests().await.unwrap();
    let token_hits = requests
        .iter()
        .filter(|req| req.url.path() == "/oauth/token")
        .count();
    assert!(token_hits >= 2);
}

#[tokio::test]
async fn submit_transaction_self_sign_uses_workstream_catalog_and_extended_fields() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({
                "participant_did":"did:test:123",
                "workstream_id":"wrk-1"
            })),
            "expires_in": 300
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/interactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": "int-123",
                "workstreamId": "wrk-1",
                "sourceParticipantId": "part-1",
                "targetParticipantId": "part-2",
                "state": "triage"
            }]
        })))
        .mount(&server)
        .await;

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

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "txn-1",
            "correlationId": "corr-1",
            "workstreamId": "wrk-1",
            "interactionId": "int-123",
            "timestamp": "2026-02-09T00:00:00Z",
            "sourceDid": "did:test:123",
            "targetDid": "did:test:456",
            "state": "triage",
            "stateId": "state-1",
            "stateLabel": "Triage",
            "roiBaseCost": 100,
            "roiBaseTime": 20,
            "roiCostSaving": 15,
            "roiTimeSaving": 3,
            "signature": {
                "algorithm": "EdDSA",
                "value": "signed-value",
                "keyId": "did:test:123#keys-1"
            },
            "payloadHash": "hash",
            "actorExternalId": "actor-1",
            "actorExternalDisplayName": "Ops Agent",
            "actorExternalSource": "zendesk",
            "assigneeExternalId": "assignee-1",
            "assigneeExternalDisplayName": "Case Owner",
            "assigneeExternalSource": "jira",
            "status": "PENDING",
            "createdAt": "2026-02-09T00:00:00Z",
            "updatedAt": "2026-02-09T00:00:00Z"
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

    let mut request = TransactionRequest::new("corr-1", "int-123")
        .unwrap()
        .with_payload_bytes(br#"{"foo":"bar"}"#)
        .with_state("triage")
        .with_state_id("state-1")
        .with_state_label("Triage")
        .with_actor_external("zendesk", "actor-1", "Ops Agent")
        .with_assignee_external("jira", "assignee-1", "Case Owner")
        .with_customer_id("cust-1")
        .with_workspace_id("ws-1")
        .with_created_by("system");
    request.roi_base_cost = Some(100);
    request.roi_base_time = Some(20);
    request.roi_cost_saving = Some(15);
    request.roi_time_saving = Some(3);

    let txn = client.submit_transaction(request).await.unwrap();
    assert_eq!(txn.id, "txn-1");
    assert_eq!(txn.workstream_id, "wrk-1");
    assert_eq!(txn.signature.value, "signed-value");

    let requests = server.received_requests().await.unwrap();
    let submission = requests
        .iter()
        .find(|entry| entry.url.path() == "/v1/transactions")
        .expect("transaction request exists");

    let body: serde_json::Value = serde_json::from_slice(&submission.body).unwrap();
    assert_eq!(body["workstreamId"], "wrk-1");
    assert_eq!(body["actorExternalId"], "actor-1");
    assert_eq!(body["assigneeExternalId"], "assignee-1");
    assert_eq!(body["stateId"], "state-1");
    assert_eq!(body["roiBaseCost"], 100);
    assert!(body.get("channelId").is_none());
}

#[tokio::test]
async fn generate_and_validate_signature_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({
                "participant_did":"did:test:123",
                "workstream_id":"wrk-1"
            })),
            "expires_in": 300
        })))
        .expect(1)
        .mount(&server)
        .await;

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

    Mock::given(method("POST"))
        .and(path("/v1/dids/did%3Atest%3A123/signature/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "valid",
            "did": "did:test:123",
            "payloadHash": "abc",
            "algorithm": "EdDSA",
            "keyId": "did:test:123#keys-1"
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
    let payload = br#"{"sample":true}"#;

    let headers = client
        .generate_signature_headers(payload, None)
        .await
        .unwrap();

    assert_eq!(headers.get("X-Operon-DID").unwrap(), "did:test:123");
    assert_eq!(
        headers.get("X-Operon-Signature-KeyId").unwrap(),
        "did:test:123#keys-1"
    );

    let result = client
        .validate_signature_headers(payload, &headers)
        .await
        .unwrap();

    assert_eq!(result.status, "valid");
    assert_eq!(result.key_id, "did:test:123#keys-1");
}

#[tokio::test]
async fn workstream_dataset_methods_use_token_workstream() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": build_token(serde_json::json!({
                "participant_did":"did:test:123",
                "workstream_id":"wrk-1"
            })),
            "expires_in": 300
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/workstreams/wrk-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "wrk-1",
            "name": "Primary"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/workstreams/wrk-1/interactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "interactions": [{
                "id": "int-1",
                "channelId": "wrk-1",
                "sourceParticipantId": "p-1",
                "targetParticipantId": "p-2"
            }],
            "totalCount": 1,
            "page": 1,
            "pageSize": 50,
            "hasMore": false
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/workstreams/wrk-1/participants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "participants": [{
                "id": "p-1",
                "did": "did:test:123",
                "channelId": "wrk-1"
            }],
            "totalCount": 1,
            "page": 1,
            "pageSize": 50,
            "hasMore": false
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

    let workstream = client.get_workstream(None).await.unwrap();
    assert_eq!(workstream.id, "wrk-1");

    let interactions = client.get_workstream_interactions(None).await.unwrap();
    assert_eq!(interactions.interactions.len(), 1);
    assert_eq!(interactions.interactions[0].workstream_id, "wrk-1");

    let participants = client.get_workstream_participants(None).await.unwrap();
    assert_eq!(participants.participants.len(), 1);
    assert_eq!(
        participants.participants[0].workstream_id.as_deref(),
        Some("wrk-1")
    );
}
