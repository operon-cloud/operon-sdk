use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use operon_sdk::{validate_session, SessionValidationConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_token(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn validate_session_merges_pat_claims_and_api_payload() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/session/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "user_id": "usr-1",
            "email": "user@example.com",
            "name": "User One",
            "customer_id": "cust-1",
            "roles": ["admin", " analyst "],
            "feature_flags": {"new_ui": true}
        })))
        .mount(&server)
        .await;

    let pat = build_token(serde_json::json!({
        "participant_did":"did:test:123",
        "participant_id":"part-1",
        "workstream_id":"wrk-1",
        "workspace_id":"ws-1",
        "client_id":"cli-1",
        "session_id":"sess-1",
        "exp": 2524608000i64
    }));

    let info = validate_session(
        &SessionValidationConfig {
            base_url: Some(server.uri()),
            ..Default::default()
        },
        &pat,
    )
    .await
    .unwrap();

    assert_eq!(info.user_id.as_deref(), Some("usr-1"));
    assert_eq!(info.workstream_id.as_deref(), Some("wrk-1"));
    assert_eq!(info.channel_id.as_deref(), Some("wrk-1"));
    assert_eq!(info.participant_did.as_deref(), Some("did:test:123"));
    assert_eq!(info.client_id.as_deref(), Some("cli-1"));
    assert_eq!(
        info.feature_flags.get("new_ui").unwrap(),
        &serde_json::json!(true)
    );
    assert!(info.expires_in_seconds.unwrap_or_default() >= 0);
}
