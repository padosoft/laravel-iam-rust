//! Async integration tests (doc 20 §7) against a `wiremock` server.
//!
//! Every error path is asserted to collapse to **deny** via [`ResultExt::is_allowed`], and the
//! request body is checked against the exact PHP `HttpDecider` wire shape.

mod common;

use std::time::Duration;

use laravel_iam::{DecisionQuery, IamClient, IamError, ResultExt, Subject};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> IamClient {
    IamClient::builder()
        .base_url(server.uri())
        .token("service-token")
        .issuer(common::ISSUER)
        .audience(common::AUDIENCE)
        .timeout(Duration::from_millis(500))
        .build()
        .expect("client builds")
}

fn sample_query() -> DecisionQuery {
    DecisionQuery {
        subject: Subject::user("usr_123"),
        application: Some("warehouse".into()),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        context: json!({ "amount": 300 }),
        ..Default::default()
    }
}

async fn mount_check(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/decisions/check"))
        .respond_with(response)
        .mount(server)
        .await;
}

#[tokio::test]
async fn check_happy_path_is_allowed() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
            "decision_id": "dec_1",
            "policy_version": 7,
            "requires_step_up": false,
            "explanation": ["role grants stock.adjust"]
        })),
    )
    .await;

    let result = client(&server).check(sample_query()).await;
    let decision = result.expect("ok");
    assert!(decision.allowed);
    assert!(decision.granted());
    assert!(decision.is_allowed());
    assert_eq!(decision.decision_id, "dec_1");
    assert_eq!(decision.policy_version, 7);
}

#[tokio::test]
async fn check_sends_exact_php_wire_shape() {
    let server = MockServer::start().await;
    // Body must match the PHP DecisionRequest::toArray() shape EXACTLY.
    Mock::given(method("POST"))
        .and(path("/decisions/check"))
        .and(header("authorization", "Bearer service-token"))
        .and(header("accept", "application/json"))
        .and(body_json(json!({
            "subject": { "type": "user", "id": "usr_123" },
            "permission": "stock.adjust",
            "organization": null,
            "application": "warehouse",
            "resource": "wh_milan",
            "context": { "amount": 300 },
            "current_aal": "aal1",
            "explain": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": true })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client(&server).check(sample_query()).await;
    assert!(result.is_allowed());
}

#[tokio::test]
async fn check_step_up_is_not_granted() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
            "requires_step_up": true,
            "required_aal": "aal2"
        })),
    )
    .await;

    let result = client(&server).check(sample_query()).await;
    let decision = result.clone().expect("ok");
    assert!(decision.allowed);
    assert!(decision.requires_step_up);
    // allowed but step-up pending => NOT truly allowed (fail-safe).
    assert!(!decision.granted());
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_500_denies() {
    let server = MockServer::start().await;
    mount_check(&server, ResponseTemplate::new(500)).await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Http(500))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_400_denies() {
    let server = MockServer::start().await;
    mount_check(&server, ResponseTemplate::new(400)).await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Http(400))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_401_denies() {
    let server = MockServer::start().await;
    mount_check(&server, ResponseTemplate::new(401)).await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Unauthorized(401))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_403_denies() {
    let server = MockServer::start().await;
    mount_check(&server, ResponseTemplate::new(403)).await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Unauthorized(403))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_malformed_body_denies() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        ResponseTemplate::new(200).set_body_string("this is not json"),
    )
    .await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Malformed(_))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_non_object_body_denies() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        ResponseTemplate::new(200).set_body_json(json!([1, 2, 3])),
    )
    .await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Malformed(_))));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_missing_allowed_denies() {
    let server = MockServer::start().await;
    // Object present but `allowed` absent => defaults to false (deny), parse still succeeds.
    mount_check(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({ "decision_id": "dec_x" })),
    )
    .await;
    let result = client(&server).check(sample_query()).await;
    let decision = result.clone().expect("parses");
    assert!(!decision.allowed);
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_network_error_denies() {
    // Nothing is listening here => connection refused.
    let iam = IamClient::builder()
        .base_url("http://127.0.0.1:1")
        .token("t")
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let result = iam.check(sample_query()).await;
    assert!(matches!(
        result,
        Err(IamError::Network(_) | IamError::Timeout)
    ));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn check_timeout_denies() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        ResponseTemplate::new(200)
            .set_delay(Duration::from_secs(5))
            .set_body_json(json!({ "allowed": true })),
    )
    .await;
    let result = client(&server).check(sample_query()).await;
    assert!(matches!(result, Err(IamError::Timeout)));
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn list_resources_happy_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/list-resources"))
        .and(body_json(json!({
            "subject": { "type": "user", "id": "usr_123" },
            "relation": "viewer"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resources": [
                { "type": "warehouse", "id": "wh_milan" },
                { "type": "warehouse", "id": "wh_rome" }
            ]
        })))
        .mount(&server)
        .await;

    let resources = client(&server)
        .list_resources(Subject::user("usr_123"), "viewer")
        .await
        .expect("ok");
    assert_eq!(resources.len(), 2);
    assert_eq!(resources[0].id, "wh_milan");
}

#[tokio::test]
async fn list_resources_error_is_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/list-resources"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let result = client(&server)
        .list_resources(Subject::user("usr_123"), "viewer")
        .await;
    assert!(matches!(result, Err(IamError::Http(500))));
}

async fn mount_jwks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(common::JWKS_JSON))
        .mount(server)
        .await;
}

#[tokio::test]
async fn verify_token_valid() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let token = common::sign_jwt(&common::valid_claims());

    let claims = client(&server)
        .verify_token(&token)
        .await
        .expect("valid token");
    assert_eq!(claims.sub, "usr_123");
    assert_eq!(claims.iss, common::ISSUER);
}

#[tokio::test]
async fn verify_token_expired_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let claims = json!({
        "sub": "usr_123",
        "iss": common::ISSUER,
        "aud": common::AUDIENCE,
        "exp": common::now() - 3600,
    });
    let token = common::sign_jwt(&claims);

    let result = client(&server).verify_token(&token).await;
    assert!(matches!(result, Err(IamError::TokenInvalid(_))));
}

#[tokio::test]
async fn verify_token_wrong_audience_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let claims = json!({
        "sub": "usr_123",
        "iss": common::ISSUER,
        "aud": "some-other-api",
        "exp": common::now() + 3600,
    });
    let token = common::sign_jwt(&claims);

    let result = client(&server).verify_token(&token).await;
    assert!(matches!(result, Err(IamError::TokenInvalid(_))));
}

#[tokio::test]
async fn verify_token_wrong_issuer_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let claims = json!({
        "sub": "usr_123",
        "iss": "https://evil.example.com",
        "aud": common::AUDIENCE,
        "exp": common::now() + 3600,
    });
    let token = common::sign_jwt(&claims);

    let result = client(&server).verify_token(&token).await;
    assert!(matches!(result, Err(IamError::TokenInvalid(_))));
}

#[tokio::test]
async fn verify_token_unknown_kid_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let token = common::sign_jwt_with_kid(&common::valid_claims(), "nope");

    let result = client(&server).verify_token(&token).await;
    assert!(matches!(result, Err(IamError::TokenInvalid(_))));
}

#[tokio::test]
async fn verify_token_tampered_signature_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let mut token = common::sign_jwt(&common::valid_claims());
    // Flip the last character of the signature.
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });

    let result = client(&server).verify_token(&token).await;
    assert!(matches!(result, Err(IamError::TokenInvalid(_))));
}

#[tokio::test]
async fn verify_token_without_issuer_audience_is_config_error() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let iam = IamClient::builder().base_url(server.uri()).build().unwrap();
    let token = common::sign_jwt(&common::valid_claims());

    let result = iam.verify_token(&token).await;
    assert!(matches!(result, Err(IamError::Config(_))));
}

#[tokio::test]
async fn builder_requires_base_url() {
    let result = IamClient::builder().token("t").build();
    assert!(matches!(result, Err(IamError::Config(_))));
}
