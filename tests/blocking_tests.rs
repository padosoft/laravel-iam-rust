//! Synchronous-client integration tests. Compiled only with `--features blocking`.
//!
//! The blocking client must never be called from within an async runtime thread, so each call
//! runs inside `spawn_blocking` (a dedicated blocking thread with no runtime entered).

#![cfg(feature = "blocking")]

mod common;

use std::time::Duration;

use laravel_iam::blocking::IamClient;
use laravel_iam::{DecisionQuery, IamError, ResultExt, Subject};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_client(base_url: String) -> IamClient {
    IamClient::builder()
        .base_url(base_url)
        .token("service-token")
        .issuer(common::ISSUER)
        .audience(common::AUDIENCE)
        .timeout(Duration::from_millis(500))
        .build_blocking()
        .expect("client builds")
}

fn sample_query() -> DecisionQuery {
    DecisionQuery {
        subject: Subject::user("usr_123"),
        application: Some("warehouse".into()),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn blocking_check_happy_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
            "decision_id": "dec_1"
        })))
        .mount(&server)
        .await;

    let uri = server.uri();
    let decision = tokio::task::spawn_blocking(move || build_client(uri).check(sample_query()))
        .await
        .unwrap()
        .expect("ok");
    assert!(decision.granted());
}

#[tokio::test]
async fn blocking_check_500_denies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = tokio::task::spawn_blocking(move || build_client(uri).check(sample_query()))
        .await
        .unwrap();
    assert!(!result.is_allowed());
    assert!(matches!(result, Err(IamError::Http(500))));
}

#[tokio::test]
async fn blocking_check_network_error_denies() {
    let result = tokio::task::spawn_blocking(|| {
        build_client("http://127.0.0.1:1".to_string()).check(sample_query())
    })
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(IamError::Network(_) | IamError::Timeout)
    ));
}

#[tokio::test]
async fn blocking_list_resources() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/list-resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resources": [{ "type": "warehouse", "id": "wh_milan" }]
        })))
        .mount(&server)
        .await;

    let uri = server.uri();
    let resources = tokio::task::spawn_blocking(move || {
        build_client(uri).list_resources(Subject::user("usr_123"), "viewer")
    })
    .await
    .unwrap()
    .expect("ok");
    assert_eq!(resources.len(), 1);
}

#[tokio::test]
async fn blocking_verify_token_valid_and_expired() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(common::JWKS_JSON))
        .mount(&server)
        .await;

    let valid = common::sign_jwt(&common::valid_claims());
    let expired = common::sign_jwt(&json!({
        "sub": "usr_123",
        "iss": common::ISSUER,
        "aud": common::AUDIENCE,
        "exp": common::now() - 10,
    }));

    let uri = server.uri();
    let (ok, bad) = tokio::task::spawn_blocking(move || {
        let iam = build_client(uri);
        (iam.verify_token(&valid), iam.verify_token(&expired))
    })
    .await
    .unwrap();

    assert_eq!(ok.expect("valid").sub, "usr_123");
    assert!(matches!(bad, Err(IamError::TokenInvalid(_))));
}
