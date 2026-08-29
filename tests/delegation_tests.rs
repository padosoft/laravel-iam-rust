//! Integration tests for delegated access (RFC 8693) against a `wiremock` server.
//!
//! Every rule that keeps delegation from becoming an escalation path is pinned here as a
//! NEGATIVE test: an empty chain refuses, unreachable introspection refuses, an inactive
//! token refuses, a malformed `act` refuses without even reaching the network.

mod common;

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use laravel_iam::{DecisionQuery, IamClient, IamError, ResultExt, Subject};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> IamClient {
    IamClient::builder()
        .base_url(server.uri())
        .token("service-token")
        .introspection_url(format!("{}/oauth/introspect", server.uri()))
        .timeout(Duration::from_millis(500))
        .build()
        .expect("client builds")
}

/// An unsigned JWT-shaped string: local inspection never checks signatures.
fn jwt_of(header: &Value, claims: &Value) -> String {
    let encode = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    format!("{}.{}.sig", encode(header), encode(claims))
}

fn delegated_token() -> String {
    jwt_of(
        &json!({ "alg": "ES256", "typ": "delegated+jwt" }),
        &json!({
            "sub": "user:42",
            "act": { "sub": "agent:a1" },
            "pds_dgr": "dgr_1",
            "scope": "orders:read",
        }),
    )
}

async fn mount_introspection(server: &MockServer, body: Value, status: u16) {
    Mock::given(method("POST"))
        .and(path("/oauth/introspect"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

// ---- the delegated decision -------------------------------------------------

#[tokio::test]
async fn delegated_check_routes_to_the_delegated_endpoint_with_the_chain() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check-delegated"))
        .and(body_json(json!({
            "subject": { "type": "user", "id": "usr_123" },
            "permission": "orders.draft",
            "organization": null,
            "application": null,
            "resource": "ord_1",
            "context": {},
            "current_aal": "aal1",
            "explain": false,
            "actors": ["agent:hop2", "agent:hop1"],
            "delegation_grant_id": "dgr_9",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": true })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client(&server)
        .check_delegated_with(DecisionQuery {
            subject: Subject::user("usr_123"),
            permission: "orders.draft".into(),
            resource: Some("ord_1".into()),
            actors: vec!["agent:hop2".into(), "agent:hop1".into()],
            delegation_grant_id: Some("dgr_9".into()),
            ..DecisionQuery::default()
        })
        .await;

    assert!(result.is_allowed());
}

#[tokio::test]
async fn a_plain_check_never_reaches_the_delegated_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": true })))
        .expect(1)
        .mount(&server)
        .await;

    let result = client(&server)
        .check(DecisionQuery::new(Subject::user("usr_1"), "stock.adjust"))
        .await;
    assert!(result.is_allowed());
}

#[tokio::test]
async fn an_empty_actor_chain_refuses_without_calling_the_server() {
    // NOT "fall back to checking the user": an empty chain means the caller lost track of
    // who is acting, and answering the user-only question would hand the agent's request
    // the user's full authority — the escalation delegation exists to prevent.
    let server = MockServer::start().await;
    let result = client(&server)
        .check_delegated(Subject::user("usr_1"), vec![], "orders.read")
        .await;

    assert!(matches!(result, Err(IamError::Config(_))));
    assert!(!result.is_allowed());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_chain_of_blanks_refuses_too() {
    let server = MockServer::start().await;
    let result = client(&server)
        .check_delegated(
            Subject::user("usr_1"),
            vec![String::new(), String::new()],
            "orders.read",
        )
        .await;

    assert!(matches!(result, Err(IamError::Config(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_delegated_denial_is_a_denial() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check-delegated"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "allowed": false, "explanation": ["agent-denied"] })),
        )
        .mount(&server)
        .await;

    let result = client(&server)
        .check_delegated(
            Subject::user("usr_1"),
            vec!["agent:a1".into()],
            "orders.pay",
        )
        .await;
    assert!(!result.is_allowed());
}

#[tokio::test]
async fn a_delegated_step_up_is_not_granted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/decisions/check-delegated"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "allowed": true, "requires_step_up": true, "required_aal": "aal2" }),
        ))
        .mount(&server)
        .await;

    let result = client(&server)
        .check_delegated(
            Subject::user("usr_1"),
            vec!["agent:a1".into()],
            "orders.pay",
        )
        .await;
    assert!(!result.is_allowed(), "a pending step-up is not a grant");
}

// ---- introspection is mandatory ---------------------------------------------

#[tokio::test]
async fn the_view_comes_from_the_introspected_claims_not_the_local_bytes() {
    let server = MockServer::start().await;
    // The token says one hop and dgr_1; the server says two hops and dgr_server. The
    // server wins — that is what "server-side truth" means.
    mount_introspection(
        &server,
        json!({
            "active": true,
            "sub": "user:42",
            "act": { "sub": "agent:hop2", "act": { "sub": "agent:hop1" } },
            "pds_dgr": "dgr_server",
            "scope": "orders:read orders:draft",
        }),
        200,
    )
    .await;

    let bearer = client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .expect("introspection confirms")
        .expect("token is delegated");

    assert_eq!(bearer.sub, "user:42");
    assert_eq!(bearer.actors, vec!["agent:hop2", "agent:hop1"]);
    assert_eq!(bearer.grant_id.as_deref(), Some("dgr_server"));
    assert_eq!(bearer.scopes, vec!["orders:read", "orders:draft"]);
    assert!(bearer.verified);
}

#[tokio::test]
async fn introspection_receives_the_token_form_encoded() {
    let server = MockServer::start().await;
    let token = delegated_token();
    Mock::given(method("POST"))
        .and(path("/oauth/introspect"))
        .and(body_string_contains("token="))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "active": true, "sub": "user:42" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    assert!(client(&server).verify_delegated_token(&token).await.is_ok());
}

#[tokio::test]
async fn a_server_that_omits_act_keeps_the_local_chain() {
    let server = MockServer::start().await;
    mount_introspection(&server, json!({ "active": true, "sub": "user:42" }), 200).await;

    let bearer = client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(bearer.actors, vec!["agent:a1"]);
    assert_eq!(bearer.grant_id.as_deref(), Some("dgr_1"));
    assert_eq!(bearer.scopes, vec!["orders:read"]);
    assert!(bearer.verified);
}

#[tokio::test]
async fn an_inactive_token_is_refused() {
    // A revoked grant stops right here, inside the token's remaining lifetime.
    let server = MockServer::start().await;
    mount_introspection(&server, json!({ "active": false }), 200).await;

    assert!(client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .is_err());
}

#[tokio::test]
async fn unreachable_introspection_refuses_it_never_degrades_to_the_local_parse() {
    // The load-bearing case: the token looks perfectly well-formed and says `sub: user:42`.
    // Without introspection there is no way to know the user's session is still alive, so
    // the answer is deny — not "trust the bytes".
    let server = MockServer::start().await;
    mount_introspection(&server, json!({ "error": "boom" }), 500).await;

    assert!(client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .is_err());
}

#[tokio::test]
async fn introspection_disabled_refuses_delegated_tokens_outright() {
    let server = MockServer::start().await;
    let iam = IamClient::builder()
        .base_url(server.uri())
        .token("service-token")
        .introspection_url("")
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();

    assert!(matches!(
        iam.verify_delegated_token(&delegated_token()).await,
        Err(IamError::Config(_))
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_unreadable_act_from_the_server_is_refused() {
    let server = MockServer::start().await;
    mount_introspection(
        &server,
        json!({ "active": true, "sub": "user:42", "act": { "sub": "user:99" } }),
        200,
    )
    .await;

    assert!(client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .is_err());
}

#[tokio::test]
async fn introspection_without_sub_is_refused() {
    let server = MockServer::start().await;
    mount_introspection(
        &server,
        json!({ "active": true, "scope": "orders:read" }),
        200,
    )
    .await;

    assert!(client(&server)
        .verify_delegated_token(&delegated_token())
        .await
        .is_err());
}

// ---- routing: what is, and is not, this path --------------------------------

#[tokio::test]
async fn a_malformed_delegated_token_is_refused_before_any_network_call() {
    let server = MockServer::start().await;
    let broken = jwt_of(
        &json!({ "alg": "ES256" }),
        &json!({ "sub": "user:42", "act": { "sub": "not-an-agent" } }),
    );

    assert!(matches!(
        client(&server).verify_delegated_token(&broken).await,
        Err(IamError::TokenInvalid(_))
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_plain_token_is_not_this_paths_business() {
    let server = MockServer::start().await;
    let plain = jwt_of(
        &json!({ "alg": "ES256" }),
        &json!({ "sub": "user:42", "scope": "orders:read" }),
    );

    assert_eq!(
        client(&server)
            .verify_delegated_token(&plain)
            .await
            .unwrap(),
        None,
        "a non-delegated token is not an error here — verify it on the normal path"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
