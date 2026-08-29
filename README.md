# laravel-iam (Rust SDK)

[![tests](https://github.com/padosoft/laravel-iam-rust/actions/workflows/tests.yml/badge.svg)](https://github.com/padosoft/laravel-iam-rust/actions/workflows/tests.yml)
[![crates.io](https://img.shields.io/crates/v/laravel-iam.svg)](https://crates.io/crates/laravel-iam)
[![docs.rs](https://img.shields.io/docsrs/laravel-iam.svg)](https://docs.rs/laravel-iam)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A thin, **fail-closed** Rust client for the [Laravel IAM](https://github.com/padosoft) authorization
server. It asks the control plane for policy decisions and verifies OIDC tokens — and it is built
so that a gate **cannot accidentally open**.

📖 **Documentation:** [doc.laravel-iam-rust.padosoft.com](https://doc.laravel-iam-rust.padosoft.com)
· **Crate:** [crates.io/crates/laravel-iam](https://crates.io/crates/laravel-iam)
· **API docs:** [docs.rs/laravel-iam](https://docs.rs/laravel-iam)

> Same wire contract as the production PHP client (`Padosoft\Iam\Client`), different language.
> No policy logic lives on the client: every decision belongs to the server.

## Why

Authorization clients fail in the worst possible way when they fail *open* — a timeout or a 500
quietly becomes "allow". This SDK makes that impossible by construction:

- A network error, timeout, 5xx, 4xx, malformed body or unverifiable token **always** maps to **deny**.
- There is **no** fail-open switch. (If you need to tolerate an outage, do it deliberately at the
  application layer — never silently in the transport.)
- An `allowed` decision that still `requires_step_up` is treated as **not yet allowed**.

## Install

```toml
[dependencies]
laravel-iam = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Enable the synchronous client with the `blocking` feature:

```toml
laravel-iam = { version = "1", features = ["blocking"] }
```

## Quick start

```rust
use std::time::Duration;
use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iam = IamClient::builder()
        .base_url("https://iam.example.com/api/iam/v1")
        .token(std::env::var("IAM_SERVICE_TOKEN")?) // Client Credentials service token
        .timeout(Duration::from_secs(2))
        .build()?;

    let decision = iam.check(DecisionQuery {
        subject: Subject::user("usr_123"),
        application: Some("warehouse".into()),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        context: json!({ "amount": 300 }),
        ..Default::default()
    }).await;

    // `decision` is `Result<Decision, IamError>`.
    // On ANY error — network, timeout, 5xx, 4xx, malformed — this is `false`.
    if !decision.is_allowed() {
        return Err("forbidden".into()); // fail-closed
    }

    Ok(())
}
```

### The fail-closed note (read this)

`check()` returns `Result<Decision, IamError>`. The [`ResultExt::is_allowed`] helper is the safe
gate: it is `true` **only** when the call succeeded *and* the decision is truly granted (allowed
with no pending step-up). Every other outcome — including every error variant — is `false`.

```rust
# use laravel_iam::ResultExt;
# async fn demo(iam: laravel_iam::IamClient, q: laravel_iam::DecisionQuery) {
if iam.check(q).await.is_allowed() {
    // allow — the ONLY path that reaches here is an explicit server permit
} else {
    // deny — network error, timeout, 4xx/5xx, malformed body, or an explicit server deny
}
# }
```

If you need the details (auditing, step-up flows), inspect the `Ok(Decision)`:

```rust
# use laravel_iam::{Decision, IamError};
# fn demo(decision: Result<Decision, IamError>) {
match decision {
    Ok(d) if d.granted() => { /* allow */ }
    Ok(d) if d.requires_step_up => { /* prompt step-up to d.required_aal */ }
    Ok(_)  => { /* explicit deny */ }
    Err(_) => { /* transport/parse failure → deny */ }
}
# }
```

## Token verification

`verify_token` validates an ES256 signature against the server's JWKS
(`{base_url}/.well-known/jwks.json`, cached) plus the `iss` / `aud` / `exp` / `nbf` claims. Configure
the expected issuer and audience on the builder:

```rust
# use std::error::Error;
# fn demo() -> Result<(), Box<dyn Error>> {
use laravel_iam::IamClient;

let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .issuer("https://iam.example.com")
    .audience("warehouse-api")
    .build()?;
# let _ = iam;
# Ok(())
# }
```

```rust
# async fn demo(iam: laravel_iam::IamClient, jwt: &str) {
match iam.verify_token(jwt).await {
    Ok(claims) => { /* trusted: claims.sub, claims.iss, ... */ }
    Err(_)     => { /* reject — bad signature, expired, wrong aud/iss, unknown key, ... */ }
}
# }
```

## API

| Method | Description |
|---|---|
| `IamClient::builder()` | `base_url`, `token` **or** `client_id`+`client_secret` (+`oauth_url`), `timeout` (default 2s), `issuer`, `audience`, `introspection_url` → `build()` / `build_blocking()` |
| `check_delegated` / `check_delegated_with` | A decision for an **agent acting on behalf of a user** (strict intersection). |
| `verify_delegated_token` | Verify a delegated bearer through RFC 7662 introspection. |

### Authentication: static token, `client_credentials`, or `private_key_jwt`

Authenticate to the PDP in one of three ways (highest precedence first):

- **`private_key_jwt` — asymmetric, no shared secret (strongest)**: pass `.client_id(...)` and
  `.private_key(pem)` (an ES256 PKCS#8 PEM, `.private_key_kid(...)` optional). The client signs a short-lived
  assertion per token request instead of sending a secret. Register the matching **public** key (JWKS) in
  IAM. Both the async and `blocking` clients support it.

  ```rust
  let iam = IamClient::builder()
      .base_url("https://iam.example.com/api/iam/v1")
      .client_id("cli_warehouse")
      .private_key(std::fs::read_to_string("iam-client.pem")?) // ES256 PKCS#8 PEM
      .private_key_kid("k1")
      .build()?;
  ```

  Full guide: [private_key_jwt](https://doc.laravel-iam-server.padosoft.com/guides/private-key-jwt).

- **Static token** (`.token(...)`): a service bearer obtained out of band.
- **Self-managed `client_credentials`** (recommended for long-lived services): pass `.client_id(...)`
  and `.client_secret(...)`. The client mints and refreshes its own access token, and when IAM
  **auto-rotates** the secret it **self-fetches** the new one (during the grace) and hot-swaps it — the
  service never breaks on a rotation and no secret is handled by hand. Takes precedence over `token`.

```rust
let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .client_id("cli_warehouse")
    .client_secret(std::env::var("IAM_CLIENT_SECRET")?) // rotatable; followed automatically
    // .oauth_url("https://iam.example.com/oauth")       // optional; derived from base_url if omitted
    .build()?;
```

Enable the self-fetch endpoint server-side with `IAM_OAUTH_CLIENT_SELFFETCH=true`. Both the async and
`blocking` clients support it. See
[Application credentials & lifecycle](https://doc.laravel-iam-server.padosoft.com/guides/application-credentials).
| `check(DecisionQuery) -> Result<Decision, IamError>` | `POST {base_url}/decisions/check` |
| `list_resources(Subject, relation) -> Result<Vec<Resource>, IamError>` | `POST {base_url}/decisions/list-resources` |
| `submit_manifest(Option<&str>, &Value) -> Result<Value, IamError>` | `POST {base_url}/applications/{app}/manifests` |
| `verify_token(jwt) -> Result<Claims, IamError>` | ES256 + `iss`/`aud`/`exp` against the cached JWKS |
| `validate_manifest(&Value) -> ManifestValidation` | local check vs `laravel-iam.manifest.v2` (no network) |
| `Decision::granted()` / `is_allowed()` | allowed **and** no pending step-up |
| `Result::is_allowed()` (via `ResultExt`) | the fail-closed gate: any error ⇒ `false` |

### Declare & sync a manifest

A service that owns a permission catalog **declares** it in a manifest (a versioned file — the source of
truth) and pushes it to IAM. `validate_manifest` checks it locally (mirrors the server + the published schema
at `/.well-known/iam-manifest-schema.json`); `submit_manifest` pushes it (bearer needs `iam:manifests.submit`).

```rust
let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("iam.manifest.json")?)?;
let v = laravel_iam::validate_manifest(&manifest);
if !v.valid { return Err(format!("invalid manifest: {}", v.errors.join("; ")).into()); }

// IAM diffs it: additive changes apply, a removal is gated for approval and DEPRECATED (kept, disabled).
let result = iam.submit_manifest(None, &manifest).await?; // app.key comes from the manifest
```

See [Keeping IAM in sync](https://doc.laravel-iam-server.padosoft.com/guides/keeping-in-sync).

### Delegated access (agents acting for users)

When an **AI agent acts on behalf of a user**, the token carries *two* identities: `sub` is the user, `act` is the agent (nested outermost-first when the chain is longer than one hop — RFC 8693 §4.1). The verdict is the **strict intersection** of what the user may do and what *every* actor in the chain may do — never the union. Adding a hop can only narrow authority; it can never grant anything new.

```rust
use laravel_iam::{DecisionQuery, IamClient, ResultExt, Subject};

# async fn run(iam: IamClient, token: &str) -> Result<(), Box<dyn std::error::Error>> {
// Delegated tokens are introspection-mandatory: this call asks the server.
let Some(bearer) = iam.verify_delegated_token(token).await? else {
    return Ok(()); // not a delegated token — verify it with `verify_token` instead
};

let allowed = iam.check_delegated_with(DecisionQuery {
    subject: Subject::user(&bearer.sub),      // the USER — never the agent
    permission: "orders.draft".into(),
    resource: Some("ord_1".into()),
    actors: bearer.actors.clone(),            // current actor first
    delegation_grant_id: bearer.grant_id.clone(),
    ..Default::default()
}).await.is_allowed();
# let _ = allowed;
# Ok(())
# }
```

Three rules the SDK enforces for you, because getting any of them wrong turns delegation into an escalation path:

- **Introspection is mandatory.** `verify_delegated_token` never builds its answer from the local bytes: it calls the server's `/oauth/introspect`, which re-checks the signature, the expiry **and that the user's session is still alive**. Unreachable introspection is a deny, not a fallback. `typ: delegated+jwt` is routing, not a defence. Configure the endpoint with `.introspection_url(…)` (defaults to `<oauth_base>/introspect`); pass `""` to refuse delegated tokens outright.
- **A malformed `act` is refused; an absent one is not.** No `act` means "not delegated, use the normal path" (`Ok(None)`). An *unreadable* `act` is an error — silently degrading it into a full-authority user token is precisely the confused deputy delegation exists to prevent.
- **An empty actor chain is refused**, never a fall-back to the user-only check: it means the caller lost track of who is acting.

The plain-check body is unchanged — `actors` and `delegation_grant_id` are skipped when empty, so an older server that never heard of delegation is unaffected. This crate holds **no decision cache**, so a delegated verdict is always fresh by construction.

Requires [`laravel-iam-agents`](https://github.com/padosoft/laravel-iam-agents) on the server. Available on both the async and `blocking` clients.

### Errors

All variants of `IamError` (`Network`, `Timeout`, `Unauthorized`, `Http`, `Malformed`,
`TokenInvalid`, `Config`) mean "could not obtain a permit" and must be treated as **deny** — which
`ResultExt::is_allowed` does for you.

## Wire contract

This client mirrors the PHP `HttpDecider` exactly:

- **Endpoint:** `POST {base_url}/decisions/check` — or `POST {base_url}/decisions/check-delegated`
  when an act chain is present
- **Headers:** `Accept: application/json`, `Authorization: Bearer <service token>`
- **Request body:** `{ subject: {type, id}, permission, organization, application, resource,
  context, current_aal, explain }`, plus `actors` and `delegation_grant_id` on delegated
  queries only — a plain check's body is byte-identical to what it has always been
- **Introspection:** `POST {oauth_base}/introspect` (form-encoded, RFC 7662), for delegated tokens
- **Response:** `{ allowed, decision_id, policy_version, requires_step_up, required_aal,
  explanation }`, parsed defensively (any wrong-typed field falls back to its safe default; a
  non-object body is a deny).

## Ecosystem

This SDK is one client in the **Laravel IAM** suite. The server is the policy authority; the SDKs and
clients only transport the question and the answer.

| Package | Role |
|---|---|
| [`laravel-iam-server`](https://github.com/padosoft/laravel-iam-server) | The IAM server: identity, org, Application Registry, PDP (RBAC+ABAC+ReBAC), OAuth/OIDC, tamper-evident audit, IGA, Admin API. |
| [`laravel-iam-contracts`](https://github.com/padosoft/laravel-iam-contracts) | Shared contracts/interfaces + DTOs. |
| [`laravel-iam-client`](https://github.com/padosoft/laravel-iam-client) | Laravel client for consumer apps (OIDC login, JWT/JWKS verify, middleware, Gate adapter). |
| [`laravel-iam-node`](https://github.com/padosoft/laravel-iam-node) | Node/TS SDK (`@padosoft/laravel-iam-node`), thin + fail-closed. |
| [`laravel-iam-react-native`](https://github.com/padosoft/laravel-iam-react-native) | React Native SDK (`@padosoft/laravel-iam-react-native`). |
| **`laravel-iam-rust`** | **This package** — Rust SDK (crate `laravel-iam`), async + blocking, fail-closed. |

All SDKs and the PHP client speak the **same wire contract**. Full docs:
[doc.laravel-iam-rust.padosoft.com](https://doc.laravel-iam-rust.padosoft.com).

## License

MIT © Padosoft. See [LICENSE](LICENSE).
