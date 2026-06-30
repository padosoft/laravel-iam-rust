# laravel-iam (Rust SDK)

[![tests](https://github.com/padosoft/laravel-iam-rust/actions/workflows/tests.yml/badge.svg)](https://github.com/padosoft/laravel-iam-rust/actions/workflows/tests.yml)
[![crates.io](https://img.shields.io/crates/v/laravel-iam.svg)](https://crates.io/crates/laravel-iam)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A thin, **fail-closed** Rust client for the [Laravel IAM](https://github.com/padosoft) authorization
server. It asks the control plane for policy decisions and verifies OIDC tokens — and it is built
so that a gate **cannot accidentally open**.

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
| `IamClient::builder()` | `base_url`, `token`, `timeout` (default 2s), `issuer`, `audience` → `build()` / `build_blocking()` |
| `check(DecisionQuery) -> Result<Decision, IamError>` | `POST {base_url}/decisions/check` |
| `list_resources(Subject, relation) -> Result<Vec<Resource>, IamError>` | `POST {base_url}/decisions/list-resources` |
| `verify_token(jwt) -> Result<Claims, IamError>` | ES256 + `iss`/`aud`/`exp` against the cached JWKS |
| `Decision::granted()` / `is_allowed()` | allowed **and** no pending step-up |
| `Result::is_allowed()` (via `ResultExt`) | the fail-closed gate: any error ⇒ `false` |

### Errors

All variants of `IamError` (`Network`, `Timeout`, `Unauthorized`, `Http`, `Malformed`,
`TokenInvalid`, `Config`) mean "could not obtain a permit" and must be treated as **deny** — which
`ResultExt::is_allowed` does for you.

## Wire contract

This client mirrors the PHP `HttpDecider` exactly:

- **Endpoint:** `POST {base_url}/decisions/check`
- **Headers:** `Accept: application/json`, `Authorization: Bearer <service token>`
- **Request body:** `{ subject: {type, id}, permission, organization, application, resource,
  context, current_aal, explain }`
- **Response:** `{ allowed, decision_id, policy_version, requires_step_up, required_aal,
  explanation }`, parsed defensively (any wrong-typed field falls back to its safe default; a
  non-object body is a deny).

## License

MIT © Padosoft. See [LICENSE](LICENSE).
