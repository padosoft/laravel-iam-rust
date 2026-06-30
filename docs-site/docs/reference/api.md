# API reference

The public surface of the crate. Canonical, generated docs live on
[docs.rs/laravel-iam](https://docs.rs/laravel-iam); this page is a curated quick reference.

## Re-exports (`laravel_iam`)

```rust
pub use IamClient;        // async client
pub use IamClientBuilder; // shared builder
pub use IamError;         // error taxonomy
pub use {Claims, Decision, DecisionQuery, Resource, Subject}; // wire types
pub trait ResultExt;      // fail-closed helper

#[cfg(feature = "blocking")]
pub mod blocking;         // synchronous IamClient
```

## `IamClient` (async)

| Method | Signature | Description |
|---|---|---|
| `builder` | `fn builder() -> IamClientBuilder` | Start configuring a client. |
| `check` | `async fn check(&self, query: DecisionQuery) -> Result<Decision, IamError>` | `POST {base}/decisions/check`. Fail-closed. |
| `list_resources` | `async fn list_resources(&self, subject: Subject, relation: impl AsRef<str>) -> Result<Vec<Resource>, IamError>` | `POST {base}/decisions/list-resources`. |
| `verify_token` | `async fn verify_token(&self, jwt: &str) -> Result<Claims, IamError>` | ES256 + `iss`/`aud`/`exp`/`nbf` against the cached JWKS. |

`IamClient` is `Clone` (cheap — wraps `Arc`s; clones share the JWKS cache and HTTP pool).

```rust
let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .token("svc")
    .build()?;

let decision = iam.check(query).await?;     // Result<Decision, IamError>
let res = iam.list_resources(subj, "viewer").await?; // Vec<Resource>
let claims = iam.verify_token(jwt).await?;   // Claims
```

## `blocking::IamClient` (feature `blocking`)

Same methods without `async`/`.await`; built with `build_blocking()`.

| Method | Signature |
|---|---|
| `builder` | `fn builder() -> IamClientBuilder` |
| `check` | `fn check(&self, query: DecisionQuery) -> Result<Decision, IamError>` |
| `list_resources` | `fn list_resources(&self, subject: Subject, relation: impl AsRef<str>) -> Result<Vec<Resource>, IamError>` |
| `verify_token` | `fn verify_token(&self, jwt: &str) -> Result<Claims, IamError>` |

See [The blocking client](/guides/blocking-client).

## `IamClientBuilder`

| Method | Signature | Notes |
|---|---|---|
| `base_url` | `fn base_url(self, impl Into<String>) -> Self` | Required. Trailing slash trimmed. |
| `token` | `fn token(self, impl Into<String>) -> Self` | `Authorization: Bearer`. |
| `timeout` | `fn timeout(self, Duration) -> Self` | Default 2s. |
| `issuer` | `fn issuer(self, impl Into<String>) -> Self` | Required by `verify_token`. |
| `audience` | `fn audience(self, impl Into<String>) -> Self` | Required by `verify_token`. |
| `build` | `fn build(self) -> Result<IamClient, IamError>` | Async client. |
| `build_blocking` | `fn build_blocking(self) -> Result<blocking::IamClient, IamError>` | Blocking client (feature `blocking`). |

All setters are `#[must_use]` and consume/return `self` for chaining. See
[Configuration](/operations/configuration).

## `ResultExt` — the fail-closed gate

```rust
pub trait ResultExt {
    fn is_allowed(&self) -> bool;
}

impl ResultExt for Result<Decision, IamError> {
    fn is_allowed(&self) -> bool {
        matches!(self, Ok(decision) if decision.is_allowed())
    }
}
```

`true` **only** when the call succeeded *and* the decision is `granted()` (allowed and no pending
step-up). Every `IamError` yields `false`.

```rust
use laravel_iam::ResultExt;
if iam.check(q).await.is_allowed() { /* allow */ } else { /* deny */ }
```

## `Decision` helpers

| Method | Returns | Meaning |
|---|---|---|
| `granted()` | `bool` | `allowed && !requires_step_up`. The fail-safe gate value. |
| `is_allowed()` | `bool` | Alias of `granted()`. |
| `deny(reason)` | `Decision` | Construct an explicit denial carrying a reason. |

Field reference is in [Types](/reference/types); error reference in [Error taxonomy](/reference/errors).

## Crate-level attributes

```rust
#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
```

No `unsafe` anywhere; the crate is clippy-pedantic clean.
