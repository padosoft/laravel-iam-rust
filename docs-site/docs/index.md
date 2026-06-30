---
title: "laravel-iam (Rust SDK)"
description: "A thin, fail-closed Rust client for the Laravel IAM authorization server — async + optional blocking, pure-Rust ES256/JWKS token verification."
---

# laravel-iam — Rust SDK

A thin, **fail-closed** Rust client for the [Laravel IAM](https://github.com/padosoft) authorization
server. It asks the control plane for policy decisions and verifies OIDC tokens — and it is built so
that a gate **cannot accidentally open**.

> Same wire contract as the production PHP client (`Padosoft\Iam\Client`), different language.
> No policy logic lives on the client: every decision belongs to the server.

The crate is published as [`laravel-iam` on crates.io](https://crates.io/crates/laravel-iam)
(API docs on [docs.rs/laravel-iam](https://docs.rs/laravel-iam)).

::: callout info
**New here?** Jump to the [Quickstart](/quickstart) for a five-minute integration, or read
[Core concepts](/core-concepts) to understand what "fail-closed" buys you before you write a line of code.
:::

## Why this SDK exists

Authorization clients fail in the worst possible way when they fail *open*: a timeout or a `500`
quietly becomes "allow", and a security boundary evaporates exactly when the system is already under
stress. This SDK makes that outcome impossible **by construction**:

- A network error, timeout, `5xx`, `4xx`, malformed body or unverifiable token **always** maps to **deny**.
- There is **no** fail-open switch. If you must tolerate an outage, do it deliberately at the
  application layer — never silently in the transport.
- An `allowed` decision that still `requires_step_up` is treated as **not yet allowed**.

## What it does

::: grids
::: grid
::: card "Remote decisions" icon:shield-check
`check()` posts a [`DecisionQuery`](/reference/types) to `POST {base}/decisions/check` and returns a
normalized [`Decision`](/reference/types). The server holds all RBAC + ABAC + ReBAC policy.

[Checking decisions →](/guides/checking-decisions)
:::
:::
::: grid
::: card "Token verification" icon:key-round
`verify_token()` checks an **ES256** signature against the server's cached **JWKS**, then validates
`iss` / `aud` / `exp` / `nbf` — all in pure-Rust crypto (`p256`).

[Verifying tokens →](/guides/verifying-tokens)
:::
:::
::: grid
::: card "ReBAC listing" icon:list-tree
`list_resources()` answers "which resources can this subject reach under relation *r*?" via
`POST {base}/decisions/list-resources`.

[Listing resources →](/guides/listing-resources)
:::
:::
:::

## A taste

```rust
use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iam = IamClient::builder()
        .base_url("https://iam.example.com/api/iam/v1")
        .token(std::env::var("IAM_SERVICE_TOKEN")?)
        .build()?;

    let allowed = iam.check(DecisionQuery {
        subject: Subject::user("usr_123"),
        application: Some("warehouse".into()),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        context: json!({ "amount": 300 }),
        ..Default::default()
    }).await.is_allowed(); // <- ANY error collapses to `false`

    if !allowed { return Err("forbidden".into()); }
    Ok(())
}
```

The whole design is in that last comment: `is_allowed()` is `true` **only** on an explicit server
permit. Read [Fail-closed authorization](/concepts/fail-closed) for the full argument.

## Ecosystem

`laravel-iam-rust` is one client SDK in the **Laravel IAM** suite. The server is the policy authority;
the SDKs and clients only transport the question and the answer.

| Package | Role |
|---|---|
| [`laravel-iam-server`](https://doc.laravel-iam-server.padosoft.com) | The IAM server: identity, org, Application Registry + manifest, PDP (RBAC+ABAC+ReBAC), OAuth/OIDC, tamper-evident audit, IGA, Admin API + panel. |
| [`laravel-iam-contracts`](https://doc.laravel-iam-contracts.padosoft.com) | Shared contracts/interfaces + DTOs (PDP, KeyProvider, Assurance, FeatureScope). |
| [`laravel-iam-client`](https://doc.laravel-iam-client.padosoft.com) | Laravel client for consumer apps: OIDC login, JWT/JWKS verify, introspection, `iam.auth`/`iam.can` middleware, Gate adapter. |
| [`laravel-iam-node`](https://doc.laravel-iam-node.padosoft.com) | Node/TS SDK (`@padosoft/laravel-iam-node`), thin + fail-closed. |
| [`laravel-iam-react-native`](https://doc.laravel-iam-react-native.padosoft.com) | React Native SDK (`@padosoft/laravel-iam-react-native`), thin + hooks. |
| **`laravel-iam-rust`** | **This package** — Rust SDK (crate `laravel-iam`), async + blocking, fail-closed. |
| [`laravel-iam-ai`](https://doc.laravel-iam-ai.padosoft.com) | Optional advisory-only AI module (redaction + hallucination-guard + audit). |
| [`laravel-iam-directory`](https://doc.laravel-iam-directory.padosoft.com) | Optional LDAP / Active Directory module (LdapRecord). |
| [`laravel-iam-bridge-spatie-permission`](https://doc.laravel-iam-bridge-spatie-permission.padosoft.com) | Migration bridge from `spatie/laravel-permission`. |

All SDKs and the PHP client speak the **same wire contract** — see [The wire contract](/concepts/wire-contract).

## Where to go next

::: steps
1. **Install the crate**
   Add `laravel-iam` to `Cargo.toml`. See [Installation](/installation).

2. **Run the Quickstart**
   A working async gate in a few lines. See [Quickstart](/quickstart).

3. **Understand the model**
   [Core concepts](/core-concepts) and [Fail-closed authorization](/concepts/fail-closed).

4. **Go deep**
   [Architecture overview](/architecture/overview), the [check flow](/architecture/check-flow), and the
   [API reference](/reference/api).
:::
