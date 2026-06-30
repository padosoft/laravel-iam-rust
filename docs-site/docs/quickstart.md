# Quickstart

This page takes you from an empty `Cargo.toml` to a working, fail-closed authorization gate in a few
minutes. It assumes you have a running [Laravel IAM server](https://doc.laravel-iam-server.padosoft.com)
and a service token (Client Credentials).

## 1. Add the dependency

```toml
[dependencies]
laravel-iam = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde_json = "1"
```

The crate is async-first and built on `reqwest` + `tokio`. If you want the synchronous client instead,
enable the [`blocking` feature](/guides/blocking-client).

## 2. Build a client

```rust
use std::time::Duration;
use laravel_iam::IamClient;

let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .token(std::env::var("IAM_SERVICE_TOKEN")?) // Client Credentials service token
    .timeout(Duration::from_secs(2))            // default is already 2s
    .build()?;
```

::: callout info
The `base_url` is the **versioned API root** (`/api/iam/v1`), not the bare host. The SDK appends the
endpoint paths (`/decisions/check`, `/decisions/list-resources`, `/.well-known/jwks.json`). A trailing
slash is trimmed for you.
:::

## 3. Ask for a decision

```rust
use laravel_iam::{DecisionQuery, Subject, ResultExt};
use serde_json::json;

let decision = iam.check(DecisionQuery {
    subject: Subject::user("usr_123"),
    application: Some("warehouse".into()),
    permission: "stock.adjust".into(),
    resource: Some("wh_milan".into()),
    context: json!({ "amount": 300 }),
    ..Default::default()
}).await;

if decision.is_allowed() {
    // allow — the ONLY path here is an explicit server permit
} else {
    // deny — server denial OR any transport/parse failure
}
```

`check()` returns `Result<Decision, IamError>`. The [`ResultExt::is_allowed`](/reference/api) helper —
brought into scope by `use laravel_iam::ResultExt;` — collapses **every** error into `false`, so the
gate cannot accidentally open. This is the heart of the SDK; see
[Fail-closed authorization](/concepts/fail-closed).

## 4. The full program

```rust
use std::time::Duration;
use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iam = IamClient::builder()
        .base_url("https://iam.example.com/api/iam/v1")
        .token(std::env::var("IAM_SERVICE_TOKEN")?)
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

    if !decision.is_allowed() {
        return Err("forbidden".into()); // fail-closed
    }

    println!("allowed");
    Ok(())
}
```

## 5. Inspect the decision (optional)

When you need the details — auditing, or driving a step-up flow — match on the `Ok(Decision)`:

```rust
use laravel_iam::{Decision, IamError};

match iam.check(query).await {
    Ok(d) if d.granted()         => { /* allow */ }
    Ok(d) if d.requires_step_up  => { /* prompt step-up to d.required_aal */ }
    Ok(_)                        => { /* explicit deny */ }
    Err(_)                       => { /* transport/parse failure → deny */ }
}
```

`granted()` is `allowed && !requires_step_up`. See [Core concepts](/core-concepts) for the difference
between `allowed`, `granted()`, and `ResultExt::is_allowed()`.

## Next steps

::: grids
::: grid
::: card "Verify tokens" icon:key-round
Validate OIDC access tokens against the server's JWKS.

[Verifying tokens →](/guides/verifying-tokens)
:::
:::
::: grid
::: card "Fail-closed patterns" icon:shield
Idioms for wiring `is_allowed()` into middleware and gates.

[Fail-closed patterns →](/guides/fail-closed-patterns)
:::
:::
::: grid
::: card "Configuration" icon:settings
Timeouts, issuer/audience, environment-driven setup.

[Configuration →](/operations/configuration)
:::
:::
:::
