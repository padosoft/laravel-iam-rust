# The blocking client

The default [`IamClient`](/reference/api) is async. When you are not in an async context — a CLI tool, a
build script, a synchronous worker — enable the `blocking` feature to get a synchronous twin with
**identical** fail-closed semantics.

## Enable the feature

```toml
[dependencies]
laravel-iam = { version = "1", features = ["blocking"] }
```

This turns on `reqwest/blocking` and exposes `laravel_iam::blocking::IamClient`.

## Build and use

The builder is shared; you just finish it with `build_blocking()` instead of `build()`:

```rust
use laravel_iam::{blocking::IamClient, DecisionQuery, Subject, ResultExt};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iam = IamClient::builder()
        .base_url("https://iam.example.com/api/iam/v1")
        .token(std::env::var("IAM_SERVICE_TOKEN")?)
        .build_blocking()?;                       // <- not build()

    let decision = iam.check(DecisionQuery {
        subject: Subject::user("usr_123"),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        context: json!({ "amount": 300 }),
        ..Default::default()
    });                                           // <- no .await

    if !decision.is_allowed() {
        return Err("forbidden".into());
    }
    Ok(())
}
```

The API surface is the same minus `.await`: `check()`, `list_resources()`, `verify_token()`, and the
same [`Decision`](/reference/types) / [`Claims`](/reference/types) / [`IamError`](/reference/errors)
types. `ResultExt::is_allowed` works identically on the blocking result.

## Identical semantics by construction

The async and blocking clients are **not** parallel reimplementations. Everything that does not depend
on *how bytes move over the network* — URL construction, HTTP-status mapping, response parsing, and JWT
verification — lives in one transport-agnostic `wire` module. Both clients call into it, so they apply
**byte-identical**, fail-closed rules. The only difference is `reqwest::Client` vs
`reqwest::blocking::Client` and `tokio::sync::RwLock` vs `std::sync::RwLock` for the JWKS cache.

See [The check flow](/architecture/check-flow) for the shared pipeline, and
[ADR-0002](/architecture/decisions) for why both clients exist.

## The one rule

::: callout danger
**Never call the blocking client from inside an async runtime thread.** `reqwest::blocking` drives its
own internal runtime; calling it from a `tokio` worker thread can deadlock or panic. If you are already
in async code, use the async [`IamClient`](/reference/api). If you must bridge, hand the call to
`tokio::task::spawn_blocking`.
:::

## When to choose blocking

::: tabs
== tab "Use blocking"

- Command-line tools and one-shot scripts.
- `build.rs` / tooling with no runtime.
- Synchronous services or libraries that have no async stack.

== tab "Use async (default)"

- Web servers and request handlers (`axum`, `actix`, `warp`, …).
- Anything already running under `tokio`.
- High-concurrency workloads where threads-per-request is wasteful.

:::

## Gotchas

::: callout warning
- **`build_blocking()`, not `build()`** — calling `build()` after enabling the feature gives you the
  async client.
- **No `.await`** on blocking methods; adding one will not compile.
- **Don't mix** — pick one client per call site; do not call blocking methods from async tasks.
:::
