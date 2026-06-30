# Integration patterns

Practical guidance for wiring the SDK into a Rust service so it is correct, fast, and easy to operate.

## Build one client, share it

`IamClient` is `Clone` and internally holds `Arc`s (the HTTP client, the config, the JWKS cache), so
cloning is cheap and clones **share** the JWKS cache and connection pool. Construct it once at startup,
store it in application state, and clone per request.

```rust
use laravel_iam::IamClient;

let iam = IamClient::builder()
    .base_url(std::env::var("IAM_BASE_URL")?)
    .token(std::env::var("IAM_SERVICE_TOKEN")?)
    .issuer(std::env::var("IAM_ISSUER")?)
    .audience(std::env::var("IAM_AUDIENCE")?)
    .build()?;
// e.g. axum: .with_state(AppState { iam })
```

::: callout warning
Do **not** build a fresh client per request — you would re-fetch the JWKS every time and lose connection
reuse.
:::

## Authorize at the boundary

Put the gate at the edge of the protected action (middleware, handler entry), and read
[`is_allowed()`](/reference/api):

```rust
use laravel_iam::{DecisionQuery, Subject, ResultExt};

async fn handler(state: AppState, user_id: String) -> Response {
    let ok = state.iam.check(DecisionQuery {
        subject: Subject::user(&user_id),
        permission: "stock.adjust".into(),
        resource: Some("wh_milan".into()),
        ..Default::default()
    }).await.is_allowed();

    if !ok { return forbidden(); }
    perform_action()
}
```

## Pass real ABAC context

The `context` field is where attribute-based rules get their facts. Send what the policy needs — amounts,
time, IP, request shape — as a `serde_json::Value`:

```rust
use serde_json::json;

let context = json!({
    "amount": order.total_cents,
    "currency": order.currency,
    "ip": client_ip.to_string(),
});
```

Keep it to the facts the server's policies actually consult; don't dump the whole request.

## Choose timeouts deliberately

The default per-request timeout is **2s**. Authorization sits on the critical path, so a tight timeout is
usually right — a slow IAM should fail fast to a deny rather than stall the request:

```rust
use std::time::Duration;
let iam = builder.timeout(Duration::from_millis(800)).build()?;
```

Pair a tight timeout with monitoring on `IamError::Timeout` rates (see
[Troubleshooting](/operations/troubleshooting)).

## Separate authentication from authorization

A common shape: verify the token once at the edge to authenticate, then `check()` for each protected
action.

::: steps
1. **Authenticate.** `verify_token(jwt)` → `claims.sub` is the principal. Reject on `Err`.
2. **Authorize.** Build `Subject::user(claims.sub)` and `check()` the specific permission/resource.
3. **Audit.** Log `decision_id` + `policy_version` from the `Ok(Decision)` for traceability.
:::

## Map errors to HTTP honestly

Both the authorization deny and any transport error map to "not allowed", but you may want different HTTP
statuses for observability:

```rust
use laravel_iam::{Decision, IamError};

match iam.check(q).await {
    Ok(d) if d.granted()           => ok(),
    Ok(d) if d.requires_step_up    => step_up(d.required_aal),   // 401 + WWW-Authenticate
    Ok(_)                          => forbidden(),               // 403 explicit deny
    Err(IamError::Unauthorized(_)) => bad_gateway("iam creds"),  // your service token is wrong
    Err(_)                         => forbidden(),               // fail-closed default
}
```

Note `Unauthorized` here means **your service token** was rejected, not the end user — alert on it.

## Concurrency

`check()` and `verify_token()` are independent and safe to run concurrently across cloned clients. For a
batch authorization, issue calls concurrently with `futures::future::join_all` (async) rather than
serially.

## Gotchas

::: callout warning
- **One client, cloned** — not one per request.
- **Tight timeouts** on the auth path; monitor timeout rates.
- **`Unauthorized` is your problem** — it means the service token is bad, not the user.
- **Don't cache decisions yourself** unless you also track `policy_version` for invalidation.
:::

See also: [Fail-closed patterns](/guides/fail-closed-patterns), [Configuration](/operations/configuration),
[Security](/best-practices/security).
