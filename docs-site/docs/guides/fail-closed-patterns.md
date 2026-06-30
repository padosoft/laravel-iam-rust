# Fail-closed patterns

This guide is a cookbook of idioms for wiring the SDK into real call sites without ever leaving a gate
that can accidentally open. The principle behind them is in
[Fail-closed authorization](/concepts/fail-closed).

## The golden rule

At a gate, read [`ResultExt::is_allowed`](/reference/api) and nothing else:

```rust
use laravel_iam::ResultExt;

if iam.check(query).await.is_allowed() {
    // allow — the ONLY path that reaches here is an explicit server permit
} else {
    // deny — server denial OR any transport/parse failure
}
```

Because `is_allowed()` is implemented on `Result<Decision, IamError>`, you never have to unwrap, match,
or remember which error variants mean "deny". They all do.

## Anti-patterns to avoid

::: callout danger
```rust
// ❌ panics on a transport error instead of denying
if iam.check(q).await.unwrap().allowed { allow(); }

// ❌ reads the raw boolean — ignores requires_step_up
if let Ok(d) = iam.check(q).await { if d.allowed { allow(); } }

// ❌ treats an error as "allow" to "not block users during an outage"
let ok = iam.check(q).await.map(|d| d.granted()).unwrap_or(true); // NEVER
```
Each of these can open the gate on failure. Use `is_allowed()`.
:::

## Pattern: a reusable gate helper

```rust
use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};

async fn can(iam: &IamClient, user: &str, perm: &str, resource: &str) -> bool {
    iam.check(DecisionQuery {
        subject: Subject::user(user),
        permission: perm.into(),
        resource: Some(resource.into()),
        ..Default::default()
    }).await.is_allowed()
}

// at the call site
if !can(&iam, "usr_123", "stock.adjust", "wh_milan").await {
    return forbidden();
}
```

## Pattern: distinguishing deny from step-up

When the UX needs to *prompt* rather than hard-deny, branch on the `Ok` but keep `Err` as deny:

```rust
use laravel_iam::{Decision, IamError};

enum Gate { Allow, StepUp(Option<String>), Deny }

fn classify(result: Result<Decision, IamError>) -> Gate {
    match result {
        Ok(d) if d.granted()        => Gate::Allow,
        Ok(d) if d.requires_step_up => Gate::StepUp(d.required_aal),
        Ok(_)                       => Gate::Deny, // explicit policy deny
        Err(_)                      => Gate::Deny, // transport/parse failure
    }
}
```

## Pattern: deliberate outage tolerance (use with care)

Fail-closed is the default *because* silent fail-open is dangerous. If a specific, low-risk action must
remain available during an IAM outage, make that decision **explicit, scoped, logged, and owned** — at
the application layer, never in the transport:

```rust
use laravel_iam::IamError;

let decision = iam.check(low_risk_query).await;
let allow = match &decision {
    // Only a TIMEOUT or NETWORK error, only for an explicitly low-risk action,
    // and we record it loudly.
    Err(IamError::Timeout | IamError::Network(_)) => {
        tracing::warn!("IAM unreachable; degrading OPEN for low-risk action (audited)");
        true
    }
    _ => decision.is_allowed(), // everything else stays fail-closed
};
```

::: callout warning
This is an escape hatch, not a default. Never degrade open for a security-sensitive action, and never on
a `4xx`/`malformed`/`token` error (those are not outages — they are denials). When in doubt, deny.
:::

## Pattern: one shared client

`IamClient` is `Clone` and wraps `Arc`s, so cloning is cheap and the JWKS cache is shared. Build it once
(at startup) and clone it into handlers, rather than constructing one per request:

```rust
let iam = IamClient::builder()
    .base_url(std::env::var("IAM_BASE_URL")?)
    .token(std::env::var("IAM_SERVICE_TOKEN")?)
    .issuer(std::env::var("IAM_ISSUER")?)
    .audience(std::env::var("IAM_AUDIENCE")?)
    .build()?;

// store `iam` in app state; clone per request
```

## Checklist

::: steps
1. **Gates read `is_allowed()`** — not `allowed`, not `unwrap()`.
2. **Errors mean deny** — verified by treating `Err(_)` as the deny branch.
3. **Step-up handled** — `requires_step_up` prompts, it does not silently allow.
4. **Outage tolerance is explicit** — scoped, logged, owned; never in the transport.
5. **One client, shared** — so the JWKS cache and connection pool are reused.
:::

See also: [Fail-closed authorization](/concepts/fail-closed), [Integration patterns](/best-practices/integration).
