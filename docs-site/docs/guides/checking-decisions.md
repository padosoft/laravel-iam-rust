# Checking decisions

`check()` is the core operation: it asks the server "may this subject perform this permission on this
resource?" and returns a normalized [`Decision`](/reference/types). This guide covers building the query,
reading the answer, and the fail-closed contract around it.

## Motivation

You want a single, unambiguous yes/no for an action, with the policy decision made centrally on the
server. The client must never invent an "allow" — if it cannot reach the server or cannot understand the
answer, the only safe response is **deny**.

## The call

```rust
use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};
use serde_json::json;

let decision = iam.check(DecisionQuery {
    subject: Subject::user("usr_123"),
    application: Some("warehouse".into()),
    permission: "stock.adjust".into(),
    resource: Some("wh_milan".into()),
    context: json!({ "amount": 300 }),
    ..Default::default()
}).await;

if !decision.is_allowed() {
    // deny
}
```

`check()` performs `POST {base_url}/decisions/check` with `Accept: application/json` and, when a token is
configured, `Authorization: Bearer <token>`.

## Building the query

[`DecisionQuery`](/reference/types) implements `Default`, so use struct-update syntax and only set what
you need:

| Field | Type | Default | Notes |
|---|---|---|---|
| `subject` | `Subject` | empty | **Required.** Use `Subject::user(..)` etc. |
| `permission` | `String` | `""` | **Required.** The ability, e.g. `stock.adjust`. |
| `organization` | `Option<String>` | `None` | Tenancy scope. |
| `application` | `Option<String>` | `None` | App scope. |
| `resource` | `Option<String>` | `None` | Encoded as a **plain string**, not an object — mirrors the PHP client. |
| `context` | `Value` | `{}` | ABAC facts. |
| `current_aal` | `String` | `"aal1"` | The subject's current assurance level. |
| `explain` | `bool` | `false` | Ask the server to include `explanation` lines. |

There is also a convenience constructor for the common case:

```rust
// subject + permission, everything else defaulted
let q = DecisionQuery::new(Subject::user("usr_123"), "stock.adjust");
```

::: callout info
`resource` is a string (`"wh_milan"`), not a `{type, id}` object. This intentionally matches the PHP
`DecisionRequest::toArray()` wire shape so every IAM SDK is byte-compatible. See
[The wire contract](/concepts/wire-contract).
:::

## Reading the answer

For a gate, read [`ResultExt::is_allowed`](/reference/api) and stop there. When you need detail, match on
the `Ok`:

```rust
use laravel_iam::{Decision, IamError};

match iam.check(query).await {
    Ok(d) if d.granted()        => grant(),
    Ok(d) if d.requires_step_up => prompt_step_up(d.required_aal),
    Ok(_)                       => deny("policy denied"),
    Err(IamError::Timeout)      => deny("iam timeout"),
    Err(e)                      => deny(&format!("iam error: {e}")),
}
```

A [`Decision`](/reference/types) carries:

| Field | Meaning |
|---|---|
| `allowed` | raw server boolean (true only if the server sent `true`) |
| `granted()` | `allowed && !requires_step_up` — the fail-safe gate value |
| `decision_id` | opaque id for audit/correlation |
| `policy_version` | policy version that produced the decision (cache invalidation) |
| `requires_step_up` | the action needs a higher assurance level first |
| `required_aal` | the level needed when `requires_step_up` is set |
| `explanation` | human-readable lines (present when `explain: true`) |

## Defensive parsing

The response is parsed with the same rules as the PHP `IamDecision::fromArray`:

- A non-2xx status is an error before the body is even read — see [the check flow](/architecture/check-flow).
- A body that is not a JSON **object** is [`IamError::Malformed`](/reference/errors) → deny.
- Any individual field that is missing or wrong-typed falls back to its **safe default**
  (`allowed → false`, `policy_version → 0`, etc.).
- `allowed` is `true` **only** when the server sent the boolean `true`.

So a successful HTTP 200 with `{ "decision_id": "x" }` (no `allowed`) parses cleanly to a **deny**.

## Worked example: a step-up sensitive action

```rust
use laravel_iam::{DecisionQuery, Subject};
use serde_json::json;

let query = DecisionQuery {
    subject: Subject::user("usr_123"),
    application: Some("banking".into()),
    permission: "wire.transfer".into(),
    resource: Some("acct_42".into()),
    context: json!({ "amount": 50_000, "currency": "EUR" }),
    current_aal: "aal1".into(),
    explain: true,
    ..Default::default()
};

match iam.check(query).await {
    Ok(d) if d.granted() => execute_transfer(),
    Ok(d) if d.requires_step_up => {
        // The user is allowed in principle but must re-auth at a higher level.
        redirect_to_step_up(d.required_aal.as_deref().unwrap_or("aal2"));
    }
    _ => deny(), // explicit deny OR any error — fail-closed
}
```

## Gotchas

::: callout warning
- **`allowed` is not enough.** An `allowed` decision with `requires_step_up: true` must be treated as
  *not yet allowed*. Use `granted()` / `is_allowed()`.
- **Don't unwrap the result at a gate.** `iam.check(q).await.unwrap()` defeats fail-closed by panicking
  on transport errors instead of denying. Use `ResultExt::is_allowed`.
- **`resource` is a string**, not an object. Passing structured data there will not match a server
  resource id.
:::

See also: [Listing resources](/guides/listing-resources), [Fail-closed patterns](/guides/fail-closed-patterns).
