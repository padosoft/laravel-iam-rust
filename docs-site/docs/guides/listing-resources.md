# Listing resources (ReBAC)

`list_resources()` answers the *reverse* question of `check()`: instead of "may this subject act on this
one resource?", it asks "**which** resources can this subject reach under a given relation?". This is a
ReBAC (relationship-based) lookup, served by `POST {base}/decisions/list-resources`.

## Motivation

To render a list view — "the warehouses I can view", "the projects I can edit" — you do not want to call
`check()` once per candidate resource. `list_resources()` lets the server enumerate the reachable set in
a single round-trip.

## The call

```rust
use laravel_iam::Subject;

let warehouses = iam
    .list_resources(Subject::user("usr_123"), "viewer")
    .await?;

for r in &warehouses {
    println!("{}:{}", r.kind, r.id); // e.g. "warehouse:wh_milan"
}
```

The signature is:

```rust
pub async fn list_resources(
    &self,
    subject: Subject,
    relation: impl AsRef<str>,
) -> Result<Vec<Resource>, IamError>
```

`relation` accepts anything string-like (`&str`, `String`, …). The request body is exactly
`{ "subject": { "type", "id" }, "relation": "<relation>" }`.

## The response

Each entry is a [`Resource`](/reference/types) — `{ kind, id }`, where `kind` serializes as `type` on the
wire. The parser is permissive about envelope shape: it accepts **either**

```json
{ "resources": [ { "type": "warehouse", "id": "wh_milan" } ] }
```

**or** a bare top-level array:

```json
[ { "type": "warehouse", "id": "wh_milan" } ]
```

## Fail-closed, but not "deny"

`list_resources()` is fail-closed in the sense that **any** failure yields an `Err` rather than a partial
or empty list — you never silently get a truncated set that looks like "no access":

```rust
match iam.list_resources(Subject::user("usr_123"), "viewer").await {
    Ok(resources) => render(resources),
    Err(e)        => {
        // Do NOT treat this as "empty list" — it's an error. Surface or retry.
        tracing::warn!("list_resources failed: {e}");
        show_error_state();
    }
}
```

::: callout warning
Unlike `check()` — where an error collapses to *deny* — an error from `list_resources()` is **not** the
same as "the subject can reach nothing". Distinguish `Ok(vec![])` (genuinely empty) from `Err(..)`
(could not determine the set). Treating an error as an empty list can hide data the user is entitled to,
or mask an outage.
:::

## Worked example: building a scoped menu

```rust
use laravel_iam::{IamClient, Subject, Resource};

async fn editable_projects(iam: &IamClient, user_id: &str) -> Result<Vec<Resource>, ()> {
    iam.list_resources(Subject::user(user_id), "editor")
        .await
        .map_err(|e| {
            tracing::error!("could not list editable projects: {e}");
        })
}
```

## Status and error handling

The same status mapping as `check()` applies before parsing:

| Server status | Result |
|---|---|
| `2xx` | parsed into `Vec<Resource>` |
| `401` / `403` | [`IamError::Unauthorized`](/reference/errors) |
| other non-2xx | [`IamError::Http`](/reference/errors) |
| unparseable / wrong-shaped body | [`IamError::Malformed`](/reference/errors) |

## Gotchas

::: callout warning
- **`Err` ≠ empty.** See above — the most common mistake is collapsing errors into "no results".
- **Relation names are server-defined.** `viewer`, `editor`, `owner`, … must match the relations the
  server's ReBAC model defines for that resource type.
- **Large sets.** The server returns the full reachable set; for very large tenancies prefer a scoped
  `check()` on a specific resource where you can.
:::

See also: [Checking decisions](/guides/checking-decisions), [The wire contract](/concepts/wire-contract).
