# Types

The wire types, re-exported from `laravel_iam`. They are deliberately byte-compatible with the PHP
client's request/response shapes — see [The wire contract](/concepts/wire-contract).

## `Subject`

The principal a decision is about. Serialized as `{ "type": "...", "id": "..." }` (the Rust field `kind`
is renamed to `type` on the wire).

```rust
pub struct Subject {
    pub kind: String, // serde rename = "type"
    pub id: String,
}
```

| Constructor | Result |
|---|---|
| `Subject::new(kind, id)` | explicit type |
| `Subject::user(id)` | `type = "user"` |
| `Subject::service_account(id)` | `type = "service_account"` |
| `Subject::group(id)` | `type = "group"` |

```rust
let s = Subject::user("usr_123");           // {"type":"user","id":"usr_123"}
let a = Subject::new("agent", "agt_7");      // {"type":"agent","id":"agt_7"}
```

`Subject` is `Clone + PartialEq + Eq + Serialize + Deserialize`.

## `Resource`

A typed resource reference — e.g. an entry from `list_resources()`. Same `kind` ↔ `type` rename.

```rust
pub struct Resource {
    pub kind: String, // serde rename = "type"
    pub id: String,
}

let r = Resource::new("warehouse", "wh_milan"); // {"type":"warehouse","id":"wh_milan"}
```

## `DecisionQuery`

The body of `POST {base}/decisions/check`. Implements `Default`; build with struct-update syntax.

```rust
pub struct DecisionQuery {
    pub subject: Subject,
    pub permission: String,
    pub organization: Option<String>,
    pub application: Option<String>,
    pub resource: Option<String>, // plain string, NOT an object
    pub context: Value,           // serde_json::Value; default {}
    pub current_aal: String,      // default "aal1"
    pub explain: bool,            // default false
}
```

| Field | Default | Notes |
|---|---|---|
| `subject` | empty subject | set it; required |
| `permission` | `""` | set it; required |
| `organization` | `None` | serialized even when `null` |
| `application` | `None` | app scope |
| `resource` | `None` | **string**, e.g. `"wh_milan"` |
| `context` | `{}` | ABAC facts |
| `current_aal` | `"aal1"` | current assurance level |
| `explain` | `false` | request `explanation` lines |

Constructors:

```rust
// subject + permission, rest defaulted
let q = DecisionQuery::new(Subject::user("usr_123"), "stock.adjust");

// full struct literal
let q = DecisionQuery {
    subject: Subject::user("usr_123"),
    application: Some("warehouse".into()),
    permission: "stock.adjust".into(),
    resource: Some("wh_milan".into()),
    context: serde_json::json!({ "amount": 300 }),
    ..Default::default()
};
```

## `Decision`

The normalized response from `decisions/check`, parsed defensively (any missing/wrong-typed field falls
back to its safe default; `allowed` is `true` only if the server sent boolean `true`).

```rust
pub struct Decision {
    pub allowed: bool,
    pub decision_id: String,
    pub policy_version: i64,
    pub requires_step_up: bool,
    pub required_aal: Option<String>,
    pub explanation: Vec<String>,
}
```

| Field | Meaning |
|---|---|
| `allowed` | raw server permit boolean |
| `decision_id` | opaque id for audit/correlation |
| `policy_version` | version that produced the decision (cache invalidation) |
| `requires_step_up` | action needs a higher assurance level first |
| `required_aal` | the level required when `requires_step_up` |
| `explanation` | human-readable lines (when `explain` was requested) |

Methods:

| Method | Returns | Meaning |
|---|---|---|
| `granted()` | `bool` | `allowed && !requires_step_up` — the fail-safe gate value |
| `is_allowed()` | `bool` | alias of `granted()` |
| `Decision::deny(reason)` | `Decision` | explicit denial carrying a reason |

::: callout warning
`allowed == true` is **not** sufficient. A decision that also `requires_step_up` is **not** `granted()`.
Read `granted()` / `is_allowed()`, not the raw boolean. See [ADR-0006](/architecture/decisions).
:::

## `Claims`

Verified claims returned by `verify_token()`.

```rust
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: Value,                 // string or array (RFC 7519)
    pub exp: i64,                   // unix seconds
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub extra: Map<String, Value>,  // serde(flatten) — any other claims
}
```

`aud` is a `serde_json::Value` because RFC 7519 allows it to be a single string or an array. Any claims
beyond the registered ones are captured in `extra` via `#[serde(flatten)]`.

::: callout info
A `Claims` value is trustworthy **only** when it came from `verify_token()` returning `Ok`. Never
construct trust from a JWT you decoded yourself without verification — see
[JWT / JWKS verification](/concepts/jwt-verification).
:::

See also: [The wire contract](/concepts/wire-contract), [API reference](/reference/api),
[Error taxonomy](/reference/errors).
