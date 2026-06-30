# Core concepts

This page defines the vocabulary used throughout the docs. Five ideas carry the whole SDK:
**the client is thin**, **decisions are the server's**, **everything is fail-closed**, **`allowed`
is not the same as `granted`**, and **tokens are verified locally**.

## The client is thin

There is **no policy logic on the client**. The SDK does exactly three things:

1. Serialize a question and POST it to the server.
2. Parse the server's answer defensively.
3. Verify OIDC tokens against the server's published keys.

Every RBAC role, ABAC rule, and ReBAC relationship lives on the
[IAM server](https://doc.laravel-iam-server.padosoft.com). This keeps the trust boundary in one place
and means the client never has to be redeployed when a policy changes.

## Subjects, permissions, resources

A decision question is built from a small typed vocabulary (full schema in [Types](/reference/types)):

| Term | Type | Meaning |
|---|---|---|
| **Subject** | `Subject { kind, id }` | Who is asking — `user`, `service_account`, `group`, `agent`. Constructors: `Subject::user(id)`, `Subject::service_account(id)`, `Subject::group(id)`. |
| **Permission** | `String` | The ability being checked, e.g. `stock.adjust`. |
| **Resource** | `Option<String>` | The specific object the action targets, e.g. `wh_milan`. |
| **Organization / Application** | `Option<String>` | Tenancy and app scope. |
| **Context** | `serde_json::Value` | Free-form ABAC facts (amount, time, IP…). |
| **`current_aal`** | `String` | The subject's current authenticator assurance level. Defaults to `aal1`. |

These are assembled into a [`DecisionQuery`](/reference/types) and serialized **verbatim** into the
request body, matching the PHP `DecisionRequest::toArray()` shape exactly.

## The three "is it allowed?" answers

This is the single most important distinction in the SDK. There are three layers, each stricter than
the last:

::: steps
1. **`Decision::allowed`** — the raw server boolean
   `true` only if the server explicitly sent boolean `true`. A missing or wrong-typed field is `false`.
   **Not sufficient on its own** to permit an action.

2. **`Decision::granted()`** — allowed *and* settled
   Defined as `allowed && !requires_step_up`. An `allowed` decision that still demands a step-up to a
   higher assurance level is **not** granted. This is the value a naive allow/deny gate should read.

3. **`Result::is_allowed()`** — the fail-closed gate
   Provided by the [`ResultExt`](/reference/api) trait on `Result<Decision, IamError>`. It is `true`
   **only** when the call succeeded *and* `granted()` is true. **Any** `IamError` — network, timeout,
   `4xx`, `5xx`, malformed body — evaluates to `false`.
:::

```rust
// allowed:        the server's raw boolean
// granted():      allowed AND no pending step-up
// is_allowed():   granted() AND the call itself succeeded (else deny)
```

::: callout warning
Reach for `Result::is_allowed()` at the gate. Only inspect `allowed` / `granted()` / `requires_step_up`
on an `Ok(Decision)` when you are deliberately implementing auditing or a step-up flow.
:::

## Fail-closed

A network error, timeout, `5xx`, `4xx`, malformed body, or unverifiable token **always** becomes a
**deny**, never an allow. There is no fail-open switch. The full theory — including why this is the only
safe default and how to *deliberately* tolerate outages when you must — is in
[Fail-closed authorization](/concepts/fail-closed).

## Local token verification

`verify_token()` does **not** call the server per request. It:

1. fetches the server's JWKS once (`{base}/.well-known/jwks.json`) and caches it;
2. verifies the JWT's **ES256** signature with pure-Rust `p256`;
3. validates `iss` / `aud` / `exp` / `nbf` with **no leeway**.

Issuer and audience are **mandatory** — a token the client cannot fully validate is never accepted. See
[JWT / JWKS verification](/concepts/jwt-verification).

## Async first, blocking optional

The default [`IamClient`](/reference/api) is async (`reqwest` + `tokio`). The `blocking` feature adds a
synchronous twin with byte-identical semantics — the shared logic lives in one transport-agnostic module
so the two clients can never drift. See [The check flow](/architecture/check-flow) and
[The blocking client](/guides/blocking-client).

## Where to go next

- [Fail-closed authorization](/concepts/fail-closed) — the formal argument.
- [The wire contract](/concepts/wire-contract) — exact request/response shapes.
- [Architecture overview](/architecture/overview) — how the pieces fit.
