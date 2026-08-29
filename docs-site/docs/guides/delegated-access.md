# Delegated access (agents acting for users)

When an **AI agent acts on behalf of a user**, the token it presents carries *two* identities, not one: `sub` is the user, and `act` is the agent acting for them. This crate reads both, and asks the PDP a different question than it asks for a human.

This is the client half of [`laravel-iam-agents`](https://doc.laravel-iam-agents.padosoft.com) (RFC 8693 token exchange). Without that module on the server there is nothing to verify — `/decisions/check-delegated` and delegated tokens only exist when it is installed.

## The invariant

> **Two identities, strict intersection, never union, fail-closed.**

The verdict is what the user may do **AND** what every actor in the chain may do — never the union. That single sentence is what makes handing an agent a delegation safer than handing it a session token:

- The agent can never do more than the user could.
- The agent can never do more than *it* was allowed.
- **Adding a hop can only narrow authority.** A chain of three agents is bounded by the smallest of the four sets — which is why depth is an accountability question, not an authority one.

A deny at any layer wins.

## The act chain

For one hop, `act` is a single level; for several it nests, outermost-first (RFC 8693 §4.1):

```json
{ "sub": "user:42", "act": { "sub": "agent:hop2", "act": { "sub": "agent:hop1" } } }
```

`actor_chain_from_claims` flattens that to `["agent:hop2", "agent:hop1"]`, and the ordering is load-bearing:

- **`actors[0]` is the CURRENT actor** — the one holding the token right now.
- **The last element is the root** — the agent the user actually consented to, whose grant governs the whole chain. Revoke it and everything downstream stops.

Reading that order backwards silently checks the wrong agent, so it is pinned by a test rather than left to a comment.

## Verifying a delegated token

```rust
use laravel_iam::IamClient;

# async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .token(std::env::var("IAM_SERVICE_TOKEN")?)
    // .introspection_url(…) — defaults to <oauth_base>/introspect
    .build()?;

match iam.verify_delegated_token(token).await {
    Ok(Some(bearer)) => { /* delegated and confirmed */ }
    Ok(None)         => { /* not delegated — use verify_token on the normal path */ }
    Err(_)           => { /* deny */ }
}
# Ok(())
# }
```

The three outcomes are genuinely distinct, and conflating the last two is the bug this API is shaped to prevent:

| Result | Meaning |
| --- | --- |
| `Ok(Some(bearer))` | Delegated, and introspection confirmed it. `bearer.verified == true`. |
| `Ok(None)` | **Not delegated.** Not an error — this token is not this method's business. |
| `Err(_)` | Delegated but malformed, unconfirmed, or unverifiable. **Deny.** |

### Introspection is mandatory

This is the rule most likely to be "optimised away" by someone who has not been bitten by it, so it is worth stating plainly: **the authorization view never comes from the local bytes.**

`verify_delegated_token` calls the server's RFC 7662 `/oauth/introspect` and builds its answer from the claims that come back. The server re-checks the signature, the expiry, **and that the delegating user's session is still alive** — the last of which no amount of local parsing can tell you. A user who logged out ten seconds ago still has a perfectly valid-looking token in the agent's hands.

So: **no introspection reachable ⇒ no delegated authorization.** Not "fall back to the local parse" — deny.

::: callout warning "typ is routing, not a defence"
`typ: delegated+jwt` tells the SDK which path a token belongs on — nothing more. A verifier that trusts a header field to decide how much authority a token carries is trusting the token to describe itself.
:::

To refuse delegated tokens outright on a resource server that should never see them, build with `.introspection_url("")`: every delegated token is then rejected without a round-trip.

## Asking for a delegated decision

```rust
use laravel_iam::{DecisionQuery, IamClient, ResultExt, Subject};

# async fn run(iam: IamClient, bearer: laravel_iam::DelegatedBearer) {
let allowed = iam.check_delegated_with(DecisionQuery {
    subject: Subject::user(&bearer.sub),   // the USER — never the agent
    permission: "orders.draft".into(),
    resource: Some("ord_1".into()),
    actors: bearer.actors.clone(),         // current actor first
    delegation_grant_id: bearer.grant_id.clone(),
    ..Default::default()
}).await.is_allowed();
# let _ = allowed;
# }
```

`check_delegated` is the short form when only subject, chain and permission matter; `check_delegated_with` takes the full query. Both return `Result<Decision, IamError>`, so `ResultExt::is_allowed` collapses every error path — and every pending step-up — to `false`, exactly as on the plain path.

Passing `delegation_grant_id` matters: the PDP looks the grant up on every delegated decision, so a grant revoked one second ago stops the very next request rather than waiting for the token to expire.

### An empty actor chain is refused

```rust
# use laravel_iam::{IamClient, Subject};
# async fn run(iam: IamClient) {
let result = iam.check_delegated(Subject::user("usr_1"), vec![], "orders.read").await;
// → Err(IamError::Config(…)), and no request was sent
# let _ = result;
# }
```

It is **not** "fall back to checking the user". An empty chain means the caller lost track of who is acting, and quietly answering the user-only question there would hand the agent's request the user's full authority — the exact escalation delegation exists to prevent.

## Malformed `act` is refused; absent `act` is not

| Claim | Meaning | Behaviour |
| --- | --- | --- |
| no `act` | not delegated | `Ok(None)` — use the normal path |
| readable `act` | delegated | the chain |
| unreadable `act` | delegated, but broken | `Err(IamError::TokenInvalid)` |

Degrading a broken delegated token into "a normal user token" is the confused deputy in one line of code: the `act` that bounded the agent's authority becomes unreadable, so the agent inherits the user's. The same applies to a `typ: delegated+jwt` header with no `act` to act on, and to a chain deeper than 16 hops (a cyclic claim must not spin the parser).

## Backward compatibility, and the cache

`actors` and `delegation_grant_id` are skipped when empty, so a plain check's body is byte-identical to what it has always been — an older server that never heard of delegation is unaffected. The existing exact-wire-shape test asserts this rather than trusting the diff.

This crate holds **no decision cache** (only JWKS and OAuth tokens are cached), so a delegated verdict is always fresh by construction. That is deliberate: a cached delegated allow would outlive the revocation meant to stop it, and the kill switch working *now* is the point of short-lived delegation.

## The blocking client

Everything above exists on `blocking::IamClient` with identical semantics and identical refusals — `check_delegated`, `check_delegated_with`, `verify_delegated_token`. The empty-chain guard is literally shared code, so the two flavours cannot drift apart. See [The blocking client](/guides/blocking-client).

## Logging both identities

Once a request is delegated, "who did this" has two answers, and an audit trail recording only one of them is not an audit trail:

```rust
# use laravel_iam::DelegatedBearer;
# fn log(bearer: &DelegatedBearer, decision_id: &str) {
tracing::info!(
    sub = %bearer.sub,                        // on whose behalf
    actor = %bearer.actors[0],                // who actually did it
    chain = ?bearer.actors,                   // the full path of authority
    grant = ?bearer.grant_id,                 // what the user consented to
    decision_id = %decision_id,               // replayable against the PDP
    "order drafted",
);
# }
```

That set answers the two questions an auditor actually asks — *everything agent X did, for anyone* and *everything done on behalf of user Y, by any agent* — and the `decision_id` lets them replay the verdict instead of taking your word for it.

## See also

- [`laravel-iam-agents`](https://doc.laravel-iam-agents.padosoft.com) — the server module
- [Verifying tokens](/guides/verifying-tokens) — the non-delegated path
- [Fail-closed patterns](/guides/fail-closed-patterns)
