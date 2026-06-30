# CLAUDE.md

Guidance for AI agents working in this repository.

## What this is

`laravel-iam` — a thin, **fail-closed** Rust client SDK for the Laravel IAM authorization server.
It is the Rust sibling of the production PHP client (`Padosoft\Iam\Client`) and the
`@padosoft/laravel-iam-node` SDK. It transports decision requests and verifies OIDC tokens; it
contains **no policy logic** of its own.

## The one rule: never fail open

Every error or ambiguity must become **deny**, never allow. Concretely:

- Network error / timeout / 5xx / 4xx / malformed body / unverifiable token ⇒ deny.
- `ResultExt::is_allowed` (on `Result<Decision, IamError>`) is the gate: any `Err` ⇒ `false`.
- `Decision::granted()` requires `allowed && !requires_step_up`.
- Token verification accepts a token only when ES256 signature **and** `iss`/`aud`/`exp`/`nbf`
  all pass. Missing issuer/audience config ⇒ reject (`IamError::Config`), never accept.

If you add a code path, add a test proving it denies. There is no fail-open option, by design.

## Wire contract (do not drift)

Mirrors the PHP `HttpDecider` exactly:
- `POST {base_url}/decisions:check`, `Accept: application/json`, `Authorization: Bearer <token>`.
- Request body and response parsing live in `src/types.rs`; status/JWT logic in `src/wire.rs`.
- `resource` is encoded as a plain string and `current_aal` is sent — matching PHP, not the
  illustrative example in spec doc 20.

## Layout

- `src/lib.rs` — crate docs, `ResultExt`, re-exports.
- `src/client.rs` — async client + shared builder `build()`.
- `src/blocking.rs` — sync client (`blocking` feature), `build_blocking()`.
- `src/wire.rs` — transport-agnostic helpers (URLs, status mapping, JWKS/JWT verify via `p256`).
- `src/types.rs` / `src/error.rs` / `src/config.rs` — types, errors, builder.
- `tests/` — `wiremock`-backed async + blocking suites; fixtures in `tests/fixtures/`.

## Local commands

```bash
cargo fmt --all --check
cargo clippy --all-features --all-targets -- -D warnings   # pedantic, must be clean
cargo test --all-features
```

Crypto is pure-Rust (`p256`) and TLS is `native-tls`, so **no C toolchain is required**. Do not
re-introduce `ring`/`rustls`/`jsonwebtoken` without checking they build on the target environments.

## Don'ts

- Don't publish to crates.io from automation — the maintainer does that.
- Don't add a local (in-process) decider; decisions are always the server's (see spec doc 20 §9).
- Don't let any cache turn a deny into an allow.
