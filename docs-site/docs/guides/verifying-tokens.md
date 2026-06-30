# Verifying tokens

`verify_token()` validates an OIDC access/ID token locally: it checks the **ES256** signature against
the server's JWKS, then validates the registered claims. This guide is the practical how-to; the theory
is in [JWT / JWKS verification](/concepts/jwt-verification).

## Motivation

A consumer service receives a JWT and must decide whether to trust it — without a network round-trip per
request. The SDK verifies the signature and claims against the server's **published** public keys, so
trust flows from the IAM server's signing key, not from the token's self-asserted contents.

## Configure issuer and audience

Issuer and audience are **mandatory** for verification. They are set on the builder:

```rust
use laravel_iam::IamClient;

let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .issuer("https://iam.example.com")   // expected `iss`
    .audience("warehouse-api")           // expected `aud`
    .build()?;
```

::: callout warning
If you call `verify_token()` without configuring **both** an issuer and an audience, the result is
[`IamError::Config`](/reference/errors) — never an accepted token. A token the client cannot fully
validate must never be trusted. This is enforced in `wire::verify_jwt`.
:::

## Verify

```rust
match iam.verify_token(jwt).await {
    Ok(claims) => {
        // trusted
        println!("subject = {}", claims.sub);
    }
    Err(_) => {
        // reject — bad signature, expired, wrong aud/iss, unknown key, malformed, …
    }
}
```

`verify_token()` returns `Result<Claims, IamError>`. On success you get verified
[`Claims`](/reference/types): `sub`, `iss`, `aud`, `exp`, optional `nbf`/`iat`, and any extra claims
flattened into `claims.extra`.

## What is checked, in order

::: steps
1. **Extract `kid`** from the JWT header (no verification yet).

2. **Resolve the key.** The cached JWKS is consulted; on a cache miss (or unknown `kid`) the SDK fetches
   `{base}/.well-known/jwks.json` once and re-caches it. This handles **key rotation** transparently.

3. **Pin the algorithm.** The header `alg` must be exactly `ES256`; anything else is rejected. This
   blocks `alg` confusion / `none` attacks.

4. **Verify the signature** over `header.payload` with pure-Rust `p256` before any claim is trusted.

5. **Validate claims** with **no leeway**: `iss` must match, `aud` must match (string or array per
   RFC 7519), `exp` must be in the future, and `nbf` (if present) must be in the past.
:::

A token is accepted **only when every step passes**. Any failure is
[`IamError::TokenInvalid`](/reference/errors).

## Worked example: an auth middleware shape

```rust
use laravel_iam::IamClient;

async fn authenticate(iam: &IamClient, bearer: &str) -> Result<String, ()> {
    // `bearer` is the raw JWT (strip "Bearer " yourself upstream).
    match iam.verify_token(bearer).await {
        Ok(claims) => Ok(claims.sub),   // authenticated principal
        Err(_)     => Err(()),          // 401 — reject
    }
}
```

The verified `claims.sub` is then a good `Subject::user(..)` id for a follow-up
[`check()`](/guides/checking-decisions).

## JWKS caching

The JWKS is cached in-process behind an `RwLock` (async: `tokio::sync::RwLock`; blocking:
`std::sync::RwLock`). The cache is populated on first use and refreshed automatically when a token
presents a `kid` the cache does not contain. There is no TTL: rotation is detected by `kid`, not by
clock.

::: callout tip
Because the cache is per-client-instance, share **one** `IamClient` (it is `Clone` and cheap to clone —
it wraps `Arc`s) across your handlers rather than building a new one per request, so the JWKS is fetched
once.
:::

## Gotchas

::: callout warning
- **Both `issuer` and `audience` are required** — omitting either yields `IamError::Config`, not a pass.
- **No clock leeway.** A token that expired one second ago is rejected. Keep server and client clocks in
  sync (NTP).
- **Only ES256.** RS256/HS256 tokens are rejected by design; the IAM server signs with EC P-256.
- **Don't trust unverified claims.** Never read claims out of a raw JWT yourself; only the `Ok(Claims)`
  from `verify_token()` is trustworthy.
:::

See also: [JWT / JWKS verification](/concepts/jwt-verification), [Security](/best-practices/security).
