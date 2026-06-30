# Configuration

All configuration goes through `IamClientBuilder`. This page is the complete reference for the builder
options, their defaults, and validation.

## The builder

Obtain it from `IamClient::builder()`, set options fluently, and finish with `build()` (async) or
`build_blocking()` (the `blocking` feature):

```rust
use std::time::Duration;
use laravel_iam::IamClient;

let iam = IamClient::builder()
    .base_url("https://iam.example.com/api/iam/v1")
    .token("svc_token")
    .timeout(Duration::from_secs(2))
    .issuer("https://iam.example.com")
    .audience("warehouse-api")
    .build()?;
```

## Options

| Method | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `base_url(..)` | `impl Into<String>` | **yes** | — | Versioned API root, e.g. `…/api/iam/v1`. Trailing slash trimmed. |
| `token(..)` | `impl Into<String>` | no | none | Client-Credentials service token → `Authorization: Bearer`. |
| `timeout(..)` | `Duration` | no | `2s` | Per-request timeout. |
| `issuer(..)` | `impl Into<String>` | for `verify_token` | none | Expected `iss`. |
| `audience(..)` | `impl Into<String>` | for `verify_token` | none | Expected `aud`. |

## Validation

`build()` / `build_blocking()` validate the configuration (`finish()` in `config.rs`):

- **`base_url` is required and non-empty.** Missing or empty → [`IamError::Config`](/reference/errors).
- The trailing `/` is trimmed, so `…/v1` and `…/v1/` behave identically.
- The HTTP client is constructed with the timeout; a failure to build it is `IamError::Network`.

```rust
// Missing base_url is a configuration error, surfaced at build time.
let err = IamClient::builder().token("t").build();
assert!(matches!(err, Err(laravel_iam::IamError::Config(_))));
```

## When issuer/audience are required

- `check()` and `list_resources()` do **not** need `issuer`/`audience`.
- `verify_token()` **requires both**. Calling it on a client built without them returns
  `IamError::Config` — see [JWT / JWKS verification](/concepts/jwt-verification).

## Environment-driven setup

A typical production wiring reads everything from the environment:

```rust
use std::time::Duration;
use laravel_iam::IamClient;

fn build_iam() -> Result<IamClient, Box<dyn std::error::Error>> {
    Ok(IamClient::builder()
        .base_url(std::env::var("IAM_BASE_URL")?)
        .token(std::env::var("IAM_SERVICE_TOKEN")?)
        .issuer(std::env::var("IAM_ISSUER")?)
        .audience(std::env::var("IAM_AUDIENCE")?)
        .timeout(Duration::from_millis(
            std::env::var("IAM_TIMEOUT_MS").ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
        ))
        .build()?)
}
```

| Env var | Maps to |
|---|---|
| `IAM_BASE_URL` | `base_url` |
| `IAM_SERVICE_TOKEN` | `token` |
| `IAM_ISSUER` | `issuer` |
| `IAM_AUDIENCE` | `audience` |
| `IAM_TIMEOUT_MS` | `timeout` |

## Cargo features

| Feature | Default | Effect |
|---|---|---|
| `blocking` | off | Enables `reqwest/blocking` and `blocking::IamClient` (finish with `build_blocking()`). |

See [Installation](/installation) for the dependency snippet and [The blocking client](/guides/blocking-client).

## Defaults at a glance

::: callout info
- **Timeout:** 2 seconds.
- **Token:** none (anonymous) unless set — most decision endpoints expect a service token.
- **Issuer / audience:** none — must be set before `verify_token()`.
- **TLS:** `native-tls` (platform stack).
:::

See also: [Best practices: integration](/best-practices/integration), [Troubleshooting](/operations/troubleshooting).
