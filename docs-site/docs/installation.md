# Installation

## Requirements

| Requirement | Value |
|---|---|
| Crate | [`laravel-iam`](https://crates.io/crates/laravel-iam) |
| Latest version | `1.0.1` |
| Minimum supported Rust | `1.74` (`rust-version` in `Cargo.toml`) |
| Edition | 2021 |
| Async runtime | [`tokio`](https://tokio.rs) (for the default async client) |

## Add the crate

```toml
[dependencies]
laravel-iam = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde_json = "1"
```

Or with Cargo:

```bash
cargo add laravel-iam
cargo add tokio --features rt-multi-thread,macros
cargo add serde_json
```

`serde_json` is convenient because the `context` field of a [`DecisionQuery`](/reference/types) is a
`serde_json::Value`, and the `json!` macro is the ergonomic way to build it.

## Cargo features

::: tabs
== tab "Default (async)"

```toml
laravel-iam = "1"
```

Pulls in the async [`IamClient`](/reference/api) on `reqwest` + `tokio`. This is the recommended path
for servers, web handlers, and any code already inside an async runtime.

== tab "Blocking"

```toml
laravel-iam = { version = "1", features = ["blocking"] }
```

Adds the synchronous [`laravel_iam::blocking::IamClient`](/guides/blocking-client) with **identical**
fail-closed semantics, built on `reqwest::blocking`. Use it from CLI tools, build scripts, or sync call
sites. Do **not** call it from inside an async runtime thread — see the [blocking guide](/guides/blocking-client).

:::

The feature table from `Cargo.toml`:

| Feature | Default | Effect |
|---|---|---|
| `blocking` | off | Enables `reqwest/blocking` and the synchronous `blocking::IamClient`. |

## What gets pulled in

The dependency tree is deliberately lean and built for **portable, C-free builds**:

| Dependency | Purpose |
|---|---|
| `reqwest` (`json`, `native-tls`, `default-features = false`) | HTTP transport |
| `tokio` (`sync`) | `RwLock` for the JWKS cache (async client) |
| `serde` / `serde_json` | (de)serialization of the wire types |
| `p256` (`ecdsa`, `std`) | **pure-Rust** ES256 verification — no OpenSSL, no C toolchain |
| `base64` | JWT segment decoding |
| `thiserror` | the [`IamError`](/reference/errors) enum |

::: callout tip
Token verification uses [`p256`](https://crates.io/crates/p256) (RustCrypto) rather than the
C-backed `jsonwebtoken`/OpenSSL path. That keeps cross-compilation and container builds simple — there
is nothing to link. The rationale is recorded in [ADR-0001](/architecture/decisions).
:::

## TLS backend

`reqwest` is configured with `native-tls`, so it uses the platform TLS stack (Schannel on Windows,
Secure Transport on macOS, OpenSSL on Linux). If you need rustls instead, depend on `reqwest`
explicitly in your own `Cargo.toml` and configure features there; the SDK does not re-export the
transport.

## Verify the install

```bash
cargo build
cargo test           # runs the crate's own suite if you vendored it
```

A minimal smoke test:

```rust
use laravel_iam::IamClient;

fn main() {
    // Building a client validates configuration; an empty base_url is a Config error.
    let built = IamClient::builder()
        .base_url("https://iam.example.com/api/iam/v1")
        .build();
    assert!(built.is_ok());
}
```

Next: the [Quickstart](/quickstart), or [Configuration](/operations/configuration) for the full set of
builder options.
