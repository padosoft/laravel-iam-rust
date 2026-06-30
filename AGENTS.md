# AGENTS.md

See [CLAUDE.md](CLAUDE.md) for the full guide. In short:

- `laravel-iam` is a **fail-closed** Rust client for the Laravel IAM server. Every error ⇒ **deny**.
- Mirror the PHP `HttpDecider` wire contract exactly; no client-side policy logic.
- Before claiming done, all three must be green:
  - `cargo fmt --all --check`
  - `cargo clippy --all-features --all-targets -- -D warnings`
  - `cargo test --all-features`
- Pure-Rust deps only (`p256` + `native-tls`); no C toolchain needed. Don't re-add `ring`.
- Do not publish to crates.io from automation.
