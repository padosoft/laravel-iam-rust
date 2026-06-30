//! # laravel-iam
//!
//! A thin, **fail-closed** Rust client for the [Laravel IAM](https://github.com/padosoft)
//! authorization server. It speaks the canonical decision protocol
//! (`POST {base_url}/decisions/check`) and verifies OIDC tokens against the server's JWKS —
//! mirroring the production PHP client's wire contract exactly, in idiomatic async Rust.
//!
//! There is **no policy logic on the client**: every decision is the server's. The client only
//! transports the question and the answer, and refuses to invent an "allow".
//!
//! ## Fail-closed guarantee
//!
//! A network error, timeout, 5xx, 4xx, malformed body or unverifiable token always becomes a
//! **deny** — never an allow. Operations return `Result<_, IamError>`; the [`ResultExt::is_allowed`]
//! helper collapses any error into `false` so a gate cannot accidentally open:
//!
//! ```no_run
//! use laravel_iam::{IamClient, DecisionQuery, Subject, ResultExt};
//! use serde_json::json;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let iam = IamClient::builder()
//!     .base_url("https://iam.example.com/api/iam/v1")
//!     .token(std::env::var("IAM_SERVICE_TOKEN")?)
//!     .build()?;
//!
//! let decision = iam.check(DecisionQuery {
//!     subject: Subject::user("usr_123"),
//!     application: Some("warehouse".into()),
//!     permission: "stock.adjust".into(),
//!     resource: Some("wh_milan".into()),
//!     context: json!({ "amount": 300 }),
//!     ..Default::default()
//! }).await;
//!
//! // `decision` is `Result<Decision, IamError>`; on ANY error this is `false`.
//! if !decision.is_allowed() {
//!     // deny — fail-closed
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Token verification
//!
//! [`IamClient::verify_token`] checks an ES256 signature against the cached JWKS plus the
//! `iss`/`aud`/`exp` claims. Configure the expected issuer and audience on the builder.
//!
//! ## Features
//!
//! - `blocking` — adds a synchronous [`blocking::IamClient`] with identical semantics.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod client;
mod config;
mod error;
mod types;
mod wire;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use client::IamClient;
pub use config::IamClientBuilder;
pub use error::IamError;
pub use types::{Claims, Decision, DecisionQuery, Resource, Subject};

/// Fail-closed extension for `Result<Decision, IamError>`.
///
/// Lets a caller write `if iam.check(q).await.is_allowed()` and be certain that **every**
/// error path — and every pending step-up — evaluates to `false`.
pub trait ResultExt {
    /// `true` only when the call succeeded **and** the decision is truly granted
    /// (allowed and no pending step-up). Any [`IamError`] yields `false`.
    fn is_allowed(&self) -> bool;
}

impl ResultExt for Result<Decision, IamError> {
    fn is_allowed(&self) -> bool {
        matches!(self, Ok(decision) if decision.is_allowed())
    }
}
