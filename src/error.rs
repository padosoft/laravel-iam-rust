//! Error type for the IAM client.
//!
//! Every variant represents a situation in which a decision could **not** be obtained
//! (or a token could not be verified). By the crate's fail-closed contract, all of them
//! must be treated as **deny** by callers — see [`crate::ResultExt::is_allowed`].

use thiserror::Error;

/// Errors returned by [`crate::IamClient`] operations.
///
/// None of these ever mean "allow". A caller that turns any [`IamError`] into anything
/// other than a denial has broken the fail-closed guarantee.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum IamError {
    /// Transport failure: connection refused, DNS error, TLS error, broken pipe, etc.
    #[error("network error: {0}")]
    Network(String),

    /// The request did not complete within the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// The server rejected the service credentials (HTTP 401 or 403).
    #[error("unauthorized (HTTP {0})")]
    Unauthorized(u16),

    /// The server returned a non-2xx status that is not an auth error.
    #[error("server returned HTTP {0}")]
    Http(u16),

    /// The response body could not be parsed into the expected shape.
    #[error("malformed response: {0}")]
    Malformed(String),

    /// A JWT could not be verified (bad signature, wrong algorithm, expired,
    /// wrong issuer/audience, unknown key, …).
    #[error("token verification failed: {0}")]
    TokenInvalid(String),

    /// The client was misconfigured for the requested operation (e.g. `verify_token`
    /// called without an issuer/audience, or an empty base URL).
    #[error("client configuration error: {0}")]
    Config(String),
}
