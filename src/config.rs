//! Client configuration and the shared builder.

use std::time::Duration;

use crate::error::IamError;

/// Default request timeout when none is configured (matches the PHP client).
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Validated, immutable configuration shared by both client flavours.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// Base URL with any trailing slash removed.
    pub base_url: String,
    /// Optional service token (Client Credentials), sent as `Authorization: Bearer`.
    pub token: Option<String>,
    pub timeout: Duration,
    /// Expected token issuer, required by `verify_token`.
    pub issuer: Option<String>,
    /// Expected token audience, required by `verify_token`.
    pub audience: Option<String>,
}

/// Builder for an IAM client.
///
/// Obtain one from [`IamClient::builder`](crate::IamClient::builder) and finish with
/// [`build`](IamClientBuilder::build) for the async client, or — with the `blocking`
/// feature — [`build_blocking`](IamClientBuilder::build_blocking) for the synchronous one.
#[derive(Debug, Clone, Default)]
pub struct IamClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
    timeout: Option<Duration>,
    issuer: Option<String>,
    audience: Option<String>,
}

impl IamClientBuilder {
    /// Base URL of the IAM control plane, e.g. `https://iam.example.com/api/iam/v1`.
    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Service token used for `Authorization: Bearer` on decision requests.
    #[must_use]
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Per-request timeout. Defaults to 2 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Expected token issuer (`iss`). Required for [`verify_token`](crate::IamClient::verify_token).
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Expected token audience (`aud`). Required for [`verify_token`](crate::IamClient::verify_token).
    #[must_use]
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Validate the builder and produce an immutable [`Config`].
    ///
    /// # Errors
    /// Returns [`IamError::Config`] if no (non-empty) base URL was provided.
    pub(crate) fn finish(self) -> Result<Config, IamError> {
        let base_url = self
            .base_url
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .ok_or_else(|| IamError::Config("a non-empty base_url is required".to_string()))?;

        Ok(Config {
            base_url,
            token: self.token,
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            issuer: self.issuer,
            audience: self.audience,
        })
    }
}
