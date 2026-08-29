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
    /// Optional STATIC service token, sent as `Authorization: Bearer`.
    pub token: Option<String>,
    /// Self-managed `client_credentials`: when both are set, the client mints/refreshes the token itself
    /// and auto-follows IAM's client-secret rotation (self-fetch). Takes precedence over `token`.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// `private_key_jwt` (RFC 7523): an ES256 private key (PKCS#8 PEM). With `client_id` set, the client
    /// signs a short-lived assertion instead of sending a secret. Highest precedence.
    pub private_key: Option<String>,
    pub private_key_kid: Option<String>,
    /// OAuth base for token + self-fetch (e.g. `https://iam.example.com/oauth`); derived if unset.
    pub oauth_url: Option<String>,
    pub timeout: Duration,
    /// Expected token issuer, required by `verify_token`.
    pub issuer: Option<String>,
    /// Expected token audience, required by `verify_token`.
    pub audience: Option<String>,
    /// RFC 7662 introspection endpoint; derived from `oauth_base()` when unset. Set it to an
    /// empty string to refuse delegated tokens outright.
    pub introspection_url: Option<String>,
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
    client_id: Option<String>,
    client_secret: Option<String>,
    private_key: Option<String>,
    private_key_kid: Option<String>,
    oauth_url: Option<String>,
    timeout: Option<Duration>,
    issuer: Option<String>,
    audience: Option<String>,
    introspection_url: Option<String>,
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

    /// Self-managed `client_credentials`: the OAuth client id (e.g. `cli_myapp`). Pair with
    /// [`client_secret`](Self::client_secret). Takes precedence over a static [`token`](Self::token).
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The OAuth client secret issued by IAM. Rotatable — the client follows rotations automatically.
    #[must_use]
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// `private_key_jwt` (RFC 7523): the ES256 private key (PKCS#8 PEM). With `client_id`, the client signs an
    /// assertion instead of sending a secret. Highest precedence. Register the matching public key in IAM.
    #[must_use]
    pub fn private_key(mut self, private_key_pem: impl Into<String>) -> Self {
        self.private_key = Some(private_key_pem.into());
        self
    }

    /// The `kid` of the registered public key, written into the assertion header.
    #[must_use]
    pub fn private_key_kid(mut self, kid: impl Into<String>) -> Self {
        self.private_key_kid = Some(kid.into());
        self
    }

    /// OAuth base for the token + self-fetch endpoints, e.g. `https://iam.example.com/oauth`.
    /// If unset, it is derived from `base_url` by stripping a trailing `/api/iam/vN`.
    #[must_use]
    pub fn oauth_url(mut self, oauth_url: impl Into<String>) -> Self {
        self.oauth_url = Some(oauth_url.into());
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

    /// RFC 7662 introspection endpoint, e.g. `https://iam.example.com/oauth/introspect`.
    ///
    /// Delegated tokens are **introspection-mandatory**, so without a reachable endpoint
    /// [`verify_delegated_token`](crate::IamClient::verify_delegated_token) always denies.
    /// Defaults to `<oauth_base>/introspect`; pass `""` to refuse delegated tokens outright.
    #[must_use]
    pub fn introspection_url(mut self, url: impl Into<String>) -> Self {
        self.introspection_url = Some(url.into());
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
            client_id: self.client_id,
            client_secret: self.client_secret,
            private_key: self.private_key,
            private_key_kid: self.private_key_kid,
            oauth_url: self.oauth_url,
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            issuer: self.issuer,
            audience: self.audience,
            introspection_url: self.introspection_url,
        })
    }
}

impl Config {
    /// True when `private_key_jwt` is configured (`client_id` + a private key present). Highest precedence.
    pub(crate) fn uses_private_key_jwt(&self) -> bool {
        self.client_id.is_some() && self.private_key.is_some()
    }

    /// True when self-managed `client_credentials` is configured (both id + secret present).
    pub(crate) fn uses_client_credentials(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }

    /// Introspection endpoint: explicit `introspection_url`, else `<oauth_base>/introspect`.
    /// An empty string means "refuse delegated tokens", and is returned verbatim.
    pub(crate) fn introspection_endpoint(&self) -> String {
        match &self.introspection_url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => crate::wire::introspect_url(&self.oauth_base()),
        }
    }

    /// OAuth base URL: explicit `oauth_url`, else derived from `base_url` (strip trailing `/api/iam/vN`).
    pub(crate) fn oauth_base(&self) -> String {
        if let Some(url) = &self.oauth_url {
            return url.trim_end_matches('/').to_string();
        }
        let trimmed = self.base_url.trim_end_matches('/');
        let root = match trimmed.rfind("/api/iam/v") {
            Some(idx) => &trimmed[..idx],
            None => trimmed,
        };
        format!("{}/oauth", root.trim_end_matches('/'))
    }
}
