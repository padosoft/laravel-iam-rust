//! Asynchronous IAM client (built on `reqwest` + `tokio`).

use std::sync::Arc;

use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::json;
use tokio::sync::RwLock;

use crate::config::{Config, IamClientBuilder};
use crate::error::IamError;
use crate::types::{Claims, Decision, DecisionQuery, Resource, Subject};
use crate::wire::{self, Jwks};

/// A thin, fail-closed async client for the Laravel IAM control plane.
///
/// Construct it with the builder:
///
/// ```no_run
/// use std::time::Duration;
/// use laravel_iam::IamClient;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let iam = IamClient::builder()
///     .base_url("https://iam.example.com/api/iam/v1")
///     .token(std::env::var("IAM_SERVICE_TOKEN")?)
///     .timeout(Duration::from_secs(2))
///     .build()?;
/// # let _ = iam;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct IamClient {
    http: reqwest::Client,
    config: Arc<Config>,
    jwks_cache: Arc<RwLock<Option<Jwks>>>,
}

impl IamClient {
    /// Start building a client.
    #[must_use]
    pub fn builder() -> IamClientBuilder {
        IamClientBuilder::default()
    }

    fn from_config(config: Config) -> Result<Self, IamError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| IamError::Network(e.to_string()))?;
        Ok(Self {
            http,
            config: Arc::new(config),
            jwks_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Ask the server for a policy decision.
    ///
    /// Fail-closed: any transport error, timeout, non-2xx status or malformed body is
    /// returned as an [`IamError`], which [`crate::ResultExt::is_allowed`] maps to deny.
    ///
    /// # Errors
    /// See [`IamError`].
    pub async fn check(&self, query: DecisionQuery) -> Result<Decision, IamError> {
        let response = self
            .send_json(&wire::check_url(&self.config.base_url), &query)
            .await?;
        let (status, body) = read(response).await?;
        wire::parse_decision(status, &body)
    }

    /// List the resources a subject can reach under a given relation (doc 20 §2 / M16).
    ///
    /// # Errors
    /// See [`IamError`]. Any failure yields an error rather than a partial list.
    pub async fn list_resources(
        &self,
        subject: Subject,
        relation: impl AsRef<str>,
    ) -> Result<Vec<Resource>, IamError> {
        let payload = json!({ "subject": subject, "relation": relation.as_ref() });
        let response = self
            .send_json(&wire::list_resources_url(&self.config.base_url), &payload)
            .await?;
        let (status, body) = read(response).await?;
        wire::parse_resources(status, &body)
    }

    /// Verify an OIDC token: ES256 signature against the cached JWKS, plus `iss`/`aud`/`exp`.
    ///
    /// # Errors
    /// [`IamError::TokenInvalid`] on any verification failure, or [`IamError::Config`] if no
    /// issuer/audience were configured. A token is accepted only when every check passes.
    pub async fn verify_token(&self, jwt: &str) -> Result<Claims, IamError> {
        let kid = wire::token_kid(jwt)?;
        let jwks = self.jwks_for_kid(&kid).await?;
        wire::verify_jwt(
            jwt,
            &jwks,
            self.config.issuer.as_deref(),
            self.config.audience.as_deref(),
        )
    }

    /// Return a JWKS guaranteed to contain `kid`, fetching (once) on a cache miss so that
    /// key rotation is handled transparently.
    async fn jwks_for_kid(&self, kid: &str) -> Result<Jwks, IamError> {
        if let Some(jwks) = self.jwks_cache.read().await.as_ref() {
            if wire::jwks_has_kid(jwks, kid) {
                return Ok(jwks.clone());
            }
        }
        let fetched = self.fetch_jwks().await?;
        *self.jwks_cache.write().await = Some(fetched.clone());
        Ok(fetched)
    }

    async fn fetch_jwks(&self) -> Result<Jwks, IamError> {
        let response = self
            .http
            .get(wire::jwks_url(&self.config.base_url))
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let (status, body) = read(response).await?;
        if let Some(err) = wire::status_error(status) {
            return Err(err);
        }
        wire::parse_jwks(&body)
    }

    async fn send_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<reqwest::Response, IamError> {
        let mut request = self.http.post(url).header(ACCEPT, "application/json");
        if let Some(token) = &self.config.token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        request.json(body).send().await.map_err(map_reqwest_error)
    }
}

impl IamClientBuilder {
    /// Build an asynchronous [`IamClient`].
    ///
    /// # Errors
    /// Returns [`IamError::Config`] for invalid configuration, or [`IamError::Network`] if the
    /// underlying HTTP client cannot be created.
    pub fn build(self) -> Result<IamClient, IamError> {
        IamClient::from_config(self.finish()?)
    }
}

async fn read(response: reqwest::Response) -> Result<(u16, Vec<u8>), IamError> {
    let status = response.status().as_u16();
    let body = response.bytes().await.map_err(map_reqwest_error)?;
    Ok((status, body.to_vec()))
}

/// Map a `reqwest` error onto the fail-closed taxonomy.
#[allow(clippy::needless_pass_by_value)] // used as a `map_err` fn, which needs an owned argument
pub(crate) fn map_reqwest_error(error: reqwest::Error) -> IamError {
    if error.is_timeout() {
        IamError::Timeout
    } else {
        IamError::Network(error.to_string())
    }
}
