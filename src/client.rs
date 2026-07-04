//! Asynchronous IAM client (built on `reqwest` + `tokio`).

use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Cached `client_credentials` access token + its expiry (only used in `client_credentials` mode).
    token_cache: Arc<RwLock<Option<(String, Instant)>>>,
    /// The current client secret once it has been auto-rotated (None → fall back to config).
    rotated_secret: Arc<RwLock<Option<String>>>,
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
            token_cache: Arc::new(RwLock::new(None)),
            rotated_secret: Arc::new(RwLock::new(None)),
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
        if let Some(token) = self.resolve_token().await {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        request.json(body).send().await.map_err(map_reqwest_error)
    }

    /// Resolve the Bearer: the static token, or a self-managed `client_credentials` token that mints,
    /// caches and auto-follows secret rotation (self-fetch). `None` → no header → fail-closed deny.
    async fn resolve_token(&self) -> Option<String> {
        if !self.config.uses_client_credentials() {
            return self.config.token.clone();
        }
        let client_id = self.config.client_id.as_deref()?;
        if let Some((token, expiry)) = self.token_cache.read().await.as_ref() {
            if Instant::now() < *expiry {
                return Some(token.clone());
            }
        }
        let oauth = self.config.oauth_base();
        if let Some(token) = self.mint_token(client_id, &oauth).await {
            return Some(token);
        }
        // The secret may have been auto-rotated: fetch the new one and retry once.
        if self.fetch_rotated_secret(client_id, &oauth).await {
            return self.mint_token(client_id, &oauth).await;
        }
        None
    }

    async fn mint_token(&self, client_id: &str, oauth: &str) -> Option<String> {
        let secret = self.current_secret().await;
        let response = self
            .http
            .post(wire::token_url(oauth))
            .header(ACCEPT, "application/json")
            .basic_auth(client_id, Some(secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .ok()?;
        if response.status().as_u16() != 200 {
            return None;
        }
        let body = response.bytes().await.ok()?;
        let (token, expires_in) = wire::parse_token(&body)?;
        let expiry = Instant::now() + Duration::from_secs(expires_in.saturating_sub(30).max(1));
        *self.token_cache.write().await = Some((token.clone(), expiry));
        Some(token)
    }

    async fn fetch_rotated_secret(&self, client_id: &str, oauth: &str) -> bool {
        let secret = self.current_secret().await;
        let Ok(response) = self
            .http
            .post(wire::client_secret_url(oauth))
            .header(ACCEPT, "application/json")
            .basic_auth(client_id, Some(secret))
            .send()
            .await
        else {
            return false;
        };
        if response.status().as_u16() != 200 {
            return false;
        }
        let Ok(body) = response.bytes().await else {
            return false;
        };
        if let Some(new_secret) = wire::parse_rotated_secret(&body) {
            *self.rotated_secret.write().await = Some(new_secret);
            return true;
        }
        false
    }

    async fn current_secret(&self) -> String {
        if let Some(secret) = self.rotated_secret.read().await.as_ref() {
            return secret.clone();
        }
        self.config.client_secret.clone().unwrap_or_default()
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
