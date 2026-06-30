//! Synchronous IAM client (enabled by the `blocking` feature).
//!
//! Same fail-closed semantics as the async [`crate::IamClient`], built on
//! `reqwest::blocking`. Do not call it from inside an async runtime thread.

use std::sync::{Arc, RwLock};

use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::json;

use crate::client::map_reqwest_error;
use crate::config::{Config, IamClientBuilder};
use crate::error::IamError;
use crate::types::{Claims, Decision, DecisionQuery, Resource, Subject};
use crate::wire::{self, Jwks};

/// A thin, fail-closed synchronous client for the Laravel IAM control plane.
#[derive(Clone)]
pub struct IamClient {
    http: reqwest::blocking::Client,
    config: Arc<Config>,
    jwks_cache: Arc<RwLock<Option<Jwks>>>,
}

impl IamClient {
    /// Start building a client. Finish with [`IamClientBuilder::build_blocking`].
    #[must_use]
    pub fn builder() -> IamClientBuilder {
        IamClientBuilder::default()
    }

    fn from_config(config: Config) -> Result<Self, IamError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| IamError::Network(e.to_string()))?;
        Ok(Self {
            http,
            config: Arc::new(config),
            jwks_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Ask the server for a policy decision (fail-closed).
    ///
    /// # Errors
    /// See [`IamError`].
    #[allow(clippy::needless_pass_by_value)] // mirrors the async client's owned-query API
    pub fn check(&self, query: DecisionQuery) -> Result<Decision, IamError> {
        let (status, body) = self.send_json(&wire::check_url(&self.config.base_url), &query)?;
        wire::parse_decision(status, &body)
    }

    /// List the resources a subject can reach under a relation.
    ///
    /// # Errors
    /// See [`IamError`].
    #[allow(clippy::needless_pass_by_value)] // mirrors the async client's owned-subject API
    pub fn list_resources(
        &self,
        subject: Subject,
        relation: impl AsRef<str>,
    ) -> Result<Vec<Resource>, IamError> {
        let payload = json!({ "subject": subject, "relation": relation.as_ref() });
        let (status, body) =
            self.send_json(&wire::list_resources_url(&self.config.base_url), &payload)?;
        wire::parse_resources(status, &body)
    }

    /// Verify an OIDC token (ES256 + `iss`/`aud`/`exp`) against the cached JWKS.
    ///
    /// # Errors
    /// [`IamError::TokenInvalid`] on any verification failure, or [`IamError::Config`] if no
    /// issuer/audience were configured.
    pub fn verify_token(&self, jwt: &str) -> Result<Claims, IamError> {
        let kid = wire::token_kid(jwt)?;
        let jwks = self.jwks_for_kid(&kid)?;
        wire::verify_jwt(
            jwt,
            &jwks,
            self.config.issuer.as_deref(),
            self.config.audience.as_deref(),
        )
    }

    fn jwks_for_kid(&self, kid: &str) -> Result<Jwks, IamError> {
        if let Some(jwks) = self
            .jwks_cache
            .read()
            .expect("jwks cache lock poisoned")
            .as_ref()
        {
            if wire::jwks_has_kid(jwks, kid) {
                return Ok(jwks.clone());
            }
        }
        let fetched = self.fetch_jwks()?;
        *self.jwks_cache.write().expect("jwks cache lock poisoned") = Some(fetched.clone());
        Ok(fetched)
    }

    fn fetch_jwks(&self) -> Result<Jwks, IamError> {
        let response = self
            .http
            .get(wire::jwks_url(&self.config.base_url))
            .header(ACCEPT, "application/json")
            .send()
            .map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let body = response.bytes().map_err(map_reqwest_error)?;
        if let Some(err) = wire::status_error(status) {
            return Err(err);
        }
        wire::parse_jwks(&body)
    }

    fn send_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<(u16, Vec<u8>), IamError> {
        let mut request = self.http.post(url).header(ACCEPT, "application/json");
        if let Some(token) = &self.config.token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request.json(body).send().map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().map_err(map_reqwest_error)?;
        Ok((status, bytes.to_vec()))
    }
}

impl IamClientBuilder {
    /// Build a synchronous [`blocking::IamClient`](crate::blocking::IamClient).
    ///
    /// # Errors
    /// Returns [`IamError::Config`] for invalid configuration, or [`IamError::Network`] if the
    /// underlying HTTP client cannot be created.
    pub fn build_blocking(self) -> Result<IamClient, IamError> {
        IamClient::from_config(self.finish()?)
    }
}
