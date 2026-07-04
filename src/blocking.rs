//! Synchronous IAM client (enabled by the `blocking` feature).
//!
//! Same fail-closed semantics as the async [`crate::IamClient`], built on
//! `reqwest::blocking`. Do not call it from inside an async runtime thread.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
    token_cache: Arc<RwLock<Option<(String, Instant)>>>,
    rotated_secret: Arc<RwLock<Option<String>>>,
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
            token_cache: Arc::new(RwLock::new(None)),
            rotated_secret: Arc::new(RwLock::new(None)),
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
        if let Some(token) = self.resolve_token() {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request.json(body).send().map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().map_err(map_reqwest_error)?;
        Ok((status, bytes.to_vec()))
    }

    /// Resolve the Bearer: static token, or self-managed `client_credentials` (mint + cache + auto-follow
    /// secret rotation via self-fetch). `None` → no header → fail-closed deny. Mirrors the async client.
    fn resolve_token(&self) -> Option<String> {
        if !self.config.uses_client_credentials() {
            return self.config.token.clone();
        }
        let client_id = self.config.client_id.as_deref()?;
        if let Ok(guard) = self.token_cache.read() {
            if let Some((token, expiry)) = guard.as_ref() {
                if Instant::now() < *expiry {
                    return Some(token.clone());
                }
            }
        }
        let oauth = self.config.oauth_base();
        if let Some(token) = self.mint_token(client_id, &oauth) {
            return Some(token);
        }
        if self.fetch_rotated_secret(client_id, &oauth) {
            return self.mint_token(client_id, &oauth);
        }
        None
    }

    fn mint_token(&self, client_id: &str, oauth: &str) -> Option<String> {
        let secret = self.current_secret();
        let response = self
            .http
            .post(wire::token_url(oauth))
            .header(ACCEPT, "application/json")
            .basic_auth(client_id, Some(secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .ok()?;
        if response.status().as_u16() != 200 {
            return None;
        }
        let body = response.bytes().ok()?;
        let (token, expires_in) = wire::parse_token(&body)?;
        let expiry = Instant::now() + Duration::from_secs(expires_in.saturating_sub(30).max(1));
        if let Ok(mut guard) = self.token_cache.write() {
            *guard = Some((token.clone(), expiry));
        }
        Some(token)
    }

    fn fetch_rotated_secret(&self, client_id: &str, oauth: &str) -> bool {
        let secret = self.current_secret();
        let Ok(response) = self
            .http
            .post(wire::client_secret_url(oauth))
            .header(ACCEPT, "application/json")
            .basic_auth(client_id, Some(secret))
            .send()
        else {
            return false;
        };
        if response.status().as_u16() != 200 {
            return false;
        }
        let Ok(body) = response.bytes() else {
            return false;
        };
        if let Some(new_secret) = wire::parse_rotated_secret(&body) {
            if let Ok(mut guard) = self.rotated_secret.write() {
                *guard = Some(new_secret);
            }
            return true;
        }
        false
    }

    fn current_secret(&self) -> String {
        if let Ok(guard) = self.rotated_secret.read() {
            if let Some(secret) = guard.as_ref() {
                return secret.clone();
            }
        }
        self.config.client_secret.clone().unwrap_or_default()
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
