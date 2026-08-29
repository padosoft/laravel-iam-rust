//! Asynchronous IAM client (built on `reqwest` + `tokio`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::config::{Config, IamClientBuilder};
use crate::delegation::{inspect_delegated_bearer, DelegatedBearer};
use crate::error::IamError;
use crate::manifest::validate_manifest;
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
        let url = if query.is_delegated() {
            wire::check_delegated_url(&self.config.base_url)
        } else {
            wire::check_url(&self.config.base_url)
        };
        let response = self.send_json(&url, &query).await?;
        let (status, body) = read(response).await?;
        wire::parse_decision(status, &body)
    }

    /// Ask whether an **agent may act on behalf of a user**.
    ///
    /// The verdict is the strict intersection — the subject's authority AND every actor's
    /// authority AND the grant's scope — never the union. Adding a hop can only narrow what
    /// is permitted; it can never grant anything new.
    ///
    /// `actors` is the act chain, `agent:<id>`, **current actor first**. An empty chain is
    /// not "check the user instead", it is a refusal: it means the caller lost track of who
    /// is acting, and answering the user-only question there would hand the agent's request
    /// the user's full authority.
    ///
    /// # Errors
    /// [`IamError::Config`] on an empty actor chain; otherwise as [`check`](Self::check).
    pub async fn check_delegated(
        &self,
        subject: Subject,
        actors: Vec<String>,
        permission: impl Into<String>,
    ) -> Result<Decision, IamError> {
        self.check_delegated_with(DecisionQuery {
            subject,
            permission: permission.into(),
            actors,
            ..DecisionQuery::default()
        })
        .await
    }

    /// [`check_delegated`](Self::check_delegated) with a fully-built query, for callers that
    /// need `resource`, `context`, `organization`, `current_aal` or `delegation_grant_id`.
    ///
    /// # Errors
    /// [`IamError::Config`] when `query.actors` is empty; otherwise as [`check`](Self::check).
    pub async fn check_delegated_with(&self, query: DecisionQuery) -> Result<Decision, IamError> {
        let query = require_actors(query)?;
        self.check(query).await
    }

    /// Verify a **delegated** bearer token.
    ///
    /// Delegated tokens are **introspection-mandatory** (RFC 7662): the authorization view is
    /// built from the claims the server returns — it verifies the signature, the expiry AND
    /// that the delegating user's session is still alive — never from the local parse.
    /// `typ: delegated+jwt` is routing, not a defence.
    ///
    /// Returns `Ok(None)` for a token that is **not** delegated: that token is not this
    /// method's business, verify it with [`verify_token`](Self::verify_token) instead.
    ///
    /// # Errors
    /// [`IamError::TokenInvalid`] when the token is delegated but malformed, when
    /// introspection is unreachable or refuses it, or when the response is incoherent.
    /// Every error is a deny — there is no partial acceptance.
    pub async fn verify_delegated_token(
        &self,
        jwt: &str,
    ) -> Result<Option<DelegatedBearer>, IamError> {
        let Some(local) = inspect_delegated_bearer(jwt)? else {
            return Ok(None); // not delegated: not this path
        };

        let endpoint = self.config.introspection_endpoint();
        if endpoint.is_empty() {
            // No introspection possible ⇒ no delegated authorization. Never the local parse.
            return Err(IamError::Config(
                "delegated tokens require an introspection endpoint".to_string(),
            ));
        }

        let mut request = self.http.post(&endpoint).header(ACCEPT, "application/json");
        if let Some(token) = self.resolve_token().await {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .form(&[("token", jwt)])
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let (status, body) = read(response).await?;

        wire::parse_introspection(status, &body, &local)
            .map(Some)
            .ok_or_else(|| {
                IamError::TokenInvalid("introspection did not confirm the delegation".to_string())
            })
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

    /// Push a manifest to IAM's Admin API (`POST /applications/{app}/manifests`) — declare & sync a permission
    /// catalog/roles for a service that owns them. Validates locally first, then submits with the bearer + an
    /// `Idempotency-Key`. IAM diffs it: additive changes apply, a removal is gated for approval and the removed
    /// role/permission is **deprecated** (kept for history, disabled), never deleted. `app_key` defaults to the
    /// manifest's `app.key`. Returns the response body's `data` (or the whole body).
    ///
    /// # Errors
    /// [`IamError::Config`] if there is no app key or the manifest fails local validation;
    /// [`IamError::Http`]/[`IamError::Network`] on a non-2xx or transport failure.
    pub async fn submit_manifest(
        &self,
        app_key: Option<&str>,
        manifest: &Value,
    ) -> Result<Value, IamError> {
        let app = app_key
            .map(str::to_string)
            .or_else(|| {
                manifest
                    .get("app")
                    .and_then(|a| a.get("key"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                IamError::Config("no app key (pass app_key or set manifest.app.key)".into())
            })?;

        let validation = validate_manifest(manifest);
        if !validation.valid {
            return Err(IamError::Config(format!(
                "invalid manifest: {}",
                validation.errors.join("; ")
            )));
        }

        let mut request = self
            .http
            .post(wire::manifest_url(&self.config.base_url, &app))
            .header(ACCEPT, "application/json")
            .header("Idempotency-Key", next_jti());
        if let Some(token) = self.resolve_token().await {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .json(&json!({ "manifest": manifest }))
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let (status, body) = read(response).await?;
        if !(200..300).contains(&status) {
            return Err(IamError::Http(status));
        }
        let parsed: Value =
            serde_json::from_slice(&body).map_err(|e| IamError::Malformed(e.to_string()))?;
        Ok(parsed.get("data").cloned().unwrap_or(parsed))
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
        // private_key_jwt (RFC 7523): sign a fresh assertion and exchange it — no shared secret. Cached.
        if self.config.uses_private_key_jwt() {
            if let Some((token, expiry)) = self.token_cache.read().await.as_ref() {
                if Instant::now() < *expiry {
                    return Some(token.clone());
                }
            }
            return self.mint_with_assertion().await;
        }
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

    async fn mint_with_assertion(&self) -> Option<String> {
        let assertion = self.build_assertion()?;
        let response = self
            .http
            .post(wire::token_url(&self.config.oauth_base()))
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "client_credentials"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
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

    fn build_assertion(&self) -> Option<String> {
        let client_id = self.config.client_id.as_deref()?;
        let private_key = self.config.private_key.as_deref()?;
        let aud = format!("{}/token", self.config.oauth_base().trim_end_matches('/'));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        wire::build_client_assertion(
            private_key,
            client_id,
            &aud,
            self.config.private_key_kid.as_deref(),
            60,
            now,
            &next_jti(),
        )
    }
}

/// A per-process-unique jti for a `private_key_jwt` assertion (nanos + a monotonic counter). The server also
/// enforces single-use per jti, so this only needs to avoid local collisions within an assertion's lifetime.
pub(crate) fn next_jti() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos}-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
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

/// Drop blank actors and refuse an empty chain. Shared by both client flavours so the
/// refusal cannot drift between them.
pub(crate) fn require_actors(mut query: DecisionQuery) -> Result<DecisionQuery, IamError> {
    query.actors.retain(|a| !a.is_empty());
    if query.actors.is_empty() {
        return Err(IamError::Config(
            "a delegated check requires a non-empty actor chain".to_string(),
        ));
    }
    Ok(query)
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
