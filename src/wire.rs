//! Transport-agnostic helpers shared by the async and blocking clients.
//!
//! These functions contain everything that does **not** depend on how the bytes were
//! moved over the network: URL construction, HTTP-status mapping, response parsing and
//! JWT verification. Keeping them here guarantees the async and `blocking` clients apply
//! byte-identical, fail-closed semantics.
//!
//! Token verification is implemented with pure-Rust crypto (`p256`): an ES256 signature is
//! checked against a JWKS key, then `iss` / `aud` / `exp` / `nbf` are validated. A token is
//! accepted only when every check passes.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::error::IamError;
use crate::types::{Claims, Decision, Resource};

/// A single JSON Web Key (only the fields needed to verify an ES256 token).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub x: String,
    #[serde(default)]
    pub y: String,
}

/// A JSON Web Key Set, as served at `/.well-known/jwks.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Jwks {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Find the key whose `kid` matches.
    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Endpoint path for a decision check (mirrors the PHP `HttpDecider`: AIP-style custom method).
pub(crate) fn check_url(base_url: &str) -> String {
    format!("{base_url}/decisions:check")
}

/// Endpoint path for listing resources reachable by a subject under a relation.
pub(crate) fn list_resources_url(base_url: &str) -> String {
    format!("{base_url}/decisions:list-resources")
}

/// JWKS document location.
pub(crate) fn jwks_url(base_url: &str) -> String {
    format!("{base_url}/.well-known/jwks.json")
}

/// Map an HTTP status to an error, or `None` for any 2xx.
///
/// Mirrors the PHP client, which denies on every non-2xx; 401/403 are surfaced as
/// [`IamError::Unauthorized`] for nicer typing, everything else as [`IamError::Http`].
pub(crate) fn status_error(status: u16) -> Option<IamError> {
    match status {
        200..=299 => None,
        401 | 403 => Some(IamError::Unauthorized(status)),
        other => Some(IamError::Http(other)),
    }
}

/// Parse a `decisions:check` response, applying fail-closed rules.
pub(crate) fn parse_decision(status: u16, body: &[u8]) -> Result<Decision, IamError> {
    if let Some(err) = status_error(status) {
        return Err(err);
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|e| IamError::Malformed(e.to_string()))?;
    Decision::from_value(&value)
}

/// Parse a `decisions:list-resources` response into typed resource references.
///
/// Accepts either `{ "resources": [...] }` or a bare top-level array.
pub(crate) fn parse_resources(status: u16, body: &[u8]) -> Result<Vec<Resource>, IamError> {
    if let Some(err) = status_error(status) {
        return Err(err);
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|e| IamError::Malformed(e.to_string()))?;

    let array = value
        .get("resources")
        .or(Some(&value))
        .and_then(Value::as_array)
        .ok_or_else(|| IamError::Malformed("expected a `resources` array".to_string()))?;

    array
        .iter()
        .map(|item| {
            serde_json::from_value::<Resource>(item.clone())
                .map_err(|e| IamError::Malformed(e.to_string()))
        })
        .collect()
}

/// Parse a JWKS document.
pub(crate) fn parse_jwks(body: &[u8]) -> Result<Jwks, IamError> {
    serde_json::from_slice(body).map_err(|e| IamError::Malformed(e.to_string()))
}

/// Does this JWKS contain a key for `kid`?
pub(crate) fn jwks_has_kid(jwks: &Jwks, kid: &str) -> bool {
    jwks.find(kid).is_some()
}

/// Extract the `kid` from a JWT header without verifying anything.
pub(crate) fn token_kid(jwt: &str) -> Result<String, IamError> {
    let header_b64 = jwt
        .split('.')
        .next()
        .ok_or_else(|| IamError::TokenInvalid("token is not a JWT".to_string()))?;
    let header = decode_segment(header_b64)?;
    let header: JoseHeader =
        serde_json::from_slice(&header).map_err(|e| IamError::TokenInvalid(e.to_string()))?;
    header
        .kid
        .ok_or_else(|| IamError::TokenInvalid("token header has no `kid`".to_string()))
}

#[derive(Debug, Deserialize)]
struct JoseHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Verify a JWT against a JWKS using ES256 and the configured issuer/audience.
///
/// Any failure — wrong algorithm, missing/unknown `kid`, bad signature, expired token,
/// wrong issuer/audience, malformed JWK — yields [`IamError::TokenInvalid`]; misconfiguration
/// yields [`IamError::Config`].
pub(crate) fn verify_jwt(
    jwt: &str,
    jwks: &Jwks,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> Result<Claims, IamError> {
    // Issuer/audience are mandatory: a token we cannot fully validate must never be accepted.
    let issuer = issuer.ok_or_else(|| {
        IamError::Config("verify_token requires an issuer to be configured".to_string())
    })?;
    let audience = audience.ok_or_else(|| {
        IamError::Config("verify_token requires an audience to be configured".to_string())
    })?;

    let mut parts = jwt.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IamError::TokenInvalid(
            "token must have exactly three segments".to_string(),
        ));
    };

    let header: JoseHeader = serde_json::from_slice(&decode_segment(header_b64)?)
        .map_err(|e| IamError::TokenInvalid(e.to_string()))?;
    if header.alg != "ES256" {
        return Err(IamError::TokenInvalid(format!(
            "unexpected algorithm `{}`, only ES256 is accepted",
            header.alg
        )));
    }
    let kid = header
        .kid
        .ok_or_else(|| IamError::TokenInvalid("token header has no `kid`".to_string()))?;

    let key = verifying_key(jwks, &kid)?;

    // Verify the signature over `header.payload` before trusting any claim.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = decode_segment(sig_b64)?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| IamError::TokenInvalid(format!("malformed signature: {e}")))?;
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| IamError::TokenInvalid("signature verification failed".to_string()))?;

    let claims: Claims = serde_json::from_slice(&decode_segment(payload_b64)?)
        .map_err(|e| IamError::TokenInvalid(format!("malformed claims: {e}")))?;

    validate_claims(&claims, issuer, audience)?;
    Ok(claims)
}

/// Build a `p256` verifying key from the JWK identified by `kid`.
fn verifying_key(jwks: &Jwks, kid: &str) -> Result<VerifyingKey, IamError> {
    let jwk = jwks
        .find(kid)
        .ok_or_else(|| IamError::TokenInvalid(format!("no JWK matches kid `{kid}`")))?;

    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(IamError::TokenInvalid(
            "JWK is not an EC P-256 key".to_string(),
        ));
    }

    let x = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| IamError::TokenInvalid(format!("invalid JWK `x`: {e}")))?;
    let y = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|e| IamError::TokenInvalid(format!("invalid JWK `y`: {e}")))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(IamError::TokenInvalid(
            "JWK coordinates are not 32 bytes".to_string(),
        ));
    }

    // SEC1 uncompressed point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| IamError::TokenInvalid(format!("unusable JWK: {e}")))
}

/// Validate the registered claims (`iss` / `aud` / `exp` / `nbf`). No leeway.
fn validate_claims(claims: &Claims, issuer: &str, audience: &str) -> Result<(), IamError> {
    if claims.iss != issuer {
        return Err(IamError::TokenInvalid(format!(
            "unexpected issuer `{}`",
            claims.iss
        )));
    }
    if !audience_matches(&claims.aud, audience) {
        return Err(IamError::TokenInvalid("audience mismatch".to_string()));
    }

    let now = now_secs();
    if now >= claims.exp {
        return Err(IamError::TokenInvalid("token has expired".to_string()));
    }
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err(IamError::TokenInvalid("token is not yet valid".to_string()));
        }
    }
    Ok(())
}

/// `aud` may be a single string or an array of strings (RFC 7519).
fn audience_matches(aud: &Value, expected: &str) -> bool {
    match aud {
        Value::String(s) => s == expected,
        Value::Array(items) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, IamError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| IamError::TokenInvalid(format!("invalid base64url segment: {e}")))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
