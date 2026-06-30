//! Shared helpers for the integration tests: ES256 signing and JWKS fixtures.
//!
//! The private key and its matching JWKS live in `tests/fixtures/` and were generated with
//! OpenSSL (P-256). Tokens are signed here with pure-Rust `p256` so the suite needs no crypto
//! toolchain.

#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::Value;

pub const ISSUER: &str = "https://iam.example.com";
pub const AUDIENCE: &str = "warehouse-api";
pub const KID: &str = "test-key-1";

/// The JWKS document matching the fixture private key.
pub const JWKS_JSON: &str = include_str!("../fixtures/jwks.json");

fn signing_key() -> SigningKey {
    let pem = include_str!("../fixtures/es256-private.pem");
    SigningKey::from_pkcs8_pem(pem).expect("fixture is a valid PKCS#8 EC key")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Current Unix time in seconds.
pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Sign an ES256 JWT with the fixture key, using `kid` in the header.
pub fn sign_jwt_with_kid(claims: &Value, kid: &str) -> String {
    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
    let header_b64 = b64(&serde_json::to_vec(&header).unwrap());
    let payload_b64 = b64(&serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = signing_key().sign(signing_input.as_bytes());
    let sig_b64 = b64(&signature.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

/// Sign an ES256 JWT with the fixture key and the canonical test `kid`.
pub fn sign_jwt(claims: &Value) -> String {
    sign_jwt_with_kid(claims, KID)
}

/// A valid claim set (issuer/audience correct, not expired).
pub fn valid_claims() -> Value {
    serde_json::json!({
        "sub": "usr_123",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now(),
        "exp": now() + 3600,
    })
}
