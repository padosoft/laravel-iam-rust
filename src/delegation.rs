//! Delegated access (RFC 8693): the act chain, and the fail-closed rules around it.
//!
//! A delegated token carries **two** identities — `sub` is the user, `act` is the agent
//! acting for them, nested outward-in when the chain is longer than one hop
//! (RFC 8693 §4.1). Nothing here decides anything: it parses, and it refuses to guess.
//!
//! Parity target: `Padosoft\Iam\Client\Support\DelegatedBearerInspector` in the PHP SDK
//! and `src/delegation.ts` in the Node one. The shapes and the failure modes are identical
//! on purpose — the server cannot tell the callers apart.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::IamError;

/// Header `typ` carried by tokens minted through the token-exchange grant.
pub const TYP_DELEGATED: &str = "delegated+jwt";

/// Subject-type prefix every actor in an act chain must carry.
const AGENT_PREFIX: &str = "agent:";

/// A cyclic or absurdly deep `act` claim must not spin the parser.
const MAX_CHAIN_DEPTH: usize = 16;

/// The authorization view of a delegated bearer token.
///
/// `verified` says where the view came from: `true` only when the claims were returned by
/// the server's introspection endpoint. A `verified: false` view is routing information —
/// it must never authorize anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedBearer {
    /// The delegating user — never the agent.
    pub sub: String,
    /// The act chain, **current actor first** (outermost in the nested claim); the last
    /// element is the root, whose grant governs the whole chain.
    pub actors: Vec<String>,
    /// `pds_dgr` — the grant this delegation descends from, for targeted revocation.
    pub grant_id: Option<String>,
    /// The scopes the token was minted with.
    pub scopes: Vec<String>,
    /// Whether these claims came from server-side introspection.
    pub verified: bool,
}

/// Read the act chain out of a claim set.
///
/// Returns `Ok(None)` when `act` is absent (the token is simply not delegated), and an
/// **error** when it is present but malformed.
///
/// The asymmetry is deliberate and load-bearing: a token with an unreadable `act` must not
/// silently degrade into a full-authority user token. Absent means "not delegated";
/// unreadable means "refuse". That silent degradation is precisely the confused deputy
/// delegation exists to prevent.
///
/// # Errors
/// [`IamError::TokenInvalid`] when `act` is present but not a readable chain of
/// `agent:<id>` levels, or when it nests deeper than 16 hops.
pub fn actor_chain_from_claims(claims: &Value) -> Result<Option<Vec<String>>, IamError> {
    let Some(act) = claims.get("act") else {
        return Ok(None);
    };
    if act.is_null() {
        return Ok(None);
    }

    let mut actors = Vec::new();
    let mut level = act;
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(object) = level.as_object() else {
            return Err(malformed("act level is not an object"));
        };
        let sub = object
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !sub.starts_with(AGENT_PREFIX) || sub.len() <= AGENT_PREFIX.len() {
            return Err(malformed("act level without a valid `agent:<id>` sub"));
        }
        actors.push(sub.to_string());

        match object.get("act") {
            None | Some(Value::Null) => return Ok(Some(actors)),
            Some(next) => level = next,
        }
    }
    Err(malformed("act chain deeper than 16 hops"))
}

/// True when this claim set describes a delegated token.
#[must_use]
pub fn is_delegated(claims: &Value) -> bool {
    !matches!(claims.get("act"), None | Some(Value::Null))
}

/// Split an OAuth `scope` string into a list, dropping empty fragments.
#[must_use]
pub fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Build the authorization view from a claim set.
///
/// Used for **both** halves of the delegated path — the local (unverified, routing-only)
/// inspection and the introspected (verified) one — so the parsing rules cannot diverge
/// between them.
///
/// Returns `Ok(None)` when the claims are not delegated.
///
/// # Errors
/// [`IamError::TokenInvalid`] when the claims are delegated but unreadable, or carry no `sub`.
pub fn delegated_bearer_from_claims(
    claims: &Value,
    verified: bool,
) -> Result<Option<DelegatedBearer>, IamError> {
    let Some(actors) = actor_chain_from_claims(claims)? else {
        return Ok(None);
    };

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if sub.is_empty() {
        return Err(malformed("delegated token without sub"));
    }

    let grant_id = claims
        .get("pds_dgr")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    Ok(Some(DelegatedBearer {
        sub: sub.to_string(),
        actors,
        grant_id,
        scopes: parse_scopes(claims.get("scope").and_then(Value::as_str)),
        verified,
    }))
}

/// **Local** inspection of a bearer JWT — no signature check.
///
/// It answers one question: is this a delegated token, and to whom does it refer? The
/// answer is **routing, never authorization**: a delegated token is authorized through
/// introspection plus a delegated decision, never from what the bytes say locally.
///
/// Returns `Ok(None)` when the token is not delegated (proceed on the normal path).
///
/// # Errors
/// [`IamError::TokenInvalid`] when the token looks delegated but is unreadable.
pub fn inspect_delegated_bearer(jwt: &str) -> Result<Option<DelegatedBearer>, IamError> {
    let mut parts = jwt.split('.');
    let (Some(header_b64), Some(payload_b64), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Ok(None); // not even a JWT: not delegated
    };

    let (Some(header), Some(claims)) = (decode_json(header_b64), decode_json(payload_b64)) else {
        return Ok(None);
    };

    let typ_delegated = header.get("typ").and_then(Value::as_str) == Some(TYP_DELEGATED);
    let has_act = claims.get("act").is_some();
    if !typ_delegated && !has_act {
        return Ok(None);
    }

    // From here the token IS delegated: every defect is refused (fail-closed).
    match delegated_bearer_from_claims(&claims, false)? {
        Some(bearer) => Ok(Some(bearer)),
        // `typ` said delegated but there is no `act` to act on — refuse rather than hand
        // back a token that would then be read as full user authority.
        None => Err(malformed(
            "typ is delegated+jwt but the act claim is absent",
        )),
    }
}

fn decode_json(segment: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

fn malformed(reason: &str) -> IamError {
    IamError::TokenInvalid(format!("malformed delegated token: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwt_of(header: &Value, claims: &Value) -> String {
        let encode = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!("{}.{}.sig", encode(header), encode(claims))
    }

    #[test]
    fn absent_act_is_not_delegated() {
        assert_eq!(
            actor_chain_from_claims(&json!({ "sub": "user:42" })).unwrap(),
            None
        );
        assert_eq!(
            actor_chain_from_claims(&json!({ "sub": "user:42", "act": null })).unwrap(),
            None
        );
    }

    #[test]
    fn nested_chain_is_current_actor_first_root_last() {
        // Outermost = the actor holding the token right now; innermost = the root the user
        // actually consented to. Reading this backwards checks the wrong agent, so it is pinned.
        let claims = json!({ "act": { "sub": "agent:hop2", "act": { "sub": "agent:hop1" } } });
        assert_eq!(
            actor_chain_from_claims(&claims).unwrap(),
            Some(vec!["agent:hop2".to_string(), "agent:hop1".to_string()])
        );
    }

    #[test]
    fn malformed_act_is_refused_never_degraded() {
        for claims in [
            json!({ "act": "agent:a1" }),
            json!({ "act": ["agent:a1"] }),
            json!({ "act": {} }),
            json!({ "act": { "sub": "user:42" } }),
            json!({ "act": { "sub": "agent:" } }),
            json!({ "act": { "sub": "agent:a1", "act": "agent:a2" } }),
        ] {
            assert!(
                actor_chain_from_claims(&claims).is_err(),
                "should refuse: {claims}"
            );
        }
    }

    #[test]
    fn a_chain_deeper_than_the_cap_is_refused_rather_than_spinning() {
        let mut act = json!({ "sub": "agent:leaf" });
        for i in 0..40 {
            act = json!({ "sub": format!("agent:h{i}"), "act": act });
        }
        assert!(actor_chain_from_claims(&json!({ "act": act })).is_err());
    }

    #[test]
    fn bearer_keeps_sub_as_the_user_never_the_agent() {
        let claims = json!({
            "sub": "user:42",
            "act": { "sub": "agent:a1" },
            "pds_dgr": "dgr_01J9",
            "scope": "orders:read orders:draft",
        });
        let bearer = delegated_bearer_from_claims(&claims, true)
            .unwrap()
            .unwrap();
        assert_eq!(bearer.sub, "user:42");
        assert_eq!(bearer.actors, vec!["agent:a1".to_string()]);
        assert_eq!(bearer.grant_id.as_deref(), Some("dgr_01J9"));
        assert_eq!(bearer.scopes, vec!["orders:read", "orders:draft"]);
        assert!(bearer.verified);
    }

    #[test]
    fn a_delegated_token_without_sub_is_refused() {
        assert!(
            delegated_bearer_from_claims(&json!({ "act": { "sub": "agent:a1" } }), false).is_err()
        );
    }

    #[test]
    fn local_inspection_is_never_marked_verified() {
        let jwt = jwt_of(
            &json!({ "alg": "ES256", "typ": TYP_DELEGATED }),
            &json!({ "sub": "user:42", "act": { "sub": "agent:a1" } }),
        );
        let bearer = inspect_delegated_bearer(&jwt).unwrap().unwrap();
        assert!(!bearer.verified, "local bytes must never authorize");
    }

    #[test]
    fn plain_tokens_and_non_jwts_are_simply_not_delegated() {
        let plain = jwt_of(&json!({ "alg": "ES256" }), &json!({ "sub": "user:42" }));
        assert_eq!(inspect_delegated_bearer(&plain).unwrap(), None);
        assert_eq!(inspect_delegated_bearer("not-a-jwt").unwrap(), None);
        assert_eq!(inspect_delegated_bearer("").unwrap(), None);
    }

    #[test]
    fn act_alone_is_enough_to_detect_delegation() {
        let jwt = jwt_of(
            &json!({ "alg": "ES256" }),
            &json!({ "sub": "user:42", "act": { "sub": "agent:a1" } }),
        );
        assert!(inspect_delegated_bearer(&jwt).unwrap().is_some());
    }

    #[test]
    fn typ_delegated_without_act_is_refused() {
        // The dangerous case: without the refusal this reads back as a full-authority user token.
        let jwt = jwt_of(
            &json!({ "alg": "ES256", "typ": TYP_DELEGATED }),
            &json!({ "sub": "user:42" }),
        );
        assert!(inspect_delegated_bearer(&jwt).is_err());
    }

    #[test]
    fn scopes_split_and_drop_blanks() {
        assert_eq!(parse_scopes(Some("a  b")), vec!["a", "b"]);
        assert_eq!(parse_scopes(Some("")), Vec::<String>::new());
        assert_eq!(parse_scopes(None), Vec::<String>::new());
    }
}
