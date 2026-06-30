//! Wire types for the IAM decision protocol.
//!
//! These mirror, byte-for-byte, the request/response contract spoken by the canonical
//! PHP client (`Padosoft\Iam\Client\Deciders\HttpDecider`): the request is the JSON body
//! of `POST {base_url}/decisions:check`, and the response is parsed with the same
//! defensive, fail-closed rules as `IamDecision::fromArray`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::IamError;

/// The principal a decision is about: `{ "type": "...", "id": "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Subject type, e.g. `user`, `service_account`, `group`, `agent`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Stable subject identifier.
    pub id: String,
}

impl Subject {
    /// Build a subject with an explicit type.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }

    /// Convenience for `type = "user"`.
    pub fn user(id: impl Into<String>) -> Self {
        Self::new("user", id)
    }

    /// Convenience for `type = "service_account"`.
    pub fn service_account(id: impl Into<String>) -> Self {
        Self::new("service_account", id)
    }

    /// Convenience for `type = "group"`.
    pub fn group(id: impl Into<String>) -> Self {
        Self::new("group", id)
    }
}

/// A typed resource reference, e.g. an entry returned by
/// [`IamClient::list_resources`](crate::IamClient::list_resources).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// Resource type, e.g. `warehouse`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Resource identifier, e.g. `wh_milan`.
    pub id: String,
}

impl Resource {
    /// Build a resource reference.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// A policy-decision query.
///
/// Serialized verbatim into the body of `POST {base_url}/decisions:check`, matching the PHP
/// `DecisionRequest::toArray()` shape exactly — including the `current_aal` field and the
/// `resource` field encoded as a plain string (not an object).
///
/// Build it with a struct literal and [`Default`]:
///
/// ```
/// use laravel_iam::{DecisionQuery, Subject};
/// use serde_json::json;
///
/// let q = DecisionQuery {
///     subject: Subject::user("usr_123"),
///     application: Some("warehouse".into()),
///     permission: "stock.adjust".into(),
///     resource: Some("wh_milan".into()),
///     context: json!({ "amount": 300 }),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionQuery {
    /// Who is asking.
    pub subject: Subject,
    /// The permission/ability being checked, e.g. `stock.adjust`.
    pub permission: String,
    /// Optional organization scope.
    pub organization: Option<String>,
    /// Optional application scope.
    pub application: Option<String>,
    /// Optional resource scope, encoded as a plain string to mirror the PHP client.
    pub resource: Option<String>,
    /// Free-form ABAC facts (amount, time, …). Defaults to an empty object.
    pub context: Value,
    /// The subject's current authenticator assurance level. Defaults to `aal1`.
    pub current_aal: String,
    /// Ask the server to include a human-readable explanation in the response.
    pub explain: bool,
}

impl Default for DecisionQuery {
    fn default() -> Self {
        Self {
            subject: Subject::new(String::new(), String::new()),
            permission: String::new(),
            organization: None,
            application: None,
            resource: None,
            context: Value::Object(serde_json::Map::new()),
            current_aal: "aal1".to_string(),
            explain: false,
        }
    }
}

impl DecisionQuery {
    /// Start a query for `subject` asking about `permission`; all other fields take their defaults.
    pub fn new(subject: Subject, permission: impl Into<String>) -> Self {
        Self {
            subject,
            permission: permission.into(),
            ..Self::default()
        }
    }
}

/// A normalized policy decision.
///
/// Parsed from the server response with the same defensive rules as the PHP
/// `IamDecision::fromArray`: a field that is missing or has the wrong type falls back to its
/// safe default, and `allowed` is `true` only when the server sent the boolean `true`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Whether the policy engine permitted the action. **Not sufficient on its own** to
    /// allow an action — see [`Decision::granted`].
    pub allowed: bool,
    /// Opaque decision identifier for auditing/correlation.
    pub decision_id: String,
    /// Policy version that produced this decision (used for cache invalidation).
    pub policy_version: i64,
    /// The action is permitted only after a step-up to a higher assurance level.
    pub requires_step_up: bool,
    /// The assurance level required when [`Decision::requires_step_up`] is set.
    pub required_aal: Option<String>,
    /// Human-readable explanation lines (present when `explain` was requested).
    pub explanation: Vec<String>,
}

impl Decision {
    /// An explicit denial, carrying a reason. Used for fail-closed defaults.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            explanation: vec![reason.into()],
            ..Self::default()
        }
    }

    /// Parse a decision from an already-decoded JSON value, mirroring `IamDecision::fromArray`.
    ///
    /// # Errors
    /// Returns [`IamError::Malformed`] if the value is not a JSON object.
    pub(crate) fn from_value(value: &Value) -> Result<Self, IamError> {
        let obj = value
            .as_object()
            .ok_or_else(|| IamError::Malformed("response body is not a JSON object".to_string()))?;

        let explanation = obj
            .get("explanation")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            // Allowed ONLY when the server explicitly sent boolean `true`.
            allowed: obj.get("allowed") == Some(&Value::Bool(true)),
            decision_id: obj
                .get("decision_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            policy_version: obj
                .get("policy_version")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            requires_step_up: obj.get("requires_step_up") == Some(&Value::Bool(true)),
            required_aal: obj
                .get("required_aal")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            explanation,
        })
    }

    /// The fail-safe gate: permitted **and** no pending step-up.
    ///
    /// This is the value a naive `allow/deny` gate should use; a caller that wants to drive a
    /// step-up flow can inspect [`Decision::requires_step_up`] / [`Decision::required_aal`].
    #[must_use]
    pub fn granted(&self) -> bool {
        self.allowed && !self.requires_step_up
    }

    /// Alias of [`Decision::granted`]: the fail-safe "is this truly allowed?" check.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.granted()
    }
}

/// Verified claims extracted from an OIDC access/ID token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier (`sub`).
    pub sub: String,
    /// Token issuer (`iss`).
    pub iss: String,
    /// Audience (`aud`) — a string or array per RFC 7519.
    #[serde(default)]
    pub aud: Value,
    /// Expiration time (`exp`, seconds since the Unix epoch).
    pub exp: i64,
    /// Not-before time (`nbf`), if present.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Issued-at time (`iat`), if present.
    #[serde(default)]
    pub iat: Option<i64>,
    /// Any additional claims not captured above.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
