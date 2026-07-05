//! Manifest tooling — declare & validate a permission catalog/roles for IAM, the cross-language equivalent of
//! the Laravel client's `iam:manifest:push`. A service that owns a catalog **declares** it in a manifest (a
//! versioned file — the source of truth). [`validate_manifest`] checks it locally (mirrors the server rules +
//! the published JSON Schema at `/.well-known/iam-manifest-schema.json`); pushing is
//! [`crate::IamClient::submit_manifest`].

use serde_json::Value;

/// Result of a local manifest validation.
#[derive(Debug, Clone)]
pub struct ManifestValidation {
    /// True when there are no errors.
    pub valid: bool,
    /// Human-readable problems (empty when valid).
    pub errors: Vec<String>,
}

const RISK: [&str; 4] = ["low", "medium", "high", "critical"];

/// Slug rule shared by app/permission/role keys: `^[a-z][a-z0-9_.-]*$`.
fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-')
}

/// Validate a manifest value against the `laravel-iam.manifest.v2` rules. Pure, no network.
pub fn validate_manifest(manifest: &Value) -> ManifestValidation {
    let mut errors: Vec<String> = Vec::new();

    if manifest.get("schema").and_then(Value::as_str) != Some("laravel-iam.manifest.v2") {
        errors.push("schema must be \"laravel-iam.manifest.v2\"".into());
    }

    let app = manifest.get("app");
    match app.and_then(|a| a.get("key")).and_then(Value::as_str) {
        Some(k) if is_valid_key(k) => {}
        _ => errors.push("app.key missing or malformed (slug [a-z][a-z0-9_.-]*)".into()),
    }
    match app.and_then(|a| a.get("name")).and_then(Value::as_str) {
        Some(n) if !n.is_empty() => {}
        _ => errors.push("app.name required".into()),
    }
    if let Some(rl) = app
        .and_then(|a| a.get("risk_level"))
        .and_then(Value::as_str)
    {
        if !RISK.contains(&rl) {
            errors.push("app.risk_level invalid (low|medium|high|critical)".into());
        }
    }

    let mut perm_keys: Vec<String> = Vec::new();
    if let Some(perms) = manifest.get("permissions").and_then(Value::as_array) {
        for (i, p) in perms.iter().enumerate() {
            match p.get("key").and_then(Value::as_str) {
                Some(k) if is_valid_key(k) => {
                    if perm_keys.iter().any(|e| e == k) {
                        errors.push(format!("permissions: duplicate key \"{k}\""));
                    }
                    perm_keys.push(k.to_string());
                }
                _ => errors.push(format!("permissions[{i}].key missing or malformed")),
            }
            if let Some(r) = p.get("risk").and_then(Value::as_str) {
                if !RISK.contains(&r) {
                    errors.push(format!("permissions risk invalid: {r}"));
                }
            }
        }
    }

    if let Some(roles) = manifest.get("roles").and_then(Value::as_array) {
        for (i, r) in roles.iter().enumerate() {
            let rkey = r.get("key").and_then(Value::as_str);
            match rkey {
                Some(k) if is_valid_key(k) => {}
                _ => errors.push(format!("roles[{i}].key missing or malformed")),
            }
            if let Some(refs) = r.get("permissions").and_then(Value::as_array) {
                for pref in refs {
                    let pk = pref.as_str().unwrap_or("");
                    if !perm_keys.iter().any(|e| e == pk) {
                        errors.push(format!(
                            "roles[\"{}\"] references an undeclared permission: {pk}",
                            rkey.unwrap_or("")
                        ));
                    }
                }
            }
        }
    }

    ManifestValidation {
        valid: errors.is_empty(),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_a_well_formed_manifest() {
        let m = json!({
            "schema": "laravel-iam.manifest.v2",
            "app": { "key": "shop", "name": "Shop" },
            "permissions": [{ "key": "orders.view", "risk": "low" }],
            "roles": [{ "key": "clerk", "permissions": ["orders.view"] }]
        });
        let v = validate_manifest(&m);
        assert!(v.valid, "{:?}", v.errors);
    }

    #[test]
    fn rejects_bad_schema_key_and_dangling_role_ref() {
        let m = json!({
            "schema": "wrong",
            "app": { "key": "Bad Key", "name": "X" },
            "permissions": [{ "key": "orders.view" }],
            "roles": [{ "key": "clerk", "permissions": ["orders.delete"] }]
        });
        let v = validate_manifest(&m);
        assert!(!v.valid);
        assert!(v.errors.iter().any(|e| e.contains("schema")));
        assert!(v.errors.iter().any(|e| e.contains("app.key")));
        assert!(v.errors.iter().any(|e| e.contains("undeclared permission")));
    }
}
