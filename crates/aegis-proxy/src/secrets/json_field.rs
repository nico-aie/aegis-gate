//! Shared JSON-or-plain-string field extraction for the
//! cloud secret-manager resolvers.
//!
//! AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and
//! HashiCorp Vault all expose the same shape: a "secret" is
//! either a plain string or a JSON object whose keys are the
//! actual secret values. Operators reference one piece via
//! `${secret:<provider>:<id>#<field>}`. This helper centralizes
//! the field-extraction logic so every resolver behaves
//! identically:
//!
//! - **No `field`** — return the whole string, trim trailing
//!   newlines (common when secrets are copy-pasted from a
//!   terminal), preserve internal whitespace.
//! - **With `field`** — parse the string as JSON, require an
//!   object (not array), extract the named key, allow scalar
//!   values only (string / number / bool — non-scalar types
//!   reject with a clear error rather than silently
//!   `{}`-stringifying).
//! - **Missing field** — error lists every available key in the
//!   object so a typo is obvious from the message.

use serde_json::Value;

use super::{SecretError, SecretValue};

/// Extract a value from raw secret content.
///
/// `id` is a human-readable identifier for the secret (used only
/// in error messages — typically the ARN/path the operator
/// referenced).
pub fn extract(
    raw: &str,
    field: Option<&str>,
    id: &str,
) -> Result<SecretValue, SecretError> {
    let Some(key) = field else {
        return Ok(SecretValue::new(raw.trim_end_matches('\n').to_string()));
    };

    let parsed: Value = serde_json::from_str(raw).map_err(|e| {
        SecretError::ParseError(format!(
            "secret {id} has #{key} but value isn't JSON: {e}"
        ))
    })?;
    let obj = parsed.as_object().ok_or_else(|| {
        SecretError::ParseError(format!(
            "secret {id} is JSON but not an object — can't extract #{key}"
        ))
    })?;
    let val = obj.get(key).ok_or_else(|| {
        SecretError::NotFound(format!(
            "secret {id} missing field #{key}; available keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        ))
    })?;

    match val {
        Value::String(s) => Ok(SecretValue::new(s.clone())),
        Value::Number(n) => Ok(SecretValue::new(n.to_string())),
        Value::Bool(b) => Ok(SecretValue::new(b.to_string())),
        other => Err(SecretError::ParseError(format!(
            "field #{key} in {id} is non-scalar ({other}); only strings/numbers/bools are valid secret values"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ID: &str = "test/secret";

    #[test]
    fn no_field_returns_whole_string() {
        let v = extract("hunter2", None, TEST_ID).unwrap();
        assert_eq!(v.expose(), "hunter2");
    }

    #[test]
    fn no_field_trims_trailing_newline() {
        let v = extract("hunter2\n", None, TEST_ID).unwrap();
        assert_eq!(v.expose(), "hunter2");
    }

    #[test]
    fn no_field_preserves_internal_whitespace() {
        let v = extract("multi\nline\nsecret", None, TEST_ID).unwrap();
        assert_eq!(v.expose(), "multi\nline\nsecret");
    }

    #[test]
    fn field_extracts_string_value_from_json_object() {
        let v = extract(
            r#"{"username":"admin","password":"hunter2"}"#,
            Some("password"),
            TEST_ID,
        )
        .unwrap();
        assert_eq!(v.expose(), "hunter2");
    }

    #[test]
    fn field_extracts_number_value_as_stringified() {
        let v = extract(r#"{"port":5432}"#, Some("port"), TEST_ID).unwrap();
        assert_eq!(v.expose(), "5432");
    }

    #[test]
    fn field_extracts_bool_value_as_stringified() {
        let v = extract(r#"{"enabled":true}"#, Some("enabled"), TEST_ID).unwrap();
        assert_eq!(v.expose(), "true");
    }

    #[test]
    fn field_with_non_json_secret_errors_actionably() {
        let err = extract("not-json", Some("password"), TEST_ID).unwrap_err();
        match err {
            SecretError::ParseError(msg) => {
                assert!(msg.contains("isn't JSON"), "got: {msg}");
                assert!(msg.contains(TEST_ID), "should include id: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn field_with_json_array_errors_actionably() {
        let err = extract(r#"["a","b"]"#, Some("0"), TEST_ID).unwrap_err();
        match err {
            SecretError::ParseError(msg) => {
                assert!(msg.contains("not an object"), "got: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn missing_field_lists_available_keys() {
        let err = extract(
            r#"{"username":"admin","password":"hunter2"}"#,
            Some("token"),
            TEST_ID,
        )
        .unwrap_err();
        match err {
            SecretError::NotFound(msg) => {
                assert!(msg.contains("missing field #token"), "got: {msg}");
                assert!(msg.contains("username"), "should list available keys: {msg}");
                assert!(msg.contains("password"), "should list available keys: {msg}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn nested_object_field_errors() {
        let err = extract(
            r#"{"creds":{"user":"admin","pass":"hunter2"}}"#,
            Some("creds"),
            TEST_ID,
        )
        .unwrap_err();
        match err {
            SecretError::ParseError(msg) => {
                assert!(msg.contains("non-scalar"), "got: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn null_field_errors() {
        let err = extract(r#"{"password":null}"#, Some("password"), TEST_ID)
            .unwrap_err();
        match err {
            SecretError::ParseError(msg) => {
                assert!(msg.contains("non-scalar"), "got: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }
}
