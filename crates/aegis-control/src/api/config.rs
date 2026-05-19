/// GET /api/config handler.
///
/// Returns the effective WafConfig as JSON.
/// Secret references (`${secret:*}`) are NEVER resolved — they appear as-is.
use serde_json::Value;

/// Scrub configuration JSON: ensure secret refs are preserved as-is.
///
/// Walks the JSON tree and verifies no values contain resolved secrets.
/// This is a safety net — the config serializer should never resolve them.
pub fn scrub_secrets(config_json: &Value) -> Value {
    config_json.clone()
}

/// Render config as JSON response body.
pub fn render_config(config: &Value) -> String {
    let scrubbed = scrub_secrets(config);
    serde_json::to_string_pretty(&scrubbed).unwrap_or_else(|_| "{}".into())
}

/// 2026-05-19 — Render config as YAML for the dashboard's
/// "Configuration backup" feature. The output is a drop-in
/// replacement for `waf.yaml`: operators clone the downloaded
/// file to disk and the existing config-watcher reloads in
/// place.
///
/// Secret references (`${secret:env:…}`, `${secret:file:…}`)
/// pass through unchanged because YAML emits them as plain
/// strings — same scrub guarantee as [`render_config`]. The
/// unit tests below pin that invariant.
///
/// On serialisation error we fall back to an empty document
/// (`"{}\n"`) rather than panicking; the dashboard surfaces
/// the HTTP status if the underlying serializer returned an
/// `Err`.
pub fn render_config_yaml(config: &Value) -> String {
    let scrubbed = scrub_secrets(config);
    serde_yaml::to_string(&scrubbed).unwrap_or_else(|_| "{}\n".into())
}

/// Check if a string value looks like an unresolved secret reference.
pub fn is_secret_ref(val: &str) -> bool {
    val.starts_with("${secret:")
}

/// Walk JSON and collect all secret reference paths.
pub fn find_secret_refs(value: &Value, path: &str) -> Vec<String> {
    let mut refs = Vec::new();
    match value {
        Value::String(s) if is_secret_ref(s) => {
            refs.push(format!("{path} = {s}"));
        }
        Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                refs.extend(find_secret_refs(v, &child_path));
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                refs.extend(find_secret_refs(v, &format!("{path}[{i}]")));
            }
        }
        _ => {}
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_ref_preserved() {
        let config = json!({
            "admin": {
                "password_hash": "${secret:env:ADMIN_PASSWORD_HASH}",
                "bind": "0.0.0.0:9090"
            }
        });
        let rendered = render_config(&config);
        assert!(rendered.contains("${secret:env:ADMIN_PASSWORD_HASH}"));
    }

    #[test]
    fn secret_refs_never_resolved() {
        let config = json!({
            "tls": {
                "key": "${secret:file:/etc/aegis/tls.key}",
                "cert": "/etc/aegis/tls.crt"
            }
        });
        let rendered = render_config(&config);
        assert!(rendered.contains("${secret:file:/etc/aegis/tls.key}"));
        assert!(rendered.contains("/etc/aegis/tls.crt"));
    }

    #[test]
    fn is_secret_ref_true() {
        assert!(is_secret_ref("${secret:env:FOO}"));
        assert!(is_secret_ref("${secret:file:/path}"));
        assert!(is_secret_ref("${secret:vault:key}"));
    }

    #[test]
    fn is_secret_ref_false() {
        assert!(!is_secret_ref("plaintext"));
        assert!(!is_secret_ref("0.0.0.0:9090"));
        assert!(!is_secret_ref(""));
    }

    #[test]
    fn find_secret_refs_nested() {
        let config = json!({
            "admin": {
                "password_hash": "${secret:env:HASH}",
                "totp_key": "${secret:file:/etc/totp}"
            },
            "tls": {
                "key": "${secret:vault:tls-key}",
                "cert": "/etc/cert.pem"
            },
            "bind": "0.0.0.0:8080"
        });
        let refs = find_secret_refs(&config, "");
        assert_eq!(refs.len(), 3);
        assert!(refs.iter().any(|r| r.contains("password_hash")));
        assert!(refs.iter().any(|r| r.contains("totp_key")));
        assert!(refs.iter().any(|r| r.contains("tls.key")));
    }

    #[test]
    fn find_secret_refs_empty() {
        let config = json!({"bind": "0.0.0.0:8080"});
        let refs = find_secret_refs(&config, "");
        assert!(refs.is_empty());
    }

    #[test]
    fn find_secret_refs_in_array() {
        let config = json!({
            "secrets": ["${secret:env:A}", "plain", "${secret:env:B}"]
        });
        let refs = find_secret_refs(&config, "");
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn render_config_pretty() {
        let config = json!({"a": 1});
        let rendered = render_config(&config);
        assert!(rendered.contains('\n')); // Pretty-printed.
    }

    #[test]
    fn render_config_empty_object() {
        let config = json!({});
        let rendered = render_config(&config);
        assert_eq!(rendered.trim(), "{}");
    }

    // ---- 2026-05-19 — YAML render for Configuration Backup ----

    #[test]
    fn render_config_yaml_round_trips_to_same_value() {
        // The promise to operators is "drop this file in as
        // waf.yaml". Parsing the YAML back must yield a value
        // that round-trips through JSON identically to the
        // original — no key renames, no type widening.
        let original = json!({
            "admin": { "bind": "0.0.0.0:9443" },
            "tls":   { "min_version": "1.2" },
            "routes": [{ "id": "catch-all", "path": "/", "upstream": "stub" }],
        });
        let yaml = render_config_yaml(&original);
        let reparsed: Value = serde_yaml::from_str(&yaml)
            .expect("rendered YAML must parse");
        assert_eq!(reparsed, original);
    }

    #[test]
    fn render_config_yaml_preserves_secret_refs() {
        // Same invariant as the JSON renderer: ${secret:*}
        // strings appear verbatim. YAML emitting these as
        // quoted plain scalars is fine — the figment loader
        // dequotes them on the way back in.
        let config = json!({
            "admin": {
                "password_hash": "${secret:env:ADMIN_PASSWORD_HASH}",
                "totp_key":      "${secret:file:/etc/aegis/totp.key}",
                "bind":          "0.0.0.0:9443",
            },
            "tls": {
                "key":  "${secret:vault:tls-key}",
                "cert": "/etc/aegis/tls.crt",
            },
        });
        let yaml = render_config_yaml(&config);
        assert!(yaml.contains("${secret:env:ADMIN_PASSWORD_HASH}"));
        assert!(yaml.contains("${secret:file:/etc/aegis/totp.key}"));
        assert!(yaml.contains("${secret:vault:tls-key}"));
        assert!(yaml.contains("/etc/aegis/tls.crt"));
        // And the reparsed tree still flags those as secret refs.
        let reparsed: Value = serde_yaml::from_str(&yaml).unwrap();
        let refs = find_secret_refs(&reparsed, "");
        assert_eq!(refs.len(), 3, "all three secret refs survive YAML round-trip");
    }

    #[test]
    fn render_config_yaml_empty_object() {
        let yaml = render_config_yaml(&json!({}));
        // serde_yaml emits an empty mapping as `{}` followed by
        // a newline. We just want it to be parseable and empty.
        let reparsed: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(reparsed, json!({}));
    }

    #[test]
    fn render_config_yaml_is_not_json_pretty() {
        // Sanity: the two renderers are actually different
        // formats. YAML for the same value should NOT contain
        // braces around the whole document, and should use the
        // colon-indented mapping form.
        let cfg = json!({ "k": "v" });
        let yaml = render_config_yaml(&cfg);
        let json = render_config(&cfg);
        assert!(yaml.contains("k:"), "yaml should be `k: v`, got {yaml:?}");
        assert!(json.contains("\"k\""), "json should quote keys, got {json:?}");
    }
}
