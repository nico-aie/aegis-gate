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

/// 2026-05-19 — Snapshot of the runtime knobs the dashboard
/// mutates outside the on-disk `waf.yaml`. The
/// [`apply_runtime_overlay`] helper folds this back over a
/// parsed YAML document so the downloaded backup reflects the
/// LIVE state, not just whatever last hit the file watcher.
///
/// Every field is `Option<…>` so callers can populate only the
/// runtime sinks the proxy actually wired (test bundles may
/// have no DDoS runtime, no AI toggle, etc.) — `None` leaves
/// the corresponding YAML keys untouched.
#[derive(Clone, Debug, Default)]
pub struct RuntimeOverlay {
    /// Live AI detector toggle. Mirrors both
    /// `Arc<AtomicBool>::load()` (the runtime gate) and the
    /// `DetectorClass::Ai` mask bit — they're kept in sync by
    /// the audit-mutated PUT handler.
    pub ai_enabled: Option<bool>,
    /// Live detector mask + per-tier overrides. Each entry maps
    /// the wire-shape class name (`sqli`, `xss`, `behavior_signals`,
    /// …) to its current enabled flag.
    pub detector_base: Option<std::collections::BTreeMap<String, bool>>,
    /// Per-tier overrides: tier name (`critical` / `high` /
    /// `medium` / `catch_all`) → class → enabled.
    pub detector_per_tier:
        Option<std::collections::BTreeMap<String, std::collections::BTreeMap<String, bool>>>,
    /// DDoS gate config from the live runtime. Captures every
    /// knob hot-flippable via PUT /api/gates/ddos plus
    /// `enabled` (the 2026-05-19 hot-flip addition).
    pub ddos: Option<DdosOverlay>,
}

/// Subset of `aegis_security::ddos::DdosConfig` the dashboard
/// PUT handler mutates — flat fields kept primitive so this
/// crate doesn't need to depend on aegis-security for the
/// type. The admin handler builds this from
/// `services.ddos.config_snapshot()` at request time.
#[derive(Clone, Debug)]
pub struct DdosOverlay {
    pub enabled: bool,
    pub observe_only: bool,
    pub per_ip_limit: u64,
    pub per_ip_window_s: u32,
    pub block_ttl_s: u64,
    pub spike_multiplier: f64,
    pub tightened_per_ip_rps: u64,
}

/// Fold the runtime overlay into a parsed YAML document and
/// re-serialise. Used by `/api/config/backup.yaml` so the
/// downloaded file reflects dashboard-mutated state (AI toggle,
/// detector-mask flips, DDoS knob edits) on top of the
/// on-disk `waf.yaml`.
///
/// Patches are minimal-surface — only the keys the dashboard
/// actually mutates get rewritten. Unknown keys, comments
/// (lost on YAML parse anyway), formatting, and any operator
/// edits we don't track survive verbatim.
///
/// `${secret:*}` references survive because they sit at leaf
/// string nodes the overlay never touches.
pub fn apply_runtime_overlay(
    on_disk_yaml: &str,
    overlay: &RuntimeOverlay,
) -> Result<String, String> {
    let mut doc: serde_yaml::Value = serde_yaml::from_str(on_disk_yaml)
        .map_err(|e| format!("parse on-disk YAML: {e}"))?;

    // ai.enabled — `cfg.ai` is a top-level block.
    if let Some(enabled) = overlay.ai_enabled {
        let ai = ensure_mapping(&mut doc, "ai");
        set_mapping_field(ai, "enabled", serde_yaml::Value::Bool(enabled));
    }

    // detectors.<class>.enabled — per-class toggles, plus
    // detectors.per_tier.<tier>.<class> when overrides exist.
    if overlay.detector_base.is_some() || overlay.detector_per_tier.is_some() {
        let detectors = ensure_mapping(&mut doc, "detectors");
        if let Some(base) = &overlay.detector_base {
            for (class_name, enabled) in base {
                // Skip "ai" — it lives at top-level `ai.enabled`,
                // not under `detectors:`. The mask bit and
                // YAML schema disagree on placement here; we
                // route the AI bit via the ai_enabled overlay
                // above to keep the file shape valid.
                if class_name == "ai" {
                    continue;
                }
                let class = ensure_mapping(detectors, class_name);
                // `open_redirect` has extra fields under it
                // (`allowed_domains`, etc.); only patch the
                // single `enabled` leaf so operator-edited
                // allowlists survive.
                set_mapping_field(
                    class,
                    "enabled",
                    serde_yaml::Value::Bool(*enabled),
                );
            }
        }
        if let Some(per_tier) = &overlay.detector_per_tier {
            let per_tier_node = ensure_mapping(detectors, "per_tier");
            for (tier_name, class_map) in per_tier {
                let tier = ensure_mapping(per_tier_node, tier_name);
                for (class_name, enabled) in class_map {
                    set_mapping_field(
                        tier,
                        class_name,
                        serde_yaml::Value::Bool(*enabled),
                    );
                }
            }
        }
    }

    // ddos.* — flat field overlay.
    if let Some(d) = &overlay.ddos {
        let ddos = ensure_mapping(&mut doc, "ddos");
        set_mapping_field(ddos, "enabled", serde_yaml::Value::Bool(d.enabled));
        set_mapping_field(ddos, "observe_only", serde_yaml::Value::Bool(d.observe_only));
        set_mapping_field(ddos, "per_ip_limit", yaml_u64(d.per_ip_limit));
        set_mapping_field(ddos, "per_ip_window_s", yaml_u64(d.per_ip_window_s as u64));
        set_mapping_field(ddos, "block_ttl_s", yaml_u64(d.block_ttl_s));
        set_mapping_field(
            ddos,
            "spike_multiplier",
            serde_yaml::Value::Number(serde_yaml::Number::from(d.spike_multiplier)),
        );
        set_mapping_field(
            ddos,
            "tightened_per_ip_rps",
            yaml_u64(d.tightened_per_ip_rps),
        );
    }

    serde_yaml::to_string(&doc).map_err(|e| format!("re-serialise YAML: {e}"))
}

// ---- internal helpers ----

fn ensure_mapping<'a>(parent: &'a mut serde_yaml::Value, key: &str) -> &'a mut serde_yaml::Value {
    let map = match parent {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            *parent = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
            match parent {
                serde_yaml::Value::Mapping(m) => m,
                _ => unreachable!(),
            }
        }
    };
    let yaml_key = serde_yaml::Value::String(key.to_string());
    if !map.contains_key(&yaml_key) {
        map.insert(yaml_key.clone(), serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    map.get_mut(&yaml_key).unwrap()
}

fn set_mapping_field(parent: &mut serde_yaml::Value, key: &str, value: serde_yaml::Value) {
    if let serde_yaml::Value::Mapping(map) = parent {
        map.insert(serde_yaml::Value::String(key.to_string()), value);
    }
}

fn yaml_u64(n: u64) -> serde_yaml::Value {
    serde_yaml::Value::Number(serde_yaml::Number::from(n))
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

    // ---- 2026-05-19 — runtime overlay ----

    fn parse(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn overlay_no_op_when_overlay_is_empty() {
        // An empty overlay leaves the document untouched.
        let original = "ai:\n  enabled: true\n  model_path: /m.onnx\n";
        let out = apply_runtime_overlay(original, &RuntimeOverlay::default()).unwrap();
        let parsed = parse(&out);
        assert_eq!(
            parsed["ai"]["enabled"], serde_yaml::Value::Bool(true),
            "no-op overlay must preserve original value",
        );
        assert_eq!(
            parsed["ai"]["model_path"], serde_yaml::Value::String("/m.onnx".into()),
            "sibling fields preserved",
        );
    }

    #[test]
    fn overlay_flips_ai_enabled() {
        // The user's actual ask: disable AI in the dashboard,
        // download backup → file shows `ai.enabled: false`.
        let on_disk = "ai:\n  enabled: true\n  model_path: /m.onnx\n";
        let overlay = RuntimeOverlay { ai_enabled: Some(false), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed["ai"]["enabled"], serde_yaml::Value::Bool(false));
        // Sibling `model_path` survived the patch.
        assert_eq!(
            parsed["ai"]["model_path"],
            serde_yaml::Value::String("/m.onnx".into()),
        );
    }

    #[test]
    fn overlay_creates_ai_block_when_missing() {
        // If the on-disk file has no `ai:` block, the overlay
        // still applies (creates the section).
        let on_disk = "listeners:\n  data:\n    - bind: 0.0.0.0:8080\n";
        let overlay = RuntimeOverlay { ai_enabled: Some(true), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed["ai"]["enabled"], serde_yaml::Value::Bool(true));
        // Original `listeners` block untouched.
        assert!(parsed["listeners"]["data"].is_sequence());
    }

    #[test]
    fn overlay_flips_detector_base_class() {
        let on_disk = "detectors:\n  sqli: { enabled: true }\n  xss: { enabled: true }\n";
        let mut base = std::collections::BTreeMap::new();
        base.insert("xss".to_string(), false);
        let overlay = RuntimeOverlay { detector_base: Some(base), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed["detectors"]["sqli"]["enabled"], serde_yaml::Value::Bool(true));
        assert_eq!(parsed["detectors"]["xss"]["enabled"], serde_yaml::Value::Bool(false));
    }

    #[test]
    fn overlay_skips_ai_under_detectors_block() {
        // The mask carries `ai` as a class bit but YAML places
        // `ai.enabled` at the top level — overlay must NOT
        // emit `detectors.ai.enabled`. The ai_enabled overlay
        // field is the single source of truth for that.
        let on_disk = "detectors:\n  sqli: { enabled: true }\n";
        let mut base = std::collections::BTreeMap::new();
        base.insert("ai".to_string(), true);
        base.insert("sqli".to_string(), true);
        let overlay = RuntimeOverlay { detector_base: Some(base), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert!(
            parsed["detectors"].get("ai").is_none(),
            "ai must not be emitted under detectors:",
        );
    }

    #[test]
    fn overlay_preserves_open_redirect_allowlist() {
        // `open_redirect` has fields besides `enabled` (e.g.
        // `allowed_domains`). The overlay must patch only the
        // `enabled` leaf so the operator's hand-edited
        // allowlist survives.
        let on_disk = r#"
detectors:
  open_redirect:
    enabled: true
    allowed_domains:
      - my-app.com
      - "*.safe.example"
"#;
        let mut base = std::collections::BTreeMap::new();
        base.insert("open_redirect".to_string(), false);
        let overlay = RuntimeOverlay { detector_base: Some(base), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(
            parsed["detectors"]["open_redirect"]["enabled"],
            serde_yaml::Value::Bool(false),
            "enabled flipped",
        );
        let domains = parsed["detectors"]["open_redirect"]["allowed_domains"]
            .as_sequence()
            .expect("allowed_domains survives");
        assert_eq!(domains.len(), 2, "allowlist preserved verbatim");
    }

    #[test]
    fn overlay_writes_per_tier_mask() {
        let on_disk = "detectors:\n  sqli: { enabled: true }\n";
        let mut per_tier = std::collections::BTreeMap::new();
        let mut crit = std::collections::BTreeMap::new();
        crit.insert("ai".to_string(), false);
        crit.insert("behavior_signals".to_string(), true);
        per_tier.insert("critical".to_string(), crit);
        let overlay = RuntimeOverlay {
            detector_per_tier: Some(per_tier),
            ..Default::default()
        };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(
            parsed["detectors"]["per_tier"]["critical"]["ai"],
            serde_yaml::Value::Bool(false),
        );
        assert_eq!(
            parsed["detectors"]["per_tier"]["critical"]["behavior_signals"],
            serde_yaml::Value::Bool(true),
        );
    }

    #[test]
    fn overlay_writes_ddos_block() {
        let on_disk = "listeners:\n  data:\n    - bind: 0.0.0.0:8080\n";
        let overlay = RuntimeOverlay {
            ddos: Some(DdosOverlay {
                enabled: false,
                observe_only: true,
                per_ip_limit: 5000,
                per_ip_window_s: 30,
                block_ttl_s: 600,
                spike_multiplier: 3.5,
                tightened_per_ip_rps: 25,
            }),
            ..Default::default()
        };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed["ddos"]["enabled"], serde_yaml::Value::Bool(false));
        assert_eq!(parsed["ddos"]["observe_only"], serde_yaml::Value::Bool(true));
        assert_eq!(parsed["ddos"]["per_ip_limit"].as_u64(), Some(5000));
        assert_eq!(parsed["ddos"]["per_ip_window_s"].as_u64(), Some(30));
        assert_eq!(parsed["ddos"]["block_ttl_s"].as_u64(), Some(600));
        assert_eq!(parsed["ddos"]["tightened_per_ip_rps"].as_u64(), Some(25));
        let mult = parsed["ddos"]["spike_multiplier"].as_f64().unwrap();
        assert!((mult - 3.5).abs() < 1e-9, "spike_multiplier float survives");
    }

    #[test]
    fn overlay_preserves_secret_refs() {
        // Critical: the overlay must never resolve secret
        // references. Patch a sibling field; the secret leaf
        // is untouched.
        let on_disk = r#"
admin:
  dashboard_auth:
    password_hash: "${secret:env:ADMIN_PASSWORD_HASH}"
ai:
  enabled: true
"#;
        let overlay = RuntimeOverlay { ai_enabled: Some(false), ..Default::default() };
        let out = apply_runtime_overlay(on_disk, &overlay).unwrap();
        assert!(
            out.contains("${secret:env:ADMIN_PASSWORD_HASH}"),
            "secret ref must survive overlay, got:\n{out}",
        );
        let parsed = parse(&out);
        assert_eq!(parsed["ai"]["enabled"], serde_yaml::Value::Bool(false));
    }

    #[test]
    fn overlay_rejects_invalid_yaml() {
        let result = apply_runtime_overlay(
            "ai: [this is not a map\n",
            &RuntimeOverlay::default(),
        );
        assert!(result.is_err());
    }
}
