//! `/api/loadmode` — read live load mode, apply operator overrides
//! (P7 of the security-toggle plan).
//!
//! GET returns the snapshot the dashboard pill consumes. PUT
//! accepts `{ "override": "normal"|"elevated"|"critical"|null }`
//! and routes through `AuditedMutate` so every pin / unpin lands
//! an admin chain entry.


use aegis_core::{LoadGauge, LoadMode};
use serde::Deserialize;

/// Render the GET payload from a live gauge.
pub fn render_get(gauge: &LoadGauge) -> String {
    serde_json::to_string(&gauge.snapshot()).unwrap_or_else(|_| String::from("{}"))
}

/// Body shape for `PUT /api/loadmode`. Empty body is a no-op
/// (also serves as a CSRF / health probe).
///
/// Three cases:
/// - field absent → leave the override untouched
/// - `"override": "unset"` → clear the override
/// - `"override": "normal"|"elevated"|"critical"` → pin to that mode
///
/// `null` was avoided because `serde_json` collapses
/// `Option<Option<String>>` to `Option<String>` in `#[serde(default)]`
/// mode, which made the "explicit null = clear" intent
/// indistinguishable from "field missing".
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LoadModePutBody {
    #[serde(default, rename = "override")]
    pub override_value: Option<String>,
}

/// Sentinel that means "clear the operator override".
pub const UNSET_SENTINEL: &str = "unset";

/// Apply a parsed PUT body to a live gauge. Pulled out so the
/// proxy handler can call this synchronously inside the
/// `AuditedMutate` closure.
pub fn apply_put_body(
    gauge: &LoadGauge,
    body: LoadModePutBody,
) -> Result<(), String> {
    let Some(s) = body.override_value else {
        return Ok(()); // no-op
    };
    if s == UNSET_SENTINEL {
        gauge.set_override(None);
        return Ok(());
    }
    match LoadMode::parse_str(&s) {
        Some(m) => {
            gauge.set_override(Some(m));
            Ok(())
        }
        None => Err(format!("unknown load mode: {s:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::LoadModeConfig;

    fn gauge() -> LoadGauge {
        LoadGauge::new(LoadModeConfig::default())
    }

    #[test]
    fn render_get_returns_documented_shape() {
        let body = render_get(&gauge());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for k in [
            "mode",
            "effective_mode",
            "rps_last_sample",
            "override_active",
            "elevated_rps",
            "critical_rps",
        ] {
            assert!(v.get(k).is_some(), "missing field {k}");
        }
    }

    #[test]
    fn put_body_accepts_each_mode_string() {
        for s in ["normal", "elevated", "critical"] {
            let g = gauge();
            let body: LoadModePutBody =
                serde_json::from_str(&format!(r#"{{"override":"{s}"}}"#)).unwrap();
            apply_put_body(&g, body).unwrap();
            assert_eq!(g.override_value().unwrap().as_str(), s);
        }
    }

    #[test]
    fn put_body_rejects_unknown_mode() {
        let g = gauge();
        let body: LoadModePutBody =
            serde_json::from_str(r#"{"override":"silent"}"#).unwrap();
        let err = apply_put_body(&g, body).unwrap_err();
        assert!(err.contains("unknown load mode"));
        assert!(g.override_value().is_none());
    }

    #[test]
    fn put_body_with_unset_sentinel_clears_override() {
        let g = gauge();
        g.set_override(Some(LoadMode::Critical));
        let body: LoadModePutBody =
            serde_json::from_str(r#"{"override":"unset"}"#).unwrap();
        apply_put_body(&g, body).unwrap();
        assert!(g.override_value().is_none());
    }

    #[test]
    fn empty_body_is_a_noop() {
        let g = gauge();
        g.set_override(Some(LoadMode::Critical));
        let body: LoadModePutBody = serde_json::from_str("{}").unwrap();
        apply_put_body(&g, body).unwrap();
        // Override preserved — empty body must not clear it.
        assert_eq!(g.override_value(), Some(LoadMode::Critical));
    }
}
