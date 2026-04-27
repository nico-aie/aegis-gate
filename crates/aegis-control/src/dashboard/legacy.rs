//! Legacy v1 dashboard shell (D-M1-T1.6).
//!
//! The single-file dashboard that the WAF shipped before the
//! enterprise SPA. Kept on for one release behind the
//! `admin.dashboard.legacy_shell` config flag so operators can fall
//! back if the new shell breaks for them. See
//! `plans/dashboard-enterprise/milestone-1-shell.md` task T1.6 for
//! the deprecation plan; D-M6 removes this module.
//!
//! The HTML is deliberately self-contained (no external CSS / JS)
//! so it works even if the embedded asset table is broken.

use super::assets::EmbeddedAsset;
use std::sync::OnceLock;

/// The v1 dashboard HTML. Identical bytes to the constant that
/// previously lived as `super::DASHBOARD_HTML`; renamed so its
/// "deprecated, kept on for fallback" status is explicit at the
/// callsite.
pub const DASHBOARD_HTML_V1: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis WAF Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0}
header{background:#1e293b;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
header h1{font-size:1.25rem;font-weight:600}
.badge{background:#3b82f6;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem}
main{padding:2rem;max-width:1200px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:#1e293b;border-radius:8px;padding:1.5rem;border:1px solid #334155}
.card h3{font-size:0.875rem;color:#94a3b8;margin-bottom:0.5rem}
.card .value{font-size:2rem;font-weight:700}
#events{background:#1e293b;border-radius:8px;padding:1rem;border:1px solid #334155;max-height:400px;overflow-y:auto;font-family:monospace;font-size:0.8rem}
.event-line{padding:4px 0;border-bottom:1px solid #1e293b}
.event-line.detection{color:#f87171}
.event-line.admin{color:#fbbf24}
.event-line.system{color:#60a5fa}
.event-line.access{color:#34d399}
</style>
</head>
<body>
<header>
<h1>Aegis WAF</h1>
<span class="badge">Dashboard</span>
</header>
<main>
<div class="grid">
<div class="card"><h3>Status</h3><div class="value" id="status">Connecting...</div></div>
<div class="card"><h3>Events</h3><div class="value" id="event-count">0</div></div>
<div class="card"><h3>Blocks</h3><div class="value" id="block-count">0</div></div>
</div>
<h2 style="margin-bottom:1rem">Live Events</h2>
<div id="events"></div>
</main>
<script>
let eventCount=0,blockCount=0;
const es=new EventSource("/dashboard/sse");
es.onopen=()=>{document.getElementById("status").textContent="Connected"};
es.onerror=()=>{document.getElementById("status").textContent="Disconnected"};
es.onmessage=(e)=>{
  const ev=JSON.parse(e.data);
  eventCount++;
  if(ev.action==="block")blockCount++;
  document.getElementById("event-count").textContent=eventCount;
  document.getElementById("block-count").textContent=blockCount;
  const el=document.createElement("div");
  el.className="event-line "+(ev.class||"");
  el.textContent=ev.ts+" ["+ev.class+"] "+ev.action+": "+ev.reason;
  const container=document.getElementById("events");
  container.prepend(el);
  while(container.children.length>200)container.lastChild.remove();
};
</script>
</body>
</html>"#;

/// Cached BLAKE3 ETag for the V1 shell. Computed once on first
/// access — same pattern as the SPA shell ETags in `super::assets`.
static LEGACY_ETAG: OnceLock<&'static str> = OnceLock::new();

fn legacy_etag() -> &'static str {
    LEGACY_ETAG.get_or_init(|| {
        let s = blake3::hash(DASHBOARD_HTML_V1.as_bytes()).to_hex().to_string();
        Box::leak(s.into_boxed_str())
    })
}

/// Return the v1 dashboard as an [`EmbeddedAsset`] so the response
/// builder can treat it identically to any other embedded shell
/// (same content_type, ETag shape, and security-header pipeline).
pub fn legacy_shell() -> EmbeddedAsset {
    EmbeddedAsset {
        bytes: DASHBOARD_HTML_V1.as_bytes(),
        content_type: "text/html; charset=utf-8",
        etag: legacy_etag(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_html_v1_is_a_full_document() {
        assert!(DASHBOARD_HTML_V1.contains("<!DOCTYPE html>"));
        assert!(DASHBOARD_HTML_V1.contains("Aegis WAF"));
        assert!(DASHBOARD_HTML_V1.contains("EventSource"));
        assert!(DASHBOARD_HTML_V1.contains("/dashboard/sse"));
    }

    #[test]
    fn legacy_shell_returns_v1_bytes_with_text_html() {
        let asset = legacy_shell();
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert_eq!(asset.bytes, DASHBOARD_HTML_V1.as_bytes());
    }

    #[test]
    fn legacy_shell_etag_is_blake3_of_bytes_lowercase_hex() {
        let asset = legacy_shell();
        let expected = blake3::hash(asset.bytes).to_hex().to_string();
        assert_eq!(asset.etag, expected);
        assert_eq!(asset.etag.len(), 64);
        assert!(asset.etag.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn legacy_shell_etag_is_deterministic() {
        let a = legacy_shell();
        let b = legacy_shell();
        assert_eq!(a.etag, b.etag);
    }
}
