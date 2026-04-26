pub mod sse;
pub mod overview;

/// Embedded dashboard HTML shell.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
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

/// Check if a session is authenticated (stub for now).
pub fn is_authenticated(_session_cookie: Option<&str>) -> bool {
    // In W4 this will check HMAC session cookies.
    // For W1 we allow access.
    true
}

/// Redirect URL for unauthenticated requests.
pub fn login_redirect(next: &str) -> String {
    format!("/admin/login?next={}", urlencoded(next))
}

fn urlencoded(s: &str) -> String {
    s.replace('&', "%26").replace('=', "%3D").replace(' ', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_html_is_valid() {
        assert!(DASHBOARD_HTML.contains("<!DOCTYPE html>"));
        assert!(DASHBOARD_HTML.contains("Aegis WAF"));
        assert!(DASHBOARD_HTML.contains("EventSource"));
        assert!(DASHBOARD_HTML.contains("/dashboard/sse"));
    }

    #[test]
    fn login_redirect_includes_next() {
        let url = login_redirect("/dashboard/");
        assert!(url.starts_with("/admin/login?next="));
        assert!(url.contains("dashboard"));
    }

    #[test]
    fn login_redirect_encodes_special_chars() {
        let url = login_redirect("/api?a=1&b=2");
        assert!(url.contains("%26"));
        assert!(url.contains("%3D"));
    }

    #[test]
    fn is_authenticated_stub_returns_true() {
        assert!(is_authenticated(None));
        assert!(is_authenticated(Some("session123")));
    }
}
