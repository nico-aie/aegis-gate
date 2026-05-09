# Detectors

Per-attack-class detectors that feed the rule engine. Each doc
covers detection logic, the body / URL / header surface it inspects,
the bypass patterns it explicitly closes, and its corpus regression
tests.

Every detector emits a **bare class name** in
`AuditEvent.fields.detectors[]` (`"sqli"`, `"path_traversal"`,
`"xxe"`, …) — the same string the dashboard's "Detector breakdown"
chart and the Top-Attackers `categories` list display.  No
prefixes, no truncation.  When you add a new tag in detector
code, surface it under the canonical name; the by-detector
aggregator (`crates/aegis-control/src/api/attacks.rs`) uses it
verbatim.

| Doc | Tags emitted (`fields.detectors[]`) | Surface |
|---|---|---|
| [sqli.md](./sqli.md) | `sqli` | URL, body, headers |
| [xss.md](./xss.md) | `xss` | URL, body, headers |
| [path-traversal.md](./path-traversal.md) | `path_traversal` | URL, body |
| [ssrf.md](./ssrf.md) | `ssrf` | URL, body, fetch-style headers |
| [header-injection.md](./header-injection.md) | `header_injection` | Headers + query CRLF |
| [recon.md](./recon.md) | `recon_path`, `recon_tool` | URL patterns + path entropy — **framework recon** (Spring actuator dangers / Laravel Ignition / Swagger / GraphQL / K8s API / Kibana / Jenkins / CGI / Prometheus federation) added 2026-05-08 (GAP-001) |
| [brute-force.md](./brute-force.md) | `brute_force` | Login endpoints |
| [body-abuse.md](./body-abuse.md) | `body_abuse`, `xxe`, `mass_assignment`, `proto_pollution` | Body (JSON / XML / form) — **prototype pollution** (`__proto__` / `constructor.prototype`) added 2026-05-08 (GAP-010, score 45) |
| [command-injection.md](./command-injection.md) | `command_injection` | URL, body, allowlisted headers — `$()`, backticks, `\|cmd`, `;cmd`, `/bin/sh`, reverse-shell shapes, **Log4Shell `${jndi:...}`** (score 60) |
| [template-injection.md](./template-injection.md) | `template_injection` | URL, body — Jinja2 `{{config}}` / Twig / Mako / Freemarker `<#assign>` / Velocity `#set()` / SpEL `${T(...)}` / Handlebars `{{#with}}` |
| [nosql-injection.md](./nosql-injection.md) | `nosql_injection` | URL, body — MongoDB operator injection (`?param[$ne]=foo`, `{"$where":"..."}`) |
| [open-redirect.md](./open-redirect.md) | `open_redirect` | Query string — suspicious external URLs (`http(s)://`, `//`, `javascript:`, `data:`) in redirect-style params (`?next=`, `?redirect_uri=`, …); allowlist via `cfg.detectors.open_redirect.allowed_domains`. Score 30 (phishing tier). Added 2026-05-09 (GAP-009). |
| [ai-detector.md](./ai-detector.md) | `ai` | URL, body, headers (binary attack/normal verdict over a 26-feature vector via ONNX) |

The detector mask (P2/P3 in [`Implement-Progress.md`](../../../Implement-Progress.md))
controls which of these are active per tier — see
[`../tiered-protection.md`](../tiered-protection.md) and the
[`/api/detectors`](../../control-plane/enterprise/api.md) admin
endpoint.

In the dashboard, the **Detectors** page shows the merged view —
AI observability panel (predictions / attack rate / fallbacks) on
top, the per-class mask grid (base + per-tier overrides) below.
Audit-mutated; flips take effect within one hot-reload tick. The
AI detector itself is gated by `cfg.ai.enabled` at boot time
today (a runtime `PUT /api/ai/enabled` knob is queued).

> **The dashboard does not expose a per-detector score editor.** The
> score table is a calibrated ladder (25 / 30 / 35–40 / 45 / 50 / 60)
> that interacts with `risk.thresholds.challenge_at` and `block_at` —
> changing one without the other breaks both. Operators tune posture
> by adjusting thresholds, moving classes to `log_only`, applying
> per-tier overrides, or scoping `RaiseRisk(delta)` rules to a
> route. Full guide: [`../../operator/risk-tuning.md`](../../operator/risk-tuning.md).

For corpus-based regression testing, see
[`../../../tests/security/corpus/`](../../../tests/security/corpus/).
