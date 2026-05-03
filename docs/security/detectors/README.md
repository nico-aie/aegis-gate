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
| [header-injection.md](./header-injection.md) | `header_injection` | Headers |
| [recon.md](./recon.md) | `recon` | URL patterns + path entropy |
| [brute-force.md](./brute-force.md) | `brute_force` | Login endpoints |
| [body-abuse.md](./body-abuse.md) | `body_abuse`, `xxe`, `mass_assignment` | Body (JSON / XML / form) |
| [ai-detector.md](./ai-detector.md) | `ai` | URL, body, headers (binary attack/normal verdict over a 26-feature vector via ONNX) |

The detector mask (P2/P3 in [`Implement-Progress.md`](../../../Implement-Progress.md))
controls which of these are active per tier — see
[`../tiered-protection.md`](../tiered-protection.md) and the
[`/api/detectors`](../../control-plane/enterprise/api.md) admin
endpoint.

For corpus-based regression testing, see
[`../../../tests/security/corpus/`](../../../tests/security/corpus/).
