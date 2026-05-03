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

> **AI detector (AI-T)** — design ready at
> [`../../../plans/ai-detector.md`](../../../plans/ai-detector.md);
> AI-T1 (Cargo feature + `AiConfig` schema) shipped 2026-05-03.
> The remaining slices (features extraction, model loader,
> AiDetector trait impl, dashboard surface) wait on the
> operator's `.onnx` artifact.  When wired, it emits classes
> like `ai_injection` / `ai_xss` / `ai_xxe` per the dataset
> report — those land in `fields.detectors[]` alongside the
> regex/heuristic detectors.

The detector mask (P2/P3 in [`Implement-Progress.md`](../../../Implement-Progress.md))
controls which of these are active per tier — see
[`../tiered-protection.md`](../tiered-protection.md) and the
[`/api/detectors`](../../control-plane/enterprise/api.md) admin
endpoint.

For corpus-based regression testing, see
[`../../../tests/security/corpus/`](../../../tests/security/corpus/).
