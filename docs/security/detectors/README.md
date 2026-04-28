# Detectors

Per-attack-class detectors that feed the rule engine. Each doc
covers detection logic, the body / URL / header surface it inspects,
the bypass patterns it explicitly closes, and its corpus regression
tests.

| Doc | Attack class | Surface |
|---|---|---|
| [sqli.md](./sqli.md) | SQL injection | URL, body, headers |
| [xss.md](./xss.md) | Cross-site scripting | URL, body, headers |
| [path-traversal.md](./path-traversal.md) | Path traversal / LFI | URL, body |
| [ssrf.md](./ssrf.md) | Server-side request forgery | URL, body, fetch-style headers |
| [header-injection.md](./header-injection.md) | CRLF / response splitting | Headers |
| [recon.md](./recon.md) | Scanner / probe detection | URL patterns + path entropy |
| [brute-force.md](./brute-force.md) | Auth brute-force | Login endpoints |
| [body-abuse.md](./body-abuse.md) | Body size / nesting / decompression-bomb | Body |

The detector mask (P2/P3 in [`Implement-Progress.md`](../../../Implement-Progress.md))
controls which of these are active per tier — see
[`../tiered-protection.md`](../tiered-protection.md) and the
[`/api/detectors`](../../control-plane/enterprise/api.md) admin
endpoint.

For corpus-based regression testing, see
[`../../../tests/security/corpus/`](../../../tests/security/corpus/).
