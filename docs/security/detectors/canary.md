# Canary detector

Honeypot-path detector. Operators configure a list of URL paths
that no legitimate caller should ever hit (`/wp-admin`, `/.env`,
`/phpmyadmin/*`, …); any request whose path matches gets a
high-severity signal that drives the IP across the block threshold
in a single hit.

- **Source:** `crates/aegis-security/src/detectors/canary.rs`
- **Tag:** `canary`
- **Field:** `path:<matched-entry>` (e.g. `path:/wp-admin`,
  `path:/phpmyadmin/`)
- **Score:** 90
- **Surface:** URL path (no body / headers / query string —
  honeypot is path-only by design)
- **Config:** `risk.canary_paths: Vec<String>` in YAML
- **Added:** 2026-05-18 — Phase F of the
  [2026-05-17 security audit](../../../tests/s-tester/reports/2026-05-17-security-audit/)
  (F-CRITICAL-012)

## Match semantics

Two entry shapes, parsed once at startup:

| Operator writes | Interpreted as | Matches |
|---|---|---|
| `/wp-admin` | `Exact("/wp-admin")` | only `/wp-admin` |
| `/admin/*` | `Prefix("/admin/")` | `/admin/x`, `/admin/x/y`, … (any depth) |
| `/admin*` | `Prefix("/admin")` | `/admin`, `/admin/x`, `/admin-page` |
| `` (empty) | dropped | — |
| `   ` (whitespace) | dropped | — |

No regex — operators configure paths, not patterns. The matcher is
a single pass over the configured list; the audit's recommended
shape is 5-10 honeypot entries, so per-request cost is trivial.

## Why score 90

The v2.3 risk thresholds default to `challenge_at: 30`, `block_at: 70`
(F-CRITICAL-007). Score 90 in one signal carries an unauthenticated
request over the block threshold on its first request, with margin to
spare. The intent is "single hit → permanent block" semantics: nobody
legitimate hits `/wp-admin`, so the WAF doesn't need a multi-hit
window to be confident.

If an operator wants softer behaviour (e.g. log + challenge instead of
block), they can drop the path from `risk.canary_paths` and configure
an operator rule with `then: log_only` or `then: challenge: { level: js }`
instead.

## Why this lives outside `DetectorClass`

`DetectorClass` is a closed-set bitfield with stable bit positions,
paired 1-to-1 with `DetectorsConfig` fields. Canary is data-driven
(operator-supplied paths from `RiskConfig`), not pattern-class, so
it ships as a regular [`Detector`] with `id = "canary"` and runs
under the mask's "unknown id runs unconditionally" path
(`crates/aegis-security/src/detectors/mask.rs::is_enabled_id`).

Operators who want to disable canary entirely just empty
`risk.canary_paths` — no detector instance is constructed, zero
per-request cost.

## Boot-time wiring

`default_detectors_with_canary(&cfg.detectors, &cfg.risk.canary_paths)`
in `crates/aegis-security/src/detectors/mod.rs` returns the same
list as `default_detectors_with` plus the canary detector when
`canary_paths` is non-empty. The proxy boot path in
`crates/aegis-proxy/src/run.rs` calls the canary-aware constructor.

## Example config

```yaml
risk:
  canary_paths:
    - "/wp-admin"
    - "/wp-login.php"
    - "/.env"
    - "/.git/config"
    - "/phpmyadmin/*"
    - "/admin.php"
```

After save → reload, any request to any of those paths emits the
`canary` signal at score 90 and lands in the audit log with field
`path:/wp-admin` (or whichever entry matched).

## Operator playbook

1. Inspect your access log for paths only attackers hit. Common
   starters: `/wp-admin`, `/wp-login.php`, `/.env`, `/.git/config`,
   `/phpmyadmin/*`, `/manager/html` (Tomcat), `/api/v1/.well-known/openid-configuration`
   when you don't run OIDC.
2. Add them to `risk.canary_paths`.
3. Watch the dashboard's Top Attackers list — IPs that hit canary
   paths jump to the top within seconds of saving.

## Tests

`crates/aegis-security/src/detectors/canary.rs` unit tests cover:

- Exact-path match (single hit)
- Exact-path does NOT match prefix (`/wp-admin` ≠ `/wp-admin/foo`)
- Suffix glob match at multiple depths
- Suffix glob does NOT match bare prefix (`/phpmyadmin/*` ≠ `/phpmyadmin`)
- Legitimate paths never fire
- Empty configured list — detector still runs but never fires
- Empty / whitespace operator entries are dropped at compile time
- Stable detector id `"canary"`

No corpus dependency — the matcher is exact-string and has no
encoding-bypass surface (the path is normalised by the HTTP parser
before reaching us).
