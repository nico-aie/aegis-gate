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
- **Score:** 100 (raised from 90 on 2026-05-20 — see below)
- **Surface:** URL path (no body / headers / query string —
  honeypot is path-only by design)
- **Config:** `risk.canary_paths: Vec<String>` (YAML seed) — also
  editable at runtime from the dashboard **Settings → Canary
  Honeypot Paths** card, backed by the audit-mutated
  `PUT /api/risk/canary-paths` (hot-applied, no restart)
- **Toggle:** `detectors.canary.enabled` (default OFF) — flips the
  `Canary` detector-mask bit; also toggleable enforce↔log_only via
  the interop `set_profile` (`rules_engine.canary` policy)
- **Added:** 2026-05-18 — Phase F of the
  [2026-05-17 security audit](../../../tests/s-tester/reports/2026-05-17-security-audit/)
  (F-CRITICAL-012). Made runtime-editable + first-class on
  2026-05-20.

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

## Why score 100

Canary paths are operator-curated honeypots: by definition no
legitimate client ever requests them, so the false-positive rate is
~0 — uniquely among the detectors. That earns it the ceiling score.
Practical consequences:

- A single hit blocks at **every** tier, including any custom
  per-request `risk_threshold` an operator sets up to the 100 cap.
  At the old score of 90, a threshold of 91–100 would have silently
  stopped canary from blocking.
- 100 reads as "certain" in the dashboard risk/confidence UI.

100 is on the documented score ladder
(`crates/aegis-security/src/detectors/scores.rs`); it sits one rung
above the definitive-RCE classes (Log4Shell, XXE) at 90.

If an operator wants softer behaviour (log instead of block), set the
`rules_engine.canary` policy to `log_only` via the interop
`set_profile` — the detector still fires + audits but the request is
forwarded.

## DetectorClass + hot-swappable path set

Canary is a first-class `DetectorClass` (bit `1 << 14`) paired with
`detectors.canary.enabled`, so it can be toggled on/off via
`PUT /api/detectors` and surfaced/flipped enforce↔log_only via the
interop `set_profile` (`rules_engine.canary`) — same as the OWASP
detectors.

The honeypot path *set* is data-driven and lives in a shared,
hot-swappable handle (`CanaryPaths`, an `Arc<ArcSwap<…>>`). The
data-plane detector and the audit-mutated `PUT /api/risk/canary-paths`
handler hold clones of the same handle, so a path edit is observed on
the next request with no chain rebuild and no restart.

## Boot-time wiring

`crates/aegis-proxy/src/run.rs` builds one `CanaryPaths` handle from
`cfg.risk.canary_paths`, passes it to
`default_detectors_with_canary(&cfg.detectors, &canary_paths)`
(which **always** registers the detector from the handle), and clones
the same handle into `DashboardServices.canary_paths` (via
`accept.rs`) for the admin mutation. Execution is gated by the
`Canary` mask bit, so a disabled or empty canary costs one
`ArcSwap::load` that the dispatcher skips when the bit is off.

To disable canary entirely, turn off `detectors.canary.enabled`
(dashboard Detectors page or YAML). Emptying the path list also makes
it inert (the detector runs but matches nothing).

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

The YAML block seeds the path set at boot. After boot, prefer the
dashboard **Settings → Canary Honeypot Paths** card (or
`PUT /api/risk/canary-paths`) — edits hot-apply with no restart and
are recorded in the audit chain. Any request to a configured path
emits the `canary` signal at score 100 and lands in the audit log
with field `path:/wp-admin` (or whichever entry matched).

## Operator playbook

1. Make sure the canary detector is enabled (dashboard **Detectors**
   page, or `detectors.canary.enabled: true`). It defaults OFF.
2. Inspect your access log for paths only attackers hit. Common
   starters: `/wp-admin`, `/wp-login.php`, `/.env`, `/.git/config`,
   `/phpmyadmin/*`, `/manager/html` (Tomcat), `/api/v1/.well-known/openid-configuration`
   when you don't run OIDC.
3. Add them on the **Settings → Canary Honeypot Paths** card (live,
   no restart) or seed them in `risk.canary_paths`.
4. Watch the dashboard's Top Attackers list — IPs that hit canary
   paths jump to the top within seconds.

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
- Score is 100 (max confidence)
- `set()` hot-swaps the path set (replace, not merge)
- A cloned `CanaryPaths` handle observes another clone's `set()`
  (shared-state guarantee for the admin-mutation path)
- `raw()` reads back the normalized (trimmed, blanks-dropped) list

No corpus dependency — the matcher is exact-string and has no
encoding-bypass surface (the path is normalised by the HTTP parser
before reaching us).
