# Reconnaissance Detection

> **Status:** Implemented — `aegis-security/src/detectors/recon.rs`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Detect scanners, crawlers, and other reconnaissance activity before they find something exploitable. Reconnaissance is the quietest phase of an attack — identifying it early lets the WAF block the attacker before they pivot to exploitation.

## Signals

### Scanner User-Agents

Match known scanner / tool signatures in the `User-Agent` header. A non-exhaustive list:

- `sqlmap`, `sqlninja`
- `nikto`, `nessus`
- `nmap`, `masscan`, `zgrab`
- `acunetix`, `burpsuite`, `burp`
- `wpscan`, `joomlascan`
- `dirbuster`, `gobuster`, `ffuf`, `wfuzz`, `feroxbuster`
- `nuclei`
- `zap`, `owasp`
- `havij`

Attackers can trivially change UAs, so this is a **low-confidence** signal on its own but stacks with others.

### Path probing signature

Requests to known reconnaissance paths score risk immediately:

- **Config exposure:** `/.env`, `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/.DS_Store`
- **Admin panels:** `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`, `/pma`
- **CMS fingerprints:** `/wp-login.php`, `/wp-content/`, `/wp-includes/`, `/user/login`, `/drupal/`
- **Server info:** `/server-status`, `/server-info`, `/phpinfo.php`, `/info.php`
- **Backups:** `/backup.sql`, `/dump.sql`, `/*.bak`, `/*.old`, `/*.swp`, `/*.tar.gz`
- **Development:** `/.htaccess`, `/web.config`, `/appsettings.json`, `/application.yml`
- **Credentials:** `/.ssh/id_rsa`, `/credentials.json`, `/.aws/credentials`
- **Docker REST API:** `/v1.24/containers/json`, `/v1.41/info`, `/v1.43/images/json`, `/v1.40/networks`, `/v1.41/swarm`, `/_ping` (the daemon's HTTP API surface, reachable when the socket is mistakenly exposed via TCP / a sidecar proxy — added 2026-05-08 SEC-L001)

#### Framework reconnaissance (added 2026-05-08, GAP-001)

QA Run-5 found the framework-recon corpus passing 1/9 — the WAF caught the obvious `/.env` shape but missed every framework-specific probe. Added the following pattern groups, all kept **conservative** so operator-hosted endpoints (`/health`, `/metrics`, `/actuator/health`, `/actuator/info`) do **not** false-positive:

| Pattern shape | Why dangerous | Examples |
|---|---|---|
| `/actuator/(heapdump\|env\|threaddump\|jolokia\|env\|configprops\|...)` | Spring Boot — heapdump leaks memory; env leaks secrets; jolokia is RCE if writable | `/actuator/heapdump`, `/actuator/jolokia` |
| `/_ignition/(execute-solution\|health-check\|update-config)` | Laravel Ignition — CVE-2021-3129, direct RCE | `/_ignition/execute-solution` |
| `/(swagger-ui\|swagger\.json\|v\d+/api-docs\|openapi\.(json\|yaml))` | Surface enumeration; not always sensitive but standard recon target | `/swagger-ui.html`, `/v3/api-docs` |
| `/graphql(\|/\|?)`, `/graphiql`, `/playground` | GraphQL introspection often disabled in prod; flag for visibility | `/graphql?query=__schema` |
| `/api/v1/(namespaces\|pods)`, `/apis/apps/v1/deployments` | Kubernetes API — full cluster takeover if reachable | `/api/v1/pods` |
| `/(\.kibana(/\|/_search)\|_cat/indices\|_cluster/health)` | Elastic / Kibana internals — data exposure | `/.kibana/_search`, `/_cat/indices` |
| `/(script(Text)?\|jnlpJars/jenkins-cli\.jar\|computer/(\(master\|built-in\))/script)` | Jenkins — Groovy console = RCE; CLI jar = unauth admin | `/script`, `/scriptText` |
| `/cgi-bin/(printenv\.pl\|test-cgi\|php-cgi\|\.\.)` | Legacy CGI — Shellshock + classic info disclosure | `/cgi-bin/printenv.pl` |
| `/metrics\?(format=\|target=\|module=)` | Prometheus federation/scrape-target probe — bare `/metrics` is **not** flagged (legit operator endpoint); only the suspicious-query shapes fire | `/metrics?format=prometheus`, `/metrics?target=10.0.0.1:9100` |

**Why the conservative shape:** many operators legitimately host `/health`, `/metrics`, `/info`, `/status` on their own services. Pattern-matching on bare `/actuator` or `/health` would FP on every Spring-Boot-style operator endpoint that's intentionally public. Each pattern targets the **known-dangerous subpath** specifically. `/actuator/health` and `/actuator/info` therefore stay green.

#### Bare-discovery paths (added 2026-05-09 GAP-001b)

QA Run-6 found three additional probe shapes that the danger-subpath patterns above did not cover:

| Pattern | Why dangerous | Examples |
|---|---|---|
| `/actuator(?:$\|\?\|#)` (bare, no subpath) | Spring Boot Actuator's **root index page** lists every available endpoint — universal first-step recon. Matches `/actuator` and `/actuator?refresh=true` only; `/actuator/health` (subpath form) still goes through the danger-subpath pattern above and stays green | `/actuator`, `/actuator?refresh=true` |
| `/rails/info(?:/\|$)` | Rails debug surface — `/rails/info/properties` leaks installed gems / env / routes. Development-only by design; reachable in prod = recon dump | `/rails/info/properties`, `/rails/info/routes` |
| `/(?:phpinfo\|info\|test\|i)\.php(?:$\|\?\|/)` | Classic PHP-debug-leftover files — `phpinfo()` output dumps loaded modules / paths / environment. Distinct from the existing `phpinfo\(\)` function-call match (which catches the shape inside a body or query value); the file-shape match catches the path-as-filename probe | `/phpinfo.php`, `/info.php`, `/test.php`, `/i.php` |

**Why the file-shape pattern is narrow:** `/index.php` and `/app.php` are common production entry points and **must not** flag. The pattern allowlists only the four canonical debug-file names (`phpinfo`, `info`, `test`, `i`) — operators with debug files outside that allowlist won't be caught, but those four cover the QA Run-6 corpus and the OWASP-recommended probe set.

#### Why bare `/metrics` stays unflagged (deliberate trade-off)

QA Run-6 reported bare `/metrics` as a missed probe; this is **deliberately not flagged**. The Prometheus scrape endpoint is hosted legitimately on essentially every modern operator-monitored service. Flagging it bare would FP on every legit Prometheus scrape and break the monitoring infrastructure operators are paid to keep running. Operators who genuinely don't host Prometheus and want `/metrics` flagged for their environment can:

1. Add a per-environment custom rule via `POST /api/rules` matching `/metrics` exactly, or
2. Move `recon` to `enforce` mode at a tighter `challenge_at` threshold (defeats the operator-friendly default but gives strict-recon coverage),
3. Combine with the `?format=` / `?target=` / `?module=` pattern above which catches the Prometheus-federation probe specifically.

The trade-off is documented here so future QA runs don't re-flag the same gap.

**Score:** existing recon score (25 for path, 30 for UA). Recon is info disclosure, not exec — the detector's job is signal accumulation across multiple probes, not one-shot block. A determined scanner hitting `/actuator/env` once doesn't deserve a block; the third recon probe in a row should (`risk.thresholds.challenge_at = 40` lifts to challenge after a couple of hits, `block_at = 80` blocks once enough recon stacks up).

**Field tag:** `recon_path` (for path hits) — same as Docker REST and the original recon-path corpus.

These are treated as **canary routes** — a request to any of them sets risk to 100 immediately (see [risk scoring](../risk-scoring.md)).

### High path diversity

A client hitting many different paths in quick succession — especially paths that return 404 — is almost certainly scanning. See [behavioral analysis](../behavioral-analysis.md) for path entropy scoring.

### Method probing

Legitimate browsers primarily use `GET` and `POST`. Clients sending `OPTIONS`, `TRACE`, `DEBUG`, `CONNECT`, or unusual methods are probing for supported methods — a classic recon step.

### Error rate

Scanners produce many 404s and 403s relative to 2xxs. A session with >50% error rate and >20 requests is flagged.

### robots.txt / sitemap harvest

A request for `/robots.txt` followed immediately by requests for every disallowed path is scanner behavior. The WAF tracks this.

### Version probing

Requests targeting specific software versions (e.g., `/phpmyadmin/index.php?token=`, `/wp-login.php`) indicate the attacker is testing for a specific vulnerability.

## Scoring

Reconnaissance is rarely blocking-worthy on its own (a legitimate user might occasionally type `/admin` by mistake). The risk increments are moderate:

- Scanner UA: +30
- Canary path hit: set risk to 100 (immediate block)
- Method probing: +10 per suspicious method
- High error rate: +20 (via behavioral analysis)
- robots.txt harvest: +25

When multiple signals combine, the risk score quickly pushes the client into block territory.

## Configuration

```yaml
detection:
  recon:
    enabled: true
    scanner_ua_patterns:
      - "(?i)sqlmap|nikto|nmap|masscan|nuclei|acunetix"
      - "(?i)wpscan|dirbuster|gobuster|ffuf|wfuzz"
    canary_paths:
      - "/.env"
      - "/.git/config"
      - "/wp-login.php"
      - "/phpinfo.php"
    suspicious_methods: [TRACE, DEBUG, CONNECT]
    risk_increment_scanner_ua: 30
```

Canary path list is merged with the risk engine's canary list — both do the same thing.

## Actions

- Scanner UA: elevate risk, challenge new requests
- Canary path: block, audit log with high severity, dashboard alert
- Scanner behavior pattern: block IP for 30 minutes

## Implementation

- `src/detection/recon.rs` — UA matcher, canary path matcher, method probing

## Design notes

- Recon detection is **low-cost** — UA matching uses Aho-Corasick, canary paths use a hash set
- Combining recon + behavior + rate limit creates a compound defense: a scanner hits canary routes (high risk), has high path entropy (behavior penalty), and triggers rate limits (more risk) — all within seconds of starting to scan
