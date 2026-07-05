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
| `/(app/kibana\|kibana/(app\|api)\|\.kibana(/\|/_search)\|_cat/indices\|_cluster/health)` | Elastic / Kibana internals (Kibana 6+ legacy `/app/kibana` AND Kibana 7+/8+ `/kibana/app`, `/kibana/api/...`) — data exposure | `/app/kibana`, `/kibana/app/dashboards`, `/kibana/api/saved_objects`, `/.kibana/_search`, `/_cat/indices` |
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

#### Missing signature families (added 2026-07-05, RC-3)

Wave A of `FEAT-recon-canary-hardening` closed genuinely-missing families from the 263-path recon
corpus. All score `recon::PATH = 25` unless noted (the secret ones fold into the SENSITIVE tier
above), all tight-anchored with look-alike negative tests:

| Family | Signatures | Notes |
|---|---|---|
| Secrets | `/id_rsa`, `/.npmrc`, `/.git-credentials`, `secrets?.{json,txt,ya?ml,env,config}` | SENSITIVE tier (50); anchored so `/id_rsa_setup_guide.html`, `/secrets-rotation-guide.html` do NOT fire |
| `.env` / backup gaps | `word.env` (`config.env`, `aws.env`), `/wp-config.txt`, `.backup` suffix, backup-word-anchored archives (`www.tar.gz`, `site.zip`, `db.gz`) | `*.environment` and legit downloadable archives (`/downloads/report.zip`, `/assets/app.js.gz`) do NOT fire |
| Exchange / ProxyShell | `/autodiscover/autodiscover.json`, `/owa/auth/logon.aspx`, `/Core/Skin/Login.aspx` | the legit `autodiscover.xml` (hit by every Outlook client) is deliberately excluded |
| WordPress | `/wp-json/{gravitysmtp,wp/v2/settings}`, `/wlwmanifest.xml`, `/xmlrpc.php` | bare `/wp-json/` and legit REST collections (`/wp-json/wp/v2/posts`) do NOT fire |
| Misc | `/Jenkinsfile`, jenkins-anchored `config.xml`, `/.terraform/` | bare `/config.xml` (too generic) does NOT fire; `.terraform/` is SENSITIVE |

#### Encoding / traversal evasion (added 2026-07-05, RC-4)

The recon patterns match the **raw** request path. The [canary detector](../risk-scoring.md#canary-honeypots)
additionally matches a **normalized** copy (`aegis_core::normalize::normalize_path`: percent-decode
+ `//`-collapse + `.`/`..` resolution), so encoding/traversal evasions of a honeypot entry —
`/%2egit/config`, `//.git/config`, `/x/../.git/config` — still trip it. This is canary-only for now
(the single-hit-block tripwire is the high-value target); the raw form stays the contract for every
other detector. Cost is a single scan (`Cow::Borrowed`, no allocation) when the path is already
canonical — the common benign case.

#### Why bare `/metrics` stays unflagged (deliberate trade-off)

QA Run-6 reported bare `/metrics` as a missed probe; this is **deliberately not flagged**. The Prometheus scrape endpoint is hosted legitimately on essentially every modern operator-monitored service. Flagging it bare would FP on every legit Prometheus scrape and break the monitoring infrastructure operators are paid to keep running. Operators who genuinely don't host Prometheus and want `/metrics` flagged for their environment can:

1. Add a per-environment custom rule via `POST /api/rules` matching `/metrics` exactly, or
2. Move `recon` to `enforce` mode at a tighter `challenge_at` threshold (defeats the operator-friendly default but gives strict-recon coverage),
3. Combine with the `?format=` / `?target=` / `?module=` pattern above which catches the Prometheus-federation probe specifically.

The trade-off is documented here so future QA runs don't re-flag the same gap.

**Score (two tiers since RC-2, 2026-07-05):**

- **`recon::PATH = 25`** — generic / ambiguous probes (`/wp-admin`, `/phpinfo.php`, the swagger
  surface, the bare `/actuator` index). Info disclosure, not exec: the detector's job here is
  signal accumulation across multiple probes, not a one-shot block. A determined scanner hitting a
  generic probe once doesn't deserve a block; enough of them stack up via the cumulative per-IP
  risk model (`challenge_at = 40`, `block_at = 80`).
- **`recon::SENSITIVE = 50`** — the secret-exposure subset (`RECON_SENSITIVE_PATHS`), checked
  first: credential files (`.aws/credentials`, `.git-credentials`, `.npmrc`, `secrets?.{json,txt,
  ya?ml,env,config}`, `secrets|settings|credentials|database|parameters.ya?ml`), private-key /
  keystore material (`.pem/.key/.p12/.pfx/.jks/.keystore`, `.ssh/`, `/id_rsa`), `.terraform/`, the
  Spring actuator secret/RCE subset (`heapdump`, `threaddump`, `env`, `configprops`, `jolokia`,
  `shutdown`, `dump`), and `wp-config.php`/`.txt`. Higher confidence → double weight, but still
  **below `block_at` (70)**: a single hit is at most a challenge; two hits cumulative-block. Any
  escalation to a single-hit-block score (≥ 70) is gated on the FP-baseline corpus + owner sign-off.
- **Scanner UA:** `recon::TOOL = 50` (`sqlmap`, `nikto`, `nmap`, …).

**Field tag:** `recon_path` for path hits (both tiers — only the score differs), `recon_tool` for UA.

**Not the same as the canary detector.** Recon paths *score* (25 / 50) and accumulate; they do
**not** hard-block. The [canary detector](../risk-scoring.md#canary-honeypots) is a **separate**,
operator-curated honeypot list (`risk.canary_paths`, default 11 entries since RC-1) whose single
hit scores **100** — an instant block at every tier. Some paths appear in both (e.g.
`/wp-config.php`, `/.aws/credentials`): the canary hard-blocks them, and recon independently scores
them. `/actuator/env` is a deliberate example of the difference — recon scores it sensitive (50)
but it was **dropped from the canary set** (2026-07-05) because Spring Boot Admin polls it
legitimately through the edge, so it must not hard-block.

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

- Generic probe path (`recon_path`): +25
- Secret-exposure path (`recon_path`, SENSITIVE tier): +50
- Scanner UA (`recon_tool`): +50
- Method probing: +10 per suspicious method
- High error rate: +20 (via behavioral analysis)
- robots.txt harvest: +25

A **canary** hit (the separate operator-curated honeypot list) sets risk to 100 for an immediate
block — that is the canary detector, not recon; see [risk scoring](../risk-scoring.md#canary-honeypots).
When multiple recon signals combine, the cumulative per-IP score quickly pushes the client into
challenge then block territory.

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
