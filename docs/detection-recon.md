# Reconnaissance Detection

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

These are treated as **canary routes** — a request to any of them sets risk to 100 immediately (see [risk scoring](./risk-scoring.md)).

### High path diversity

A client hitting many different paths in quick succession — especially paths that return 404 — is almost certainly scanning. See [behavioral analysis](./behavioral-analysis.md) for path entropy scoring.

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
