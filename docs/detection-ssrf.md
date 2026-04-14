# SSRF (Server-Side Request Forgery) Detection

## Purpose

Detect requests that attempt to coerce the backend into making outbound connections to internal services, cloud metadata endpoints, or private networks. SSRF is especially dangerous on cloud platforms where the metadata service can leak credentials.

## What SSRF looks like

Any user-supplied URL or hostname that points to:

- Private IP ranges (RFC 1918)
- Loopback (`127.0.0.0/8`, `::1`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Cloud metadata: `169.254.169.254` (AWS, GCP, Azure), `fd00:ec2::254` (AWS IPv6)
- DNS private zones: `*.internal`, `*.local`, `*.lan`, `*.corp`
- Protocols other than `http`/`https`: `gopher://`, `file://`, `dict://`, `ftp://`, `ldap://`, `jar://`

## Detection strategy

The detector scans request surfaces for URL-like tokens, parses each one, resolves hostnames (if configured), and checks the target against the block list.

### Surfaces

- Query parameters (common: `?url=`, `?redirect=`, `?next=`, `?image=`, `?callback=`)
- Request body fields named like `url`, `webhook`, `callback`, `target`, etc.
- `Referer` and custom URL-bearing headers
- JSON fields in POST bodies (recursive scan)

### Patterns

Literal IP ranges in any form:

- `127.0.0.1`, `localhost`, `0.0.0.0`
- `10.*`, `172.16-31.*`, `192.168.*`
- `169.254.169.254` (cloud metadata)
- `0x7f.0.0.1` (hex), `2130706433` (decimal IP)
- `0177.0.0.1` (octal)
- `::1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`

Protocol enumeration:

- `gopher://`, `file://`, `dict://`, `ftp://`, `ldap://`, `jar://`, `netdoc://`, `php://`

Cloud metadata-specific:

- `/latest/meta-data/` (AWS)
- `/computeMetadata/v1/` (GCP)
- `/metadata/instance/` (Azure)

### Bypass patterns

Attackers commonly use redirectors and alternate encodings:

- `@` in URLs: `http://example.com@169.254.169.254/` — authority is the RIGHT side
- DNS rebinding indicators (domains that resolve to private IPs)
- URL-shortener-style redirects (if the submitted URL is a known redirector, rescan the target)
- IPv6 mapping: `::ffff:169.254.169.254`

## DNS resolution

If `resolve_hostnames: true` (opt-in, off by default for latency reasons), the detector resolves hostnames to check if they point to private IPs. This catches DNS rebinding but adds latency.

With resolution off, the detector relies purely on the textual URL — still effective for the majority of cases since most SSRF attacks use raw IPs.

## Scoring

SSRF is high-confidence when detected:

- Direct private IP in a URL parameter: +50 risk, flag immediately
- Cloud metadata IP: +80 risk, flag immediately
- Suspicious protocol: +40 risk
- Fuzzy match (e.g., `localhost` in a text field that normally takes URLs): +20 risk

## Configuration

```yaml
detection:
  ssrf:
    enabled: true
    resolve_hostnames: false
    allow_localhost_in_body: false
    block_protocols: [gopher, file, dict, ftp, ldap, jar]
    risk_increment: 50
    url_param_names:
      - url
      - redirect
      - next
      - callback
      - webhook
      - image
      - src
```

## Actions

- Add risk increment
- Audit log with the submitted URL and the matched reason
- Typically blocks outright because SSRF has essentially no legitimate use case against private IP space

## Implementation

- `src/detection/ssrf.rs`

## Design notes

- The WAF only *detects* SSRF attempts; it does not prevent the backend from making its own requests (that's the backend's responsibility, enforced by network egress rules)
- By detecting in the WAF, operators get visibility and can block the request before the backend is even invoked
- The `url_param_names` list lets operators tune which parameters are considered URL-bearing
