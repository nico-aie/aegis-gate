# SSRF (Server-Side Request Forgery) Detection

> **Status:** Implemented — `aegis-security/src/detectors/ssrf.rs`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

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

#### URL userinfo (added 2026-05-09 GAP-004)

Some URL parsers split the authority on the **first** `@` they see; others on the **last**. Attackers exploit the discrepancy:

```
http://[email protected]:8080/path
                        ^---- some parsers split here
        ^----------------- others split here
```

A naive WAF allowlist that sees the URL "starts with `http://` and contains `evil.com`" allows the request — even though the real fetch goes to `internal-svc:8080/path` (the parser interpreted `evil.com:80@` as userinfo, not host).

The detector now flags any HTTP(S) URL with userinfo via the regex
`https?://[^@/\s]+@`. Tag stays `ssrf`, score `50`. Examples:

| Input | Why it flags |
|---|---|
| `?url=http://user:pass@10.0.0.1/secret` | Direct userinfo + private IP destination |
| `?url=https://evil.com:80@internal-svc/` | Parser-split bypass (the real host is `internal-svc`) |
| `?u=http://x@127.0.0.1` | Trivial userinfo + loopback |

Negative cases that do NOT flag:

- `?email=user@example.com` — no `://` scheme prefix
- `?to=mailto:user@example.com` — `mailto:` not `http(s)://`
- `/oauth/callback?code=abc&user=fred` — no `@` in the URL value

**Why the userinfo shape and not "just match internal IP after `@`":** that would be brittle — attackers can use DNS rebinding or direct hostnames. Catching the userinfo shape itself is the right hook because the parser-confusion vector applies regardless of destination.

HTTP basic-auth in URL form is RFC 3986-deprecated and rare in modern apps; legitimate auth lives in `Authorization` headers. Flagging URL-userinfo matches Chrome's behaviour (warns / blocks) and major-WAF practice.
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
