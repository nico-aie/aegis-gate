# Security regression checklist

Replay known-bad payloads through the data plane and assert the
right detector fires + the right `x-waf-rule-id` shows up. This
is regression coverage — every payload below has a documented
detector that should fire.

If a payload doesn't fire its expected detector, that's at least
HIGH (a regression in the security posture). If it fires but
the rule_id doesn't match the documented one, that's MEDIUM.

## Setup

```bash
DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"

# Helper: probe and report
probe() {
  local label="$1"; shift
  local resp status rule
  resp=$(mktemp)
  status=$(curl -s -o "$resp" -D "$resp.h" -w "%{http_code}" "$@")
  rule=$(grep -i '^x-waf-rule-id:' "$resp.h" | awk '{print $2}' | tr -d '\r')
  printf "  %-35s status=%-3s rule_id=%s\n" "$label" "$status" "${rule:-(none)}"
  rm -f "$resp" "$resp.h"
}
```

## SQLi

- [ ] `union+select` — should fire `sqli`
  `probe "sqli union" "$DATA/?q=UNION+SELECT+null,version()"`
- [ ] Boolean-based `or 1=1` — should fire `sqli`
  `probe "sqli bool" "$DATA/login?u=admin'+OR+1=1--"`
- [ ] Time-based `sleep` — should fire `sqli`
  `probe "sqli time" "$DATA/?q=1';WAITFOR+DELAY'0:0:5'--"`

## XSS

- [ ] Inline `<script>alert(1)</script>` — should fire `xss`
  `probe "xss script" "$DATA/?q=<script>alert(1)</script>"`
- [ ] Event-handler `onerror=` — should fire `xss`
  `probe "xss onerror" "$DATA/?q=<img+src=x+onerror=alert(1)>"`

## Path traversal

- [ ] `../../etc/passwd` — should fire `path_traversal`
  `probe "ptrav passwd" "$DATA/files?p=../../../../etc/passwd"`
- [ ] URL-encoded `..%2f..` — should fire `path_traversal`
  `probe "ptrav enc"    "$DATA/files?p=..%2f..%2f..%2fetc%2fpasswd"`

## SSRF

- [ ] `http://169.254.169.254/` (AWS IMDS) in body — should fire
      `ssrf`
- [ ] `http://127.0.0.1:22` in URL params — should fire `ssrf`
  `probe "ssrf loopback" "$DATA/fetch?url=http://127.0.0.1:22"`

## Header injection

- [ ] `X-Custom: foo\r\nX-Smuggled: bar` — should fire
      `header_injection`. Note: many curl versions strip CRLF;
      use `--data-binary` against the body or URL-encode in the
      query.

## XXE (POST body)

- [ ] `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` —
      should fire `xxe`
```bash
curl -s -X POST -H "content-type: application/xml" \
  --data-binary '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  "$DATA/api/parse"
```

## Recon

- [ ] `/.env` — should fire `recon`
- [ ] `/wp-admin` — should fire `recon`
- [ ] `/.git/config` — should fire `recon`
- [ ] `/phpmyadmin/` — should fire `recon`

## Brute force (auth)

- [ ] 11 failed `POST /admin/login` from the same IP within 60 s
      → 11th lands `429 Too Many Requests` with retry-after.
- [ ] Successful login resets the failure counter for that IP.

Reference: `tests/api/auth.sh` for the exact thresholds.

## Mass assignment

- [ ] `POST /api/users` with `{"name":"x","admin":true,"role":"superuser"}`
      → should fire `mass_assignment` against the privileged
      fields.

## Body abuse — oversized

- [ ] POST 10 MB body → should hit body cap and return
      `413 Payload Too Large` (data-plane cap is configurable;
      default tests against `cfg.body.max_bytes`).

## Headers — overlong

- [ ] Single header value of >8 KB → 431 / 400.

## Bot fingerprint

- [ ] User-Agent `curl/8.1.2` + JA4-incompatible TLS shape →
      Bot Mix should classify as `unknown` or `suspect`.
- [ ] Known good UA + correct JA4 → `verified`.

## Compliance

- [ ] `cfg.compliance.modes: pci_dss`. Try to disable a
      PCI-pinned detector via `PUT /api/detectors`. Should be
      clamped — detector stays enabled, audit logs
      `compliance_clamp_applied`.

## Authorisation drift

- [ ] Hit a mutating admin endpoint (e.g. `PUT /api/blacklist`)
      with no session at all → 401 / redirect to /admin/login.
- [ ] Same with a session but the wrong CSRF → 403.

## Source-of-truth references

- All detector class names + their `rule_id` shape:
  `crates/aegis-security/src/detectors/`
- Existing security regression coverage:
  `tests/security/` + `tests/contract/`
- Nuclei runs:
  `nuclei -u http://127.0.0.1:8080/ -tags sqli,xss,traversal -duc`
