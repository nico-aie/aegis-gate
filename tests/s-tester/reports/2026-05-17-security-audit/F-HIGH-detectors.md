---
id: 2026-05-17-high-detectors-bundle
date: 2026-05-17T00:00Z
severity: HIGH
area: security · OWASP detectors
component: crates/aegis-security/src/detectors/{sqli,xss,path_traversal,ssrf,command_injection,recon,body_abuse}.rs
interop_contract: official rules §5.3 OWASP Top-5 + extended detector coverage
status: open
test_mode: source-review
---

# F-HIGH-detectors bundle — 9 mutation-resistance + coverage gaps in OWASP detectors

---

## D-01 · SQLi: headers scanned RAW, no URL-decode

**Component:** [detectors/sqli.rs:67](../../../../crates/aegis-security/src/detectors/sqli.rs#L67)

URI and body are URL-decoded before SQLi scan, but headers (Cookie,
Referer, User-Agent, custom headers) are NOT. Payload:
`Cookie: q=UN%49ON%20SELECT` bypasses every pattern in the header
surface. xss.rs:80-86 by contrast DOES decode headers (asymmetry).
**Fix:** call the same `url_decode` helper on header values before
pattern match.

---

## D-02 · Path-traversal: most patterns omit `(?i)` flag → uppercase-hex bypass

**Component:** [detectors/path_traversal.rs:13-19](../../../../crates/aegis-security/src/detectors/path_traversal.rs#L13-L19)

Only the explicit overlong patterns carry `(?i)`. The base patterns
(`%2e%2e/`, `..\`, etc.) are case-sensitive. `%2E%2E%2F` (uppercase
hex, identical decoded value) bypasses. Mutation-trivial.
**Fix:** prefix every regex with `(?i)`.

---

## D-03 · Path-traversal: headers never scanned

**Component:** [detectors/path_traversal.rs:62-69](../../../../crates/aegis-security/src/detectors/path_traversal.rs#L62-L69)

Only URI + body scanned. SSRF and command_injection scan headers;
path-traversal does not. `X-Original-URL: ../../etc/passwd`,
`X-Rewrite-URL: /../../etc/passwd` (well-known reverse-proxy
override headers) pass through.
**Fix:** extend the scan loop to include headers in the
`x-*-url` / `x-original-url` / `x-rewrite-url` / `referer` set.

---

## D-04 · Command-injection: `${VAR}` template-shape pattern produces FPs

**Component:** [detectors/command_injection.rs:78](../../../../crates/aegis-security/src/detectors/command_injection.rs#L78)

`\$\{[A-Za-z_][^}]+\}` matches ANY `${VAR}` shell-template substitution,
including benign `${HOME}/dir`, `${user.name}` (the test at line 328
EXPECTS this to fire). Real apps echo template syntax into URLs
(CMS preview tools, GraphQL variable URLs).
**Fix:** tighten the suspicious-content check: require the brace
content to look like a shell expansion (`IFS`, `PATH`, `:-`, `:+`,
`jndi:`) or backtick-eval. Allow plain `${IDENTIFIER}` to pass.

---

## D-05 · Command-injection: shell-builtin allowlist too narrow

**Component:** [detectors/command_injection.rs:86-91](../../../../crates/aegis-security/src/detectors/command_injection.rs#L86-L91)

After `|` / `;` / `&&`, only a fixed allowlist of shell builtins is
considered suspicious. Mutations like `;w h o a m i` (spaces),
`${IFS}whoami`, `;wh\oami` evade. Misses common attacker binaries
not on the list: `base64`, `xxd`, `tee`, `dd`, `env`, `printf`,
`kill`, `eval`, `exec`, `nohup`, `setsid`.
**Fix:** invert the logic — match on the presence of ANY non-quoted
shell metachar followed by ANY character class consistent with a
command name, then post-filter for known-safe contexts.

---

## D-06 · XSS: body scanned only as UTF-8; multipart-form binary preamble truncates scan

**Component:** [detectors/xss.rs:69](../../../../crates/aegis-security/src/detectors/xss.rs#L69)

`std::str::from_utf8(req.body.peek(8192)).unwrap_or("")` — when the
first bytes are not UTF-8 (multipart-form upload preamble), the
whole peek returns `""` and the body scan is skipped. Same issue in
sqli.rs:61, path_traversal.rs:65, command_injection.rs:129.
**Fix:** parse multipart and scan each field VALUE as UTF-8;
fall back to substring search on the bytes for non-text payloads.

---

## D-07 · SSRF: scheme-bound to `https?://` → scheme-relative + LDAP/Redis/gopher bypass

**Component:** [detectors/ssrf.rs:18-25](../../../../crates/aegis-security/src/detectors/ssrf.rs#L18-L25)

IPv4-literal patterns all require `https?://` prefix. Bypass vectors:

- Scheme-relative `//169.254.169.254/latest/meta-data/` (cloud metadata!)
- Different schemes used in SSRF payloads: `ldap://10.0.0.1`,
  `redis://127.0.0.1:6379`, `dict://`, `tftp://`, `mongodb://`.

The file scheme-flexes only `file/gopher/dict/ftp` — wrong set.
**Fix:** make the scheme optional in the IP-literal patterns;
match the host portion regardless of scheme. Augment with
explicit scheme blocklist (`ldap://`, `redis://`, `mongodb://`,
`memcached://`).

---

## D-08 · body_abuse: no decompression-bomb check

**Component:** [detectors/body_abuse.rs](../../../../crates/aegis-security/src/detectors/body_abuse.rs)

Official rules §5.3 enumerate "decompression bomb" as a Body Abuse
vector. The detector covers oversize / nesting depth / mass-assign /
XXE / proto-pollution but doesn't decompress gzip/deflate bodies to
check the decompressed size ratio. A `Content-Encoding: gzip` body
of 1 KB that decompresses to 10 GB OOMs the upstream (or the WAF
itself if it ever decompresses).
**Fix:** if `Content-Encoding` is `gzip`/`deflate`/`br`, decompress
into a size-capped buffer (cap ~10 MiB) and check the ratio
(`decompressed.len() / compressed.len() > 1000` → block).

---

## D-09 · recon: no OPTIONS-method abuse, no 4xx-burst pattern

**Component:** [detectors/recon.rs:139-180](../../../../crates/aegis-security/src/detectors/recon.rs#L139-L180)

Official rules §5.3 enumerate "Rapid 4xx/5xx pattern, endpoint
enumeration, option method abuse" as the recon coverage. The
detector implements only path-list + scanner-UA matching. Missing:

- OPTIONS method abuse: scanners use OPTIONS to enumerate without
  triggering normal access logs. No method check.
- Per-IP 4xx/5xx burst: scanners get many 404s. No
  response-code-driven counter.

**Fix:** add an OPTIONS-rate check (per-IP, e.g. >5 OPTIONS in 10s
→ recon). Add a per-IP response-code counter that bumps risk when
4xx ratio over the last N requests is > 0.5.

---

## Severity rationale

HIGH. Each is a mutation-resistance gap on an OWASP-Top-5 detector
class — directly costs Security Effectiveness points (40/120) for
every variation the Red Team uses. None alone is CRITICAL because
basic payloads still match; the gaps are on the mutation surface.
