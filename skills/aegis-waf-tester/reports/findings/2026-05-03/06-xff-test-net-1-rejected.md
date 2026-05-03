---
id: 2026-05-03-xff-test-net-1-rejected
date: 2026-05-03T16:10Z
severity: INFO
area: data-plane
component: drive-traffic.sh + XFF resolver
status: open
build_sha: cb95934
test_mode: smoke
---

# Test traffic with `X-Forwarded-For: 192.0.2.x` is recorded as `client_ip: 127.0.0.1`

## Summary

`drive-traffic.sh` spreads its "legit" requests across
`192.0.2.10/11/12` (TEST-NET-1, RFC 5737 — reserved for
documentation).  The audit chain records every one of those
requests with `client_ip: 127.0.0.1` rather than the spoofed
XFF.  Attacker IPs (8.8.8.8, 1.1.1.1, 9.9.9.9 — real public
ranges) resolve correctly via XFF.

This is almost certainly the WAF's XFF resolver correctly
rejecting documentation-range / bogon IPs to prevent header-
forging clients from spoofing fake source IPs.  Defensible
behaviour, but it surfaces in the Skill's traffic mix as
"every legit hit shows up as 127.0.0.1" which (a) skews the
Top-Attackers ranking on a fresh-boot test and (b) doesn't
exercise the XFF path on legit traffic.

## Repro

```bash
DURATION=20 bash skills/aegis-waf-tester/scripts/drive-traffic.sh
# Audit shows attacker IPs resolved, legit IPs as loopback:
curl -s -b /tmp/aegis-skill.jar \
  "http://127.0.0.1:9443/api/audit/since?limit=200" \
  | jq '[.events[] | .client_ip] | group_by(.) | map({ip: .[0], n: length})'
```

## Expected (if intentional)

Document that XFF rejects RFC 5737 ranges and
`drive-traffic.sh` uses real-world public IPs for legit
sources too.

## Actual

```jsonc
[
  { "ip": "127.0.0.1", "n": 122 },   // 122 legit requests fell back
  { "ip": "1.1.1.1",   "n": 27 },
  { "ip": "9.9.9.9",   "n": 21 },
  { "ip": "8.8.8.8",   "n": 20 }
]
```

Net 68 attacker XFF hits resolved correctly; 122 legit hits
fell back to peer IP.

## Suggested fix

Two-part:

1. **Skill side** — update `skills/aegis-waf-tester/scripts/drive-traffic.sh`
   to use real public ranges for legit traffic.  Cloudflare
   public DNS (1.0.0.1) or known-mobile carrier ranges are
   non-controversial.  Avoid TEST-NET-1/2/3 in XFF.

2. **Product side** — confirm the rejection IS intentional and
   document it in `docs/security/xff.md`.  The check probably
   lives in `crates/aegis-security/src/ip_rep/xff.rs`; the
   reject criteria should be visible in the operator docs so
   `tests/manual/fake-country-ips.sh` (which is well-behaved
   today) doesn't regress.

## Severity rationale

INFO — not a product bug, just a script + docs gap that
surfaced through the Skill run.  Moves to LOW if the docs
pass doesn't happen this sprint.

## Done-when

`drive-traffic.sh` uses non-bogon legit ranges and
`docs/security/xff.md` documents the rejection rule.
