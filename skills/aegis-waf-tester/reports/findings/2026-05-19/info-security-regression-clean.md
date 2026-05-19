---
id: 2026-05-19-info-security-regression-clean
date: 2026-05-19T12:40Z
severity: INFO
area: data-plane
component: detector-chain
status: open
test_mode: functional
---

# Security regression: 7/7 attack probes blocked, 3/3 clean baselines pass

## Summary

After the risk-composite-key data-plane swap, the detector chain
still produces the same behavior the audit asserted before the
swap. No SSRF false-positives on clean baselines, no duplicated
detector classes in any `X-WAF-Rule-Id`, no combination-string
buckets in `/api/attacks/by-detector`. The new
`build_risk_key(peer_ip, headers, tls_fp)` call site did not
disturb the detector flow above it.

## Repro

Phase 7 probe sweep against `http://127.0.0.1:8080` from a fresh
cookieless context.

## Actual

```
sqli union    status=403 classes=sqli                        ✓
sqli boolean  status=403 classes=sqli                        ✓
xss script    status=403 classes=xss,recon_path,ai           ✓ (xss present; multi-class is fine)
ptrav         status=403 classes=path_traversal              ✓
ssrf imds     status=403 classes=ssrf,open_redirect          ✓
recon env     status=403 classes=recon_path                  ✓
recon admin   status=403 classes=recon_path                  ✓

clean root    status=200 classes=none                        ✓
clean api     status=404 classes=none                        ✓ (404 from upstream, not WAF)
clean fav     status=404 classes=none                        ✓
```

`/api/attacks/by-detector?window=3600` after the smoke drive
reports single-class rows (`sqli`, `path_traversal`,
`recon_path`, `xss`, `ai`), no combination-string buckets.

## Suggested fix

None.

## Severity rationale

INFO — passing regression. Captured for the run record.
