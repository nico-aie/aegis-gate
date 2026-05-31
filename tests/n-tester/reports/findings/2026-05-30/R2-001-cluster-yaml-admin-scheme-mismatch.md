---
id: 2026-05-30-cluster-yaml-admin-scheme-mismatch
date: 2026-05-30T20:30Z
severity: HIGH
area: docs
component: cluster-fixtures, ui-playbooks
status: open
test_mode: full-qc
---

# Cluster fixtures bind admin plaintext but every UI playbook + Round-2 prompt uses `https://`

## Summary

`config/cluster-{a,b}.yaml` ship `admin.bind: 127.0.0.1:9{443,543}` with
**no `tls:` block** under `admin:`. At boot the WAF confirms this with
`admin-plane listening on 127.0.0.1:9443 (http)` (not `(tls)`). But:

- `tests/n-tester/ui/README.md` setup step 3: `Chrome logged in to https://127.0.0.1:9443/`.
- Every NT-UI-* playbook's Paste-to-Claude block: `Drive Chrome to https://127.0.0.1:9443/`.
- The Round-2 operator prompt's Step 1.6 regression check: `curl … https://127.0.0.1:9443/admin/login`.

Result: a SOC analyst (or QC tester) following any of these gets a TLS
handshake against a plaintext socket — curl returns HTTP 000, Chrome
shows ERR_SSL_PROTOCOL_ERROR. The dashboard appears unreachable.

The shell-suite escapes this because `_common.sh` defaults
`NODE_A_ADMIN=http://127.0.0.1:9443`. Only the human-facing surfaces
mismatch.

## Repro

```sh
cd /Users/nico/waf-code/aegis-gate
./target/release/waf run --config config/cluster-a.yaml > /tmp/a.log 2>&1 &
sleep 2
grep 'admin-plane listening' /tmp/a.log
# → admin-plane listening on 127.0.0.1:9443 (http)

curl -ks -o /dev/null -w '%{http_code}\n' https://127.0.0.1:9443/healthz/ready
# → 000

curl  -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9443/healthz/ready
# → 200
```

## Expected

One of:

- A: cluster fixtures gain a `tls:` block under `admin:` so the
  playbooks' `https://` works as written. Matches `dev.yaml`'s
  conventions if dev.yaml also serves admin over HTTPS — and matches
  the implicit "port 9443 == HTTPS" convention of every other port
  named after the well-known HTTPS prefix.
- B: every playbook + the README + the operator prompt flip to
  `http://127.0.0.1:9443`.

## Actual

Cluster YAMLs bind plaintext; every Markdown surface that an operator
reads says HTTPS. A first-time tester is dead-in-the-water for ~15
minutes while they figure out the scheme.

## Suggested fix

Option B is cheaper and lower-blast-radius. Search/replace
`https://127.0.0.1:9443` → `http://127.0.0.1:9443` (and 9543) under:

- `tests/n-tester/ui/README.md`
- `tests/n-tester/ui/nt-ui-{01..07}-*.md`
- `tests/n-tester/README.md` (if any references)

If admin SHOULD terminate TLS in cluster fixtures (matching production
profiles), Option A is the real fix — add a `tls:` block to the admin
listener and point at `config/certs/dev.crt`. The dev profile already
ships a self-signed cert for the data plane; admin can ride the same
material.

## Severity rationale

HIGH — every UI playbook is unrunnable as written. A new operator
or QC tester following the README sees nothing work and has no
diagnostic path. Not CRITICAL because the workaround (flip scheme)
is one keystroke once you know.
