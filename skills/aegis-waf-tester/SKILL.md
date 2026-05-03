---
name: aegis-waf-tester
description: End-to-end QA tester for the Aegis-Gate WAF. Drives the
  data plane via curl + the dashboard via a real browser (Playwright
  when available), evaluates functional correctness, UX from a
  SOC-analyst perspective, and basic performance, then writes
  structured bug / issue / feedback reports. Use whenever the
  operator asks for "test the WAF", "QC the dashboard", "is the WAF
  working", or wants a regression round after a release.
---

# Aegis-Gate End-to-End Tester (skill)

You are acting as a **senior QA engineer** doing a fresh-eyes pass on
the Aegis-Gate WAF. You drive both surfaces — the **data plane**
(HTTP/HTTPS/WebSocket through `:8080` / `:8443`) and the **admin
dashboard** (`:9443`) — and write structured findings the dev team
can triage.

You are NOT writing fixes. Your job is to **find problems, document
them clearly, and rank them**. Recommend fixes only as part of the
finding write-up.

---

## How to invoke

Run when the operator says "test the WAF", "QC the dashboard", "run
the aegis-waf-tester skill", or similar. Three modes:

| Mode | Time | Coverage |
|---|---|---|
| **Smoke** | ~5 min | Pre-flight + auth flow + click every dashboard page + one curl through data plane. Catches regressions. |
| **Functional** | ~20 min | Smoke + every interactive control + every shipped feature surface. Catches broken features. |
| **Full QC** | ~60 min | Functional + UX (SOC-analyst lens) + perf smoke + security regression. Release readiness. |

If the operator doesn't specify, default to **Smoke** and offer to
extend after.

---

## Setup — read this BEFORE running

The Skill needs **two things** to be useful:

1. **A running WAF** on the default ports (data plane `:8080`,
   admin `:9443`, Redis `:6379`).
2. **The repo folder mounted in the session** (so you can read
   the test scripts and write findings into `reports/findings/`).

If **either** is missing, do this in order:

### A. Pre-flight before anything else

If you have access to `Bash` AND can see a `skills/aegis-waf-tester/`
folder in the working directory:

```bash
bash skills/aegis-waf-tester/scripts/verify-waf-up.sh
```

If you don't see the skill folder (Claude Desktop without the repo
connected), the same checks inline:

```bash
curl -fsS --max-time 3 http://127.0.0.1:9443/healthz/live  || echo "WAF admin DOWN"
curl -fsS --max-time 3 http://127.0.0.1:8080/   2>&1 | grep -q . || echo "WAF data DOWN"
(echo PING; sleep 0.2) | nc -w 2 127.0.0.1 6379 | grep -q PONG || echo "Redis DOWN"
```

### B. If the WAF is down

**Don't refuse to run** — offer to start it. If you can run shell:

```bash
# From the aegis-gate repo root:
make redis-up      # starts the dev Redis (idempotent)
make run-dev &     # boots the WAF in the background
sleep 5
bash skills/aegis-waf-tester/scripts/verify-waf-up.sh
```

If you don't have shell access to the operator's machine, **tell
them this exact pair of commands** and ask them to run it in
another terminal, then come back. One short message — don't
fabricate findings while you wait.

### C. If the repo isn't connected to the session

This is fine — fall back to **self-contained mode**:

- Don't try to `cd aegis-gate` or read `tests/manual/`.
- Use only the inline curl commands embedded in this SKILL.md.
- Write findings as **markdown to chat** (using the FINDING
  TEMPLATE below) instead of files. The operator can save them
  manually.
- Report counts the same way at the end (`Findings: N CRITICAL …`).

### D. Required tools

| Tool | Purpose | Required? |
|---|---|---|
| `Bash` | curl + nc + jq | **Yes** — without it you can do nothing. |
| `Read` / `Write` / `Edit` | repo file access | Optional — write findings to chat instead when missing. |
| `mcp__plugin_ecc_playwright__browser_*` | browser automation | Optional — fall back to curl-only and log a single INFO finding noting the gap. |

If Playwright is missing, that's already documented as the
expected fallback path. Note it once and proceed.

---

## Default credentials (`make run-dev`)

- User: `admin`
- Password: `aegis-test-1234`
- Admin: `http://127.0.0.1:9443`
- Data plane: `http://127.0.0.1:8080` (HTTP), `https://127.0.0.1:8443` (HTTPS)
- After `POST /admin/login` you'll get an `aegis_session` + `aegis_csrf`
  cookie pair. Subsequent mutations need `X-CSRF-Token: <csrf-cookie-value>`
  on the request header AND the cookie itself sent. Standard double-submit.

---

## Embedded test plan

Every check below is a yes/no. File a finding for any "no" outcome.

### Phase 1 — Auth + Dashboard shell

```bash
A=http://127.0.0.1:9443

# 1. GET /admin/login renders the login form
curl -fsS "$A/admin/login" | grep -q 'id="login-form"'

# 2. POST with bad creds -> 401 + reason invalid_credentials
curl -s -o /tmp/r -w "%{http_code}" -X POST -H "content-type: application/json" \
  -d '{"user":"admin","password":"wrong"}' "$A/admin/login"
# expect: 401 ; jq -r .reason /tmp/r == "invalid_credentials"

# 3. POST with good creds -> 200 + sets aegis_session AND aegis_csrf cookies
curl -s -c /tmp/jar -X POST -H "content-type: application/json" \
  -d '{"user":"admin","password":"aegis-test-1234"}' "$A/admin/login"
grep -q aegis_session /tmp/jar && grep -q aegis_csrf /tmp/jar

# 4. SPA shell loads
curl -fsS -b /tmp/jar "$A/" | grep -q 'id="root"'
curl -fsS -b /tmp/jar "$A/dashboard/assets/app.js" >/dev/null

# 5. Every documented dashboard API returns 200
for path in \
  /api/about /api/cluster /api/runtime /api/loadmode /api/state \
  /api/routes /api/upstreams /api/upstreams/config \
  /api/detectors /api/rules /api/blacklist /api/whitelist \
  /api/audit/since?limit=5 /api/attacks/top \
  /api/attacks/by-detector?window=3600 \
  /api/bots/mix?window=3600 /api/threat-intel/hits /api/threat-intel/feeds \
  /api/geoip/status /api/slo /api/alerts /api/alert-receivers \
  /api/certs /api/risk /api/incidents \
  /api/stats/timeseries?window=3600 /api/analytics/latency \
  /api/mtls/connections /api/mtls/failures /api/mtls/ca-summary \
  /api/admin/sessions /api/admin/break-glass /api/cold-tier \
  /api/integrations /api/gitops/status /api/config /api/config/version
do
  s=$(curl -s -b /tmp/jar -o /dev/null -w "%{http_code}" "$A$path")
  [[ "$s" == "200" ]] || echo "  FAIL $s $path"
done
```

### Phase 2 — Drive synthetic traffic so the dashboard has signal

```bash
DATA=http://127.0.0.1:8080
ATTACKER=( 8.8.8.8 1.1.1.1 9.9.9.9 )
LEGIT=(    1.0.0.1 9.9.9.10 8.8.4.4 )

for i in 1 2 3 4 5 6 7 8 9 10; do
  ip="${ATTACKER[$((i % 3))]}"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "$DATA/login?u=admin'+OR+1=1--"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "$DATA/?q=<script>alert(1)</script>"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "$DATA/files?p=../../../../etc/passwd"
  curl -s -o /dev/null -H "X-Forwarded-For: $ip" "$DATA/.env"

  legit="${LEGIT[$((i % 3))]}"
  curl -s -o /dev/null -H "X-Forwarded-For: $legit" "$DATA/api/users/$i"
  curl -s -o /dev/null -A "Mozilla/5.0 (Macintosh; Intel) AppleWebKit/605.1.15" \
       -H "X-Forwarded-For: $legit" "$DATA/api/list"
done
sleep 2
```

After this drive, validate:

```bash
# A — Top Attackers populates with real signal
curl -s -b /tmp/jar "$A/api/attacks/top?window=300" \
  | jq '.attackers | length, .attackers[0:3] | map({identifier, hits, country, asn})'

# B — by-detector chart shows real classes (sqli / xss / path_traversal /
#     recon), NOT prefixed with "detector:" and NOT truncated.
curl -s -b /tmp/jar "$A/api/attacks/by-detector?window=300" | jq '.detectors'

# C — Bot mix has more than just "unknown"
curl -s -b /tmp/jar "$A/api/bots/mix?window=300" | jq '.categories'

# D — Live Feed audit shape — fields.{method,path,status} populated
curl -s -b /tmp/jar "$A/api/audit/since?limit=3" \
  | jq '.events[0] | {ts, action, client_ip, fields: (.fields | {method, path, status, bot_category})}'
```

### Phase 3 — CSRF + auth gate

```bash
CSRF=$(awk -v IGNORECASE=1 '/aegis_csrf/{print $7}' /tmp/jar)
NOW=$(date -u +%FT%TZ)

# Add a real entry — needs full body shape (id, kind, value, note, bypass, created_at)
BODY="{\"id\":\"qa-test\",\"kind\":\"ip\",\"value\":\"203.0.113.99\",\"note\":\"qa\",\"bypass\":[],\"created_at\":\"$NOW\"}"

# 1. POST with valid CSRF -> 201
curl -s -b /tmp/jar -X POST -H "content-type: application/json" -H "x-csrf-token: $CSRF" \
  -d "$BODY" -o /dev/null -w "%{http_code}\n" "$A/api/blacklist"
# expect: 201

# 2. POST with no CSRF header -> 403, reason csrf_missing_header
curl -s -b /tmp/jar -X POST -H "content-type: application/json" \
  -d "${BODY/qa-test/qa-test-2}" -o /tmp/r -w "%{http_code}\n" "$A/api/blacklist"
# expect: 403 ; jq -r .reason /tmp/r == "csrf_missing_header"

# 3. POST with wrong CSRF header -> 403, reason csrf_mismatch
curl -s -b /tmp/jar -X POST -H "content-type: application/json" -H "x-csrf-token: WRONG" \
  -d "${BODY/qa-test/qa-test-3}" -o /tmp/r -w "%{http_code}\n" "$A/api/blacklist"
# expect: 403 ; jq -r .reason /tmp/r == "csrf_mismatch"

# 4. Verify the entry actually blocks traffic
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 203.0.113.99" "$DATA/"
# expect: 403

# Cleanup
curl -s -b /tmp/jar -H "x-csrf-token: $CSRF" -X DELETE "$A/api/blacklist/qa-test" -o /dev/null
```

### Phase 4 — Functional spot-checks

For Functional + Full QC modes only. Pick one or two from each
group below:

- **Access lists runtime enforcement.** Add a CIDR blacklist
  entry. Verify `203.0.113.0/24` block applies to `.42` and `.7`
  but not to `192.0.2.7`.
- **Country-code blacklist (needs GeoIP).** Add `kind: country`
  entry for CN. `curl -H "X-Forwarded-For: 223.5.5.5"` returns 403.
  If `/api/geoip/status.db_loaded == false`, skip with INFO.
- **WebSocket bridge.** Pick a route on a non-tcp scheme. From
  the operator's machine: `websocat ws://127.0.0.1:8080/`. The
  audit chain emits `websocket_open` + `websocket_close`.
- **Hot-reload.** Edit `config/dev.yaml`'s
  `cfg.detectors.recon.enabled` to false. Within ~5 s the WAF
  logs `config_reload`; data plane stops firing recon.
  *(skip if no repo access)*

### Phase 5 — UX from SOC-analyst lens (Full QC only)

Pretend you're a SOC analyst on day 1. For each scenario below,
rate 1-5 (5 = effortless, 1 = friction); file a finding for any
score ≤ 3.

- **S1** "I just got paged" — open Overview. Within 5 s can the
  analyst tell: WAF up? Traffic flowing? Anything blocked? Any
  active alerts?
- **S2** "Who's attacking me?" — Top Attackers ranks by hits, not
  alpha. One-click Pivot + Block.
- **S3** "What did this attacker do?" — Pivot lands on
  Investigation with the IP pre-filled and timeline populated.
  Drawer shows status / latency / route / extra fields.
- **S4** Audit Trail surfaces recent mutations within 3 s, with
  actor + chain hash visible.
- **S5** Empty states are honest — no fake numbers on a fresh boot.

### Phase 6 — Performance smoke (Full QC only)

```bash
# Baseline: prod-balanced 5 k+ RPS / p99 1.03 ms / 80 % detection.
# Compare against tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/.

# Quick throughput check on `make run-dev`:
make mock-load-mix DURATION=30s &
sleep 32
curl -s "$A/api/analytics/latency" | jq '.stages.total // {note: "no samples yet"}'
# Expect: p99 ≤ 5 ms on a laptop, ≥ 1 000 RPS sustained
```

### Phase 7 — Security regression (Full QC only)

Replay known-bad payloads + assert the right detector fires:

```bash
probe() {
  local label="$1" path="$2"
  local s rule
  s=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 8.8.8.8" "$DATA$path")
  rule=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 8.8.8.8" "$DATA$path" \
         | grep -i '^x-waf-rule-id:' | awk '{print $2}' | tr -d '\r')
  printf "  %-22s status=%s rule=%s\n" "$label" "$s" "${rule:-(none)}"
}
probe "sqli union"    "/?q=UNION+SELECT+null,version()"
probe "sqli boolean"  "/login?u=admin'+OR+1=1--"
probe "xss script"    "/?q=<script>alert(1)</script>"
probe "ptrav"         "/files?p=../../../../etc/passwd"
probe "ssrf imds"     "/fetch?url=http://169.254.169.254/"
probe "recon env"     "/.env"
probe "recon admin"   "/wp-admin"
```

Expect every probe to return `status=403` with a `rule_id` matching
its detector class (`sqli` / `xss` / `path_traversal` / `ssrf` /
`recon`). Any 200 or empty `rule` is a finding.

---

## Findings — file shape

### Severity ladder (use exactly these strings)

- `CRITICAL` — security vulnerability, data loss, complete breakage
  of a primary surface. Stop testing, escalate.
- `HIGH` — primary feature broken (Live Feed empty, blacklist not
  enforced, dashboard stuck loading). Worth a hotfix.
- `MEDIUM` — secondary feature degraded, UX friction that costs the
  operator real time, perf regression beyond 2× baseline.
- `LOW` — typo, polish, "would be nice".
- `INFO` — passing observation; "this works as designed" or "this
  is a documented limitation". File these too — they're proof the
  test ran.

### Output destination

- **If the repo is connected** (you can see `skills/aegis-waf-tester/reports/`):
  write each finding to `skills/aegis-waf-tester/reports/findings/YYYY-MM-DD/<slug>.md`
  using the template below.
- **If the repo is NOT connected**: emit each finding directly into
  the chat using the same template. Operator copies them out
  manually.

### FINDING TEMPLATE (copy + fill in)

```markdown
---
id: YYYY-MM-DD-<short-slug>
date: YYYY-MM-DDTHH:MMZ
severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
area: dashboard | data-plane | admin-api | docs | perf | security
component: <e.g. live-feed, blacklist, websocket-bridge>
status: open
test_mode: smoke | functional | full-qc
---

# <One-line title>

## Summary
What's broken, where, why it matters to a SOC operator.

## Repro
Numbered, copy-pasteable steps with exact commands + env.

## Expected
What a SOC operator would expect.

## Actual
What happened. Paste exact output, trimmed.

## Suggested fix
One paragraph. Point at file:line when you can.

## Severity rationale
Why this severity? Be specific.
```

---

## End-of-run summary (always emit)

```
Aegis-Gate test run complete · <mode> · <duration>
Findings: <C> CRITICAL · <H> HIGH · <M> MEDIUM · <L> LOW · <I> INFO
Top blocker: <one-line summary of the most-severe finding>
Reports: <path>  (or "in chat above" when no repo)
Next suggested action: <one concrete dev-task or "ship it">
```

Keep this summary under 8 lines.

---

## Anti-patterns (don't do these)

- ❌ **Refusing to run because something is missing.** If pre-flight
  fails, OFFER the start commands. If repo is missing, run
  self-contained. The operator wants forward progress.
- ❌ **Fabricating browser interactions** when Playwright isn't
  loaded. Note the gap, fall back to curl, keep going.
- ❌ **Filing CRITICAL on documented limitations** (e.g. AI
  detector empty when no `.onnx` is configured). Read
  `Implement-Progress.md`'s carry-over list when the repo is
  available; otherwise default to LOW / INFO for anything
  ambiguous.
- ❌ **Editing the WAF source code.** You're a tester. Fixes are
  suggestions in the finding write-up, not commits.
- ❌ **Reporting "tests passed" without enumerating what you ran.**
- ❌ **Marking everything CRITICAL.** Save the label for things
  that genuinely block release.

---

## Repo references (when available)

- `tests/manual/` — hand-runnable validation scripts (mirror of
  Phase 4 above).
- `Implement-Progress.md` — current state of every track,
  including documented limitations to NOT file findings against.
- `tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/` —
  perf baseline for comparison.
- `docs/operator/upstream-cookbook.md` — what each `connection.scheme`
  supports (HTTP / HTTPS / WebSocket auto-bridge / gRPC / TCP CONNECT /
  multi-vhost).
- `docs/security/detectors/README.md` — per-detector class names +
  which tags each emits in `fields.detectors[]`.
