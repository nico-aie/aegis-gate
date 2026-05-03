---
name: aegis-waf-tester
description: End-to-end QA tester for the Aegis-Gate WAF. Drives the
  data plane via curl/in-page fetch + the dashboard via a real browser
  (Claude in Chrome preferred, Playwright as alternative). Walks every
  sidebar page (17), exercises every interactive control, evaluates
  functional correctness, UX from a SOC-analyst perspective (S1-S8),
  and basic performance, then writes structured bug / issue / feedback
  reports. Use whenever the operator asks for "test the WAF",
  "QC the dashboard", "is the WAF working", or wants a regression
  round after a release.
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

Pick whichever is available — both work, browser is preferred for
UX coverage:

| Tool | Purpose | Required? |
|---|---|---|
| `mcp__Claude_in_Chrome__*` | drive the dashboard, click buttons, screenshot, run in-page `fetch()` against admin + data plane | **Strongly preferred** — only path that exercises UI/UX scenarios properly |
| `Bash` | curl + nc + jq when running outside Cowork | **Optional** — only useful when the runner is on the *same* loopback as the WAF |
| `Read` / `Write` / `Edit` | repo file access for findings | Required when filing structured findings to disk |
| `mcp__plugin_ecc_playwright__browser_*` | alternative browser path | Optional — Claude in Chrome is preferred |

### E. Cowork-mode reality check

When this skill runs inside a Cowork session, the bash sandbox is
on **a different host** than the operator's WAF. The sandbox can't
reach `127.0.0.1:9443` / `127.0.0.1:8080` on the operator's Mac
(no `host.docker.internal`, just `127.0.0.1 localhost` in
`/etc/hosts`). The pre-built `target/release/waf` is also Mach-O,
won't exec on the Linux sandbox, and the toolchain to rebuild
isn't installed. Do NOT waste time trying to curl the WAF from
sandbox bash; use **Claude in Chrome** for everything that touches
the running WAF.

The Cowork-friendly run sequence:

1. Operator boots the WAF on their host
   (`make redis-up && make run-dev`).
2. Confirm Chrome is connected: call
   `mcp__Claude_in_Chrome__tabs_context_mcp` with
   `createIfEmpty: true`.
3. Drive the admin in tab A (open
   `http://127.0.0.1:9443/admin/login`, fill the form, log in).
4. Drive the data plane in tab B (open
   `http://127.0.0.1:8080/__qa-anchor`); fetch from this tab's
   page-context so `X-Forwarded-For` headers send without CORS
   preflight.
5. Use `mcp__Claude_in_Chrome__javascript_tool` (`javascript_exec`)
   to run cookie-bearing fetch() against the admin from tab A
   and against the data plane from tab B.

Sandbox bash is still useful for: reading repo files, grepping
the dashboard `src/` for typo'd hook aliases, writing finding
markdown, looking at `Implement-Progress.md`'s carry-over list.
Just not for hitting the WAF.

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

**Browser path equivalent** (when running in Cowork — preferred):
sign in via the form (find user/pass/Sign-in inputs, fill, click),
then run the API sweep via `javascript_tool`:

```js
// from the dashboard tab (cookies attached automatically)
(async () => {
  const paths = [/* same list as above */];
  const out = [];
  for (const p of paths) {
    const r = await fetch(p, {credentials: "include"});
    const t = await r.text();
    out.push({path: p, status: r.status, len: t.length, head: t.slice(0,120)});
  }
  return out;
})()
```

Any non-200 is a finding. Cookie-pair check: in the same console
verify both `aegis_session` and `aegis_csrf` are present
(`document.cookie.match(/aegis_(session|csrf)=/g)`).

#### 1f — Error-boundary smoke (do this every run)

This catches the entire class of "page never mounts" bugs that
cost a SOC analyst the workflow they came for. Walk every sidebar
item, click each, screenshot, and check no error-boundary card is
rendered. From the dashboard tab:

```js
// list every sidebar nav target
(async () => {
  const links = [...document.querySelectorAll('aside a, aside button, nav a, nav button')]
    .map(el => ({text: el.textContent.trim(), href: el.getAttribute('href') || el.dataset.route || ''}))
    .filter(x => x.text && x.text.length < 40);
  return links;
})()
```

For each one, click it, then assert via `read_page` /
`get_page_text` / `find` that the body is **NOT** showing
`Page render error` (the error-boundary card title) and **IS**
showing the page's expected H1 (e.g. "Top Attackers", "Live Feed",
"Audit Trail"). File a CRITICAL the moment any page errors out.

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
# A — Top Attackers populates with real signal.
#     The connection peer (127.0.0.1 / loopback) MUST NOT outrank the
#     spoofed IPs; if it does, the audit double-write regression is back.
curl -s -b /tmp/jar "$A/api/attacks/top?window=300" \
  | jq '.attackers | length, .attackers[0:3] | map({identifier, hits, country, asn})'

# B — by-detector chart shows ONE row PER DETECTOR CLASS
#     (sqli / xss / path_traversal / ssrf / recon_path), with
#     the `name` field carrying ONLY the class. Combination
#     strings ("sqli,ssrf", "path_traversal,path_traversal,ssrf")
#     mean the bucketing regression is back. Counts should be
#     summed across combinations.
curl -s -b /tmp/jar "$A/api/attacks/by-detector?window=300" | jq '.detectors'

# C — Bot mix has more than just "unknown"
curl -s -b /tmp/jar "$A/api/bots/mix?window=300" | jq '.categories'

# D — Live Feed audit shape — fields.{method,path,status} populated.
#     For the 60-probe drive above, audit count should be ~60 (one
#     row per request), NOT ~120 (the double-write regression).
curl -s -b /tmp/jar "$A/api/audit/since?limit=3" \
  | jq '.events[0] | {ts, action, client_ip, peer_ip: .fields.peer_ip,
                      fields: (.fields | {method, path, status, bot_category, detectors})}'

# E — Clean baseline: clean GET / from a fresh IP returns 200
#     (or 502 if upstream absent). NOT 403.  If it's 403 with
#     `detector:ssrf` or any other detector tag, the SSRF
#     false-positive regression is back.
curl -i -H "X-Forwarded-For: 192.0.2.50" "$DATA/" | head -5
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

### Phase 4 — Per-page coverage matrix

For **Functional + Full QC** modes: hit every page below. For
each one, record the four checks. Skipping a page is a finding
in itself ("page not exercised in this run").

Use `mcp__Claude_in_Chrome__find` (or `read_page` with
`filter: "interactive"`) to enumerate every button / dropdown /
input / toggle / link on the page, then click / fill / open
each one. Don't assume "if I'm on this page it works"; assume
the developer typo'd one of these controls.

For each page:

1. **Mounts cleanly?** No `Page render error` card; no console
   errors visible via `read_console_messages` filtered to
   `pattern: "error|warning"`.
2. **Primary data correct?** Cross-check the page's main
   table / chart / card against the API endpoint(s) it pulls
   from. UI count == API count.
3. **Every control functions?** Click every button (ignoring
   destructive ones until you confirm), open every dropdown,
   fill every input, toggle every switch. Capture state
   change. Specifically:
   - Buttons: click → expected modal / API call / row mutation.
   - Dropdowns: open → all options visible → pick a non-default
     → state change visible in URL or in API response.
   - Inputs: focus → type sample → blur → page state updates
     (filter / search / form).
   - Toggles: flip → page state changes → flip back → state
     restored.
4. **Empty / loading / error states honest?** Empty table says
   "no entries", not "—". Loading state shows a skeleton or
   spinner, not the previous data. Error state surfaces the
   actual error, not a swallowed `console.error`.

#### Page inventory (17 pages, all sidebar items)

For each page write a mini-row in your run summary:
`<page> mounts:✓ data:✓ controls:✓ empty:✓` or list which
sub-checks failed. File a finding for any sub-check that fails.

| Section | Page | Primary API | Controls to exercise |
|---|---|---|---|
| Security Ops | **Overview** | `/api/loadmode`, `/api/cluster`, `/api/upstreams`, `/api/stats/timeseries`, `/api/attacks/by-detector` | Refresh button, Export button, Open Grafana, "Notify me" CTA, time-window selector on charts |
| Security Ops | **Live Feed** | SSE `/api/audit/stream` + initial `/api/audit/since?limit=80` | Pause / Resume, CSV export, "All actions" + "All risk tiers" dropdowns, search input, row → request-detail drawer |
| Security Ops | **Incidents** | `/api/incidents` | Time window, severity filter, expand row → details |
| Security Ops | **Investigation** | `/api/audit/since` filtered by pivot | Pivot input, kind selector (auto / ip / request_id / rule_id), action filter (all / block / allow / challenge), event row → detail drawer |
| Security Ops | **Top Attackers** | `/api/attacks/top` | Window dropdown (5m / 15m / 1h / 24h), Refresh, **Pivot** link → Investigation, **Block** button → POST /api/blacklist with confirm |
| Security Ops | **Threat Intel** | `/api/threat-intel/hits`, `/api/threat-intel/feeds` | Feed list, refresh, expand a hit |
| Policy | **Rules** | `/api/rules` | Add rule, edit, delete (all CSRF-gated POST/DELETE) |
| Policy | **Detectors** | `/api/detectors` | Edit base mask, edit per-tier override, tier selector (critical / high / medium / low), routes-assigned table |
| Policy | **Access Lists** | `/api/blacklist`, `/api/whitelist` | Tab switch (Black/White), add entry (kind ip / cidr / asn / country), edit, delete, bulk import, search, expiry picker |
| Policy | **Routing & Upstreams** | `/api/routes`, `/api/upstreams`, `/api/upstreams/config` | Route list expand, member health, edit member, scheme selector |
| Policy | **Compliance** | `/api/config` (compliance section) | Profile picker, mode toggle, audit on profile flip |
| Observability | **Performance** | `/api/analytics/latency`, `/api/runtime` | Stage breakdown, percentile selector, runtime knob view |
| Observability | **Health & SLOs** | `/api/slo`, `/api/alerts`, `/api/alert-receivers` | SLI cards, Alerts firing/pending/resolved tabs, receiver list, "send test alert" button |
| Observability | **Audit Trail** | `/api/audit/since` | Filters: client IP, rule_id, request_id, time window (1h / 24h / 7d / all), Refresh, cursor pagination, row → expand |
| Observability | **Scaling** | `/api/loadmode`, `/api/runtime` | Mode override (normal / elevated / critical), worker mode, force apply |
| Admin | **Settings** | `/api/admin/sessions`, `/api/admin/break-glass`, `/api/integrations`, `/api/certs`, `/api/mtls/*` | Sessions list, terminate session, break-glass toggle, integrations form, cert list expand, mTLS CA summary |
| Admin | **Reports** | `/api/cold-tier`, export endpoints | Date range, generate, download |
| Admin | **Help & Guide** | static | scroll, internal links resolve |

#### Functional spot-checks (still required for Full QC)

After the matrix sweep, run these end-to-end flows. They
exercise data-plane × control-plane interaction that the
per-page UI checks alone don't cover:

- **Access lists runtime enforcement.** Add a CIDR blacklist
  entry via the UI (kind=cidr, value=`203.0.113.0/24`). Verify
  via curl/fetch that `203.0.113.42` and `203.0.113.7` get
  blocked but `192.0.2.7` does not.
- **Country-code blacklist (needs GeoIP).** Add `kind: country`
  entry for CN via the UI. `fetch("/", { headers: {"X-Forwarded-For": "223.5.5.5"} })`
  returns 403. If `/api/geoip/status.db_loaded == false`, skip
  with INFO.
- **WebSocket bridge.** Pick a route on a non-tcp scheme. From
  the operator's machine: `websocat ws://127.0.0.1:8080/`. The
  audit chain emits `websocket_open` + `websocket_close`.
- **Hot-reload.** Edit `config/dev.yaml`'s
  `cfg.detectors.recon.enabled` to false. Within ~5 s the WAF
  logs `config_reload`; data plane stops firing recon.
  *(skip if no repo access)*
- **Detector mask flip via UI.** Toggle one detector off in
  the Detectors page; verify the audit row records the mutation
  with actor + chain hash; verify a request that previously
  matched that detector now passes.
- **Re-auth flow.** Trigger a `csrf_mismatch` deliberately,
  then hit any admin page → confirm session integrity (whether
  the session was force-rotated or kept). Document either
  outcome — both are valid policies, surprises aren't.

### Phase 5 — UX from SOC-analyst lens (Full QC only)

Pretend you're a SOC analyst on day 1. For each scenario below,
rate 1-5 (5 = effortless, 1 = friction); file a finding for any
score ≤ 3.

- **S1** "I just got paged" — open Overview. Within 5 s can the
  analyst tell: WAF up? Traffic flowing? Anything blocked? Any
  active alerts? Status badges should NOT paint red on a healthy
  unconfigured-but-functional system (cluster=single-node,
  GitOps=off, etc.); reserve red for outages.
- **S2** "Who's attacking me?" — Top Attackers ranks by hits, not
  alpha. One-click Pivot + Block. The connection peer (loopback
  in dev) MUST NOT outrank the resolved client IPs.
- **S3** "What did this attacker do?" — Pivot lands on
  Investigation with the IP pre-filled and timeline populated.
  Drawer shows status / latency / route / extra fields.
  Pivot must navigate the shell, not just rewrite the URL hash.
- **S4** Audit Trail surfaces recent mutations within 3 s, with
  actor + chain hash visible. Each blocked request appears as
  one row, not two.
- **S5** Empty states are honest — no fake numbers on a fresh boot.
  Cards that pull from one API must agree with that API
  (Upstream card vs `/api/upstreams.state`, etc.).
- **S6** "Block this attacker." Click Block on a Top Attackers
  row → confirm modal → confirm → row turns blocked → next
  request from that IP returns 403 `blacklist`. End-to-end
  mutation flow ≤ 3 clicks.
- **S7** "Reload tolerance." On every page, hit the browser
  reload button. State that should persist (filters, time window,
  selected tab) should survive; state that shouldn't (modals,
  unsaved form input) should not. URL hash must reflect the
  current view enough that copy-paste recreates it.
- **S8** "Console hygiene." With the dashboard open, monitor
  `read_console_messages` over a 60-second idle period. No
  red errors. No 4xx from the SPA's own polling. Any `console.error`
  is a finding.

#### Visual / accessibility quick passes

- Hover every interactive element; tooltips render legibly.
- Tab through the page once; focus ring is visible at every stop.
- Resize the window to 1024×768 and 1920×1080; layout doesn't break.
- Take a screenshot of every page at 1568×782 for the run record.

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

Replay known-bad payloads + assert the right detector fires.
The `X-WAF-Rule-Id` response header is prefixed `detector:` for
detector-class hits and `blacklist` / `blacklist:<id>` for
access-list hits. Strip the prefix before comparing.

```bash
probe() {
  local label="$1" path="$2" expect="$3"
  local s rule classes
  s=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 8.8.8.8" "$DATA$path")
  rule=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 8.8.8.8" "$DATA$path" \
         | awk 'BEGIN{IGNORECASE=1}/^x-waf-rule-id:/{print $2}' | tr -d '\r')
  classes=${rule#detector:}
  printf "  %-22s status=%s classes=%s\n" "$label" "$s" "${classes:-(none)}"
  # Assertions:
  #   1. status MUST be 403.
  #   2. `classes` MUST contain `$expect` as a comma-separated token.
  #   3. `classes` MUST NOT contain `ssrf` UNLESS expect == "ssrf"
  #      (catches the SSRF false-positive regression).
  #   4. No detector class appears twice in `classes`.
}
probe "sqli union"    "/?q=UNION+SELECT+null,version()"  sqli
probe "sqli boolean"  "/login?u=admin'+OR+1=1--"         sqli
probe "xss script"    "/?q=<script>alert(1)</script>"    xss
probe "ptrav"         "/files?p=../../../../etc/passwd"  path_traversal
probe "ssrf imds"     "/fetch?url=http://169.254.169.254/" ssrf
probe "recon env"     "/.env"                            recon_path
probe "recon admin"   "/wp-admin"                        recon_path

# CLEAN baselines — these MUST NOT match.  If any return 403,
# file a CRITICAL false-positive finding.
probe "clean root"    "/"                                NONE
probe "clean api"     "/api/users/100"                   NONE
probe "clean fav"     "/favicon.ico"                     NONE
```

Browser equivalent (preferred when running in Cowork): from the
data-plane tab, fetch each path with `X-Forwarded-For` and read
the response header via `r.headers.get("x-waf-rule-id")`.

Any 200 on an attack probe, any 403 on a clean baseline, or any
`ssrf` tag on a non-SSRF probe → finding.

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

For Functional / Full QC modes, also include a per-page pass/fail
matrix:

```
Pages exercised (17): Overview ✓ · Live Feed ✓ · Incidents ✓ ·
Investigation ✗ (mounts:✗ — see crit-investigation-page-crash) ·
Top Attackers ✓ · Threat Intel ✓ · Rules ✓ · Detectors ✓ ·
Access Lists ✓ · Routing & Upstreams ✓ · Compliance ✓ ·
Performance ✓ · Health & SLOs ✓ · Audit Trail ✓ · Scaling ✓ ·
Settings ✓ · Reports ✓ · Help & Guide ✓
```

Plus an SOC-scenario score line:

```
SOC scenarios: S1=3 S2=2 S3=1 S4=4 S5=2 S6=- S7=- S8=- (- = not run)
```

Keep the headline summary under 8 lines; the matrix and scenario
scores can sit below it as separate blocks.

---

## Anti-patterns (don't do these)

- ❌ **Refusing to run because something is missing.** If pre-flight
  fails, OFFER the start commands. If repo is missing, run
  self-contained. The operator wants forward progress.
- ❌ **Trying to curl the WAF from sandbox bash in a Cowork
  session.** It won't reach the operator's host loopback. Use
  Claude in Chrome.
- ❌ **Fabricating browser interactions** when no browser tool
  is loaded. Note the gap, fall back to curl, keep going.
- ❌ **Filing CRITICAL on documented limitations** (e.g. AI
  detector empty when no `.onnx` is configured). Read
  `Implement-Progress.md`'s carry-over list when the repo is
  available; otherwise default to LOW / INFO for anything
  ambiguous.
- ❌ **Skipping a page because "it looks fine" from a screenshot.**
  Click every control; screenshots only catch missing data, not
  broken handlers.
- ❌ **Trusting the URL hash as proof of navigation.** A page can
  rewrite the hash without remounting (the Top-Attackers Pivot
  bug did exactly this). Always confirm the page H1 changed.
- ❌ **Reading API response shapes from this SKILL.md** when they
  contradict the live response. The skill drifts; the API is
  truth. File a LOW skill-drift finding when they disagree.
- ❌ **Editing the WAF source code.** You're a tester. Fixes are
  suggestions in the finding write-up, not commits.
- ❌ **Reporting "tests passed" without enumerating what you ran.**
  Always emit the per-page matrix and SOC-scenario scores in the
  summary block.
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
