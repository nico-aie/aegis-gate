# Aegis-Gate — Round-2 Regression Suite (`r2-regression`)

A self-evaluation test set + bash runner for the Aegis-Gate WAF ahead of hackathon
round 2. It mimics what the committee is likely to send through our WAF — realistic
**benign** NovaBet traffic that must pass, plus **attack** traffic that must be
blocked/flagged — with heavy coverage of the round-2 detector surfaces
(**WebSocket, JWT, response caching**) on top of the standard web attack classes.

> All attack payloads are for testing **our own WAF locally**. Nothing here is meant
> to be fired at the committee's upstream. The live site was only mapped
> non-destructively (spec fetch + reading the client JS). See `recon/RECON-SUMMARY.md`.

---

## Layout

```
r2-regression/
├── README.md                  ← this file
├── recon/RECON-SUMMARY.md     ← Phase 1 (log analysis) + Phase 2 (live recon) + gap analysis
├── run.sh                     ← bash runner (curl + jq). Run a class, several, or all.
├── lib/ws_probe.py            ← OPTIONAL helper for WebSocket *frame* cases (auto-detected)
├── gen/generate.py            ← one-time authoring tool that (re)builds cases/  (Python)
├── cases/                     ← committed JSON test set, one folder per class
│   ├── manifest.json
│   ├── benign-baseline/cases.json
│   ├── injection-sqli/cases.json
│   ├── injection-cmdi/cases.json
│   ├── injection-nosql/cases.json
│   ├── xss/cases.json
│   ├── path-traversal/cases.json
│   ├── ssrf/cases.json
│   ├── auth-jwt/cases.json
│   ├── websocket/cases.json
│   ├── sse/cases.json
│   ├── caching/cases.json
│   ├── cors/cases.json
│   ├── rate-limit/cases.json
│   └── protocol/cases.json
└── reports/                   ← per-run output (jsonl + summary.json), created on first run
```

**1,159 cases / 14 classes** (1,037 attack · 122 benign). New-surface weighting:
WebSocket 322 · SSE 92 · caching 33 · auth-jwt 61. Live counts: `bash run.sh --list`.

Because `cases/` is committed JSON, the runner needs only **bash + curl + jq** at run
time. Python is required *only* to regenerate the set or to drive WebSocket frame cases.

---

## Quick start

```sh
# point at your locally-running WAF data plane (waf.yaml default listener)
export WAF_BASE_URL=http://localhost:8080

bash run.sh                      # whole suite
bash run.sh injection-sqli       # one class (folder name)
bash run.sh websocket sse xss    # several classes
bash run.sh --file cases/caching/cases.json
bash run.sh --all --verbose      # show every PASS line, not just FAILs
bash run.sh --list               # list classes + counts, run nothing
```

Exit code is **0** only when there are zero false-negatives *and* zero false-positives.

### Useful env / flags

| Env / flag | Default | Meaning |
|---|---|---|
| `WAF_BASE_URL` / `--base-url URL` | `http://localhost:8080` | WAF data-plane endpoint under test |
| `AEGIS_SID` / `--sid VALUE` | `regression-dummy-sid` | cookie used for `auth:session` cases |
| `--login` | off | attempt the real `/login`+`/otp` flow (alice) to get a live `sid` |
| `AEGIS_TIMEOUT` | `7` | per-request curl timeout (s) |
| `AEGIS_MAX_REPEAT` | `40` | cap on burst size for rate-limit cases (courtesy throttle) |
| `--verbose` / `-v` | off | print PASS lines too |
| `--only-fp` | off | quieter; focus output on failures |

---

## How a verdict is decided

The runner reads the **always-on `X-WAF-*` response headers** (stamped on every WAF
response — see `crates/aegis-control/src/interop/headers.rs`), in order:

1. **`X-WAF-Action`** → `allow` / `block` / `challenge` / `rate_limit` / `timeout` /
   `circuit_breaker` (authoritative; `rate_limit` collapses into `challenge`,
   `timeout`/`circuit_breaker` count as not-passed).
2. **`X-Aegis-Decision`** — the gated diagnostic header, only present with a bench
   token; used as a fallback if `X-WAF-Action` is somehow absent.
3. Fallback by status: `403`/`413` → block, `429` → challenge, `101`/`2xx`/`3xx`/`401`/`404`
   → allow (passed through), `000` → error.
4. **`400` with no `X-WAF-*` headers → `rejected`** — hyper rejected the request framing
   *before* the WAF ran (usually a raw space/control byte in the URI). Bucketed
   separately: not a WAF miss, but it doesn't exercise the WAF either.

Alongside the verdict, every case captures the rest of the `X-WAF-*` set —
`X-WAF-Rule-Id` (which rule/detector fired), `X-WAF-Risk-Score` (cumulative per-IP
risk), `X-WAF-Mode` (`enforce`/`log_only`), `X-WAF-Cache`, `X-WAF-Tier`, and
`X-WAF-Overhead-Latency` — and folds them into the report.

Comparison to the case's `expect.verdict`:

| Expected | Pass when actual is | Failure type if not |
|---|---|---|
| `allow` | `allow` | **false_positive** (benign traffic blocked) |
| `block` | `block` or `challenge` | **false_negative** (attack slipped through) |
| `challenge` | `challenge` or `block` | **false_negative** |

`skip` (non-executable cases) and `rejected` (pre-WAF 400s) are excluded from pass/fail
and from the detection-rate denominator.

The summary prints a per-class table and totals, and highlights **false negatives**
(attacks allowed) and **false positives** (benign blocked) — the two numbers that
matter for the contest score — plus an **`X-WAF-*` telemetry** block (mode, decision
mix, overhead percentiles, per-IP risk saturation).

Each run writes three files to `reports/`:

- **`run-<ts>.md`** + **`latest.md`** — human-readable analysis report: a **WAF posture**
  banner read from the headers (mode, decision mix, WAF overhead p50/p95, risk
  saturation warning); a **rule-attribution** rollup (`X-WAF-Rule-Id` counts — what
  actually fired); the per-class detection-rate table; **false-negatives inline**
  (id, method, path, **status, action, risk, rule**) with a *bypass-by-evasion-technique*
  breakdown; **false-positives inline** plus a *benign-blocks-by-firing-rule* rollup so
  you know which rule to tune; an errors section; and a **rejected (malformed framing)**
  section listing cases to URL-encode. This is the artifact to read after a run.
- **`run-<ts>.summary.json`** — machine summary (totals, FP/FN, detection_rate,
  `waf_actions`, `waf_modes`, `rule_fires`, `overhead_ms`, risk saturation) for CI.
- **`run-<ts>.jsonl`** — one record per case (id, class, method, path, expected, actual,
  kind, rule_id, tags, severity, source, **plus** `waf_action`, `waf_mode`, `http_status`,
  `risk_score`, `detector_score`, `tier`, `cache`, `latency_ms`, `request_id`) for ad-hoc
  `jq` analysis, e.g. `jq 'select(.kind=="false_negative")' reports/run-*.jsonl`.

---

## Case schema

Each `cases/<class>/cases.json` is a JSON array of case objects:

```jsonc
{
  "id": "sqli-0007",
  "class": "injection-sqli",          // == folder name
  "name": "short label",
  "description": "what this probes",
  "severity": "low|medium|high|critical",
  "source": "seed|generated|teammate-ws-dataset|hk-round-1",
  "tags": ["evasion:double-urlencode", "owasp:A03", "repeat:60"],
  "request": {
    "method": "GET|POST|PUT|OPTIONS|PROPFIND|…",
    "path": "/api/transactions?page=' OR 1=1--",  // literal target, sent --path-as-is
    "headers": { "Content-Type": "application/json" },
    "auth": "none|session",            // session => runner adds Cookie: sid=…
    "body": "{\"x\":1}",               // or null
    "body_b64": false,                  // true => body is base64 (multipart / gzip / binary)
    "execute": true                     // false => informational, runner SKIPs (e.g. DoS pattern)
  },
  "ws": {                               // present only for WebSocket frame cases
    "handshake_path": "/ws/live",
    "handshake_headers": { "Origin": "…", "Cookie": "sid=…", … },
    "frames": [ { "opcode": "text", "payload_b64": "…" } ],
    "handshake_only": false
  },
  "expect": { "verdict": "allow|block|challenge", "rule_id_contains": ["sqli"] }
}
```

### Notes on a few classes

- **websocket** — *handshake-only* cases (CSWSH origin, missing/tampered headers, upgrade
  on a protected path, host-header SSRF) are fully exercised by curl: the WAF decides at
  the handshake, so a `403`/`X-Aegis-Decision: block` is captured directly. *Frame* cases
  (injection / oversized) carry a `ws.frames` sequence and need the optional
  `lib/ws_probe.py` (`pip install websocket-client`); without it the runner marks them
  **SKIP**, not fail.
- **rate-limit** — cases tagged `repeat:N` are sent N times (capped at `AEGIS_MAX_REPEAT`);
  the verdict is `challenge` if any response in the burst is 429/blocked. DoS-*pattern*
  cases folded in from the teammate dataset are `execute:false` (you can't represent a
  flood as one request) and are **SKIP**ped/counted separately.
- **auth-jwt** — the real app is cookie-only, so these probe the WAF's Bearer/JWT detector
  with tokens the upstream never issues. Benign well-formed tokens are included as FP checks.
- **benign-baseline** — the false-positive backbone: realistic logins, deposits, bets,
  paginated reads, multipart KYC, gzip analytics, CORS preflight, conditional GETs, i18n
  names, and prose containing SQL/HTML-looking words (`select`, `drop`, `O'Brien`).

---

## Local smoke test (verify the harness end-to-end)

Run the suite against your WAF once it's up. A handy one-liner to sanity-check the
runner itself with a throwaway echo server (returns block for obviously-bad requests):

```sh
# in one shell – tiny mock that emits X-Aegis-Decision
python3 - <<'PY' &
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
BAD = re.compile(r"(<script|onerror|union\s+select|or\s+1=1|etc/passwd|\.\./|%2e%2e|\$ne|169\.254|alg\"?:\s*\"?none|__control|evil\.com|%0d%0a)", re.I)
class H(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.0"
    def log_message(self,*a): pass
    def go(self):
        n=int(self.headers.get("content-length",0) or 0); b=self.rfile.read(n) if n else b""
        block=bool(BAD.search(self.path+str(self.headers)+b.decode("latin1","ignore"))) or "evil" in self.headers.get("Origin","")
        self.send_response(403 if block else 200)
        self.send_header("X-Aegis-Decision","block" if block else "allow")
        self.send_header("Content-Length","2"); self.end_headers()
        if self.command!="HEAD": self.wfile.write(b"OK")
    do_GET=do_POST=do_PUT=do_HEAD=do_OPTIONS=do_DELETE=do_PATCH=do_TRACE=lambda s:s.go()
ThreadingHTTPServer(("127.0.0.1",8088),H).serve_forever()
PY
WAF_BASE_URL=http://127.0.0.1:8088 bash run.sh injection-sqli xss
kill %1
```

Most SQLi/XSS cases should report **PASS** (blocked) and most benign cases **PASS**
(allowed); against the *real* WAF the FP/FN numbers are your actual regression signal.

---

## Regenerating the set

```sh
python3 gen/generate.py          # rewrites cases/*/cases.json deterministically (seed=20260613)
```

Edit the payload banks / targets in `gen/generate.py` to add variants. The generator
folds a fresh sample from `../websocket_attack_samples.json` (the teammate WS dataset)
into `websocket/`, `sse/`, and `rate-limit/` each run.
