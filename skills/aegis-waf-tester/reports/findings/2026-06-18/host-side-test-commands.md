# Host-side test commands — run on your Mac, paste output back

These cover the four areas the Chrome-only QA session can't reach (they need
process/config control on the loopback host). Run each in a terminal at the
repo root with the dev WAF already up (`make run-dev`). Paste the marked
output back and I'll fold it into the compliance report.

Vars used below:
```bash
A=http://127.0.0.1:8080
SECRET="waf-hackathon-2026-ctrl"
```

---

## 1. Config hot-reload (Cat F / Cat D — Official Rules §5.4, MANDATORY)

The reload watcher (`notify + ArcSwap`) has a history of being gated behind
runtime plumbing — so the point of this test is to confirm it's actually LIVE.

```bash
# baseline: recon path should block in enforce
curl -s -o /dev/null -w "before=%{http_code}\n" -H "X-Forwarded-For: 8.8.8.8" "$A/.env"

# flip a detector off in the live config and save
sed -n '/recon/,+3p' config/dev.yaml          # find the recon enabled flag first
#  -> edit config/dev.yaml: set the recon detector enabled: false  (save)

sleep 6
tail -5 waf_audit.log | grep -i config_reload   # EXPECT a config_reload event
curl -s -o /dev/null -w "after=%{http_code}\n" -H "X-Forwarded-For: 8.8.8.8" "$A/.env"
#  -> revert the edit, save, confirm a second config_reload + block returns
```
**PASS** = `config_reload` event appears AND data-plane behavior changes within
~5 s without a restart. **FAIL** (file a finding) = no event / no behavior change.
Paste: the two curl lines + the `grep config_reload` output.

---

## 2. Large-rule reload (Cat D4 — 1k / 5k / 10k rules)

```bash
gen() { python3 - "$1" <<'PY'
import sys,yaml,json
n=int(sys.argv[1]); rules=[{"id":f"r{i:05d}","match":{"path_prefix":f"/x{i}"},"action":"block"} for i in range(n)]
print(yaml.safe_dump({"rules":rules}))
PY
}
for N in 1000 5000 10000; do
  gen $N > /tmp/rules-$N.yaml
  /usr/bin/time -l ./waf validate --config config/dev.yaml 2>/dev/null  # adjust if rules live in a separate file
  echo "generated $N rules -> /tmp/rules-$N.yaml ($(wc -l </tmp/rules-$N.yaml) lines)"
done
```
Then apply each via your rule-management surface (Rules page / admin PUT) and
record: reload duration, peak RSS, CPU. **Verify:** no timeout, no crash, no OOM.
Paste: the `time -l` blocks + reload durations.

---

## 3. Repeated reload stress (Cat D8 — FD / thread leak)

```bash
PID=$(pgrep -f 'waf run')
echo "fd_before=$(lsof -p $PID | wc -l)  threads_before=$(ps -M $PID | wc -l)"
for i in $(seq 1 100); do
  curl -s -o /dev/null -X POST -H "X-Benchmark-Secret: $SECRET" -d '{}' "$A/__waf_control/reset_state"
  touch config/dev.yaml          # trigger a file-watch reload each iteration
  sleep 0.1
done
echo "fd_after=$(lsof -p $PID | wc -l)  threads_after=$(ps -M $PID | wc -l)"
ps -o rss= -p $PID                 # RSS should be flat, not climbing
```
**PASS** = FD count, thread count, and RSS stable (no monotonic climb).
Paste: the before/after lines + final RSS.

---

## 4. Formal benchmark — normal / mixed / attack (Cat H)

Needs k6 (`brew install k6`). Each run prints k6's RPS + p50/p95/p99.

```bash
make mock-load        DURATION=60s   # normal-ish mix (~50 RPS)
make mock-load-mix    DURATION=60s   # high-volume mix (~5k RPS)
make mock-load-attacks DURATION=60s  # 100% attack flood

# while each runs, in another shell sample WAF CPU/MEM:
PID=$(pgrep -f 'waf run'); while true; do ps -o %cpu=,rss= -p $PID; sleep 2; done
# and pull WAF-side latency after each:
curl -s -b /tmp/jar "http://127.0.0.1:9443/api/analytics/latency" | jq '.stages.total'
```
Collect per scenario: RPS, P50, P95, P99, CPU%, RSS, error rate. Compare against
the baseline in `tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`.
Paste: the k6 summary tables + the CPU/RSS samples.

---

## 5. (Optional) Long-running stability (Cat M — 30–60 min)

```bash
make mock-load-mix DURATION=45m &
PID=$(pgrep -f 'waf run')
while kill -0 $PID 2>/dev/null; do date +%T; ps -o %cpu=,rss= -p $PID; sleep 60; done > /tmp/stability.log
```
**PASS** = CPU trend flat, RSS trend flat (no leak), latency steady. Paste the
first and last ~5 lines of `/tmp/stability.log`.
