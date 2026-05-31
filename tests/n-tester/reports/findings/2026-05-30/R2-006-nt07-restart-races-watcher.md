---
id: 2026-05-30-nt07-restart-races-watcher
date: 2026-05-30T20:30Z
severity: HIGH
area: docs
component: tests/n-tester/nt-07-ai-confidence-persists
status: open
test_mode: full-qc
---

# NT-07 reads the restarted node before its watcher has applied the cluster doc

## Summary

NT-07 fails with `pre-restart value mismatch: 0.8500000238418579 vs
0.42` — the restarted node returns the cfg-loaded default (0.85),
not the cluster doc value (0.42).

Sequence:

1. PUT `confidence_threshold = 0.42` on node A → activates new
   cluster doc.
2. `stop_node "$NODE_B_PID"`, then `start_node B`, then
   `wait_ready "$NODE_B_ADMIN"`.
3. Immediately read `/api/ai/confidence` on B.

`wait_ready` returns when `/healthz/ready` is 200 — which it is once
the redis state hydration completes (~3 ms per boot log). But the
config-plane watcher runs separately and hasn't necessarily polled
yet (poll interval 3 s); the live AI confidence reflects whatever
the boot YAML said — 0.85.

Same root cause as nt-01: the test confuses "node responding" with
"node converged to cluster doc".

## Repro

```sh
cd /Users/nico/waf-code/aegis-gate
bash tests/n-tester/nt-07-ai-confidence-persists.sh 2>&1 | tail -20
# → FAIL: pre-restart value mismatch: 0.8500000238418579 vs 0.42
```

## Expected

After PUT + restart + watcher tick, B reports the cluster doc
value.

## Actual

B reports its YAML default because the test doesn't wait for the
watcher to apply.

## Suggested fix

Wrap the `/api/ai/confidence` read in a `wait_for`:

```sh
b_at_target() {
  local v
  v="$(admin_get "$NODE_B_ADMIN" "/api/ai/confidence" \
       | jq -r '.confidence_threshold')"
  awk -v a="$v" -v b="$target" 'BEGIN{ exit !( (a+0) == (b+0) ) }'
}
wait_for b_at_target 10 \
  || fail "B did not converge to cluster doc value $target after restart"
```

(plus the same float-tolerance comparison the test already uses
elsewhere — `awk` numeric coercion handles `0.85` vs
`0.8500000238418579` correctly).

## Severity rationale

HIGH. The persistence assertion is one of the most important
contracts of the cluster config plane: "a config change survives
a restart". Marking it FAIL on a working system is misleading; if
it ever truly broke, this test's signal-to-noise is already shot.
