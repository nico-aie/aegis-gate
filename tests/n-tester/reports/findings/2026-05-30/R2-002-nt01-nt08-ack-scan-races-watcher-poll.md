---
id: 2026-05-30-nt01-nt08-ack-scan-races-watcher-poll
date: 2026-05-30T20:30Z
severity: HIGH
area: docs
component: tests/n-tester/nt-01, tests/n-tester/nt-08
status: open
test_mode: full-qc
---

# NT-01 / NT-08 race the watcher poll interval — fail on a working cluster

## Summary

Both tests check for per-node ACK keys (`config:waf:applied:<node>`)
*immediately* after `wait_for converged_on_b 10` returns. They fail
with `expected ≥ 2 ACK keys, got 0` on every clean run.

But the product mechanism is sound: a live probe on a manually
running cluster shows both `applied:waf-a=v` and `applied:waf-b=v`
keys land within ~5 s of a PUT, refreshed every poll (TTL=29 s,
poll=3 s).

The test's mistake: `/api/config` reads `config:waf:doc` from Redis
directly, so `converged_on_b` passes in milliseconds — long before
the per-node watcher loop's next 3-second tick fires. The ACK scan
then runs in the window between "doc is live" and "watcher has
re-polled and called `record_applied`".

## Repro

```sh
cd /Users/nico/waf-code/aegis-gate
docker exec aegis-cluster-redis sh -c \
  'redis-cli --scan --pattern "config:waf:*" | xargs -r redis-cli DEL'
./target/release/waf run --config config/cluster-a.yaml > /tmp/a.log 2>&1 &
./target/release/waf run --config config/cluster-b.yaml > /tmp/b.log 2>&1 &
sleep 3

# Login + PUT
J=$(mktemp)
curl -s -c "$J" -X POST -H 'content-type: application/json' \
  -d '{"user":"admin","password":"aegis-test-1234"}' \
  http://127.0.0.1:9443/admin/login >/dev/null
CSRF=$(awk -F'\t' '/aegis_csrf/{print $NF}' "$J")
curl -s -b "$J" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -X PUT -d '{"scrub_stack_traces": false}' \
  http://127.0.0.1:9443/api/response-filter > /dev/null

# Immediately scan ACKs — like nt-01 does
docker exec aegis-cluster-redis redis-cli --scan --pattern 'config:waf:applied:*'
# → (often empty within the first ~3 s)

sleep 5
docker exec aegis-cluster-redis redis-cli --scan --pattern 'config:waf:applied:*'
# → config:waf:applied:waf-a
#   config:waf:applied:waf-b
```

## Expected

After PUT + ≤ one poll interval (~3.5 s), both nodes have written
their ACK keys.

## Actual

Mechanism works. The test scans too early.

## Suggested fix

Replace the bare `acks=$(...)` block in nt-01 (and nt-08) with a
`wait_for`:

```sh
acks_present() {
  local n
  n="$(docker exec "$AEGIS_REDIS_NAME" redis-cli --no-raw \
        --scan --pattern 'config:waf:applied:*' | wc -l | tr -d ' ')"
  (( n >= 2 ))
}
wait_for acks_present 10 \
  || fail "expected ≥ 2 ACK keys after 10s, still missing"
```

This matches the test's own pattern for `converged_on_b` and gives
the watcher time to land its first tick after PUT.

## Severity rationale

HIGH because it makes a green build look red — 2 of the 9 FAILs in
the Round-2 suite trace to this. Not a product regression, so not
CRITICAL.
