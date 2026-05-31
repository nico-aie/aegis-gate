---
id: 2026-05-30-start-cluster-no-port-conflict-check
date: 2026-05-30T20:30Z
severity: MEDIUM
area: docs
component: tests/n-tester/_common.sh::start_cluster
status: open
test_mode: full-qc
---

# `start_cluster` silently runs against a squatting cluster when ports are already bound

## Summary

`_common.sh::start_cluster` does not verify that ports 9443, 9543,
8080, 8090 are free before spawning Nodes A and B. If a previous
cluster (or an unrelated process) is already on those ports, the
test's own `waf run` invocations fail to bind and exit immediately.

The fail is invisible:

- `start_node` captures `LAST_NODE_PID=$!` BEFORE the WAF has had
  time to fail-bind, so the PID exists for an instant.
- `wait_ready` then GETs `/healthz/ready`, which returns 200 —
  served by the *squatting* cluster, not the test's WAF (which is
  already dead).
- The test believes its cluster is up and proceeds. Every
  subsequent assertion talks to the squatter.
- Then `reset_redis_config_plane` wipes `config:waf:*` in Redis —
  not the test's keyspace (there is none) but the squatter's
  config-plane state. The squatter's running watcher sees
  `Ok(None)` and goes idle.

I caught this today: my manually-started cluster (the one used
for the live-probe diagnostic) was still bound to 9443/9543 when
`tests/n-tester/run-all.sh` started. The first 9/12 fails in
that run were partly squatter-corruption. Killing the manual
cluster and re-running flipped nt-12 from FAIL to PASS but the
test-design bugs (R2-002, R2-003, R2-006) still surfaced.

## Repro

```sh
# Operator-side
./target/release/waf run --config config/cluster-a.yaml > /tmp/a.log 2>&1 &
./target/release/waf run --config config/cluster-b.yaml > /tmp/b.log 2>&1 &
sleep 2

# Run any nt-* test
bash tests/n-tester/nt-01-clu-config-plane-converge.sh
# → fails with weird symptoms; the test never realized its own waf binary
#   couldn't bind.

# Cleanup
pkill -f 'target/release/waf'
```

## Expected

`start_cluster` checks ports are free up front; if not, fails with
`fail "port 9443 already bound — kill the holder before running"`.
That single sentence saves an operator 30 minutes of confusion.

## Actual

Silently steals the existing cluster, wipes its Redis state, then
runs tests against a half-broken target.

## Suggested fix

In `_common.sh` add at the top of `start_cluster`:

```sh
for port in 9443 9543 8080 8090; do
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    fail "port $port already in use — stop the squatting process \
(probably a prior \`waf run\`) before starting the test cluster"
  fi
done
```

For extra safety, after `start_node`, give it a moment then verify
its PID is still alive (`kill -0 $LAST_NODE_PID`); if not, dump the
node log tail and fail.

## Severity rationale

MEDIUM. Doesn't break a green run, but during debugging it can
direct attention to the wrong cause (as it did today). HIGH for any
operator running the suite for the first time without realizing they
have a stale cluster in another terminal.
