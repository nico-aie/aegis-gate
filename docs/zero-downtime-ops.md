# Zero-Downtime Operations (v2, new)

> **New in v2.** SO_REUSEPORT worker model, graceful drain on shutdown,
> hot binary reload via listener-FD handoff, and dry-run config
> validation before any swap.

## Purpose

Restart, upgrade, and reconfigure the WAF without dropping connections,
losing in-flight requests, or exposing a brief unprotected window to
attackers.

## Worker model

A supervisor process binds the listener(s) once. Workers accept
connections via `SO_REUSEPORT`:

- N worker tasks per CPU (configurable)
- Kernel-level load balancing across workers
- Each worker owns its own `tokio` runtime or shares one (configurable)
- Workers are isolated — a panic in one doesn't affect the others
  (caught at the task boundary)

```yaml
workers:
  count: auto             # auto = num_cpus
  runtime: shared         # shared | per_worker
  reuse_port: true
  nice: 0
```

## Graceful drain

On `SIGTERM` or explicit admin drain:

1. Supervisor stops accepting new connections
2. Running tasks finish in-flight requests
3. In-flight counter is tracked via a `tokio::sync::watch`
4. When the counter hits zero OR `drain_timeout` expires, the worker
   exits
5. Remaining in-flight is aborted at the deadline with a `503 + Retry-After`

Health probe returns `503` immediately on drain start so load balancers
bleed traffic away ahead of connection close.

## Hot binary reload

Inspired by nginx's master/worker upgrade:

1. New binary is started with `--inherit-fds`
2. Supervisor passes the listener FD(s) via `SCM_RIGHTS` (unix) or
   Windows handle duplication
3. New process binds to the same FD and starts accepting
4. Old process transitions to drain
5. On success, old process exits; on failure, it resumes accepting
   (rollback)

```yaml
hot_reload:
  socket: "/run/waf.sock"
  drain_timeout_s: 60
  rollback_on_healthz_fail: true
```

## Dry-run config validation

Every config reload — file, Git pull, admin API — runs the dry-run
compile+validate from [`config-hot-reload.md`](./config-hot-reload.md)
before the atomic swap. Bad configs never touch the running process.

## Cert reload

File-watcher reloads certs atomically via the `ArcSwap<CertStore>` in
[`tls-termination.md`](./tls-termination.md). In-flight handshakes
finish on the old cert; new ones pick up the new cert. No connection
drops.

## Rolling fleet upgrades

Recommended pattern for multi-node deployments:

1. Drain node A from the external LB
2. Hot-reload binary on node A
3. Wait for `/healthz/ready` to return 200
4. Reinstate in LB
5. Repeat for nodes B, C, …

The clustered state backend (see [`ha-clustering.md`](./ha-clustering.md))
ensures blocks, counters, and challenge nonces survive the rollout.

## Configuration

```yaml
lifecycle:
  graceful_shutdown_timeout_s: 60
  drain_on_sigterm: true
  drain_reports_not_ready: true
  hot_reload:
    enabled: true
    socket: "/run/waf.sock"
  workers:
    count: auto
    reuse_port: true
```

## Implementation

- `src/supervisor/mod.rs` — main loop, signal handlers, FD inheritance
- `src/supervisor/workers.rs` — worker pool with SO_REUSEPORT
- `src/supervisor/drain.rs` — in-flight tracker + deadline
- `src/supervisor/hot_reload.rs` — SCM_RIGHTS handoff

## Performance notes

- SO_REUSEPORT spreads `accept()` across workers in kernel, no
  userspace contention
- In-flight counter is a single atomic; drain check is wait-free
- Hot reload has a sub-100ms overlap window where both processes
  accept connections; no unprotected gap
