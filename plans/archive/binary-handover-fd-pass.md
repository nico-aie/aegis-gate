# B6-T5 — Binary Handover via FD-Passing

> **Status:** ✅ FDP-T1..T6 shipped. Track ID prefix
> `FDP-T<n>`. The library primitives are landed and tested;
> SIGUSR2 listening + parent-to-child readiness signalling are
> wired into the live boot path. The final accept-loop drain
> + handover-trigger glue (the `polling loop` referenced in
> §4) is the one remaining gap: SIGUSR2 sets the reloader
> flag today but the `perform_handover` invocation needs an
> accept-loop refactor that's a separate track. Operators
> get clean adopt-or-bind on first boot today; full hot-
> restart lands when the accept-loop refactor closes.

## 0 · One-line summary

On SIGUSR2 the running `waf` process `exec`s a new binary,
passing live listen-FDs (admin :9443, data :8080, data-TLS
:8443, etc.) through inherited file descriptors so the new
process accepts on the same kernel listen queues without ever
having an unbound second.

## 1 · Why FD-pass, not SO_REUSEPORT alone

Three candidates considered:

| Candidate | How | Verdict |
|---|---|---|
| **A. FD-pass via `exec`** | Old proc forks/execs new binary, leaks listen-FDs into slots 3..N. New proc adopts via `from_raw_fd`. Both procs share the SAME kernel listen queue during handover. | **Pick.** Same primitive nginx + envoy + h2o use; battle-tested kernel path. |
| **B. SO_REUSEPORT-only** | Both old + new procs `bind` the same address with `SO_REUSEPORT`. Kernel hashes new connections across the per-process queues. | Reject. **Two distinct queues during handover** — connections accepted by either proc finish on that proc, but distribution is round-robin kernel-decided which makes drain timing unpredictable. Also a tiny race: parent socket closes between child bind and parent unbind → kernel can reject SYNs on the parent's queue if ACCEPT is already paused. |
| **C. systemd socket activation** | systemd holds the listen sockets across restarts; service unit gets fresh FDs each boot. | Reject for the in-process path. Useful as an *additional* mode (operators on systemd-managed deployments would already get this for free); fold into FDP-T6 below as a compat wrapper. |

The fundamental property we want — **no SYN ever lands on a
queue with no one accepting** — only A delivers in the general
case. SO_REUSEPORT loses it whenever the parent's accept loop
exits before the kernel has retargeted the listen-tuple.

## 2 · Lifecycle

```
operator                    parent (waf v1)              child (waf v2)
   │                              │                            │
   │ kill -USR2 <pid>             │                            │
   ├─────────────────────────────►│                            │
   │                              │                            │
   │                              │ HotReloader::signal()      │
   │                              │ → take_signal()            │
   │                              │ build env: AEGIS_LISTEN_FDS=N
   │                              │            AEGIS_LISTEN_FD_NAMES=admin,data,data-tls
   │                              │ fork+exec /proc/self/exe   │
   │                              │ ─────────────────────────► │ start
   │                              │ → state = Pending          │ inherit FDs 3..3+N
   │                              │                            │ TcpListener::from_std
   │                              │                            │ build runtime
   │                              │                            │ start accept loops
   │                              │                            │ /healthz/ready advertises
   │                              │ poll child readiness       │
   │                              │ ◄──────── ready ────────── │
   │                              │                            │
   │                              │ → state = Draining         │
   │                              │ stop accept loops          │ accepts new conns
   │                              │ in-flight conns finish     │
   │                              │ wait grace_period          │
   │                              │ exit 0                     │
   │                              │                            │
   │                              │                            │ continues...
   │                              │                            │
```

If the child's `/healthz/ready` doesn't return 200 within
`reload.readiness_timeout` (default 30s), the parent kills the
child and transitions back to `state = RolledBack`, resuming
its own accept loops. Operators see a stuck deploy in metrics +
audit, never a dropped connection.

## 3 · Inherited-FD layout

The parent sets two env vars before `exec`:

```
AEGIS_LISTEN_FDS=4
AEGIS_LISTEN_FD_NAMES=admin,data,data-tls,force-https
```

The N FDs land in slots `3..3+N`. The names list (comma-
separated, same order as the FD slots) tells the child which
listener each FD is. The child's boot path:

```rust
fn adopt_inherited_listeners() -> Option<HashMap<String, std::net::TcpListener>> {
    let n = hotbin::inherited_fd_count()?;
    let names = std::env::var("AEGIS_LISTEN_FD_NAMES").ok()?;
    let names: Vec<&str> = names.split(',').collect();
    if names.len() != n {
        tracing::error!(
            "AEGIS_LISTEN_FD_NAMES count {} != AEGIS_LISTEN_FDS {}",
            names.len(), n,
        );
        return None;  // fall through to fresh bind
    }
    let mut out = HashMap::new();
    for (i, name) in names.iter().enumerate() {
        let fd = (3 + i) as RawFd;
        // SAFETY: kernel passed us this FD via exec inheritance.
        // We're the only owner from here forward.
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true).ok()?;
        out.insert((*name).to_string(), std_listener);
    }
    Some(out)
}
```

Each call site that today does `TcpListener::bind(addr)`
becomes:

```rust
let listener = match inherited.remove("admin") {
    Some(std_l) => tokio::net::TcpListener::from_std(std_l)?,
    None => tokio::net::TcpListener::bind(admin_addr).await?,
};
```

That's the only change at every bind site — fresh bind stays
the default path; FD-adopt is the opt-in for the hot-handover
case.

## 4 · Handover protocol details

### Parent side — pre-exec

1. **Capture the live listener FDs**: the boot path stashed
   `Arc<TcpListener>` instances (admin, data, data-tls,
   force-https). Convert each to `RawFd` via `as_raw_fd()`;
   keep the `Arc` alive until the child is `Pending` so the
   parent's reference doesn't drop the underlying fd.
2. **Prepare CLOEXEC clearance**: tokio's `TcpListener` may
   set `O_CLOEXEC` on the underlying FD. Before exec, clear it
   with `fcntl(fd, F_SETFD, fd & !FD_CLOEXEC)`. Otherwise the
   child sees no inherited FDs.
3. **Build env**: `AEGIS_LISTEN_FDS=N` + `AEGIS_LISTEN_FD_NAMES=...`
   in the comma-order matching slots 3..3+N.
4. **fork+exec**: `Command::new("/proc/self/exe").args(...)`.
   On platforms without `/proc` (macOS), use the path captured
   from `std::env::current_exe()` at boot.

### Parent side — post-exec, awaiting child readiness

1. Spawn a polling task: every 500ms, hit
   `http://127.0.0.1:<admin>/healthz/ready` against the live
   admin port. The child binds nothing new — it's serving on
   the same FD the parent shares — so the response comes from
   whichever process accept'd the SYN first. Once the child is
   running its own accept loop, ~50% of probes hit the child;
   we just need ONE 200 to signal readiness.
   - **Race-free alternative**: the child writes a single byte
     to a pipe FD passed alongside the listeners (slot
     `3+N`). Parent reads → child is ready. No HTTP probe
     needed. Recommended; HTTP probe is the fallback.
2. Move state `Pending → Draining`.

### Parent side — drain

1. Drop the parent's accept-loop tasks (or signal them via a
   shared `AtomicBool` to break their loops). The
   `TcpListener` is shared with the child via FD; closing
   the parent's tokio handle just removes one reference.
2. Wait `drain_grace_seconds` (default 30s) for in-flight
   requests + tunnels to complete. Track in-flight count
   via a shared `AtomicUsize` incremented on accept and
   decremented on response-write-complete.
3. When in-flight reaches 0 OR the grace expires, call
   `std::process::exit(0)`. The remaining (still-spawned)
   tasks die with the process — their connections were
   already past the deadline.

### Child side — boot

1. `inherited_fd_count()` → Some(N). Adopt the N listeners.
2. Skip the `TcpListener::bind` calls for any listener whose
   name was inherited. Fresh-bind the rest (none, in the
   typical case).
3. Run the rest of the boot path normally — config load,
   detector mask, audit bus, etc.
4. Once the accept loops are running, signal the parent:
   write 1 byte to the pipe FD from §4.1.

## 5 · Failure modes + mitigations

| Mode | Detection | Action |
|---|---|---|
| Child's binary is broken (exec fails) | Parent's `Command::spawn` returns Err | `state = RolledBack`; parent resumes; emit `binary_handover_exec_failed` audit |
| Child boots but fails readiness | Parent's polling timeout | `kill -KILL <child>`; resume; emit `binary_handover_readiness_failed` audit |
| Child boots but its config is invalid | Child's own validation fails before accept loops start; child exits non-zero | Parent sees child exit code; same path as readiness failure |
| Parent OOM during drain | Kernel kills parent; child still owns the FDs | No drop — child accepts everything from now on. Audit gap on parent's tail. |
| Both procs deadlock on shared resource | n/a (in scope: nothing is shared except the FDs) | n/a |
| Audit chain reset across hot-restart | Operator reads `/api/audit` and sees sequence-number reset to 0 | Document. Persist-chain-across-restart is a separate track (FDP-T7) |

## 6 · Implementation slices

| Slice | Scope | Estimate |
|---|---|---|
| **FDP-T1** | `hotbin::adopt_inherited_listeners()` — pure FD-adopt logic + real-kernel test | ✅ `6d98c5d` |
| **FDP-T2** | Wire `adopt_or_bind` into `run.rs` at every bind site | ✅ `d2bc935` |
| **FDP-T3** | `spawn_successor` with FD pre-placement + CLOEXEC clear | ✅ `24a9f9f` |
| **FDP-T4** | Drain protocol: `InFlightCounter` + `perform_handover` orchestration | ✅ `de63985` |
| **FDP-T5** | Pipe-based readiness signal (single-byte) | ✅ `827b144` |
| **FDP-T6** | systemd `LISTEN_FDS` / `LISTEN_FDNAMES` compat (with colon-separator support) + SIGUSR2 listener wired into boot path | ✅ this commit |
| **FDP-T7** | Persist audit-chain state across handover (separate track, here for completeness — *not* in this design). | (deferred) |

26 tests total across FDP-T1..T6.

**One gap remains** — the accept-loop drain refactor. Today's
wiring records the SIGUSR2 in `HotReloader` but doesn't invoke
`perform_handover` because the accept loops don't yet accept a
shutdown channel + the shared `InFlightCounter`. Library
primitives are all proven correct in tests; the refactor to
wire them into a live SIGUSR2-driven handover is its own
track. Operators get clean adopt-or-bind on first boot today;
full hot-restart lands when the accept-loop refactor closes.

## 7 · Test plan

| Layer | Test | Outcome |
|---|---|---|
| Unit | `inherited_fd_count_parses_env` | Some(N) when set, None otherwise |
| Unit | `adopt_listeners_with_mismatched_names_falls_back` | Returns None when name count ≠ FD count |
| Integration | `child_adopts_socketpair_fd_and_accepts` | Spawn a child via Command + FD inheritance, send a connection through, child responds |
| Integration | `parent_drains_inflight_requests_within_grace` | Open N long-running requests, send SIGUSR2, kill the child fork, assert all N requests complete on the parent |
| Integration | `child_readiness_failure_triggers_rollback` | Child exits 1 immediately; parent must resume accepting (same connection that was queued lands on parent post-rollback) |
| Integration | `connect_tunnels_finish_on_old_proc_after_handover` | Open a CONNECT tunnel via TCP-T3, send SIGUSR2, assert the tunnel keeps moving bytes for 5s past the handover signal |
| E2E | `tests/api/binary-handover.sh` | Drive a real `make run-dev` → `kill -USR2` → confirm `/healthz/ready` stays 200 throughout, no 5xx in metrics, audit chain has the `binary_handover_*` events |

## 8 · Audit shape

Two events per handover, sharing a generated `handover_id`:

```jsonc
{
  "action": "binary_handover_started",
  "rule_id": "handover_initiated",
  "fields": {
    "handover_id": "...",
    "old_pid": 12345,
    "new_pid": 12678,
    "fd_count": 4,
    "fd_names": ["admin", "data", "data-tls", "force-https"]
  }
}

{
  "action": "binary_handover_completed",
  "rule_id": "handover_drained",  // or "handover_rolled_back"
  "fields": {
    "handover_id": "...",
    "drain_duration_ms": 4200,
    "inflight_at_signal": 17,
    "inflight_at_exit": 0,
    "outcome": "drained"  // or "rolled_back" / "drain_timeout"
  }
}
```

## 9 · Out of scope (deferred to FDP-T7)

- **Audit-chain persistence across handover.** Today the chain
  is in-memory; new binary starts a fresh chain. Operators
  reading `/api/audit/since` across a handover see a sequence-
  number reset. Persist-to-disk is a separate track because
  the chain layer needs an `AsyncWrite` plumbing pass.
- **Cross-handover state-store warmup.** Redis-backed state is
  fine (both procs read the same keys). In-memory state
  (rate-limit counters, risk strikes) resets — operators get
  a brief window where blocked sources can retry.
- **Windows support.** Windows has no `fcntl` / `O_CLOEXEC`
  / `fork+exec` semantics; the equivalent is `DuplicateHandle`
  + `CreateProcess`. Linux + macOS are the supported
  deployment surface; Windows is a future track.

## 10 · Operator footguns (designed-out)

- **CLOEXEC leak**: O_CLOEXEC defaults vary by tokio version.
  Pre-exec we explicitly clear it; if we miss one FD, the
  child exits 1 with a clear error rather than half-handing-
  over. (FDP-T3 owns the assertion.)
- **Stale env vars**: if the operator manually `unset`s
  `AEGIS_LISTEN_FDS` between exec calls, the child fresh-binds
  — likely fails because the parent still owns the FD on the
  same port. Document the env-var contract.
- **Multiple SIGUSR2 in flight**: if a second SIGUSR2 arrives
  while `state == Pending`, ignore it. The HotReloader's state
  mutex enforces this.
- **Chained handovers (v1 → v2 → v3 quickly)**: each handover
  is a clean exec, so chaining works as long as each child
  passes readiness. No special-case logic needed.

## 11 · Done-when

- `cargo test -p aegis-proxy hotbin::` passes with the FDP-T*
  tests.
- `tests/api/binary-handover.sh` drives a real `make run-dev`
  through SIGUSR2 with no observed 5xx + no dropped
  connections.
- `docs/control-plane/zero-downtime-ops.md` flips its banner
  from **Partial** → **Implemented**.
- `Implement-Progress.md` flips B6-T5 from "deferred" →
  "shipped" with the implementation commit SHA.
- `plans/phase-b/README.md` B6-T5 row updated to closed.
