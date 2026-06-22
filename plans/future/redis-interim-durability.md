# Redis-backed interim durability — survive restart now, replace with ClickHouse/Postgres later

**Status:** Future / designed-only (no production code yet)
**Filed:** 2026-06-22
**Origin:** *"Control state and Analytics data are wiped on restart — should we
just store them in Redis for now, and do proper persistence later (as planned)?"*
This is the **interim, dependency-light** answer to the same gaps audited in
[`persistent-datastore-tracking-data.md`](./persistent-datastore-tracking-data.md):
reuse the Redis we already ship instead of standing up ClickHouse + Postgres today.
**Decision locked (2026-06-22):** **control state + small analytics counters →
durable Redis now; analytics rings/timeseries wait for ClickHouse.** Feature-gated
on the existing `redis` Cargo feature; with no Redis the behaviour is byte-for-byte
today's (in-memory only).
**Related:** [`persistent-datastore-tracking-data.md`](./persistent-datastore-tracking-data.md)
(the eventual ClickHouse+Postgres replacement — this doc is the bridge to it),
[`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md),
[`config-etcd-source-of-truth.md`](./config-etcd-source-of-truth.md),
[`config-auto-restore.md`](./config-auto-restore.md),
[[project_cache_l2_single_node]], [[project_config_plane_doc_vs_file]],
[[feedback_two_score_model]], [[project_health_signals_reported_not_gating]].

---

## 1. The reframe — "store it in Redis" is two pieces of work, not one

"Put it in Redis so it survives restart" only half-holds with what we ship today.
Two preconditions must be met or the work buys **nothing** on restart:

1. **Redis itself is not durable as shipped.** `deploy/redis/redis.conf:39-43`
   enables RDB and `deploy/compose/docker-compose.yml:16-24` runs
   `--appendonly yes`, **but neither shipped compose file mounts a volume on
   `/data`** (`docker-compose.dev.yml` declares only `etcd-data` / `grafana-data`).
   So RDB/AOF files live on the container's ephemeral layer and vanish on
   `docker compose down`. Helm doesn't provision Redis at all — it points at an
   external one (`deploy/helm/aegis-gate/values.yaml:65-73`). **A data volume (or
   a persistence-enabled managed Redis) is a hard prerequisite.**
2. **The hot `g:*` keyspace is deliberately wiped.** `/__waf_control/reset_state`
   clears `g:risk:*`, `g:block:*`, `g:nonce:*`, `g:rl:sw:*`, `g:rl:tb:*` via
   `reset_ephemeral`'s `EPHEMERAL_PATTERNS` (`crates/aegis-proxy/src/state/redis.rs:699-705`).
   Durable interim state must therefore live under the **`control:waf:*`**
   namespace (already exempt from reset, treated as the durable control plane),
   **not** under `g:*`.

Net: this plan = *write to a durable keyspace* **+** *make Redis durable*. Skip
either and restart still loses everything (a false sense of durability — the
HIGH risk below).

## 2. The hot-path question — the decisive split

The four restart-fragile surfaces fall into two write-frequency tiers, and **only
one touches the request hot path**:

| Surface | Write trigger | On hot path? | Structure / bound |
|---|---|---|---|
| **RiskTracker** strikes/trust (`aegis-security/src/risk/tracker.rs`) | **per request** (`aegis-proxy/src/data_plane.rs:766 / 1160 / 1380`) | **YES** | `DashMap`, `MAX_TRACKED_KEYS = 1_000_000` |
| Incidents ack/snooze/resolve/note (`aegis-control/src/api/incidents.rs`) | per admin action | No | `Mutex<HashMap>`, unbounded (low cardinality) |
| Attacks ring (`aegis-control/src/api/attacks.rs`) | per audit event, on bus **drain task** | No | `Mutex<VecDeque>`, 900 s **and** 1 M events |
| Stats aggregator (`aegis-control/src/api/stats.rs`) | per audit event, on bus **drain task** | No | `Mutex` over VecDeque/HashMap/BTreeMap |

**Performance posture (answers the explicit hot-path concern):**

- **RiskTracker is the only hot-path writer.** A synchronous per-request Redis
  write here would add network I/O to every request and break the documented
  sub-ms posture (`X-WAF-Overhead-Latency`, p99 ≤ 1 ms). **We do not do that.**
  Instead: mark slots dirty on write, and a **background task flushes dirty slots
  on an interval** + **hydrates on boot**. The request path stays `DashMap`-only →
  **zero added per-request latency.** (This is exactly the future plan's P2 stance:
  "DashMap stays the hot read cache; Redis/PG never the per-request lookup".)
- **Two distinct flush concerns — RiskTracker writes *a lot*:** because it mutates
  per request, the naïve flush would be high-volume. Both are designed out:
  - **Coalescing (temporal debounce):** the flush snapshots the *dirty set*, so a
    key written 500× within one interval flushes **once** with its latest value.
    Flush volume is bounded by **distinct dirty keys per interval, not request
    count** — this is the dominant saving.
  - **Batching (network):** the distinct dirty keys are written as **one pipelined
    / multi-field `HSET` per tick**, chunked into bounded batches (e.g. ≤500–1000
    fields per command) so a wide dirty set under attack doesn't become N
    round-trips or one giant Redis-blocking command. A per-tick field cap +
    overflow policy (**flush highest-strike slots first, defer the rest to the next
    tick**) bounds worst-case work — the same drop/shed contract the audit sinks
    use. (A DDoS with many distinct source IPs is the worst case; the
    `strikes>0`/above-threshold write filter in §4 already discards the clean
    long tail before it ever enters the dirty set.)
- **Incidents / attacks / stats are already off the request path** — fed from the
  single audit-bus drain task (`aegis-control/src/dashboard_services.rs:553-588`),
  or from rare admin handlers. The one caveat: attacks/stats writes run inside a
  single `std::sync::Mutex` on that one drain loop, so any Redis I/O must be done
  **outside the lock** (snapshot → release lock → write), or the drain stalls and
  the broadcast drops events (`Lagged`).
- **Graceful degradation reuses the existing pattern** — the `ReconcilingBackend`
  (`aegis-proxy/src/state/reconcile.rs`) already serves from an in-memory fallback
  when Redis is unreachable. Interim durability inherits the same fail-soft
  behaviour: Redis down ⇒ behaves exactly like today (state in-memory, lost on
  restart), never fail-closed on the data plane
  ([[project_health_signals_reported_not_gating]]).

## 3. Decision — what goes to Redis now, what waits

**Persist to durable Redis now (high value, zero/low hot-path cost):**

1. **Incidents** — tiny, off-path, per-admin-action. The cleanest win: operator
   ack/snooze/resolve/notes currently vanish on restart.
2. **RiskTracker strikes/trust** — the highest-value gap. The module advertises a
   "permanent block" that silently evaporates on restart; debounced flush +
   hydrate-on-boot restores that guarantee (the fail2ban/CrowdSec "relational
   store is system of record, enforcer reads the cache" pattern — here Redis
   stands in for the eventual Postgres).
3. **Small lifetime analytics counters only** — e.g. `StatsAggregator.blocks_total`
   (`aegis-control/src/api/stats.rs`) and any equivalent monotone totals, so the
   Overview top-line numbers survive restart. These are scalars, off-path, cheap.

**Do NOT put in Redis now (wrong tool — wait for ClickHouse):**

4. **Attacks ring + per-second stats timeseries.** This is OLAP/timeseries data
   (top-N attackers, per-second buckets, a 1 M-event ring up to ~200 MB).
   Reproducing it in Redis means hand-rolling rollups, holding hundreds of MB, and
   still getting no real range query — precisely the job ClickHouse owns in
   [`persistent-datastore-tracking-data.md`](./persistent-datastore-tracking-data.md)
   P1/P3 and [`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md).
   The in-memory live ring stays the live tier, unchanged; durable *history*
   arrives with ClickHouse, not Redis.

This split mirrors the future plan's tiering (control state → relational/durable
store; analytics firehose → ClickHouse) — we're just substituting Redis for
Postgres in the interim and persisting only counters, not the firehose.

## 4. Keyspace & reset semantics

All interim state under the durable, reset-exempt `control:waf:*` namespace
(sibling of `control:waf:modes` / `:reset_epoch`, defined in
`aegis-control/src/interop/cluster_sync.rs`):

- `control:waf:incidents` — hash, `alert_id → IncidentState` JSON.
- `control:waf:risk` — capped hash/sorted-set, `RiskKey → {score, strikes,
  last_seen}` JSON; only slots with `strikes > 0` or score above threshold are
  written (skip clean zero-value slots) so memory stays bounded under
  `MAX_TRACKED_KEYS`.
- `control:waf:stats:counters` — small hash of monotone totals (`blocks_total`, …).

**Reset consistency (MEDIUM risk if missed):** because this state is now durable,
the existing reset paths must also delete the durable copy, or stale strikes/
incidents resurrect on next boot:

- `/__waf_control/reset_state` → `RiskTracker::reset_all` (`tracker.rs:548-550`)
  and the attacks/stats `reset()` must `DEL` the matching `control:waf:*` keys.
- `PUT /api/risk/<ip>/reset` and operator key reset
  (`aegis-proxy/src/admin_mutate.rs:3670 / 3803`) must `HDEL` the per-key entry.

This is the inverse of the usual rule (`reset_ephemeral` leaves `control:waf:*`
alone): here we *opt these specific keys back into* the reset wipe to preserve
bench / denial-of-defense semantics ([[project_control_plane_loopback_only]]).

## 5. Phased plan

| Phase | Scope | Effort |
|---|---|---|
| **P0 — Durability foundation** (prerequisite, no behavior change) | Mount a Redis data volume in both shipped compose files; confirm RDB/AOF actually persists; document the persistence-enabled-managed-Redis expectation for Helm. Establish the `control:waf:*` interim keyspace + the reset-wiring contract in §4. Serialization helpers (`serde_json`) for the three value shapes. | **S** |
| **P1 — Incidents durability** (smallest; ship first) | Behind `IncidentTracker` (`api/incidents.rs`): write-through on `ack`/`snooze`/`resolve` (`incidents.rs:106 / 122 / 138`) to `control:waf:incidents`; load-on-boot into the existing `Mutex<HashMap>` (now a read cache). Feature-gated on `redis`; no-Redis path identical to today. | **S** |
| **P2 — RiskTracker durability** (hot-path-safe) | Dirty-flag slots in `record_*_with_key`; a background interval task (e.g. 1–5 s) snapshots the **dirty set** off the request path (temporal coalescing) and flushes to `control:waf:risk` via **pipelined / chunked multi-field `HSET`** (network batching, per-tick field cap, highest-strike-first overflow — §2), bounded per §4; hydrate on boot. Wire the reset paths in §4. Hot path stays `DashMap`-only — **no per-request I/O.** | **M** |
| **P3 — Analytics lifetime counters** | Persist only the small monotone totals (`blocks_total`, …) to `control:waf:stats:counters` from the drain task **outside the aggregator `Mutex`**; reload on boot. Rings/timeseries explicitly out of scope (ClickHouse). | **S** |
| **P4 — (deferred, not now)** | Attacks ring + timeseries history → ClickHouse, per [`persistent-datastore-tracking-data.md`](./persistent-datastore-tracking-data.md) P1/P3. This interim doc's write-through/load-on-boot seams are forward-compatible: Postgres later replaces the Redis backing for P1/P2 with no API change. | — |

**Start at P0+P1** — self-contained, smallest blast radius, closes the operator-
workflow durability gap. P2 is the independent high-value "permanent block
survives restart" win. P3 is a cheap nicety.

## 6. Non-goals / boundaries

- **Not** a per-request DB call — P2 is debounced/background; no new hot-path I/O.
- **Not** a replacement for the ClickHouse/Postgres plan — this is the bridge;
  the analytics firehose still waits for ClickHouse, and the eventual Postgres
  control-state store replaces the Redis backing here behind the same seams.
- **Not** moving the ephemeral `g:*` hot tier off Redis — rate limits, per-IP
  risk scores, nonces, leases stay ephemeral by design ([[feedback_two_score_model]]).
- **Not** changing fail-soft behaviour — Redis down ⇒ in-memory, never
  fail-closed on the data plane.

## 7. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Per-request Redis write stalls the hot path | **CRITICAL (avoided)** | P2 is debounced/background; request path stays `DashMap`-only. Verify with `X-WAF-Overhead-Latency` under load before/after. |
| False sense of durability (volume/keyspace skipped) | **HIGH** | P0 is a hard prerequisite — without the mounted volume **and** the `control:waf:*` keyspace, restart still loses everything. |
| Reset paths don't clear durable copy → stale strikes/incidents resurrect | MEDIUM | §4 reset-wiring contract: `reset_state` + per-IP reset also `DEL`/`HDEL` the `control:waf:*` keys. |
| Drain-loop stall from in-lock Redis I/O (P3) | MEDIUM | Snapshot under the `Mutex`, release, then write; never hold the lock across Redis I/O. |
| Redis unavailable | LOW | Reuse `ReconcilingBackend` fail-soft; degrade to today's in-memory behaviour. |
| RiskTracker flush write-amplification (per-request mutation → high flush volume) | MEDIUM | Temporal coalescing (dirty-set, one write per key per interval) + network batching (pipelined chunked `HSET`, per-tick field cap, highest-strike-first overflow) — §2. Worst case (DDoS, many distinct IPs) shed by the `strikes>0` write filter + per-tick cap. |
| Redis memory growth from risk keys | LOW | Persist only `strikes>0`/above-threshold slots, bounded by `MAX_TRACKED_KEYS`; TTL/idle-evict mirrors the in-mem `IDLE_TTL`. |

## 8. Wire-in points (already exist)

- **`StateBackend` trait** (`aegis-core/src/state.rs:134-253`) + `RedisBackend`
  (`aegis-proxy/src/state/redis.rs`) — reuse `get`/`set`/`del`/`incrby`/`scan_prefix`
  for the new `control:waf:*` keys; no new Redis client.
- **`control:waf:*` keyspace** — `aegis-control/src/interop/cluster_sync.rs`
  (`MODES_KEY` et al.) is the durable, reset-exempt convention to extend.
- **Mutation points** — incidents: `api/incidents.rs:106/122/138`; RiskTracker:
  `tracker.rs` `record_*_with_key`; counters: `api/stats.rs` drain via
  `dashboard_services.rs:758`. All small, localized.
- **Cargo feature** — gate on the existing `redis` feature
  (`crates/aegis-proxy/Cargo.toml:11` → `aegis-bin/Cargo.toml:17`); no new deps
  beyond `serde_json` (already in-tree).
- **Compose/Helm** — add the Redis data volume (P0); managed-Redis durability
  mirrors today's external-Redis posture.

## 9. DDoS / stress posture — persistence must never degrade enforcement

The governing invariant: **under load, durability is best-effort and strictly
subordinate to enforcement.** The WAF's DDoS protection lives in the in-memory
DashMap / rate-limit hot path; persistence is a background convenience that must
*yield* the moment it would compete for a shared resource. Concrete failure modes
and their designed-in answers:

1. **Shared Redis pool starvation (the sharp edge).** `RedisBackend` holds a
   *single* `deadpool` pool (default 16 conns, `state/redis.rs:275-297`) serving
   the hot `g:rl:*` / `g:risk:*` enforcement ops. A flush that grabs connections
   under a DDoS could **starve rate-limiting on the hot path** — persistence
   harming enforcement. Mitigation: the flush acquires **one connection with a
   short checkout timeout**; on contention (timeout/pool-exhausted) it **skips the
   tick and keeps the dirty set for next time** — never blocks, never expands its
   connection budget. (A dedicated tiny pool is the alternative if even one shared
   conn proves too much; single-conn-skip is the KISS default.)
2. **IP-flood memory bound.** A DDoS with many distinct/spoofed source IPs grows
   the DashMap toward `MAX_TRACKED_KEYS` (1 M) and the dirty set with it. The dirty
   set is bounded by the DashMap cap **and** the `strikes>0`/above-threshold write
   filter (§4) that discards the clean long tail before it's ever marked dirty.
   The flush buffer is further capped per tick (highest-strike-first; overflow
   defers) — **no unbounded growth** under flood.
3. **`reset_state` stays O(1) under bench churn.** The bench harness wipes state
   between phases via `/__waf_control/reset_state`. The single-hash design
   (`control:waf:risk`, not per-key) makes the wipe a single `UNLINK`
   (non-blocking) — **not** a `SCAN`+`DEL` over a million keys that would stall
   Redis mid-benchmark. This is the concrete reason to use one hash, not a
   `g:risk:*`-style per-key layout.
4. **Boot hydration after a stress run.** Up to ~1 M persisted slots must load via
   **batched `HSCAN`** (not one giant `HGETALL`), respect `MAX_TRACKED_KEYS`, and
   hydrate **in the background without blocking readiness** — serve from a warming
   DashMap (fail-soft, mirrors the reconcile warm-up). A cold start under attack
   enforces from a fresh DashMap immediately; history backfills behind it.
5. **Drain-loop firehose (P3 counters).** Under a 5k-RPS attack the audit bus is
   saturated and already tolerates `Lagged`. The counter flush therefore does
   **zero Redis I/O per event** — it accumulates deltas in memory and flushes a
   single `INCRBY` on an interval, so it can't add `Lagged` drops.
6. **Load-mode awareness.** When the WAF enters a high load-shedding mode, the
   flush **backs off further** (longer interval / smaller cap) — persistence is
   the first thing to shed, consistent with the shadow-DDoS / load-mode posture
   (`aegis-security/src/ddos.rs`, `tests/load/loadmode-degradation.js`).
7. **Redis-down during DDoS = today's behaviour.** Reconcile fallback serves from
   in-memory; the flush no-ops; enforcement continues from the DashMap unaffected.
   Persistence loss never escalates to a data-plane outage
   ([[project_health_signals_reported_not_gating]]).

### Validation — reuse the existing k6 load suite (`tests/load/`)

This is a **hard acceptance gate**: the feature ships only if every metric below
is statistically unchanged with persistence **on vs off**.

| Scenario | Script | What it proves | Gate |
|---|---|---|---|
| RiskTracker under sustained strikes | `tests/load/risk-strikes.js` | The one hot-path surface — flush adds no request latency | `X-WAF-Overhead-Latency` p99 delta ≈ 0; strikes survive a mid-run restart |
| IP-flood DDoS | `tests/load/ddos-burst.js` | Flush sheds (skips ticks), no unbounded memory, **no pool starvation** | Redis pool checkout p99 wait on the hot path unchanged; RSS bounded |
| Redis loss under load | `tests/load/failover-burst.js` | Persistence-down never fails closed | No 5xx from state loss; flush no-ops; enforcement continues |
| Load-mode shedding | `tests/load/loadmode-degradation.js` | Flush backs off with load mode | Degradation curve unchanged vs baseline |
| Baseline / rate-limit | `tests/load/baseline.js`, `rate-limit.js` | No regression on the core hot path | p50/p99 unchanged |

Plus: `reset_state` latency unchanged under bench churn (invariant 3), and no
increase in broadcast `Lagged` counters (invariant 5). Run with the existing
`make bench-dev` binary-contract harness so results are comparable to prior runs
([[feedback_e2e_docker_cleanup]] — `make bench-dev` is a foreground server, not a
hang).

---

**See also:**
[`persistent-datastore-tracking-data.md`](./persistent-datastore-tracking-data.md)
(the eventual ClickHouse + Postgres replacement — this doc bridges to it and
shares its write-through/load-on-boot seams),
[`security-analytics-and-reporting.md`](./security-analytics-and-reporting.md)
(the analytics-tier deep dive),
[`config-etcd-source-of-truth.md`](./config-etcd-source-of-truth.md) (the parallel
"move the config plane off Redis" track).
