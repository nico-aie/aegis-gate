# Enforcement Modes — `enforce` vs `log_only`

> Every policy decision runs in one of two modes. In **`enforce`** the
> WAF applies its decision (a `block` returns 403, a `rate_limit` returns
> 429, a `challenge` returns the 429 PoW). In **`log_only`** the policy is
> evaluated exactly the same and still **reports** the intended
> `X-WAF-Action` + `X-WAF-Rule-Id` + audit evidence, but the enforcement
> effect is **not applied** — the request is forwarded upstream and the
> response carries `X-WAF-Mode: log_only`. This lets the event organizers
> (or an operator tuning a new detector) confirm a policy fires without
> denying every test request.
>
> Mode lives in a lock-free `ModeStore`
> ([`crates/aegis-control/src/interop/mode.rs`](../../crates/aegis-control/src/interop/mode.rs)),
> so changes apply **hot — no restart** — and every change is audit-logged.
> Default is `enforce` (secure-by-default).

## Two ways to change it

| | Committee / benchmarker | Operator |
|---|---|---|
| Endpoint | `POST /__waf_control/set_profile` | `PUT /api/mode` + dashboard Settings |
| Auth | `X-Benchmark-Secret` header, loopback-gated | session cookie + CSRF |
| Granularity | all **/ features / policies** | **global only** (`scope: all` equivalent) |
| Restart | no (hot) | no (hot) |
| Audit-logged | yes | yes (`mode_set`) |

### 1. Committee / benchmarker — the contract path (granular)

`POST /__waf_control/set_profile` is the contract-mandated control endpoint
(v2.5 §2.5). It is the **only** path with per-feature / per-policy scope.

```bash
SECRET="waf-hackathon-2026-ctrl"   # config: interop.control_secret

# all features → log_only   (scope: all is MUST-supported)
curl -X POST http://127.0.0.1:9443/__waf_control/set_profile \
  -H "X-Benchmark-Secret: $SECRET" -H "content-type: application/json" \
  -d '{"scope":"all","mode":"log_only"}'

# one feature only          (scope: features — SHOULD)
  -d '{"scope":"features","mode":"log_only","features":["rules_engine"]}'

# one policy only           (scope: policies — SHOULD)
  -d '{"scope":"policies","mode":"log_only","feature":"rules_engine","policies":["sqli"]}'

# back to enforce everywhere (also clears all overrides)
  -d '{"scope":"all","mode":"enforce"}'
```

Resolution is **most-specific-wins**: `policy → feature → default`. A
`scope: all` write resets the default **and** clears every feature/policy
override.

### 2. Operator — dashboard or admin API (global)

All three are admin-plane, audit-mutated, and CSRF-gated:

- **Dashboard:** **Settings → "Shadow Mode (Dry-Run)"** toggle flips the
  global mode `enforce` ↔ `log_only`. It's hot-applied (waits for the config
  version to bump, then toasts the apply latency), CSRF-gated, and
  audit-chained — `log_only` also raises a "Shadow mode is ON — no traffic
  is being blocked" banner. The *Policy posture* status chip shown across the
  dashboard is **read-only**: it displays the current mode and links here.
- **API:** `PUT /api/mode` with `{"mode":"enforce"}` or `{"mode":"log_only"}`
  (`"shadow"` is accepted as an alias for `log_only`).
- **Read:** `GET /api/mode` → `{"mode":"enforce"}`.

The operator path calls `set_all` — it only moves the **global default**.
For per-feature / per-policy control use the committee `set_profile`
endpoint above.

## Which actions honor `log_only`

| Action | log_only-gated | Where |
|---|---|---|
| `block` (detectors, blacklist, strike-block, risk-score) | ✅ | data plane gates |
| `rate_limit` (per-IP gate) | ✅ | data plane |
| `challenge` (cumulative-risk PoW) | ✅ | data plane (fixed 2026-05-22) |
| `timeout` / `circuit_breaker` | n/a | upstream-availability outcomes — the contract carves these out of the "must not apply" rule |

## Verifying a change took effect

- **Per response:** the `X-WAF-Mode` header reflects the mode of the
  policy that produced `X-WAF-Action` (and the ambient default on a clean
  allow). In `log_only` an attack returns the **upstream** status with the
  intended `X-WAF-Action` set; in `enforce` it returns `403` / `429`.
- **Current state:** `GET /__waf_control/capabilities` →
  `active.default_mode` + `active.overrides`; or `GET /api/mode`.
- **Regression test:** [`tests/interop/dr-t6-mode-enforcement.sh`](../../tests/interop/dr-t6-mode-enforcement.sh)
  exercises `block` + `rate_limit` × `enforce` / `log_only` end-to-end;
  [`dr-t3-mode-cycle.sh`](../../tests/interop/dr-t3-mode-cycle.sh) checks
  the header flips + scope overrides.

## See also

- [risk-tuning.md](./risk-tuning.md) — `set_profile log_only` as a
  detector-tuning tool, plus the other safe knobs.
- [traffic-gates.md](./traffic-gates.md) — the gates whose actions the
  mode governs.
- [`../architecture/storage-and-contract.md`](../architecture/storage-and-contract.md)
  — the v2.x contract compliance matrix.
