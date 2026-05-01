# Aegis-Gate — plans/

The single place to look for **what to build next**, **what's
shipped**, and **how the AI assistant should work** in this repo.

If you only read one thing: pick the row in
[§ Status board](#status-board) that says **Active** and follow
the link.

---

## For humans

| Want to know | Read |
|---|---|
| What's the next task? | [`../Implement-Progress.md`](../Implement-Progress.md) § Next Task |
| What's the current status of every doc / feature? | [`implementation-matrix.md`](./implementation-matrix.md) |
| What's the active work track? | [§ Status board](#status-board) below — find the row marked **Active** |
| What's done? | [§ Status board](#status-board) — rows marked **Closed** |

## For the AI assistant

| Need | File |
|---|---|
| Session-start protocol (the rules) | [`plan.md`](./plan.md) |
| What to load on session start | [`plan.md` § 0.1](./plan.md#01-session-startup-always-do-this-first) |
| Progress-file protocol (how to update `Implement-Progress.md`) | [`plan.md` § 0.3](./plan.md#03-progress-file-protocol-strict) |
| Doc-by-doc implementation status | [`implementation-matrix.md`](./implementation-matrix.md) |
| Active milestone breakdown | The Active track listed in the status board |

---

## Status board

Order = execution priority. **Earlier rows run first.** The
"Closed" rows below are reference material; the "Active" /
"Queued" rows are real work.

| State | Track | Plan file | Task ID prefix | Notes |
|---|---|---|---|---|
| Closed | Hackathon-readiness — v2.3 contract + Tier bonuses | [`hackathon-readiness.md`](./hackathon-readiness.md) | `HACK-T<n>` | ✅ HACK-T1..T5 shipped 2026-05-01 / 2026-05-02. Round 1 mock-data risk closed; Round 2 contract gate (40/40 PASS); Tier A (rule simulator), Tier B (config history), Tier C (Syslog/CEF) all claimed. Deferred: HACK-T4 rollback action, HACK-T5 TLS transport. |
| **Queued** | mTLS — Console mutation surfaces | [`mtls.md`](./mtls.md) | `MTLS-T<n>` | T1..T5 + T6 ✅ shipped 2026-05-01 (rustls inbound, identity extraction, route-scoped policy gate, hot-reload, console observability). T7..T11 (mode toggle, SAN allowlist, break-glass, CA upload, per-route editor) deferred. |
| **Queued** | Phase B — production packaging | [`phase-b/README.md`](./phase-b/README.md) | `B<n>-T<x>` | B1..B5 ✅ closed. B6-T1 (Dockerfile) ✅ shipped; B6-T2 (Helm) + B6-T3 (CI) pending; B6-T4 (HSM) + B6-T5 (fd-pass) deferred. |
| **Queued** | Scaling configuration — Tier A bonus complement | [`scaling-config.md`](./scaling-config.md) | `SC-T<n>` | T1..T3 + T5 ✅ shipped 2026-05-01 (`/api/state` + Scaling page + Settings hint + docs). T4 (`tokio_unstable` Prometheus metrics) deferred — optional polish. |
| Closed | Console config pages — upstreams editor + alerts | [`console-config-pages.md`](./console-config-pages.md) | `CC-T<n>` | Reference only — CC-T1..T3 + alert-receivers shipped (run-11/run-12) |
| Closed | Proxy refactor — `lib.rs` 5569 → 559 lines | [`proxy-refactor.md`](./proxy-refactor.md) | `PRE-T<n>` | Reference only — PRE-T1..T8 shipped 2026-05-01; lib.rs is now a thin facade |
| Closed | Dashboard redesign — Aegis WAF Console | [`dashboard-redesign.md`](./dashboard-redesign.md) | `DD-T<n>` | Reference only — shipped in run-10 (DD-T0..T8) |
| Closed | Cluster ingress / load-balancer | [`cluster-ingress-lb.md`](./cluster-ingress-lb.md) | `HA-T<n>` | Reference only — HA-T1..T5 shipped in run-05 |
| Closed | External interop contract (v2.3 §2 control plane) | [`interop-contract.md`](./interop-contract.md) | `IT-T<n>` | Reference only — IT-T1..T6 shipped; `/__waf_control/*` + `X-WAF-*` headers + audit JSONL all green per run-12 |
| Closed | Interop contract dry-run | [`interop-dry-run.md`](./interop-dry-run.md) | `DR-T<n>` | Reference only — DR-T1..T7 shipped in run-08 |
| Closed | Post-run-08 short tracks | [`post-run-08.md`](./post-run-08.md) | `AF-T1` / `HP-T1` / `TLS-T1` | Reference only — all three shipped |
| Closed | Proxy core (M1) | [`proxy.md`](./proxy.md) | `M{n}-T{x}.{y}` | Reference only — full data plane shipped |
| Closed | Security pipeline (M2) | [`security.md`](./security.md) | `M{n}-T{x}.{y}` | Reference only — rule engine + detectors + risk + challenge shipped |
| Closed | Control plane (M3) | [`control.md`](./control.md) | `M{n}-T{x}.{y}` | Reference only — dashboard + audit + auth + compliance shipped |
| Closed | Enterprise dashboard (D-M1..D-M6) — superseded by DD-T0..T8 | [`archive/dashboard-enterprise/README.md`](./archive/dashboard-enterprise/README.md) | `D-M{n}-T{x}.{y}` | Reference only — replaced by the DD-T0..T8 redesign |
| Closed | Security toggles + post-k6 (P1..P8 + F-T1..F-T10) | [`post-k6-followup.md`](./post-k6-followup.md) | `P<n>` / `F-T<n>` | Reference only — admin-API security toggles shipped |
| Folded | Benchmark mode (B-T1..B-T6) | [`benchmark-mode.md`](./benchmark-mode.md) | `B-T<n>.<y>` | Folded into Phase B as **B5-T2** — see [`phase-b/README.md`](./phase-b/README.md#b5--protocols--benchmark) |
| Open intake | Advanced features | [`../docs/future/advanced-features.md`](../docs/future/advanced-features.md) | — | For proposals NOT covered above (multi-tenancy, RBAC/SSO, etc.) |

### Hackathon v2.3 compliance map

The active hackathon track maps directly to the rounds defined
in [`../Hackathon_Doc/EN_present_v2.3.md`](../Hackathon_Doc/EN_present_v2.3.md):

| Round | Weight | Status | Track |
|---|---|---|---|
| 1 — Functionality (Pass/Fail) | gate | ✅ mock-data risk closed (run-14) | **HACK-T1** ✅ |
| 2 — Automated benchmark | 65% (≥ 70% gate) | ✅ run-12 + HACK-T2 regression gate (40/40 PASS) | **HACK-T2** ✅ |
| 3 — Performance + Tier bonuses | 35% + bonus | ✅ Tier A + B + C all claimed (rule simulator / config history / Syslog forwarder) | **HACK-T3..T5** ✅ |

---

## Layout

```
plans/
├── README.md                       this status board
├── plan.md                         AI assistant guide (rules + protocol)
├── implementation-matrix.md        doc-by-doc Implemented / Partial / Designed-only
│
├── hackathon-readiness.md          ACTIVE — HACK-T1..T5 (Round 1 / 2 / 3 gap fixes + Tier bonuses)
│
├── mtls.md                         QUEUED — MTLS-T7..T11 Console mutations remain
├── scaling-config.md               QUEUED — SC-T4 (tokio_unstable metrics) remains, optional
├── phase-b/                        QUEUED — production packaging
│   └── README.md                   B1..B5 closed; B6-T2 / T3 pending; T4 / T5 deferred
│
├── proxy-refactor.md               CLOSED — PRE-T1..T8 (lib.rs 5569 → 559)
├── console-config-pages.md         CLOSED — CC-T1..T3 + alert-receivers
│
└── (older closed tracks — reference only, do not start new work here)
    ├── proxy.md                    M1 — proxy core
    ├── security.md                 M2 — security pipeline
    ├── control.md                  M3 — control plane
    ├── dashboard-redesign.md       DD-T0..T8 — Aegis WAF Console
    ├── cluster-ingress-lb.md       HA-T1..T5 — single-VIP HAProxy + perf
    ├── interop-contract.md         IT-T1..T6 — external interop contract
    ├── interop-dry-run.md          DR-T1..T7 — self-driven dry-run
    ├── post-run-08.md              AF-T1, HP-T1, TLS-T1 — three short tracks
    ├── post-k6-followup.md         P1..P8 + F-T1..F-T10
    ├── benchmark-mode.md           folded into Phase B (B5-T2)
    └── archive/
        ├── dashboard-enterprise/           D-M1..D-M6 — superseded by DD-T0..T8
        └── dashboard-redesign-early-brief/ M0..M10 brief — superseded by DD-T0..T8
```

---

## Conventions

### Task IDs

| Prefix | Meaning |
|---|---|
| `HACK-T<n>` | **Hackathon-readiness — active** |
| `MTLS-T<n>` | mTLS server-side track — T1..T6 closed; T7..T11 queued |
| `SC-T<n>` | Scaling configuration — T1..T3 + T5 closed; T4 optional / queued |
| `B<n>-T<x>` | Phase B production-readiness — B1..B5 closed; B6 partially closed |
| `PRE-T<n>` | Proxy refactor — closed (lib.rs 5569 → 559) |
| `CC-T<n>` | Console config pages — closed |
| `M{n}-T{x}.{y}` | Original milestone tracks (M1 / M2 / M3) — closed |
| `D-M{n}-T{x}.{y}` | Enterprise dashboard track (D-M1..D-M6) — closed (superseded by DD) |
| `DD-T<n>` | Aegis WAF Console redesign (DD-T0..T8) — closed |
| `HA-T<n>` | Cluster ingress / load-balancer — closed |
| `IT-T<n>` | External interop contract — closed |
| `DR-T<n>` | Interop contract self-driven dry-run — closed |
| `AF-T1`, `HP-T1`, `TLS-T1` | Post-run-08 short tracks — closed |
| `P<n>` | Security-toggle phases (P1..P8) — closed |
| `F-T<n>` | Post-k6 follow-up — closed |
| `B-T<n>` | Benchmark-mode track — folded into B5-T2 |

### Status banner

Every plan file carries a one-line `> **Status:**` banner under
its H1 telling you immediately whether it's Active / Queued /
Closed / Folded / AI-guide. Mirror what's in this status board.

### Updating priority

When the active track closes:
1. Promote the next available work to **Active** in this README
   (or open intake to a new track if Phase B is fully closed).
2. Flip the Status banner on the promoted plan file.
3. Update `Implement-Progress.md` § Next Task with the first task
   of the newly-active track.
4. Update [`implementation-matrix.md`](./implementation-matrix.md)
   if the closure flipped any doc banners from Partial /
   Designed-only to Implemented.
