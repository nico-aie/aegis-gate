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

Order = execution priority. **Earlier rows run first.** The dashed
rows are reference material, not work to do.

| State | Track | Plan file | Task ID prefix | Notes |
|---|---|---|---|---|
| **Active** | Phase B — production-readiness | [`phase-b/README.md`](./phase-b/README.md) | `B<n>-T<x>` | B1..B5 closed; **B6 packaging is the only remaining milestone** (B6-T1 production Dockerfile is the in-flight task) |
| **Open intake** | Phase B advanced features | [`../docs/future/advanced-features.md`](../docs/future/advanced-features.md) | — | For proposals NOT covered by Phase B (multi-tenancy, RBAC/SSO, etc.) |
| Closed | Dashboard redesign — Aegis WAF Console | [`dashboard-redesign.md`](./dashboard-redesign.md) | `DD-T<n>` | Reference only — shipped in run-10 (DD-T0..T8) |
| Closed | Cluster ingress / load-balancer | [`cluster-ingress-lb.md`](./cluster-ingress-lb.md) | `HA-T<n>` | Reference only — HA-T1..T5 shipped in run-05; closes carry-over 6 |
| Closed | External interop contract | [`interop-contract.md`](./interop-contract.md) | `IT-T<n>` | Reference only — IT-T1..T6 shipped; X-WAF-* headers + audit always-on |
| Closed | Interop contract dry-run | [`interop-dry-run.md`](./interop-dry-run.md) | `DR-T<n>` | Reference only — DR-T1..T7 shipped in run-08 |
| Closed | Post-run-08 short tracks | [`post-run-08.md`](./post-run-08.md) | `AF-T1` / `HP-T1` / `TLS-T1` | Reference only — all three shipped |
| Closed | Proxy core (M1) | [`proxy.md`](./proxy.md) | `M{n}-T{x}.{y}` | Reference only — full data plane shipped |
| Closed | Security pipeline (M2) | [`security.md`](./security.md) | `M{n}-T{x}.{y}` | Reference only — rule engine + detectors + risk + challenge shipped |
| Closed | Control plane (M3) | [`control.md`](./control.md) | `M{n}-T{x}.{y}` | Reference only — dashboard + audit + auth + compliance shipped |
| Closed | Enterprise dashboard (D-M1..D-M6) — superseded by DD-T0..T8 | [`archive/dashboard-enterprise/README.md`](./archive/dashboard-enterprise/README.md) | `D-M{n}-T{x}.{y}` | Reference only — replaced by the DD-T0..T8 redesign |
| Closed | Security toggles + post-k6 (P1..P8 + F-T1..F-T10) | [`post-k6-followup.md`](./post-k6-followup.md) | `P<n>` / `F-T<n>` | Reference only — admin-API security toggles shipped |
| Folded | Benchmark mode (B-T1..B-T6) | [`benchmark-mode.md`](./benchmark-mode.md) | `B-T<n>.<y>` | Folded into Phase B as **B5-T2** — see [`phase-b/README.md`](./phase-b/README.md#b5--protocols--benchmark) |

---

## Layout

```
plans/
├── README.md                       this status board
├── plan.md                         AI assistant guide (rules + protocol)
├── implementation-matrix.md        doc-by-doc Implemented / Partial / Designed-only
│
├── phase-b/                        ACTIVE — production-readiness track
│   └── README.md                   B1..B6 milestone breakdown (B1..B5 closed)
│
└── (closed tracks — reference only, do not start new work here)
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
| `M{n}-T{x}.{y}` | Original milestone tracks (M1 / M2 / M3) — closed |
| `D-M{n}-T{x}.{y}` | Enterprise dashboard track (D-M1..D-M6) — closed (superseded by DD) |
| `DD-T<n>` | Aegis WAF Console redesign (DD-T0..T8) — closed |
| `B<n>-T<x>` | Phase B (B1..B6) — active, B6 only |
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
