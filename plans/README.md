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
| What's the next task? | [`Implement-Progress.md`](../Implement-Progress.md) § Next Task |
| What's the current status of every doc / feature? | [`implementation-matrix.md`](./implementation-matrix.md) |
| What's the active work track? | [§ Status board](#status-board) below — find the row marked **Active** |
| What's done? | [§ Status board](#status-board) — rows marked **Closed** |
| What's queued? | [§ Status board](#status-board) — rows marked **Queued** |

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
| **Active** | Phase B — production-readiness | [`phase-b/README.md`](./phase-b/README.md) | `B<n>-T<x>` | Six milestones B1..B6 close every "Partial" / "Designed-only" doc banner |
| **Active** | Cluster ingress / load-balancer | [`cluster-ingress-lb.md`](./cluster-ingress-lb.md) | `HA-T<n>` | HAProxy reference deploy + single-VIP perf tests + membership. Closes carry-over 6 (HA test methodology). Runs in parallel with Phase B. |
| **Queued** | Dashboard redesign | [`dashboard-redesign/README.md`](./dashboard-redesign/README.md) | `R-M<n>-T<x>` | Eleven milestones M0..M10. Runs after Phase B closes |
| **Open intake** | Phase B advanced features | [`../docs/future/advanced-features.md`](../docs/future/advanced-features.md) | — | For proposals NOT covered by Phase B (multi-tenancy, RBAC/SSO, etc.) |
| Closed | Proxy core (M1) | [`proxy.md`](./proxy.md) | `M{n}-T{x}.{y}` | Reference only — full data plane shipped |
| Closed | Security pipeline (M2) | [`security.md`](./security.md) | `M{n}-T{x}.{y}` | Reference only — rule engine + detectors + risk + challenge shipped |
| Closed | Control plane (M3) | [`control.md`](./control.md) | `M{n}-T{x}.{y}` | Reference only — dashboard + audit + auth + compliance shipped |
| Closed | Enterprise dashboard (D-M1..D-M6) | [`dashboard-enterprise/README.md`](./dashboard-enterprise/README.md) | `D-M{n}-T{x}.{y}` | Reference only — bundled SPA shipped |
| Closed | Security toggles + post-k6 (P1..P8 + F-T1..F-T10) | [`post-k6-followup.md`](./post-k6-followup.md) | `P<n>` / `F-T<n>` | Reference only — admin-API security toggles shipped |
| Folded | Benchmark mode (B-T1..B-T6) | [`benchmark-mode.md`](./benchmark-mode.md) | `B-T<n>.<y>` | Folded into Phase B as **B5-T2** — see [`phase-b/README.md`](./phase-b/README.md#b5--protocols--benchmark) |

### Why Phase B before dashboard redesign?

Operators can run a useful single-node WAF today. They cannot:
- deploy multi-node (HA clustering is a stub),
- plug in a real secret manager (Vault/AWS/GCP/Azure resolvers
  return `NotImplemented`),
- fetch a STIX/TAXII threat feed,
- or block by country (no GeoIP).

Phase B closes those gaps. A dashboard refresh, however nice, is
strictly lower-impact than turning the WAF into something
operators can actually deploy at scale.

---

## Layout

```
plans/
├── README.md                       this status board
├── plan.md                         AI assistant guide (rules + protocol)
├── implementation-matrix.md        doc-by-doc Implemented / Partial / Designed-only
│
├── phase-b/                        ACTIVE — production-readiness track
│   └── README.md                   B1..B6 milestone breakdown
│
├── dashboard-redesign/             QUEUED — runs after Phase B
│   ├── README.md                   M0..M10 milestone overview
│   ├── workflow.md                 Claude-Design 5-stage loop
│   ├── design-system.md            tokens, fonts, motion, spacing
│   ├── milestone-0-foundations.md  M0 detail
│   └── pages/                      per-page redesign briefs
│
└── (closed tracks — kept for reference, do not start new work here)
    ├── proxy.md                    M1 — proxy core
    ├── security.md                 M2 — security pipeline
    ├── control.md                  M3 — control plane
    ├── dashboard-enterprise/       D-M1..D-M6 — enterprise dashboard track
    ├── post-k6-followup.md         P1..P8 + F-T1..F-T10
    └── benchmark-mode.md           folded into Phase B (B5-T2)
```

---

## Conventions

### Task IDs

| Prefix | Meaning |
|---|---|
| `M{n}-T{x}.{y}` | Original milestone tracks (M1 / M2 / M3) — closed |
| `D-M{n}-T{x}.{y}` | Enterprise dashboard track (D-M1..D-M6) — closed |
| `R-M{n}-T{x}` | Dashboard redesign (M0..M10) — queued |
| `B<n>-T<x>` | Phase B (B1..B6) — active |
| `P<n>` | Security-toggle phases (P1..P8) — closed |
| `F-T<n>` | Post-k6 follow-up — closed |

### Status banner

Every plan file carries a one-line `> **Status:**` banner under
its H1 telling you immediately whether it's Active / Queued /
Closed / Folded / AI-guide. Mirror what's in this status board.

### Updating priority

When the active track closes:
1. Promote the next **Queued** row to **Active** in this README.
2. Flip the Status banner on the promoted plan file.
3. Update `Implement-Progress.md` § Next Task with the first task
   of the newly-active track.
4. Update [`implementation-matrix.md`](./implementation-matrix.md)
   if the closure flipped any doc banners from Partial /
   Designed-only to Implemented.
