# AI Assistant Guide

> **Status:** AI assistant guide — rules + protocol. Pure reference,
> no implementation status here.
>
> For implementation status see [`implementation-matrix.md`](./implementation-matrix.md).
> For the priority of tracks see [`README.md`](./README.md).

This file is the protocol you follow when working on Aegis-Gate.
Read it once at session start, then refer back to it whenever you
finish a task. The companion files split clean responsibilities:

| File | Holds |
|---|---|
| [`README.md`](./README.md) | Status board — which track is active, queued, or closed |
| [`implementation-matrix.md`](./implementation-matrix.md) | Per-doc status (Implemented / Partial / Designed-only / Deferred) |
| [`phase-b/README.md`](./phase-b/README.md) | The active milestone breakdown (B1..B6) |
| `plan.md` (this file) | The rules — session startup, prompt template, progress-file protocol, mental model |

---

## 0.1 Session Startup (Always Do This First)

Before implementing anything, load context in this exact order:

1. [`README.md`](../README.md) — top-level architecture + crate
   responsibilities.
2. [`Implement-Progress.md`](../Implement-Progress.md) — current
   state + next task + carry-overs.
3. [`plans/README.md`](./README.md) — track status board (which
   track is **Active**).
4. [`plans/plan.md`](./plan.md) — this assistant guide (rules +
   protocol).
5. The active track's plan file:
   - **Phase B (active):** [`plans/phase-b/README.md`](./phase-b/README.md)
   - **Dashboard redesign (queued):** [`plans/dashboard-redesign/README.md`](./dashboard-redesign/README.md)
6. (When relevant) the matching doc under `docs/<category>/...`
   that the task touches — its `> **Status:**` banner is the fast
   read on what already works.

Do not start coding without reading 1–5.

---

## 0.2 Universal Implementation Prompt (Copy-Paste)

Use this template every time you start or resume work. Copy the
fenced block below verbatim — the code fence preserves the
`<placeholder>` markers so they survive markdown rendering.

```text
Context files to read first (in order):
1. README.md
2. Implement-Progress.md
3. plans/README.md (status board — confirm active track)
4. plans/plan.md (this assistant guide)
5. Active track's plan file:
   - Phase B (active):       plans/phase-b/README.md
   - Dashboard redesign:     plans/dashboard-redesign/README.md
                             + plans/dashboard-redesign/milestone-<N>-*.md
                             + docs/control-plane/enterprise/README.md (design spec)
6. Per-doc status:           plans/implementation-matrix.md

Task:
<copy NEXT TASK from Implement-Progress.md, e.g. "B1-T1 Real Redis backend">

Target crate:
<aegis-proxy | aegis-security | aegis-control | aegis-core | aegis-bin>

Requirements:
- Follow exact types and traits from aegis-core
- Do not invent new interfaces unless necessary
- Use only dependencies already in Cargo.toml
- If a new dependency is needed -> list it, do not add it

Implementation rules:
- Modify only the target crate (except aegis-core if required)
- Keep code idiomatic and production-ready
- Handle errors explicitly (no unwrap in core paths)
- Respect tier + failure-mode semantics

Testing:
- Add unit + integration tests where applicable
- Ensure (replace CRATE with the target crate name):
    cargo test -p CRATE
    cargo clippy -p CRATE -- -D warnings

Completion:
- All tests pass
- No clippy warnings
- Update Implement-Progress.md per § 0.3
- If the task closes a Partial/Designed-only banner: flip the
  doc's `> **Status:**` line AND the matching row in
  plans/implementation-matrix.md
```

---

## 0.3 Progress File Protocol (Strict)

`Implement-Progress.md` is a **living snapshot**, not a changelog.
The Completed Tasks Log at the bottom is the only append-only
section. Every other section is overwritten in place.

The file ships with a header that documents this protocol — keep
that header intact.

### Section rules

| Section | What it holds | Update cadence |
|---|---|---|
| **Status (snapshot)** | Date + test count + clippy state + active track + next task + one-line "latest activity" | Every closed task |
| **Last Completed** | Current task in full detail (outcome + files + verification) | Every closed task — overwrite |
| **Recent History** | Previous **5** tasks, **1–2 lines each**, table form | Push the old "Last Completed" down to the top of this table |
| **Next Task** | The immediate next item, or a list of open tracks if no task is in flight | Every closed task — overwrite |
| **Tracks in flight** | Long-running tracks + their open/closed state | Only when a track opens or closes |
| **Carry-overs / known limitations** | Durable list of things that work but aren't fully shipped | Only when a carry-over graduates to "shipped" |
| **Future phases** | Pointers to `plans/dashboard-redesign/` + `docs/future/advanced-features.md` | Rarely |
| **Verification (last full run)** | `cargo test` count + clippy state | Every closed task |
| **Completed Tasks Log** | One row per closed task | **Append only** — never edit older rows |

### After completing a task

1. **Move** the current "Last Completed" → top row of "Recent
   History" table, compressed to 1–2 lines.
2. **Overwrite** "Last Completed" with the new task's full detail.
3. **Overwrite** "Next Task" with what to do next (or list open
   tracks if you don't know).
4. **Update** "Status (snapshot)" with the new date / test count.
5. **Append** one row to "Completed Tasks Log".
6. **Update** "Verification" with the latest `cargo test --workspace`
   count.
7. Touch "Tracks", "Carry-overs", or "Future phases" **only** if
   the closed task changes their state.
8. If the closed task graduated a doc from Partial / Designed-only
   to Implemented: flip the `> **Status:**` banner on the doc AND
   the row in [`implementation-matrix.md`](./implementation-matrix.md).

Do NOT add per-task "Earlier Completed" or "Previous (X) — for
context" sections. That pattern bloated the file before this
template existed; the Recent History table replaces it.

### Last Completed entry format

```markdown
## Last Completed

**Task:** <code + title>

**Outcome.** <2–4 sentences: what now works, observable from the
outside.>

**Files changed.**
- <path> — <one-line note>
- ...

**Verification.** <commands run + their results>
```

---

## 0.4 Execution Rules (Always Enforced)

- Never skip reading context files
- Never guess missing types — check `aegis-core`
- Never modify unrelated crates
- Never introduce hidden coupling between crates
- Prefer simple, testable implementations first
- Keep performance in mind (this is a data-plane system)
- When the task closes a Partial / Designed-only feature: flip its
  banner in the doc *and* the row in `implementation-matrix.md` in
  the same commit.

---

## 0.5 Mental Model for the Assistant

When implementing, always think:

- **Proxy** = execution engine (data plane)
- **Security** = decision engine
- **Control** = visibility + management
- **Core** = contract (source of truth)

If something feels unclear → it likely belongs in `aegis-core`.

For where each subsystem lives in code, see the ownership section
of [`docs/README.md`](../docs/README.md#ownership-map).

---

## 0.6 Tracks priority

The current execution order — earlier rows run first. Re-derive
this from [`README.md`](./README.md) on session start; do not
trust this section if it disagrees with the README status board.

| # | Track | Plan root | Task ID prefix | State |
|---|---|---|---|---|
| 1 | **Phase B — production-readiness** | [`phase-b/`](./phase-b/README.md) | `B<n>-T<x>` | **active** |
| 2 | Dashboard redesign | [`dashboard-redesign/`](./dashboard-redesign/README.md) | `R-M<n>-T<x>` | queued |
| — | All M{n} / D-M{n} / P / F-T tracks | — | various | closed |

**Why Phase B before dashboard redesign.** Operators can run a
single-node WAF today but cannot deploy multi-node, plug in Vault,
fetch a STIX feed, or block by country. Phase B closes those gaps
— higher impact than a dashboard refresh.

---

## 0.7 When Resuming Work

Do NOT ask what to do next.

Instead:

1. Read [`Implement-Progress.md`](../Implement-Progress.md).
2. Take the **Next Task**.
3. Continue implementation immediately.

If "Next Task" is empty or stale, fall through to
[`README.md`](./README.md) status board → take the first task of
the **Active** track.
