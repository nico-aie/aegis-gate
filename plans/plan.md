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
| [`archive/phase-b-2026/README.md`](./archive/phase-b-2026/README.md) | Shipped milestone breakdown (B1..B6) — closed reference |
| `plan.md` (this file) | The rules — session startup, prompt template, progress-file protocol, mental model |

---

## 0.1 Session Startup (Always Do This First)

Before implementing anything, load context in this exact order:

1. [`README.md`](../README.md) — top-level architecture + crate
   responsibilities.
2. [`plans/README.md`](./README.md) — track status board (which
   track is **Active**). For *current state* — what shipped and when —
   read recent **git history** + the open items in
   [`issues/README.md`](./issues/README.md). There is no hand-maintained
   progress file; git + the issues board are the source of truth.
3. [`plans/plan.md`](./plan.md) — this assistant guide (rules +
   protocol).
4. The active track's plan file (if any):
   - **No active top-level track.** Phase B (B1..B6) shipped and is
     archived at [`plans/archive/phase-b-2026/`](./archive/phase-b-2026/README.md);
     pick the next track from [`future/`](./README.md) per the status board.
   - Closed reference: [`plans/archive/dashboard-redesign.md`](./archive/dashboard-redesign.md) (DD-T0..T8 — Aegis WAF Console)
5. (When relevant) the matching doc under `docs/<category>/...`
   that the task touches — its `> **Status:**` banner is the fast
   read on what already works.

Do not start coding without reading 1–4.

---

## 0.2 Universal Implementation Prompt (Copy-Paste)

Use this template every time you start or resume work. Copy the
fenced block below verbatim — the code fence preserves the
`<placeholder>` markers so they survive markdown rendering.

```text
Context files to read first (in order):
1. README.md
2. plans/README.md (status board — confirm active track; current state =
   git history + plans/issues/)
3. plans/plan.md (this assistant guide)
4. Active track's plan file (if any):
   - No active top-level track — Phase B shipped (plans/archive/phase-b-2026/).
     Pick the next track from plans/README.md → future/.
   - Closed reference:        plans/archive/dashboard-redesign.md
                             + docs/control-plane/enterprise/README.md (design spec)
5. Per-doc status:           plans/implementation-matrix.md

Task:
<the next item from plans/issues/ or the active track>

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
- A clear commit / PR is the task record (no progress file to update)
- If the task closes a Partial/Designed-only banner: flip the
  doc's `> **Status:**` line AND the matching row in
  plans/implementation-matrix.md
- If it resolves a plans/issues/ item: move it to issues/archived/
  and add a Resolved row in issues/README.md
```

---

## 0.3 Status & History (where the project's state lives)

There is **no hand-maintained progress file** (the old
`Implement-Progress.md` + `docs/progress/` were removed 2026-06-19 —
they drifted stale and contradicted the real state). The source of
truth is now:

| Want to know… | Read… |
|---|---|
| What just shipped / when / by whom | **`git log`** + merged PRs (each commit/PR is the task record) |
| Open backlog + known issues | [`issues/README.md`](./issues/README.md) — Open table + per-file plans; resolved items live in [`issues/archived/`](./issues/archived/) |
| Per-doc Implemented / Partial / Designed-only | [`implementation-matrix.md`](./implementation-matrix.md) |
| Which track is active / queued / closed | [`README.md`](./README.md) status board |

### When you close a task

1. Land a clear **commit / PR** — that *is* the record. No file to update.
2. If it resolves a `plans/issues/` item: `git mv` the file into
   `issues/archived/` and add a **Resolved** row in
   [`issues/README.md`](./issues/README.md).
3. If it graduates a doc from Partial / Designed-only → Implemented:
   flip the doc's `> **Status:**` banner AND the matching row in
   [`implementation-matrix.md`](./implementation-matrix.md) in the same
   commit.

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
| — | Phase B — production-readiness | [`archive/phase-b-2026/`](./archive/phase-b-2026/README.md) | `B<n>-T<x>` | closed |
| — | Dashboard redesign | [`archive/dashboard-redesign.md`](./archive/dashboard-redesign.md) | `R-M<n>-T<x>` / `DD-T<x>` | closed |
| — | All M{n} / D-M{n} / P / F-T tracks | — | various | closed |

**No active top-level track.** Phase B (multi-node, Vault, STIX,
country-block) and the dashboard redesign both shipped. Pick the
next track from [`README.md`](./README.md)'s `future/` section.

---

## 0.7 When Resuming Work

Do NOT ask what to do next.

Instead:

1. Check recent **git history** + the Open table in
   [`issues/README.md`](./issues/README.md).
2. Take the highest-priority open item (or the first task of the
   **Active** track per the [`README.md`](./README.md) status board).
3. Continue implementation immediately.
