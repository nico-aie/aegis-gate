# 0. AI Assistant Guide (Reusable)

## 0.1 Session Startup (Always Do This First)

Before implementing anything, load context in this exact order:

1. README.md — architecture + crate responsibilities  
2. Implement-Progress.md — last state + next task  
3. plans/plan.md — this assistant guide (rules + protocol)  
4. Relevant sub-plan:
   - plans/proxy.md — `aegis-proxy` track (M1/M2/… task IDs)
   - plans/security.md — `aegis-security` track
   - plans/control.md — `aegis-control` track
   - plans/dashboard-enterprise/README.md — enterprise dashboard
     track (D-M1/D-M2/… task IDs); design spec lives at
     `docs/dashboard-enterprise/`

Do not start coding without reading these.

---

## 0.2 Universal Implementation Prompt (Copy-Paste)

Use this template every time you start or resume work. Copy the
fenced block below verbatim — the code fence preserves the
`<placeholder>` markers so they survive markdown rendering.

```text
Context files to read first (in order):
1. README.md
2. Implement-Progress.md
3. plans/plan.md (this assistant guide)
4. Track-specific plan:
   - Proxy:    plans/proxy.md
   - Security: plans/security.md
   - Control:  plans/control.md
   - Dashboard:
       plans/dashboard-enterprise/README.md
       + plans/dashboard-enterprise/milestone-<N>-*.md
       + docs/dashboard-enterprise/README.md   (design spec)

Task:
<copy NEXT TASK from Implement-Progress.md, e.g. "D-M1-T1.1 Asset embedder">

Target crate:
<aegis-proxy | aegis-security | aegis-control | aegis-core | aegis-bin>
(dashboard-enterprise track is aegis-control only)

Requirements:
- Follow exact types and traits from aegis-core
- Do not invent new interfaces unless necessary
- Use only dependencies already in Cargo.toml
- If a new dependency is needed -> list it, do not add it

Implementation rules:
- Modify only the target crate (except aegis-core if required)
- Keep code idiomatic and production-ready
- Handle errors explicitly (no unwrap in core paths)
- Respect tier + failure mode semantics

Testing:
- Add unit + integration tests where applicable
- Ensure (replace CRATE with the target crate name):
    cargo test -p CRATE
    cargo clippy -p CRATE -- -D warnings

Completion:
- All tests pass
- No clippy warnings
- Update Implement-Progress.md (overwrite fully)
```

---

## 0.3 Progress File Protocol (Strict)

After completing a task:

- Overwrite entire Implement-Progress.md
- Never append
- Never leave partial updates

Template (copy the fenced block — code fence preserves placeholders):

```markdown
# Aegis-Gate Implementation Progress

## Last Completed
- Task: <code + title>
- Crate: <crate>
- Files changed: <files>
- Status: DONE
- Date: <YYYY-MM-DD>

## Next Task
- Task: <next task>
  (use M{n}-T{x}.{y} for proxy/security/control,
   D-M{n}-T{x}.{y} for dashboard-enterprise)
- Plan: plans/<proxy|security|control>.md
        or plans/dashboard-enterprise/milestone-{n}-*.md
- Notes: <optional>

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| ... |
```

---

## 0.4 Execution Rules (Always Enforced)

- Never skip reading context files  
- Never guess missing types — check aegis-core  
- Never modify unrelated crates  
- Never introduce hidden coupling between crates  
- Prefer simple, testable implementations first  
- Keep performance in mind (this is a data-plane system)  

---

## 0.5 Mental Model for the Assistant

When implementing, always think:

- Proxy = execution engine (data plane)  
- Security = decision engine  
- Control = visibility + management  
- Core = contract (source of truth)  

If something feels unclear → it likely belongs in aegis-core.

### Tracks currently in flight

| Track | Plan root | Task ID prefix | Crates touched |
|-------|-----------|----------------|----------------|
| Proxy core | `plans/proxy.md` | `M{n}-T{x}.{y}` | aegis-proxy (+ aegis-core) |
| Security pipeline | `plans/security.md` | `M{n}-T{x}.{y}` | aegis-security |
| Control plane | `plans/control.md` | `M{n}-T{x}.{y}` | aegis-control |
| Enterprise dashboard | `plans/dashboard-enterprise/` | `D-M{n}-T{x}.{y}` | aegis-control only |
| Benchmark mode | `plans/benchmark-mode.md` | `B-T{n}.{y}` | aegis-core, aegis-proxy, aegis-security, aegis-control, aegis-bin |

The `D-` and `B-` prefixes keep dashboard and benchmark task IDs
disjoint from the original M1/M2/M3 IDs already in the Completed
Tasks Log. The dashboard and benchmark tracks are parallel — B-T1..B-T3
can land before D-M1 finishes; B-T4.5 / B-T4.6 (dashboard panels)
are the only B- tasks gated on dashboard milestones.

---

## 0.6 When Resuming Work

Do NOT ask what to do next.

Instead:

1. Read Implement-Progress.md  
2. Take the Next Task  
3. Continue implementation immediately  
