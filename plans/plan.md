# 0. AI Assistant Guide (Reusable)

## 0.1 Session Startup (Always Do This First)

Before implementing anything, load context in this exact order:

1. README.md — architecture + crate responsibilities  
2. Implement-Progress.md — last state + next task  
3. plans/plan.md — shared types (§2) + traits (§3)  
4. Relevant sub-plan:
   - plans/proxy.md
   - plans/security.md
   - plans/control.md

Do not start coding without reading these.

---

## 0.2 Universal Implementation Prompt (Copy-Paste)

Use this template every time you start or resume work:

Context files to read first (in order):
1. README.md
2. Implement-Progress.md
3. plans/plan.md (shared types §2, traits §3)
4. plans/<proxy|security|control>.md

Task:
<copy NEXT TASK from Implement-Progress.md>

Target crate:
<aegis-proxy | aegis-security | aegis-control | aegis-core | aegis-bin>

Requirements:
- Follow exact types and traits from aegis-core
- Do not invent new interfaces unless necessary
- Use only dependencies already in Cargo.toml
- If a new dependency is needed → list it, do not add it

Implementation rules:
- Modify only the target crate (except aegis-core if required)
- Keep code idiomatic and production-ready
- Handle errors explicitly (no unwrap in core paths)
- Respect tier + failure mode semantics

Testing:
- Add unit + integration tests where applicable
- Ensure:
  cargo test -p <crate>
  cargo clippy -p <crate> -- -D warnings

Completion:
- All tests pass
- No clippy warnings
- Update Implement-Progress.md (overwrite fully)

---

## 0.3 Progress File Protocol (Strict)

After completing a task:

- Overwrite entire Implement-Progress.md
- Never append
- Never leave partial updates

Template:

# Aegis-Gate Implementation Progress

## Last Completed
- Task: <code + title>
- Crate: <crate>
- Files changed: <files>
- Status: DONE
- Date: <YYYY-MM-DD>

## Next Task
- Task: <next task>
- Plan: plans/<proxy|security|control>.md
- Notes: <optional>

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| ... |

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

---

## 0.6 When Resuming Work

Do NOT ask what to do next.

Instead:

1. Read Implement-Progress.md  
2. Take the Next Task  
3. Continue implementation immediately  
