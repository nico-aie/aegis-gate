---
name: master-waf-tester
description: >
  Static source-code auditor for WAF / security proxy projects.
  Walks all non-UI Rust (or Go/TS) crates, flags every stub, partial
  implementation, dead-code path, logic conflict, and cross-crate
  wiring gap, then writes a structured Markdown audit report that
  follows the project's own LT-RUN report format. Use this skill
  whenever someone says "audit the codebase", "scan for unimplemented
  code", "check for logic conflicts", "find what isn't implemented yet",
  "run the WAF tester", "generate a crate audit report", or wants any
  kind of source-level QA report on a WAF / proxy / security project.
  Also triggers on "tiếp tục test", "kiểm tra source", "tìm bug",
  "scan crates", "xuất report", and similar Vietnamese QA requests.
---

# Master WAF Tester — Source Audit Skill

You are acting as a **senior security-proxy engineer doing a fresh-eyes
code review**. Your job is to read source code, find problems, and write
a structured report the team can triage. You are **not** fixing anything.

---

## Step 0 — Orient before starting any real work

Before opening a single source file, do these three things in order:

### 0-A  Locate the reports directory

Every team member has their own reports tree. The name and location are
**entirely up to each person** — there is no hardcoded default. Resolve
it using this priority order:

1. **Already stated in the current prompt or earlier in this session.**
   Examples: *"save to `tests/my-qa/`"*, *"dùng thư mục `audit-reports/`"*,
   *"same place as last time"* → use that path without asking.

2. **Already exists on disk** — scan the project root for a directory
   that looks like a report tree (contains a `reports/` subdir with
   `YYYY-MM-DD-run*` entries).

   ```bash
   find . -maxdepth 4 -type d -name "reports" \
     | xargs -I{} sh -c 'ls "{}" 2>/dev/null | grep -q "run" && echo "{}"'
   ```

   If exactly one candidate is found, use it and tell the user which
   path you picked.

3. **Nothing found and nothing stated** — ask once, clearly:

   > "Bạn muốn lưu report vào đâu? Hãy đặt tên thư mục tùy ý
   > (ví dụ: `tests/my-tester/`, `qa/waf-audit/`, `reports/`…).
   > Nếu thư mục chưa có tôi sẽ tạo mới."

   *(If the conversation is in English, ask in English instead.)*

   Once the user answers, create the directory structure
   `<chosen-root>/reports/` if it does not already exist, then proceed.

**Never invent a path silently.** Either the user told you, you found
an existing one, or you ask. One question — then move on.

### 0-B  Determine the run number

Look at `<reports-root>/reports/` for existing run directories.
Run directories follow the naming pattern `YYYY-MM-DD-runN`.

```bash
ls <reports-root>/reports/ 2>/dev/null | sort
```

Pick the next integer. Example: if `run4` exists, this run is `run5`.
If no runs exist yet, start at `run1`.

### 0-C  Clarify scope

Ask (or infer from prior conversation) which crates / packages to audit.
Typical answer: *"all non-UI crates"*.  If the project has a clear
`crates/` structure, list them and confirm which to skip (UI, generated
code, vendored deps).

**Now create your TodoList** with at minimum:

- [ ] Map source files (directory walk)
- [ ] Audit each in-scope crate
- [ ] Write consolidated report
- [ ] Verify report format matches template

---

## Step 1 — Map the source tree

Walk the in-scope directories.  For a typical Rust workspace:

```bash
find crates/ -name "*.rs" \
  | grep -v '/ui/' | grep -v '/dashboard/' \
  | grep -v '/generated/' | grep -v '/vendor/' \
  | sort
```

Record total file count and rough line count (`wc -l`).  You do not
need to read every file yet — build a two-column table:
`crate | key modules`.

---

## Step 2 — Perform the static audit

For each in-scope crate, read its source files and apply the
**Audit Checklist** (see `references/audit-checklist.md`).

**Key things to look for** (not exhaustive — use your judgment):

### 2-A  Stubs and unimplemented code
- `todo!()`, `unimplemented!()`, `panic!("not implemented")` macros
- Functions that always return a hardcoded `Ok(true)` / `false` / `0`
  without doing any real work
- Module-level doc comments that say "stub", "TODO", "Phase N", "not yet"
- `#[allow(dead_code)]` on whole modules or public API functions
- Traits with a `Default` impl that never connects to real I/O

### 2-B  Partial implementations
- Fields that are parsed and stored but never read downstream
- Config values that pass validation but are silently ignored at runtime
- Feature flags or match arms that have no dispatch path (fall-through
  to default behavior without surfacing an error)
- Background tasks / futures / timers that are created but immediately
  dropped (never `.await`ed or `.spawn()`ed into the runtime)

### 2-C  Logic conflicts
- A field's doc comment describing a default that contradicts the
  actual `Default` implementation
- Two match arms that produce contradictory behaviors for the same
  input condition
- A config value accepted at parse time that triggers an error at
  runtime (fail-at-boot vs. fail-at-request)
- Functions that accumulate a value without bounding it (overflow risk)
- Race conditions where two code paths generate the "same" token
  independently

### 2-D  Wiring gaps (cross-crate)
- A trait defined in `core` with a real implementation in `feature-crate`
  but the binary entry-point (`main.rs`) wires the Noop version
- Modules that are fully built and tested but have zero call sites in
  the request-handling hot path
- Audit sinks that accept events but never deliver them to the
  external system (in-memory buffer, no network call)
- Security checks that are bypassed by CAPTCHA/JWT/signature stubs

### 2-E  Contract violations
- API response shapes that contradict the project's interop contract doc
- Bulk-mode changes that silently destroy fine-grained overrides
- Password / credential rotation that does not invalidate live sessions
- Invariants stated in architecture docs (README, Requirement.md, etc.)
  that the code silently violates

---

## Step 3 — Write the findings

For every problem found, record:

| Field | What to write |
|-------|--------------|
| **ID** | `<CRATE_PREFIX>-NN` (e.g. `PROXY-02`, `SEC-07`, `CTL-19`) |
| **Severity** | Critical / High / Medium / Low — see ladder below |
| **Category** | `Not Implemented`, `Partial Impl`, `Logic Conflict`, `Contract Violation` |
| **Short Description** | One-line summary suitable for a table row |
| **File(s) + lines** | `crates/foo/src/bar.rs:42–55` |
| **Code snippet** | The problematic lines, trimmed |
| **Impact** | What breaks for an operator or end-user |
| **Suggested fix** | One concrete paragraph |

### Severity ladder

| Level | When to use |
|-------|-------------|
| **Critical** | A security control is completely bypassed (CAPTCHA always passes, JWT never verified, pipeline always no-ops). Stop — escalate. |
| **High** | A primary feature is silently broken or a config option crashes the process at boot. |
| **Medium** | A secondary feature is degraded, a config option is silently ignored, or a documented behaviour contradicts the code. |
| **Low** | Dead code, minor doc mismatch, suboptimal algorithm with no user-visible impact. |

---

## Step 4 — Write the report file

Read `references/report-template.md` for the exact file structure to
follow. Do not deviate from the section headings or table schema in
that template.

**Save the report to:**

```
<user-chosen-root>/reports/YYYY-MM-DD-runN/<RUN-ID>-<CRATE-SCOPE>-AUDIT.md
```

Where `<user-chosen-root>` is whatever the user (or Step 0-A) resolved.
Examples of what the full path might look like for different team members:

```
tests/my-tester/reports/2026-05-10-run5/MY-RUN-5-FULL-CRATE-AUDIT.md
qa/waf-audit/reports/2026-05-10-run1/WAF-RUN-1-PROXY-AUDIT.md
audit-reports/reports/2026-05-10-run2/AUDIT-RUN-2-SECURITY-AUDIT.md
```

**If the directory already exists, add the file there without
recreating the directory.  If the directory does not exist, create it.**

After saving, provide the user with a clickable link and a 6-8 line
summary covering: total findings, critical count, top 3 issues by
impact, and the recommended first fix.

---

## Step 5 — Cross-crate wiring table (always include)

After individual crate findings, build an end-to-end wiring table:

| Feature | Configured In | Implemented In | Wired Into Pipeline | Net Status |
|---------|--------------|----------------|--------------------|-----------| 
| JWT auth | config | auth/jwt.rs ✗ stub | route middleware ✓ | **Bypass** |
| CAPTCHA | config | challenge/captcha.rs ✗ stub | challenge flow ✓ | **Bypass** |
| SQLi detector | config | sqli/mod.rs ✓ | pipeline.rs ✗ | **Dead** |

Fill in one row per security-relevant feature. Use ✓ / ✗ in each cell.
Net status must be one of: `Working`, `Dead — not called`, `Bypass`,
`Stub`, `Silent drop`, `Logic conflict`.

---

## Anti-patterns — don't do these

- ❌ **Asking for the reports path when the user already stated it** (in
  this session, in a previous summarised session, or in the current prompt).
- ❌ **Inventing or hardcoding a path** like `tests/l-tester/` when the
  user hasn't specified one — always ask first.
- ❌ **Overwriting an existing run directory** — always increment the run number.
- ❌ **Filing "CRITICAL" for documented limitations** listed in
  `Implement-Progress.md` or similar carry-over docs.
- ❌ **Omitting the cross-crate wiring table** — it is the most
  actionable part of the report.
- ❌ **Writing prose findings without file:line references** — every
  finding needs a location.
- ❌ **Truncating the finding index table** — it must list every finding,
  not just the highlights.
- ❌ **Fabricating findings** you did not observe in the source. If you
  haven't read the file, say so and read it.

---

## Reference files

- `references/report-template.md` — exact section headings + table
  schema to use when writing the report file.  **Read before writing
  the report.**
- `references/audit-checklist.md` — per-category checklist to step
  through for each module.
