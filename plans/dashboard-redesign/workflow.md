# Claude-Design Workflow

> **Purpose.** Define a deterministic, repeatable process for
> driving a single dashboard milestone (M0..M10) from
> requirements → design → implementation → ship using Claude
> as the design + frontend collaborator. Every milestone in
> [`README.md`](./README.md) is executed by walking these
> stages in order. The prompts below are ready to copy-paste.

## Tool selection

You will use two Claude surfaces. Each shines at different
stages — pick deliberately, not by habit.

| Surface | Best for | Why |
|---|---|---|
| **claude.ai web** (with Artifacts) | stage 1 (design brief), stage 4 (screenshot review) | Live preview of HTML/CSS in the artifact pane; vision input for screenshots; long context window for the full design contract. |
| **Claude Code CLI** (this tool) | stage 2 (design critique), stage 3 (implementation), stage 5 (test wiring) | File-system access; can edit `.js`/`.css`/`.html` in place; runs `cargo test --workspace` and the `tests/api/*.sh` smoke layer between iterations. |

Switching surfaces mid-milestone is fine. Keep the design
brief output of stage 1 as a single markdown file under
`plans/dashboard-redesign/<milestone>.brief.md` so both
surfaces share an authoritative reference.

## The five stages

```
  Stage 1                  Stage 2                  Stage 3                  Stage 4                Stage 5
  ┌──────────┐             ┌──────────┐             ┌──────────┐             ┌──────────┐           ┌──────────┐
  │  Design  │   brief.md  │  Critique │   v2.md     │   Impl   │   diff     │  Visual  │   notes   │   Tests  │
  │  brief   │ ──────────▶ │   + a11y  │ ──────────▶ │   in     │ ──────────▶│  review  │ ────────▶ │  + ship  │
  │          │             │   review  │             │   place  │             │  (vision)│           │          │
  └──────────┘             └──────────┘             └──────────┘             └──────────┘           └──────────┘
   claude.ai                Claude Code              Claude Code              claude.ai              Claude Code
```

### Stage 1 — Design brief (claude.ai web)

**Input:** the page's design contract at
`docs/control-plane/enterprise/pages/<page>.md`, the API contract
section for the relevant endpoints from
`docs/control-plane/enterprise/api.md`, the milestone's plan file
under `plans/dashboard-redesign/pages/<id>.md`, and the
foundation-level tokens from
`plans/dashboard-redesign/design-system.md`.

**Output:** one self-contained brief saved to
`plans/dashboard-redesign/<id>.brief.md`. The brief replaces
discussion-level prose with concrete decisions: layout
sketch (ASCII or artifact), copy, color decisions, motion
decisions, empty/loading/error states.

**Prompt template** (copy-paste verbatim into a fresh
claude.ai conversation; replace the placeholders):

```text
You are a senior product designer redesigning one page of a
WAF control plane. Output exactly one document in the
attached format — no preamble, no follow-up questions.

CONTEXT — read these in order:
- design contract:    [paste content of docs/control-plane/enterprise/pages/<page>.md]
- API contract:       [paste relevant section of docs/control-plane/enterprise/api.md]
- design tokens:      [paste plans/dashboard-redesign/design-system.md]
- milestone scope:    [paste plans/dashboard-redesign/pages/<id>.md]

DELIVERABLE — produce a markdown document with these sections,
in this order, no others:

1. Page purpose (1 sentence + 3 user goals)
2. Information density target (rows-per-screen estimate)
3. Layout sketch (ASCII frame, 12-column grid)
4. Per-region copy + interactions (one heading per region)
5. Empty state, loading state, error state, stale-data state
6. Accessibility decisions (focus order, ARIA roles, motion)
7. Dark + light specifics (only deltas vs the token set)
8. Out of scope (what this page deliberately doesn't do)

CONSTRAINTS:
- Honour every endpoint listed in the API contract; do not
  invent new ones.
- Honour the design tokens; do not introduce new colors,
  type sizes, or spacing values without naming the new token
  in §7.
- Bundle budget: this page's JS module must stay under 32 KB
  raw (per `tests/dashboard_polish.rs::individual_pages_…`).
- Anti-template: no shadcn-default, no centered-headline +
  gradient-blob hero, no card grids with uniform spacing.
  See `~/.claude/rules/web/design-quality.md` for the banned
  patterns.

If a decision can't be made from the inputs alone, state the
gap explicitly under "Open questions" and pick a defensible
default.
```

Save the output to `plans/dashboard-redesign/<id>.brief.md`.
This file is the contract for stages 2–5.

### Stage 2 — Critique (Claude Code CLI)

**Input:** the brief from stage 1.

**Output:** a `<id>.brief.md` revised in place + an
acceptance-checklist comment block at the top.

**Prompt template** (paste into Claude Code with the brief
file open in the workspace):

```text
Read plans/dashboard-redesign/<id>.brief.md.

Critique the brief against three lenses:
1. **Accessibility (WCAG 2.2 AA).** Focus order, color
   contrast (compute against the actual tokens in
   design-system.md), motion-reduce paths, keyboard reach
   for every documented interaction.
2. **Operator workflow.** For each user goal in §1, walk the
   path through the layout. Flag any goal that takes more
   than three clicks or requires reading the same data twice.
3. **Anti-template.** Score the page against the 10 required
   qualities in `~/.claude/rules/web/design-quality.md` —
   how many of them does the brief land?

Apply your fixes directly to the brief — don't write a
separate critique document. Add a fenced block at the very
top of the file listing the acceptance checklist so the
implementation stage can verify against it later.
```

### Stage 3 — Implementation (Claude Code CLI)

**Input:** the revised brief + the existing component
inventory at
`crates/aegis-control/assets/dashboard/components/`.

**Output:** the page module, supporting CSS, any new
components, plus a structure test under
`tests/dashboard_polish.rs` if a new asset path is added.

**Prompt template:**

```text
Read plans/dashboard-redesign/<id>.brief.md and treat the
acceptance checklist at the top of that file as the
hard contract.

Implement the redesign by editing
`crates/aegis-control/assets/dashboard/pages/<page>.js`
and any supporting CSS in
`crates/aegis-control/assets/dashboard/aegis.css`.

Rules:
- Reuse existing components from
  `crates/aegis-control/assets/dashboard/components/` when
  one fits. If a new component is justified, create it
  there with a matching `mount(el, props)` /
  `update(state, props)` / `destroy(state)` shape so it
  composes with the existing pages.
- Hot path: do NOT introduce a new framework. Stay on
  vanilla ES modules with dynamic imports.
- Hard budget: the page module must stay under 32 KB raw
  per `tests/dashboard_polish.rs::individual_pages_each_under_per_file_budget`.
  Total bundle stays under 700 KB raw per
  `bundle_under_documented_budget`.
- Audit: every mutating call MUST go through the existing
  `aegis_csrf` cookie + `X-CSRF-Token` header pattern. No
  endpoint that isn't already in
  `docs/control-plane/enterprise/api.md`.
- Tests: after editing, run
  `cargo test -p aegis-control --lib dashboard` and
  `cargo test --test dashboard_polish` and report the diff
  in test counts.

Do NOT touch anything outside
`crates/aegis-control/assets/dashboard/` and the polish-test
file.
```

### Stage 4 — Visual review (claude.ai web with vision)

**Input:** screenshots at three breakpoints (1920, 1440,
1280) and both themes (dark + light) — six images. Take them
with a real browser pointed at a running gateway.

**Output:** one bullet list of follow-up items applied back
in stage 3.

**Prompt template:**

```text
You are reviewing six screenshots of one dashboard page —
1920 / 1440 / 1280 widths, in both light and dark themes.

Compare against this brief: [paste brief.md]

For each screenshot, answer:
1. Does the layout match the brief's sketch?
2. Are any tokens off? (color contrast, spacing, type scale)
3. Are interactive states (hover, focus, active) discernible?
4. Anything that screams "Tailwind default" / "shadcn out of
   the box"?

Output: one numbered list of fixes, each tagged with the
breakpoint + theme it applies to. Do NOT describe what's
already correct — only what needs fixing.
```

Apply each fix back in stage 3 (Claude Code) and re-screenshot.

### Stage 5 — Tests + ship (Claude Code CLI)

**Input:** the in-place page module from stage 3 +
acceptance checklist from stage 2.

**Output:** test additions, a clean `cargo test --workspace`
+ `cargo clippy --workspace -- -D warnings` run, and a
`tests/api/<id>.sh` smoke or `tests/e2e/dashboard/<id>.spec.ts`
playwright spec for the user-facing journey.

**Prompt template:**

```text
The redesign of page <id> is in. Wrap it for ship:

1. Add a structure test if a new asset filename was
   introduced (mirror the existing
   `tests/dashboard_polish.rs` patterns).
2. Add or extend the API smoke at
   `tests/api/<endpoint>.sh` if the page exercises an
   endpoint not yet covered there.
3. Update `docs/control-plane/enterprise/pages/<page>.md` if any
   of the design decisions diverged from the contract —
   keep doc and code in sync.
4. Run, in this order:
     cargo test -p aegis-control
     cargo test --test dashboard_polish
     cargo clippy --workspace -- -D warnings
   Report any deltas. If anything fails, fix and re-run.
5. Update `Implement-Progress.md` with a "Last Completed"
   entry summarising what landed for this milestone.
```

## Anti-patterns to refuse

When Claude (in any stage) drifts toward these, push back —
they're the difference between "designed" and "Tailwind
default":

- A centered-hero layout with a gradient blob behind it.
- A 3- or 4-column card grid with uniform padding for
  unrelated metrics.
- Dropdowns or modals when a side drawer would keep the
  caller's context visible.
- Color used decoratively rather than semantically.
- Generic "Settings", "Manage", "Configure" copy.
- A theme toggle that re-uses the same hue with different
  brightness — both themes need *intentional* palettes.

## Per-milestone checklist

Use this table when running through a milestone end-to-end:

| Stage | Tool | Output | Pass criteria |
|---|---|---|---|
| 1 | claude.ai web | `<id>.brief.md` | All 8 sections filled; no open question without a defensible default |
| 2 | Claude Code | revised brief | Acceptance block at top of file; ≥7 of the 10 design-quality bullets land |
| 3 | Claude Code | page module + CSS edits | `cargo test -p aegis-control` green; per-file < 32 KB; bundle < 700 KB |
| 4 | claude.ai web | fix list | Both themes look intentional, not auto-derived |
| 5 | Claude Code | tests + progress entry | `cargo test --workspace` green; clippy clean; new test added |

If any stage fails, do NOT skip ahead. Loop within that
stage until it passes.
