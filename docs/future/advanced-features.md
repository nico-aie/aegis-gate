# Phase B — advanced-features intake

> **Status:** Intake template — see [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

**Status:** open. Use this doc to propose, score, and triage candidate
features for the next major scope expansion. The current scope (P1–P8
plus the F-T1..F-T10 follow-up) is closed; this is the catch-basin for
"what's next".

If a request is accepted, it graduates out of this file:

1. A spec doc lands in the appropriate category folder
   (`data-plane/`, `security/`, `observability/`, etc.)
2. A planning track lands in [`../../plans/`](../../plans/)
3. `Implement-Progress.md` picks up its task IDs

## Proposing a feature

Open a section under [`### Candidates`](#candidates) below using this
template. Don't trim or skip sections — gaps are themselves signal
during triage.

```markdown
### <feature name>

- **Proposed by:** <name / role>
- **Date:** <YYYY-MM-DD>
- **Category:** <data-plane | security | control-plane | observability | operations>
- **Status:** proposed | under-review | accepted | rejected | parked

**Problem.**  
<2–4 sentences. What is the operator/user pain or compliance gap
this addresses? Reference real incidents, audit findings, or
customer asks where possible.>

**Proposed approach.**  
<Sketch — not a full design. Reference existing subsystems it would
touch. Call out anything that would require breaking changes.>

**Out of scope.**  
<What this proposal explicitly does NOT cover, so the conversation
doesn't drift.>

**Effort estimate.**  
<S / M / L / XL — and a one-liner why.>

**Risk.**  
<What could go wrong. Compliance? Performance? Migration burden?>

**Dependencies.**  
<Which deferred designs (e.g. RBAC, multi-tenancy) or upstream pieces
must land first.>

**Success metric.**  
<How will we know this worked, three months after shipping it?>
```

## Scoring rubric

When triaging, score each candidate on a 1–5 scale across four axes.
Total ≥ 14 → accepted. 10–13 → revisit next quarter. < 10 → reject or
park indefinitely.

| Axis | 1 | 3 | 5 |
|---|---|---|---|
| **Impact** | Nice-to-have | Helps a known customer / unlocks a use case | Blocks a known sale or compliance gate |
| **Reach** | One operator | Several operators | Every Aegis-Gate deployment |
| **Cost** | XL effort or major refactor | M effort, contained blast radius | S effort, isolated module |
| **Confidence** | Speculative | Backed by ≥ 1 user request | Hard data — incidents, audits, contracts |

A request that scores 5/5 on Impact but 1 on Confidence still goes to
"under-review" — collect evidence first.

## Triage cadence

- Open candidates are reviewed at the **start of every two-week
  iteration**.
- Accepted candidates move out of this file the same day.
- Rejected candidates stay here with a one-line reason — duplicates
  often resurface, and rejection rationale is load-bearing.

## Out-of-scope categories (default reject)

These aren't worth opening as candidates without a strong, specific
business case attached:

- "AI-detect anything" without a defined corpus + measurable lift
- Any change that breaks the FIPS / PCI / HIPAA mode invariants in
  [`../operations/compliance.md`](../operations/compliance.md)
- Features that require eBPF or kernel modules (consider an
  out-of-process agent instead)
- Anything that lands data in a third-party SaaS by default (see
  [`../operations/data-residency-retention.md`](../operations/data-residency-retention.md))

## Already-deferred designs

These are NOT candidates — they have full specs and are waiting on
prerequisites:

- [`multi-tenancy.md`](./multi-tenancy.md) — needs the operator-RBAC
  story to land first
- [`rbac-sso.md`](./rbac-sso.md) — needs an SSO target customer +
  OIDC integration spec sign-off

If a candidate below would need either of those, mark it under
**Dependencies** rather than re-litigating the design.

## Candidates

<!-- Add new proposals below. Newest first. -->

*(none yet — open the first one)*
