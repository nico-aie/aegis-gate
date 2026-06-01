# Next-step candidates — 2026-06-01

> **Purpose:** a shared snapshot of what we could pick up next, with
> enough trade-off context for a team discussion. Underlying ordering
> doc: [`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md).
> This doc is the **tactical "this week"** view; the roadmap is the
> **strategic "this quarter"** view.
>
> Dated so it expires honestly — if you're reading this past
> 2026-06-15, check `git log` for a newer candidate list before
> trusting these choices.

## State as of today (cluster + AI threshold landing)

What shipped this past week:

- **Cluster config plane** — track CLOSED 2026-05-27 (Phase 0+A+B+C+D)
- **AI `confidence_threshold` adjust** — shipped 2026-05-28 (`e77d379`)
- **AI threshold live-propagate** — shipped 2026-05-31 (`6db09b1`), closes the cross-node + post-restart gap
- **n-tester QC suite** — shipped 2026-05-31 (`3b5c350`); 12 tests, 9 pass / 0 fail / 3 expected skips; QC rounds 1–2 closed (note: `plans/issue-fix/n-tester-2026-05-29-cluster-ai-rounds-1-2/`)

Implication for picking next: the **test safety net is hot** for the cluster + AI surfaces, and the team has momentum on test infra. That favours either capitalising on the test infra (sweep deferred polish) or starting a new feature now that there's a regression net.

Tier-0 hygiene is **partly** clear — the two pre-existing red tests (`state_select::in_memory_selects_…` reaper panic, `dashboard_polish` JS-budget) are unchanged.

---

## Candidates by bite-size

### A · Quick wins — ≤ 1–2 days each

| ID | Candidate | Where it lives | Effort | Why pick |
|---|---|---|---|---|
| **A1** | Close R2-009 sub-A + sub-B (deferred UI polish from QC): render the AI-row threshold input read-only with cfg default in feature-off state; add `aria-disabled` + `title=` + `cursor:not-allowed` on the disabled Enable button | `plans/issue-fix/n-tester-2026-05-29-cluster-ai-rounds-1-2/README.md` → "Deferred" section | S | Closes the last open QC items; keeps the suite honest at 9/0/3 |
| **A2** | Fix the 2 pre-existing red tests — `state_select::in_memory_selects_in_memory_backend` reaper panic (`crates/aegis-proxy/src/state/in_memory.rs:40`); `dashboard_polish` JS-bundle-budget (app.js > 444 KB) | Tier 0 of roadmap | S–M | Gets `cargo test -p aegis-bin` fully green; unblocks Tier-0 sign-off |
| **A3** | Finish JA4 device-FP axis in the composite-key risk bucket (~50 LoC + a JA4 hash helper) | [`risk-composite-key-data-plane.md`](./risk-composite-key-data-plane.md) | S | Partial since boot; tiny finishing move; lifts a "Partial" row in the implementation matrix |
| **A4** | `threat_intel::check_domain` subdomain walk — ~6 LoC, makes feed entries for `evil.com` actually catch `c2.evil.com` | [`unwired-stubs-catalog.md`](./unwired-stubs-catalog.md) → "Domain threat-intel" | S | Smallest real correctness win on the books |

### B · Medium tracks — 1–2 weeks

| ID | Candidate | Where it lives | Effort | Why pick |
|---|---|---|---|---|
| **B1** | **Tier 1A — wire existing API-security guards** (`api_keys`, `hmac_sign`, GraphQL guard) onto the request path behind a per-route `api_security` policy | [`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md) Tier 1A | M (mostly wire-up) | **Gartner #1 buyer priority** for WAAP; code is built and dormant; lays the call-site for 1B / 1C / 1D. Highest leverage on the board. |
| **B2** | **Tier 2A — prompt-injection / jailbreak detection** on bodies routed to LLM endpoints; heuristic-first, then embedding-based via the existing `ai` model infra | Tier 2A | M | Hot 2025–2026 category; **net-new differentiator**; reuses AI infra already shipped |
| **B3** | **Bot-classifier enforcement** — FCrDNS reverse-DNS → `verified`, JS-pass → `human`, per-class `action_mapping` | [`bot-classifier-enforcement.md`](./bot-classifier-enforcement.md) | S–M | Plan already written; classifier ships observational; this puts it on the request path |
| **B4** | **`alerts-refactor` Phase 1** — non-SLO event classes (DDoS mode, leader lost, hot-reload fail, …), rich chat payload + dedup, per-severity receiver routing | [`alerts-refactor.md`](./alerts-refactor.md) | M (~2 d Phase 1) | High operator value; pure ops polish; no product-shape risk |
| **B5** | **ICAP content scanning wire-up** — built module gets an `OutboundAction::Abort` rung between DLP and pass-through | [`unwired-stubs-catalog.md`](./unwired-stubs-catalog.md) → "Content scanning — ICAP" | M | Platform AV-ready; the module already exists |

### C · Large tracks — 3+ weeks

| ID | Candidate | Where it lives | Effort | Why pick |
|---|---|---|---|---|
| **C1** | **Tier 1B + 1C — OpenAPI positive enforcement + API discovery** (assumes B1 is done) | Tier 1B + 1C | L | The full API-security story. Schema upload per route + passive endpoint learning + shadow/zombie surfacing |
| **C2** | **Tier 3 — Client-side / Page Shield (PCI DSS 4.0.1)** — CSP report endpoint + script inventory + integrity baseline + drift alerts | Tier 3 | M–L | **Compliance-forced** since 2025-03-31 (§6.4.3 + §11.6.1). Worth jumping the queue if any tenant has PCI in scope |
| **C3** | **Tier 4C — Credential-stuffing / ATO defense** — breached-credential check (HIBP k-anonymity range API), impossible-travel, login-endpoint protection | Tier 4C | M | Builds on `brute_force` + `velocity_sequence`; covers a top attack class with no current coverage |
| **C4** | **Tier 6 — Managed ruleset / virtual patching feed** — port OWASP CRS into the rule DSL with a signed auto-update channel | Tier 6 | M–L | Adds a curated managed-signature surface; rides the GitOps + TAXII plumbing already in the codebase |

### D · Strategic but speculative — months, not weeks

- **Tier 5 — ML positive-security learning** — auto-learn per-route param profiles → suggested rules an operator can promote. Biggest "modern WAF" lift but heaviest work; deferred until at least Tier 1 + Tier 3 are landed.

---

## Trade-off matrix

| ID | Effort | Market value | Momentum fit | Closes existing debt | Net-new vs polish |
|---|---|---|---|---|---|
| A1 | XS | low | ★★★ | yes | polish |
| A2 | S  | low | ★★  | yes | polish |
| A3 | S  | low | ★★  | yes | polish (Partial → Done) |
| A4 | XS | low | ★★  | yes | polish (correctness) |
| B1 | M  | **★★★ (Gartner #1)** | ★★ | partial (wires built code) | mixed |
| B2 | M  | **★★★ (hot 2025–2026)** | ★ | no | net-new |
| B3 | S–M | ★★ | ★★ | partial | net-new feature, plan ready |
| B4 | M  | ★★ (operator value) | ★★ | yes | polish |
| B5 | M  | ★ | ★ | yes (built-but-dormant) | wire-up |
| C1 | L  | ★★★ | ★ | no | net-new (after B1) |
| C2 | M–L | ★★★ (compliance) | ★ | no | net-new |
| C3 | M  | ★★ | ★ | no | net-new |
| C4 | M–L | ★★ | ★ | no | net-new |

**Reading the columns:**
- **Momentum fit:** how well it capitalises on the test infra + cluster work just shipped. ★★★ = obvious next step from current context.
- **Closes existing debt:** does it tick off something already on the books (Partial in the matrix, deferred QC item, red test)?

---

## My recommendation (open to override)

> **A1 → B1 sequence.** Spend an afternoon closing R2-009 sub-A + sub-B
> (test infra still warm, sub-day work), then start **Tier 1A · wire
> the API-security guards** as the next medium track. A1 closes the
> last QC-open items; B1 ships Gartner's #1 buyer priority on dormant
> code that already exists.

Alternative shape for different appetites:

- **"Single bold move"** — skip A1 polish, go straight to **B1**.
- **"Completionist warmup"** — do **A1 → A2 → A3 → A4** in sequence (all sub-day, closes 4 debts), then re-pick from the medium track later.
- **"Compliance-forced"** — if any tenant has a PCI deadline, **C2** jumps the queue regardless of momentum.
- **"Net-new differentiator"** — go straight to **B2** (LLM firewall) if the product narrative needs a flashy 2026 category.

---

## How to use this doc

1. Read the candidate table. Disagree freely.
2. Pick one (or a sequence). Comment with rationale.
3. Once agreed, the chosen ID becomes the next `Implement-Progress.md` → "Next Task" header. This doc gets archived when the work starts.

If nothing here lands well, the bigger backlog is in
[`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md) — these
candidates are the subset that look right *this week*.
