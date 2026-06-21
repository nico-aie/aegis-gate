# Rules screen — correctness fixes, UX cleanup, and AI rule generation

**Status:** 🟢 P1–P4 shipped (TDD, `develop`, 2026-06-21)
**Filed:** 2026-06-21
**Reporter:** pre-prod UX review of the Rules page
**Severity:** 🟡 Mixed — P1 is a correctness bug (id divergence), P2/P3 UX, P4 feature

## Findings (verified in code)

1. **Rule-id divergence (bug).** POST/PUT carry both a form `id` and a DSL
   `body` that has its own `id:`. The store keys by the **form id**
   (`admin_mutate.rs:2776` → `rule_def_yaml`), but the engine concatenates only
   each rule's **body** and matches/audits on the body's `id:`
   (`api/rules.rs:413` `rebuild_active_ruleset`; `rules/eval.rs:156`). Nothing
   validates they match → list shows `custom-block-ip` while the engine uses
   `block-bad-ips`.
2. **New rule doesn't auto-display.** Create reloads, but config activation
   propagates asynchronously (the POST's own note), so the immediate refetch
   races the rule store.
3. **Bogus/stub fields.** `Risk Δ +50` is a hardcoded frontend default
   (`pages.jsx:2748` `r.risk ?? 50`) — the rule model has no risk field; only
   `RuleAction::RaiseRisk(u32)` carries a delta, and `block` is terminal. And
   `hits/1h` is always 0 — `GET /api/rules` returns no hit count (real hits live
   on the unjoined `/api/rules/top`, keyed by body id). `priority` IS real
   (`eval.rs:131`, higher wins) — keep it.
4. **No AI assist.** Operators hand-write DSL. The Copilot provider layer
   (`copilot/service.rs`, `complete_guarded` redact→cost-guard→LLM) already
   exists and can generate DSL from a natural-language intent.

## Phases

### P1 — rule-id single source of truth (correctness)
- Backend: `validate_rule_id_matches_body(form_id, body)` in `api/rules.rs`
  (parse `Vec<ast::Rule>`, compare the first rule's `id:` to the form id);
  call it in `handle_rules_post` + `handle_rules_put` → 400 on mismatch.
- Frontend: auto-sync — rewrite the body's first `id:` to the entered Rule ID on
  template insert and before submit, so users don't trip the new validation.

### P2 — create auto-display (correctness)
- Frontend: after create, poll `/api/rules` (reload) until the new id appears
  (bounded retries) before clearing the modal, so the row shows without a
  manual reload.

### P3 — UX cleanup
- Remove the `Risk Δ +{risk}` badge (list + detail) — not a real field.
- **Hide `hits/1h`** (header + detail) — stub until a real join lands.
- Drop the vestigial merge placeholders (`field`/`op`/`pattern`/`cat`) that
  don't map to the freeform DSL.

### P4 — AI Copilot rule generation (feature)
- Backend: `copilot/rulegen.rs` — `render_rule_prompt(intent)` (DSL grammar +
  examples + intent) + a `CopilotService::generate_rule(intent)` reusing
  `complete_guarded`; strip markdown fences from the model output.
  New handler `POST /api/copilot/rule` `{ intent }` → `{ ok, body, validation }`
  (server-validates with `validate_rule_body`). 503 when copilot disabled.
- Frontend: "✨ Generate with AI" in the New-rule modal → intent box → call the
  endpoint → prefill the body editor (+ sync the id).

## TDD
- P1: `validate_rule_id_matches_body` — matches ok / mismatch flagged / empty
  body tolerated.
- P4: `render_rule_prompt` includes the grammar + intent; `strip_code_fences`
  unwraps ```` ```yaml ```` blocks; `generate_rule` with the mock provider
  returns the body.
- P2/P3 are frontend (esbuild validates; manual verify).

## Acceptance
- [ ] Creating a rule whose body id ≠ form id is rejected with a clear error;
      the synced form never trips it.
- [ ] A newly created rule appears without a manual reload.
- [ ] No `Risk Δ` badge; no `hits/1h` shown.
- [ ] "Generate with AI" produces a valid DSL body prefilled into the editor
      (when copilot enabled); graceful 503 message when disabled.
- [ ] Lib tests green; 0 warnings; bundle < 600 KB.
