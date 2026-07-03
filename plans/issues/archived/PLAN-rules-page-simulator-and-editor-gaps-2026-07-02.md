# Rules page — simulator custom-rule support, syntax-help completeness, editor parity

**Status:** 🟢 P1–P5 shipped (TDD, `feat/rules-page-simulator-and-editor-gaps`, 2026-07-02)

Implementation notes vs. plan:
- P1 plumbing was already half-done: `services.active_ruleset` existed
  (`accept.rs:975`) — only the simulator-side wiring was missing.
- Discovered during P1: the v1 forward path enforces `block` ONLY
  (`data_plane.rs:2036-2042`) — challenge/rate_limit rules fall through.
  The simulator mirrors this and reports such matches with
  `enforced: false` rather than claiming a challenge verdict.
- P4's `/api/rules/validate` did NOT exist (the plan's F5 assumed it did —
  only the internal `validate_rule_body` fn existed); the endpoint was
  added as part of P4.
- P5 bundle check: develop's embedded app.js already contained the AI box
  (rebuilt 2026-07-01) — visibility was a parity/discoverability issue,
  not staleness.
- GeoIP finding: no caller wires `evaluate_with_ctx`, so `country`/`asn`
  rules match nothing on the live path today — documented honestly in
  `docs/operator/rules-dsl.md` (follow-up candidate).
**Date:** 2026-07-02
**Reported by:** Nico (screenshot: rule `rule-test` using `query_matches` + `body_matches`, detail Dsl view)
**Predecessor:** `plans/issues/archived/PLAN-rules-screen-ux-and-ai-gen-2026-06-21.md` (P1–P4 shipped)

---

## Findings (verified in code, 2026-07-02)

Each of the four reported observations was checked against `develop`. Verdicts:

### F1 — Syntax help omits `query_matches` (and much more) — ✅ CONFIRMED

`RULE_DSL_CHEATSHEET` (`assets/dashboard/src/pages.jsx:2652`) lists 8 conditions:

```
path_matches | ip_in | header_matches | method | host_matches | body_matches | all/any/not | true
```

The engine AST (`crates/aegis-security/src/rules/ast.rs:88-113`) supports **16**. Missing
from the cheatsheet:

- `query_matches { name, op }` ← the one in the screenshot
- `cookie_matches { name, op }`
- `jwt_claim { path, op }`
- `bot_class [..]`
- `threat_feed { id, min_confidence }`
- `schema_violation`
- `country [..]` / `asn [..]` (GeoIP-gated)

Also undocumented:

- The match-op forms themselves (`exact | prefix | suffix | contains | regex`,
  `ast.rs:53-59`) — the cheatsheet never shows that `header_matches`/`query_matches`
  need a nested `op:` map.
- The `raise_risk: <n>` action (`ast.rs:196`) — cheatsheet lists 5 of 6 actions.
- `docs/operator/rules-dsl.md`, referenced by the cheatsheet comment
  (`pages.jsx:2650`) as the "full reference", **does not exist** (checked
  `docs/operator/`). The rule-cookbook PR never happened.

### F2 — "✨ Generate with AI" not displayed — ⚠️ PARTLY CONFIRMED (parity + discoverability gap)

The feature is fully implemented end-to-end:

- UI: rendered **unconditionally** inside `NewRuleModal` (`pages.jsx:3403-3444`).
- Data layer: `rulesGenerate` → `POST /api/copilot/rule` (`data.jsx:1449`).
- Backend: `handle_copilot_generate_rule` (`aegis-proxy/src/admin_get.rs:1696`),
  dispatched at `admin_dispatch.rs:576`, server-validates the draft via
  `validate_rule_body` and returns 503 with a hint when copilot is off.

Why the operator doesn't see it:

1. **It only exists in the New-rule modal.** The Edit flow (detail → Dsl tab →
   Edit, `pages.jsx:3181-3207`) has **no** AI generate, **no** Syntax help, and
   **no** quick templates — just a bare textarea. The screenshot is the detail
   view, which is exactly where none of this surfaces.
2. **Possible stale embedded bundle.** The dashboard is compiled into the binary
   (`app.js` embedded — rebuild required to see JSX changes). Verify the running
   binary was built after 2026-06-21 (P4). If the modal genuinely lacks the AI
   box at runtime, the fix is a rebuild, not code.
3. **No disabled-state affordance.** When copilot is off the box still renders a
   live-looking Generate button; the operator only learns via a post-click 503
   toast. There is no upfront "copilot disabled — how to enable" state.

### F3 — Simulator does not evaluate custom rules — ✅ CONFIRMED (core defect)

`simulate()` (`aegis-control/src/api/simulator.rs:146-281`) runs **detectors
only**. It never calls `aegis_security::rules::evaluate`; the `RequestCtx` import
is literally consumed by a `PhantomData` marked "reserved for the rules-engine
integration in a follow-up" (`simulator.rs:268-270`). The module doc's claim that
"Both code paths share … `aegis-security::rules::evaluate`, so behaviour can't
drift" (`simulator.rs:27-28`) is **false today**.

So a `block` rule like the screenshot's `rule-test` shows `allow` in the
simulator no matter what — the page's own header says "validate before apply",
but the simulator can't validate the very artifacts the page manages.

Secondary gaps that block rule testing even after wiring:

- **Plumbing:** `DashboardServices` carries `detectors` for the simulator
  (`dashboard_services.rs:324-330`) but has **no ruleset handle**. The live
  ruleset lives on `upstream_ctx.active_ruleset` (data plane reads it at
  `data_plane.rs:1087-1100`); it must be shared to services in the `accept.rs`
  boot path exactly like `services.detectors`.
- **Inputs:** the simulator UI (`RuleSimulator`, `pages.jsx:2679`) exposes only
  method/path/body. The backend already accepts `host` + `headers`
  (`SimulateRequest`, `simulator.rs:44-66`) but the UI never sends them — so
  `header_matches`, `cookie_matches`, `jwt_claim`, `host_matches` rules can't be
  exercised. Peer IP is hardcoded `127.0.0.1:0` (`simulator.rs:200`), so
  `ip_in` / `country` / `asn` rules can never match.
- **Response shape:** `rule_id` in `SimulateResponse` is actually the first
  *detector* id (`simulator.rs:258`) — the name collides with real user-rule ids
  and will confuse output once rules are wired.
- **Semantics to mirror** (from the data plane): an explicit terminal
  `then: allow` rule match bypasses the detector chain
  (`data_plane.rs:1070-1103`, incl. the "evaluate defaults to Allow" footgun);
  `block`/`challenge`/`rate_limit` rules enforce on the forward path
  (`data_plane.rs:2071`); `log_only`/`raise_risk` are non-terminal. The
  simulator uses a synthetic global route, so route-scoped rules won't fire —
  must be surfaced in the UI, not silently ignored.

### F4 — No "save but not enable" — ❌ NOT CONFIRMED (exists; discoverability problem)

The New-rule modal **has** an "Enabled on save" checkbox
(`pages.jsx:3479-3482`, state `newEnabled`, default `true`), `createNew` sends
it (`pages.jsx:2987`), and the backend persists it
(`admin_mutate.rs::handle_rules_post` → `patch_rule_upsert(id, body, enabled)`).
`PUT /api/rules/{id}/toggle` also exists for flipping later.

So this is a **UX/visibility** issue (compounded by a possibly stale bundle —
same verification as F2): a small unchecked-by-default-looking checkbox at the
bottom of a long modal, below the fold once templates + AI + syntax help are
expanded, does not read as "save as draft".

### F5 — (found while auditing) No pre-save validation in the UI

`POST /api/rules/validate` exists on the backend (referenced at
`aegis-control/src/api/rules.rs:435`) and is used to validate AI drafts
server-side, but the dashboard never calls it for hand-typed bodies — YAML/DSL
errors only surface as a failed save toast. The editor should validate before
(or on) save and render inline errors.

---

## Phases

Ordered by operator impact. P1 is the substantive engine work; P2–P5 are
dashboard-side (JSX — remember: rebuild binary to see changes; `build.sh` runs
the acorn rules-of-hooks guard; hooks in `pages.jsx` are aliased `*P`).

### P1 — Simulator evaluates custom rules (correctness, backend)

1. Share the live ruleset handle: add
   `pub ruleset: Option<Arc<...ActiveRuleset...>>` to `DashboardServices`
   (default `None`, same pattern as `detectors`); wire it in the `accept.rs`
   boot path next to `services.detectors = Some(detectors)`.
2. Extend `simulate()` to mirror the data-plane order:
   - evaluate rules once via `rules::evaluate(&snapshot, &view, route)`;
   - explicit terminal `allow` rule match → decision `allow`, detectors skipped
     (report them as skipped, mirroring the whitelist-bypass contract);
   - `block` / `challenge` / `rate_limit` rule match → that decision wins
     (report the rule's action + status);
   - `log_only` / `raise_risk` → non-terminal: note the match, fall through to
     the detector-threshold decision (raise_risk adds to the score like the
     forward path does);
   - no rule matched → today's detector-threshold behavior (unchanged).
   - Guard the eval.rs footgun: "decision is Allow" alone is NOT an allow-rule
     match — check the matched rule's action is `RuleAction::Allow`
     (copy the `data_plane.rs:1087-1100` shape).
3. Response shape: add `matched_rule` (`{ id, action, terminal }`) and rename
   the existing detector-derived `rule_id` → keep it for back-compat but add
   `first_detector`; dashboard switches to the new fields.
4. Fix the module doc (`simulator.rs:21-28`) so it stops claiming rules are
   shared; drop the `PhantomData` hack.
5. Route scope: keep the synthetic global route for v1, but return
   `route_scoped_rules_skipped: [ids]` so the UI can say "N route-scoped rules
   not evaluated" instead of silently pretending they don't exist.

### P2 — Simulator input coverage (backend + UI)

1. Backend: add optional `peer_ip` to `SimulateRequest` (default `127.0.0.1`,
   parse-validated) so `ip_in` / `country` / `asn` / access-list-adjacent rules
   are testable. (`host` + `headers` already exist server-side.)
2. UI (`RuleSimulator`): add Host + peer-IP inputs and a headers editor
   (simple `Name: value` lines textarea → map), plus a hint row listing which
   rule conditions each input exercises.
3. UI: render the new `matched_rule` prominently (pill with the rule action +
   id), the route-scoped-skip note, and keep the detector panel as-is.
4. Optional (cheap): "Simulate" button on a selected rule's detail pane that
   jumps to the Simulator tab pre-filled with a request sketched from the
   rule's conditions.

### P3 — Syntax help completeness + DSL reference doc

1. Rewrite `RULE_DSL_CHEATSHEET` to cover **all 16 conditions** (grouped:
   request-shape / identity / advanced), **all 6 actions** (incl. `raise_risk`),
   the 5 match-op forms with a nested-`op` example (`header_matches` /
   `query_matches` / `cookie_matches` need it), and `scope`.
   Keep it a compact reference block — the modal pane already scrolls
   (`whiteSpace: pre; overflowX: auto`).
2. Write `docs/operator/rules-dsl.md` — the full reference the cheatsheet
   comment has promised since 2026-05-17: every condition/action with a copy-
   pasteable YAML example, evaluation order (priority, terminal vs non-terminal,
   allow-overrides-detectors contract), scope semantics, and the GeoIP/threat-
   feed prerequisites for `country`/`asn`/`threat_feed`/`bot_class`.
3. Add 1–2 templates using the nested-op conditions (e.g. "Block query param
   value" using `query_matches`) so the pattern is discoverable by click, per
   the existing keep-it-to-6 guidance.

### P4 — Editor parity + save-as-draft UX (UI)

1. Extract the Syntax-help disclosure + AI-generate box from `NewRuleModal`
   into shared components; mount both in the detail-pane **Edit** mode
   (`pages.jsx:3181-3207`) so editing an existing rule gets the same help.
2. Pre-save validation: call `POST /api/rules/validate` from Save (create and
   edit paths); on errors, keep the modal open and render them inline next to
   the body textarea (same style as the AI `aiNote`), instead of a failed-save
   toast after close. Keep server-side enforcement as the source of truth.
3. Save-as-draft clarity: move the enabled control up next to the Save button
   and make it explicit — e.g. Save button label switches
   `Save & enable` / `Save as draft (disabled)` based on the checkbox; after a
   disabled save, toast "Rule created (disabled — enable from the list)".
   The list already shows enabled state; no backend change needed.

### P5 — AI generate visibility (verification + polish)

1. **Verify first:** confirm the running binary embeds the P4 (2026-06-21)
   bundle — open New rule modal, check for the AI box. If absent → rebuild;
   report back before any code change.
2. Probe copilot enablement when the modal opens (existing enablement probe —
   the floating Copilot launcher already does this) and render the disabled
   state honestly: grayed Generate button + inline hint
   ("Copilot disabled — set LLM_ENABLED=true … --features llm"), instead of a
   post-click 503 toast.

---

## TDD

- **P1 (Rust, `simulator.rs` tests):**
  - block rule on matching path → `decision_action == "block"`, `matched_rule.id` set, status surfaced;
  - explicit allow rule + attack payload → `allow`, detectors skipped/reported;
  - `log_only` rule match → detector decision unchanged, match still reported;
  - `raise_risk` rule adds to score and can cross the tier threshold;
  - no-rules snapshot → byte-identical behavior to today (regression guard);
  - route-scoped rule → not evaluated, id listed in `route_scoped_rules_skipped`;
  - eval-default-allow footgun: unmatched request with rules present must NOT report an allow-rule match.
- **P2 (Rust):** `peer_ip` respected by `ip_in` rule; invalid `peer_ip` → 400.
- **P3/P4/P5 (JSX):** no runtime test harness exists for the dashboard — verify
  via `build.sh` (hook-guard + bundle), then manual browser pass; keep bundle
  budget in mind. Cheatsheet completeness can get a cheap Rust-side guard:
  a test asserting every `Condition`/`RuleAction` variant name appears in
  `docs/operator/rules-dsl.md`.

## Acceptance

- [ ] Simulating the screenshot's `rule-test` (POST + `?test=zxc` + body `ABC`) returns `block 403` with `matched_rule.id == "rule-test"`.
- [ ] An explicit `then: allow` rule suppresses detector blocks in the simulator, matching the data plane.
- [ ] Simulator can express header / query / peer-IP inputs from the UI.
- [ ] Syntax help lists all 16 conditions + 6 actions + 5 match ops; `docs/operator/rules-dsl.md` exists and is linked.
- [ ] Edit flow shows Syntax help + Generate with AI, same as New rule.
- [ ] Invalid DSL surfaces inline before the modal closes.
- [ ] Saving with "Save as draft" produces a disabled rule and says so.
- [ ] Copilot-off renders a disabled Generate affordance with an enable hint.
- [ ] `cargo test --workspace` green; dashboard `build.sh` (hook guard) green; no new warnings.

## Risks

- **Simulator/data-plane drift** (HIGH): the data plane evaluates rules in two
  places (allow-precheck `data_plane.rs:1087`, forward-path enforce `:2071`).
  Mitigate by reusing `rules::evaluate` + copying the exact allow-match guard,
  and encoding the contract in the P1 test list.
- **Ruleset handle plumbing** (MEDIUM): `DashboardServices` default must stay
  `None`-safe for test bundles (503/absent, like `detectors`); missing boot-path
  wiring = silent "no rules in simulator" — add a boot-wiring test mirroring the
  `apply_and_swap` structural-guard pattern if feasible.
- **Modal length** (LOW): P3+P4 add content to an already tall modal; keep
  disclosures collapsed by default (existing pattern) and consider moving the
  cheatsheet to a side-by-side layout only if it overflows at 90vw.
- **Stale-bundle confusion** (LOW): F2/F4 may partly evaporate after a rebuild —
  do P5.1 verification first so the plan isn't fixing phantoms.

## Estimated complexity: MEDIUM

- P1 backend + tests: ~half day
- P2: ~2-3 h
- P3: ~2-3 h (doc is the bulk)
- P4: ~3-4 h
- P5: ~1 h
