# Plans

Cleaned up 2026-05-19. The top level holds tracking + reference
files only — every closed or paused plan lives in
[`archive/`](./archive/), and feature plans we've intentionally
deferred live in [`future/`](./future/).

## Layout

```
plans/
├── README.md                       ← this file (entry point)
├── plan.md                         ← AI-assistant guide for this repo
├── implementation-matrix.md        ← doc-by-doc Implemented / Partial / Designed status
├── future/                         ← deferred features (operator-confirmed, not yet built)
└── archive/                        ← closed / shipped / paused plans (read-only history)
```

## Active plans

None at top level. Pick up the next track from `future/` (each
file is self-contained — Status / Why deferred / Code anchor /
Future plan / Restoration checklist).

## Reference (kept at top level)

- [`plan.md`](./plan.md) — assistant protocol + repo conventions.
  Read this when picking up a new task.
- [`implementation-matrix.md`](./implementation-matrix.md) —
  status of every documented feature: Implemented / Partial /
  Designed / Deferred.

## `future/`

> **Start here:**
> [`world-class-waf-roadmap.md`](./future/world-class-waf-roadmap.md) —
> the **ordering document**. It grades Aegis against the 2025–2026 WAAP
> leaders (Cloudflare / Akamai / Imperva), names the code-verified gaps,
> and sequences them into Tiers 0–6. The files below are the per-feature
> specs; the roadmap says which to do next and why. **Read it before
> picking up anything in `future/`.**

The roadmap groups the work as (effort: S ≤ ~3 d · M ~1–2 wk · L ~3 wk+):

| Tier | Theme | Existing spec(s) here |
|---|---|---|
| **0** | Hygiene (2 red tests; H3 wire-up before enabling) | `unwired-stubs-catalog.md` |
| **1** | **API security** (Gartner #1 — guards wired → schema → discovery → BOLA/BFLA) | *new* |
| **2** | **AI/LLM firewall** (prompt-injection / output inspection) | *new* |
| **3** | **Client-side protection** (Page Shield, PCI DSS 4.0.1) | `compliance-profiles.md` |
| **4** | **Bot enforcement + ATO** | `bot-classifier-enforcement.md`, `rule-non-block-actions.md`, `risk-composite-key-data-plane.md` |
| **5** | ML positive-security learning | *new* |
| **6** | Managed ruleset / virtual patching | *new* |
| **Ops** | Operator value, interleave by capacity | `alerts-refactor.md`, `audit-log-disk-growth.md`, `audit-cold-tier-export.md`, `smart-caching.md` |

Per-feature specs (each captures Status / Why deferred / Code anchor /
plan / checklist):

- [`bot-classifier-enforcement.md`](./future/bot-classifier-enforcement.md)
  *(Tier 4A)* — wire the dead classifier buckets (reverse-DNS → `verified`,
  JS-pass → `human`) + per-class `action_mapping`. **Drafted 2026-05-21,
  not started.**
- [`risk-composite-key-data-plane.md`](./future/risk-composite-key-data-plane.md)
  *(Tier 4, support)* — finish the JA4 device-FP axis of the composite-key
  risk bucket. Storage + most sites landed. **Tracked, partial.**
- [`rule-non-block-actions.md`](./future/rule-non-block-actions.md)
  *(Tier 4, support)* — rule actions beyond block/log (challenge, tarpit,
  mirror). **Drafted, not started.**
- [`compliance-profiles.md`](./future/compliance-profiles.md) *(Tier 3,
  support)* — per-regime detector pinning + clamp enforcement
  (FIPS / PCI / SOC 2 / GDPR / HIPAA). Modes parse + surface as doc tags
  today; the lock is a no-op until the pin list is repopulated.
  **Deferred 2026-05-10.**
- [`alerts-refactor.md`](./future/alerts-refactor.md) *(Ops)* —
  operator-useful alerting; VipTalk-first. Non-SLO event classes, rich
  chat payload + deep-link, dedup, per-severity routing, ack/silence.
  Phase 1 ≈ 2 d. **Drafted 2026-05-20, designed only.**
- [`audit-log-disk-growth.md`](./future/audit-log-disk-growth.md) *(Ops)* —
  `./waf_audit.log` grows ~6 GB/min under attack flood (soak-measured).
  Contract §6 forbids in-run rotation, so the fix is disk guard +
  between-run rotation tooling. **Drafted 2026-05-20, designed only.**
- [`audit-cold-tier-export.md`](./future/audit-cold-tier-export.md) *(Ops)* —
  scheduled long-tail audit exports (S3 / SFTP) beyond the 200-event ring.
  **Drafted, not started.**
- [`smart-caching.md`](./future/smart-caching.md) *(Ops)* — opt-in
  in-memory LRU response cache; flips `X-WAF-Cache: HIT/MISS` from the
  always-`BYPASS` baseline. Phase 1 ≈ 3 d. **Drafted 2026-05-19,
  designed only.**
- [`unwired-stubs-catalog.md`](./future/unwired-stubs-catalog.md)
  *(reference)* — running catalogue of types/traits built but not yet
  wired to the data plane (ICAP, per-route quota, traffic mirror, JWT,
  OPA, vendor CAPTCHA, H3, …). The Tier-0/Ops wire-up backlog.

> **Adding a future plan**: new file in `future/<short-slug>.md`
> with sections "Status / Why deferred / Code anchor / Future
> plan / Restoration checklist". Mirror `smart-caching.md`. If it's a
> net-new capability, also slot it into a tier in
> `world-class-waf-roadmap.md`.

## `archive/`

Closed plans kept for history. Files are individual feature
tracks that shipped or paused; subfolders bundle related work:

- [`archive/issue-fix/`](./archive/issue-fix/) — QA-driven fix
  plans (run-by-run; tester-n + tester-l + page-audit + DDoS
  internal audit).
- [`archive/phase-b-2026/`](./archive/phase-b-2026/) — Phase B
  production-packaging tracks (B1..B6).
- [`archive/multi-node-deployment/`](./archive/multi-node-deployment/) —
  multi-node proposal awaiting SA Team answers (paused, not
  rejected). Move to `future/` if a revisit is scheduled.
- [`archive/dashboard-enterprise/`](./archive/dashboard-enterprise/) —
  D-M1..D-M6 (superseded by DD-T\*).

Top-level archive files (one per shipped track, in alphabetical
order): `ai-assistant-testing-kickoff.md`, `ai-detector.md`,
`benchmark-mode.md`, `binary-handover-fd-pass.md`,
`cluster-ingress-lb.md`, `console-api-integration.md`,
`console-config-pages.md`, `console-fixups.md`, `console-qa.md`,
`console-soc-refactor.md`, `control.md`, `dashboard-redesign.md`,
`followups-rollback-and-sans.md`, `hackathon-readiness.md`,
`hackathon-stress-test.md`, `interop-contract.md`,
`interop-dry-run.md`, `mtls.md`, `post-k6-followup.md`,
`post-run-08.md`, `proxy.md`, `proxy-refactor.md`,
`scaling-config.md`, `security.md`, `tcp-forwarder-phase-4.md`,
`websocket-bridge.md`.

For the implementation log of what's shipped, see
[`../Implement-Progress.md`](../Implement-Progress.md).

## Working with plans

When picking up new work:

1. **Search `archive/` first** — existing-feature context is
   usually there.
2. **Check `future/`** — if the feature is deferred, the
   restoration checklist tells you what changes are needed.
3. **Active multi-step work** — drop a plan in `plans/`
   directly (e.g. `plans/<feature>.md`); promote to
   `archive/` once the work ships.
4. **Don't restart `archive/`** — closed plans are reference;
   if you need to extend old work, write a new plan that
   references the archived one.

## Recent cleanups

- 2026-05-28 — added `future/world-class-waf-roadmap.md` (market scan
  vs WAAP leaders + code-verified gap analysis + Tier 0–6 ordering);
  reordered the `future/` index by tier; archived two **completed**
  tracks — `cluster-config-sync-and-scaling.md` (Phases 0/A/B/C/D all
  shipped) and `multi-node-metrics-aggregation.md` (Phase C shipped) —
  into `archive/`, repointing the live links. Refreshed stale entries in
  `unwired-stubs-catalog.md` (`rules::evaluate` is now wired at
  `data_plane.rs:1630`; HTTP/2 rapid-reset cap shipped).
- 2026-05-20 — memory soak (73k RPS): fixed AttacksAggregator
  count cap (`MAX_EVENTS`) in code; drafted
  `future/audit-log-disk-growth.md` for the 9 GB/90s audit-log
  growth (contract §6 forbids in-run rotation).
- 2026-05-20 — drafted `future/alerts-refactor.md` (VipTalk-
  focused alert mechanism refactor: non-SLO event classes,
  rich chat payload + dedup, per-severity receiver routing,
  ack/silence history).
- 2026-05-19 — moved 13 closed issue-fix sprints (2026-05-11
  → 2026-05-18) into `archive/issue-fix/`; archived shipped
  `dns-upstream-resolution.md` (hickory-resolver + multi-A
  expansion landed); flipped smart-caching matrix row from
  Implemented to Deferred (TierCache removed 2026-05-11);
  drafted `future/smart-caching.md`.
- 2026-05-10 — folded ~25 top-level shipped plans into
  `archive/`; moved `issue-fix/`, `phase-b/`,
  `multi-node-deployment/` into `archive/`. Top level now
  has README + `plan.md` + `implementation-matrix.md` +
  `future/` + `archive/` only.
- 2026-05-10 — created `future/compliance-profiles.md`
  alongside the lock-by-mode deferral.
