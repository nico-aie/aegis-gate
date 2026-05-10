# Phase 4 — LOW fixes (rerun)

> **Branch:** all changes target `develop`.

---

## NEW-5 · `challenge_at: 99998` default makes challenge tier permanently dead

**Source:** Run-2 §2 NEW-5.

### Verified state (2026-05-08, on `develop`)

`config/dev.yaml:145-153`:

```yaml
risk:
  ...
  thresholds:
    # Score-based block threshold raised so legit-user VUs sharing
    # 127.0.0.1 with attacker traffic from `make mock-load` don't
    # cross it within seconds. Production uses 40/80/100 (see
    # config/profiles/prod-balanced.yaml). Detector-driven blocks
    # still fire — they don't need a high score.
    challenge_at: 99998
    block_at:     99999
    max:          100
```

The comment explains *why* the values are large (multi-VU shared-IP testing) but doesn't make explicit that the **challenge tier is therefore disabled in dev**. The QA's complaint is fair: a reader of the config sees `challenge_at: 99998` next to `max: 100` and has to do mental arithmetic to realise it's intentional.

The QA also flagged a leftover `QA-TEMP: lowered to test challenge engine (restore to 99998 after)` line. **Verified absent** as of 2026-05-08 — `dev.yaml` shows `99998` cleanly. No commit needed for that part.

### Plan

**Step 1 — replace the cryptic comment with an explicit "disabled" call-out.**

```yaml
# config/dev.yaml:145
risk:
  ...
  thresholds:
    # Challenge tier is INTENTIONALLY DISABLED in dev. The values
    # below sit far above `max: 100` so `level()` always returns
    # `Allow` (or `Block` if `block_at` is reached, which is also
    # impossible at max=100). Detector-driven blocks still fire
    # independently of these thresholds — they don't go through
    # `level()`.
    #
    # Why: dev runs with shared-IP traffic (one source IP for many
    # k6 VUs), so a low challenge_at would cause legit-user VUs to
    # share strikes with attacker VUs and trigger spurious 429s.
    # Production uses challenge_at=40 / block_at=80 / max=100 (see
    # config/profiles/prod-balanced.yaml).
    #
    # To enable the challenge tier in dev, set BOTH challenge_at
    # and max to a sane pair (e.g. challenge_at=40, max=100) and
    # restart the WAF — or PUT /api/risk/thresholds via the
    # dashboard's Settings → Cumulative IP risk thresholds card
    # (now hot-reload-aware after NEW-1 fix lands).
    challenge_at: 99998       # disabled — see comment above
    block_at:     99999       # disabled — see comment above
    max:          100
```

**Step 2 — same kind of "disabled" hint on the strike block-at if it's unreasonably high.**

`block_at: 1000000` for strikes is also intentionally high; one-line comment update:

```yaml
strikes:
  block_at: 1000000   # disabled in dev (shared-IP friendly); prod uses 50
```

**Step 3 — no code changes.** Pure config doc improvement.

### Acceptance

- [ ] `config/dev.yaml` documents the disabled-in-dev intent inline
- [ ] No QA-TEMP comments remain (verified: there were none on develop as of 2026-05-08; if any leaked, drop them)
- [ ] No behavior change

**Effort:** ~10 min.

---

## S7 · "Why is my SLO red?" UX (3/5)

**Source:** Run-2 §4 SOC scenarios — S7 scored 3/5.

> "SLO widget shows 39.67% but doesn't explain why. No drilldown to identify the AI FP as the cause. Analyst must cross-reference attack logs manually."

### Plan

When `data_plane_availability` (or any SLO objective) drops below threshold, the Health & SLOs page should surface a **root-cause hint** linking to the most likely culprit's filtered audit view.

The hint should be derived, not hard-coded. The simplest signal: top blocked-traffic detector class over the same time window the SLO covers.

**Step 1 — extend the dashboard's Health & SLOs card to compute a hint.**

```jsx
// crates/aegis-control/assets/dashboard/src/pages.jsx — Health & SLOs section
// When an SLO is below target:
const breaking = sloRows.filter(r => r.actual_pct < r.target_pct);
if (breaking.length > 0) {
  // Pull the top-detector for the SLO's window from /api/attacks/by-detector
  const byDet = window.useAttacksByDetectorApi
    ? window.useAttacksByDetectorApi(60 * 60)  // 1h window
    : { data: null };
  const topDetector = (byDet.data?.by_detector || [])
    .sort((a, b) => (b.blocks ?? 0) - (a.blocks ?? 0))[0];

  // Render hint
  if (topDetector) {
    return (
      <div className="callout warn">
        <strong>{breaking.length} SLO{breaking.length === 1 ? '' : 's'} below target.</strong>
        {' '}Top blocking detector in this window: <code>{topDetector.detector}</code>
        {' '}({topDetector.blocks} blocks). View the audit:
        {' '}<a href={`#/audit?detector=${encodeURIComponent(topDetector.detector)}`}>
          Audit Trail filtered to {topDetector.detector} →
        </a>
      </div>
    );
  }
}
```

**Step 2 — no backend change.** The endpoints already exist (`useAttacksByDetectorApi` is wired today).

**Step 3 — manual verification.**

```sh
# With the AI detector enabled (or any over-firing detector):
# 1. Drive synthetic clean traffic for ~5 min via make mock-load
# 2. Observe Health & SLOs page
# 3. SLO drops below 99.9%, hint appears: "Top blocking detector: ai (N blocks). Audit Trail filtered to ai →"
# 4. Click the link — Audit Trail page mounts with detector=ai filter active
# 5. Operator sees: "Oh, AI is over-firing on /api/list etc." in 5 seconds, not 5 minutes
```

### Acceptance

- [ ] Health & SLOs page surfaces a root-cause hint when an SLO is below target
- [ ] Hint links to the Audit Trail filtered to the top blocking detector
- [ ] Hint disappears cleanly when the SLO recovers
- [ ] No new API endpoints; reuses `/api/slo` + `/api/attacks/by-detector`

**Effort:** ~50 min. Dashboard-only.

---

## Sequencing

NEW-5 first (10 min, doc-only). S7 second (50 min, dashboard-only).

One PR: `fix(misc): challenge_at default doc + SLO root-cause hint (NEW-5 + S7)`.

---

## Out of scope for this round

- Per-deployment AI calibration tooling
- Scheduled report delivery (mentioned in M007 follow-ups)
- Multi-step / human-interaction CAPTCHA challenge (PoW is sufficient for the v2.3 contract)
- `/api/audit?detector=...` query-param wiring if it doesn't exist today — fall back to a client-side filter on the Audit Trail page (it already supports detector filtering via the existing UI controls)
