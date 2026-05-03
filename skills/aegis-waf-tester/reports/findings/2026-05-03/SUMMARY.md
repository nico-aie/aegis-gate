---
date: 2026-05-03T17:50Z
mode: full-qc (run 2)
duration: ~25 min, browser-driven
---

# 2026-05-03 — Aegis-Gate test run summary

```
Aegis-Gate test run complete · full-qc · ~25 min
Findings: 2 CRITICAL · 3 HIGH · 2 MEDIUM · 1 LOW · 2 INFO
Top blocker: SSRF detector blocks every request including clean GET / — false positives poison Top Attackers and the Attack-distribution donut. (#critical-ssrf-detector-blocks-all-traffic)
Reports: skills/aegis-waf-tester/reports/findings/2026-05-03/
Next suggested action: fix the SSRF detector AND the Investigation page typo (`useEffectW` → `useEffectP` at pages.jsx:5718). One is a 1-char patch; the other gates the central SOC workflow. Ship those, re-run this skill.
```

## What ran (this run, browser-driven via Claude in Chrome)

- **Pre-flight** — operator booted the WAF on their Mac
  (`make redis-up && make run-dev`); admin healthz `OK`,
  login renders.
- **Phase 1** — Auth via the form, sweep of 36 documented
  `/api/*` endpoints via in-page `fetch()`. **All 200.**
  Cookie pair (`aegis_session` + `aegis_csrf`) present.
- **Phase 2** — Drove 60 requests through the data plane
  (10 attacker IPs × 4 classes + 10 legit × 3 IPs × 2 paths).
  Cross-checked Top Attackers, by-detector, bot mix, audit feed.
  Several findings.
- **Phase 3** — CSRF gate fully validated (201 / csrf_missing_header /
  csrf_mismatch); blacklist enforcement confirmed (`reason: "blocked by blacklist"`);
  cleanup successful.
- **Phase 5 (UX)** — Click-through of Overview, Top Attackers,
  Pivot → Investigation, Live Feed, Audit Trail, Detectors.
  Screenshots captured, scenario scores recorded below.
- **Phase 7** — Replayed sqli / xss / ptrav / ssrf / recon /
  clean-GET probes and asserted `X-WAF-Rule-Id` per class.
  Detectors fire, but every probe also tags `ssrf` because the
  SSRF detector matches everything (see Critical #2).

## SOC-analyst UX scenario scoring

| Scenario | Score | Note |
|---|---|---|
| S1 "I just got paged" | 3/5 | Status badge "UNKNOWN" + "GitOps UNKNOWN" + "no members configured" all paint red on a healthy dev WAF. (Medium #1) |
| S2 "Who's attacking me?" | 2/5 | 127.0.0.1 ranks #1, three legit IPs (1.0.0.1, 9.9.9.10, 8.8.4.4) appear as risk-100 attackers because of the SSRF false positive. Pivot/Block UX itself is good. |
| S3 "What did this attacker do?" | 1/5 | Investigation page CRASHES (`useEffectW is not defined`). Pivot from Top Attackers updates URL but doesn't navigate. (Critical #1) |
| S4 Audit Trail | 4/5 | Hash-chained, filters work, request_id present, 145 events visible. -1 for the dual-write per block. |
| S5 Empty states honest? | 2/5 | Upstream card says "no members configured" while `/api/upstreams` says "Healthy 1/1". Block-rate "0.0% · 142 blocked total" reads as "100% blocked". (Medium #1) |

## Findings index

### CRITICAL
- [`critical-investigation-page-crash.md`](./critical-investigation-page-crash.md)
  — Investigation page never renders. One-character typo at
  `pages.jsx:5718` (`useEffectW` should be `useEffectP`). Kills
  the Pivot-to-investigate workflow.
- [`critical-ssrf-detector-blocks-all-traffic.md`](./critical-ssrf-detector-blocks-all-traffic.md)
  — SSRF detector matches every request. Clean `GET /` is
  blocked. Legitimate IPs appear in Top Attackers.

### HIGH
- [`high-by-detector-chart-mis-bucketed.md`](./high-by-detector-chart-mis-bucketed.md)
  — `/api/attacks/by-detector` buckets by *combination* of
  detector tags instead of by class. Donut legend shows `sqli`
  in two buckets, `ssrf` in five. Also: tag list contains
  duplicates (`path_traversal,path_traversal`); `?window=` is
  silently clamped to 900.
- [`high-audit-double-write-per-block.md`](./high-audit-double-write-per-block.md)
  — Every block writes two audit rows (peer-IP + XFF-IP).
  Counts double; loopback IP ranks #1 in Top Attackers.
- (the previous run's
  [`blocked-no-runnable-waf-binary.md`](./blocked-no-runnable-waf-binary.md)
  is still open — it's a tooling gap that prevents the skill
  from running self-contained in a Cowork sandbox; not a WAF
  bug.)

### MEDIUM
- [`medium-overview-status-noise.md`](./medium-overview-status-noise.md)
  — Status badges paint red on a healthy single-node dev WAF
  ("UNKNOWN", "GitOps UNKNOWN"). Block-rate card cumulative vs
  rate is confusing.
- [`medium-live-feed-no-backfill-on-mount.md`](./medium-live-feed-no-backfill-on-mount.md)
  — Live Feed shows "1 of 1 events" on a busy WAF; doesn't
  backfill from `/api/audit/since` on mount.

### LOW
- [`low-rule-id-prefix-and-skill-drift.md`](./low-rule-id-prefix-and-skill-drift.md)
  — `X-WAF-Rule-Id` carries `detector:` prefix; the SKILL.md
  Phase 2 + Phase 7 expectations are out of date.

### INFO
- [`info-csrf-flow-clean.md`](./info-csrf-flow-clean.md)
  — CSRF double-submit flow + blacklist enforcement passed.
- [`static-skill-code-alignment.md`](./static-skill-code-alignment.md)
  — Static fallback from earlier (skill ↔ code alignment).

## Recommended fix order

1. Fix `pages.jsx:5718` — one-character patch unblocks the
   Investigation page. Trivial. Add a Playwright smoke test
   that mounts every sidebar page and asserts no error
   boundary.
2. Fix the SSRF detector. Until that's done, Top Attackers
   is producing false positives at the rate of legitimate
   traffic.
3. Fix `/api/attacks/by-detector` aggregation to bucket by
   class, dedupe tags, and either honour `?window=` or echo
   the requested vs effective window.
4. Decide on the audit single-vs-double-write policy and pick
   one IP-key for downstream aggregation.
5. Soften the Overview red badges and reconcile the Upstream
   card with `/api/upstreams.state`.
6. Update SKILL.md to match the live `detector:` prefix and
   re-run.
