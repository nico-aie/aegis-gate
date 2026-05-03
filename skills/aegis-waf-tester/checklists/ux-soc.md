# UX checklist — SOC analyst lens

Pretend you're a SOC analyst on day 1. You opened the dashboard
because an alert fired. Your job: find out what happened, decide
what to do, and act.

For each scenario, walk it as that analyst and rate the experience
on a 1-5 scale (5 = effortless, 1 = frustrated). File a finding
for any score ≤ 3 with concrete repro + suggested fix.

## S1 — "I just got paged. What's happening right now?"

Path: open dashboard → first thing you see is **Overview**.

- [ ] Within 5 seconds of the page rendering, can the analyst tell:
      (a) is the WAF up? (b) is traffic flowing? (c) is anything
      blocked? (d) are there active SLO alerts?
- [ ] Are the headline numbers (RPS, block %, p99) live and
      correct?
- [ ] Is there an obvious "go deeper" affordance for each
      headline? (e.g. block % → Live Feed filtered to blocks)

## S2 — "Who's attacking me?"

Path: Overview → **Top Attackers**.

- [ ] Default view shows attackers ranked by hits (not alphabetical).
- [ ] Each row shows enough context (IP, country, ASN, detectors
      fired, last seen) to make a triage call without clicking.
- [ ] One-click pivot into Investigation works.
- [ ] One-click block adds the IP to the blacklist with
      confirmation, lands an audit-chain entry, removes the row
      on next refresh.

## S3 — "What did this specific attacker do?"

Path: Top Attackers → click a row → **Investigation** filtered
to that IP.

- [ ] The pivot lands with the IP pre-filled and the audit
      timeline populated. No empty state, no spinner stuck.
- [ ] Click any row in the timeline → drawer shows:
      - method + path
      - status code (colour-coded: green ≤3xx, yellow 4xx, red 5xx)
      - latency
      - detection reason
      - request_id + audit chain hash
      - "Copy as cURL" + "Block IP" + "Whitelist" actions
- [ ] The "Pivot to Investigation" link in the drawer is wired
      (no-op in pivot mode is acceptable).

## S4 — "Wait, what just changed?"

Path: any page → **Audit Trail**.

- [ ] Recent mutations (mode toggle, blacklist add, detector
      change) show up within 3 seconds.
- [ ] Each entry shows actor + timestamp + request_id + hash chain.
- [ ] Search by `actor` / `rule_id` / `request_id` works.
- [ ] Hash-chain integrity is visible (a broken chain reads
      as broken; not silently OK).

## S5 — "Is this WAF healthy?"

Path: **Health & SLOs** + **Performance**.

- [ ] Health page shows live readiness, leader status, Redis
      health, certificate expiry — not stub values.
- [ ] Performance page renders RPS / block ratio / latency
      sparklines. If no traffic flowed yet, the empty state
      says so honestly ("no traffic in last 1h", not "0 RPS"
      that looks like real data).
- [ ] Latency p50/p95/p99 are reported with units.

## S6 — "I need to see what configuration is live."

Path: **Settings** + **Routing & Upstreams** + **Detectors**.

- [ ] Each surface reflects the running config (not the
      template / default config).
- [ ] Hot-reload from disk surfaces in the dashboard within 10 s
      with a visible diff or version bump.
- [ ] "What detector classes are pinned by my compliance mode?"
      is answerable in one click on the Compliance page.

## S7 — Empty states + first-light

Path: fresh `make run-dev` boot, no traffic yet.

- [ ] Overview reads "No traffic yet — try `make mock-load`" or
      similar; doesn't show fake numbers.
- [ ] Live Feed shows "Awaiting events…" not a stuck spinner.
- [ ] Top Attackers, Threat Intel, Audit Trail, Reports — each
      has an honest empty state with a concrete "what unlocks
      this" hint.

## S8 — Friction audit

Walk every sidebar entry. For each:

- [ ] Page title matches the sidebar label.
- [ ] No required action is hidden behind hover-only UI on a
      laptop trackpad.
- [ ] Destructive actions (block IP, delete rule, change mode)
      have a confirmation dialog with the right verb.
- [ ] Toasts surface success + failure clearly; no silent
      failures.

## S9 — Accessibility quick-pass

- [ ] Tab order on the login page reaches the submit button.
- [ ] Form errors are announced (`role="alert"` or `aria-live`).
- [ ] Pill colours have a non-colour signal (text + icon, not
      just hue) so colour-blind operators aren't blocked.
- [ ] Page works at 200% zoom without horizontal scrolling.

## S10 — Copy + microcopy

- [ ] No raw rule_ids leaked into UI without a friendly label
      (e.g. `csrf_missing` should appear as "CSRF token missing"
      somewhere in the UI, not just the raw code).
- [ ] Error messages say what to do next, not just what's broken.
- [ ] Empty-state copy points at the next action ("run X" or
      "configure Y in cfg/Z.yaml").
