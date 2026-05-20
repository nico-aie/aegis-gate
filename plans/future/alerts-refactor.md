# Alerts refactor — operator-useful alerting (VipTalk-first)

> **Status (2026-05-20): Phase 1 core + Phase 2 dedup + Phase 3
> severity routing SHIPPED; producers + dashboard UI + Phase 4
> deferred.** Branch `feat/alerts-refactor-viptalk`.
>
> **What shipped:**
> - `AlertEvent` enum (`crates/aegis-control/src/slo.rs`)
>   subsuming `SloAlert` + 10 non-SLO variants, with
>   `severity()` / `fired_at()` / `fingerprint()`.
> - `dispatch_event(event, receivers, dedup)`
>   (`slo/dispatch.rs`) with severity routing + dedup gate;
>   `send_alert` kept as a back-compat wrapper.
> - `AlertDedupCache` (5-min default window, configurable;
>   `(+N suppressed)` note on re-emit).
> - `AlertSeverity::Info` variant + `AlertReceiver.severities`
>   filter (empty = all; serde-default so existing configs are
>   unchanged).
> - `format_event_text(event, suppressed)` — per-variant VipTalk
>   chat formatting.
> - SLO eval task (`accept.rs`) now dispatches through
>   `dispatch_event` with a process-lifetime dedup cache, so a
>   multi-tick burn breach fires VipTalk once instead of every
>   30 s.
> - 6 new unit tests (severity matrix, receiver filter, dedup
>   window + fingerprint distinctness, event formatting).
>
> **What remains (Phase B — needs boot-path plumbing):**
> - Producers for the 9 non-SLO variants. Each needs an
>   `AlertEvent` sender threaded from `run.rs` into the
>   subsystem (ddos.rs, upstream/health.rs, listener/tls.rs
>   cert poll, risk/tracker.rs, supervisor.rs, gitops poll,
>   audit chain-verify, cluster leader watcher). The enum
>   variants + formatting are ready; only emission sites are
>   missing. **Recommended: an `mpsc::UnboundedSender<AlertEvent>`
>   + one consumer task in the admin loop reusing the same
>   dedup cache + receiver list.**
> - Dashboard severity-filter multiselect on the Tracking page
>   receiver editor (Phase 3 UI half).
> - Phase 4 (alert history + ack/silence).
> - `cfg.slo.dedup_seconds` config knob (today the cache uses
>   the hard-coded 5-min default; wire it to config).
>
> Original design below — kept for the deferred phases.

## Why

The current alert path is correct but narrow. An operator
running Aegis-Gate in front of real traffic gets:

- **Two alert sources only** — SLO burn-rate on
  `DataPlaneAvailability` + `AuditDeliveryRate`. The audit log
  already records DDoS-mode flips, strike-block surges, leader-
  lost, cert near-expiry, GitOps drift, hot-reload failure — but
  none of them fan out to VipTalk.
- **Sparse message body** — `SloAlert` carries SLI, severity,
  burn rate, budget %, runbook URL. No top contributing
  `rule_id`s, no sample `request_id`s, no dashboard deep-link
  for the window.
- **No dedup / silence** — a 5-minute burn-rate breach can fan
  the same alert to VipTalk on every evaluation tick.
- **No severity routing** — every receiver in
  `cfg.slo.receivers[]` gets every alert. An operator who has
  both an on-call room and a low-priority audit room can't say
  "Page → on-call, Ticket → audit".
- **External-receiver kinds are dead weight** — Slack /
  PagerDuty / Alertmanager / ServiceNow / Jira variants exist in
  `ReceiverKind` but `send_alert` only hands them to an
  external dispatcher. Operators not running Alertmanager
  silently get no alerts for those.

VipTalk is the project's default and the only end-to-end
delivery surface today, so the highest-leverage refactor is to
make it the rich, multi-source, deduped operator surface — and
leave the other `ReceiverKind` variants as documented
extension hooks rather than first-class delivery targets.

## Why deferred

- Not contract-required. v2.5 §5–§6 mandate observability
  headers + audit log; alerting is operator-facing polish.
- The current SLO path is correct and the VipTalk dispatcher
  has good fundamentals (SSRF-safe path composition, timeout,
  honest `DispatchSummary` buckets). Building on it is purely
  additive.
- Real operator pressure shows up post-judging when a deploy
  has been running for ≥ 1 week and the on-call wants to know
  about DDoS mode flips without watching the dashboard.

## Code anchor

- `crates/aegis-control/src/slo.rs` — `SloAlert`,
  `AlertReceiver`, `ReceiverKind`, `default_receivers()`,
  `default_objectives()`.
- `crates/aegis-control/src/slo/dispatch.rs` —
  `send_alert(alert, receivers) → DispatchSummary`,
  `send_viptalk(bot_token, room_ids, alert)`,
  `format_alert_text(alert)`. Behind `aegis-control/alerts`
  feature.
- `crates/aegis-control/src/api/alert_receivers.rs` —
  audit-mutated CRUD + `POST /api/alert-receivers/{name}/test`
  preview endpoint.
- `crates/aegis-control/src/dashboard_services.rs:130-147` —
  `alert_receivers` + `alert_receivers_store` (ArcSwap'd) +
  `alert_receivers_ring` (dispatch outcome history).
- `crates/aegis-control/assets/dashboard/src/data.jsx:958` —
  `useAlertsApi` (read `/api/alerts`) + lines 1190+
  receiver-CRUD helpers (Tracking page).
- `crates/aegis-control/assets/dashboard/src/pages.jsx:243-289` —
  Overview "firing alerts" callout consumer.

## Future plan

### Phase 1 — Multi-source event router (VipTalk-only delivery)

**Scope:** introduce an `AlertEvent` enum that subsumes
`SloAlert` and the operationally-important non-SLO classes;
route every variant through the existing
`send_alert(receivers)` path with VipTalk as the only real
delivery kind. Other `ReceiverKind` variants keep their
`external` bucket behaviour — no scope creep.

**New types in `slo.rs` (or a new `crates/aegis-control/src/alerts/`):**

```rust
pub enum AlertEvent {
    Slo(SloAlert),                          // existing
    DdosModeEntered { trigger: String, observed_rps: u32 },
    DdosModeCleared { duration_seconds: u64 },
    StrikeBlockSurge {
        unique_ips: u32, window_seconds: u32, top_rule_ids: Vec<String>,
    },
    UpstreamPoolDegraded {
        pool: String, healthy: u32, total: u32, first_down: String,
    },
    UpstreamPoolRecovered { pool: String },
    CertExpiringSoon { host: String, days_remaining: u32, not_after: DateTime<Utc> },
    LeaderLost { previous_leader: String, our_node: String },
    HotReloadFailed { reason: String, last_known_good_version: u64 },
    GitOpsDrift { repo: String, expected: String, observed: String },
    AuditChainBreak { last_good_seq: u64, observed_seq: u64 },
}

pub trait AlertSeverityFor {
    fn severity(&self) -> AlertSeverity;   // Page | Ticket | Info (new)
}
```

Add an `Info` severity variant for cleared / informational
events so the dispatcher can keep the lower-priority room out
of paging traffic.

**Producers:**
- `crates/aegis-security/src/ddos.rs` — emit
  `DdosModeEntered` / `DdosModeCleared` from the spike-detection
  ticker.
- `crates/aegis-security/src/risk/tracker.rs` — emit
  `StrikeBlockSurge` from the same hot path that already stamps
  `risk-strikes` rule_ids when the count crosses N within W.
- `crates/aegis-proxy/src/upstream/health.rs` — emit
  `UpstreamPoolDegraded` / `…Recovered` from the active health-
  check loop.
- `crates/aegis-proxy/src/listener/tls.rs` — emit
  `CertExpiringSoon` from the daily cert-inventory poll.
- `crates/aegis-control/src/cluster/leader.rs` (or equivalent) —
  emit `LeaderLost` when the lease holder watcher flips.
- `crates/aegis-proxy/src/supervisor.rs` — emit
  `HotReloadFailed` from the reload path that already keeps the
  old config live.
- `crates/aegis-control/src/gitops/poll_driver.rs` — emit
  `GitOpsDrift` on the existing drift detection.
- `crates/aegis-core/src/audit.rs` — emit `AuditChainBreak`
  from the chain-verify helper on hash mismatch.

**Dispatcher changes:**
- Rename `send_alert(alert, …)` → `dispatch_event(event, …)`;
  keep the old function as a thin wrapper for one release.
- `format_alert_text(event)` becomes an `impl AlertEvent`
  method returning per-variant Markdown-ish text suitable for
  VipTalk chat.
- Every variant carries a `runbook_url: Option<&'static str>`
  pointing at the right page in
  `docs/operator/runbooks/*.md` (a new directory; one runbook
  per event class).

**Acceptance:**
- DDoS spike → VipTalk message arrives within 5 s with
  `[Page] DDoS gate entered enforce — 1840 rps observed, top trigger: cumulative-risk`.
- Cert 14 days from expiry → daily `[Ticket] cert
  api.example.com expires 2026-06-03 (14 days)` to the audit
  room only (severity routing — see Phase 3).
- Audit chain break → `[Page] audit chain break at seq 18342`
  + runbook URL.

### Phase 2 — Rich VipTalk payload + dedup

**Scope:** build out `format_alert_text` so an operator can act
without opening the dashboard, plus a short suppression window
so the same fingerprint doesn't refire on every evaluation tick.

**Rich payload (VipTalk only — uses chat-friendly formatting):**
```
[Page] StrikeBlockSurge — 27 unique IPs blocked in 60s
Top rules: sqli (14), ai (8), path_traversal (5)
Sample request IDs:
  • req_01HF8...A2 — 203.0.113.7 — /login
  • req_01HF8...B9 — 198.51.100.4 — /search
Dashboard:
  https://waf-host/dashboard/#/audit?from=2026-05-20T11:30Z&to=2026-05-20T11:31Z
Runbook: https://waf-host/dashboard/#/help/strike-block-surge
```

The dashboard deep-link is a stable URL pattern shipped from
the WAF (no external link shortener). The runbook URL points
into the in-tree dashboard help page so it works without
internet.

**Dedup:**
- Per-event `fingerprint() -> u64` (blake3 of variant tag +
  load-bearing fields — e.g. for `CertExpiringSoon`,
  `(host, not_after_day)`; for `DdosModeEntered`, `(observed_rps_bucket)`).
- 5-minute LRU in `DispatchSummary`'s parent struct
  (`AlertDedupCache`): if the fingerprint fired in the last
  5 minutes, increment a count and skip delivery. The next
  fire after the window resends with a `(+N suppressed)` suffix.
- `cfg.slo.dedup_seconds` (default 300, range 0–3600). 0 =
  disabled (preserves today's behaviour for ops that rely on
  every tick).

**Acceptance:**
- 10 consecutive StrikeBlockSurge fires within 60 s → 1 VipTalk
  message; minute-6 fire → `(+9 suppressed)` in the message.
- VipTalk message under 3 KB (well within chat limits) with
  the rich payload above.
- Dashboard deep-link opens the Audit Trail page with the
  correct time-window filter pre-applied.

### Phase 3 — Per-severity receiver routing

**Scope:** `AlertReceiver` gains an optional
`severities: Vec<AlertSeverity>` filter; the dispatcher only
hands an event to a receiver whose filter contains the event's
severity. Default behaviour (empty filter) = receive all
severities — preserves today's behaviour.

**Config shape:**
```yaml
slo:
  receivers:
    - name: oncall-pager
      severities: [Page]
      kind:
        VipTalk:
          bot_token: "${secret:env:AEGIS_VIPTALK_BOT_TOKEN_ONCALL}"
          room_ids: ["!oncall-room:matrix.viptalk.org"]
    - name: audit-feed
      severities: [Ticket, Info]
      kind:
        VipTalk:
          bot_token: "${secret:env:AEGIS_VIPTALK_BOT_TOKEN_OPS}"
          room_ids:
            - "!ops-room:matrix.viptalk.org"
            - "!audit-room:matrix.viptalk.org"
```

**Dashboard:** the Tracking page receiver editor gets a
multiselect for severities. Test-send endpoint
(`POST /api/alert-receivers/{name}/test`) is updated to
respect the filter and report "skipped: severity not in
filter" in `DispatchSummary`.

**Acceptance:**
- Page-class event → only `oncall-pager` delivered.
- Ticket-class event → only `audit-feed` delivered.
- Receiver with no `severities:` block → unchanged (gets
  everything).

### Phase 4 — Alert history + ack/silence

**Scope:** ring-buffered `AlertHistoryStore` (last 200 events)
with `acked_at: Option<DateTime>` and `silenced_until:
Option<DateTime>` per event fingerprint. Operator UI on the
Tracking page shows the history; per-row Ack + Silence-for-15m
buttons (audit-mutated POSTs).

The store is in-memory only in this phase. Cluster-wide
silence syncs through Redis when the multi-node deploy lands
(`plans/archive/multi-node-deployment/`).

**Acceptance:**
- Acked alert renders dimmed in the Tracking history.
- Silenced fingerprint doesn't refire for the silence window
  (audit event records who silenced + reason).

## Restoration checklist

When this plan is picked up:

1. **Confirm VipTalk-only scope is still correct.** If the
   operator now also wants Slack delivery, fold a `send_slack`
   sibling into Phase 1 — keep the same `dispatch_event`
   surface.
2. **Decide on `Info` severity.** Adds a third variant to
   `AlertSeverity` (which serialises to JSON across the API);
   confirm no consumer panics on unknown variants.
3. **Wire the producers BEFORE building the new VipTalk
   payload format.** Cheap event sites (DDoS, upstream
   health, leader-lost) are 5–10 LoC each. Land them first
   so Phase 2 has real data to format against.
4. **Don't break the `external` bucket semantics.** Existing
   operator-side dispatchers reading `cfg.slo.receivers[]`
   still need to see Slack / PagerDuty / Alertmanager
   variants in the list — Phase 1 doesn't touch that
   contract.
5. **Update `Implement-Progress.md`** when each phase ships.
   Smart-caching status row → Deferred pattern works here.

## Effort estimate

| Phase | Est. LoC | Est. days |
|---|---|---|
| 1 — `AlertEvent` enum + producers + dispatch_event | ~450 | 2 |
| 2 — rich VipTalk payload + dedup cache | ~300 | 1.5 |
| 3 — severity routing config + dashboard UI | ~250 | 1 |
| 4 — alert history + ack/silence | ~400 | 2 |
| Tests (per-producer + dedup + routing) | ~350 | 1.5 |
| Operator runbooks (`docs/operator/runbooks/*.md`) | ~200 | 0.5 |
| **Total** | **~1950** | **~8.5 days** |

## Out of scope

- Slack / PagerDuty / Alertmanager / ServiceNow / Jira real
  delivery. Those `ReceiverKind` variants keep their current
  "descriptive metadata for an external dispatcher" semantics.
- Email / SMS receivers. Add a separate `ReceiverKind::Email`
  if requested.
- Webhook signatures (HMAC-signed outbound) — VipTalk's bot
  API doesn't need them; revisit when adding non-chat
  receivers.
- Alert grouping across event classes (one VipTalk message
  covering DDoS + StrikeBlockSurge for the same window).
  Useful but UX-intensive; defer.

## Related work / cross-references

- `archive/post-k6-followup.md` — original VipTalk wire-up
  side-quest that landed the bot delivery.
- `archive/issue-fix/2026-05-17-control-core-security-audits/` —
  F-CRITICAL-015 hardened the VipTalk path against
  bot-token SSRF; that work stays load-bearing here.
- `future/audit-cold-tier-export.md` — alert history could
  feed the cold-tier export once it ships.
- `future/multi-node-metrics-aggregation.md` — cluster-wide
  silence sync depends on the same Redis layer.
