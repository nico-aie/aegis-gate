---
id: 2026-05-17-medium-bundle-aegis-control-audit
date: 2026-05-17T00:00Z
severity: MEDIUM
area: multiple
component: per-item — see Component line
interop_contract: latent / posture / fragility
status: open
test_mode: source-review
---

# F-MEDIUM bundle — ~30 MEDIUM-grade findings from the aegis-control audit

Grouped by domain. Each item small, latent, fragility-class, or
operator-edge.

---

## Audit chain + sinks

### M-01 · `chain.rs::serde_json::to_string(event).unwrap_or_default()` poisons chain on serialization failure
**Component:** [audit/chain.rs:26](aegis-gate/crates/aegis-control/src/audit/chain.rs#L26)
On serde failure, the canonical hash is computed over `""` — chain-poisoning. Practically never fires today but the fallback is a sharp edge. Propagate the error.

### M-02 · `chain.rs::hex_encode` reimplemented locally
**Component:** [audit/chain.rs:97-102](aegis-gate/crates/aegis-control/src/audit/chain.rs#L97-L102)
`hex` crate already in dep tree. Local impl is a maintenance footgun (collides with the crate name).

### M-03 · `jsonl.rs::write_event` two separate `write_all` calls (line + `\n`)
**Component:** [audit/sinks/jsonl.rs:262-264](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L262-L264)
Not atomic — a torn write leaves a half-line that verifier reports as ParseError. Combine into a single buffer write.

### M-04 · `jsonl.rs::resolve_dir` heuristic broken for directories with `.` in name
**Component:** [audit/sinks/jsonl.rs:111-117](aegis-gate/crates/aegis-control/src/audit/sinks/jsonl.rs#L111-L117)
`/var/log/aegis.audit/` (directory) misclassified as file. Use `metadata().is_dir()`.

### M-05 · `syslog.rs` emits HOSTNAME / PROCID / MSGID as `-` (NIL)
**Component:** [audit/sinks/syslog.rs:280](aegis-gate/crates/aegis-control/src/audit/sinks/syslog.rs#L280)
RFC-tolerated but breaks ArcSight's source-host filtering. Stamp `gethostname()` + `std::process::id()`.

### M-06 · `splunk_hec.rs::HecConfig::token` is plain `String`
**Component:** [audit/sinks/splunk_hec.rs:8-13](aegis-gate/crates/aegis-control/src/audit/sinks/splunk_hec.rs#L8-L13)
Leaks into Debug logs via `#[derive(Debug)]`. Wrap in `SecretString` / custom Debug.

### M-07 · `leef.rs` separator may not match QRadar 2.0 default
**Component:** [audit/sinks/leef.rs:13](aegis-gate/crates/aegis-control/src/audit/sinks/leef.rs#L13)
Uses literal `\t`. Verify against QRadar docs; pin with comment.

### M-08 · `interop/audit.rs::MinimalJsonlSink::open` sync but called from async context
**Component:** [interop/audit.rs:67-77](aegis-gate/crates/aegis-control/src/audit/audit.rs#L67-L77)
Sync open is once-at-boot so OK; flag for consistency.

### M-09 · `audit/mod.rs::AdminChangeEntry::to_audit_event` sets `client_ip: String::new()`
**Component:** [audit/mod.rs:33](aegis-gate/crates/aegis-control/src/audit/mod.rs#L33)
Empty string makes IP-based audit filtering on admin events silently no-op. Use `"127.0.0.1"` or `"<admin>"` sentinel.

### M-10 · `verify.rs` reads full file into RAM
**Component:** [aegis-bin/src/main.rs:492-524](aegis-gate/crates/aegis-bin/src/main.rs#L492-L524)
CLI verifier loads multi-GB audit files via `std::fs::read_to_string`. Stream via `BufReader::lines()`.

---

## Read API

### M-11 · Audit `render_since_filtered` cache only when `filter.is_empty()`
**Component:** [api/audit.rs:386-423](aegis-gate/crates/aegis-control/src/api/audit.rs#L386-L423)
Operator using filter chips gets zero cache benefit. Document or add `(cursor, limit, filter_fingerprint)` keyed cache.

### M-12 · `attacks::detector_name` doesn't include `:` in split separators
**Component:** [api/attacks.rs:633-673](aegis-gate/crates/aegis-control/src/api/attacks.rs#L633-L673)
`split(['-', '/']).next()` for rule_id prefix. `blocklist:abuse-ch:1.2.3.4` returns `blocklist:abuse` (label pollution).

### M-13 · SSE `parse_class` silently drops unknown class values
**Component:** [dashboard/sse.rs:64-72](aegis-gate/crates/aegis-control/src/dashboard/sse.rs#L64-L72)
`?class=detect` (typo) → empty result, opaque. Echo `parsed_filter` in preamble or 400 on unknown.

### M-14 · `filters.rs::insert_pruned` O(n) under mutex
**Component:** [api/filters.rs:111-127](aegis-gate/crates/aegis-control/src/api/filters.rs#L111-L127)
`map.retain` + `min_by_key` per record() at 5k RPS = 10k ops per event. Use reverse-index for cheap-min eviction.

### M-15 · `stats::snapshot` rate-math always divides by 10s window
**Component:** [api/stats.rs:204-225](aegis-gate/crates/aegis-control/src/api/stats.rs#L204-L225)
Reads artificially low on cold-start. Document or use actual window-elapsed.

### M-16 · `tracking::render_cert_renew` always 405
**Component:** [api/tracking.rs:626-634](aegis-gate/crates/aegis-control/src/api/tracking.rs#L626-L634)
UI shows "Renew" button. Hide the button when cert provider unwired or actually trigger ACME.

### M-17 · `access_log.rs::format_template` no escape on operator-templated variables
**Component:** [access_log.rs:32-71](aegis-gate/crates/aegis-control/src/access_log.rs#L32-L71)
Attacker-supplied UA `; rm -rf /;` breaks downstream JSON parsers. Document or per-variable escape.

### M-18 · `access_log.rs::AccessLogWriter::write` uses Mutex on hot path
**Component:** [access_log.rs:92-101](aegis-gate/crates/aegis-control/src/access_log.rs#L92-L101)
Under high concurrency serializes every request. Switch to `DashMap` or channel-based writer.

### M-19 · `dashboard/assets.rs` no asset size validation
**Component:** [dashboard/assets.rs:90-97](aegis-gate/crates/aegis-control/src/dashboard/assets.rs#L90-L97)
README mentions 612 KB cap on `app.js`; not enforced. Add `const_assert!`.

---

## Mutation API

### M-20 · `blacklist::EntryHitRing` broken under wall-clock backward jump
**Component:** [api/blacklist.rs:34-104](aegis-gate/crates/aegis-control/src/api/blacklist.rs#L34-L104)
NTP correction can mark all buckets "fully expired" → zeroes everything. Lossy not security.

### M-21 · `routes_config::is_only_catchall` misses per-host catchalls
**Component:** [api/routes_config.rs:294-302](aegis-gate/crates/aegis-control/src/api/routes_config.rs#L294-L302)
Deleting the last `host: api.example.com / path: "/"` still passes the check → opaque "build failed" instead of targeted 409.

### M-22 · `config_versions::build` walks whole audit ring per call
**Component:** [api/config_versions.rs:101-130](aegis-gate/crates/aegis-control/src/api/config_versions.rs#L101-L130)
With dashboard SPA polling becomes hot CPU consumer. Cache or paginate.

### M-23 · `detectors_persist::save_snapshot` doesn't fsync parent directory
**Component:** [api/detectors_persist.rs:142-170](aegis-gate/crates/aegis-control/src/api/detectors_persist.rs#L142-L170)
On crash between rename + parent-dir-fsync, rename may be lost. Add `File::open(parent).sync_all()`.

### M-24 · `rules::RuleStore` `lock().expect("rule store poisoned")` on hot path
**Component:** [api/rules.rs:175,188,215,253](aegis-gate/crates/aegis-control/src/api/rules.rs#L175)
Panic in any handler poisons the lock → entire rules page 500. Use ArcSwap pattern.

### M-25 · `rollback::apply_access_list_rollback` doesn't verify event action matches target list type
**Component:** [api/rollback.rs:495-559](aegis-gate/crates/aegis-control/src/api/rollback.rs#L495-L559)
`is_add = action.ends_with("_add")` check doesn't verify `event.action` prefix matches the target list type — wrong-list rollback possible.

---

## Services / SLO / metrics

### M-26 · `DashboardServices` drain task default channel capacity too small
**Component:** [dashboard_services.rs:421-438](aegis-gate/crates/aegis-control/src/dashboard_services.rs#L421-L438)
Default broadcast cap ~256; under 5k req/s any dashboard hiccup overruns. Cross-ref F-CRITICAL-011. Increase to 4096+.

### M-27 · `upstreams.rs::UpstreamHandler` holds cache mutex across `serde_json::to_string`
**Component:** [api/upstreams.rs:104-152](aegis-gate/crates/aegis-control/src/api/upstreams.rs#L104-L152)
Serialization inside the lock. Use `parking_lot::Mutex` or move serialization outside.

### M-28 · `admin::BreakGlass::snapshot` filters expired entries on read but doesn't clear
**Component:** [api/admin.rs:170-236](aegis-gate/crates/aegis-control/src/api/admin.rs#L170-L236)
Memory not freed until `disable()`. Add `disable_if_expired` call.

### M-29 · `request_duration::BUCKETS_MS` too coarse near p99 boundary
**Component:** [metrics/request_duration.rs:41-44](aegis-gate/crates/aegis-control/src/metrics/request_duration.rs#L41-L44)
Cross-ref F-HIGH-slo-metrics SM-02. Promoted there.

### M-30 · `route_activity::RouteActivityWindow::record` allocates `route_id.to_string()` per call
**Component:** [metrics/route_activity.rs:182-188](aegis-gate/crates/aegis-control/src/metrics/route_activity.rs#L182-L188)
DashMap::get first, fall back to entry only on miss.

### M-31 · `identity_tracker::last_seen_to_unix_ms` mixes Instant + Utc::now()
**Component:** [identity_tracker.rs:463-467](aegis-gate/crates/aegis-control/src/identity_tracker.rs#L463-L467)
Clock-skew-affected hosts drift indefinitely. Document or use monotonic-only math.

---

## Interop / admin auth

### M-32 · `interop/control.rs::reset_state` callbacks sequential no per-callback timeout
**Component:** [interop/control.rs:264-282](aegis-gate/crates/aegis-control/src/interop/control.rs#L264-L282)
A single slow callback (future Redis flush) blocks the endpoint. Per-callback timeout + log.

### M-33 · `session::parse_cookie` looks up before HMAC verify
**Component:** [admin_auth/session.rs:122-136](aegis-gate/crates/aegis-control/src/admin_auth/session.rs#L122-L136)
Timing oracle for session-id existence. Always do HMAC compare first.

### M-34 · `rate_limit::record_failure` read-modify-write not atomic with `check`
**Component:** [admin_auth/rate_limit.rs:138-153](aegis-gate/crates/aegis-control/src/admin_auth/rate_limit.rs#L138-L153)
Concurrent attempts can record more failures than threshold before lockout. Microsecond window; minor.

### M-35 · `headers.rs::insert` silently swallows malformed values
**Component:** [interop/headers.rs:241-243](aegis-gate/crates/aegis-control/src/interop/headers.rs#L241-L243)
If `rule_id` ever contains an invalid byte, the header is omitted entirely. Insert literal `"invalid"` instead.

---

## Severity rationale

All MEDIUM because each:
- Affects a narrow case OR is latent OR
- Is performance fragility rather than active bug OR
- Is operator-edge / UX nit

None alone justifies an individual file. Bundled for a single
hardening PR after CRITICAL + HIGH sets land.
