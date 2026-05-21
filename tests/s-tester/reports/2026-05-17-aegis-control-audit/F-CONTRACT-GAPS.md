---
id: 2026-05-17-control-contract-gaps
date: 2026-05-17T00:00Z
severity: contract-gap (semantic)
area: v2.3 interop · README claims vs reality
component: crates/aegis-control/src/interop/* · crates/aegis-control/src/audit/sinks/* · crates/aegis-proxy/src/run.rs (build_interop_runtime)
interop_contract: v2.3 §2.3, §2.4 · README "8 SIEM sink formats"
status: open
test_mode: source-review
---

# F-CONTRACT-GAPS · 4 semantic gaps where code disagrees with the spec or the README

These are not bugs in the "code does the wrong thing" sense — code
does what its author intended. They are gaps where the WAF's
behavior diverges from documented expectations.

---

## C-01 · `capabilities` response omits `open_redirect` policy (already filed as F-CRITICAL-010)

This is cross-listed here for completeness — the contract gap is the
disagreement between the capabilities response and the rule_map's
detector mapping.

---

## C-02 · `reset_state` covers 4 of 6 enumerated state classes (BehavioralAnalyzer + temp client metadata not wired)

**Component:** [aegis-proxy/src/run.rs:1678-1699](../../../../crates/aegis-proxy/src/run.rs#L1678-L1699)

§2.4 enumerates 6 state classes that `reset_state` must clear:

1. risk state ✅ wired
2. rate-limit counters ✅ wired
3. cache state ✅ via separate `flush_cache`
4. challenge/session state ⚠️ documented as "stateless PoW" — OK
5. temporary client/session metadata ❌ BehavioralAnalyzer not wired
6. temporary enforcement state ⚠️ session preserved-by-design — OK

The block comment at lines 1662-1699 acknowledges the
BehavioralAnalyzer gap as "not wired into request path".

**Impact:** graders running a "burn velocity state → reset_state →
verify state cleared" probe see the behavior state persist.
Per-§2.4 wording "appear atomic to caller" still holds (no
partial-clear surface), but the completeness is partial.

**Fix:** wire `services.behavior_analyzer.reset()` into the
reset_state callback list once BehavioralAnalyzer is on the request
path (per F-CRITICAL-004 in security audit, behavior signals are
mostly unimplemented anyway).

---

## C-03 · `audit_log_preserved: true` hardcoded in reset_state response

**Component:** [interop/control.rs:279](../../../../crates/aegis-control/src/interop/control.rs#L279)

The reset_state response includes `audit_log_preserved: true`. The
value is hardcoded — not derived from any actual check that the
audit sink wasn't truncated.

Today the value is correct (no reset_state code path truncates the
log). But if reset_state ever evolves to optionally rotate or
clear the log, the field becomes a lie.

**Fix:** derive from a real predicate:

```rust
let audit_log_preserved = !services.audit_sink.was_truncated_during_reset();
```

Even if the predicate is always `true` today, structuring it as a
runtime check protects against future regressions.

---

## C-04 · README "8 SIEM sink formats" — 8 formatters exist, only 2 actually transmit

**Component:** [audit/sinks/mod.rs:1-8](../../../../crates/aegis-control/src/audit/sinks/mod.rs#L1-L8)

README claims the WAF ships with 8 SIEM sink formats. The module
declares 8 formatters: `jsonl`, `syslog`, `cef`, `ecs`, `kafka`,
`leef`, `ocsf`, `splunk_hec`.

Reality (per Agent A reading):

- **jsonl**: actually transmits (file sink)
- **syslog**: actually transmits (UDP/TCP/TLS)
- **splunk_hec**: stub — only buffers in `Mutex<Vec<String>>`, no HTTP send
- **kafka**: stub
- **cef, ecs, leef, ocsf**: format-only — no sink struct, only formatters

So 6 of the 8 "sinks" are format-only OR stubs. Operators reading
the README assume SIEM integration is one-config-flip away; it isn't.

**Impact:** README veracity. If a judge probes "which SIEM
integrations are wired" and the team can only demo jsonl + syslog,
the 8-claim looks like marketing.

**Fix:** EITHER finish wiring the other 6 (substantial: HEC needs
HTTP client, Kafka needs rdkafka or similar, the others need a
transport like webhook + format application) OR update the README:

> *Supports 2 SIEM transports (jsonl, syslog) with formatters for
> CEF, ECS, LEEF, OCSF, Splunk HEC. Splunk-HEC and Kafka transports
> are stubbed; contributions welcome.*

The format-only modules (CEF/ECS/LEEF/OCSF) are still useful
artifacts — operators can paste their output into any existing SIEM
pipeline. But "supports 8 SIEM formats" implies push, not pipe.

---

## Severity classification

Contract-gap level. Each is a documented expectation that the code
doesn't deliver. Combined effect: operators reading the README assume
features that aren't fully there.
