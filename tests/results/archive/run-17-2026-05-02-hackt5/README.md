# Run 17 — 2026-05-02 — HACK-T5 verification

End-to-end verification after **HACK-T5** (Tier-C bonus:
Syslog/CEF audit forwarder) — final slice of
[`plans/hackathon-readiness.md`](../../../../plans/archive/hackathon-readiness.md).

## Headline

| Surface | Result |
|---|---|
| **Syslog sink unit tests** | 11/11 PASS in `aegis-control::audit::sinks::syslog::tests` |
| **Live UDP forwarder** | Allowed + blocked requests both streamed to a loopback `udp 127.0.0.1:5515` receiver as RFC 5424 framed messages |
| **Allow event PRI** | `<86>` (facility 10 × 8 + severity 6 = `Access` class) |
| **Block event PRI** | `<84>` (facility 10 × 8 + severity 4 = `Detection` class) |
| **Workspace tests** | 41 + **889** + 173 + 496 + 888 = all PASS |
| **Production build** | Clean |

## Live evidence

WAF binary started against a config with both JSONL + Syslog
sinks:

```yaml
audit:
  sinks:
    - jsonl:
        path: ./waf_audit.log
    - syslog:
        address: "127.0.0.1:5515"
        transport: udp
        format: rfc5424
```

Boot log confirms both sinks wired:

```
INFO aegis_proxy::accept: audit jsonl persistence wired sinks=1 ...
INFO aegis_proxy::accept: audit syslog forwarder wired address=127.0.0.1:5515 transport=Udp format=Rfc5424
```

A benign request and a SQLi probe are both delivered to the
syslog receiver (full receiver log in
[`syslog-receiver.log`](./syslog-receiver.log)):

```
msg1: <86>1 2026-05-01T20:11:44.294071+00:00 - aegis-waf - - -
      {"schema_version":1,..., "class":"access", "action":"allow",
       "client_ip":"127.0.0.1",
       "fields":{"method":"GET","path":"/api/test","status":200}}

msg2: <84>1 2026-05-01T20:11:57.558782+00:00 - aegis-waf - - -
      {..., "class":"detection", "action":"block",
       "reason":"blocked by detectors: sqli (score: 40)",
       "fields":{"detectors":["sqli"],
                 "path":"/api/test?id=1%27%20OR%20%271%27=%271",
                 "strikes":1}}
```

Both events match the v2.3 minimal-schema (request_id,
ts_ms equivalent, ip, method, path, action, risk_score, mode)
plus the full enriched audit event.

## Format support

The forwarder can emit either:

- **RFC 5424** (`<PRI>1 TS HOST APP PROCID MSGID STRUCTURED MSG`)
  with the audit event JSON in the MSG slot — what most SIEMs
  parse natively.
- **CEF** (`CEF:0|Aegis|aegis-waf|0.1.0|<class_id>|<action>|<sev>|<extension>`)
  with `act=`, `src=`, `request_id=`, `mode=`, `cs1=` (rule_id),
  `cn1=` (risk_score) — for SIEMs that prefer CEF.

CEF severity per audit class: Detection=7, Admin=4, Access=3,
System=5. Pipe / equals / backslash / newline are escaped per
spec.

## Transport support

- **UDP** (RFC 5426): one datagram per event, default port 514.
  Lossy under congestion (UDP has no acknowledgement).
- **TCP** (RFC 6587 §3.4 newline-framed): reconnects lazily on
  send failure. Send errors log + drop from this sink only;
  JSONL persistence is unaffected.
- **TLS** transport variant exists in the config schema but
  the sink falls back to TCP — TLS-wrapping is a separable
  follow-up using `tokio_rustls::TlsConnector`.

## Tests (11/11 PASS)

- `rfc5424_priority_calculated_from_facility_and_severity`
- `rfc5424_carries_app_name_and_event_json`
- `rfc5424_admin_class_severity_is_6`
- `cef_starts_with_canonical_header`
- `cef_includes_action_src_request_id_mode`
- `cef_includes_rule_id_and_risk_score_when_present`
- `cef_escape_handles_pipe_equals_backslash`
- `cef_severity_per_audit_class`
- `udp_send_round_trips_to_loopback_receiver` —
  binds a UDP receiver on 127.0.0.1:0, sends one event,
  asserts the receiver got the framed line.
- `tcp_send_round_trips_to_loopback_listener` —
  binds a TCP listener, sends one CEF-formatted event,
  asserts the receiver got the line newline-terminated.
- `tcp_reconnect_after_initial_failure_does_not_panic` —
  connects to an unbound port, asserts the sink constructs
  cleanly and the first send returns Err (so the forwarder
  task can log + continue, not panic).

## Files touched

- `crates/aegis-core/src/config.rs`
  - `AuditSinkConfig::Syslog` extended with `transport` /
    `format` / `facility` / `app_name` (was just `address`).
  - New `SyslogTransport { Udp, Tcp }` enum.
  - New `SyslogFormat { Rfc5424, Cef }` enum.
- `crates/aegis-control/src/audit/sinks/syslog.rs`
  (~440 LOC + 11 unit tests) — full rewrite.
  - `SyslogSink::connect(cfg) -> Result<Self>` async constructor
    that binds UDP / opens TCP.
  - `send(&self, ev) -> Result<()>` per-event method.
  - `format_rfc5424` + `format_cef` pure formatters.
  - `cef_escape` for pipe/equals/backslash/newline.
  - `run_forward_task(bus, sink)` spawnable subscriber that
    drains the audit broadcast and forwards every event.
- `crates/aegis-control/src/api/logging.rs` — pattern-match
  destructuring updated for the new fields; test fixture
  updated.
- `crates/aegis-control/tests/dod.rs` — multi-sink smoke test
  updated to use the new `connect()` async API + UDP loopback.
- `crates/aegis-proxy/src/accept.rs` — boot-time spawn of the
  syslog forwarder alongside the existing JSONL persist task,
  one task per `AuditSinkConfig::Syslog` entry.

## Definition of Done

- [x] `SyslogSink` actually sends to a remote endpoint
      (was an in-memory stub).
- [x] UDP + TCP transports both work (TCP with lazy
      reconnect).
- [x] RFC 5424 + CEF formats both produce valid framed
      messages.
- [x] Boot path spawns one forwarder task per
      `AuditSinkConfig::Syslog` entry.
- [x] Live verification — UDP receiver got framed messages
      end-to-end for both Allow and Block events.
- [x] 11 unit tests pass.
- [x] Workspace tests + production build clean.

## What's next

- HACK-T track is **complete**. Hackathon-readiness scope
  closed for v2.3 except for the explicit "deferred to
  follow-up" items (HACK-T4 rollback action, TLS syslog
  transport).
