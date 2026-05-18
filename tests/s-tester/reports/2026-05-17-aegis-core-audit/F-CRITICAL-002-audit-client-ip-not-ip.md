---
id: 2026-05-17-audit-client-ip-not-ip
date: 2026-05-17T00:00Z
severity: CRITICAL
area: contract schema · audit event
component: crates/aegis-core/src/audit.rs (AuditEvent.client_ip field)
interop_contract: v2.3 §6 (audit log required field `ip` — TCP peer)
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-002 · `audit.rs::AuditEvent.client_ip` — §6 requires bare `ip`

## Summary

§6 of the v2.3 contract requires:

> *`ip` — TCP peer address (`peer_addr` / `remote_addr` from socket), NOT XFF*

`AuditEvent` declares the field as `client_ip`.

**Spot-verified** at [audit.rs:13](aegis-gate/crates/aegis-core/src/audit.rs#L13):

```rust
pub struct AuditEvent {
    ...
    pub client_ip: String,
    ...
}
```

The serde-emitted key on the wire is therefore `"client_ip"`. The
§6 validator looks for `"ip"`. Every event is non-compliant on
field-name alone.

Additionally, `client_ip: String` instead of `IpAddr` defers
normalization to every populator → enables typos like
`"127.0.0.1:42"` (forgot to strip port) or `" 10.0.0.1"` (leading
whitespace) silently slipping through.

## Suggested fix

```diff
 pub struct AuditEvent {
     ...
-    pub client_ip: String,
+    /// §6 contract: TCP peer (NOT XFF). Always the socket peer.
+    pub ip: std::net::IpAddr,
     ...
 }
```

OR if migration cost is too high to rename:

```diff
-    pub client_ip: String,
+    #[serde(rename = "ip")]
+    pub client_ip: std::net::IpAddr,
```

Both options change the wire format from `"client_ip"` to `"ip"` and
the type from `String` to `IpAddr`. Populators update from
`client_ip: peer.ip().to_string()` to `ip: peer.ip()`.

Strongly prefer the typed rename (drop the String) — typed `IpAddr`
catches the populator-side bugs (forgot to strip port, etc.) at
compile time.

## Verification

```sh
make run-dev
curl -ski http://127.0.0.1:8080/ -o /dev/null
tail -1 ./waf_audit.log | jq '{ip, client_ip}'
# Expect: { "ip": "127.0.0.1", "client_ip": null }
# Today:  { "ip": null, "client_ip": "127.0.0.1" }
```

Contract regression test:

```rust
#[test]
fn audit_event_field_name_is_ip() {
    let event = AuditEvent { ip: "127.0.0.1".parse().unwrap(), ... };
    let json: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert!(json["ip"].is_string());
    assert!(json.get("client_ip").is_none(), "old field name must not appear");
}
```

## Severity rationale

CRITICAL. Wrong wire key on every audit event. ~5 LoC + populator
migration. Part of audit-schema cluster — land with F-CRITICAL-001/003/004/005.
