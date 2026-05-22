---
id: 2026-05-17-no-same-device-different-ip-detection
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · device fingerprinting
component: crates/aegis-security/src/fingerprint/mod.rs
interop_contract: official rules §5.2 #08 · Attack Battle scenario 04 (Device fingerprint evasion)
status: open
test_mode: source-review
---

# F-CRITICAL-010 · No "same device, different IP" detection — §5.2 #08 unaddressed

## Summary

Official rules §5.2 #08:

> *Device Fingerprinting: Tạo device ID bền vững từ: TLS fingerprint
> (JA3/JA4), HTTP/2 settings, User-Agent entropy, Accept-Encoding
> pattern. **Phát hiện cùng device đổi IP để bypass block**.*

Two requirements: (a) stable device ID, (b) detection of "same
device, different IP" rotation.

Requirement (a) is broken by F-CRITICAL-011 (JA4 sorts + GREASE not
stripped).

Requirement (b) is completely unimplemented. `fingerprint::device_id()`
returns a hash. There is no reverse map `device_id → set<IP>` that
would let the WAF observe "this device has been seen from IPs X, Y, Z
in the last hour — that's IP rotation".

Combined with F-CRITICAL-001 (risk tracker keyed by IP only), even
when a device's risk score IS elevated, the score is bound to the
SOURCE IP at the time, not to the device — so when the attacker
rotates to a fresh IP with the same device, they get a fresh
zero-risk bucket.

## Observed code path

[fingerprint/mod.rs:10-31](../../../../crates/aegis-security/src/fingerprint/mod.rs#L10-L31) — `device_id()`:

```rust
pub fn device_id(
    ja3:         Option<&str>,
    ja4:         Option<&str>,
    h2_settings: Option<&str>,
    ua:          &str,
    accept_encoding: Option<&str>,
    header_order: &[String],     // ← also breaks stability per F-HIGH-bots-fingerprint
) -> String {
    let combined = format!(...);
    blake3::hash(combined.as_bytes()).to_hex()[..32].to_string()
}
```

The output is a 128-bit device hash. There is no `device_seen_with_ip(device, ip)` API; no `device_id → IpSet` map; no
"rotation detected" signal.

`bots.rs::BotSignals` carries a `ja4_fingerprint` field
([bots.rs:17](../../../../crates/aegis-security/src/bots.rs#L17)) but the classifier never reads it (cf.
F-CRITICAL-015).

## Impact

- **§5.2 #08 violation** — the spec explicitly says "detect same
  device changing IP". This signal is the headline reason device
  fingerprinting exists. Without it, the device ID computed at
  great cost (JA3 + JA4 + H2 + UA + Accept-Encoding) is unused.
- **Attack Battle scenario 04** (Device fingerprint evasion) —
  Red Team rotates JA3 + UA + residential IP for multi-account
  abuse. WAF cannot link the multi-account abuse back to one device.
- **Security Effectiveness (40/120)** — combined with F-CRITICAL-011
  (JA4 instability), the fingerprinting subsystem doesn't deliver
  the scoring item.
- **Intelligence rubric (20/120)** — "Device fingerprinting accuracy"
  explicitly enumerated.

## Suggested fix

Net-new `device_to_ips_tracker.rs`:

```rust
pub struct DeviceIpTracker {
    // Per-device, last N IPs observed in the last window.
    map: DashMap<String /* device_id */, (VecDeque<(IpAddr, Instant)>, /* anomaly score */ u32)>,
    cfg: DeviceIpConfig,
}

pub struct DeviceIpConfig {
    pub max_ips_per_device: usize,          // e.g. 16
    pub observation_window: Duration,       // e.g. 1 hour
    pub rotation_threshold: usize,          // e.g. 4 distinct IPs in 1 min → rotation
    pub rotation_score_boost: u32,          // e.g. 50
}

impl DeviceIpTracker {
    pub fn observe(&self, device_id: &str, ip: IpAddr, now: Instant) -> Option<RotationSignal> {
        let mut entry = self.map.entry(device_id.to_string()).or_default();
        let (log, _) = &mut *entry;

        // Append + trim oldest beyond window/cap.
        log.push_back((ip, now));
        let cutoff = now - self.cfg.observation_window;
        while log.front().map_or(false, |(_, t)| *t < cutoff) || log.len() > self.cfg.max_ips_per_device {
            log.pop_front();
        }

        let distinct_ips: std::collections::HashSet<_> = log.iter().map(|(ip, _)| *ip).collect();
        if distinct_ips.len() >= self.cfg.rotation_threshold {
            return Some(RotationSignal {
                device_id: device_id.to_string(),
                ips_seen: distinct_ips.into_iter().collect(),
                window: now - log.front().unwrap().1,
            });
        }
        None
    }
}

pub struct RotationSignal {
    pub device_id: String,
    pub ips_seen: Vec<IpAddr>,
    pub window: Duration,
}
```

Wire into the pipeline:

```rust
// data_plane.rs (or pipeline.rs once F-CRITICAL-008 is fixed):
let dev_id = fingerprint::device_id(...);
if let Some(rotation) = device_ip_tracker.observe(&dev_id, peer.ip(), Instant::now()) {
    // Boost risk on the device key (per F-CRITICAL-001 fix shape):
    risk_tracker.record_malicious(&RiskKey {
        device_fp: Some(dev_id.clone()), ..
    }, cfg.canary.rotation_score_boost);
    audit_emit(AuditEntry {
        action: "challenge",
        rule_id: "fingerprint.ip_rotation",
        device_fp: Some(dev_id),
        fields: serde_json::json!({ "ips_seen": rotation.ips_seen, "window_s": rotation.window.as_secs() }),
        ...
    });
}
```

Bounded memory by `max_ips_per_device` × window expiry.

## Verification

```sh
HOST="http://127.0.0.1:8080"

# Same client (curl with stable JA3+UA+H2) from 5 different IPs:
for i in 1 2 3 4 5; do
    curl -ski --interface 127.0.0.$i \
        -A "Same-UA/1.0" \
        "$HOST/" -o /dev/null
done

# Should observe a rotation signal on the 4th or 5th request.
tail -5 ./waf_audit.log | jq '{rule_id, device_fp, fields}'
# Expect: rule_id: fingerprint.ip_rotation on at least one entry.
```

Regression case in `tests/security/fingerprint_rotation.sh`.

## Severity rationale

CRITICAL. Explicit Attack Battle scenario, explicit §5.2 #08 mandate.
Net-new module but small (~120 LoC). Without F-CRITICAL-001's fixed
key shape, the score boost from this tracker won't persist across
IP rotation either — fix both together for the full benefit.
