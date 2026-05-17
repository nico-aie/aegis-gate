---
id: 2026-05-17-risktracker-keyed-by-ip-only
date: 2026-05-17T00:00Z
severity: CRITICAL
area: security · risk engine
component: crates/aegis-security/src/risk/tracker.rs (RiskTracker storage)
interop_contract: official rules §5.5 (risk per {IP + device_fp + session}) · Intelligence rubric 20/120
status: open
test_mode: source-review (spot-verified)
---

# F-CRITICAL-001 · `RiskTracker` keyed by `IpAddr` only — §5.5 requires `{IP + device_fp + session}`

## Summary

The in-process `RiskTracker` (the production risk engine; `RiskEngine`
in `risk/mod.rs` is the unused state-backed alternative) stores
accumulated risk in a `DashMap<IpAddr, Slot>`. Every risk read/write
in the WAF — `level()`, `record_malicious()`, `record_clean()`,
`top()`, the strike gate — keys on a single `IpAddr`.

The official rules §5.5 are explicit:

> *Risk score tích lũy per **{IP + device fingerprint + session}** —
> không reset sau mỗi request*

The shape MUST contain device and session axes. Without them:

- Two browsers behind a NAT (corporate offices, ISP CGNAT) share the
  same risk bucket — one user's malicious activity blocks the rest of
  the building.
- A single attacker rotating sessions (cookies cleared) on the same
  IP still accumulates risk on the same key — but a single attacker
  rotating IPs (the Attack Battle scenario "Distributed credential
  stuffing với IP rotation") gets a fresh risk bucket per IP and
  evades the lifetime-strikes invariant entirely.
- Per §5.2 #08 ("phát hiện cùng device đổi IP để bypass block"), the
  device dimension is exactly the signal that catches this evasion;
  with IP-only keying that signal cannot be persisted as risk.

The core types `aegis_core::risk::RiskKey` and the unused
`RiskEngine` (`risk/mod.rs:49`) already carry the right shape
(`ip + device_fp + session + tenant_id`). The bug is that the
data-plane consumer uses `RiskTracker`, not `RiskEngine`.

## Observed code path

[risk/tracker.rs:74](aegis-gate/crates/aegis-security/src/risk/tracker.rs#L74):

```rust
pub struct RiskTracker {
    ...
    map: DashMap<IpAddr, Slot>,
    ...
}
```

All mutators take `IpAddr`:

```rust
pub fn record_malicious(&self, ip: IpAddr, delta: u32) -> RiskState { ... }
pub fn record_malicious_at(&self, ip: IpAddr, ...) { ... }
pub fn level(&self, ip: IpAddr) -> RiskLevel { ... }
```

Cross-check the contract types in `aegis_core/src/risk.rs`:

```rust
pub struct RiskKey {
    pub ip: IpAddr,
    pub device_fp: Option<String>,
    pub session: Option<String>,
    pub tenant_id: Option<String>,
}
```

— exists, used by the unused `RiskEngine`, ignored by `RiskTracker`.

## Impact

- **Intelligence & Adaptiveness rubric (20 / 120, 17% of total)** —
  the headline rubric item is "Risk score accuracy (per user + device + session)". Implementation is per-IP only → graders observe wrong behavior on every test case that distinguishes by device or session.
- **Attack Battle scenario 02 (Distributed credential stuffing with IP rotation)** — evasion is trivial; risk never accumulates for the actor.
- **Attack Battle scenario 04 (Device fingerprint evasion + multi-account)** — combined with F-CRITICAL-010 (no reverse map), the WAF cannot detect a single device hopping IPs.
- **CGNAT / corporate NAT false-positives** — a single malicious user on a NAT can elevate risk for everyone behind the NAT.

## Suggested fix

Change the key shape end-to-end. Sketch:

```diff
 pub struct RiskTracker {
-    map: DashMap<IpAddr, Slot>,
+    map: DashMap<RiskKey, Slot>,
     ...
 }

-pub fn record_malicious(&self, ip: IpAddr, delta: u32) -> RiskState {
+pub fn record_malicious(&self, key: &RiskKey, delta: u32) -> RiskState {
-    let mut entry = self.map.entry(ip).or_default();
+    let mut entry = self.map.entry(key.clone()).or_default();
     ...
 }
```

Every call-site in `aegis-proxy` (`data_plane.rs`, `accept.rs`) must
construct a `RiskKey` from:

- TCP peer IP (always present)
- Device fingerprint hash (from `aegis-security::fingerprint::device_id`)
- Session ID (from authenticated session cookie or anonymous session
  cookie — issue a stable anonymous session cookie at first request)

`RiskKey` must implement `Hash + Eq` (it already does). Implement
`PartialEq` so that two requests from the SAME ip + DIFFERENT device
do NOT collapse.

Note: keying on `(IP, device, session)` tuple gives finer granularity
than the spec demands. For aggregate views (`top()`, dashboard "top
attackers"), aggregate up to the IP level for display while keeping
score increments fine-grained.

## Verification

After the fix:

```sh
# Two different devices from same IP — risk MUST be independent.
HOST="http://127.0.0.1:8080"
curl -ski "$HOST/?q=1%27%20OR%20%271%27%3D%271" \
    -A "Browser1" -H "X-Device-Fp: A"   # malicious from device A
curl -ski "$HOST/" -A "Browser2" -H "X-Device-Fp: B"  # benign from device B

# Inspect /api/risk:
curl -sk "$HOST/api/risk" | jq '.[] | select(.ip == "127.0.0.1")'
# Should show TWO entries with different device_fp, different scores.
```

Regression case in `tests/api/`: assert that requests sharing IP but
not device do NOT share risk.

## Severity rationale

CRITICAL. This is the single largest gap to the Intelligence rubric
(20/120). The fix is mechanical but touches every risk-tracker
call-site. Trivial to detect during judge code review — Hash key
shape is the first thing to look at when grading the rubric.
