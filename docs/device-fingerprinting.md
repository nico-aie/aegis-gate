# Device Fingerprinting (v2)

> **v1 → v2:** fingerprints now feed the **bot classifier**
> ([`bot-management.md`](./bot-management.md)), JA4 is the default (JA3 kept
> for compatibility), the device store is **clustered**, and fingerprints
> participate in the composite `RiskKey` used by
> [`risk-scoring.md`](./risk-scoring.md).

## Purpose

Identify a client across requests even when cookies, IPs, and User-Agents
change. Fingerprints are the primary stable key for persistent risk scores,
bot classification, and cross-node session tracking.

## Fingerprint sources

### JA3 / JA4 (TLS ClientHello)

Captured in a `rustls` `ClientHello` callback at handshake time (see
[`tls-termination.md`](./tls-termination.md)). JA4 is the default because
it is sortable, splittable, and more robust than JA3's MD5 hash.

Computed fields:

- TLS version, cipher suite list, extension list
- Supported elliptic curves + point formats
- ALPN + SNI presence flags (JA4 only)

### HTTP/2 fingerprint (Akamai / HTTP2 Fingerprint)

For HTTP/2 connections, the SETTINGS frame values, pseudo-header order,
and initial WINDOW_UPDATE size form a second, orthogonal fingerprint.
Real browsers and bot libraries diverge sharply here.

### User-Agent entropy + header order

Shannon entropy of the UA plus the observed header order are combined
with the TLS fingerprint into the composite device id.

### Composite device id

```
device_id = blake3(ja4 || h2_fp || ua_hash || accept_language || accept_encoding_set)
```

`blake3` replaces SHA-256 here for lower CPU cost; it is not used where
collision resistance matters for security (that stays on SHA-256).

## Extraction pipeline

1. TLS handshake → JA4 attached to the hyper connection extension
2. HTTP/2 preface → h2 fingerprint attached
3. Request arrives → HTTP-level entropy/order computed
4. Composite `device_id` computed once per request, cached on the
   `RequestContext`

For plain HTTP or TLS-offloaded edges, only the HTTP-level half is
available; bot classifier downgrades accordingly.

## Clustered device store

Device records (`device_id → { first_seen, last_seen, risk, confidence,
bot_class }`) live in the state backend, so a device fingerprint
observed on node A is recognized on node B within replication latency.

## Uses

- [`rate-limiting.md`](./rate-limiting.md) — scope by device to beat NAT
  sharing
- [`risk-scoring.md`](./risk-scoring.md) — `RiskKey` includes `device_fp`
- [`behavioral-analysis.md`](./behavioral-analysis.md) — session tracking
- [`challenge-engine.md`](./challenge-engine.md) — human confidence is
  stored per device
- [`bot-management.md`](./bot-management.md) — primary input feature
- [`rule-engine.md`](./rule-engine.md) — `device_fp_eq:` / `bot_class:`
  conditions
- [`audit-logging.md`](./audit-logging.md) — `device_id` in every event

## Privacy

- Fingerprints are salted hashes with a per-deployment secret
- TTL in the device store (default 24h, extended by recent activity)
- Not written to disk unless the operator explicitly enables debug tracing
- Per-tenant partitioned: fingerprints are never cross-referenced across
  tenants
- GDPR: see [`data-residency-retention.md`](./data-residency-retention.md)

## Configuration

```yaml
fingerprint:
  ja4_enabled: true
  ja3_enabled: true           # legacy
  h2_fingerprint: true
  ua_entropy: { min_normal: 3.0, max_normal: 6.0 }
  device_ttl_s: 86400
  salt: "${secret:vault:kv/data/waf#device_salt}"
```

## Implementation

- `src/fingerprint/ja4.rs` — JA4 + legacy JA3
- `src/fingerprint/h2_fp.rs` — HTTP/2 settings fingerprint
- `src/fingerprint/ua_entropy.rs` — Shannon entropy + header-order stability
- `src/fingerprint/device_id.rs` — blake3 composite
- `src/fingerprint/store.rs` — clustered device store

## Performance notes

- JA4 computation: single pass over ClientHello bytes, O(1) per handshake
- Composite hash: blake3, ~1 GB/s per core, negligible on hot path
- Device-store read: one state-backend `GET`, pipelined with rate limiter
