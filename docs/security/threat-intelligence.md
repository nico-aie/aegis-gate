# Threat Intelligence (v2)

> **Status:** Partially built, **not yet wired into the request path.**
> The in-process indicator store (`threat_intel::ThreatIntelStore`) and
> the TAXII 2.1 / STIX 2.1 client + fetcher loop (`threat_intel::taxii`,
> gated by the `aegis-security/taxii` Cargo feature) exist and are
> unit-tested, but nothing in `aegis-proxy` / `aegis-bin` constructs the
> store, spawns the fetcher, or calls `check_ip` / `check_domain` on the
> hot path. Treat this as a **library awaiting integration**, not a live
> feature.
>
> The broader "enterprise" surface (MISP + commercial-feed clients, a
> typed `ArcSwap` / AhoCorasick index, JA3 / JA4 / user-agent / ASN
> indicator matching, YAML-driven action mapping, HA-leader feed
> distribution) is **planned, not built.** Each section below is tagged
> **[built]**, **[planned]**, or **[unwired]**.
>
> See [`../../plans/plan.md`](../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Maintain an index of known-bad IPs, CIDRs, and domains (with URL and
SHA-256 indicators also ingested), refreshed from threat feeds, carrying
feed provenance (`feed_id` + `confidence`) through to the eventual block
decision. The intended consumers are [`ip-reputation.md`](./ip-reputation.md)
and the [`rule-engine.md`](./rule-engine.md) `ThreatFeed` condition — that
wiring is **not in place yet**.

## Indicator types

The implemented enum is `IndicatorType` in `threat_intel/mod.rs`. Only IP
and domain indicators have a matching path today; the rest are ingested
and stored but never queried.

| Type | Status | Matched by | Notes |
|---|---|---|---|
| `Ip` (v4 + v6) | **[built]** | `check_ip` (exact) | single `IpAddr`, string-keyed |
| `Cidr` | **[built]** | `check_ip` (linear `IpNet::contains`) | parsed once at ingest |
| `Domain` | **[built]** | `check_domain` (exact) | |
| `Url` | **[unwired]** | — | ingested into the domain map; no URL lookup caller |
| `Sha256` | **[unwired]** | — | stored in the IP bucket; never queried |
| `JA3` | **[unwired]** | — | stored; never queried |
| `ja4` / `user_agent` / `asn` | **[planned]** | — | not represented in the enum |

> **JA4 is *not* a threat-intel indicator.** Device/TLS fingerprinting is
> a separate subsystem (`aegis-security/src/fingerprint/`) that does not
> read this store. For the record: the runtime JA4 is a **TLS** post-
> handshake fingerprint ("JA4-light" — negotiated cipher + ALPN + version
> + SNI type; canonical ClientHello JA4 is implemented but unwired because
> rustls 0.23 doesn't expose the ClientHello). There is **no HTTP / JA4H
> fingerprint**; the only HTTP signal in identity is the User-Agent folded
> into the device hash (`device_fp_hash(ja4, ua)`).

## Feed providers

- **[built]** TAXII 2.1 — pull STIX 2.1 indicator objects from a
  collection (`threat_intel::taxii`, gated by the `taxii` feature).
- **[built]** Plain-text IP list — `parse_plaintext_feed` (one IP per
  line, `#` comments). **IPs only**; no URL/domain support.
- **[planned]** MISP REST client, commercial HTTPS feeds (Cloudflare,
  Crowdsec, Recorded Future, GreyNoise, Spur, AbuseIPDB), CSV / JSON feed
  parsers, local-file loader. `FeedFormat::{Csv, Json}` are enum variants
  with no parser behind them.

## Indicator record **[built]**

The actual struct (`threat_intel/mod.rs`):

```rust
pub struct Indicator {
    pub value: String,              // not a typed IndicatorValue
    pub indicator_type: IndicatorType,
    pub confidence: u8,             // 0–100
    pub severity: Severity,         // enum: Low | Medium | High | Critical
    pub feed_id: String,
    pub expires_at: Instant,        // not ttl_s / first_seen / last_seen
}
```

There is no `IndicatorValue`, `first_seen`, `last_seen`, `ttl_s`,
`action_hint`, or `labels` field. `severity` is an enum, not a 0–100 int.

## Index structure **[built]**

Per-type, behind individual `Mutex`es — **not** a single `ArcSwap`:

- `Mutex<HashMap<String, Indicator>>` for exact IPs (keyed by IP string)
- `Mutex<Vec<(IpNet, Indicator)>>` for CIDRs — **linear scan** with
  `IpNet::contains` (the comment notes a CIDR-tree can replace it if feeds
  ever reach BGP-table scale)
- `Mutex<HashMap<String, Indicator>>` for domains (and URLs)
- `Mutex<HashMap<String, OverrideAction>>` for local allow/block overrides
  (overrides always win)

There is **no `ArcSwap`, no `FeedIndex` type, and no AhoCorasick** —
URL/domain matching is exact-string HashMap lookup, and every read takes a
`Mutex` lock (reads are not wait-free). An `ArcSwap`-backed index with
literal automata is **[planned]**.

## Provenance **[built, partial]**

Each `ThreatMatch` carries the matched `Indicator` (so `feed_id` +
`confidence` are available to the caller). There is **no dedicated
`provenance.rs`** module and no `block → rule → indicator → feed → source`
trail helper — provenance is just the fields on the indicator.

Retraction is `ThreatIntelStore::clear()` (drops all indicators) plus
per-entry TTL eviction; there is no per-feed `ArcSwap`-swap retraction.

## Confidence → action **[built]**

Hardcoded in `severity_to_action(severity, confidence)` — **not**
YAML-configurable. The actual mapping:

| Severity | Confidence | Action |
|---|---|---|
| Critical | any | `Block` |
| High | ≥ 70 | `Block` |
| High | < 70 | `RaiseRisk(40)` |
| Medium | ≥ 80 | `RaiseRisk(30)` |
| Medium | < 80 | `RaiseRisk(20)` |
| Low | any | `Monitor` |

A YAML `action_mapping` block (as in earlier drafts of this doc) does not
exist.

## Feed refresh **[built for TAXII; HA distribution planned]**

`taxii::spawn_fetcher(store, cfg)` spawns a background task that polls one
collection every `cfg.poll_interval` (default 15 min), fetches
incrementally via `added_after`, drains all pages, and ingests every
decoded indicator. Transient errors trigger exponential backoff capped at
the poll interval.

- **Lease-gating** the loop (so only one cluster node fetches) is the boot
  site's responsibility — the same pattern as ACME and the gitops poll
  driver. **This wrapper does not exist yet** (no caller spawns the
  fetcher).
- "Workers consume the index via the state backend / hot-reload broadcast"
  is **[planned]** — the store is a plain in-process structure with no
  cross-node sharing.

## Freshness + staleness

- **[built]** Indicators past `expires_at` are skipped on lookup and
  evicted on the next ingest that hits the `max_indicators` cap
  (`evict_expired`).
- **[planned]** `stale_after` feed-staleness warnings and a
  `max_future_drift_s` clock-skew guard are not implemented.

## Configuration

**[built]** — the TAXII feed config (`taxii::TaxiiConfig`), constructed in
code (no unified YAML loader yet):

```rust
TaxiiConfig {
    api_root: "https://taxii.example.org/api/",
    collection_id: "<collection-uuid>",
    auth: TaxiiAuth::Bearer { token },   // None | Basic | Bearer
    poll_interval: Duration::from_secs(900),
    request_timeout: Duration::from_secs(30),
    default_confidence: 75,
    default_severity: Severity::Medium,
    default_ttl: Duration::from_secs(86_400),
    feed_id: "taxii".into(),
}
```

**[planned]** — a unified `threat_intel:` YAML block (multiple feeds,
`type`/`auth`/vault secret refs, `action_mapping`, `stale_after_s`) is not
wired. The in-code `FeedConfig` struct exposes `id`, `url`, `format`,
`default_confidence`, `default_severity`, `ttl`, `enabled` — no `auth`,
no refresh interval, no secret references.

## Implementation

Files that actually exist:

- `crates/aegis-security/src/threat_intel/mod.rs` — `Indicator`,
  `IndicatorType`, `Severity`, `ThreatIntelStore`, `severity_to_action`,
  `parse_plaintext_feed`
- `crates/aegis-security/src/threat_intel/taxii.rs` — TAXII 2.1 client,
  STIX 2.1 pattern parser, background fetcher loop (gated by `taxii`)

Files referenced by earlier drafts that **do not exist**: `fetcher.rs`,
`misp.rs`, `index.rs`, `provenance.rs`.

## Performance notes

- A lookup is a `Mutex` lock + HashMap get for exact IPs/domains, plus a
  linear scan of the CIDR vector. Not wait-free; fine for low-thousands of
  indicators.
- TAXII fetches run off the hot path in the background poll task.
- An incremental / `ArcSwap`-backed rebuild is **[planned]**, not present.
