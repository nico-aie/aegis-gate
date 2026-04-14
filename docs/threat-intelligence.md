# Threat Intelligence (v2, enterprise)

> **Enterprise addendum.** Ingests STIX 2.1 / TAXII 2.1 collections,
> commercial feeds, and plain-text IP/URL lists. Indicators feed
> [`ip-reputation.md`](./ip-reputation.md) and the
> [`rule-engine.md`](./rule-engine.md) `ThreatFeed` condition.

## Purpose

Keep an authoritative, versioned index of known-bad IPs, URLs, user
agents, JA4 fingerprints, TLS/JA3 hashes, ASNs, and domains, refreshed
on a schedule, with provenance tracked all the way to the block
decision.

## Indicator types

| Type | Example | Consumers |
|---|---|---|
| `ipv4` / `ipv6` / `cidr` | `203.0.113.0/24` | IP reputation |
| `domain` | `evil.example` | SSRF, rule engine |
| `url` | `/wp-admin/` | rule engine |
| `ja3` / `ja4` | `769,47-53...` | device fingerprint |
| `user_agent` regex | `sqlmap/.*` | rule engine |
| `asn` | `12345` | IP reputation |
| `file_hash` | `sha256:...` | content scanning |

## Feed providers

- **TAXII 2.1** — pull STIX 2.1 bundles from a collection
- **MISP** — pull events via REST API
- **Commercial HTTPS** (Cloudflare, Crowdsec, Recorded Future, GreyNoise,
  Spur, AbuseIPDB enterprise) — API-key auth
- **Plain-text list** — line-per-entry, minimal metadata
- **Local file** — air-gapped environments

## Indicator record

```rust
pub struct Indicator {
    pub value: IndicatorValue,
    pub feed_id: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub ttl_s: u64,
    pub confidence: u8,     // 0-100
    pub severity: u8,       // 0-100
    pub action_hint: ActionHint, // block | raise_risk | watch
    pub labels: Vec<String>,
}
```

## Index structure

Indexed by type for O(1) lookup:

- `HashSet<IpAddr>` for exact IPs
- CIDR sorted list with binary search
- `AhoCorasick` for URL / UA literals
- `HashMap<String, Indicator>` for hashes and JA4

All indexes live behind `ArcSwap<FeedIndex>` so updates are atomic
and hot-path reads are wait-free.

## Provenance

Every indicator carries `feed_id` + `confidence` through to the audit
record. When a block decision cites a feed indicator, the auditor can
trace the chain: `block → rule → indicator → feed → source`.

Revoking or disabling a feed removes its indicators on the next
`ArcSwap` swap — instant global retraction.

## Confidence → action

```yaml
threat_intel:
  action_mapping:
    confidence_gte_80_and_severity_gte_70: block
    confidence_gte_50: raise_risk_20
    confidence_gte_20: watch
```

## Feed refresh

Runs on the cluster leader (see [`ha-clustering.md`](./ha-clustering.md))
to avoid redundant fetches. Workers consume the resulting index
through the state backend (or hot-reload broadcast).

## Freshness + staleness

- Feeds that haven't updated within `stale_after` emit a warning
- Indicators past their TTL are evicted on the next swap
- Clock skew guarded by `max_future_drift_s`

## Configuration

```yaml
threat_intel:
  enabled: true
  feeds:
    - name: abuseipdb
      type: http_txt
      url: "https://lists.blocklist.de/lists/all.txt"
      refresh_s: 3600
      default_confidence: 60
      default_action: raise_risk_20

    - name: mitre_taxii
      type: taxii21
      url: "https://cti-taxii.mitre.org/stix/collections/..."
      refresh_s: 21600

    - name: vendor_feed
      type: http_json
      url: "https://api.vendor.example/indicators"
      auth: { type: bearer, token: "${secret:vault:kv/data/waf#ti_token}" }
      refresh_s: 900

  action_mapping: { ... }
  stale_after_s: 86400
```

## Implementation

- `src/threat_intel/fetcher.rs` — per-feed scheduler
- `src/threat_intel/taxii.rs` — STIX 2.1 + TAXII 2.1 parser
- `src/threat_intel/misp.rs` — MISP REST client
- `src/threat_intel/index.rs` — `FeedIndex` + `ArcSwap`
- `src/threat_intel/provenance.rs` — decision trail helper

## Performance notes

- Hot-path lookup is a single `ArcSwap::load()` + hashmap/binary search
- Feed fetches are off-hot-path on the leader
- Index rebuilds are incremental where possible
