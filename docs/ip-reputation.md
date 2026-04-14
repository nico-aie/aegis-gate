# IP Reputation & Proxy Detection (v2)

> **v1 → v2:** the reputation pipeline now consumes **STIX 2.1 / TAXII 2.1**
> threat-intel feeds with provenance tags, supports **per-tenant** lists,
> and records feed-id + confidence on every block so auditors can trace
> *why* an IP was rejected. See [`threat-intelligence.md`](./threat-intelligence.md).

## Purpose

Classify client IPs and short-circuit traffic from obviously hostile
sources before spending CPU on detection. Clean, high-confidence blocks
should be cheap — O(1) hash lookup plus one CIDR range check.

## Data sources

### Static lists (per tenant)

- **Blacklist** — hits return 403 immediately
- **Whitelist** — bypass IP-based blocking (detection still runs)
- **Trusted proxies** — CIDRs whose `X-Forwarded-For` is trusted

All lists hot-reload via [`config-hot-reload.md`](./config-hot-reload.md).
Tenants can add their own entries without touching cluster-wide lists.

### ASN classification

MaxMind GeoLite2-ASN (or a paid feed) maps IP → `(asn, org, category)`:

| Category | Default Δrisk | Examples |
|---|---|---|
| `residential` / `mobile` / `business` | 0 | Comcast, Vodafone, corporate uplink |
| `hosting` | +15 | AWS, GCP, Hetzner |
| `vpn` | +20 | NordVPN, Mullvad |
| `tor` | +30 | Tor exit nodes |
| `bogon` | block | private, reserved, unallocated |

Operators override the mapping in config.

### Threat-intel feeds

Managed by [`threat-intelligence.md`](./threat-intelligence.md):

- STIX 2.1 / TAXII 2.1 collections
- Plain-text lists (AbuseIPDB, emergingthreats, spamhaus)
- Commercial feeds with JWT/API-key auth
- Each indicator carries `{feed_id, first_seen, confidence, ttl}`
- Low-confidence indicators **raise risk**, high-confidence ones **block**

### Feed provenance on every decision

Audit events include `feed_id` + `confidence` so an operator can tell
which feed caused a block. Revoking or disabling a feed instantly
retracts its blocks via hot reload.

## X-Forwarded-For validation

When sitting behind a CDN or L4 LB:

1. Start from the right-most XFF entry (most recently added)
2. If the TCP peer is in `trusted_proxies`, walk left through the chain
3. The first IP not in `trusted_proxies` is the true client
4. If the TCP peer is untrusted, ignore XFF entirely — peer IS the client

This prevents spoofed XFF from upstream attackers.

## Pipeline position

Runs very early (right after XFF resolution):

1. Blacklist / feed-blocklist → 403 on match
2. Whitelist → bypass IP-based penalties
3. ASN classification → attach tag + Δrisk to context
4. Auto-block check (clustered DDoS list) → 503 if active

## Configuration

```yaml
ip_reputation:
  blacklist:
    - "198.51.100.0/24"
  whitelist:
    - "10.0.0.0/8"
  trusted_proxies:
    - "192.168.1.0/24"
  asn_database: "/etc/waf/GeoLite2-ASN.mmdb"
  asn_risk:
    hosting: 15
    vpn: 20
    tor: 30
  threat_intel_refs:
    - abuseipdb
    - spamhaus_drop
  per_tenant_overrides:
    acme:
      whitelist: ["203.0.113.0/24"]
```

## Implementation

- `src/ip/reputation.rs` — list + ASN + feed orchestrator
- `src/ip/xff.rs` — XFF validation, true-client extraction
- `src/ip/asn.rs` — MaxMind wrapper (mmap)
- `src/ip/feed_index.rs` — merged view of all active feed indicators
- `src/ip/geo.rs` — GeoIP (see [`geoip-filtering.md`](./geoip-filtering.md))

## Performance notes

- Exact-IP lookup: `HashSet<IpAddr>`, O(1)
- CIDR match: sorted `Vec<IpNet>` with binary search, O(log n)
- ASN DB is memory-mapped, zero allocation per lookup
- Per-request LRU de-dupes ASN lookups across pipeline stages
- Feed index hot-swapped via `ArcSwap<FeedIndex>`
