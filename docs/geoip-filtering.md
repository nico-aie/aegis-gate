# GeoIP Filtering (Bonus)

## Purpose

Block, allow, or challenge traffic based on the geographic origin of the client IP. GeoIP is a blunt instrument — it shouldn't be the primary defense — but it's a useful filter for compliance (geo-blocked products), targeted attack response, and traffic shaping.

## Data source

Uses the [MaxMind GeoLite2-Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database (free) or GeoIP2-City (commercial) for higher precision. Loaded via `maxminddb` crate as a memory-mapped file.

Database location is configured; the WAF supports periodic re-loading when the file on disk changes.

```yaml
geoip:
  enabled: true
  database_path: "/etc/waf/GeoLite2-Country.mmdb"
  reload_on_change: true
```

## Policies

### Country-level allow / block

```yaml
geoip:
  policy:
    mode: blocklist       # allowlist | blocklist
    countries:
      - CN
      - RU
      - KP
    action: block          # block | challenge | add_risk
    risk_increment: 20     # if action is add_risk
```

- **blocklist mode:** specified countries are blocked (or challenged); all others pass
- **allowlist mode:** only specified countries are allowed; all others are blocked

Country codes are ISO 3166-1 alpha-2.

### Per-tier overrides

```yaml
tiers:
  - name: critical
    geoip:
      blocklist: [CN, RU, KP, IR]
      action: block
  - name: high
    geoip:
      blocklist: [CN, RU]
      action: challenge
```

### ASN + geo combined rules

GeoIP integrates with [IP reputation](./ip-reputation.md) — a rule can match on both: "block traffic from hosting ASN **in** a blocked country".

## Unknown / unresolvable IPs

Some IPs don't resolve to a country (bogons, reserved ranges, brand-new allocations). The policy for unknowns is configurable:

```yaml
geoip:
  on_unknown: pass        # pass | block | challenge
```

Default: pass (fail-open for unknowns).

## Challenge instead of block

For borderline countries, operators often prefer **challenge** over **block** — real users from those countries can solve a challenge and proceed, while naive bots are filtered out.

## Dashboard integration

The dashboard's world map (see [dashboard](./dashboard.md)) uses the same GeoIP database to display traffic by country.

## Implementation

- `src/ip/geo.rs` — `maxminddb` wrapper, country lookup, policy evaluation
- Configuration lives in the main config struct so it hot-reloads

## Performance

- MaxMind lookups are O(log n) on a B-tree, memory-mapped — microsecond latency
- No allocation per lookup
- Results can be cached in a per-request LRU if multiple stages need the same country (not usually necessary)

## Caveats

- GeoIP is **not** authentication. A determined attacker will use VPNs, proxies, or hosting providers in the allowed country
- GeoIP data is updated periodically upstream — keep the MMDB fresh (automate via cron)
- Blocking by country can violate anti-discrimination or accessibility requirements in some jurisdictions — check with legal before enabling

## Design notes

- GeoIP is a **coarse** filter; pair it with fine-grained controls (ASN, rate limiting, risk scoring) rather than relying on it alone
- The `on_unknown` fallback matters: in a blocklist policy, unknowns pass; in an allowlist policy, unknowns block — choose deliberately
- For legitimate international users hitting a GeoIP block, the challenge action is friendlier than hard-blocking
