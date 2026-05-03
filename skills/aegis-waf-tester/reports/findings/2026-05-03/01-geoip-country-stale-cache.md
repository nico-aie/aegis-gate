---
id: 2026-05-03-geoip-country-stale-cache
date: 2026-05-03T16:10Z
severity: HIGH
area: control-plane
component: api/attacks/top + AttacksHandler GeoIP enrichment
status: open
build_sha: cb95934
test_mode: smoke
---

# `country` is null on existing Top-Attackers rows even when the GeoLite2 DB has the answer

## Summary

`/api/attacks/top` returns `country: null` for attackers that were
ranked early in the window, but the SAME public IP returns a
correct country code when it first hits the WAF on a fresh boot.
ASN resolves correctly on both old and new entries.  Looks like
the Attacker entry caches the country result at creation time
and never re-queries — so a transient GeoIP miss (boot race?
single-flight contention?) sticks for the lifetime of the entry.

This is HIGH because the SOC analyst sees an empty Country column
on the busiest attackers (the ones they care most about) and the
GeoIP "DB loaded" pill on Threat Intel reads as a lie.

## Repro

1. Boot WAF: `make run-dev` (with `data/geoip/GeoLite2-Country.mmdb`
   and `GeoLite2-ASN.mmdb` linked via `make geoip-link`).
2. Drive 30 s of traffic via `bash skills/aegis-waf-tester/scripts/drive-traffic.sh`.
   Script spoofs XFF from 8.8.8.8 / 1.1.1.1 / 9.9.9.9.
3. Pull `/api/attacks/top`.  The early-ranked attackers
   (1.1.1.1, 9.9.9.9, etc.) carry `country: null`.
4. Drive a few more requests from a NEW public IP
   (`curl -H "X-Forwarded-For: 8.8.8.8" $DATA/?q=union+select`).
5. Pull `/api/attacks/top` again.  The freshly-added 8.8.8.8 row
   has `country: "US"`.

## Expected

```jsonc
{ "identifier": "1.1.1.1",  "country": "US" /* or "AU" */, "asn": 13335 }
{ "identifier": "9.9.9.9",  "country": "CH",               "asn": 19281 }
```

GeoLite2-Country.mmdb has entries for all three IPs; verified via
`/api/geoip/status` returning `"db_loaded": true`.

## Actual

```jsonc
// 1.1.1.1 + 9.9.9.9 stuck at null country, asn correct:
{ "identifier": "1.1.1.1", "country": null, "asn": 13335 }
{ "identifier": "9.9.9.9", "country": null, "asn": 19281 }

// 8.8.8.8 added later, country resolves cleanly:
{ "identifier": "8.8.8.8", "country": "US", "asn": 15169 }
```

## Evidence

- `/api/geoip/status` returns:
  `{"db_loaded": true, "db_path": "data/geoip/GeoLite2-Country.mmdb",
    "asn_db_path": "data/geoip/GeoLite2-ASN.mmdb", "indicator_count": 0}`
- ASN resolves on every entry (13335 / 19281 / 15169) so the
  reader isn't broken in general — only the country field
  misses on the cached entries.

## Suggested fix

Likely in the `AttacksHandler` aggregator (probably
`crates/aegis-control/src/api/attacks.rs` around the
`Attacker::country` field).  Two probable causes:

1. The Country DB read is happening BEFORE
   `set_geo_lookup` installs the reader on the AttacksHandler
   — first audit events arrive before the reader is wired,
   their country resolves to None, and that None is cached
   for the entry's lifetime.  Re-resolve on each render
   (cheap ~µs per row) instead of caching at first-sight.
2. The DB read returns Err which is silently coerced to None
   on the cached entry.  Audit the path — if the reader
   returns Err for a known-good IP, that's the actual bug.

`indicator_count: 0` on `/api/geoip/status` is suspicious — if
the count comes from "did we successfully resolve N requests",
0 here matches the cached-null pattern.

## Severity rationale

HIGH — the Top Attackers page is the SOC analyst's morning
view (we just shipped it), and the Country column is one of
the four pieces of context that drive triage decisions.
"Country: null" for a Cloudflare attacker means the analyst
can't tell if it's a bot net or a misconfigured client.

## Done-when

`/api/attacks/top` returns the correct country for every
attacker that the GeoIP DB has data for, regardless of when
the attacker was first ranked in the window.
