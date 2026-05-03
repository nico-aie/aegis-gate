---
id: 2026-05-03-geoip-status-indicator-count-zero
date: 2026-05-03T16:10Z
severity: LOW
area: control-plane
component: api/geoip/status
status: open
build_sha: cb95934
test_mode: smoke
---

# `/api/geoip/status.indicator_count` is 0 even when both DBs are loaded

## Summary

`/api/geoip/status` reports `db_loaded: true` and the right
file paths for both `GeoLite2-Country.mmdb` and
`GeoLite2-ASN.mmdb`, but `indicator_count: 0`.  The Threat-Intel
dashboard subtitle pulls this number ("N indicators") and shows
"0 indicators" which reads as "DB is empty" — confusing
when paired with `db_loaded: true`.

## Repro

```bash
make geoip-link COUNTRY_DB=/path/to/GeoLite2-Country.mmdb \
                ASN_DB=/path/to/GeoLite2-ASN.mmdb
make run-dev
curl -s -b /tmp/aegis-skill.jar http://127.0.0.1:9443/api/geoip/status | jq
```

## Expected

`indicator_count` reports a meaningful number — typically the
record count from the .mmdb file (~600k for GeoLite2-Country,
~700k for ASN), OR the field is dropped from the response
entirely if it doesn't apply.

## Actual

```jsonc
{
  "asn_db_path": "data/geoip/GeoLite2-ASN.mmdb",
  "db_loaded": true,
  "db_path": "data/geoip/GeoLite2-Country.mmdb",
  "feature_built": true,
  "indicator_count": 0,
  "note": "GeoIP reader live. /api/attacks/top rows carry country + asn."
}
```

## Suggested fix

Either populate `indicator_count` from the maxminddb reader's
metadata (the .mmdb file format includes a `node_count` /
`record_size` block; the maxminddb crate exposes them via
`Reader::metadata`) — OR drop the field from the response and
update the dashboard's Threat-Intel page to not display it.

## Severity rationale

LOW — operator-visible inconsistency that resolves with one
sentence in the docs ("indicator_count is reserved for future
use; ignore the 0"), but worth fixing for cleanliness.

## Done-when

Field returns a meaningful number, or is removed from the
response shape and the dashboard.
