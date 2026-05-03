# Manual Validation Scripts

Hand-runnable scripts that drive the **live console** end-to-end so you
can poke at the recently-shipped fixes (access lists, CSRF, admin TLS,
WebSocket bridge, VipTalk alerts) without needing a full CI rig.

These are **not** part of `tests/api/run-all.sh` — they exist to give
the operator a fast loop while debugging or demoing.

## Prereqs

```bash
make run-dev                   # the WAF must be live on the configured ports
export ADMIN_USER=admin
export ADMIN_PASS=admin        # whatever your dev hash is
export AEGIS_ADMIN=http://127.0.0.1:9443  # use https:// once admin TLS is on
export AEGIS_DATA=http://127.0.0.1:8080   # or 8443 for the TLS listener
```

`curl` and `jq` are required.

## Scripts

| Script | What it covers |
|---|---|
| [`fake-country-ips.sh`](fake-country-ips.sh) | Drives the country-code blacklist with spoofed `X-Forwarded-For` headers from known-country IPs (US / CN / RU / DE …). Verifies the runtime matcher actually consults the GeoIP DB. |
| [`access-list-roundtrip.sh`](access-list-roundtrip.sh) | Adds + removes blacklist / whitelist entries via the Console API and asserts each one takes effect against the data plane within a request. |
| [`csrf-cookie-flow.sh`](csrf-cookie-flow.sh) | Exercises the login → CSRF cookie → mutation pipeline so you can verify a fresh session gets a valid CSRF token and stale ones get the 403 redirect. |
| [`websocket-bridge.sh`](websocket-bridge.sh) | Drives a real `wscat` / `websocat` round-trip through the WAF to a backend echo server. |
| [`viptalk-alert-test.sh`](viptalk-alert-test.sh) | Posts a synthetic alert at the `/api/alert-receivers/test` endpoint and asserts the dispatch summary calls out delivered / skipped_feature_off explicitly. |

## How fake IPs work

The data plane resolves the real client IP from `X-Forwarded-For`
**only when** the connection is from a trusted proxy. The default
trusted set is RFC 1918 + loopback (127.0.0.0/8, 10.0.0.0/8, …) so any
`curl` from your dev box is automatically trusted. You can therefore
spoof "the request came from 1.1.1.1" with:

```bash
curl -H "X-Forwarded-For: 1.1.1.1" "$AEGIS_DATA/some/path"
```

The strike gate, blacklist matcher, GeoIP lookup, and audit log all see
`1.1.1.1` as the peer. `fake-country-ips.sh` uses this trick to drive
the country-code path with one IP per region.

## Quick reference: known-country IPs

| Country | Sample IP |
|---|---|
| US | 8.8.8.8 (Google DNS) |
| CN | 223.5.5.5 (AliDNS) |
| RU | 77.88.8.8 (Yandex DNS) |
| DE | 195.30.6.6 (Telekom) |
| JP | 210.130.0.1 (NTT) |
| BR | 200.221.11.100 |
| GB | 80.0.0.1 |

These resolve cleanly against MaxMind's GeoLite2-Country.mmdb. If you
get `unknown country` from `fake-country-ips.sh`, the most likely cause
is that `cfg.geoip.country_db` isn't pointing at a valid `.mmdb` file —
run `make geoip-link MMDB=/path/to/GeoLite2-Country.mmdb` first.
