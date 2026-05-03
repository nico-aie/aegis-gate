# `data/geoip/` — MaxMind GeoIP databases (local only)

This directory holds the `.mmdb` files the WAF reads at boot when
built with the `geoip` Cargo feature. **The files themselves are
never committed** (see `.gitignore`); each operator populates
the directory locally.

## Why not in git

- MaxMind's GeoLite2 license requires updating every 30 days;
  data committed to git would go stale within a release cycle.
- Combined size is ~20 MB. Binary blobs in git history bloat
  every clone forever.
- License terms restrict redistribution — even a private repo
  can run afoul if the data leaks.

## Setup

Three options, in order of preference:

### 1. From a local download (`make geoip-link`)

Drop the MaxMind extracts into `~/Downloads/` (the default zip
shape is `GeoLite2-{Country,ASN}_<YYYYMMDD>/GeoLite2-*.mmdb`),
then:

```sh
make geoip-link
```

The target finds the most-recent extract for each DB and
symlinks the `.mmdb` into `data/geoip/`. Re-run after each
MaxMind refresh.

### 2. From a custom path

```sh
make geoip-link \
  COUNTRY_DB=/path/to/GeoLite2-Country.mmdb \
  ASN_DB=/path/to/GeoLite2-ASN.mmdb
```

### 3. Manual copy

```sh
cp /path/to/GeoLite2-Country.mmdb data/geoip/
cp /path/to/GeoLite2-ASN.mmdb     data/geoip/
```

## Wiring into config

`config/dev.yaml` already points at `data/geoip/*.mmdb` under
the `geoip:` block. Production configs reference the same
shape (see `docs/security/geoip-filtering.md`).

## Verification

After `make run-dev` with the `geoip` feature on:

```sh
curl -sk https://localhost:9443/api/attacks/top | jq '.[0]'
# Rows should carry `country` + `asn` fields. Without the DBs
# (or without the `geoip` Cargo feature), those fields are absent.
```

## License

Operators are bound by [MaxMind's GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula).
This directory's `.gitignore` exists in part to keep us on
the right side of that license.
