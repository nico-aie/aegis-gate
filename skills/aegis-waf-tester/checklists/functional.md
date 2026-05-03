# Functional checklist

Every item below is a yes/no test. Walk top-to-bottom and file a
finding for any "no" outcome. Re-use scripts under `tests/manual/`
where they exist — don't retype curl commands.

## A. Authentication + session

- [ ] `GET /admin/login` returns the login HTML page (not a 404
      JSON). HTML body contains `id="login-form"`.
- [ ] `POST /admin/login` with bad creds returns 401 and the
      response JSON has a non-empty `message` field.
- [ ] `POST /admin/login` with good creds returns 200 + sets both
      `aegis_session` and `aegis_csrf` cookies.
- [ ] An authenticated `PUT /api/blacklist` with a valid CSRF
      header succeeds (200 / 204).
- [ ] Same `PUT /api/blacklist` with a missing `x-csrf-token`
      header returns 403 with reason code `csrf_missing` (or
      similar `csrf_*` code).
- [ ] Same `PUT /api/blacklist` with a wrong `x-csrf-token`
      header returns 403 with reason `csrf_mismatch`.
- [ ] `POST /admin/logout` returns 204 and the next mutation
      attempt with the now-stale CSRF returns 403.

Reference: `tests/manual/csrf-cookie-flow.sh`.

## B. Access lists — runtime enforcement

- [ ] Add a blacklist entry for an IP via `PUT /api/blacklist`.
- [ ] An immediate `curl -H "X-Forwarded-For: <ip>"` against the
      data plane returns 403 with `x-waf-rule-id: blacklist:<id>`.
- [ ] Remove the entry. The same curl now returns 200 (or
      whatever the catch-all returns).
- [ ] Repeat with a CIDR entry — both `.7` and `.42` of the
      block are denied; an out-of-block IP passes.
- [ ] Add a whitelist entry; the same IP now passes through with
      no detector evaluation (verify by sending a SQLi-shaped
      payload from the whitelisted IP — should NOT block).

Reference: `tests/manual/access-list-roundtrip.sh`.

## C. Country-code blacklist (requires GeoIP)

Only run if `make geoip-link` was executed; otherwise skip with
a `INFO` finding noting the precondition.

- [ ] Add a `kind: country` entry for `CN`.
- [ ] `curl -H "X-Forwarded-For: 223.5.5.5"` (AliDNS) returns 403
      with the country rule_id.
- [ ] `curl -H "X-Forwarded-For: 8.8.8.8"` (US, Google DNS) passes.
- [ ] Remove the entry.

Reference: `tests/manual/fake-country-ips.sh`.

## D. WebSocket bridge

- [ ] `is_websocket_upgrade` request to `ws://localhost:8080/`
      via `websocat` / `wscat` against a local WS echo backend
      round-trips at least one frame (text "hello" → "hello").
- [ ] `aegis_websocket_open_total` on `/metrics` increments by 1
      per upgrade.
- [ ] `aegis_websocket_active` reaches at least 1 during the
      session and returns to 0 on disconnect.
- [ ] Audit chain shows a `websocket_open` event followed by a
      `websocket_close` event with byte counters.
- [ ] Live Feed dashboard shows a row with `Proto = ws-open`
      pill.

Reference: `tests/manual/websocket-bridge.sh`.

## E. Multi-vhost upstream

- [ ] Edit a member with `host_header: "your-host.example"` (HTTP).
      Restart `make run-dev`.
- [ ] Send a request through; capture the upstream's request
      view (e.g. tcpdump, or via a debug echo upstream). The
      `Host:` header upstream sees is the override, not the IP.
- [ ] Original client `Host:` rides as `X-Forwarded-Host`.
- [ ] For HTTPS — point a member at a real public TLS service
      (e.g. `addr: "<dig +short example.com>:443"` +
      `host_header: "example.com"` + `connection.scheme: https`).
      The connection succeeds (no cert / SNI errors).

Reference: `QUICKSTART.md` § "Pointing at a real upstream".

## F. CRUD on dashboard surfaces

- [ ] **Routes** — `GET /api/routes` returns the configured
      routes; the dashboard "Routing & Upstreams" page renders
      them.
- [ ] **Upstreams** — Pool edit modal lets you toggle
      `host_header` per member; PUT `/api/upstreams/config`
      hot-swaps the pool without a restart.
- [ ] **Detectors** — toggle one detector off via
      `PUT /api/detectors`; data plane stops firing it within
      ~2 s. Toggle back on; firings resume.
- [ ] **Alert receivers** — add a stub VipTalk receiver, fire
      `/api/alert-receivers/<id>/test`; response JSON has
      `delivered` OR `skipped_feature_off` (NOT a silent empty).
- [ ] **Mode toggles** — `POST /__waf_control/mode` between
      `enforce` / `monitor` / `bypass` lands an entry in the
      audit chain with the right rule_id.

## G. Audit + observability

- [ ] `/api/audit/since?limit=10` returns the latest 10 events
      with hash chain (each event has `seq`, `hash`, `prev_hash`).
- [ ] `waf audit verify --from /tmp/aegis-dev-audit.jsonl`
      returns 0 (chain integrity).
- [ ] `/dashboard/sse` streams new events live (open with
      `curl -N`, drive traffic, observe new lines).
- [ ] Live Feed Path column populates (was a known historical
      bug — verify it's still fixed).
- [ ] `/api/attacks/top` returns ranked attackers within ~10 s
      of running the drive-traffic script.

## H. Hot-reload

- [ ] Edit `cfg.detectors.<one-class>.enabled: false` in
      `config/dev.yaml`. Save. Within ~5 s the WAF logs
      `config_reload`; data plane stops firing that class.
- [ ] Restore the field; reload re-enables.
- [ ] Edit a route's `path:`. Save. Routing follows the new
      path within ~5 s.
- [ ] Edit `cfg.tls.certificates`. Save (or run `make reset-cert`).
      In-flight handshakes finish on the old store; new ones
      use the rotated cert.

## I. Compliance modes

- [ ] `cfg.compliance.modes: pci_dss`. Try to disable a
      PCI-pinned detector via `PUT /api/detectors`. Should be
      clamped — detector stays enabled, audit logs
      `compliance_clamp_applied`.
