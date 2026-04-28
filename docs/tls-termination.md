# TLS Termination (v2)

> **v1 → v2:** TLS is **promoted from bonus to required**. The listener now
> supports SNI with a dynamic cert resolver, file-watch reloads without
> dropping connections, optional ACME auto-issue, OCSP stapling, FIPS mode,
> and mTLS to upstream pools.

## Purpose

Terminate TLS at the WAF so the security pipeline can inspect plaintext,
then (optionally) re-encrypt to the backend with mTLS. A single listener
serves many hostnames via SNI.

## Design

- `rustls 0.23` with the `aws-lc-rs` provider (FIPS-capable under
  [`compliance.md`](./compliance.md))
- A dynamic `ResolvesServerCert` backed by an `ArcSwap<CertStore>`
- ALPN advertising `h2, http/1.1` (and `acme-tls/1` when ACME TLS-ALPN-01 is active)
- TLS 1.3 enabled by default; TLS 1.2 allowed via config (rejected in PCI mode)

```rust
pub struct CertStore {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

pub struct DynamicResolver { store: Arc<ArcSwap<CertStore>> }

impl rustls::server::ResolvesServerCert for DynamicResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let store = self.store.load();
        hello.server_name()
            .and_then(|s| store.by_host.get(s).cloned())
            .or_else(|| store.default.clone())
    }
}
```

## Cert sources

1. **File** — PEM cert + key pairs on disk, watched by `notify`. On change,
   the loader parses, validates the cert chain, and atomically swaps the
   `CertStore`.
2. **ACME** (optional, `--features acme`) — Let's Encrypt via
   `instant-acme`. Supports HTTP-01 (route `/.well-known/acme-challenge/*`
   injected automatically) and TLS-ALPN-01 (ALPN `acme-tls/1`). Renewal runs
   on a timer.
3. **HSM / PKCS#11** (bonus) — private key stays in the HSM; signing ops
   via `cryptoki`.

## OCSP stapling

A background task refreshes OCSP responses per cert at half of their
validity window, writes them into `CertifiedKey::ocsp`, and the swap is
atomic with the rest of the cert store.

## Cipher suite policy

- Default: TLS 1.3 (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`,
  `TLS_CHACHA20_POLY1305_SHA256`) + TLS 1.2 ECDHE-GCM suites
- FIPS mode: only the `aws-lc-rs` FIPS-validated subset
- PCI mode: TLS 1.2+ only, weak suites refused at config load

## mTLS to upstream

Configured per pool in [`upstream-pools.md`](./upstream-pools.md):

```yaml
upstreams:
  internal_svc:
    members: [...]
    tls:
      sni: "internal.svc.local"
      ca_bundle: "/etc/waf/certs/internal-ca.pem"
      client_cert: "/etc/waf/certs/waf-client.pem"
      client_key:  "${secret:vault:kv/data/waf#upstream_key}"
      min_version: tls1_3
```

Each pool owns a dedicated `hyper` client with a distinct `rustls::ClientConfig`.

## Zero-downtime cert reload

File-change events do not touch the listener. In-flight handshakes complete
with the old cert; new handshakes pick up the new one. No connection drops.

## Configuration

```yaml
listeners:
  data: [{ bind: "0.0.0.0:443" }]
  admin: { bind: "127.0.0.1:9443" }
  # P4: optional plain-HTTP redirect listener.
  force_https: { bind: "0.0.0.0:80", status: 301 }   # 301 or 308

tls:
  # P4 hardening
  min_version: "1.2"          # "1.2" or "1.3"; rejected at config load otherwise
  force_https: true           # informational; redirect listener above does the work
  hsts:
    max_age: 31536000         # >= 31536000 if `preload: true`
    include_subdomains: true  # required for `preload: true`
    preload: false

  certificates:
    - cert_path: "/etc/waf/certs/api.pem"
      key_ref:   "${secret:file:/etc/waf/keys/api.key}"
      hosts:     ["api.example.com"]

  # P5: ACME / Let's Encrypt automation
  acme:
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    contacts: ["mailto:ops@example.com"]
    domains:  ["api.example.com"]
    account_key_path: "/var/lib/aegis/acme.json"
    cert_dir:         "/var/lib/aegis/certs"
    renew_before:     30d
    terms_of_service_agreed: true
    challenge: http01           # http01 | tls_alpn01 | dns01
```

### P4 hardening invariants

`WafConfig::validate()` rejects:

| Field | Constraint |
|---|---|
| `tls.min_version` | must be `"1.2"` or `"1.3"` |
| `tls.hsts.max_age` | must be > 0 (RFC 6797 §6.1.1) |
| `tls.hsts.preload` | requires `max_age >= 31536000` and `include_subdomains: true` |
| `listeners.force_https.status` | must be 301 or 308 |

The hardened rustls `ServerConfig` is built via
`aegis_proxy::listener::tls_policy::build_hardened_server_config(resolver, min_version)`
which uses `ServerConfig::builder_with_protocol_versions(versions)`.
Older clients fail the handshake rather than negotiate down.

### P5 ACME flow

1. Boot reads `tls.acme`, validates contacts / domains / TOS.
2. `register_account` loads `account_key_path` if it exists or
   registers a new account (persists `AccountCredentials` JSON
   with `0600` mode).
3. `place_order` extracts the HTTP-01 token + key authorisation
   for each domain and publishes them to the `ChallengeStore`
   shared with the `force_https_loop`.
4. The plain-HTTP listener serves
   `/.well-known/acme-challenge/{token}` directly (200 +
   `application/octet-stream`); every other request redirects.
5. After validation, finalise via `rcgen`-built CSR, download
   the chain, write `cert_dir/{domain}/{cert,key}.pem` and
   swap into the live `Arc<ArcSwap<CertStore>>`.
6. The renewal scheduler (`spawn_renewal_scheduler`) ticks at
   half the renew window, clamped to `[60s, 3600s]`, and
   triggers `manager.issue()` whenever any inventoried cert is
   within `renew_before` of expiry.

## Implementation

- `aegis-proxy::listener::tls` — `DynamicResolver`, `CertStore`
- `aegis-proxy::listener::tls_policy` — **P4** `protocol_versions_for`,
  `build_hardened_server_config`, `format_hsts_header`,
  `force_https_redirect_response`
- `aegis-proxy::acme` — **P5** trait + `AcmeManager` state machine
  + `ChallengeStore`
- `aegis-proxy::acme_instant` — **P5 follow-up** `instant-acme`
  network adapter + persistence helpers
- `aegis-proxy::force_https_loop` — plain-HTTP listener that
  serves both ACME HTTP-01 challenges and the redirect

## Performance notes

- Handshake on fresh connection: ~1–2 ms with TLS 1.3 + AES-NI
- Session resumption (tickets, 0-RTT optional) avoids full handshake cost
- `aws-lc-rs` is faster than `ring` for AES-GCM on most CPUs
- Cert store lookup is a single hashmap get on the hot path
