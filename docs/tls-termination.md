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
tls:
  listen: "0.0.0.0:443"
  min_version: tls1_2       # tls1_3 in PCI mode
  certificates:
    - host: "api.example.com"
      cert_file: "/etc/waf/certs/api.pem"
      key_file:  "${secret:file:/etc/waf/keys/api.key}"
    - host: "*.example.com"
      cert_file: "/etc/waf/certs/wildcard.pem"
      key_file:  "/etc/waf/certs/wildcard.key"
  default_cert:
      cert_file: "/etc/waf/certs/default.pem"
      key_file:  "/etc/waf/certs/default.key"
  acme:
    enabled: false
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    email: "ops@example.com"
    hosts: ["api.example.com"]
    challenge: http01       # or tls_alpn01
  ocsp_stapling: true
```

## Implementation

- `src/tls/resolver.rs` — `DynamicResolver`, `CertStore`
- `src/tls/loader.rs` — file parser + watcher
- `src/tls/acme.rs` — ACME client (feature-gated)
- `src/tls/ocsp.rs` — OCSP refresher
- `src/tls/fips.rs` — FIPS provider selection + cipher allowlist

## Performance notes

- Handshake on fresh connection: ~1–2 ms with TLS 1.3 + AES-NI
- Session resumption (tickets, 0-RTT optional) avoids full handshake cost
- `aws-lc-rs` is faster than `ring` for AES-GCM on most CPUs
- Cert store lookup is a single hashmap get on the hot path
