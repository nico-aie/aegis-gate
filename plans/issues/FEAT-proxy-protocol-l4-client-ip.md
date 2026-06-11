# FEAT — PROXY protocol: real client IP behind an L4 load balancer

> **Type:** FEAT (feature track) · **Status:** Designed — not started · **Branch:** `develop`
> **Design doc:** [`../future/proxy-protocol.md`](../future/proxy-protocol.md) (decisions + justification live there)
> **Roadmap slot:** [`../future/world-class-waf-roadmap.md`](../future/world-class-waf-roadmap.md) — HA/LB tier.
> **Builds on (shipped):** C-5 `proxy.trusted_proxies` ([`../archive/multi-node-consistency-implementation.md`](../archive/multi-node-consistency-implementation.md) P1) — same trust set, extended from XFF to PROXY.

**Goal (one line):** let an L4 / TCP-passthrough load balancer (nginx `stream proxy_protocol on;`
or HAProxy `send-proxy-v2`) prepend a PROXY-protocol header carrying the **real client IP**; the
WAF parses it on the raw socket **before** the TLS handshake, adopts it as the effective peer, then
terminates TLS exactly as today — so per-IP rate-limit / risk / geoip key on the real client **and**
JA3/JA4 still come from the client's own ClientHello.

**Off by default.** `accept_proxy` defaults to `off` on every listener: no extra read, no parse, no
allocation on the accept path. Existing single-node / DNS-RR / L4 deployments are byte-for-byte
unchanged. (Design §0.)

---

## Phase checklist

- [ ] **P1 — Parse + listener flag (observe-only)** — `~350 LoC · ~2d`
  - New `crates/aegis-proxy/src/listener/proxy_protocol.rs`: bounded v1/v2 async read + `ppp` parse + unit tests.
  - `ProxyProtocolMode` enum (`off | strict | optional`) on `ListenerConfig`, `#[serde(default)] = off`.
  - Thread mode + parsed trusted nets through `run.rs:1509` → `accept_loop`.
  - **Parse + log + count only — do NOT override the peer yet.**
  - **Gate:** parser unit matrix green; default-off path proven to do zero extra reads.
- [ ] **P2 — Trust + effective-peer override + boot validation** — `~250 LoC · ~2d`
  - Honour header only from a TCP peer inside `proxy.trusted_proxies`; untrusted source → close (fail-closed).
  - Rebind `peer: SocketAddr` in `accept_loop` after parse, **before** `acc.accept(stream)`.
  - Boot validation: any listener with `accept_proxy != off` requires `proxy.trusted_proxies` non-empty.
  - **Gate:** differential-risk behaviour live — attacker IP A gated while clean IP B (same LB) unaffected.
- [ ] **P3 — Audit / XFF precedence + failure-mode hardening + metrics** — `~250 LoC · ~1.5d`
  - `proxy_via` debug field (real LB hop); confirm PROXY→XFF composition (`resolve_client_ip` unchanged).
  - Full failure-mode table (design §3.6): v2 LOCAL / UNSPEC / IPv6 / malformed / timeout.
  - Metrics counter `proxy_protocol_events{result=...}`; document the audit-`ip` semantics shift.
  - **Gate:** every §3.6 row maps to its documented outcome + metric label under test.
- [ ] **P4 — Docs + LB wiring + cluster rig** — `~300 LoC · ~2d` (+ `~300 LoC · ~1.5d` tests)
  - `config/REFERENCE.md` (`accept_proxy`); deploy topology matrix 4th row + nginx `stream` / HAProxy examples.
  - `tests/cluster/10-proxy-protocol-client-ip.sh` 2-node rig + `run-all.sh` entry; FEATURES/architecture cross-refs.
  - **Gate:** §"Acceptance gates" below fully green before recommending PROXY as a supported topology.

**Total: ~1,700 LoC · ~9 working days.**

---

## Decisions to lock before P1 (design §10 — recommended defaults, confirm in review)

| # | Decision | Recommended default | Locked? |
|---|---|---|---|
| 1 | Parser crate: `ppp` vs `proxy-protocol` | `ppp` (pure-Rust v1+v2; pin + `cargo deny`) | [ ] |
| 2 | Dedicated trust list vs reuse `proxy.trusted_proxies` | Reuse; add split only if a real split-trust topology appears | [ ] |
| 3 | `UNIX` address family handling | Lenient — use real peer (TCP edge won't see it; treat like LOCAL) | [ ] |
| 4 | Adopt PROXY source **port** into `peer` | Adopt (audit completeness; risk/RL key on IP so cosmetic) | [ ] |
| 5 | `proxy_via` surface | Audit-only field, no `X-WAF-Proxy-Via` header injection | [ ] |
| 6 | Canonical deploy doc for topology matrix | Confirm `deploy/HACKATHON-FLEET.md` is the live home | [ ] |
| 7 | v2 TLV passthrough | Ignore TLVs in v1; AWS-NLB SNI TLVs are a future enhancement | [ ] |

---

## Files to touch (anticipated — design §5)

- **new** `crates/aegis-proxy/src/listener/proxy_protocol.rs` — bounded async read + `ppp` parse → `ProxyHeader { source: Option<SocketAddr>, command }` + unit tests.
- `crates/aegis-proxy/src/listener/mod.rs` — register module.
- `crates/aegis-proxy/src/accept.rs` — `accept_loop` (~1404–1466): post-`tcp.accept()`, gated read+parse+trust+rebind before `acc.accept`. New params: `proxy_mode` + `trusted_proxies: Arc<Vec<IpNet>>`.
- `crates/aegis-proxy/src/run.rs` (~1509–1560) — read `listener_cfg.accept_proxy`, pass mode + parsed nets into `accept_loop`.
- `crates/aegis-core/src/config.rs` — `ProxyProtocolMode` enum; `accept_proxy` field on `ListenerConfig`; validation in `WafConfig::validate` (near the C-5 `trusted_proxies` check ~`:988`).
- `crates/aegis-proxy/Cargo.toml` + workspace `Cargo.toml` — add `ppp` (pin + `cargo deny`).
- Audit projection — optional `proxy_via`.
- `crates/aegis-control/src/metrics/` — `proxy_protocol_events` counter (follow `decisions` / `detector_hits` pattern).
- Docs: `config/REFERENCE.md`, `deploy/HACKATHON-FLEET.md`, `docs/security/ip-reputation.md`, `docs/security/risk-scoring.md`, `docs/FEATURES.md`.
- Tests: `proxy_protocol.rs` unit tests; an integration test; `tests/cluster/10-proxy-protocol-client-ip.sh` + `run-all.sh`.

---

## Acceptance gates (merge bar — design §7)

- [ ] PROXY header honoured **only** from a peer in `trusted_proxies`; untrusted source → closed.
- [ ] `accept_proxy ⇒ trusted_proxies non-empty` enforced at boot (no silent reject-all / honour-all).
- [ ] Default `off` proven zero-cost / zero-behaviour-change (no read on the accept path).
- [ ] Exact-length read — no ClientHello byte consumed; JA3/JA4 unchanged (test asserts).
- [ ] Malformed / truncated / oversized header closes the connection, never falls through to TLS.
- [ ] Pre-TLS read is deadline-bounded (no slowloris on the raw socket).
- [ ] Differential-risk test: attacker IP A gated while clean IP B (same LB) unaffected.
- [ ] `proxy_via` recorded; audit-`ip` semantics documented.
- [ ] mTLS (`zero_trust.downstream`) still verifies the client cert on a PROXY listener.

---

## Out of scope (design §11)

PROXY *upstream* (WAF → backend); TPROXY / `IP_TRANSPARENT` (needs root); L7-LB + XFF JA3/JA4
recovery (impossible by construction); any new auth/identity mechanism (PROXY asserts a network
address, not an identity — rides entirely on the `trusted_proxies` boundary).
