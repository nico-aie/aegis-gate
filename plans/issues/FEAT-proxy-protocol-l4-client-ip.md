# FEAT — PROXY protocol: real client IP behind an L4 load balancer

> **Type:** FEAT (feature track) · **Status:** 🟠 P1 shipped — P2 next · **Branch:** `develop`
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

- [x] **P1 — Parse + listener flag (observe-only)** — *shipped*
  - New `crates/aegis-proxy/src/listener/proxy_protocol.rs`: peek-sniff (1 byte, no consume) + exact-length v1/v2 async read + `ppp` v2.3.0 parse + deadline-bounded; 10 unit tests incl. "no ClientHello over-read" assertions.
  - `ProxyProtocolMode` enum (`off | strict | optional`) on `ListenerConfig`, `#[serde(default)] = off` + `is_enabled()`; config-plane round-trip tests.
  - Threaded `accept_proxy` through `run.rs` → `accept_loop` (new `proxy_mode` param); reads `upstream_ctx.trusted_proxies` for the observe-only `trusted_lb` log field.
  - **Parse + log + observe only — peer NOT overridden; trust NOT enforced (P2).** Corrupted streams (malformed/oversize/timeout/eof) dropped; `strict`-missing/`absent` fall through to TLS (strict-close is P2).
  - **Gate:** ✅ parser unit matrix green (10/10); ✅ default-off path branch-skipped (798 aegis-proxy + config tests green, `run_binds_and_serves_200` unchanged).
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

## Decisions — locked at recommended defaults (operator: "use recommended defaults", 2026-06-11)

| # | Decision | Locked value | Locked? |
|---|---|---|---|
| 1 | Parser crate: `ppp` vs `proxy-protocol` | `ppp` v2.3.0, pinned (`=2.3.0`). No `deny.toml` in repo yet → not surfaced to `cargo deny` (follow-up if one is added). | [x] |
| 2 | Dedicated trust list vs reuse `proxy.trusted_proxies` | Reuse `proxy.trusted_proxies` (P1 observes `trusted_lb`; P2 enforces). | [x] |
| 3 | `UNIX` address family handling | Lenient — `source: None` → keep real peer (same as LOCAL/UNSPEC). | [x] |
| 4 | Adopt PROXY source **port** into `peer` | Adopt — `ProxyHeader.source` carries source IP **and** port. | [x] |
| 5 | `proxy_via` surface | Audit-only field, no header injection (P3). | [x] |
| 6 | Canonical deploy doc for topology matrix | `deploy/HACKATHON-FLEET.md` (revisit in P4). | [x] |
| 7 | v2 TLV passthrough | Ignore TLVs; payload read but not parsed (cap 1 KiB). | [x] |

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
