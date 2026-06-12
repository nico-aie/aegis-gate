# PROXY protocol — real client IP behind an L4 load balancer (TLS still terminated at the WAF)

> **Status (2026-06-11): Design only — not started.** Target branch: `develop`.
> Implementation tracker: [`../issues/FEAT-proxy-protocol-l4-client-ip.md`](../issues/FEAT-proxy-protocol-l4-client-ip.md)
> (phase checklist + acceptance gates). This doc holds the design rationale.
>
> **Goal (one line):** let an L4 / TCP-passthrough load balancer (nginx `stream`
> `proxy_protocol on;`, or HAProxy `send-proxy-v2`) prepend a PROXY-protocol header
> carrying the **real client IP**; the WAF parses it on the raw socket **before** the
> TLS handshake, adopts it as the effective peer, then terminates TLS exactly as
> today — so per-IP rate-limit / risk / geoip key on the real client **and** JA3/JA4
> still come from the client's own ClientHello.
>
> **Five directional decisions (recommended, confirm in review):**
> 1. **Vetted parser, our own bounded read** — use the `ppp` crate for v1+v2 parsing;
>    we own the exact-length async read on the raw `TcpStream` so no ClientHello byte
>    is ever swallowed. (Decision §3.1.)
> 2. **Per-listener opt-in** — `accept_proxy` on `ListenerConfig`, an enum
>    `off | strict | optional`, default `off` ⇒ zero cost, zero behaviour change.
>    (Decision §3.2.)
> 3. **Reuse `proxy.trusted_proxies`** as the single "who may assert the client IP"
>    set (PROXY *and* XFF). PROXY from a peer outside it → connection closed,
>    fail-closed. (Decision §3.3.)
> 4. **Effective-peer override** — the PROXY source IP replaces the TCP peer
>    `SocketAddr` in `accept_loop` before TLS; everything downstream (incl. audit
>    `ip`) keys on it. The real LB hop is preserved as a debug field `proxy_via`.
>    (Decision §3.4.)
> 5. **Strict requires a trusted source** — `accept_proxy: strict|optional` is a boot
>    validation error unless `proxy.trusted_proxies` is non-empty. (Decision §3.3.)
>
> **Why now:** PROXY protocol is the *only* topology that delivers real-client-IP +
> JA3/JA4 + all protocols + a real single-VIP LB + **no root** (the infra host is
> rootless Docker, so TPROXY is unavailable). See §1. This is the fourth row of the
> deployment topology matrix, and the one that removes the current forced trade-off.

---

## 0. Off by default — single-node / DNS-RR / L4 stay byte-for-byte unchanged

`accept_proxy` defaults to `off` on every listener. With it off there is **no extra
read, no parse, no allocation** on the accept path — `tcp.accept()` → TLS handshake
runs exactly as today. PROXY parsing is gated on `accept_proxy != off` for that
listener, so existing deployments (WAF-at-edge, DNS round-robin, the current L4
passthrough) are completely unaffected. This mirrors the "cluster mode is opt-in"
gating in [`../archive/cluster-mode-multinode-sync.md`](../archive/cluster-mode-multinode-sync.md) §0.

---

## 1. The problem this solves (topology matrix)

Aegis-Gate terminates TLS at the edge (so JA3/JA4 / `device_fp` work) and keys
rate-limit / risk / geoip on the **client IP**. Getting the real client IP to the WAF
behind a load balancer currently forces a trade-off:

| Topology | Real client IP | JA3/JA4 | Single VIP / LB | Root? | Verdict |
|---|---|---|---|---|---|
| **nginx `stream` (L4 passthrough)** | ❌ SNAT → peer = LB IP; per-IP buckets **collapse** (one attacker poisons the shared key, legit traffic gets risk 100). No XFF (L4 can't add headers). | ✅ | ✅ | no | TLS ✓ but client-IP broken |
| **nginx `http` (L7) + XFF** | ✅ (C-5: `proxy.trusted_proxies` plumbed) | ❌ LB terminates TLS → ClientHello lost | ✅ | no | client-IP ✓ but JA3/JA4 gone |
| **TPROXY** | ✅ | ✅ | ✅ | **yes (root + host net)** | unavailable on rootless Docker |
| **DNS round-robin (no LB)** | ✅ | ✅ | ❌ no VIP/HA/drain | no | works, but gives up the LB |
| **➡ PROXY protocol (this plan)** | ✅ header carries real IP | ✅ WAF still terminates TLS | ✅ | **no** | **all four, no root** |

PROXY protocol sidesteps the rootless-SNAT problem because the real IP rides in a
small header at the start of the TCP connection, **not** in the TCP source address.

---

## 2. What exists today (verified against code 2026-06-10)

- **Client-IP resolution (C-5, shipped):** `data_plane.rs:283-293` calls
  `aegis_security::ip_rep::xff::resolve_client_ip(peer.ip(), xff, &upstream_ctx.trusted_proxies)`.
  The parsed nets come from `cfg.proxy.trusted_proxies` via
  `ProxyConfig::parsed_trusted_proxies()` (`config.rs:617`), validated as CIDRs at
  boot (`config.rs:988-996`), default empty (peer wins, XFF ignored — F-HIGH-002-safe).
  `resolve_client_ip` (`ip_rep/xff.rs:13`) returns the peer untouched when the peer is
  not trusted. **This is the exact pattern PROXY trust extends.**
- **Accept path / TLS / peer:** `accept.rs:1404-1411` — `let (stream, peer) = tcp.accept().await`.
  TLS handshake at `accept.rs:1466` (`acc.accept(stream).await`); JA3/JA4 built at
  `accept.rs:1482` (`listener::tls::compute_post_handshake_fingerprint`, `listener/tls.rs:34`);
  mTLS peer-cert identity extracted at `accept.rs:1475`. The single `peer: SocketAddr`
  flows into the per-request `service_fn` closure (used at `accept.rs:1579`, and into
  `handle_data_request` → `resolve_client_ip`). **`peer` is the one value to override.**
- **Per-listener spawn:** `run.rs:1509-1560` iterates `cfg.listeners.data`, reads
  `listener_cfg.tls` (`run.rs:1522`), resolves the per-listener `acceptor`, and spawns
  `accept_loop(...)`. **This is where a per-listener `accept_proxy` mode + the parsed
  trusted-proxy nets get threaded in.**
- **Listener config:** `ListenerConfig { bind: SocketAddr, tls: bool }` (`config.rs:1327`),
  inside `Listeners { data: Vec<ListenerConfig>, admin, force_https }` (`config.rs:1300`).
- **Audit `ip` semantics:** docs/security/ip-reputation.md §"resolution" and
  risk-scoring.md ("`ip` — TCP peer IP (post-XFF), always present"). PROXY redefines
  "TCP peer" as "the peer asserted by a trusted PROXY header" — call out explicitly (§3.4).
- **Deps:** `crates/aegis-proxy/Cargo.toml` uses `tokio` + `tokio-rustls`; **no**
  PROXY-protocol crate yet — `ppp` (or `proxy-protocol`) must be added to the workspace.
- **No conflict with mTLS:** `zero_trust.downstream` client-cert verification happens
  *inside* the TLS handshake, which still runs on the post-PROXY stream (§3.5).

---

## 3. Proposed design (decisions + justification)

### 3.1 Parsing — vetted crate, our own exact-length read (decision)

**Decision: use the `ppp` crate for v1 (text) + v2 (binary) header *parsing*; own the
async *read* so we consume exactly the header and not one byte of the ClientHello.**

- v2 binary parsing (12-byte signature, version/command byte, family/transport byte,
  16-bit length, address block, optional TLVs, checksum) is fiddly and
  security-sensitive — hand-rolling it is a needless footgun. `ppp` is pure-Rust, no
  async I/O baked in (we feed it `&[u8]`), supports v1+v2. Alternative considered:
  `proxy-protocol` crate (similar) — pick one in review; pin the version, add to
  `cargo deny`/`cargo audit` (per Rust security rules).
- **Read discipline (new `listener/proxy_protocol.rs`):**
  - Peek/sniff the first bytes: v1 starts `b"PROXY "`; v2 starts with the 12-byte
    signature `\r\n\r\n\0\r\nQUIT\n`.
  - **v1:** read until the first `\r\n`, hard-capped at **107 bytes** (spec max line);
    no match within cap → malformed → close.
  - **v2:** read the fixed **16-byte** header, take the declared payload length, read
    exactly that many more bytes; cap total well under 65 535.
  - Hand the exact header bytes to `ppp::HeaderResult`. Because we read **exactly** the
    header length, the stream is left positioned at the first ClientHello byte — no
    over-read, no need for a replay/“prefixed-stream” wrapper. (If review prefers a
    buffered read, wrap the leftover in a small `Chain`-style adapter before TLS;
    exact-read is simpler and preferred.)
  - Bound the whole pre-TLS read with a short deadline (e.g. **5 s**, reuse/define a
    constant) so a peer that opens a socket and stalls can't tie up a task before TLS.

### 3.2 Per-listener config + mode (decision)

**Decision: add `accept_proxy: ProxyProtocolMode` to `ListenerConfig`, default `off`.**

```rust
// config.rs
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolMode {
    #[default]
    Off,      // no parse; today's behaviour (default)
    Strict,   // header REQUIRED on every connection; missing/untrusted → close
    Optional, // sniff the v1/v2 signature; if absent, treat as a direct client
}
```

- **`strict`** is the correct production setting behind a dedicated PROXY-enabled LB
  listener — every connection arrives via the LB, so every connection must carry a
  header. A header-less or untrusted connection is closed (fail-closed).
- **`optional`** eases migration / mixed fleets but is a soft downgrade: a client that
  simply omits the header is treated as direct (its peer = the LB's SNAT IP, i.e. the
  benefit is *lost*, not a spoof of a third party). Document "optional = migration
  only; prefer strict."
- **A `strict` listener cannot also serve header-less direct clients.** If a deployment
  needs both, run two data listeners (e.g. `:8443` `accept_proxy: strict` for the LB,
  and a second port for direct) — the per-listener loop at `run.rs:1509` already
  supports `Vec<ListenerConfig>`.

### 3.3 Trust model — reuse `proxy.trusted_proxies`, fail-closed (decision)

**Decision: honour a PROXY header ONLY when the real TCP peer (the LB) is inside
`proxy.trusted_proxies`. Untrusted source sending PROXY → close the connection.**

- One mental model: `trusted_proxies` already answers "who may tell us the client IP"
  for XFF; PROXY is the same assertion over a different channel. Trusting *different*
  sets for XFF vs PROXY would be confusing. (Open question §10: a dedicated
  `proxy.proxy_protocol_trusted` list if an operator ever needs to split them — default
  to reuse.)
- **Validation (boot, `WafConfig::validate`):** any data listener with
  `accept_proxy != off` requires `proxy.trusted_proxies` **non-empty** — otherwise every
  connection would be rejected (fail-closed but a silent footgun). Reject with a clear
  error: `"listener <bind>: accept_proxy requires proxy.trusted_proxies to list the load balancer's CIDR(s)"`.
- An untrusted peer that sends a PROXY header is **closed** (never honoured), with a
  counter (§6). This is the anti-spoofing guarantee: a direct attacker cannot forge a
  PROXY header to move its own (or a victim's) risk key, because its TCP source isn't in
  the trusted set.

### 3.4 Effective-peer wiring + audit semantics (decision)

**Decision: the PROXY source IP replaces the `peer: SocketAddr` in `accept_loop`
(right after parse, before `acc.accept(stream)`); the real TCP peer is kept as
`proxy_via` for debugging.**

- After a successful trusted parse, rebind `peer` to the PROXY-asserted
  `SocketAddr` (source IP + source port). Every downstream consumer — `resolve_client_ip`,
  rate-limit, risk, geoip, audit `ip`, the dashboard origin map — then keys on the real
  client with **no further change** (they already read `peer`).
- **Precedence (PROXY vs XFF):** PROXY sets the *new peer*; `resolve_client_ip(peer, xff, trusted)`
  then runs unchanged on top. For an L4 LB there is no XFF, so the PROXY client wins
  cleanly. In a chained edge (PROXY then an inner L7 hop that adds XFF), if the
  PROXY-client IP is itself listed in `trusted_proxies`, the existing right-to-left XFF
  walk continues — i.e. PROXY and XFF compose correctly without special-casing.
- **Audit `ip` (vs contract "ip = TCP peer"):** with PROXY the "effective peer" *is* the
  real client — that's the whole point — so audit `ip` = the PROXY-asserted client
  (post-XFF), consistent with how C-5 already makes `ip` the post-XFF client. Update the
  ip-reputation / risk-scoring docs to define "TCP peer" as "the transport peer, or the
  peer asserted by a trusted PROXY header when `accept_proxy` is on." Add an optional
  audit/debug field **`proxy_via`** = the real LB transport IP when a header was consumed
  (so an operator can still see which LB node fronted the request).

### 3.5 TLS interaction (confirm, no change to JA3/JA4 or mTLS)

The header is consumed on the raw stream first; `acc.accept(stream)` then runs exactly
as today on the remaining bytes → JA3/JA4 computed from the **client's real ClientHello**
(`compute_post_handshake_fingerprint`, unchanged). mTLS (`zero_trust.downstream`)
client-cert verification happens *inside* that same handshake, so the PROXY-asserted IP
and the mTLS peer identity are orthogonal and both correct. Ordering on a PROXY+TLS+mTLS
listener: **PROXY parse → TLS accept (incl. client-cert verify) → fingerprint → serve.**

### 3.6 Failure modes (decision table)

| Condition | Behaviour | Metric label |
|---|---|---|
| Malformed / truncated header | Close connection (do **not** fall through to TLS — risk of misparsing ClientHello as a header) | `malformed` |
| Missing header, `strict` | Close | `missing_strict` |
| Missing signature, `optional` | Treat as direct client (peer = real TCP peer) | `absent_optional` |
| Header from untrusted peer | Close (never honour) | `untrusted_source` |
| v2 `LOCAL` command (LB health checks) | No address asserted → use the real TCP peer, proceed | `local_command` |
| v2 `PROXY` + `UNSPEC` family | Treat like `LOCAL` (use real peer) | `unspec_family` |
| IPv6 source | Supported → `IpAddr::V6` | — |
| `UNIX`/`AF_UNIX` family | Not meaningful at a TCP edge → use real peer (or reject; decide in review) | `unix_family` |
| Pre-TLS read deadline exceeded | Close | `read_timeout` |

---

## 4. Phasing (mirrors `archive/zero-trust-unified-mtls.md` §4)

| Phase | Scope | Est. |
|---|---|---|
| **P1 — Parse + listener flag (observe-only)** | New `listener/proxy_protocol.rs` (bounded v1/v2 read + `ppp` parse + unit tests); `ProxyProtocolMode` on `ListenerConfig`; thread the mode + parsed trusted nets through `run.rs:1509` → `accept_loop`. Parse + **log + count only** — do NOT override the peer yet. Behind `accept_proxy`, default off. | ~350 LoC · 2d |
| **P2 — Trust + effective-peer** | Honour the header only from a trusted TCP peer; rebind `peer` in `accept_loop` before TLS; boot validation (`accept_proxy ⇒ trusted_proxies non-empty`); fail-closed close on untrusted/strict-missing. Differential-risk behaviour now live. | ~250 LoC · 2d |
| **P3 — Audit / XFF precedence + hardening** | `proxy_via` debug field; confirm PROXY→XFF composition; full failure-mode table (§3.6) incl. v2 LOCAL/UNSPEC/IPv6/timeout; metrics counter `proxy_protocol_events{result=...}`; doc the audit-`ip` semantics shift. | ~250 LoC · 1.5d |
| **P4 — Docs + LB wiring + cluster rig** | REFERENCE.md (listener `accept_proxy`); deploy topology matrix 4th row + nginx `stream proxy_protocol on;` and HAProxy `send-proxy-v2` examples; `tests/cluster/10-proxy-protocol-client-ip.sh` 2-node rig; FEATURES/architecture cross-refs. | ~300 LoC · 2d |
| — | Tests: v1/v2/LOCAL/malformed/untrusted/IPv6 parse matrix; integration (crafted v2 header → asserted effective peer + JA3/JA4 still computed); differential-risk cluster test. | ~300 LoC · 1.5d |

Defaults **off**; operator opts in per listener. **~1,700 LoC · ~9 working days.**

### 4.1 Progress tracker (update as phases land)
- [x] **P1** parse + listener flag (observe-only) — `ppp` v2.3.0 pinned;
      `ProxyProtocolMode` (`off`/`strict`/`optional`, default off) on
      `ListenerConfig`; new `listener/proxy_protocol.rs` (peek-sniff +
      exact-length v1/v2 read, deadline-bounded, 10 unit tests proving no
      ClientHello over-read); `accept_loop` reads+logs+observes ahead of
      TLS, peer NOT yet overridden. Default-off path unchanged (798
      aegis-proxy tests green).
- [x] **P2** trust + effective-peer override + boot validation —
      `decide_peer_action(outcome, trusted_lb) → Override/Proceed/Close`
      (anti-spoof: a header from an untrusted source closes); `accept_loop`
      rebinds `peer` to the asserted client before TLS; boot validation
      `accept_proxy ⇒ trusted_proxies non-empty`. 5 decision unit tests +
      3 boot-validation tests; core 295 / proxy 803 green. Live
      end-to-end differential-risk test deferred to P4's cluster rig.
- [x] **P3** audit/XFF precedence + failure-mode hardening + metrics —
      `waf_proxy_protocol_events_total{result}` counter (10 labels incl.
      `untrusted_source`/`unspec_family`, pre-registered); `proxy_via`
      additive audit field on the HTTP request-decision events
      (ddos/rate-limit/detector blocks) via `with_proxy_via`; PROXY→XFF
      composition confirmed (`resolve_client_ip` unchanged); audit-`ip`
      semantics documented in ip-reputation.md + risk-scoring.md.
      Failure-mode §3.6 labels all covered by unit tests. (Live 5s
      read-timeout test deferred — too slow for a unit; WS/tunnel/
      challenge audit events carry no `proxy_via` by design.)
- [x] **P4** docs + nginx/HAProxy wiring + `tests/cluster` rig —
      `config/REFERENCE.md` `accept_proxy` entry; topology matrix 4th row
      + nginx `stream`/HAProxy `send-proxy-v2` examples in
      `deploy/HACKATHON-FLEET.md`; `docs/FEATURES.md` row;
      `tests/cluster/10-proxy-protocol-client-ip.sh` (self-contained
      in-memory fixture `config/cluster-proxy.yaml`, no docker/redis) +
      `run-all.sh` entry. **Rig runs green end-to-end against the real
      binary: attacker=100 / clean=0 / LB(127.0.0.1)=0 — buckets key on
      the real client, not the collapsed LB IP.**
- [x] **Gates** — §7 checklist green: trusted-only honour, boot
      validation, default-off zero-cost, exact-length read, malformed
      closes, deadline-bounded, **differential-risk live** (rig),
      `proxy_via` recorded + audit-`ip` documented. (JA3/JA4-unchanged +
      mTLS-on-PROXY assert through a TLS listener — covered architecturally;
      a TLS variant of the rig can extend §8 later.)

---

## 5. Files to touch (anticipated)

- `crates/aegis-proxy/src/listener/proxy_protocol.rs` — **new**: bounded async read +
  `ppp` parse → `ProxyHeader { source: Option<SocketAddr>, command }` + unit tests.
- `crates/aegis-proxy/src/listener/mod.rs` — register the module.
- `crates/aegis-proxy/src/accept.rs` — in `accept_loop` (~1404-1466): after
  `tcp.accept()`, if this listener's `accept_proxy != off`, read+parse the header,
  enforce trust, rebind `peer`, then proceed to `acc.accept(stream)`. New `accept_loop`
  params: `proxy_mode: ProxyProtocolMode` + `trusted_proxies: Arc<Vec<IpNet>>` (or read
  off `upstream_ctx`).
- `crates/aegis-proxy/src/run.rs` (~1509-1560) — read `listener_cfg.accept_proxy`, pass
  it + the parsed trusted nets into `accept_loop`.
- `crates/aegis-core/src/config.rs` — `ProxyProtocolMode` enum; `accept_proxy` field on
  `ListenerConfig` (`#[serde(default)]`); validation in `WafConfig::validate` (≈near the
  C-5 `trusted_proxies` check at `:988`).
- `crates/aegis-proxy/Cargo.toml` + workspace `Cargo.toml` — add `ppp` (pin + `cargo deny`).
- Audit projection (wherever the data-plane audit event is built) — optional `proxy_via`.
- `crates/aegis-control/src/metrics/` — `proxy_protocol_events` counter (follow the
  `decisions`/`detector_hits` counter pattern).
- Docs: `config/REFERENCE.md`, `deploy/HACKATHON-FLEET.md` (topology matrix lives here —
  confirm the canonical deploy doc in review), `docs/security/ip-reputation.md`,
  `docs/security/risk-scoring.md`, `docs/FEATURES.md`.
- Tests: `crates/aegis-proxy/src/listener/proxy_protocol.rs` unit tests; an integration
  test; `tests/cluster/10-proxy-protocol-client-ip.sh` + `run-all.sh` entry.

---

## 6. Config + docs sketch

```yaml
# waf.yaml — a PROXY-enabled edge listener behind an L4 LB
proxy:
  trusted_proxies: ["10.0.0.0/8"]   # the LB's source CIDR — REQUIRED when accept_proxy is on
listeners:
  data:
    - bind: "0.0.0.0:8443"
      tls: true
      accept_proxy: strict          # off (default) | strict | optional
```

```nginx
# nginx L4 passthrough that prepends the PROXY header
stream {
  upstream waf { server 10.0.0.11:8443; server 10.0.0.12:8443; }
  server {
    listen 443;
    proxy_pass waf;
    proxy_protocol on;     # prepend PROXY v1; nginx sends v1 by default
  }
}
```
HAProxy equivalent: `server waf-a 10.0.0.11:8443 send-proxy-v2`.

---

## 7. Security checklist (gate before recommending PROXY as supported)

- [ ] PROXY header honoured **only** from a peer in `trusted_proxies`; untrusted source → closed.
- [ ] `accept_proxy ⇒ trusted_proxies non-empty` enforced at boot (no silent
      reject-all; no silent honour-all).
- [ ] Default `off` proven zero-cost / zero-behaviour-change (no read on the accept path).
- [ ] Exact-length read — no ClientHello byte consumed; JA3/JA4 unchanged (test asserts).
- [ ] Malformed/truncated/oversized header closes the connection, never falls through to TLS.
- [ ] Pre-TLS read is deadline-bounded (no slowloris on the raw socket).
- [ ] Differential-risk test: attacker IP A is gated while a clean IP B (same LB) is
      unaffected — proves buckets no longer collapse onto the LB IP.
- [ ] `proxy_via` (real LB hop) recorded; audit-`ip` semantics documented.
- [ ] mTLS (`zero_trust.downstream`) still verifies the client cert on a PROXY listener.

---

## 8. Test plan

- **Unit (`proxy_protocol.rs`):** parse v1 text, v2 binary (IPv4 + IPv6), v2 `LOCAL`,
  v2 `UNSPEC`, truncated v1 (no CRLF in cap), truncated v2 (short payload), oversized,
  garbage bytes → each maps to the §3.6 outcome.
- **Trust/peer unit:** trusted peer + valid header → effective peer = asserted client;
  untrusted peer + valid header → closed; `optional` + no signature → peer = TCP peer.
- **Integration:** open a TCP conn, write a crafted v2 header for client `203.0.113.7`,
  complete TLS → assert the request's resolved client IP / risk key = `203.0.113.7` and
  that JA3/JA4 are still computed.
- **`tests/cluster/10-proxy-protocol-client-ip.sh` (2-node rig, nginx `stream
  proxy_protocol on`):** (a) attack as client A → A's risk climbs while client B stays
  clean (differential — the collapse bug is gone); (b) JA3/JA4 present in the audit;
  (c) a direct connection to the WAF *without* a header on a `strict` listener is
  closed; (d) a malformed header closes cleanly. Follows the existing
  `tests/cluster/05-single-vip-baseline.sh` / `07-control-plane-sync.sh` style.

---

## 9. Roadmap slot + cross-refs

- Operational/topology capability — slot into
  [`world-class-waf-roadmap.md`](./world-class-waf-roadmap.md) alongside the HA/LB
  tier (the C-5 `trusted_proxies` work and `ha-clustering` live there).
- Builds directly on **C-5** (`proxy.trusted_proxies`,
  [`../archive/multi-node-consistency-implementation.md`](../archive/multi-node-consistency-implementation.md)
  P1) — same trust set, extended from XFF to PROXY.
- Deploy topology: [`deploy/HACKATHON-FLEET.md`](../../deploy/HACKATHON-FLEET.md)
  (the L4-passthrough story this plan completes).
- TLS/mTLS interaction: [`docs/security/zero-trust-mtls.md`](../../docs/security/zero-trust-mtls.md).

---

## 10. Open questions (decide in review)

1. **Parser crate:** `ppp` vs `proxy-protocol` — pick one (both pure-Rust v1+v2). Lean `ppp`.
2. **Dedicated trust list?** Reuse `proxy.trusted_proxies` (recommended) vs a separate
   `proxy.proxy_protocol_trusted`. Default reuse; add the split only if a real split-trust
   topology appears.
3. **`UNIX` address family:** use the real peer (lenient) vs reject (strict)? Lean lenient
   (a TCP edge won't see it; treat like LOCAL).
4. **Source *port*:** adopt the PROXY-asserted source port into `peer` too, or keep the
   real transport port and override only the IP? (Risk/rate-limit key on IP, so it's
   cosmetic — but audit completeness argues for adopting it.)
5. **`proxy_via` surface:** audit-only field vs also an internal `X-WAF-Proxy-Via` header?
   Lean audit-only (no header injection).
6. **Canonical deploy doc** for the topology matrix — confirm `deploy/HACKATHON-FLEET.md`
   is the live home (vs a renamed PRE-PROD deploy guide).
7. **v2 TLV passthrough:** ignore TLVs (recommended) vs surface AWS-NLB VPC-endpoint /
   TLS-SNI TLVs later as a future enhancement.

---

## 11. Out of scope

- Sending PROXY protocol *upstream* (WAF → backend) — this plan is ingress only.
- TPROXY / `IP_TRANSPARENT` (needs root; explicitly unavailable here).
- L7 LB + XFF JA3/JA4 recovery (impossible by construction — the LB owns the handshake).
- A new auth/identity mechanism — PROXY asserts a network address, not an identity; it
  rides entirely on the `trusted_proxies` network-trust boundary.
