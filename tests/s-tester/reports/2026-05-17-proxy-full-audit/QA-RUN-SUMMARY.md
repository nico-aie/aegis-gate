---
id: 2026-05-17-proxy-full-audit
date: 2026-05-17T00:00Z
test_mode: source-review
scope:
  - Full audit of `crates/aegis-proxy/` minus the 4 hot-path files
    already covered by `2026-05-17-entry-cli-dataplane-audit/`
    (accept.rs, data_plane.rs, run.rs, main.rs).
  - 35 files / ~35k LoC across 5 functional groups:
    A) Protocol handlers + responses + tunnel + transforms
    B) Routing + Listener (incl. HTTP/3 / QUIC) + proxy.rs
    C) Admin REST surface + sessions + interop control
    D) Process lifecycle (hotbin / supervisor / shed / quota / dr / traffic)
    E) Stateful systems (TLS lifecycle / upstream / cluster / state /
       service discovery / secrets / config_source)
  - Cross-referenced into `crates/aegis-control/` where the proxy
    delegates (admin_auth/*, interop/*, api/login.rs, api/mutation.rs).
  - Compliance gate: `Hackathon_Doc/VN_waf_interop_contract_v2.3.md`
tester: Claude (5 parallel general-purpose audit agents +
                spot-verification by reading flagged file:line ranges
                and grep for cross-file dead-code claims)
---

# Aegis-Gate `aegis-proxy` full-crate audit — 2026-05-17

**Mode:** Source review only. 5 parallel agents each took one functional
group (~5–13k LoC). Findings cross-checked against v2.3 contract clauses.
Highest-severity findings spot-verified by reading the cited file:line
and by `grep` (e.g. dead-code claims confirmed by zero-hit search across
`crates/`).

**WAF version:** 0.1.0 (workspace at HEAD on 2026-05-17)
**Interop contract:** [`Hackathon_Doc/VN_waf_interop_contract_v2.3.md`](../../../../Hackathon_Doc/VN_waf_interop_contract_v2.3.md)

---

## Finding counts

| Severity | Count |
|---|---|
| CRITICAL | 10 |
| HIGH     | 23 |
| MEDIUM   | 15+ (bundled) |
| Contract gaps (semantic) | 3 |
| **Total** | **51+** |

Compare to the previous data-plane audit (`2026-05-17-entry-cli-dataplane-audit/`):
4 CRITICAL + 5 HIGH + 5 MEDIUM. This second pass surfaces ~3x more
findings because the audited surface is ~5x larger.

---

## Findings index

### CRITICAL — likely to fail Round 1 or cause major Round-2 scoring loss

| ID | Title |
|---|---|
| F-CRITICAL-001 | HTTP/3 / QUIC path bypasses the entire security pipeline + lacks the 6 §5 headers + loses peer identity (§10) |
| F-CRITICAL-002 | Admin listener has NO session / IP-allowlist / capability check — every mutation handler reachable to anyone on the admin port (only "CSRF" gate, which is bypassable) |
| F-CRITICAL-003 | TOTP module exists but is never invoked from the login flow — auth chain step 4 (RFC 6238) missing |
| F-CRITICAL-004 | Audit-chain `actor` field is taken verbatim from the client-supplied `X-Actor` request header — anyone can impersonate any operator in the durable chain |
| F-CRITICAL-005 | CSRF tokens, session IDs, salts derived from `blake3(clock_nanos + counter)` — not crypto-random; combined with F-CRITICAL-002, fully bypassable |
| F-CRITICAL-006 | Dead-code modules: `shed.rs`, `quota.rs`, `dr.rs`, `traffic.rs` advertised in README/Architecture but have zero call sites across the crate — load shedding, body limits, snapshot/restore, traffic mirroring all non-functional |
| F-CRITICAL-007 | In-memory token-bucket rate-limit broken: `decode_bucket` discards the stored timestamp and returns `Instant::now()` — bucket never refills; after `burst` calls, all subsequent denied permanently |
| F-CRITICAL-008 | `Member.inflight` counter not RAII-guarded — cancellation / panic during `forward()` leaks the counter; LeastConn / P2C load balancers skew permanently against the affected pool member |
| F-CRITICAL-009 | CORS preflight handler `unwrap()`s `HeaderValue::from_str(&client_origin)` — a crafted `Origin:` byte (e.g. DEL `0x7F`) panics the worker on the hot path |
| F-CRITICAL-010 | WebSocket upstream handshake parser accepts `\n`-only line terminators in upstream response headers and forwards them verbatim to the client 101 response — header smuggling vector |

### HIGH — contract gap or significant correctness issue (bundled by domain)

| ID | Domain | Mini-findings inside |
|---|---|---|
| F-HIGH-protocol | Protocol handlers | 6 items: h2 rapid-reset detector broken (CVE-2023-44487 mitigation non-functional after first 30 s) · WS upstream `read_response_head` no deadline (slowloris) · CONNECT tunnel no idle timeout · H2/H3 Host fallback to "localhost" · H3 unbounded body buffer · QUIC transport limits missing |
| F-HIGH-admin | Admin / auth | 7 items: mutation handlers no body cap · TOTP code uses SHA256 while doc/URI claim SHA1 · TOTP no replay protection · SSE unauthenticated + unbounded subscribers · Session store hard-coded TTL ignores config + unbounded HashMap · Argon2 `dummy_verify` uses `hash_password` (timing oracle) · Rate-limit trackers unbounded HashMap |
| F-HIGH-stateful | Upstream / TLS / SD / Secrets | 7 items: upstream HTTPS only uses webpki roots (private CA unsupported despite README) · SD watchers (k8s/etcd/consul) exit permanently on 401/403 · ACME no rate-limit backoff (Let's Encrypt 429 → retry storm) · OCSP module is a shell — no fetcher, no background task · forward.rs body collection has no timeout · in-memory state unbounded + risk scores never expire · Vault re-authenticates every secret resolve |
| F-HIGH-lifecycle | Process / hot-restart | 4 items: hotbin SIGUSR2 re-entrant + state field unused · hotbin pipe2 not used → fd leak via non-atomic CLOEXEC set · hotbin `env::remove_var` race on Rust 2024 (UB) · LoadShedder gradient algorithm only ever decreases (no recovery) |

### CONTRACT GAPS (semantic — §3 / §5 / hot-reload)

| ID | Title |
|---|---|
| F-CONTRACT-001 | WS no-healthy-member returns `block` instead of `circuit_breaker` per §3 |
| F-CONTRACT-002 | CONNECT to an unreachable upstream returns 200 then RST — `timeout` / `circuit_breaker` never surfaced to the client |
| F-CONTRACT-003 | `cfg.upstreams` reload from file/etcd is silently skipped — README's "hot-reload via YAML edit" claim is false; only dashboard PUT works |

### MEDIUM — bundled

`F-MEDIUM-ALL.md` — 15+ items including: notify watcher 100 ms is a fixed delay not a debounce; AEGIS_INSECURE_COOKIES drops `Secure` in prod if accidentally set; LB p2c bias on small n; redis backend has no TLS / no AUTH env split; supervisor.rs is a misnomer (no process supervision); CONNECT `set_nodelay` only on upstream side; secret `Drop` only zeroes original buffer (resolved cleartext lives unzeroed); `dr::restore` accepts `{}` and would wipe config; etc.

---

## Interop contract compliance (v2.3) — delta from previous audit

The previous audit verified the HAPPY-PATH headers + audit + control
endpoints. This audit found **additional surfaces** where the contract
is violated:

| Clause | Surface | Status | Evidence |
|---|---|---|---|
| §5 six headers on every response | H3 / QUIC responses | ❌ | F-CRITICAL-001 — `listener/http3.rs:261` |
| §5 six headers | admin listener responses (not stamped) | ⚠️ | F-HIGH-admin bullet — `accept.rs:875-901` calls `handle_admin_request` directly, no stamping |
| §3 `circuit_breaker` action | WS no-healthy-member | ❌ | F-CONTRACT-001 — `data_plane.rs:1086-1117` returns `block` |
| §3 `timeout` / `circuit_breaker` | CONNECT to unreachable upstream | ❌ | F-CONTRACT-002 — `data_plane.rs:1742` returns 200 before connect |
| §6 audit `actor` integrity | every mutation | ❌ | F-CRITICAL-004 — `admin_mutate.rs:1420-1425` |
| §10 peer identity | QUIC listener | ❌ | F-CRITICAL-001 — `listener/http3.rs:204` never reads `connection.remote_address()` |
| Round-1 dashboard auth chain steps 1–7 | login flow | ❌ | F-CRITICAL-002/003/005 — IP allow-list, TOTP, randomness all missing |
| Round-1 audit-mutated CRUD | every mutation | ❌ | F-CRITICAL-004 (actor spoof) + F-CRITICAL-002 (no session) |
| Round-1 hot-reload via YAML | `cfg.upstreams` | ❌ | F-CONTRACT-003 — `config_source/reload.rs:258-260` |
| Round-1 stability under load | unbounded memory growth | ❌ | F-HIGH-admin (4 unbounded maps) + F-HIGH-stateful (in-memory state cap missing) |

---

## Verdict

The previous audit (data plane only) was tentatively pass-Round-1.
This expanded audit **changes that verdict**.

**Round 1 fails likely on these grounds:**

1. **Dashboard auth chain is illusory.** Steps 1 (IP allow-list),
   2 (mTLS optional but spec'd), 4 (TOTP), 6 (CSRF — entropy + no
   session = double-submit theatre), 7 (rate-limit — unbounded map).
   Only steps 3 (argon2 — though `dummy_verify` is broken) and 5
   (HMAC cookie — though entropy is broken) are partially in place.
   Anyone reachable to the admin port can mint a CSRF cookie via
   GET, then call any mutation. The "Pass/Fail" Round-1 gate for
   dashboard auth fails.

2. **HTTP/3 traffic bypasses the WAF entirely.** Detectors don't
   run, rate-limit doesn't apply, audit doesn't emit, headers don't
   ship. If the OC harness probes H3 (the README advertises the
   `http3` feature), every test case scores as `passed` (attack
   reached upstream) and every request lacks the 6 §5 headers.

3. **Audit chain attribution is forgeable.** Any operator action
   in the durable, hash-chained NDJSON can be attributed to any
   identity the attacker types into `X-Actor:`. Round-1
   "audit-mutated CRUD" requirement is defeated at the source.

4. **Multiple advertised features are dead code.** Load shedding
   (Round 3 resilience), body limits (Round 1 stability + Round 2
   FP minimization), DR snapshot/restore (operator-quality bonus),
   traffic mirroring (Round 3 bonus) — all advertised in
   README/Architecture but zero call sites in the crate. The QA
   tester (or any BTC reviewer) who tests these features finds
   them non-functional, then the README's veracity collapses
   wholesale — every other claim becomes suspect.

5. **In-memory rate-limit is mathematically broken.** Under the
   default backend, every IP gets exactly `burst` requests then is
   permanently denied (token bucket never refills). False-positive
   rate (§7 normalization) goes to 100% after a brief warm-up.

**Three smallest CRITICALs to fix immediately** (low LoC, big scoring impact):

- F-CRITICAL-007 (in-memory token bucket) — 10 LoC, swap to epoch ts
- F-CRITICAL-009 (CORS panic) — 3 LoC, replace `.unwrap()` with `.ok()`
- F-CRITICAL-004 (X-Actor spoof) — 5 LoC, take actor from session, not header

**Largest** (ordered by effort):

- F-CRITICAL-002 (admin auth gate) — needs session middleware design (~200 LoC)
- F-CRITICAL-001 (H3 pipeline) — needs `data_plane::handle_data_request` wiring into the H3 service (~80 LoC)
- F-CRITICAL-006 (dead modules) — either wire them or remove from README; design call

---

## Files in this report

```
QA-RUN-SUMMARY.md                                          (this file)
F-CRITICAL-001-h3-bypass-no-security-pipeline.md
F-CRITICAL-002-admin-listener-no-session-auth-gate.md
F-CRITICAL-003-totp-not-wired-into-login-flow.md
F-CRITICAL-004-audit-actor-spoofable-via-x-actor-header.md
F-CRITICAL-005-csrf-session-tokens-not-crypto-random.md
F-CRITICAL-006-dead-code-modules-shed-quota-dr-traffic.md
F-CRITICAL-007-in-memory-token-bucket-broken-never-refills.md
F-CRITICAL-008-member-inflight-counter-not-raii-guarded.md
F-CRITICAL-009-cors-preflight-panic-on-hostile-origin.md
F-CRITICAL-010-ws-upstream-header-smuggling.md
F-HIGH-protocol.md         (6 items)
F-HIGH-admin.md            (7 items)
F-HIGH-stateful.md         (7 items)
F-HIGH-lifecycle.md        (4 items)
F-CONTRACT-GAPS.md         (3 §3/§5/hot-reload semantic gaps)
F-MEDIUM-ALL.md            (15+ items)
```
