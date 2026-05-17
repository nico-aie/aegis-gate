---
id: 2026-05-17-medium-bundle-security-audit
date: 2026-05-17T00:00Z
severity: MEDIUM
area: multiple
component: per-item — see Component line
interop_contract: latent / posture / non-contract correctness
status: open
test_mode: source-review
---

# F-MEDIUM bundle — ~28 MEDIUM findings from the aegis-security audit

Grouped by domain. Each item is small, latent, or fragility-class.

---

## Detectors

### M-01 · SQLi `--\s*$` end-anchor breaks classic comment mutation
**Component:** [sqli.rs:23](aegis-gate/crates/aegis-security/src/detectors/sqli.rs#L23)
Pattern `(?i)(?:--\s*$)` requires `--` to be at end of string. Real SQLi: `1' OR 1=1-- -` (`--` followed by content) does NOT match. Drop the `$` anchor.

### M-02 · XSS event-handler list is enumerated, not generic
**Component:** [xss.rs:16](aegis-gate/crates/aegis-security/src/detectors/xss.rs#L16)
Hardcodes `onload | onerror | onclick | ...`. Misses newer handlers: `onpointerdown`, `onauxclick`, `oncopy`, `onpaste`, `onbeforeunload`. Replace with generic `on\w+\s*=`.

### M-03 · XSS `\u00[0-9a-f]{2}` pattern misses ES6 `\u{3c}` and ` `
**Component:** [xss.rs:40](aegis-gate/crates/aegis-security/src/detectors/xss.rs#L40)
Only matches `\u00XX` form. Add `\u{...}` (ES6) and `\u20[23][89]` (line/paragraph separator) variants.

### M-04 · body_abuse `MASS_ASSIGN_KEYS` matches inside string values
**Component:** [body_abuse.rs:35-43](aegis-gate/crates/aegis-security/src/detectors/body_abuse.rs#L35-L43)
Regex `"role"\s*:` matches anywhere in body including inside string values like `{"explanation":"set \"role\":\"admin\" to elevate"}`. FP class. JSON-parse instead of regex.

### M-05 · body_abuse: case-sensitive pre-filter for `__proto__` / `constructor`
**Component:** [body_abuse.rs:148, 142](aegis-gate/crates/aegis-security/src/detectors/body_abuse.rs#L148)
Pre-filter uses case-sensitive `contains`. `__PROTO__` payloads bypass pre-filter and never reach the lowercase path.

### M-06 · header_injection `take(6)` magic number fragile
**Component:** [header_injection.rs:333](aegis-gate/crates/aegis-security/src/detectors/header_injection.rs#L333)
`INJECTION_PATTERNS.iter().take(6)` limits header CRLF check to first 6 patterns. Reordering the array silently shrinks the header scan set. Use a labelled constant for the index range.

### M-07 · template_injection `<%[!=]?\s*` pattern broad
**Component:** [detectors/template_injection.rs:64](aegis-gate/crates/aegis-security/src/detectors/template_injection.rs#L64)
Detector docstring claims "bare matched braces alone do NOT fire" but `<%` (Mako syntax) DOES fire. Conflict between stated invariant and implementation.

### M-08 · open_redirect score 30 doesn't reach challenge_at: 40
**Component:** [detectors/open_redirect.rs:82](aegis-gate/crates/aegis-security/src/detectors/open_redirect.rs#L82)
By design ("single hit doesn't reach challenge_at"), but the README's threshold claim is 30/70 (challenge_at: 30) where the score WOULD reach. Resolve doc/default disagreement per F-CRITICAL-006.

### M-09 · detector dispatcher has no per-detector panic isolation
**Component:** [detectors/mod.rs:193-216](aegis-gate/crates/aegis-security/src/detectors/mod.rs#L193-L216)
`run_all_filtered` calls `d.inspect(req)` directly. If any detector panics, the whole request handler panics. Wrap in `std::panic::catch_unwind` and skip-on-panic + metric.

### M-10 · detector dispatcher has no `X-WAF-Rule-Id` selection logic
**Component:** [detectors/mod.rs](aegis-gate/crates/aegis-security/src/detectors/mod.rs)
Returns ALL fired detector ids; rule-id selection lives in `rules/eval.rs` (first-match). For multi-detector hits, no deterministic "winner" for the §5 header. Add highest-score-wins + tiebreak by `DetectorClass::ALL` order.

---

## AI / scoring

### M-11 · AI body cap 4 KiB; other detectors 8 KiB
**Component:** [detectors/ai/mod.rs:212](aegis-gate/crates/aegis-security/src/detectors/ai/mod.rs#L212) vs other detectors at 8 KiB
Asymmetric caps mean the byte at offset 5000 contributes to SSTI detection but NOT AI. Either unify to one constant or document.

### M-12 · features.rs `url_decode` differs from `detectors/mod.rs::url_decode`
**Component:** [detectors/ai/features.rs:194-211](aegis-gate/crates/aegis-security/src/detectors/ai/features.rs#L194-L211)
AI version doesn't decode `+` → space; detector version does. Training/inference skew vector. Dedupe to one helper.

### M-13 · mask.rs read-modify-write race for concurrent writers
**Component:** [mask.rs:439-454](aegis-gate/crates/aegis-security/src/detectors/mask.rs#L439-L454)
`ArcSwap::store` is atomic per-store but not CAS. Two concurrent writers (dashboard PUT + bootstrap restore) can lose an override. Add a `compare_and_swap` loop or document "single-writer".

### M-14 · `DetectorClass::ALL` const array can drift from enum
**Component:** [mask.rs:67-80](aegis-gate/crates/aegis-security/src/detectors/mask.rs#L67-L80)
12-element const array; adding a new class but forgetting to update `ALL` compiles silently (only caught by a unit test). Use `#[non_exhaustive]` discipline or a derive-macro.

---

## Risk / rules / pipeline

### M-15 · `rules/eval.rs::matches_op` `Mutex` panic on hot path
**Component:** [rules/eval.rs:46](aegis-gate/crates/aegis-security/src/rules/eval.rs#L46)
`state.lock().expect("rule rate-limit state poisoned")` is a panic on the hot path. A panic in any other thread holding the lock takes the whole limiter down. Use `match`/fall-through to allow + log.

### M-16 · `Block { status }` accepts any u16 including 200
**Component:** [rules/ast.rs:222-224](aegis-gate/crates/aegis-security/src/rules/ast.rs#L222-L224)
A misconfigured rule could "block" with a 200 response. Validate `[400, 599]` at lint time.

### M-17 · Linter doesn't flag "always-match" / hardcoded-loophole rules
**Component:** [rules/linter.rs](aegis-gate/crates/aegis-security/src/rules/linter.rs)
No detection for: `Condition::True` at top level (the §9-forbidden hardcoded loophole), duplicate priorities at same scope, dead-code rules unreachable behind a higher-priority True/Allow, regex catastrophic-backtracking patterns.

### M-18 · `Condition` deserializer doesn't enforce single-key
**Component:** [rules/ast.rs:115-186](aegis-gate/crates/aegis-security/src/rules/ast.rs#L115-L186)
A YAML map with two keys silently picks the first by iteration order and drops the rest. Add a `next_key().is_none()` assertion.

### M-19 · `risk/tracker.rs::record_malicious` u32 overflow on hot path
**Component:** [risk/tracker.rs:163](aegis-gate/crates/aegis-security/src/risk/tracker.rs#L163)
`entry.score + delta` panics in debug builds on overflow. With operator-config-reachable `delta = 2_000_000_000`, attacker-reachable. Use `saturating_add` (the strikes line below already does).

### M-20 · `risk/tracker.rs` no eviction → unbounded growth
**Component:** [risk/tracker.rs:73-87](aegis-gate/crates/aegis-security/src/risk/tracker.rs#L73-L87)
A long-lived WAF hit by a botnet from millions of IPs grows the DashMap until OOM. Add background sweep that drops slots with `last_seen` > 24 h.

### M-21 · `Pipeline::on_body_frame` `from_utf8` short-circuit drops DLP/scrub on multi-frame UTF-8 split
**Component:** [pipeline.rs:201-203](aegis-gate/crates/aegis-security/src/pipeline.rs#L201-L203)
A 2-byte codepoint split across frame boundaries skips DLP on both frames. Today the comment claims "one frame today" but the contract requires safe streaming.

---

## Bots / behavior / velocity

### M-22 · `behavior.rs` all anomaly thresholds hardcoded
**Component:** [behavior.rs:89, 99, 111, 123, 135](aegis-gate/crates/aegis-security/src/behavior.rs#L89)
Thresholds (>50, >30, >0.5, <0.05) are inline constants. Operators can't tune without recompile. Move to config.

### M-23 · `velocity.rs` discriminator has no enforced format
**Component:** [velocity.rs:30-51](aegis-gate/crates/aegis-security/src/velocity.rs#L30-L51)
Caller-supplied string with no validation; empty string collapses all users into one bucket. Provide a typed `VelocityKey { user_id, ip, action }`.

### M-24 · `bots.rs` UA blocklist hardcoded
**Component:** [bots.rs:42-53](aegis-gate/crates/aegis-security/src/bots.rs#L42-L53)
List is generic tooling (sqlmap/nikto) — defensible but should be config-loaded with a default rather than baked.

### M-25 · `bots.rs` UA contains-match allocates per request via `to_lowercase`
**Component:** [bots.rs:73-82](aegis-gate/crates/aegis-security/src/bots.rs#L73-L82)
Per-request `String::to_lowercase` allocation. Use precompiled `aho-corasick::AhoCorasick` matcher.

---

## Auth / API security / threat intel

### M-26 · `threat_intel/mod.rs::check_ip` takes Mutex on hot path
**Component:** [threat_intel/mod.rs:67-86, 178-232](aegis-gate/crates/aegis-security/src/threat_intel/mod.rs#L67-L86)
Per-request lookup takes 1-3 `std::sync::Mutex` locks. Under contention serializes the whole data plane. Use `RwLock` or `ArcSwap<HashMap>`.

### M-27 · `threat_intel` cap check `>=` then unconditional insert
**Component:** [threat_intel/mod.rs:131-134, 161-163](aegis-gate/crates/aegis-security/src/threat_intel/mod.rs#L131-L134)
If `evict_expired` frees nothing, map grows past `max_indicators` indefinitely. Add LRU eviction.

### M-28 · `threat_intel/taxii` fetcher has no jitter
**Component:** [threat_intel/taxii.rs:389-417](aegis-gate/crates/aegis-security/src/threat_intel/taxii.rs#L389-L417)
N feeds align on the same tick. Add jitter (±20% of `poll_interval`) to spread network load.

### M-29 · `api_security/graphql.rs` depth-counting fooled by string literals
**Component:** [api_security/graphql.rs:38-95](aegis-gate/crates/aegis-security/src/api_security/graphql.rs#L38-L95)
`query { f(arg: "}") }` decrements depth inside a string. Need a state machine that tracks string boundaries.

### M-30 · `challenge/ladder.rs` thresholds hardcoded inline
**Component:** [challenge/ladder.rs:24-52](aegis-gate/crates/aegis-security/src/challenge/ladder.rs#L24-L52)
`0..=29`, `30..=49`, etc. — not loaded from config. Acceptable for hackathon but flag for production.

### M-31 · `challenge/ladder.rs` bot-class branch can block at risk=61
**Component:** [challenge/ladder.rs:36-38](aegis-gate/crates/aegis-security/src/challenge/ladder.rs#L36-L38)
`BotClass::Automated && risk > 60 → block` crosses the §5.5 ladder boundary (block should be >70). Align thresholds.

---

## Severity rationale

All MEDIUM because:
- Each affects a narrow case OR is latent (M-23 relies on caller misuse).
- Code-rot smell rather than active bug (M-14, M-15, M-17).
- Performance / fragility under specific conditions (M-09, M-13, M-25, M-26, M-28).
- Mutation-resistance edge cases (M-01, M-02, M-03, M-04, M-05) — each one would normally be HIGH, but bundled because of volume and similar fix shape (regex tuning).

None alone justifies an individual file. Bundled for a single
hardening PR after the CRITICAL+HIGH set is landed.
