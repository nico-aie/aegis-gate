# l-tester cross-check + DDoS audit — unified fix plan (2026-05-09)

> **Sources:**
> - [`tests/l-tester/reports/2026-05-09-run1/LT-RUN-1-CONTRACT-COMPLIANCE.md`](../../../../tests/l-tester/reports/2026-05-09-run1/LT-RUN-1-CONTRACT-COMPLIANCE.md) — 108/108 PASS
> - [`tests/l-tester/reports/2026-05-09-run2/LT-RUN-2-BUG-HUNTER.md`](../../../../tests/l-tester/reports/2026-05-09-run2/LT-RUN-2-BUG-HUNTER.md) — 149/149 PASS (against mock v2)
> - [`tests/l-tester/reports/2026-05-09-run3/LT-RUN-3-HACKER-BYPASS.md`](../../../../tests/l-tester/reports/2026-05-09-run3/LT-RUN-3-HACKER-BYPASS.md) — 17 confirmed bypasses (against unpatched mock v2)
> - [`reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md`](../../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md) — DDoS module is dead code
>
> **Branch:** all changes target `develop`.

---

## TL;DR

The three l-tester reports look alarming at first glance (especially Run-3's "12 confirmed bypasses"), but **most of those bugs are in the Python `mock_waf.py` reference, not in the Rust WAF.** Cross-checking each bypass against `crates/aegis-security/` reveals only **2 of 17** apply to Rust. The DDoS audit is a separate, independent issue.

This plan groups the work into three independent tracks so they can ship in any order:

| Track | What | Effort | Owner | Status |
|---|---|---|---|---|
| **A.** Confirmed Rust bypasses (l-tester) | Fix SSTI space-tolerance + add IPv4-mapped IPv6 SSRF coverage | ~1 hr | This plan, Phase 1 | ✅ **Shipped** ([`3e1270b`](#)) |
| **B.** Verify-only l-tester bypasses (regression pinning) | Add Rust regression tests proving the other 10 bypasses don't apply | ~1 hr | This plan, Phase 2 | ⏳ Pending |
| **C.** DDoS wire-up (internal audit) | Two-phase wire-up of `DdosDetector` (already planned) | ~2 days | [`internal-audit-2026-05-09-ddos/`](../internal-audit-2026-05-09-ddos/README.md) | Phase 1 ✅ shipped, Phase 2 pending |

---

## Important: scope of the l-tester reports

The l-tester suite (`tests/l-tester/`) is a **Python bash + curl harness** that asserts contract behaviour against a configurable target. Its ground-truth reference for "what the WAF should do" is the Python `mock_waf.py` it ships alongside. The reports' bug catalogues describe gaps the tester **found in the mock** by reading the Rust source — i.e. the mock didn't faithfully reproduce the Rust WAF's behaviour.

This is visible in the report wording itself:

- Run-2 §3 BUG-04: *"Mock WAF (v1) `reset_state()` called `_state["default_mode"] = "enforce"`. ... The real WAF [Rust] correctly preserves modes."*
- Run-3 header: *"Mock WAF version: **v2 (unpatched)** — bugs NOT yet fixed"*
- Run-2 §"Mock WAF v2 Changes": *"Reference implementation"* changes only.

So Run-1's 108/108 PASS is meaningful — it confirms the **Rust** WAF passes the contract on the surfaces tested (auth, capabilities, reset, set_profile, headers, audit, caching, log_only, source IP). Run-2 and Run-3 catalogue **mock-vs-Rust drift** — useful for keeping the mock honest, but not action items for the Rust binary unless cross-checked.

The cross-check below verifies **each Run-3 bypass** against `crates/aegis-security/`.

---

## Cross-check table — Run-3 bypasses vs Rust source

| # | Run-3 bypass | Rust state | Verdict |
|---|---|---|---|
| BYPASS-01 | SQLi `SELECT\nFROM users` | `UNION\s+SELECT` matches (`\s+` includes `\n`); `SELECT\s+.+\s+FROM` matches because `.+` between SELECT and FROM doesn't need to span newlines (the inner content `1` is on one line) | **NOT a Rust bug** — verify with regression test |
| BYPASS-02 | POST body completely uninspected | `crates/aegis-proxy/src/data_plane.rs:372` reads full body via `BodyPeek::new(body_bytes.to_vec(), ...)`, and every detector calls `req.body.peek(8192)`. SQLi, XSS, CMDi, SSRF, path-traversal all inspect body | **NOT a Rust bug** — verify with end-to-end regression test |
| BYPASS-03a | SSRF decimal IP `http://2130706433/` | `(?i)(?:https?://\d{8,10})` covers it | NOT a Rust bug |
| BYPASS-03b | SSRF hex IP `http://0x7f000001/` | `(?i)(?:https?://0x[0-9a-f]+)` covers it | NOT a Rust bug |
| BYPASS-03c | SSRF octal IP `http://0177.0.0.1/` | `(?i)(?:https?://0[0-7]+\.)` covers it | NOT a Rust bug |
| BYPASS-03d | SSRF IPv6 `http://[::1]/` | `(?i)(?:https?://\[::1?\])` covers it | NOT a Rust bug |
| BYPASS-03e | SSRF `http://0.0.0.0/` | `(?i)(?:https?://0\.0\.0\.0)` covers it | NOT a Rust bug |
| **BYPASS-03f** | SSRF IPv4-mapped IPv6 `http://[::ffff:127.0.0.1]/` and `http://[::ffff:7f00:1]/` | **No pattern covers it.** `\[::1?\]` matches `[::1]` only; the IPv4-mapped form is a distinct shape that pre-Rust-Run-5 the SSRF detector never had | **REAL Rust bug** — see Phase 1 |
| BYPASS-03g | SSRF AWS metadata as decimal `http://2852039166/` | `(?i)(?:https?://\d{8,10})` matches `2852039166` | NOT a Rust bug |
| **BYPASS-04** | Template injection `{ { 7*7 } }` (spaces between braces) | All `{{...}}` patterns require **adjacent** `\{\{`. A space between the two `{` breaks every pattern. Confirmed via reading the regex literally: `\{\{\s*['"]?\d+['"]?\s*\*\s*['"]?\d+['"]?\s*\}\}` | **REAL Rust bug** — see Phase 1 |
| BYPASS-05 | CMDi backtick `` `id` `` | `(?i)\`[^\`]+\`` exists in CMDI_PATTERNS | NOT a Rust bug |
| BYPASS-06 | Control plane: `features: "rules_engine"` (string) returns 200 | Rust uses `serde` with `Vec<String>` types; sending a string would deserialize-fail and return 400 | NOT a Rust bug — verify |
| BYPASS-07 | Control plane: `feature: ["rules_engine"]` (array) crashes | Rust uses `serde` with `Option<String>` for `feature`; array would deserialize-fail and return 400 (no crash) | NOT a Rust bug — verify |

**Summary:** **2 real Rust bypasses** (BYPASS-03f and BYPASS-04). The remaining 10 are either mock-only bugs (the Rust WAF already covers them) or worth pinning with regression tests so they stay covered.

---

## Phase 1 — Confirmed Rust bypasses (1 PR)

### BYPASS-03f · SSRF IPv4-mapped IPv6 — `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`

**Location:** `crates/aegis-security/src/detectors/ssrf.rs::SSRF_PATTERNS`

**Detection logic:**

The IPv4-mapped IPv6 prefix `::ffff:` (lower-128 form) is a documented escape hatch for SSRF allowlists that look only for dotted-decimal RFC 1918 / loopback. Browsers and many HTTP clients resolve `[::ffff:127.0.0.1]` as `127.0.0.1` natively. The mapped form occupies a fixed, narrow regex shape: `\[::ffff:` followed by either dotted-decimal or hex-colon notation.

Add two patterns to `SSRF_PATTERNS`:

```rust
// IPv4-mapped IPv6: `[::ffff:<ipv4>]` (browsers resolve this
// as the embedded IPv4). Covers loopback (`[::ffff:127.0.0.1]`),
// RFC 1918 (`[::ffff:10.0.0.1]`), link-local
// (`[::ffff:169.254.169.254]`), and AWS metadata.
r"(?i)(?:https?://\[::ffff:(?:127|10|0|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)",
// IPv4-mapped IPv6 in hex-colon form: `[::ffff:7f00:1]`,
// `[::ffff:a9fe:a9fe]` (AWS metadata as hex-pair).
r"(?i)(?:https?://\[::ffff:(?:7f00|0a[0-9a-f]{2}|a9fe|c0a8|ac1[0-9a-f]):)",
```

**Score: 50** (existing `ssrf::SSRF` const, unchanged). Same class — just additional pattern coverage.

**Field tag:** `ssrf` (existing).

**Tests:**
- Positive: `?url=http://[::ffff:127.0.0.1]/secret`, `?url=http://[::ffff:10.0.0.1]/`, `?url=http://[::ffff:169.254.169.254]/latest/`, `?url=http://[::ffff:7f00:1]/`, `?url=http://[::ffff:a9fe:a9fe]/`.
- Negative: `?url=http://[2001:db8::1]/` (public IPv6 — no SSRF), `?url=https://example.com/path` (no IPv6), `?email=user@[::ffff:127.0.0.1]` (mailto-like, no scheme — actually we may need to be careful here: this contains `://` after http if the URL is mailto, but the regex requires `https?://` so it won't fire on `mailto:user@[...]`).

### BYPASS-04 · SSTI space-between-braces tolerance — `{ { 7*7 } }`

**Location:** `crates/aegis-security/src/detectors/template_injection.rs::SSTI_PATTERNS`

**Detection logic:**

Template engines like Jinja2 + Twig **don't** accept `{ { 7*7 } }` as valid template syntax — the engine's own parser requires adjacent `{{` and `}}`. So an attacker sending `{ { 7*7 } }` as a payload **wouldn't trigger SSTI** even if the WAF allowed it through. This is a **mock-WAF artefact**, not a real attack shape, and we shouldn't broaden the regex to catch it because doing so would FP on legit JSON / brace-bearing content (`{"key": "value"}` etc. are common in URLs and bodies).

**Recommendation: do NOT loosen the pattern** — instead, document the rationale, pin a regression test that the **adjacent-brace** form fires, and **explicitly verify** the spaced form does NOT fire. The l-tester's mock_waf.py was using a more permissive regex (`\{\{.+?\}\}` per Run-3 §BYPASS-04 root cause), which is what they patched to require adjacent. The Rust WAF's stricter pattern is **correct**, not a bug.

**Action for Phase 1:**
- Add 2 negative tests pinning that `{ { 7*7 } }` **does not** fire SSTI (this is the documented behaviour, not a regression).
- Update `docs/security/detectors/template-injection.md` with a "Why we don't match `{ { ... } }`" subsection explaining the engine-validity rationale.
- The Run-3 BYPASS-04 reclassifies as **"Not a Rust WAF bug — engine wouldn't execute the payload anyway."**

### Phase 1 acceptance

- [ ] 5 positive IPv4-mapped IPv6 tests fire SSRF
- [ ] 3 negative tests (public IPv6, no scheme, mailto-like) stay green
- [ ] 2 negative tests pin `{ { 7*7 } }` does NOT fire SSTI (documented behaviour)
- [ ] Per-detector docs updated: `ssrf.md` adds an IPv4-mapped IPv6 row + rationale; `template-injection.md` adds a "Why we don't match spaced braces" subsection
- [ ] Cross-refs updated (detectors/README, security-engine, implementation-matrix)
- [ ] Workspace tests green (1242+ security, 1045+ control, 18/18 binaries)

**Effort:** ~1 hour.

---

## Phase 2 — Verify-only Rust regression tests (1 PR, optional)

For every Run-3 bypass marked "NOT a Rust bug" in the cross-check table, add a regression test that pins the Rust behaviour. This stops a future refactor from accidentally introducing the bypass — and gives operators paste-able evidence when the QA team flags a "the mock has this bypass" finding.

### Test additions

| File | Tests |
|---|---|
| `crates/aegis-security/src/detectors/sqli.rs::tests` | `sqli_newline_select_from`, `sqli_newline_union_select` (BYPASS-01) |
| `crates/aegis-security/src/detectors/ssrf.rs::tests` | `ssrf_decimal_ip`, `ssrf_hex_ip`, `ssrf_octal_ip` already exist; **add** `ssrf_ipv4_mapped_loopback`, `ssrf_ipv4_mapped_metadata` (BYPASS-03f from Phase 1) |
| `crates/aegis-security/src/detectors/command_injection.rs::tests` | `cmdi_backtick` already covered (BYPASS-05); add explicit URL-encoded variant `cmdi_backtick_url_encoded` |
| `crates/aegis-proxy/tests/post_body_inspection.rs` (new integration test) | End-to-end: POST with SQLi / XSS / CMDi / SSTI / NoSQL / SSRF / path-traversal in body returns 403 / X-WAF-Action: block. Closes BYPASS-02 audit forever. |
| `crates/aegis-control/src/api/control.rs::tests` | `set_profile_features_as_string_returns_400`, `set_profile_feature_as_array_returns_400_no_crash` (BYPASS-06, BYPASS-07) — `serde::deny_unknown_fields` + typed structs already enforce this; just pin it |

### Phase 2 acceptance

- [ ] Every Run-3 BYPASS row marked "NOT a Rust bug" has at least one Rust regression test asserting the Rust WAF catches the payload (or rejects the malformed control-plane body)
- [ ] Existing tests still pass
- [ ] Per-detector docs gain a brief "Run-3 bypass coverage" subsection cross-linking the regression tests so operators reading either doc trail can confirm coverage

**Effort:** ~1 hour.

---

## Phase 3 — Update mock_waf.py to match the Rust contract (deferred)

The l-tester's `mock_waf.py` is the test harness's reference. Run-2 found 9 mock-vs-Rust drift bugs; Run-3 found another batch by attacking the unpatched mock. Each round of l-tester work has updated the mock. The mock is now closer to the Rust WAF but still has the bugs Run-3 catalogued (since Run-3 ran against the unpatched mock).

This is **the l-tester team's work**, not a Rust-WAF fix. We should:
- Acknowledge in the l-tester README that the mock is a moving target and the **Rust binary is authoritative**.
- File a separate issue for the l-tester team to apply the Run-3 fixes to the mock if they haven't already.
- Make the cross-check table above visible to future readers (drop a NOTE in `tests/l-tester/README.md` that mock-vs-Rust drift is the dominant bug class, not real-WAF bugs).

This work doesn't gate the Rust fix plan; it's hygiene for the test harness.

**Effort:** owned by l-tester team.

---

## Track C — DDoS wire-up (cross-link, separate plan)

Independently of the l-tester findings, the [DDoS audit](../../../reports/findings/2026-05-09-internal-audit-ddos/BUG-DDOS-STUB.md) found `aegis-security/src/ddos.rs` is a stub. Wire-up plan: [`plans/issue-fix/internal-audit-2026-05-09-ddos/`](../internal-audit-2026-05-09-ddos/README.md).

Two phases (Phase 1 observe-only telemetry; Phase 2 enforce + 503). Phase 1 should land first because it's behaviour-neutral and gives operators metrics to validate the signal before flipping enforce on.

---

## Sequencing

| Order | Phase | Effort | Status | Why this order |
|---|---|---|---|---|
| 1 | This plan, Phase 1 | ~1 hr | ✅ **Shipped** ([`3e1270b`](#)) | Closes 2 confirmed Rust bypasses; small surface, easy review |
| 2 | DDoS Phase 1 (observe-only) | ~1 day | ✅ **Shipped** ([`095537d`](#)) | Higher impact than the l-tester regression pinning; behaviour-neutral so safe to land on develop without bake-in |
| 3 | This plan, Phase 2 (regression pinning) | ~1 hr | ⏳ Pending | Documentation-style work; can ship while DDoS bakes |
| 4 | DDoS Phase 2 (enforce + 503) | ~1 day | ⏳ Pending operator bake-in | Behaviour-changing; gated on DDoS Phase 1 metrics being clean |
| 5 | l-tester team updates mock_waf.py | external | external | Hygiene, doesn't affect Rust binary |

---

## What this plan does NOT cover

- **Run-1 contract pass — no work.** All 108 contract assertions green against the Rust WAF.
- **Run-2 mock-vs-Rust bugs (BUG-01 through BUG-09).** Reading those root-cause sections confirms the Rust WAF was already correct; the mock was the regression. No Rust fix needed.
- **Run-3 BYPASS-01, -02, -03a–e, -03g, -05, -06, -07.** Cross-check shows Rust catches them. Phase 2 pins this with regression tests but no detector code change.
- **The bare `/metrics` recon trade-off.** Documented in [`recon.md`](../../../../docs/security/detectors/recon.md) since Run-6 — operator-hosted Prometheus endpoint, not a missed gap.
- **Loopback alias source-IP test (Run-1 §10 SKIP).** Infrastructure-bound test; out of scope for the Rust binary.

---

## Cross-refs

- [`tests/l-tester/`](../../../../tests/l-tester) — l-tester source (the mock + test scripts)
- [`crates/aegis-security/src/detectors/ssrf.rs`](../../../../crates/aegis-security/src/detectors/ssrf.rs) — SSRF patterns to extend in Phase 1
- [`crates/aegis-security/src/detectors/template_injection.rs`](../../../../crates/aegis-security/src/detectors/template_injection.rs) — SSTI patterns (regression-pin only)
- [`crates/aegis-proxy/src/data_plane.rs`](../../../../crates/aegis-proxy/src/data_plane.rs) — body inspection wiring (BYPASS-02 evidence)
- [DDoS wire-up plan](../internal-audit-2026-05-09-ddos/README.md) — separate but parallel track
- [Operator risk-tuning guide](../../../../docs/operator/risk-tuning.md) — for the "I want bare `/metrics` flagged" trade-off
