# PLAN — Serious content-attack detector gaps (S-Tester 2026-07-06)

> **Type:** PLAN (detector coverage) · **Status:** 🔴 Open · drafted 2026-07-06
> **Track ID prefix:** `SG-<n>` · **Source:** `tests/s-tester/reports/2026-07-06/MISSED_attacks_serious.{json,md}` (18 serious misses)
> **Sibling plans:** command-injection recall → [`PLAN-cmdi-recall-2026-07-06.md`](./PLAN-cmdi-recall-2026-07-06.md) · recon → [`PLAN-recon-severity-block-2026-07-06.md`](./PLAN-recon-severity-block-2026-07-06.md) · response leak → [`PLAN-response-filtering-dlp-2026-07-06.md`](./PLAN-response-filtering-dlp-2026-07-06.md)

**Objective:** close the request-side detector gaps for the 18 serious content attacks the S-Tester
replayed and the WAF passed to the origin. **Zero-FP discipline throughout** — every signature added
here must be a token that does not occur in valid traffic, or be scoped/scored so it cannot over-block.

> ⚠️ **Framing note.** In the report all 18 show a non-`allow` `waf_status` (401/403/400/404) — but that
> is the **cumulative IP-risk gate or the upstream** reacting, *not* the content detector. The relevant
> detector (`ssrf` / `nosql` / `header_injection` / `command_injection`) contributed **no signal**. With a
> rotated/clean IP these slip. Verified: `http://internal-service:8080`, `http://127.1`, `http://redis:6379`
> match **no** `SSRF_PATTERNS` (standalone regex replay, 2026-07-06). Fix the detector, not the risk gate.

---

## 1. Miss inventory (18)

| Type | Count | Representative payload | Detector | Root cause |
|---|---|---|---|---|
| `ssrf_body` | **14** | `{"email":"http://redis:6379"}`, `http://127.1`, `http://kubernetes.default.svc.cluster.local` | `ssrf.rs` | patterns miss short-loopback, single-label internal host, internal-TLD outside `@` context |
| `cmd_injection_body` | 2 | `{"format":"cat$IFS/etc/passwd"}` · Next.js RSC `child_process.execSync` | `command_injection.rs` / `body_abuse` | `$IFS` whitespace-evasion + JS-RCE vocab absent — **see sibling cmdi plan** |
| `nosql_body` | 1 | `{\"$ne\":null}` (backslash-escaped quotes) | `nosql_injection.rs` | JSON-string escaping not normalized before match |
| `crlf_header` | 1 | `x-injected: __V10_CRLF__` via raw `\r\n` | `header_injection.rs` | hyper split the raw CRLF into 2 headers **before** the detector ran |

---

## 2. SG-1 — SSRF body patterns (14 misses) · **S** · START HERE

**File:** `crates/aegis-security/src/detectors/ssrf.rs` (`SSRF_PATTERNS`, ~L10–84). Body is already
scanned (`ssrf.rs:108`) via `form_body_is_opaque_beacon` gate — **architecture is fine, add patterns only.**

Payloads that slip (all verified no-match): `http://127.1`, `http://127.0.1`, `http://internal-service:8080`,
`http://database:3306`, `http://redis:6379`, `http://elasticsearch:9200`, `http://kubernetes.default.svc.cluster.local`.

Add three FP-safe patterns; gate the fourth:

1. **Full loopback `127.0.0.0/8` shorthand** — `(?i)https?://127(?:\.\d{1,3}){1,3}\b` → catches `127.1`, `127.0.1`.
   *FP≈0: `127.x` never appears in a public URL value.*
2. **Internal-TLD in a plain URL** (lift out of the `@`-only branch at L59) —
   `(?i)https?://[a-z0-9.-]+\.(?:internal|local|svc|cluster\.local)\b`.
   *FP≈0 for `.svc`/`.cluster.local` (K8s); `.local` is mDNS — consider **challenge** not block if dev uses it.*
3. **Single-label host + internal service port** — strong signature, low FP:
   `(?i)https?://[a-z0-9-]+:(?:22|3306|5432|6379|9200|9300|27017|11211|2379|5601|15672|8080|9000)\b`
   → catches `redis:6379`, `database:3306`, `elasticsearch:9200`, `internal-service:8080`.
   *FP low: public URLs use multi-label FQDNs + 80/443; single-label + infra port is anomalous.*
4. **(GATED) Any single-label host in a URL** — `(?i)https?://[a-z0-9-]+(?::\d+)?(?:[/?#]|$)`.
   Higher FP risk (some apps hold valid internal hostnames). **Do not hard-block:** score low /
   challenge, and prefer scoping to URL-typed fields (`/api/integrations/preview` `url`, `callback_url`,
   `webhook`). Ship #1–#3 first; only add #4 if the corpus still shows misses.

**Keep** the existing FP gates (`form_body_is_opaque_beacon`, Referer-drop). Consider an internal-host
**allowlist** if the app legitimately calls a few internal hosts.

---

## 3. SG-2 — NoSQL escaped-quote normalization (1 miss) · **S**

**File:** `crates/aegis-security/src/detectors/nosql_injection.rs`. Pattern `"\$ne"…` is correct, but the
real body is `{\"$ne\":null}` — quotes are backslash-escaped, so the literal `"$ne"` never appears.

- **Preferred:** route the nosql (and ssrf/cmdi) body scan through a **JSON-unescape** normalization pass
  (`\"`→`"`, `\\`→`\`) — mirror the existing `url_decode` / `normalize_for_detection` approach cmdi uses.
  One normalizer, reused, so double-encoding is covered everywhere. See [[project_ltester_decodes_dataplane_raw]]
  — validate with **Rust unit tests on raw forms**, not the Python harness (which double-decodes).
- **Cheaper fallback:** widen the pattern to tolerate optional backslash:
  `(?i)\\?"\$(?:ne|gt|gte|lt|lte|in|nin|eq|regex|where|exists|elemMatch)\\?"\s*:`.
  Keeps the closed operator vocabulary + `:` → FP stays low.

---

## 4. SG-3 — JS-RCE / prototype-pollution vocab (1 miss) · **M**

**Payload:** Next.js RSC multipart — `"$1:__proto__:then"`, `constructor:constructor`,
`process.mainModule.require('child_process').execSync('printenv',…)`. Currently unscored (round-1 only
tripped behavior signals).

- Add a high-specificity vocab to `body_abuse` (or `command_injection` body path): `__proto__`,
  `constructor\s*:\s*constructor`, `constructor\.constructor`, `process\.mainModule`,
  `child_process`, `execSync|spawnSync|\.exec\(`, `require\(\s*['"]child_process`.
  *FP≈0 in fintech JSON — these are exploit-only tokens. Flag `constructor:constructor` /
  `constructor.constructor` only, never bare `constructor`.*
- **Ensure multipart bodies are scanned** — payload arrived as `multipart/form-data`; confirm
  `body_is_scannable` accepts it (or scan the decoded parts).

---

## 5. SG-4 — CRLF header injection (1 miss) · **M** · defense-first

**File:** `header_injection.rs`. Raw `\r\n` in a header value is **split by hyper into two headers before the
detector runs** (`x-custom: value` + `x-injected: __V10_CRLF__`) — see [[project_hyper_normalizes_framing]].
Encoded `%0d%0a` is already caught; only **raw** CRLF slips.

Priority order:
1. **(defense, FP≈0) Output-side CR/LF strip** — guarantee the WAF strips CR/LF from any header value it
   **forwards upstream or reflects into a response**. Kills response-splitting at the source regardless of
   detection. **Do this first.**
2. **(optional, observe-only) Injected-header heuristic** — flag when a suspiciously-named / duplicate
   header appears adjacent to a client-controlled free-text header. Higher FP → log/observe, don't block.
3. **(hard) Raw ingress-byte inspection** before hyper parses — thorough but invasive; defer unless (1)+(2)
   prove insufficient.

---

## 6. Cross-cutting FP discipline (per S-Tester request)

1. Prefer **"cannot be valid"** tokens (`127.x`, `.svc/.cluster.local`, infra ports, `$IFS`, `__proto__`,
   `child_process.execSync`) → add directly, FP≈0.
2. Ambiguous signatures (any single-label host, bare command) → **separate, low-score / challenge /
   observe**, never hard-block; scope to URL/text fields where possible.
3. **Normalize before match** — url-decode (have it) **+ JSON-unescape (new)** + double-decode; many misses
   are encoding, not missing patterns.
4. Keep every existing FP gate — do **not** revert `form_body_is_opaque_beacon`, Referer-drop, or the
   removed generic `${VAR}` cmdi pattern; add **specific** tokens only.
5. **Two-way regression mandatory** — after adding patterns, replay the benign corpus
   (`waf_allowed_api_normal`, `btc_round2_benign`) to measure FP, not just attack recall. See
   [[feedback_test_suite_green_baseline]].

---

## 7. Priority & effort

| # | Track | Extra catches | FP risk | Effort |
|---|---|---|---|---|
| 1 | SG-1 SSRF (loopback + internal-TLD + single-label:port) | 14 | Very low | S |
| 2 | SG-2 NoSQL JSON-unescape normalizer | 1 (+ hardens ssrf/cmdi) | Very low | S |
| 3 | SG-3 JS-RCE / proto vocab + multipart scan | 1 | Low | M |
| 4 | SG-4 CRLF output-side strip (+ optional detect) | 1 | Very low (defense) | M |

Command-injection `$IFS` (report item 2a) is folded into the **sibling cmdi plan** so all cmdi recall work
lands together.

## 8. Test plan

- **Recall:** replay the 18 records in `MISSED_attacks_serious.json` against a clean IP → target 18/18 fire
  a **content** detector (not just the risk gate). Add each as a Rust `positive!` fixture in the owning
  detector's test module (raw JSON-escaped forms, per [[project_ltester_decodes_dataplane_raw]]).
- **FP:** replay `btc_round2_benign` + `waf_allowed_api_normal` → content-block FP < 1%.
- `cargo test --workspace` green + zero-warning ([[feedback_test_suite_green_baseline]]); hand-match style,
  only rustfmt files authored in full ([[project_rustfmt_whole_crate_hazard]]).
