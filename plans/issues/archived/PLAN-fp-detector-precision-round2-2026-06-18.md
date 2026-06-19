# PLAN — Benign over-block triage, Round 2: residual detector FPs on the 21:32 run (2026-06-18)

- **Type:** PLAN (QC FP-report double-check → code-grounded root cause + per-rule fix specs)
- **Status:** ✅ **IMPLEMENTED** (2026-06-19) on branch `fix/fp-detector-precision-round2`, TDD
  (RED→GREEN per step). All 7 steps S-A…S-G landed; full `aegis-security` lib suite green
  (**1819 passed / 0 failed**, +45 detector fixtures over the 1774 baseline). Workspace (`aegis-proxy`)
  builds; no new clippy warnings. **Remaining:** corpus replay (200k n-tester run) as the final field gate —
  the per-step fixtures reproduce every captured benign shape, so this is confirmation, not discovery.
  - ✅ **S-A** — opaque-beacon fast-path restricted to high-specificity tokens (`${jndi`, `/bin/`,
    `/etc/passwd`, `sh -c`, `union`, `select`, …); bare `` ` ``/`$(`/`${`/`{{`/`<%` dropped. Also fixed the
    gate's text/plain `=`-truncation. Clears cmdi (397) + sqli (149) beacon FPs.
  - ✅ **S-B** — beacon gate wired into xss + ssrf body scans.
  - ✅ **S-C** — mass-assignment body surfaces require value context (truthy flag / escalating role); `scope`
    dropped. Clears `is_admin:false` (122) / `admin:false` (156) / `role:CREATOR` / `scope:read` (252).
  - ✅ **S-D** — ssrf userinfo: tight RFC-3986 charclass + internal-host requirement. Clears JSON-LD
    `schema.org","@type` + Sentry DSN FPs; keeps `evil@internal-svc` / `evil@169.254.169.254`.
  - ✅ **S-E** — header-injection query **and** header-value CRLF require a header-name token after the
    newline (path scan stays strict). Clears the 107 query + 91 cookie-value `%0a`/`%0d` FPs.
  - ✅ **S-F** — recon: Docker pattern pinned to `v1.NN` (kills FB `/v6.0/plugins/…`); `is_benign_recon_path`
    guard for Chrome attribution-reporting + WordPress `admin-ajax.php`. Clears ~382 non-blocking noise hits.
  - ✅ **S-G** — xss `javascript:` requires a JS-execution sink; inert `javascript:void(0)` / `;` no longer fire.
- **Original status:** 🟡 PROPOSED (2026-06-18) — confirmed, then executed.
- **Source run:** `qc-fp-report/20260618_213203_fp_logs/` (post-fix re-run; **now logs full headers + body**,
  so the §1/S0 attribution gap from the 12:25 plan is closed — every root cause below is read off the captured
  request, not inferred from a URL).
- **Predecessor:** `PLAN-fp-detector-precision-2026-06-18.md` (the 12:25 run). S1/S3-jku/S4/S5/S2-bodygate
  landed on `develop`. This plan covers the **residuals that survived** those fixes, plus the two classes the
  prior plan had to defer for lack of body/header logs (ssrf §2g, header-injection §2f).
- **Scope (per QC request):** the 7 rules QC flagged — `recon-path` (558), `command-injection` (397),
  `mass-assignment` (252), `ssrf` (247), `header-injection` (199), `sqli` (149), `xss` (142). Other rules skipped.

---

## 0. Double-check: is QC right? — Yes. All 7 are genuine benign over-blocks.

Every case is real first-party traffic from major properties — Zara, Net-a-Porter, Instacart, Facebook, Delta,
LinkedIn, Google Analytics, WooCommerce, Samsung. Not a single sampled case is an attack. The QC report is
**correct**: these are false positives. Breakdown of what actually fires (read from the now-logged body/headers):

| Rule | Count | Action | Confirmed trigger (from captured request) | Verdict |
|------|--:|--|--|--|
| recon-path | 558 | **allow** (score 25, non-blocking) | `/.well-known/attribution-reporting/debug/…` (267), WP `admin-ajax.php` (102), FB `/v6.0/plugins/page.php` (13) | FP (noise, feeds IP-risk) |
| command-injection | 397 | block 403 | 377 `text/plain` Akamai `sensor_data` beacons | FP |
| mass-assignment | 252 | block 403 | JSON bodies with `"admin":false` (156) / `"is_admin":false` (122) | FP |
| ssrf | 247 | block 403 | userinfo `@` on JSON-LD `schema.org","@type` + Sentry DSNs; `text/plain` beacons | FP |
| header-injection | 199 | block 403 | bare `%0a`/`%0d` in benign analytics query values (107+) | FP |
| sqli | 149 | block 403 | same `text/plain` beacon blobs as cmdi | FP |
| xss | 142 | block 403 | bare `javascript:` (38, e.g. `javascript:void(0)`) + 24 beacon blobs | FP |

> **Note on recon-path:** it is `action=allow` on every one of the 558 cases (PATH score 25 < every tier), so it
> is **not blocking** anyone today. But recon PATH still contributes to the cumulative per-IP risk score, and it
> floods the audit log with benign browser/CMS/analytics paths. QC is right to flag it; it is a precision/noise
> problem, not an availability one. Fix is low-risk and high-signal-cleanup.

**One headline number for QC:** of the 7, **six block (1,193 hard 403s)** and one is non-blocking noise. The
single biggest *blocking* offender is `command-injection` (397), and it has the **same** root cause as `sqli`
(149) and the `text/plain` share of `ssrf`/`xss` — one shared fix (§2a) clears the majority.

---

## 1. Root causes (each reproduced against detector source on HEAD `8094ba4`)

### 2a. The opaque-beacon gate is defeated by its own keyword fast-path — `command-injection` (397) + `sqli` (149) + beacon share of `ssrf`/`xss`

**This is the #1 finding.** The `form_body_is_opaque_beacon` gate (`mod.rs:486`) landed exactly to skip
Akamai/PerimeterX/F5 sensor beacons. It is wired into cmdi (`command_injection.rs`), sqli (`sqli.rs`), and
template_injection — yet 397 cmdi + 149 sqli beacons still block. Why:

The gate bails (returns `false` → "scan it") whenever `has_high_signal_injection_shape(body)` matches
(`mod.rs:504`). That fast-path list (`mod.rs:452-464`) includes the **single/double-character** shapes
`` ` ``, `$(`, `${`, `{{`, `<%`. The captured beacons are ~5 KB of high-entropy printable ASCII, so they contain
those bytes **by chance, essentially always**:

```
command-injection.txt:  bodies containing  `  = 668     $( = 100     ${ = 103
```

So the gate that was supposed to skip the beacon instead re-admits it, the body scanner runs, and the random
blob's stray `` `…` `` / `$(…)` trips cmdi (and the same blob trips sqli's quote/comment shapes). The 12:25
plan's §5 risk — "keep the keyword fast-path so padded payloads are still scanned" — turns out to be the very
thing defeating the gate, because a 1–2 char shape collides with random data with probability ≈ 1.

**Fix spec (S-A).** Restrict `has_high_signal_injection_shape` to **high-specificity multi-char dictionary
tokens** that do *not* collide with random ASCII:
- Keep: `/etc/passwd`, `/bin/`, `sh -c`, `cmd /c`, `powershell`, `wget`, `curl`, `nslookup`, `union`, `select`.
- Replace bare `${` with the real attack token **`${jndi`** (log4shell must still re-admit), and drop bare
  `` ` ``, `$(`, `{{`, `<%` from the fast-path (they are 1–2 char, ~100% collision in a high-entropy blob).
- Rationale: a genuine `$(id)` / backtick payload *hidden inside a single-dominant high-entropy form blob* is
  the exact case the entropy gate is designed to accept skipping (documented S2 tradeoff). A real cmdi payload
  in **parseable** form data is multi-field / low-entropy and never reaches the beacon gate at all.

**Tests:** replay the captured `sensor_data` POSTs → 0 cmdi/sqli FP; keep positive fixtures for `;cat /etc/passwd`,
`$(id)`, `` `id` ``, `${jndi:ldap://…}` in a *normal* (multi-field / low-entropy) form body — these still fire
because they do not satisfy the single-dominant-blob beacon shape.

### 2b. `xss` and `ssrf` body scans are not behind the beacon gate at all

`grep form_body_is_opaque_beacon` → only `command_injection.rs`, `sqli.rs`, `template_injection.rs`. `xss.rs:108`
and `ssrf.rs:86` `peek(8192)` and scan the raw body with **no** opaque-beacon guard. That is why 24 xss + the
`text/plain` share of ssrf are beacon blobs.

**Fix spec (S-B).** Wire the same (post-S-A) `form_body_is_opaque_beacon` guard into the xss and ssrf body
scans, identical to cmdi/sqli. Query/path/header scans stay unguarded (beacons are body-only).

### 2c. `mass-assignment` (252) — JSON scan flags the key NAME, ignores the value

`MASS_ASSIGN_KEYS_JSON` (`body_abuse.rs:83`) matches `"key"\s*:` on name only (`body_abuse.rs:194`). The
captured FPs are overwhelmingly benign telemetry stating the user is **not** privileged:

```
"admin":false   = 156     "is_admin":false = 122     "scope":"openid"/"PAGE"/"read" …   "role":"CREATOR"/"leader"
```

`"is_admin":false` is the *opposite* of a mass-assignment attack. The S1 query-surface split already cut this
574→252; the residual is the JSON body surface flagging benign `false`/read-only values.

**Fix spec (S-C).** Move the JSON body surface from name-presence to **name + privilege-escalating value**:
- Boolean/flag keys (`is_admin|isAdmin|admin|is_superuser|isSuperuser|superuser|verified|email_verified`):
  fire only on a truthy value — `:\s*(true|1|"1"|"true"|"yes")`. `:false`/`:0` → no signal.
- Role/level keys (`role|access_level|accessLevel|user_level|userLevel`): fire only on an escalating value —
  `admin|superuser|root|owner|sa|system`. Benign roles (`CREATOR`, `leader`, `viewer`, region strings) → no signal.
- `scope` is an OAuth/analytics term (`openid`, `read`, `PAGE`, `WORLDWIDE`) — **drop it from the JSON/form body
  surface**; keep `permissions|privileges|grants`. Credential/token keys keep name-match in a write body (a
  `password_hash`/`access_token` *field* in a body is still the real shape — but see §3 note).

**Tests:** negatives for `{"is_admin":false}`, `{"admin":false}`, `{"role":"CREATOR"}`, `{"scope":"openid"}`;
positives for `{"is_admin":true}`, `{"role":"admin"}`, `{"access_level":"root"}` still fire.

### 2d. `ssrf` userinfo pattern (247) — `[^@/\s]+@` crosses JSON string boundaries

`ssrf.rs:40` `r"(?i)https?://[^@/\s]+@"`. The class excludes `/`, `@`, whitespace but **not** `"`, `,`, `\`, `{`,
`}`. In a JSON body `…"url":"https://schema.org","@type":"…"` it greedily eats `schema.org","` and matches at the
`@` of `@type`. Captured matches:

```
https://schema.org","@type   (JSON-LD microdata, dozens)     https://<32hex>@oNNN.ingest.sentry.io  (Sentry DSN, 24)
```

Neither is SSRF. A real userinfo authority never contains `"`/`,`/`\`. And a bare `user@public-host` is not SSRF
at all — the attack is `http://evil@<internal-target>`.

**Fix spec (S-D).** Two-part, both required:
1. Tighten the userinfo class to RFC 3986 userinfo+host chars: forbid quote/backslash/comma/brace/angle, e.g.
   `https?://[A-Za-z0-9._~%:+!$&'()*=;-]+@`. Kills the JSON-LD matches immediately.
2. Require the host **after** `@` to be an internal/private/metadata target (reuse the existing
   loopback/RFC-1918/`169.254`/metadata alternations) — i.e. only `…@<internal>` is SSRF. Kills the Sentry DSN
   and any benign `user@public-host`. (Alternative if §2 is too invasive: demote bare-userinfo to a corroborating
   score so it stacks instead of solo-blocking. §2 is preferred — it removes the FP without weakening real catches.)

**Tests:** negatives for `https://schema.org","@type`, `https://abc123@o42.ingest.sentry.io`; positives for
`http://evil.com@169.254.169.254/`, `http://evil.com@127.0.0.1/` still fire.

### 2e. `header-injection` (199) — bare `%0a`/`%0d` in benign query values

`INJECTION_PATTERNS` (`header_injection.rs:11-26`) includes lone `%0d`, `%0a`, `%0D%0A`, and raw `\r|\n`. The
query scan (`check`, `header_injection.rs:38`) fires on a single encoded newline. 107+/199 captured queries carry
a benign `%0A` inside form-data text — e.g. Facebook pixel `…&cd[buttonText]=%0A%20%20%20%20&…` (a button's
literal newline+indent), JSON-in-query, multiline textarea content. A lone encoded newline in a query *value* has
legitimate uses (formatted text); it is only injection when **followed by a header**.

**Fix spec (S-E).** In the **query** surface, stop firing on a bare encoded/real newline. Require CRLF *followed
by* a header-injection shape — the detector already has the header tokens (`Set-Cookie:`, `Location:…`,
`Content-Type:`, `Transfer-Encoding:`, `X-Forwarded-For:`, `HTTP/\d\.\d \d{3}`); gate the query match on
`(newline)…(one of those tokens)` rather than newline-alone. **Leave the PATH scan unchanged** — a raw `\r`/`\n`
or `%0d%0a` in a path has no legit use (per the 2026-06-16 sec-regression note) and is the real smuggling vector.
Header-value CRLF scan also unchanged.

> ~92 of 199 do **not** carry `%0a`/`%0d` in the request line (e.g. `boatpartssuperstore` `count.asp?…&r=https%3A//…`
> encoded-URL params). Confirm those against the now-logged headers during implementation — likely the
> `Location:\s*https?://` token matching a decoded `r=https://…` redirect param; if so, scope that token to
> require a *preceding* newline too (same S-E gating), since `Location:` only injects after a CRLF.

### 2f. `recon-path` (558, non-blocking) — three over-broad path patterns hit standard browser/CMS/SDK traffic

All non-blocking (score 25) but pure noise + IP-risk pollution. Three patterns account for ~382 of 558:
- `r"(?i)(?:/debug/)"` (`recon.rs:32`) matches Chrome **Privacy Sandbox** `/.well-known/attribution-reporting/debug/verbose`
  (267) — a W3C/Chrome standard endpoint, never recon.
- `r"(?i)(?:^|/)wp-admin(?:$|[/?])"` (`recon.rs:27`) matches WordPress `admin-ajax.php` (102) — the legit
  front-end AJAX endpoint hit by every WP/WooCommerce visitor.
- Docker-API `v\d+\.\d+/(?:…|plugins|…)` (`recon.rs:49`) matches Facebook Graph `/v6.0/plugins/page.php`,
  `/v5.0/plugins/customerchat.php` (~13) — `plugins` is in the Docker alternation and collides with FB's
  versioned plugin URLs.

**Fix spec (S-F).**
- Narrow `/debug/`: exclude the `/.well-known/attribution-reporting/` prefix (or require a non-well-known
  segment). The Privacy Sandbox debug path is a standard, not a probe.
- Exclude `admin-ajax.php` from the `wp-admin` probe (`(?:^|/)wp-admin(?:$|[/?])` but `admin-ajax\.php` is benign
  front-end traffic; real recon is `/wp-admin/` index, `/wp-admin/setup-config.php`, etc.).
- Constrain the Docker `v\d+\.\d+/…` pattern so `plugins` requires a Docker-shaped sibling/verb, or drop
  `plugins` from the alternation (Docker plugin probing is low value vs. the FB collision cost). Also `/__utm.gif`
  / `/g/collect` (GA beacons) — confirm the matching pattern during impl and add to the analytics exclusion.

**Tests:** negatives for `/.well-known/attribution-reporting/debug/verbose`, `/wp-admin/admin-ajax.php`,
`/v6.0/plugins/page.php`, `/__utm.gif`; positives for `/wp-admin/`, `/wp-admin/setup-config.php`, `/v1.24/containers/json`,
`/actuator/env`, `/debug/pprof/` (real debug surface) still fire.

### 2g. `xss` (142) — bare `javascript:` + un-gated beacons

After S4 (`onX=` HTML-context), the residual is: `javascript:` scheme (38, e.g. `javascript:void(0)` captured in
benign DOM/telemetry) and 24 beacon blobs (fixed by §2b S-B). The `javascript:` pattern fires anywhere, but
`javascript:void(0)` / `javascript:;` are ubiquitous benign href fillers that show up in captured page snapshots
and analytics payloads.

**Fix spec (S-G).** Require `javascript:` in an executable/attribute context, not bare: e.g. attribute form
`(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:` OR `javascript:` immediately followed by a JS-exec
shape (`alert|eval|prompt|confirm|document\.|window\.|String\.fromCharCode|\(`). Exclude the inert
`javascript:void(0)` / `javascript:;` fillers. Plus S-B (beacon gate) for the 24 blob cases.

**Tests:** negatives for `javascript:void(0)`, `javascript:;`, and a beacon body; positives for
`href="javascript:alert(1)"`, `javascript:eval(...)` still fire.

---

## 2. Sprint plan, ordering, exit criteria

| Step | Work (§) | Blocking FPs killed (est.) | Risk |
|------|------|--:|--|
| **S-A** | §2a fast-path → high-specificity tokens (`${jndi`, drop `` ` ``/`$(`/`{{`/`<%`) | ~520 (cmdi 397 + sqli 149 share) | med — re-run beacon corpus + keep positive fixtures |
| **S-B** | §2b wire beacon gate into xss + ssrf body scans | ~24 xss + ssrf text/plain share | low |
| **S-C** | §2c mass-assign JSON value-context (truthy / escalating-role; drop `scope`) | ~252 | low |
| **S-D** | §2d ssrf userinfo: tighten class + require internal host | ~80 (userinfo share) | med — security posture, keep positives |
| **S-E** | §2e header-injection query CRLF requires header token | ~107+ | low (path scan untouched) |
| **S-F** | §2f recon: narrow `/debug/`, exclude `admin-ajax.php`, fix Docker `plugins` | ~382 noise (non-blocking) | low |
| **S-G** | §2g xss `javascript:` context | ~38 | low |

**Ordering rationale:** S-A first (biggest blocking payoff, shared root cause). S-B/S-C/S-E/S-G are independent
low-risk and parallelizable. S-D carries a security-posture change (do it deliberately, keep the internal-target
positives). S-F is cleanup (non-blocking but QC-visible).

**Exit criteria.** Re-run the corpus; target **enforced FP (normal blocked) materially below the prior 2.43%**,
with **no regression** in attack block-recall on healthy classes (xss/sqli/ssrf/path_traversal/log4shell). Each
fix lands with detector-level **negative fixtures for the exact captured shapes above** and **retains all existing
positive fixtures**. Run the full `aegis-security` lib suite green after each step (prior baseline: 1774 tests).

**Method:** detector-fixture loop (reproduce benign shape as a unit test → fix → green); corpus replay is the
final gate, not the dev loop. Do **not** blanket-disable any detector — narrow each so it fires on attack
*context*, not benign *shape* (the standing decision).

## 3. Risks / notes

- **S-A** is the load-bearing change: removing 1–2 char tokens from the beacon fast-path means a payload that is
  *both* single-dominant-blob *and* high-entropy *and* uses only `` ` ``/`$(` can be skipped. This is the
  documented S2 entropy-gate tradeoff and is acceptable — real injection in parseable form data is low-entropy /
  multi-field and never hits the gate. Keep `${jndi`, `/bin/`, `/etc/passwd`, `sh -c` on the fast-path so the
  high-value RCE shapes always re-admit.
- **S-C** credential/token keys: the captured FPs were role/scope/verified, not `access_token`-in-body. Keep
  token-key body matching for now; if a later run shows benign bodies legitimately carrying `access_token`
  *fields* (common in OAuth callback echoes), down-rank those to corroborating, per the same value-context idea.
- **S-D** posture: bare-userinfo-to-public-host stops being a solo-block. Document it — an operator who wants to
  flag *all* URL-userinfo can re-add a corroborating signal. Real userinfo-to-internal still hard-blocks.
- **S-F** recon is non-blocking; lowest urgency, but it pollutes per-IP cumulative risk and the audit log, so it
  is worth doing in the same pass while the shapes are fresh.
- **Boundary lens unchanged:** token/JWT/business-rule auth belongs in the gateway, not the WAF — this plan only
  narrows the WAF detectors to stop hard-403'ing first-party browser traffic.
