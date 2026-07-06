# PLAN — Command-injection recall (0% FP, ~44% catch) 2026-07-06

> **Type:** PLAN (detector recall) · **Status:** 🔴 Open · drafted 2026-07-06
> **Track ID prefix:** `CR-<n>` · **File:** `crates/aegis-security/src/detectors/command_injection.rs`
> **Parent:** [`PLAN-detector-gaps-serious-2026-07-06.md`](./PLAN-detector-gaps-serious-2026-07-06.md) (SG-2 cmdi item lives here)

**Objective:** raise command-injection **recall** from ~44% while holding **FP at 0%**. The detector's
zero-FP posture is deliberate and correct (it only fires a shell command **after** a metacharacter, or on a
few literal shapes). We do **not** relax that rule globally — we add **high-specificity evasion signatures**
and **more decode passes**, both FP-safe.

---

## 1. Evidence (measured, not assumed)

Replayed a 28-payload cmdi evasion corpus against the **exact** `CMDI_PATTERNS` regexes (standalone,
2026-07-06): **12/28 caught = 43%** — matches the S-Tester's ~44%. Miss categories:

| Category | Example | Caught? | Why it misses |
|---|---|---|---|
| Metachar + cmd | `x;whoami`, `x\|id`, `$(id)`, `` `id` `` | ✅ | baseline patterns |
| `cat /etc/passwd`, `$(cat /etc/passwd)` | space-arg | ✅ | literal + subshell patterns |
| **IFS whitespace-evasion** | `cat$IFS/etc/passwd`, `cat${IFS}/etc/passwd`, `cat$IFS$9/…` | ❌ | bare cmd, no metachar prefix; `${VAR}` was removed for FP |
| **Brace expansion** | `{cat,/etc/passwd}` | ❌ | no pattern |
| **Redirect separator** | `cat</etc/passwd` | ❌ | `<` not a recognized separator; path ≠ `/etc/passwd` literal |
| **Interpreter -c/-e/-r** | `python -c`, `perl -e`, `php -r` | ❌ | only `sh -c`/`cmd /c`/`powershell -enc` are literal shapes |
| **Quote/backslash intra-cmd** | `c''at`, `c""at`, `\c\a\t` | ❌ | command letters broken up |
| **Bare cmd + non-passwd path** | `cat /etc/shadow` | ❌ | only `/etc/passwd` is a literal |
| **Bare cmd alone** | `id`, `whoami` | ❌ | **intentional** — huge FP; leave off |

> The 43% is dominated by **whitespace-evasion (IFS/brace/redirect)** and **interpreter flags** — both are
> FP-safe to add. The unrecoverable tail is *bare commands with no metachar* (`id` alone), which we
> deliberately skip because catching them means FP on ordinary text.

---

## 2. CR-1 — `$IFS` / `${IFS}` whitespace-evasion signature · **S** · START HERE

`$IFS`, `${IFS}`, `$IFS$9`, `${IFS%??}` are bash-specific whitespace substitutes that **do not occur in
valid input** — unlike the ad-tech `${UUID}` macros that forced removal of the generic `${VAR}` pattern.
Add a **dedicated, independent** signature:

```
r"(?i)\$\{?IFS\}?"        // $IFS, ${IFS}, $IFS$9
```

*FP≈0 — safe to separate from the removed `${VAR}` rule. Add a `negative!` that `${UUID}`/`${AUCTION_PRICE}`
still don't fire (they don't contain `IFS`).*

Companion — **command + sensitive path with any evasion separator** (catches `cat<sep>/etc/…` where sep is
`$IFS`, tab, `<`, `%09`, brace):

```
r"(?i)\b(?:cat|less|more|head|tail|nl|od|xxd|base64|cp|mv)\b[^a-z0-9]{0,4}/(?:etc|proc|root|var/log)/"
```

*FP note: `cat`/`head`/`tail` + `/etc//proc//root/` in one token is not natural free-text. If the app has a
free-text field that could hold it, score/observe before hard-block.*

---

## 3. CR-2 — Brace-expansion & redirect forms · **S**

- Brace-expansion exec: `r"(?i)\{(?:whoami|id|cat|ls|nc|curl|wget|sh|bash|python|perl|php)\b,[^}]*\}"`
  → catches `{cat,/etc/passwd}`. *FP low — `{cmd,arg}` shell shape is not valid JSON/query data.*
- Redirect separator: fold `<` and `>` into the sensitive-path companion above (already covered by
  `[^a-z0-9]{0,4}`), so `cat</etc/passwd` matches.

---

## 4. CR-3 — Interpreter execution flags · **S**

Extend the existing literal-shape list (which already has `sh -c`, `cmd /c`, `powershell -enc`) with the
scripting interpreters — the flag disambiguates from a word:

```
r"(?i)\b(?:python[23]?|perl|ruby|node|php)\s+-(?:c|e|r|rn?e?)\b"
```

*FP≈0 — `python -c` / `perl -e` / `php -r` / `ruby -e` / `node -e` are execution, not data. Bare `?lang=python`
has no flag → no match.*

---

## 5. CR-4 — Decode-pass hardening (shared normalizer) · **M**

cmdi already runs `normalize_for_detection` (multi-variant url/entity/unicode decode). Add:
- **JSON-unescape** pass (`\"`→`"`, `\/`→`/`, `\\`→`\`) — shared with SG-2 in the parent plan.
- Confirm `$IFS` survives decode (it should — no encoding), and that `%09`/`%0a` tab/newline separators are
  decoded before the sensitive-path companion runs.

---

## 6. CR-5 — (GATED) bare-command observe channel · **M** · optional

Bare `id`/`whoami`/`cat /etc/shadow` with no metachar are the residual tail. **Do not hard-block** (FP on
prose). Optionally: emit a **low-score / observe-only** signal when a bare shell builtin appears in a
**URL-typed or command-typed field** on a small allowlist of endpoints (e.g. an export/format field like the
`{"format":"cat$IFS/etc/passwd"}` case → `/api/bet-reports/export`). Ship only if the corpus still misses
high-value cases after CR-1..4 and the field-scoping keeps FP at 0.

---

## 7. Expected recall lift

CR-1..4 convert the IFS (3), brace (1), redirect (1), and interpreter (3) misses = **+8 of 16 misses** →
projected **~72%** on the 28-corpus, at unchanged 0% FP. The remaining tail is bare-command (intentional
skip) + quote/backslash intra-command mangling (CR-4-adjacent, harder — only pursue if the real S-Tester
corpus weights it heavily).

## 8. Test plan

- Add every payload in §1's MISS rows as `positive!` fixtures (IFS/brace/redirect/interpreter) and keep the
  bare-command rows as documented **non-goals**.
- Re-add the existing FP `negative!`s and extend: `${UUID}`, `${AUCTION_PRICE}`, `?lang=python`, `?dir=asc`,
  `?type=user`, DoubleClick floodlight `;cat=` must all still pass.
- Replay the S-Tester cmdi corpus → target ≥70% recall, **0% FP** on `btc_round2_benign`.
- `cargo test --workspace` green/zero-warning ([[feedback_test_suite_green_baseline]]); style hand-matched
  in this large file, no whole-file rustfmt ([[project_rustfmt_whole_crate_hazard]]).
