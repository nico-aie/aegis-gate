# PLAN — Response filtering / DLP hardening (S-Tester 2026-07-06)

> **Type:** PLAN (response filtering / DLP) · **Status:** 🔴 Open · drafted 2026-07-06
> **Track ID prefix:** `RF-<n>` · **Files:** `crates/aegis-security/src/response_filter.rs`, `dlp/mod.rs`, `detectors/egress_*.rs`, `pipeline.rs` (`on_body_frame`)
> **Source:** `SUSPICIOUS_200_{findings,malicious_findings}.json` + `RESPONSE_FILTERING_report.md`
> **Contract:** `Hackathon_Doc/EN_waf_interop_contract_v2.6.md` §5.2 (response MUST NOT contain secrets/credentials/tokens/stack traces) — **scored, mandatory feature.**
> **Root-cause sibling:** request-side block → [`PLAN-recon-severity-block-2026-07-06.md`](./PLAN-recon-severity-block-2026-07-06.md)

**Objective:** the origin serves **200** responses leaking real secrets with BTC scoring markers
(`__V22_ADMIN_ACL__`, `__V23_CONFIG_LEAK__`, …). The WAF's response filter passes **100% of them**. Close the
DLP gaps so credentials in JSON/YAML/SQL/.htaccess bodies are redacted or the response is denied — while
keeping FP low (redact the VALUE, don't nuke valid responses).

> ⚠️ **Defense-in-depth, not the root cause.** These are broken-access-control leaks — `/admin/dashboard`
> (no admin ACL) + recon files served 200. Fix **both** layers: block the request (sibling plan) **and**
> filter the response (this plan). Confirmed 2026-07-06: all 8 `/admin/dashboard` fields + the config/backup
> leaks pass current DLP (standalone pattern replay).

---

## 1. What leaks & why (verified against `dlp/mod.rs` + `response_filter.rs`)

| Leaked | Pattern that should catch it | Why it MISSES |
|---|---|---|
| `db_password: __V23_CONFIG_LEAK__` (YAML) | `env_secret` = `^KEY=VALUE$` | YAML uses `:` not `=` |
| `"db_user":"admin"` (JSON) | `env_secret` | JSON uses `:` + quoted key |
| `# SetEnv DB_PASS wafhack2026_staging` (.htaccess) | `env_secret` | space-separated, in a comment |
| `sk_live_wafhack2026_prod_key` | `stripe_key` = `sk_(live\|test)_[A-Za-z0-9]{24,}` | value has **underscores**; `[A-Za-z0-9]` run < 24 |
| bcrypt `$2b$12$…` | *(none)* | no password-hash pattern |
| `ssh-ed25519 AAAA…admin@novabet` | `pem_private_key` = `BEGIN … PRIVATE KEY` | SSH key ≠ PEM |
| `admin_secret`, `secret_key`, `db_host/db_name` (JSON) | *(none)* | no generic sensitive-JSON-field pattern |
| `db.internal.novabet.local` | `mask_internal_ips` | masks **IP literals only**, not hostnames |

Current DLP catches env-file `KEY=VALUE` + a few fixed-shape tokens (AKIA, `ghp_`, `xoxb`) but is **blind to
JSON/YAML/SQL/.htaccess** and lacks password-hash / SSH / internal-hostname / generic-secret-field coverage.
Also `egress_leak` runs **only on status ≥ 500**; every leak here is **200** → invisible.

---

## 2. RF-1 — Structural key-value secret detection (format-independent) · **M** · START HERE

Replace format-coupled `env_secret` with a **sensitive-key + any-separator** matcher across env / JSON / YAML /
htaccess. Sensitive key stems:
`password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential|db[_-]?pass|passphrase|client[_-]?secret`.

Three shapes, **redact the VALUE only** (keep structure → low FP):
- env / .htaccess: `^\s*KEY\s*=\s*VALUE`  and  `SetEnv\s+KEY\s+VALUE`
- JSON: `"KEY"\s*:\s*"VALUE"`
- YAML: `^\s*KEY\s*:\s*VALUE`

*FP guard: valid responses rarely return a field literally named `password`/`secret_key`/`db_pass` with a
value. If the app has benign fields (`password_hint_enabled`, `has_password`, `password_strength`) whose
values are bool/enum/number → **allowlist by key name**.*

---

## 3. RF-2 — Secret-shape dictionary · **S**

- **Password hashes:** bcrypt `\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}`, argon2 `\$argon2[id]{0,2}\$`,
  sha-crypt `\$6\$`, md5-crypt `\$1\$`.
- **SSH keys:** `ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,}`, `-----BEGIN OPENSSH PRIVATE KEY-----`.
- **Loosen `stripe_key`** to allow `_`: `sk_(?:live|test)_[A-Za-z0-9_]{16,}` (+ `pk_live_`, `rk_live_`);
  add Google `AIza[0-9A-Za-z_-]{35}`. Keep existing JWT/PEM/AKIA/GitHub/Slack.
  *FP≈0 — these shapes don't collide with ordinary data.*

---

## 4. RF-3 — Internal-hostname masking · **S**

Extend beyond `mask_internal_ips` (IP-only today) to mask internal **hostnames** and connection strings:
`[a-z0-9-]+\.(?:internal|local|svc|cluster\.local)\b`, `*.novabet.local`, and
`redis://|mongodb://|postgres://|mysql://` DSNs in the body → `[INTERNAL]`.
*FP guard: these suffixes are non-public; but keep it a **mask**, not a block, so a valid body that mentions
one still renders.*

---

## 5. RF-4 — Wire field-aware JSON masking into the body path · **S**

`response_filter.rs::mask_json_fields` **already exists** (recursive value-masking by key name) but its own
doc says pipeline wire-up is "a follow-up" — it is **not called from `on_body_frame`**, so it's dead today.
Wire it in for `application/json` bodies with a default denylist (`*secret*`, `*password*`, `*_key`, `db_*`,
`redis_*`, `ssh_*`, `token`, `credential`). Field-aware masking has **zero regex FP** on natural-language
bodies (it only touches listed keys' values) — the report explicitly endorses keeping it.

---

## 6. RF-5 — Scan 200 responses (perf-gated) · **M**

`egress_leak` / body scan currently runs 5xx-only → misses every 200 leak. Enable scanning on **200** but
**only when cheap**:
- (a) the request was already recon/suspicion-flagged, **OR**
- (b) content-type / extension is config/backup/sensitive (`json|yaml|sql|text|csv|html`, `.env/.yaml/.sql/.bak`),
  **OR** (c) the response body is small.
- Clean high-volume 200 JSON traffic → skip, as today. Measure overhead with `load_test/btc_load_test.py`,
  keep within SLA.

---

## 7. RF-6 — Block-on-leak for config/backup/admin · **M**

For config/backup/admin content (`.yaml/.env/.htaccess/.sql/.bak/backup`, or content-type `text/yaml`/
`application/sql`, or recon-flagged path) where the body contains a secret → **deny (403/empty)** rather than
line-by-line redact: these files should never be served even redacted. Pairs with the request-side recon
block (sibling plan) so the file is stopped before the origin in the first place.

---

## 8. Keep the good decisions

- **observe-before-redact** (`egress_sensitive.rs`) — keep.
- Card-PAN **density threshold** — keep (avoid FP on a single invoice PAN).
- `scrub_stack_traces` + internal-header strip — keep; extend frameworks (Ruby/PHP/.NET) if needed.
- Always **redact the value, don't delete the response** → app keeps working.

## 9. Priority & FP

| # | Track | Catches | FP risk | Effort |
|---|---|---|---|---|
| 1 | RF-1 structural key-value (JSON/YAML/env/htaccess) | config.yaml, .htaccess, admin/dashboard | Low | M |
| 2 | RF-2 secret-shapes (bcrypt/SSH/`sk_..._`) | backup.sql.bak, secret_key | Very low | S |
| 3 | RF-4 wire `mask_json_fields` | admin JSON fields | Very low | S |
| 4 | RF-3 internal-hostname mask | db.internal.novabet.local | Low | S |
| 5 | RF-5 scan 200 (perf-gated) | all 200-leaks | Low (if gated) | M |
| 6 | RF-6 block-on-leak config/backup | stop serving the file | Very low | M |

## 10. Test plan

- **Anti-leak:** replay the endpoints in both `SUSPICIOUS_200_*` files → body must contain **no** `__V22__`/
  `__V23__` marker; secrets → `[REDACTED]` or response denied. Assert on the raw upstream body via
  `Pipeline::on_body_frame` unit tests + a proxy integration test.
- **FP:** replay `btc_round2_benign` + valid app responses → no valid data redacted (balances, names, IDs).
- **Perf:** measure RF-5 overhead; confirm within SLA.
- `cargo test --workspace` green/zero-warning ([[feedback_test_suite_green_baseline]]); DLP tests live in
  `dlp/mod.rs` — extend that module's fixtures; hand-match style ([[project_rustfmt_whole_crate_hazard]]).
