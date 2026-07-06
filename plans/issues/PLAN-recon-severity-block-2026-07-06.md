# PLAN — Recon-path coverage + severity-based blocking (S-Tester 2026-07-06)

> **Type:** PLAN (recon detector) · **Status:** 🔴 Open · drafted 2026-07-06
> **Track ID prefix:** `RB-<n>` · **File:** `crates/aegis-security/src/detectors/recon.rs`
> **Source:** `tests/s-tester/reports/2026-07-06/RECON_MISSED_report.md` + `recon_{CRITICAL,HIGH,MEDIUM,LOW}.json`
> **Related:** [[project_recon_canary_hardening_track]] (RC Wave A/B) · response leak → [`PLAN-response-filtering-dlp-2026-07-06.md`](./PLAN-response-filtering-dlp-2026-07-06.md)

**Objective:** the S-Tester replayed **1,650 distinct recon paths** the WAF caught with **no detector**
(round-1 only blocked via IP reputation → they slip on IP rotation). Some target files **exist and are served
200**, leaking real DB password + bcrypt hashes + secret keys (`/config.yaml`, `/.htaccess`, `/backup.sql.bak`).
Move recon from **name+extension exact-match** to **keyword/stem match**, and **score by severity so
CRITICAL/HIGH config/secret files are BLOCKED, not `allow`**.

> ⚠️ Two-layer defense: this plan is the **request-side block**; even if a request slips, the response filter
> must redact/deny the secret in the body → [`PLAN-response-filtering-dlp-2026-07-06.md`](./PLAN-response-filtering-dlp-2026-07-06.md).

---

## 1. Why it misses (verified against `recon.rs`)

1. **Name+extension exact-match, not keyword/stem** → catches `secrets.json` but misses `credentials.*`;
   catches `wp-config.txt` but misses `.ini/.json/.inc`; catches `phpinfo.php.backup` but misses bare
   `phpinfo` / `_profiler/phpinfo`.
2. **Dictionary gaps**: `credentials`, `mailjet/mailer_dsn/sendgrid/sparkpost/mandrill`, `aws_access_keys`,
   `.ftpconfig/sftp.json`, `ConnectionStrings`, `.properties`, `docker-compose`, `_profiler`, bare `phpinfo`.
3. **Score too low (~25 < block threshold)** → even a match only `allow`s; `/config.yaml`, `/.htaccess`,
   `/backup.sql.bak` fire recon-path but action=allow → file served.
4. **No path normalization** → `//wp-config.php` (double-slash), `%2e`/`%2f` encoded forms bypass.

---

## 2. Severity map (from the report; classifier is deterministic/replayable)

| Tier | Distinct | Content if served | Action target |
|---|---|---|---|
| 🔴 CRITICAL | 755 | `.env`, `.aws/credentials`, private keys, `wp-config.php`, mail-service keys, DB dump, connection strings | **BLOCK** |
| 🟠 HIGH | 307 | `.git`, `docker-compose`, CI/IaC, `config.*`, `.properties`, backup archives | **BLOCK** |
| 🟡 MEDIUM | 554 | `phpinfo`, `_profiler`, `/admin`, logs, `/vendor`, `xmlrpc` | **CHALLENGE** (block if strict) |
| ⚪ LOW | 34 | `.well-known/*`, `robots.txt`, `.env.example`, dir listings | **ALLOW** (allowlist — FP risk if blocked) |

---

## 3. RB-1 — Keyword/stem matching + path normalization · **M** · START HERE

- Match a sensitive **keyword anywhere in the normalized path**, regardless of prefix/dir/extension:
  `\.env`, `wp-config`, `credential`, `secret`, `apikey|api_key`, `aws`, `_profiler`, `phpinfo`,
  `docker-compose`, `\.git`, `backup`, `id_rsa|\.pem|\.p12|\.jks|\.keystore`,
  `sendgrid|sparkpost|mailjet|mandrill|mailgun`, `\.ftpconfig|sftp`, `connectionstrings`, `\.properties`,
  `settings\.py|application\.properties|web\.config`.
- **Broaden the config/secret extension set:** `.php .json .ya?ml .ini .env .conf .properties .inc .bak
  .old .save .swp .orig .copy .tar .gz .rar .sql .\d+`.
- **Normalize before match** (new): collapse `//`→`/`, percent-decode `%2e`/`%2f`, lowercase, strip repeated
  backup suffixes (`.bak.bak`, `~`). Reuse the normalizer from the parent detector plan where possible.

---

## 4. RB-2 — Severity-based scoring so CRITICAL/HIGH block · **M**

- Emit recon score **≥ the block threshold** for CRITICAL + HIGH stems (credential/config/backup files are
  **never** legitimately served) → hard 403, not `allow`.
- MEDIUM stems → **challenge** band (or block under a strict toggle).
- Keep existing recon accumulation for anything below (broad scanning still raises cumulative IP risk).
- Confirm the emitted score actually crosses the data-plane block gate (the report's #3 root cause was a
  fire-but-allow) — add a test asserting `/config.yaml` → **block**, not just a signal.

---

## 5. RB-3 — LOW allowlist (FP guard) · **S**

This is the highest FP-risk area — **allowlist, never flag**:
- `.well-known/*` (jwks.json, openid-configuration, apple-app-site-association — public by design),
  `robots.txt`, `sitemap.xml`, `favicon.ico`, `.env.example`/`.env-sample` (templates, no real secret).
- App-legitimate runtime config (e.g. `/config.js` frontend config) → explicit path allowlist if the app
  serves one (see the previously-separated `recon_excluded_static.json`).
- Recon stays **path-based only** → no risk of FP on valid POST bodies.

---

## 6. Priority & FP

| # | Track | Coverage | FP risk |
|---|---|---|---|
| 1 | RB-1 keyword/stem + normalize + broad ext | CRITICAL+HIGH bulk (1,062) | Very low (files not valid) |
| 2 | RB-2 severity scoring → block | stops serve of config/secret/backup | Low |
| 3 | RB-3 LOW allowlist | prevents over-block | — (guard) |
| 4 | MEDIUM challenge (phpinfo/profiler/admin) | 554 | Low–med (allowlist real admin) |

## 7. Test plan

- `python3 load_test/test_recon_detection.py --confirm` per tier (`--file recon_CRITICAL.json` etc.) →
  CRITICAL/HIGH ~100% **and blocked**, LOW still `allow`.
- Add Rust `recon.rs` fixtures: `positive!` for each stem family + block-band assertion for `/config.yaml`,
  `/.htaccess`, `/backup.sql.bak`; `negative!` for the LOW allowlist paths + double-slash normalization.
- **FP replay** on `btc_round2_benign` + `waf_allowed_api_normal` → no valid asset/endpoint blocked.
- Coordinate with [[project_recon_canary_hardening_track]] so RC Wave B corpus gate covers these.
