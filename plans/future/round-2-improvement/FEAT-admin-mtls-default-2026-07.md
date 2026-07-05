# FEAT — Admin-channel mTLS: wire it, then make it the default

> **Type:** FEAT (committee round-2 🔴1) · **Status:** ☐ Not started — planned 2026-07-04
> **Track ID prefix:** `MT-A<1–3>` · **Design context:** committee round-2 response
> ([COMMITTEE-ROUND2-response-2026-07-04.md](COMMITTEE-ROUND2-response-2026-07-04.md))
>
> ⚠️ **Supersedes a round-1 contract.** `[[project_admin_public_http_contract]]` and the guardrail
> notes in `admin-accounts-rbac-sso.md` / `FEAT-admin-accounts-p1-self-service-hardening.md` record
> the round-1 mandate of public plain-HTTP admin. Round 2 explicitly asks for admin mTLS by
> default. On owner confirmation, update those guardrails + the memory before starting.

**Objective (intent, not letter):** an unauthenticated party must not be able to *reach* the admin
channel — a valid client certificate is required before any HTTP is spoken. Password/TOTP/session
auth stays as the second, application-layer gate (defense in depth).

---

## 1. Verified current state (2026-07-04)

| Fact | Anchor |
| --- | --- |
| Admin listener binds `cfg.listeners.admin.bind`, default `127.0.0.1:9443` | `run.rs:2116`, `config.rs:6007-6009` |
| Optional **server-side TLS** exists: `admin.tls: Option<TlsConfig>` (default `None` = plain HTTP) | `config.rs:5994-5995`, `run.rs:2145-2199` |
| Admin acceptor is built **without client auth** (`build_hardened_server_config`) | `run.rs:2177-2185` |
| `zero_trust.downstream.apply_to` **defaults to `[Admin]`** in schema… | `config.rs:4299-4300, 4325-4336` |
| …but only the `Data` scope is ever consumed; `Admin` is matched **nowhere** | `run.rs:1195-1210` |
| Client-cert verifier builder already exists (used by data plane): `build_hardened_server_config_with_client_auth` (WebPkiClientVerifier, Optional/Required) | `listener/tls_policy.rs:89-148` |
| Hot-swappable `ClientTrustStore` is **already passed into the admin accept loop** — but only backs `/api/mtls/*` read APIs, not the acceptor | `run.rs:2245, 2283`, `accept.rs:383,1096` |
| Admin HTTP server: hyper `http1` + tokio-rustls; ALPN pinned `http/1.1` | `accept.rs:26,1645-1657,1730-1744`, `run.rs:2188` |

**Net:** this is a *wiring* plan. No new crates, no new crypto — the verifier, trust store, and
acceptor mechanics all ship today; the admin path just never calls them. The current state is
worse than the committee stated: configuring `zero_trust.downstream` with the (default!) `Admin`
scope silently does nothing on the admin listener.

## 2. Staging

### MT-A1 — consume the `Admin` scope (make configured mTLS real) · **S–M** · START HERE
- In the admin acceptor build (`run.rs:2153-2193`): when `zero_trust.downstream` is present,
  `mode != Disabled`, and `apply_to` contains `DownstreamMtlsScope::Admin`, build with
  `build_hardened_server_config_with_client_auth(resolver, min_version, &admin_client_trust, mode)`
  instead of the no-client-auth builder. Trust store is already in scope (`run.rs:2245`).
- `Required` → handshake without a valid client cert **fails**; `Optional` → cert verified when
  presented (migration mode).
- Honor `allowed_sans` on the admin path the same way the data plane does.
- **Config validation:** `zero_trust.downstream` with `Admin` in `apply_to` but `admin.tls` unset
  → boot-time validation error (mTLS over plain HTTP is incoherent). This closes today's
  silent-no-op trap.
- Structural guard test: assert `DownstreamMtlsScope::Admin` has a consumer (mirror the
  `apply_and_swap` guard pattern, `[[project_apply_and_swap_helper_guard]]`).

### MT-A2 — provisioning & operability · **M**
- `waf admin mtls bootstrap` CLI: generate a local admin CA + one operator client cert
  (PKCS#12/PEM out), print install instructions. Without this, "default on" is a lockout machine.
- Trust-store hot-swap already exists via `/api/mtls/*` — verify the admin acceptor picks up
  swapped anchors without restart (it should, `ClientTrustStore` is live); test it.
- Dashboard: surface admin-channel mTLS state (mode, CA fingerprint, SAN allowlist) on the
  Zero-Trust page; degraded-style banner when the admin channel is serving without mTLS.
- Docs: enrollment runbook incl. browser client-cert install; break-glass = loopback/SSH-tunnel
  (`[[project_control_plane_loopback_only]]` pattern) with `Optional` mode, never a bypass flag.

### MT-A3 — flip the default · **M** (the careful one — do LAST)
- Ship default config with `admin.tls` populated (bootstrap-generated self-signed server cert) and
  `zero_trust.downstream.mode: required` + `apply_to: [Admin]`.
- First-boot flow: if no CA/cert material exists, boot generates it (or refuses with a one-line
  `waf admin mtls bootstrap` instruction — owner decision point #2 in the response doc).
- Retire `AEGIS_INSECURE_COOKIES` from the default path (Secure cookies once admin is HTTPS).
- Dev/CI/bench fallout: Makefile `run-dev`, QUICKSTART, e2e/bench harness get an explicit
  dev-mode profile (`mode: disabled` clearly labeled) — same pattern as AA-P1d's test-hash split.

## 3. Tests (RED-first)

- Handshake with no client cert → rejected in `Required`, accepted in `Optional`/`Disabled`
  (raw TLS client, not a normalizing HTTP client — `[[project_hyper_normalizes_framing]]` lesson).
- Cert from an untrusted CA → rejected; valid CA but SAN not in `allowed_sans` → rejected.
- Trust-anchor hot-swap takes effect on next handshake without restart.
- Boot validation: `Admin` scope + no `admin.tls` → config error with actionable message.
- Existing plain-HTTP dev path still boots when zero_trust absent (until MT-A3 flips defaults).
- Guard test for scope consumption (MT-A1).

## 4. Risks

| Sev | Risk | Mitigation |
|---|---|---|
| HIGH | **Operator lockout** on default-flip (no cert installed) | MT-A3 last; bootstrap CLI first; loopback break-glass documented; `Optional` migration mode |
| MEDIUM | Round-1 contract conflict — committee may re-flip | Owner confirms supersession before MT-A1; keep plain-HTTP path behind explicit config, not deleted |
| MEDIUM | Dev/CI/bench breakage on default flip | explicit dev profile in same PR (mirrors AA-P1d approach) |
| LOW | MT-A1 regression on existing admin TLS | acceptor change is additive-branch; plain + server-TLS paths keep dedicated tests |

## 5. Acceptance

- [ ] MT-A1: certless connection to a `Required`-mode admin listener fails at handshake (committee's literal verification ask).
- [ ] MT-A1: silent no-op closed — `Admin` scope either works or fails validation loudly.
- [ ] MT-A2: bootstrap CLI + hot-swap verified + dashboard visibility + runbook.
- [ ] MT-A3: fresh default install serves admin only over mTLS; dev/CI/bench green.
- [ ] Round-1 guardrail notes + `project_admin_public_http_contract` memory updated.
