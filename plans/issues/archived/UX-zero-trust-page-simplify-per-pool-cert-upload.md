# UX — Zero Trust page: simplify the upstream section to per-pool cert upload + toggle

- **Type:** UX / refactor (frontend-first; reuses the existing config-plane
  storage — **no protocol change required** for the core ask).
- **Severity:** Medium — the page works but reads as cluttered and the core
  operator workflow (download the WAF cert, give each backend pool its cert,
  flip mTLS on/off) is spread across three sibling cards with an indirection
  (named global bundles) most operators don't need.
- **Status:** 🟡 open — proposed redesign, not yet implemented.
- **Reporter:** liud (2026-06-11).
- **Affects:** `crates/aegis-control/assets/dashboard/src/pages.jsx`
  - `PageZeroTrust` (`:6975`) — the page composition.
  - `ZtUpstreamStepper` (`:6269`) — the 3-step setup card.
  - `ZtIdentityCard` (`:6379`) — Step 1, WAF client identity + cert download.
  - `ZtTrustBundlesCard` (`:6575`) — **Step 2, to be removed.**
  - `ZtUpstreamPoolsCard` (`:6742`) — **Step 3, to be reworked into the core surface.**
  - `ZtUpstreamFailuresCard` (`:6925`) — keep (read-only diagnostics).
- **Backend touched (read-only confirms — already in place):**
  - `crates/aegis-control/src/api/zero_trust/mod.rs` — view shapes + validators.
  - `crates/aegis-proxy/src/admin_mutate.rs` — `handle_zt_upstream_trust_list`
    (`:1691`), `validate_pool_trust_bundles` (`:233`), identity/trust PUT/POST.
  - `crates/aegis-core/src/config.rs` — `UPSTREAM_IDENTITY_STATE_KEY`
    (`aegis:zt:upstream:identity`, `:2574`), `UPSTREAM_TRUST_STATE_PREFIX`
    (`aegis:zt:upstream:trust:`, `:2596`), `upstream_trust_state_key()` (`:2601`).

---

## Tóm tắt yêu cầu (VN)

> Trang **Zero Trust** đang gặp các vấn đề sau, cần plan để fix + upgrade:
>
> 1. **FE rối, layout chưa clean.** Nút *Download WAF cert* khó nhìn, một số mục
>    dư thừa không cần thiết.
> 2. **Bỏ hẳn Step 2 · Backend-CA Trust Bundles.**
> 3. **Làm lại Step 3 · Upstream mTLS by Pool.** Mục đích: list hết các pool ra;
>    mỗi pool có nút **upload cert** từ backend của họ → upload xong **lưu vào
>    Redis vĩnh viễn**; thêm **nút bật/tắt enable mTLS** cho từng pool (user bật
>    hoặc tắt tuỳ ý).
>
> Cốt lõi: (a) chỗ **download cert từ WAF**, (b) chỗ **upload cert cho mỗi
> backend pool** + (c) **button bật/tắt** cho từng pool.

The good news from the code audit: requirement (a) already exists
(`ZtIdentityCard.downloadCert`, `:6437`) and **"lưu vào Redis vĩnh viễn" is
already how storage works** — both the WAF identity and every uploaded cert are
persisted in the Redis config plane (`aegis:zt:upstream:*` keys), not in browser
memory. So this is mostly a **frontend restructure**, with one small
quality-of-life backend follow-up (auto-naming per-pool bundles). See
"Implementation notes" below.

---

## What the page does today (verified in code)

`PageZeroTrust` (`:6975`) stacks, under an *Upstream — WAF → backend* label:

1. `ZtUpstreamStepper` — a 3-step "Set up upstream mTLS" checklist card.
2. `ZtIdentityCard` (**Step 1**) — the shared fleet WAF client cert. Shows
   parsed metadata + a `Download WAF cert (public)` button (`:6511`), plus a
   reference-only upload (public cert PEM + `key_ref`) gated behind
   `allow_ca_upload`.
3. `ZtTrustBundlesCard` (**Step 2**) — upload/list/delete **named, global**
   backend-CA bundles, stored at `aegis:zt:upstream:trust:<name>`.
4. `ZtUpstreamPoolsCard` (**Step 3**) — per-pool drawer with a "Present WAF
   client cert + verify backend" checkbox and a `Backend trust` `<select>` that
   picks one of the **global** bundle names uploaded in Step 2, then Save.
5. `ZtUpstreamFailuresCard` — read-only handshake-failure histogram.

Then a second *Downstream — client → WAF* section (`MtlsModeCard`,
`MtlsCaBundleCard`, `MtlsSansCard`, `:7005`) — **out of scope here.**

The friction the reporter hit:

- The current model is **two-step indirection**: upload a *global named bundle*
  (Step 2) → then in each pool *select that name* (Step 3). Most operators think
  per backend ("this pool talks to this backend, here's its cert"), not in terms
  of a shared bundle library. The indirection is the "mục dư thừa".
- The `Download WAF cert` button sits **inside** the Step 1 metadata block,
  below subject/fingerprint/expiry rows, styled as a plain `.btn` — easy to miss
  ("khó nhìn").
- Three stacked cards + a stepper for what is conceptually "download one cert,
  upload one cert per pool, toggle" = visual clutter.

---

## Target design

### 1. Clean up the layout (req. 1)

- **Promote the WAF-cert download.** Pull `Download WAF cert (public)` out of the
  metadata sub-block into a clear, primary action in the Step 1 card head (or a
  dedicated "Your WAF certificate" strip at the top of the upstream section), so
  it's the obvious first thing an operator grabs to hand to their backend team.
  Keep the helper line ("install this in your backend's client-trust store; the
  private key never leaves the WAF").
- **Trim redundant copy.** With Step 2 gone and Step 3 reworked, collapse the
  3-step `ZtUpstreamStepper` (`:6269`) into a short 2-step hint (① your WAF cert
  ② per pool) or fold it into the section intro. Drop duplicate "applies when?"
  blurbs that now live in fewer places.
- Keep `ZtUpstreamFailuresCard` as-is (useful diagnostics).

### 2. Remove Step 2 entirely (req. 2)

- Delete `ZtTrustBundlesCard` (`:6575`) and its render in `PageZeroTrust`
  (`:6998`). Remove the `ZT_ANCHOR.bundles` jump links that point at it
  (`:6229`, `:6888`, `:6906`).
- **Do not** remove the backend trust storage/endpoints — they stay and get
  reused by the per-pool upload (below). Only the *standalone global card* goes.

### 3. Rework Step 3 into the core surface (req. 3)

A single table listing **every pool**, each row with:

- Pool name + current mTLS status pill (already there, `:6842`–`:6844`).
- An **enable/disable toggle** per pool — replaces the drawer checkbox; user can
  flip it any time (`:6870`). Disabling sets `upstream_mtls = null`; enabling
  sets `{ enabled: true, verify: true, trust: <pool's cert ref> }`. The existing
  whole-pool round-trip (`poolFormFromView` → `poolConfigFromForm` →
  `window.poolUpsert`, `:6776`–`:6788`) is reused unchanged.
- An **"Upload backend cert"** control per pool — the operator pastes/selects the
  PEM of the cert their backend presents (its server cert or issuing CA). On
  upload it is **persisted to Redis** and wired to *this* pool automatically (no
  separate "name your bundle, then select it" dance).
- Show the currently-pinned cert's subject/expiry inline (reuse `ZtExpiryPill`,
  `:6220`) so the operator can see what's pinned and when it expires.
- Keep the per-pool guard: enabling requires the WAF client identity (Step 1)
  to be configured — reuse the existing `identityReady` gate + inline banner
  (`:6811`, `:6860`) so Save can't be driven into a guaranteed apply-time
  failure.

---

## Implementation notes (how to reuse what's already there)

**Persistence is already permanent + Redis-backed — do not rebuild it.**
Uploaded certs already land in the config plane via
`POST /api/zero-trust/upstream/trust/{name}` and are read back by
`handle_zt_upstream_trust_list` (`admin_mutate.rs:1691`) under the
`aegis:zt:upstream:trust:` prefix. The config plane is the Redis-backed
`state_backend`. Nothing is browser-local.

**Per-pool upload = auto-named bundle, reusing the existing endpoint.** The
cleanest path with zero protocol change: when the operator uploads a cert on
pool `<P>`'s row, the FE

1. `POST /api/zero-trust/upstream/trust/pool-<P>` with the PEM (auto-derive a
   safe bundle name from the pool name — must match `is_valid_bundle_name`:
   `[A-Za-z0-9._-]`, ≤64, `zero_trust/mod.rs:168`; sanitize/truncate as needed),
   then
2. PUT the pool with `upstream_mtls.trust = "pool-<P>"` + `enabled: true`.

`validate_pool_trust_bundles` (`admin_mutate.rs:233`) already enforces that an
enabled pool's named trust exists in the config plane, so do step 1 **before**
step 2 to avoid the 400. This keeps the global-bundle storage but hides the
naming/indirection from the operator — exactly the simplification requested.

**Optional backend follow-up (nice-to-have, not required for the core ask):** if
the team prefers a cleaner model than auto-named bundles, add a dedicated
`PUT /api/zero-trust/upstream/pool/{pool}/trust` that stores the PEM and wires it
to the pool in one audited mutation. The existing two-call FE approach ships
without it; this only removes the orphaned-bundle edge case (see Risks).

**`allow_ca_upload` still gates uploads.** Per-pool upload must honor the same
capability flag the current cards check
(`/api/zero-trust/downstream/ca-bundle/capability`, `:6384`). When it's off,
keep the existing pattern: render the control disabled with the inline note
pointing at the YAML path (`<pool>.upstream_mtls.trust`) — never hide it
silently. (This was the fix shipped in the prior ZT UX pass; preserve it.)

---

## Risks / edge cases to handle

- **Orphaned bundles on pool delete / re-upload.** Auto-named `pool-<P>` bundles
  aren't garbage-collected if a pool is deleted or its cert replaced. On
  re-upload, overwrite the same key (idempotent). Consider cleaning up the
  `pool-<P>` key when a pool's mTLS is disabled *and* the operator confirms, or
  document the leftover. (The dedicated endpoint above removes this entirely.)
- **Name collisions** between an auto-named `pool-<P>` bundle and a
  hand-authored YAML bundle of the same name — prefix (`pool-`) reduces but
  doesn't eliminate this; validate and warn.
- **Pool names with characters outside `is_valid_bundle_name`.** Sanitize to a
  deterministic safe slug and surface the derived name to the operator.
- **`verify: true` is mandatory in P2** (`zero_trust/mod.rs:205`) — enabling
  always means mutual+verify; the toggle reflects that, no "auth without verify"
  option.

---

## Acceptance

- The upstream section reads as: **(a)** one prominent "download your WAF cert"
  action, **(b)** a single per-pool table where each pool has an inline cert
  upload and an on/off toggle. No standalone Backend-CA Trust Bundles card.
- Uploading a cert on a pool persists it to Redis (survives restart / visible on
  other nodes) and pins it to that pool without the operator naming or selecting
  a global bundle.
- Toggling a pool on/off works any time; turning off clears `upstream_mtls`;
  turning on is blocked with an inline reason until the WAF client identity
  (Step 1) is configured.
- With `allow_ca_upload=false`, per-pool upload is shown-but-disabled with the
  YAML-path explanation (not hidden).
- `ZtUpstreamFailuresCard` still renders.

---

## Related

- `plans/issues/archived/UX-zero-trust-page-upstream-mtls-flow.md` — the prior ZT
  UX pass that added the stepper, gates, and `allow_ca_upload` messaging. This
  issue **simplifies** that work (removes the global-bundle indirection); keep
  the guardrails it introduced (identity gate, never-hide-upload, unified
  "applies when?" copy).
- `docs/security/zero-trust-mtls.md` — feature spec; update the per-pool flow +
  remove the standalone trust-bundle step when this ships.
- `plans/issues/archived/multi-node-consistency.md` — the config plane these
  mutations ride for fleet convergence.
