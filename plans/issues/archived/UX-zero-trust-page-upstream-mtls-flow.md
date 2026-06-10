# UX — Zero Trust page: per-upstream mTLS setup is supported but undiscoverable / no step guidance

- **Type:** UX / enhancement (not a functional bug — the API + config plane work; the
  **page doesn't make the workflow usable**).
- **Severity:** Medium — operators can't tell *what steps to take* to set up
  WAF→backend mTLS per upstream from the page, and the upload UI silently
  disappears under a server flag with no explanation. The capability exists but
  reads as "not supported."
- **Status:** ✅ resolved — UX pass shipped on branch `feat/zt-upstream-mtls-ux`
  (all six suggested improvements below implemented; frontend-only, no
  protocol/backend change).
- **Affects:** `crates/aegis-control/assets/dashboard/src/pages.jsx` — the
  Zero Trust page (`PageZeroTrust`, ~`:6683`) and its upstream cards
  (`ZtIdentityCard` `:6170`, `ZtTrustBundlesCard` `:6343`,
  `ZtUpstreamPoolsCard` `:6491`).

## Symptom (user-reported)
> "I understand we can upload and set up zero-trust (mTLS) info for each upstream
> on this page, but the UI looks like it doesn't support that and is hard to use —
> I don't know what steps to take."

## What the page actually does today (verified in code)
The page stacks four upstream cards with an uppercase section label but **no
ordering, prerequisites, or guidance**:

1. **`ZtIdentityCard`** — the shared WAF **client identity** (the cert every node
   presents to backends).
2. **`ZtTrustBundlesCard`** — named **backend-trust CA bundles** (to verify the
   backend's server cert).
3. **`ZtUpstreamPoolsCard`** — per-pool: a checkbox "Present WAF client cert +
   verify backend" + a "Backend trust" `<select>` of bundle names, then Save.
4. **`ZtUpstreamFailuresCard`** — read-only handshake-failure histogram.

There is a real **dependency chain** to enable mTLS for one upstream — but it's
only hinted in 11px grey text inside the per-pool drawer
(`:6614` "Enabling requires a configured WAF client identity. A bundle must be
uploaded above before it can be selected."):

```
(1) configure WAF Client Identity  →  (2) upload a backend-trust bundle  →
(3) open the pool's drawer, tick "Present WAF client cert + verify backend",
    pick the bundle, Save
```

## Root causes of the confusion

1. **Upload UI is gated behind a server capability and vanishes silently.**
   Both `ZtIdentityCard` and `ZtTrustBundlesCard` only render their upload
   controls when `allow_ca_upload` is true
   (`/api/zero-trust/downstream/ca-bundle/capability`, `:6175`/`:6347`). When the
   flag is **off**, the upload textareas/file inputs **don't render at all** and
   there's **no message** explaining why. The operator sees a read-only card and
   concludes "the UI doesn't support uploading." → This is the single biggest
   driver of "looks like not supported."

2. **No step-by-step / numbered flow.** The four cards are siblings with an
   uppercase label and nothing tying them together. There's no checklist,
   no "Step 1/2/3", no links from the per-pool drawer back to the
   identity/bundle cards that must be done first.

3. **The identity model isn't explained up front.** Upload is **reference-only**:
   the operator pastes the **PUBLIC** cert PEM + a `key_ref` (path or
   `${secret:…}`); the **private key must already exist on each node** as a file
   or secret (`:6318`). This is correct (the key never reaches the browser) but
   nothing on the card states it before the operator hunts for a key field.

4. **Inconsistent "applies when?" messaging.** Storing the identity toasts
   "stored in the config plane · **restart nodes to present it**" (`:6210`), yet
   the same card shows a "live · rotated ×N" hot-rotation pill (`:6252`) and the
   per-pool drawer says changes "activate fleet-wide via the config plane." The
   operator can't tell whether a restart is required.

5. **The per-pool Save isn't guarded by its prerequisites.** The drawer's Save is
   enabled even when **no identity is configured** and **no bundle exists**
   (`:6610`). Enabling then fails at apply time with a backend error instead of
   the UI proactively disabling Save with an inline "Configure WAF Client
   Identity first" / "Upload a trust bundle to select one."

6. **Empty states are dead ends.** "No upstream pools." / "not set" /
   "webpki roots" give no next action.

## Suggested improvements (UX pass — no protocol change)

1. **Make the workflow explicit.** Add a compact **"Set up upstream mTLS"
   stepper / checklist** at the top of the Upstream section that reflects live
   state: ① WAF Client Identity — `configured` / `not set`; ② Backend trust
   bundle — `N uploaded`; ③ Enable per pool. Each step links to / scrolls to its
   card. Steps 2–3 are visibly gated until step 1 is green.

2. **Never hide the upload silently.** When `allow_ca_upload` is false, still
   render the upload area but **disabled, with an inline note**: "Cert/bundle
   upload is disabled by server policy (`allow_ca_upload=false`). Provide the
   identity via `zero_trust.upstream_identity` in YAML, or enable uploads." Link
   to the config REFERENCE section.

3. **State the identity model before the inputs.** One line on `ZtIdentityCard`:
   "Paste the **public** cert chain + a **key reference**; the private key stays
   on each node and never reaches the browser." Label the `key_ref` field with an
   example.

4. **Guard the per-pool drawer.** Disable the "Present WAF client cert…"
   checkbox + Save when no identity is configured; disable the bundle `<select>`
   (already half-done via `opacity`) and show "Upload a trust bundle first" when
   the list is empty. Turn the 11px hint into an actionable inline banner with
   links.

5. **Unify the "applies when?" copy.** Pick one truth (hot-rotate live vs.
   restart-to-present) and say it consistently across the identity card toast,
   the rotation pill, and the per-pool drawer. If first-time set needs a restart
   but rotation is live, say exactly that.

6. **Actionable empty states.** "No upstream pools — add one on the Routing &
   Upstreams page" (link); "not set — add the WAF client identity to dial
   mTLS-required backends" (scroll to card).

## Acceptance
- A first-time operator can land on the Zero Trust page and, **without reading
  the code or docs**, tell (a) that per-upstream mTLS is supported here, (b) the
  ordered steps, and (c) why a control is disabled when it is.
- With `allow_ca_upload=false`, the page **explains** the YAML path instead of
  hiding the upload.
- The per-pool Save cannot be triggered into a guaranteed apply-time failure
  (identity/bundle prerequisites enforced in the UI).

## Related
- `plans/issues/archived/multi-node-consistency.md` (config-plane convergence — the same
  plane these mTLS changes ride).
- `docs/security/zero-trust-mtls.md` (feature spec; keep the "applies when?"
  wording in sync with whatever the UX pass settles on).
