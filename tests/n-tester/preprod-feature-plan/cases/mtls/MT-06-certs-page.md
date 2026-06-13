# MT-06 · Certs page — list, expiry, upload backend CA / download WAF cert

**Covers:** mTLS — `/api/certs` + cert management controls · **Severity:** **Medium** ·
**Expected duration:** ~6 min · **Prereq:** MT-01 green.

## Test

**Given** cert material is managed via `/api/certs` and the Zero Trust /
Settings surface, with the two distinct upstream actions: **upload the
backend's CA** (the anchor the WAF verifies the backend against) and
**download the WAF's client cert** (the identity the backend verifies us
against).

**When** the operator opens the certs view, expands a cert, and exercises
the upload/download controls.

**Then** certs list with subject + expiry, near-expiry is visibly flagged,
expand shows detail, and the upload/download controls are correctly
labelled and functional (no mixing up the two directions).

## Paste-to-Claude (copy verbatim)

> Admin tab N1. Open the certs view (Zero Trust page and/or Settings →
> certs).
>
> 1. ```js
>    (async () => (await fetch('/api/certs',{credentials:'include'})).json())()
>    ```
>    Report the certs listed: subject/SAN, role (downstream CA / upstream CA
>    / WAF identity), and expiry.
> 2. Compare to the UI cert list — counts + expiry match? Is any near-expiry
>    cert visibly flagged?
> 3. Expand one cert row; confirm detail (issuer, SAN, validity) renders.
> 4. Identify the **upload backend CA** control and the **download WAF cert**
>    control. Confirm they are clearly distinguished (different keypairs,
>    opposite directions) and that download produces a cert file / PEM.
>    Do NOT upload anything destructive — just confirm the control opens a
>    file picker and the labelling is unambiguous.

## Pass criteria

- [ ] `/api/certs` rows match the UI list (subject, role, expiry).
- [ ] Near-expiry certs are visibly flagged.
- [ ] Cert detail expands and renders issuer/SAN/validity.
- [ ] Upload-backend-CA vs download-WAF-cert controls are clearly
      distinguished and functional (mislabelling them ⇒ MEDIUM, it's a
      documented source of operator confusion).
- [ ] No console errors.

## Findings template

- Certs listed (role + expiry) vs UI.
- Near-expiry flagging present?
- Upload/download control clarity + screenshot.
