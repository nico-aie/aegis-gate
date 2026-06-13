# MT-02 · Downstream mTLS mode toggle is instant and validates

**Covers:** mTLS — downstream mode toggle (instant, commit `b94f93e`) +
config validation · **Severity:** **High** · **Expected duration:** ~6 min ·
**Prereq:** MT-01 green.

## Test

**Given** downstream config: `mode` ∈ {`disabled`,`optional`,`required`},
with a `ca_bundle` trust anchor, optional `allowed_sans`, and `apply_to`
planes. Validation rejects an unenforceable policy (`mode != disabled`
requires a `ca_bundle` **and** at least one `apply_to` plane). The toggle
was reworked to apply **instantly** (no stale UI).

**When** the operator flips the downstream mode on the Zero Trust page.

**Then** the change applies immediately (UI reflects the new mode with no
stale state / no full reload needed), and attempting `required`/`optional`
**without** a `ca_bundle` or `apply_to` is **rejected** with a clear error
rather than silently saving an unenforceable policy.

## Paste-to-Claude (copy verbatim)

> Admin tab N1, Zero Trust page, Downstream section.
>
> 1. Note the current downstream `mode`, `ca_bundle`, `allowed_sans`,
>    `apply_to`.
> 2. **Happy path toggle:** switch `mode` between `disabled` ⇄ `optional`
>    (only if a ca_bundle is configured). Tell me: did the UI update
>    instantly (no stale "old mode" showing, no manual reload), and what
>    toast appeared? Re-read the config via:
>    ```js
>    (async () => (await fetch('/api/zero-trust/upstream/config',{credentials:'include'})).json())()
>    ```
>    plus whatever downstream-config endpoint the page reads — confirm the
>    persisted mode matches the UI.
> 3. **Validation:** try to set `mode: required` with NO ca_bundle (or clear
>    apply_to). Report: is it rejected with a clear validation error, or did
>    it save an unenforceable policy?
> 4. Restore the original mode.

## Pass criteria

- [ ] Mode toggle applies **instantly** — UI never shows a stale mode and
      doesn't require a manual page reload (a stale toggle ⇒ regression of
      `b94f93e`, HIGH).
- [ ] Persisted config matches what the UI shows after the toggle.
- [ ] `required`/`optional` without ca_bundle or apply_to is **rejected**
      with a clear message (silently saving an unenforceable policy ⇒ HIGH).
- [ ] Original mode restored.

## Findings template

- Before/after mode; instant-apply confirmed?
- Validation behaviour for the bad config.
- Toast text + any stale-UI observation.
