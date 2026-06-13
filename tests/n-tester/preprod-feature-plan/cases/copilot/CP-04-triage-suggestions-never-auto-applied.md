# CP-04 · Smart-catch triage suggests a rule but NEVER auto-applies it

**Covers:** AI Copilot — triage suggestions (`/api/copilot/suggestions`) +
the advisory/human-in-the-loop guarantee · **Severity:** **Critical**
(auto-applying a rule would be a security/authority violation) ·
**Expected duration:** ~7 min · **Prereq:** CP-02 green; clustered/borderline traffic.

## Test

**Given** the copilot clusters borderline/noisy events and **suggests** a
candidate rule in the existing DSL that the operator can **preview** via
`POST /api/rules/simulate` and then promote. It is **never auto-applied**.

**When** the operator requests suggestions and inspects the flow.

**Then** suggestions appear with a rule preview + a simulate/preview action,
the rule is **not** active until the operator explicitly promotes it
(verify via `/api/rules` before/after), and promotion is CSRF-gated.

## Paste-to-Claude (copy verbatim)

> Admin tab N1, Copilot panel. Drive some clustered borderline traffic first
> (e.g. many requests from a /24 with a crafted Referer / rotating UA via
> the LB), then:
>
> 1. Snapshot active rules BEFORE:
>    ```js
>    (async () => (await fetch('/api/rules',{credentials:'include'})).json())()
>    ```
>    Record the rule ids.
> 2. Request suggestions:
>    ```js
>    (async () => {
>      const r=await fetch('/api/copilot/suggestions',{credentials:'include'});
>      return {status:r.status, body: await r.json().catch(()=>null)};
>    })()
>    ```
>    Report the suggested rule(s) + any campaign clustering.
> 3. In the UI, find a suggestion. Confirm it offers a **Preview / Simulate**
>    (not an instant Apply), and that previewing calls
>    `/api/rules/simulate` (a dry run), not a live PUT.
> 4. Snapshot `/api/rules` AGAIN (without promoting) — confirm the rule set
>    is **unchanged** (the suggestion did NOT auto-apply).
> 5. (Optional) Promote one suggestion explicitly and confirm it then
>    appears in `/api/rules`, and that promotion required a CSRF token.

## Pass criteria

- [ ] Suggestions return candidate rule(s) in the DSL, ideally clustered
      into named campaigns.
- [ ] The UI exposes **Preview/Simulate**, not a one-click silent apply.
- [ ] `/api/rules` is **identical** before vs after requesting/viewing
      suggestions — **nothing auto-applied** (any auto-applied rule ⇒
      CRITICAL: violates the advisory-only guarantee).
- [ ] Explicit promotion (if tested) is CSRF-gated and only then mutates rules.

## Findings template

- Rule ids before/after (must match until explicit promote).
- Suggestion content + simulate path used.
- Any evidence of auto-application (→ CRITICAL).
