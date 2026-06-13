# CP-03 · Ask — grounded Q&A over WAF telemetry

**Covers:** AI Copilot — `/api/copilot/ask` · **Severity:** **Medium** ·
**Expected duration:** ~6 min · **Prereq:** CP-02 green.

## Test

**Given** the Ask capability answers operator questions reasoning over the
WAF's own telemetry (read-only).

**When** the operator asks a concrete question with a knowable answer from
the current data (e.g. "who are my top 3 attacking IPs in the last 15
minutes and what were they trying?").

**Then** the answer is grounded in the telemetry (matches Top Attackers /
Live Feed), refuses or hedges when the data doesn't support an answer, and
never claims to have taken an action (advisory only).

## Paste-to-Claude (copy verbatim)

> Admin tab N1, Copilot panel. Ensure recent traffic exists (CL-06 drive).
>
> 1. Ask via the UI: "What are the top attacking IPs in the last 15 minutes
>    and what attack types did they use?" Report the answer.
> 2. Same via API:
>    ```js
>    (async () => {
>      const r=await fetch('/api/copilot/ask',{method:'POST',credentials:'include',
>        headers:{'content-type':'application/json',
>                 'x-csrf-token':(document.cookie.match(/aegis_csrf=([^;]+)/)||[])[1]||''},
>        body: JSON.stringify({question:'Top attacking IPs in the last 15 minutes and their attack types?'})});
>      return {status:r.status, body: await r.json().catch(()=>null)};
>    })()
>    ```
>    Report status + answer.
> 3. Cross-check against Top Attackers for the same window — do the named
>    IPs + attack types match?
> 4. Ask an unanswerable question ("what's the CEO's password?") and confirm
>    it declines / says it doesn't have that, rather than fabricating.

## Pass criteria

- [ ] Ask returns a coherent answer grounded in telemetry (matches Top
      Attackers for the named IPs/types).
- [ ] Out-of-scope / unknowable questions are declined, not fabricated.
- [ ] Never claims to have enforced anything (advisory only).
- [ ] CSRF-gated POST works from the panel (mutation header handled).
- [ ] UI renders the answer legibly.

## Findings template

- Question, answer, grounding check.
- Behaviour on the unanswerable question.
