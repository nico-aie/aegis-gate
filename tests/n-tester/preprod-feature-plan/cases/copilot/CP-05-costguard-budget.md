# CP-05 · CostGuard budget / rate limit degrades gracefully

**Covers:** AI Copilot — `CostGuard` (per-window token + request budget) ·
**Severity:** **Medium** · **Expected duration:** ~5 min ·
**Prereq:** CP-01 shows copilot configured.

## Test

**Given** a per-window budget (defaults: 200k tokens / 60 requests per
hour) so an idle copilot can't run up an LLM bill or hammer the provider.
Over-budget returns `BudgetExceeded` / `RateLimited`.

**When** the operator fires copilot requests rapidly past the request cap.

**Then** the copilot **refuses gracefully** — a clear "rate limited / budget
exceeded, try later" state in the UI — rather than crashing, hanging, or
silently spending. The WAF data plane is unaffected (copilot is off the hot path).

## Paste-to-Claude (copy verbatim)

> Admin tab N1, copilot configured. NOTE: this intentionally burns some
> budget — keep N modest.
>
> 1. Fire summary requests in a tight loop and watch for the budget/rate
>    response:
>    ```js
>    (async () => {
>      const out=[];
>      for (let i=0;i<12;i++){
>        const r=await fetch('/api/copilot/summary',{credentials:'include'});
>        out.push({i, status:r.status, body:(await r.text()).slice(0,120)});
>      }
>      return out;
>    })()
>    ```
>    Report where (if) responses switch to a rate-limited / budget-exceeded
>    state and what the message says.
> 2. In the UI, trigger Summarize a few more times quickly — does the panel
>    show a clear "rate limited / try again" state, or does it spin / error?
> 3. Sanity: from the data-plane tab, confirm normal traffic through the LB
>    still works (copilot pressure must not affect the data plane).

## Pass criteria

- [ ] Past the cap, the API returns a clear rate-limited / budget-exceeded
      response (not a 500, not a hang).
- [ ] The UI surfaces the limit gracefully ("try again later"), no crash.
- [ ] Data-plane traffic through the LB is unaffected (copilot is advisory /
      off the hot path).
- [ ] After the window, copilot recovers (spot-check later, optional).

## Findings template

- Index where rate-limit/budget kicked in + message.
- UI behaviour at the limit.
- Data-plane unaffected? (yes/no).
