# CP-02 · Situational summary produces a grounded brief

**Covers:** AI Copilot — situational summary (`/api/copilot/summary`) ·
**Severity:** **High** · **Expected duration:** ~6 min ·
**Prereq:** CP-01 shows copilot **configured**; some recent traffic
(run CL-06's attack drive first for signal).

## Test

**Given** the summary digests the last N minutes of telemetry (audit
events, risk buckets, detector-hit deltas, rate-limit/DDoS counters,
upstream health, RPS) into a short brief: headline + findings + suggested
next action. **Advisory only** — it reads telemetry, never mutates.

**When** the operator requests a summary after driving some attack traffic.

**Then** the brief is **grounded in the actual telemetry** (the attack types
/ IPs / targets it names match what the dashboard shows), structured
(headline + bullets + next action), and returns within a few seconds.

## Paste-to-Claude (copy verbatim)

> Prereq: drive some signal first (reuse CL-06 step 1 against the LB so
> there are real SQLi/XSS/path-traversal blocks). Then admin tab N1:
>
> 1. Trigger a summary from the UI (Summarize button) AND via API:
>    ```js
>    (async () => {
>      const t=performance.now();
>      const r=await fetch('/api/copilot/summary',{credentials:'include'});
>      return {status:r.status, ms:Math.round(performance.now()-t), body: await r.json().catch(()=>null)};
>    })()
>    ```
>    Report the brief text, the latency, and its structure (headline /
>    findings / suggested-action present?).
> 2. Cross-check the brief against the dashboard: do the attack types, top
>    IPs/ASNs, and target paths it mentions actually match Top Attackers /
>    Live Feed for the same window? Flag any **hallucinated** figure that
>    isn't backed by the telemetry.
> 3. Confirm the brief is framed as advisory (a *suggested* next action,
>    not "I have blocked X").

## Pass criteria

- [ ] Summary returns a structured brief (headline + findings + next action).
- [ ] Figures are **grounded** — attack classes / IPs / targets match the
      dashboard for the same window (a fabricated stat ⇒ HIGH).
- [ ] Latency is reasonable (seconds, not a 30 s hang).
- [ ] Framed as advisory; it never claims to have taken an enforcement action.
- [ ] UI renders the brief legibly (no raw JSON dumped into the panel).

## Findings template

- Brief text + structure.
- Grounding check: matched vs hallucinated figures.
- Latency; UI rendering quality.
