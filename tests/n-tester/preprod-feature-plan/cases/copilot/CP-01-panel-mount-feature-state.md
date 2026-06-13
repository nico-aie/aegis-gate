# CP-01 · Copilot panel mounts; feature-off state is clean (not a crash)

**Covers:** AI Copilot — dashboard panel + `--features llm` / provider gating ·
**Severity:** **High** · **Expected duration:** ~4 min · **Prereq:** a console open.

## Test

**Given** the Copilot is built behind `--features llm` and needs a provider
(Anthropic/OpenAI key). When configured, the dashboard shows a Copilot panel
backed by `/api/copilot/{summary,ask,suggestions}`. When not configured, the
panel must show a clear **disabled / feature-off** state — not an error
boundary or a crash.

**When** the operator opens the Copilot panel on each node.

**Then** either the panel is live (controls present) or it shows an honest
"copilot not configured" state. A crash / blank / red error is a finding.

## Paste-to-Claude (copy verbatim)

> Admin tab N1 = http://185.23.199.194:56243/. Find the **Copilot** panel
> (sidebar or a panel on Overview/Investigation).
>
> 1. Does it mount? Screenshot it. Is it live (has an Ask box / Summarize
>    button) or showing a "not configured / feature off" message?
> 2. Probe the endpoints to see whether the feature is on:
>    ```js
>    (async () => {
>      const g = async (p,opt={}) => { const r=await fetch(p,{credentials:'include',...opt});
>        return {p, status:r.status, body: await r.text().then(t=>t.slice(0,200))}; };
>      return [await g('/api/copilot/summary'),
>              await g('/api/copilot/suggestions')];
>    })()
>    ```
>    Report status + first 200 chars. A `Disabled`-type response (feature
>    off) is fine; a 500/stacktrace is not.
> 3. Repeat the panel check on N2 and N3 — note if copilot is configured on
>    some nodes but not others.

## Pass criteria

- [ ] Panel mounts on all three nodes — no error-boundary card.
- [ ] If unconfigured: a clear, honest disabled/feature-off message
      (INFO, expected — not a bug).
- [ ] If configured: live controls present (Ask / Summarize).
- [ ] Endpoints return a clean status (200, or a structured disabled
      response) — **never** a 500 / stacktrace (that's HIGH).
- [ ] Per-node config noted (copilot on vs off per node).

## Findings template

- Per-node: panel state + endpoint status.
- Screenshot names.
- Any crash / 500 vs clean disabled state.
