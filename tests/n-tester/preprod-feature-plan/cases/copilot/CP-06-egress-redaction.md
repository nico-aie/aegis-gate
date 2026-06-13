# CP-06 · Egress redaction — no PII/secrets leave for the LLM

**Covers:** AI Copilot — mandatory egress gate (`redact_for_egress` →
`dlp::redact`) · contract §11 disclosure boundary · **Severity:** **High** ·
**Expected duration:** ~6 min · **Prereq:** CP-01 configured.

> Full verification is best done with provider-egress capture or a code/log
> review — the dashboard alone can't prove what left the process. This case
> does the **observable** part (the copilot's own output doesn't echo raw
> secrets) and flags the rest for a reviewer.

## Test

**Given** every byte sent to the LLM passes through `dlp::redact` first,
because WAF telemetry carries URIs / headers / payloads that may include
PII or secrets. This is the gating safety requirement for external egress.

**When** the operator drives traffic containing recognizable secret-shaped
tokens (fake API key, email, card-shaped number) through the LB, then asks
the copilot to summarize / answer over that window.

**Then** the copilot's **rendered output does not reproduce the raw
secret-shaped tokens** (they should be redacted/masked), and — for a fuller
check — the egress payload (if capturable via provider logs or a debug log)
shows redaction applied before send.

## Paste-to-Claude (copy verbatim)

> Data-plane tab on the LB. Use clearly-fake markers so they're easy to spot.
>
> 1. Drive traffic carrying fake secrets (these are bait, not real):
>    ```js
>    (async () => {
>      const baits=['/login?email=victim%40example.com&token=sk-FAKEKEY1234567890',
>                   '/pay?card=4111111111111111','/?apikey=AKIAFAKEEXAMPLEKEY'];
>      for (let i=0;i<9;i++) await fetch(baits[i%baits.length]+'&n='+i,
>        {headers:{'X-Forwarded-For':'198.51.100.40'}});
>      return 'bait sent';
>    })()
>    ```
> 2. On N1, request a summary and/or ask "summarize requests from
>    198.51.100.40". Read the copilot output carefully.
> 3. Report whether any of the raw bait tokens (`sk-FAKEKEY…`, the email,
>    `4111111111111111`, `AKIAFAKE…`) appear **verbatim** in the copilot
>    output. They should be masked/redacted or absent.

## Pass criteria

- [ ] No raw secret-shaped bait token appears verbatim in the copilot's
      rendered output (verbatim leak ⇒ HIGH, §11 disclosure boundary).
- [ ] Email / card / key-shaped values are masked or omitted.
- [ ] **Reviewer follow-up flagged:** confirm via provider egress capture or
      a debug log that `redact_for_egress` runs before send (file INFO with
      the action item — UI alone can't fully prove egress).

## Findings template

- Bait tokens used; any verbatim leak in output?
- Masking observed.
- Reviewer follow-up logged (egress capture / code path) — yes/no.
