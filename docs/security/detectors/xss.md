# XSS Detection

> **Status:** Implemented — `aegis-security/src/detectors/xss.rs`.
>
> See [`../../../plans/plan.md`](../../../plans/plan.md#1-doc-by-doc-implementation-status) for the full matrix.

## Purpose

Detect cross-site scripting attempts — attacker payloads that aim to inject JavaScript into pages viewed by other users. The WAF detects XSS in both inbound (attacker submitting payload) and outbound (payload reflected in response) directions.

## Detection strategy

Same layered approach as [SQLi detection](./sqli.md):

1. **Aho-Corasick literal matching** for common XSS tokens
2. **Regex matching** for structural patterns (tags, attributes, event handlers)
3. **Context scoring** — multiple signals combine

## Pattern categories

### Script injection

- `<script>`, `<script `, `</script>`
- `<svg onload=`
- `<iframe srcdoc=`
- `<img src=x onerror=`

### Event handlers

Regex: `on[a-z]+\s*=` — catches `onclick`, `onload`, `onerror`, `onfocus`, `onmouseover`, etc.

### JavaScript URIs

- `javascript:`, `JaVaScRiPt:`, `java\tscript:`
- `data:text/html`
- `vbscript:`

### DOM sinks in submitted content

- `document.cookie`
- `document.write`
- `eval(`
- `innerHTML`
- `setTimeout("`

### CSS injection (added 2026-06-16) — tag `css_injection`

CSS-injection payloads have a structural fingerprint the markup/script XSS
regexes never matched (0/300 on the hackathon `css_injection_samples`), so
CSS detection had been left entirely to the AI model (fragile, threshold-
sensitive). The detector now emits a distinct `css_injection` signal (same
score 70) on the decoded URI + body for:

- **`@import` of an external sheet** — `@import url(http…)`, `@import "http…"`
  (OOB / data exfil).
- **Resource-property exfil** — `content`/`src`/`cursor`/`background`/
  `behavior`/`-moz-binding` `: url(http…)`. Gated on `https?://`, so relative
  (`url(/img.png)`) and `data:` inline assets — normal CSS — never flag.
- **Attribute-selector exfil** — `[attr^="x"]{ … url( … )}`, which leaks one
  character per request through a background callback.
- **`<style>` breakout** — `</style><style>…`.
- **Obfuscation** — a control-byte deobfuscation pass strips null/CR/LF/tab
  so `htt\x00p://` and `@im\nport` (WAF-bypass variants) still match.

### Encoded variants

The detector normalizes input before matching:

- HTML entities: `&lt;`, `&#60;`, `&#x3c;`
- URL encoding: `%3C`, `%3c`
- Unicode escapes: `\u003c`
- Backslash escapes: `\x3c`
- Mixed case (matched case-insensitively for keywords)
- Whitespace tricks: `<scr\nipt>`, `<scr\0ipt>`

#### HTML-entity decode pre-pass (added 2026-05-09 GAP-012)

The pre-existing `&#x?[0-9a-f]+;` regex already matched numeric-entity literals, but **named-entity bypasses** (`&lt;script&gt;`, `&apos;onerror=…&apos;`, `javascript&colon;…`) slipped through because the named form has no digits. QA Run-6 reported this as an XSS coverage gap.

The fix is a narrow `html_entity_decode()` helper applied as a third decode stage on every surface (URI, body, headers): `raw → url_decode → html_entity_decode → regex`. The decoded string is run through the pattern set in addition to the URL-decoded form (when the two differ).

| Entity | Decodes to | Why XSS payloads use it |
|---|---|---|
| `&lt;`, `&gt;` | `<`, `>` | Tag delimiters — bypasses naive `<script>` substring filters |
| `&quot;`, `&apos;` | `"`, `'` | Attribute-value delimiters in event-handler injection |
| `&#NN;`, `&#xHH;` | UTF-8 char | Numeric form of any character |
| `&sol;` | `/` | Tag closing |
| `&colon;` | `:` | `javascript:` URI bypass |
| `&amp;` | `&` | Defense-in-depth for re-encoded chains |

The decoder is **not** a full HTML5 entity table — only the seven entities XSS payloads use to encode tag / attribute / URI delimiters. Named entities outside the table (e.g. `&copy;`) pass through unchanged so legit copy text isn't disturbed. The pre-filter (`if !input.contains('&')`) keeps the hot-path cost negligible — most production traffic never contains `&` at all.

### Angle-bracket injection

Raw `<` and `>` in parameters that shouldn't contain HTML raise a low-confidence signal. Combined with other signals, this becomes a detection.

## Surfaces

Inbound:

- Query parameters
- Request body (HTML-encoded-aware for form submissions)
- Headers commonly reflected in pages (`User-Agent`, `Referer`)
- Cookies

Outbound (optional, enabled per tier):

- Response body scanning for obvious reflected XSS (a parameter value appearing verbatim in an HTML response that also contains `<script>` tags)
- This is a secondary defense; primary defense is inbound blocking

## Scoring

Same structure as SQLi: additive scoring with a threshold. A full `<script>alert(1)</script>` scores immediately; fragments score lower and require confirmation.

## Configuration

```yaml
detection:
  xss:
    enabled: true
    sensitivity: high
    scan_response: false        # enable outbound scanning
    max_body_scan_bytes: 65536
    score_threshold: 20
    risk_increment: 40
```

## Outbound scanning caveats

Outbound XSS scanning is **disabled by default** because:

- It's expensive (scan every response body)
- False positives are common (legitimate content can look like XSS)
- Primary defense should be CSP headers and backend escaping

When enabled, the scanner looks for reflection: a query parameter value appearing in the response body near HTML-significant characters. This catches simple reflected XSS but not stored XSS.

## Actions

- Add `risk_increment` to risk score
- Audit log with the matched pattern and evidence
- Cache bypass
- Tier-dependent final action

## Implementation

- `src/detection/xss.rs` — pattern set, matcher, scorer

## Design notes

- The most impactful defense is blocking inbound payloads, so inbound scanning is always on
- CSP header enforcement (inserting or strengthening `Content-Security-Policy`) is a response-filtering concern, handled in [response filtering](../response-filtering.md)
