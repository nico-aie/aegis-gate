# XSS Detection

## Purpose

Detect cross-site scripting attempts — attacker payloads that aim to inject JavaScript into pages viewed by other users. The WAF detects XSS in both inbound (attacker submitting payload) and outbound (payload reflected in response) directions.

## Detection strategy

Same layered approach as [SQLi detection](./detection-sqli.md):

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

### Encoded variants

The detector normalizes input before matching:

- HTML entities: `&lt;`, `&#60;`, `&#x3c;`
- URL encoding: `%3C`, `%3c`
- Unicode escapes: `\u003c`
- Backslash escapes: `\x3c`
- Mixed case (matched case-insensitively for keywords)
- Whitespace tricks: `<scr\nipt>`, `<scr\0ipt>`

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
- CSP header enforcement (inserting or strengthening `Content-Security-Policy`) is a response-filtering concern, handled in [response filtering](./response-filtering.md)
