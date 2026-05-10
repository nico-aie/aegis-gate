# Open-redirect detection

> **Status:** Implemented — `aegis-security/src/detectors/open_redirect.rs`. Run-5 GAP-009 (2026-05-09).
>
> See [`../../../plans/implementation-matrix.md`](../../../plans/implementation-matrix.md) for the full matrix.

## Purpose

Flag query parameters whose **name** is conventionally used for a post-action redirect (`?next=`, `?redirect=`, `?redirect_uri=`, `?return=`, `?goto=`, …) and whose **value** is an external URL the WAF doesn't recognise as a safe destination. Open redirect is a phishing / OAuth-token-theft / CSRF-bypass primitive — a vulnerable site that follows attacker-supplied URLs lets them craft links that look legitimate (`https://your-site.com/login?next=https://evil.com`) but land victims on attacker-controlled pages.

## Why a dedicated detector (not folded into `ssrf`)

SSRF and open redirect look syntactically similar — both feature URL-shaped values in query parameters — but have **opposite enforcement models**:

| | SSRF | Open redirect |
|---|---|---|
| Param shape | `?url=`, `?fetch=`, `?image_url=` | `?next=`, `?redirect_uri=`, `?return=` |
| Default policy | **Always block** external URLs (the WAF can't know which internal service is dangerous to fetch) | **Allow** external URLs to **operator-approved** destinations (legitimate OAuth callbacks land here) |
| Allowlist tier | Internal-only (per [SSRF doc](./ssrf.md)) — `loopback`, `private`, etc. | Operator-supplied — `cfg.detectors.open_redirect.allowed_domains` |

Folding into SSRF would force one of those policies onto the other. Splitting keeps both coherent + makes `set_profile { policies: ["open_redirect"], mode: "log_only" }` a single-target operator knob.

## Detection logic

1. Parse the query string into `(key, value)` pairs.
2. Match `key` (case-insensitive) against the **closed list** of conventional redirect-param names — `next`, `url`, `to`, `redirect`, `redirect_uri`, `redirect_url`, `return`, `return_to`, `return_url`, `rurl`, `destination`, `dest`, `goto`, `continue`, `forward`, `callback`, `checkout_url`, `image_url`, `domain`.
3. URL-decode `value` once. Apply the suspicious-shape regex set:

   | Pattern | Why dangerous |
   |---|---|
   | `^\s*https?://` | Absolute external URL with scheme |
   | `^\s*//\w` | Protocol-relative reference (`//evil.com`) — most browsers follow it |
   | `^\s*javascript\s*:` | XSS pivot via redirect |
   | `^\s*data\s*:` | HTML injection via redirect |
   | `^\s*(%2[fF])?(%2[fF])?(https?\|javascript\|data)\s*(%3[aA]\|:)` | URL-encoded scheme prefix (`%2F%2Fevil.com`, `%6A%61%76%61%73%63%72%69%70%74:` for `javascript:`) |

4. Extract the host from the value. If the host is on `cfg.detectors.open_redirect.allowed_domains` (literal or `*.example.com` glob), suppress the signal. `javascript:` and `data:` URLs have no parseable host — the allowlist can't suppress them, so they always flag.
5. Emit one signal per request — `Signal { score: 30, tag: "open_redirect", field: "uri" }`. Multiple matching params are collapsed into a single signal so a single redirect-probe shape doesn't artificially amplify risk.

## Score

**30** — phishing / OAuth-token-theft / CSRF-bypass tier.

| Score | Why this tier? |
|---|---|
| 30 | Open redirect's exploitability is real but **indirect** — it enables phishing and token theft, but isn't a direct compromise vector like sqli/cmdi. Pattern is heuristic (the URL **shape** is suspicious, not the URL **content**), so single hits shouldn't block. |
| Why not higher? | False-positive surface includes legitimate OAuth callbacks. Operators with dynamic redirect targets that change per partner can't realistically pre-populate every safe domain. Score 30 means a single hit doesn't reach `risk.thresholds.challenge_at: 40` — the signal accumulates only when the IP shows multiple suspicious behaviors (the right calibration for a phishing-class probe). |
| Why not lower? | Open redirect is the most common phishing-bootstrap primitive on auth-bearing sites. Below 30 it would be drowned by behaviour heuristics; at 30 it stacks meaningfully with `recon`, `xss`, or repeated `failed_auth` hits to push the IP into challenge / block territory. |

Operators who want stricter policy without losing the allowlist:
- raise the score in their per-detector rule (`PUT /api/rules` with `actions: [{ type: "raise_risk", delta: 25 }]` for the `open_redirect` rule),
- or move the global mode to `enforce` for this detector via `set_profile { policies: ["open_redirect"], mode: "enforce" }`.

## Allowlist behaviour

Empty `allowed_domains` (default) = **strict mode**. Every external `http(s)://` URL in a redirect param flags. This is the correct default for **first-time deployment** — operators get visibility into the redirect surface before tuning.

Populated allowlist — only off-list domains flag.

```yaml
detectors:
  open_redirect:
    enabled: true
    # Optional: hostnames considered safe redirect targets.
    # Empty = strict mode = flag every external http(s):// URL.
    allowed_domains:
      - "example.com"            # exact match, apex only
      - "*.example.com"           # subdomain wildcard
      - "accounts.google.com"     # OAuth provider
      - "login.microsoftonline.com"
```

Wildcard semantics:

| Entry | Matches | Does NOT match |
|---|---|---|
| `example.com` | `example.com` (exactly) | `foo.example.com`, `example.com.evil.com` |
| `*.example.com` | `foo.example.com`, `a.b.example.com` | `example.com` (apex), `evilexample.com` |

To allowlist both apex and subdomains, list both: `["example.com", "*.example.com"]`.

## Configuration

```yaml
detectors:
  open_redirect:
    enabled: true        # toggle the detector class on/off
    allowed_domains: []  # operator allowlist (literal or *.glob)
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | Audit-mutated; flips take effect within one hot-reload tick. |
| `allowed_domains` | list of strings | `[]` (strict) | Boot-time only — runtime allowlist updates require a restart. |

The class is hot-toggleable via `PUT /api/detectors` (the `open_redirect` field on the mask body) or via the v2.3 interop contract `set_profile { policies: ["open_redirect"], mode: "log_only" }`.

## Test corpus

Positive (should flag):

- `/login?next=http://evil.com`
- `/login?redirect=//evil.com`
- `/o?redirect_uri=javascript:alert(1)`
- `/o?redirect_uri=data:text/html,...`
- `/r?next=%2F%2Fevil.com` (URL-encoded protocol-relative)
- `/r?redirect=%6A%61%76%61%73%63%72%69%70%74:alert(1)` (URL-encoded `javascript:`)

Negative (must not flag):

- `/login?next=/dashboard` (relative path — same-origin redirect)
- `/login?next=` (empty)
- `/login?utm=campaign&id=42` (no redirect-style param)
- `/r?customParam=https://x.example` (param name not on the closed list)
- With allowlist `["example.com"]`: `/r?next=https://example.com/login`

See [`crates/aegis-security/src/detectors/open_redirect.rs`](../../../crates/aegis-security/src/detectors/open_redirect.rs)’s `tests` module for the full table (18 positives + 8 negatives + 6 allowlist).

## Cross-refs

- [`security-engine.md`](../security-engine.md) — risk-weight ladder + tag table.
- [`detectors/README.md`](./README.md) — detector index + tag catalogue.
- [`risk-scoring.md`](../risk-scoring.md) — how the 30 score interacts with `challenge_at` / `block_at` thresholds.
- [`tiered-protection.md`](../tiered-protection.md) — how this class participates in tiered enforcement.
