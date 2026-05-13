# Phase 3 — P3 (LOW + UX) Run-6

> **Branch:** `develop`. Two detector tweaks + two cosmetic UX nits. Bundle as one PR.

---

## GAP-012 · XSS HTML-entity decode pre-pass

**Source:** Run-6 §5 + §8 row 5.

### Verified state

`xss.rs` runs its regex set against the URI + URL-decoded URI + body + URL-decoded body. **HTML entities** (`&#60;`, `&lt;`, `&#x3c;`) are a separate decoding layer the detector doesn't apply. A payload like `&#60;script&#62;alert(1)&#60;/script&#62;` ships as ASCII text the XSS regexes don't recognize.

The threat: some app frameworks decode HTML entities before rendering (e.g. an admin tool that echoes user input through `innerHTML` on a page that itself has its values HTML-decoded by the templating layer). The attacker sends entity-encoded XSS that the framework decodes, leading to live `<script>` injection.

### Detection logic

**Why a pre-pass, not new patterns:** HTML entity decoding is a single normalisation step. Adding regex variants for every entity-encoded character would 4x the pattern count + slow the hot path. A small `html_entity_decode()` helper applied once per surface (URI, body) — same as the existing `url_decode()` helper — keeps the patterns clean.

**Decode scope (narrow):** only decode the entities that XSS payloads actually use:

- Numeric: `&#NN;` (decimal), `&#xHH;` (hex)
- Named: `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&amp;`, `&#0;` (null)

A full HTML5 entity table (3000+ entries) is overkill — XSS bypasses the parser, and the parser only does the canonical-XSS-relevant entities for the tags + script delimiters.

**Order of decoding:** URL-decode first (because XSS payloads often arrive as `%26%23%36%30%3B` for `&#60;` URL-encoded), then HTML-entity-decode the result. `url_decode → html_entity_decode → regex` — three calls per surface.

**Score: 35** (existing xss score, unchanged).

**Field tag:** `xss` (existing).

### Plan

New helper in `crates/aegis-security/src/detectors/mod.rs`:

```rust
/// Narrow HTML-entity decoder for XSS pattern normalization.
/// Handles `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&amp;`, numeric
/// `&#NN;` (decimal), and hex `&#xHH;`. NOT a full HTML5 entity
/// decoder — only the chars XSS payloads use.
pub(crate) fn html_entity_decode(input: &str) -> String {
    // Cheap pre-filter: bail before allocating if no `&` present.
    if !input.contains('&') {
        return input.to_string();
    }
    // ... implementation
}
```

In `xss.rs::inspect`:

```rust
let raw_uri = req.uri.to_string();
let url_decoded = super::url_decode(&raw_uri);
let entity_decoded = super::html_entity_decode(&url_decoded);
check_xss(&raw_uri, "uri", &mut signals);
check_xss(&url_decoded, "uri", &mut signals);
check_xss(&entity_decoded, "uri", &mut signals);
// (same shape for body)
```

The decoder is also useful elsewhere — `header_injection` and `path_traversal` may benefit, but expanding the scope is out of round (keep this focused on XSS to stay within the GAP-012 acceptance).

**Tests:**
- Positive: `?q=&#60;script&#62;alert(1)&#60;/script&#62;`, `?q=&#x3c;img+src=x+onerror=alert(1)&#x3e;`, `?q=&lt;svg+onload=alert(1)&gt;`, body `<input value="&#60;script&#62;...">`.
- Negative: `?q=Tom+%26+Jerry` (legitimate `&amp;` in user content), `?q=hello%20world&id=1` (URL-decoded but no entity content), bare `&` in CSS selectors.

**Doc:** update `docs/security/detectors/xss.md` — add a "Bypass: HTML-entity encoding" subsection.

### Acceptance

- [ ] 4+ entity-encoded XSS positive tests block
- [ ] `Tom & Jerry`-style FPs stay green (the regex still requires `<script>`-or-equivalent shape, even after entity decode)
- [ ] No regression on existing 50+ XSS tests
- [ ] Doc subsection added

**Effort:** ~30 min.

---

## GAP-013 · CMDi blind sleep / time-based primitive

**Source:** Run-6 §5 + §8 row 6.

### Verified state

`grep -E 'sleep|timeout' crates/aegis-security/src/detectors/command_injection.rs` — neither builtin appears in the shell-builtin allowlist. Current allowlists for `;cmd` / `|cmd` / `&&cmd`:

```
whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe
```

QA Run-6 corpus: `;sleep+5;echo+done` — no I/O builtin (`echo` isn't on our allowlist either since it has no exec impact), so the request slips through.

### Detection logic

**Why add `sleep` and `timeout`:** These are the canonical **blind-RCE primitives** — when an attacker has command injection but no output channel (the response is fixed, no SSRF echo), they verify exploitation by triggering a measurable delay. `sleep 5` makes the response take 5 s longer; `timeout 5 whoami` is the Windows equivalent. Catching them at the detector closes the blind-RCE bypass without false-positive risk because **no benign query string contains `;sleep N;`** or `|sleep N|`. The attacker shape requires the metacharacter prefix.

**Why also add `echo` cautiously:** `echo` is more common in legit contexts (logging output, debug strings), but in cmdi context it's used as a verification print after the actual exploit. We explicitly **don't** add `echo` to the allowlist — it's just a status carrier in the QA payload. The trigger is `sleep`/`timeout` after a metacharacter, which is what makes the blind shape detectable.

**Why not add bare time-based detection (response-latency analysis):** A "response took 5 s after this request" heuristic would be at the proxy level, not the detector level — much wider blast radius and FP-prone (slow upstream != attack). Keep the detection at the regex layer.

**Score:** `command_injection::BASELINE` (50, unchanged).

**Field tag:** `command_injection` (existing).

### Plan

Extend the three shell-builtin allowlists in `CMDI_PATTERNS` to include `sleep` and `timeout`:

```rust
// Pipe-to-shell-cmd
r"(?i)\|\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe|sleep\b|timeout\b)\b",
// Semicolon-shell-cmd
r"(?i);\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|sleep\b|timeout\b)\b",
// Logical-AND / logical-OR
r"(?i)(?:&&|\|\|)\s*(?:whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|sleep\b|timeout\b)\b",
```

**Tests:**
- Positive: `?x=a;sleep+5;b`, `?x=a|sleep 5`, `?x=a&&sleep 10`, `?x=test;timeout 5 whoami`.
- Negative: `?msg=I will sleep tonight`, `?action=sleep` (no metacharacter prefix), `?timeout=300` (URL param named timeout).

**Doc:** add a one-line note to `command-injection.md` mentioning blind-sleep / time-based RCE primitives.

### Acceptance

- [ ] 4+ blind-sleep positives block
- [ ] `?action=sleep` / `?timeout=300` stay green
- [ ] No regression on existing cmdi tests

**Effort:** ~10 min.

---

## UX S6 · Compliance mode badge

**Source:** Run-6 §4 + §8 row 7.

### Verified state

The Compliance page (`pages.jsx::CompliancePage`) renders the active modes (PCI/HIPAA/etc.) and pinned classes, but the **enforcement state** (`enforce` / `log_only`) is sourced from `/api/mode` and rendered as a UI toggle on the Settings page only. The Compliance page doesn't surface it.

A SOC analyst on call who lands on the Compliance page can't tell at a glance whether the WAF is actively blocking or just logging.

### Plan

Add a small badge to the Compliance page heading mirroring the existing `mode pill` (already used elsewhere). Source the value from `/api/mode` (already polled by the SPA via `useApi('/api/mode', ...)`).

Sketch (pages.jsx):

```jsx
<div className="page-head">
  <h1 className="page-title">
    Compliance Profile
    <ComplianceModeBadge />
  </h1>
  ...
</div>

function ComplianceModeBadge() {
  const mode = window.useApi
    ? window.useApi('/api/mode', { intervalMs: 5000, fallback: { mode: 'enforce' } })
    : { data: { mode: 'enforce' } };
  const m = mode.data?.mode || 'enforce';
  const cls = m === 'enforce' ? 'pill ok' : 'pill warn';
  return (
    <span className={cls} style={{ marginLeft: 12, fontSize: 11 }} title={`WAF is currently ${m}`}>
      {m === 'enforce' ? 'ENFORCING' : 'LOG-ONLY'}
    </span>
  );
}
```

Repeat the same badge on Settings → Mode card if it's not already present.

**Tests:** dashboard_polish.rs already pins the bundle-budget assertion — the new component will add ~150 bytes (well within 400 KB).

**Doc:** none needed — the badge is self-documenting.

### Acceptance

- [ ] Compliance page heading shows `ENFORCING` (green) or `LOG-ONLY` (yellow) reflecting `/api/mode`
- [ ] Toggling mode via `set_profile` flips the badge within one poll tick (5 s)
- [ ] No bundle-budget regression

**Effort:** ~20 min.

---

## UX S5 · Detector class names visible

**Source:** Run-6 §4 + §8 row 8.

### Verified state

Run-5 follow-up #293 already added the chip grid — every detector class renders as a button labeled `sqli`, `xss`, etc. inside `DetectorMaskCard`. This row was originally a P4 nit; verify it's actually surfacing the names readably and only adjust if a SOC analyst would still miss them.

### Plan

1. Open the live dashboard, navigate to Detectors page, screenshot the chip grid + score panel.
2. If class names are visible AND the tag list (e.g. `sqli · 40`, `body_oversize · 30`) appears in the score panel, this is **already done** — close the row in the QA-report follow-up note.
3. If anything's hidden behind a hover or tooltip without a baseline visible label, add a permanent label.

Acceptance is a screenshot + a one-line update in the QA-report follow-up note.

**Effort:** ~10 min (mostly verification).

---

## Sequencing

Single bundled PR: `fix(detectors+ui): XSS entity decode + cmdi blind sleep + compliance mode badge (GAP-012 + GAP-013 + UX S6)`. The XSS + CMDi work is detector-level; the compliance badge is dashboard-only — bundling cuts review overhead since both touch only test files + small surfaces.

The UX S5 verification is a docs-only follow-up; tracked but doesn't gate this PR.

---

## What this round does NOT solve

- **GAP-014 (XXE billion-laughs DoS)** — DoS pattern, not injection. Tracked separately for the hardening backlog.
- **Bare `/metrics` recon** — operator-hosted endpoint by deliberate design. Documented in Phase 2's recon doc update.
- **GAP-003 (waf.yaml stale AI config)** — QA reported as "status unknown, not re-tested." If it surfaces in Run-7, batch with that round.
- **Generic time-based response-latency analysis** — would require proxy-level instrumentation, out of scope for Run-6.
