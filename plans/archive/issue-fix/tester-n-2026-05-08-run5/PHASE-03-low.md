# Phase 3 — LOW residue (Run-5)

> **Branch:** all changes target `develop`. Three small extensions to existing detectors.

---

## GAP-002 · Path traversal evasion — extend `path_traversal.rs`

**Source:** Run-5 §GAP-002. QA missed: overlong UTF-8 (`%c0%af..%c0%af`), Docker socket path (`/var/run/docker.sock`).

### Verified state

`path_traversal.rs` already covers Windows backslash (`\..\`), URL-encoded backslash (`%5c`), single-encode `%2e%2e`, and double-encode `%252e%252e%252f`. The actual gap is overlong UTF-8 only.

### Detection logic

**Why these specific patterns:**

- **Overlong UTF-8** is RFC 3629-forbidden but still decoded by some legacy parsers (older Apache, some mod_perl handlers, certain Java URL canonicalizers). The byte sequences `%c0%ae` (overlong `.`), `%c0%af` (overlong `/`), `%c0%5c`/`%c1%9c` (overlong `\`) are unmistakably attack-shaped — there's no legitimate reason for a client to overlong-encode an ASCII character.
- **Docker socket path** (`/var/run/docker.sock`) is a filesystem destination that appears in exploitation chains where the WAF is asked to fetch / forward to the unix socket. Distinct from the Docker REST API recon (which catches `/v1.24/containers/json` URL paths) — this catches the literal socket path being smuggled through.

**Score: 45** (existing path_traversal score, unchanged). The new patterns are added to the existing pattern set; they share the existing tag and score because they're the same semantic class.

**Field tag:** `path_traversal` (existing).

### Plan

Add two patterns to `TRAVERSAL_PATTERNS`:

```rust
// Overlong UTF-8 encoding for `/` and `\`. RFC 3629 forbids
// these (any code point < 0x80 must be encoded in 1 byte),
// but legacy parsers + some app servers decode them — used
// to bypass naive prefix matching.
//   %c0%ae = overlong U+002E (`.`)
//   %c0%af = overlong U+002F (`/`)
//   %c0%5c = overlong U+005C (`\`)
//   %c1%9c = also overlong `\`
r"(?i)(?:%c0%ae){2,}",
r"(?i)%c0%af",
r"(?i)%c0%5c|%c1%9c",

// Docker socket path — unix-socket exposure attack target.
// Distinct from Docker REST API recon (caught by recon.rs):
// this catches the FILESYSTEM path appearing in path traversal
// or SSRF param values.
r"(?i)/var/run/docker\.sock\b",
```

**Tests:**
- Positive: `/?p=%c0%af..%c0%af..%c0%afetc%c0%afpasswd`, `/?p=%c0%ae%c0%ae/etc`, `/?file=/var/run/docker.sock`.
- Negative: `/api/v1/users` (legit `/v` shape, already negative-tested).

**Doc:** update `docs/security/detectors/path-traversal.md` with the overlong-UTF-8 pattern note.

### Acceptance

- [ ] Overlong UTF-8 traversal blocks
- [ ] Docker socket path triggers
- [ ] Existing path-traversal tests unaffected

**Effort:** ~15 min.

---

## GAP-004 · SSRF URL credentials — extend `ssrf.rs`

**Source:** Run-5 §GAP-004. QA missed: `http://user:pass@internal-host/`.

### Verified state

`ssrf.rs` patterns include `(?i)(?:file://)`, `(?i)(?:gopher://)`, etc., plus loopback IP forms. Userinfo (`user:pass@host`) bypasses naive hostname-only filters because parsers may interpret different ends of the URL.

### Detection logic

**Why catch userinfo specifically:** Some URL parsers split on the **first** `@` they see; others split on the **last** `@`. Attackers exploit this discrepancy:

```
http://[email protected]/path
```

A naive WAF that allowlists "evil.com" sees the URL "starts with `http://` and contains `evil.com`" → allows. The actual request fetches `internal-svc:8080/path` because the parser interprets `evil.com:8080@` as the userinfo, not the host.

The pattern `https?://[^@/\s]+@` matches **any** URL with userinfo. Legit use of HTTP basic-auth in URL form is rare in modern apps (deprecated since RFC 3986); when it does occur, it's typically in `Authorization` headers, not URL params. Flagging URL-userinfo as suspicious matches industry practice (Chrome warns / blocks; major WAFs flag).

**Why not match just internal IPs after the `@`:** That would be brittle — attackers can use DNS rebinding or direct hostnames. Catching the userinfo shape itself is the right hook because the parser-confusion vector applies regardless of destination.

**Score: 50** (existing ssrf score, unchanged). The userinfo pattern joins the existing SSRF pattern set; same class, same scoring tier.

**Field tag:** `ssrf` (existing).

### Plan

Add one pattern to `SSRF_PATTERNS`:

```rust
// SSRF via URL-userinfo. The `://[^@/]*@` shape catches
// http://user@host/, http://user:pass@host/, etc. Naive
// hostname-only allowlists check the wrong portion when
// the parser splits on `@`. Rare in legit traffic outside
// of basic-auth header content (we don't scan headers
// here — that's the auth header surface, separate detector).
r"(?i)https?://[^@/\s]+@",
```

Tag stays `ssrf`, score `50`.

**Tests:**
- Positive: `?url=http://user:pass@10.0.0.1/secret`, `?url=https://evil.com:80@internal-svc/`, `?u=http://x@127.0.0.1`.
- Negative: `?email=user@example.com` (no scheme), `?to=mailto:user@example.com` (mailto:, not http), `/oauth/callback?code=abc&user=fred` (no `@` in URL value).

**Doc:** update `docs/security/detectors/ssrf.md` with a "URL userinfo" subsection.

### Acceptance

- [ ] QA's `http://user:pass@host/` probe blocks
- [ ] `?email=user@example.com` doesn't FP

**Effort:** ~15 min.

---

## GAP-005 · X-Forwarded-Host residue — extend `xfh_is_suspicious`

**Source:** Run-5 §GAP-005. Run-4 SEC-L002 added keyword-based XFH detection; some shapes still pass (bare-internal-IP, attacker-domain without keyword).

### Verified state

`header_injection.rs::xfh_is_suspicious` flags:
- Control bytes (defense-in-depth)
- 3+ comma-separated hosts
- Attacker-keyword needles (`evil`, `attacker`, `malicious`, `phish`, `javascript:`, `data:`, `<>`, quotes) AND XFH ≠ Host

Cases that still pass:
- `X-Forwarded-Host: 127.0.0.1` (internal-IP poisoning, no keyword)
- `X-Forwarded-Host: 10.0.0.1` (RFC 1918 internal, no keyword)
- `X-Forwarded-Host: bad-domain.com` (mismatch + arbitrary domain — no keyword, no allowlist)

### Detection logic

**Why internal-IP literals specifically:** Legitimate proxy chains (load balancer → reverse proxy → app) almost always carry **public hostnames** in `X-Forwarded-Host`, not internal IPs. The whole point of XFH is to tell the app "what hostname did the client originally request?" — which is virtually always a public domain name.

When XFH carries an internal IP literal (`127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`, `169.254.x.x`, `::1`, `fe80::*`), the operator pattern is:
- Cache-key poisoning: attacker sets XFH to internal admin URL so the cache binds the response to that key
- Internal admin shape: attacker tells the app "you're being accessed via the internal admin hostname" to trigger admin-only code paths
- Host-allowlist bypass: app trusts XFH for "is this an internal call?" decisions

**Why not just block ALL XFH ≠ Host:** Many legit proxy chains do exactly that (Host = internal-svc:8080, XFH = api.example.com). Bare mismatch is too broad. Internal-IP-literal-in-XFH is the narrow shape with no legitimate use case.

**Why `xfh_is_internal_ip_literal` parses octets manually:** Standard library `IpAddr::from_str` handles arbitrary IPv6 forms but the helper here only needs to flag obvious-internal ranges. Manual octet parse is faster + clearer + reuses across IPv4 and IPv6 loopback.

**Score: 35** (existing header_injection score, unchanged). The internal-IP detection is added to the existing `xfh_is_suspicious` heuristic; emits the same signal shape as the keyword-based detection.

**Field tag:** `header_injection` with sub-field `x-forwarded-host` (existing).

### Plan

Extend the heuristic to add **internal-IP poisoning** detection. The "arbitrary domain mismatch" case stays unflagged by default — too FP-prone without an operator allowlist (which would be a feature-creep beyond this round).

```rust
// header_injection.rs xfh_is_suspicious additions:

fn xfh_is_suspicious(xfh: &str, host: &str) -> bool {
    if xfh.is_empty() {
        return false;
    }
    // ... existing control-byte + 3+ comma + keyword checks ...

    // GAP-005 (Run-5) — internal IP literal in XFH. A legitimate
    // proxy chain rarely sets XFH to an RFC 1918 / loopback IP;
    // attackers use this to poison cache keys for "this is the
    // canonical internal admin URL" or to bypass host-based ACLs.
    if xfh_is_internal_ip_literal(xfh.split(',').next().unwrap_or("").trim()) {
        return true;
    }

    // ... existing tail (mismatch + needle check) ...
    false
}

fn xfh_is_internal_ip_literal(s: &str) -> bool {
    // Strip optional :port suffix
    let host_only = s.rsplit_once(':').map(|(h, _)| h).unwrap_or(s);
    // IPv4 literal check: 4 octets, leading 10. / 127. /
    // 169.254. / 172.16-31. / 192.168.
    let parts: Vec<&str> = host_only.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        let octets: Vec<u8> = parts.iter().map(|p| p.parse().unwrap()).collect();
        return matches!(
            (octets[0], octets[1]),
            (10, _)
                | (127, _)
                | (169, 254)
                | (192, 168)
                | (172, 16..=31),
        );
    }
    // IPv6 loopback / link-local — quick string match.
    matches!(host_only, "::1" | "[::1]" | "fe80" | "[fe80")
        || host_only.starts_with("fe80:")
        || host_only.starts_with("[fe80:")
}
```

**Tests:**
- Positive: `XFH: 127.0.0.1`, `XFH: 10.0.0.1`, `XFH: 172.20.5.5:8080`, `XFH: 192.168.1.1`, `XFH: ::1`.
- Negative (matching legit Run-4 cases): `XFH: api.example.com` matching Host (allowed), 2-host comma chain (allowed).

**Doc:** update `docs/security/detectors/header-injection.md` "X-Forwarded-Host poisoning" subsection with the internal-IP row in the shape table.

### Acceptance

- [ ] XFH internal-IP literals (RFC 1918, loopback, link-local) flag
- [ ] Existing XFH tests still pass (Run-4 SEC-L002 cases unaffected)
- [ ] Doc subsection extended

**Effort:** ~30 min.

---

## Sequencing

Single bundled PR: `fix(detectors): traversal evasion + SSRF userinfo + XFH internal-IP (GAP-002 + GAP-004 + GAP-005)`. All three are pattern-extension on existing detectors, small surface, easy to review together.

---

## What this round does NOT solve

- **Open redirect with FQDN allowlist enforcement** beyond the operator-config knob proposed in Phase 2. If real-world FPs emerge, follow up with a `cfg.detectors.open_redirect.allowed_domains` schema.
- **Path normalization layer** for the path-traversal detector (would unify Windows vs URL vs UTF-8 encoding into a single canonical form before pattern matching). Phase 3 only adds the missing patterns; canonicalization is a refactor for later.
- **Strict XFH allowlist** (operator declares which XFH values are legit). Same trade-off as open redirect — feature-creep in this round.
