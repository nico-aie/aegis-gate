---
id: 2026-05-17-ws-upstream-header-smuggling
date: 2026-05-17T00:00Z
severity: CRITICAL
area: data-plane · WebSocket
component: crates/aegis-proxy/src/proto/ws_forward.rs (read_response_head + UpstreamHandshake parsing)
interop_contract: Round 1 reverse-proxy fidelity · Round 2 attack containment
status: open
test_mode: source-review
---

# F-CRITICAL-010 · WebSocket upstream-handshake parser accepts `\n`-only line terminators and forwards arbitrary headers verbatim into the client 101 — smuggling vector

## Summary

The WebSocket-upgrade upstream-handshake parser at
`ws_forward.rs:129-222` reads the upstream's HTTP/1.1 response head
into a 16 KiB buffer, looks for the `\r\n\r\n` terminator, then splits
the head on `"\r\n"` to extract headers. The crucial split is
unconditionally on `\r\n` — but the per-header parsing does NOT
reject lines that end in `\n` alone, nor lines that contain CR/LF
embedded in a header value. After parsing, every header is
appended verbatim to the response builder and shipped back to the
client in the 101 Switching Protocols response.

A malicious upstream (e.g. one operating in a separate trust zone
behind the WAF that the operator nonetheless wants to expose via
WS) can craft a response head like:

```
HTTP/1.1 101 Switching Protocols\r\n
Sec-WebSocket-Accept: <valid>\r\n
X-Custom: harmless\nSet-Cookie: session=hijacked; Path=/\r\n
\r\n
```

The parser sees three logical headers (`Sec-WebSocket-Accept`,
`X-Custom`, blank-line terminator), parses `X-Custom` with value
`harmless\nSet-Cookie: session=hijacked; Path=/`. When the
constructed response is serialized by hyper to the wire, hyper may
emit the value as a single line — but on intermediaries that parse
the WAF→client byte stream (a downstream proxy, a logging
sidecar, or even some hyper versions / older clients) the embedded
`\n` is interpreted as a header boundary, smuggling the
`Set-Cookie` past the WAF.

## Observed code path

`crates/aegis-proxy/src/proto/ws_forward.rs:171-222` (paraphrased):

```rust
let head_str = std::str::from_utf8(&buf[..pos]).map_err(...)?;
let mut lines = head_str.split("\r\n");          // ← split is \r\n
let status_line = lines.next().ok_or(...)?;

for line in lines {
    if line.is_empty() {
        break;
    }
    let (name, value) = line.split_once(':').ok_or(...)?;
    let name = name.trim();
    let value = value.trim();
    headers.append(
        HeaderName::from_bytes(name.as_bytes()).map_err(...)?,
        HeaderValue::from_str(value).map_err(...)?,    // ← rejects \r, \n, \0
    );
}
```

Wait — `HeaderValue::from_str` DOES reject `\r\n\0`. Let me re-trace.

Re-reading: `HeaderValue::from_str` actually does check for `\r`,
`\n`, `\0`. But the agent's CRITICAL claim about `\n`-only being
accepted by `split("\r\n")` is correct: a string `"X-Custom: foo\nY: bar"` is **NOT split** by `split("\r\n")` because the
separator must be the literal two-char `\r\n`. So `\nY: bar` stays
INSIDE the value of `X-Custom`. THEN `HeaderValue::from_str(value)`
DOES reject the embedded `\n` and the whole line is rejected via
`.map_err(...)?` — the request fails closed.

Re-classified: **agent overstated the impact**. `HeaderValue::from_str`
DOES catch CRLF smuggling at the value boundary, so the worst case
is that the upstream handshake errors out (`502` returned to client
via the WAF's own error path — not a smuggling vector).

The remaining real issues are:

1. **The error path** at `ws_forward.rs:202` returns `Err(_)`
   which propagates to a 502 builder at `data_plane.rs:1086-1117`
   that classifies it as `DecisionTag::block("websocket_upstream_handshake_invalid")`.
   That's the wrong §3 action — it should be `circuit_breaker`
   (upstream-protection) per §3.1 ("Upstream degradation detected
   by WAF"). Filed separately as F-CONTRACT-001 below; that one is
   real.

2. **No length cap on individual header lines** within the 16 KiB
   total. An upstream returning one header with a 16 KiB value gets
   read into memory before validation fails. Trivial DoS on the
   parsing path. (filed in F-HIGH-protocol)

3. **No validation of upstream `Sec-WebSocket-Accept` against
   the client-sent `Sec-WebSocket-Key`** before responding 101 to
   the client — if the upstream returns a wrong Accept, the WAF
   blindly forwards it. The client then fails the handshake but
   the WAF has already accepted the upgrade. (filed in F-HIGH-protocol)

## Re-classification

After spot-verification, the original Agent-A finding (CRLF
smuggling via `\n` terminators) **does not exploit** because
`HeaderValue::from_str` catches the embedded control bytes at the
end of the chain. The realistic failure mode is denial-of-service
on the WS handshake path (upstream sends a malformed header → WAF
parser errors → 502 to client) plus the `block`-vs-`circuit_breaker`
contract gap.

**This file is therefore downgraded from CRITICAL to**:

- HIGH for unbounded individual-header-line buffering (already in
  F-HIGH-protocol).
- HIGH for missing `Sec-WebSocket-Accept` validation against the
  client's `Sec-WebSocket-Key` (already in F-HIGH-protocol).
- CONTRACT GAP §3 for wrong-action 502 on upstream handshake
  failure (in F-CONTRACT-GAPS.md).

The CRITICAL slot is therefore re-allocated to **the smuggling
risk that DOES land**: the WAF's request-side serialization at
[ws_forward.rs:107-112](aegis-gate/crates/aegis-proxy/src/proto/ws_forward.rs#L107-L112) that builds the upgrade request to the
upstream writes header values from `HeaderMap` verbatim. `HeaderMap`
values constructed by hyper are guaranteed to be free of CRLF, BUT
**operator-injected header policy values via
`transform/vars::expand_variables` are not run through this
validation if the variable-expansion ever sources from
attacker-controlled signals** (cookie / JWT claims / request
headers).

Today, the variable-expansion path doesn't feed WS upgrade request
construction — the comment at `ws_forward.rs:93-97` says so — so
this is fragile but not currently exploitable.

## Recommendation

Keep this finding open as a TRACKING item for the WS handshake
parser hardening. The real exploitable bugs are folded into
F-HIGH-protocol and F-CONTRACT-GAPS.md.

Recommended hardening regardless:

1. Bound individual header line length to e.g. 8 KiB and reject
   the upstream response if exceeded.
2. After reading the upstream `Sec-WebSocket-Accept`, recompute
   the expected value from the client `Sec-WebSocket-Key` and
   reject the handshake if mismatched. (Don't forward an upstream's
   wrong Accept to the client.)
3. Centralize all "header value built from a string we received
   over the wire" code through a single `safe_header_value()`
   helper that rejects controls and length-caps.

## Severity (final)

**HIGH** (downgraded after spot-verification). Title preserved in
the file name for the audit trail but the body reflects the
re-classification. Real impact is on the handshake-parsing DoS and
the §3 contract gap, both filed elsewhere.

Listed as #10 in the CRITICAL series because the original audit
agent classified it CRITICAL; this file documents the downgrade
rationale rather than silently dropping the finding.
