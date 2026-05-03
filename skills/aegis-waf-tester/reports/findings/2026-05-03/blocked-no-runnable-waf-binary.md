---
id: 2026-05-03-blocked-no-runnable-waf-binary
date: 2026-05-03T17:15Z
severity: HIGH
area: tooling
component: aegis-waf-tester / build
status: open
test_mode: smoke
---

# Smoke run blocked: pre-built `target/release/waf` is Mach-O, sandbox is Linux

## Summary
The aegis-waf-tester skill couldn't progress past pre-flight because
the only `waf` binary on disk is `target/release/waf`, built on macOS
(Mach-O 64-bit arm64), and the Cowork bash sandbox is Linux aarch64.
The binary refuses to exec — `./target/release/waf: 1: ...: not found
... Syntax error: Unterminated quoted string` — which is the kernel
bouncing the wrong-format ELF header. There's no Rust toolchain
inside the sandbox to rebuild for Linux, no `redis-server` binary
(Docker is unavailable, `apt-get install` fails with EACCES on the
dpkg lock), and the sandbox has no network bridge to the host's
loopback (no `host.docker.internal`, `/etc/hosts` only has
`127.0.0.1 localhost`), so even if the operator boots the WAF on
their Mac, my curl from inside the sandbox can't reach `:9443` /
`:8080`.

Net effect: the skill cannot run any of Phase 1–7 in execution
mode from a Cowork session unless either (a) the repo ships a
Linux-ELF `waf` binary in `target/release/`, or (b) the sandbox is
extended with a network bridge to the operator's host loopback.

## Repro
1. From a fresh Cowork session with the aegis-gate repo mounted:
   ```bash
   $ file /sessions/.../mnt/aegis-gate/target/release/waf
   target/release/waf: Mach-O 64-bit arm64 executable
   $ uname -a
   Linux claude 6.8.0-… aarch64 GNU/Linux
   ```
2. Try the skill's `start-waf.sh` helper:
   ```bash
   $ bash skills/aegis-waf-tester/scripts/start-waf.sh
   ==> Starting dev Redis
   FAIL: make redis-up returned non-zero.  Check Docker is running.
   ```
3. Try directly:
   ```bash
   $ ./target/release/waf run --config tests/hackathon/configs/bench.yaml
   ./target/release/waf: 1: ...: not found
   ./target/release/waf: 1: Syntax error: Unterminated quoted string
   ```
4. Confirm no host-loopback bridge:
   ```bash
   $ cat /etc/hosts
   127.0.0.1 localhost
   ::1 ip6-localhost ip6-loopback
   $ getent hosts host.docker.internal
   (no output)
   ```

## Expected
The skill's "Pre-flight before anything else" section should either
succeed, or its "If the WAF is down" branch should produce a
runnable WAF the curl-driven phases can hit on `127.0.0.1:9443` /
`:8080`.

## Actual
- Pre-flight: WAF DOWN, Redis DOWN, no listeners on any expected port.
- `start-waf.sh`: refuses at the `make redis-up` step (no Docker).
- Direct exec: fails because the binary is for the wrong OS.
- No fall-back path inside the sandbox can build a fresh Linux
  binary in any reasonable time (Cargo.lock is 5,139 lines / hundreds
  of crates; sandbox has 4 cores, 3.9 GB RAM, 2.3 GB free disk).
- No way to reach a WAF the operator boots on their Mac (no host
  bridge from the sandbox).

## Suggested fix
Three options, in increasing scope:

1. **Tooling, fastest.** Have CI publish a Linux-aarch64 ELF
   `waf` binary into a known path (e.g. `dist/linux-aarch64/waf`)
   so `start-waf.sh` can pick it up when `target/release/waf` is
   the wrong format. Detection logic in
   `skills/aegis-waf-tester/scripts/start-waf.sh` ~ line 38:
   ```bash
   if [[ ! -x ./target/release/waf ]] || ! head -c4 ./target/release/waf | od -c | grep -q ELF; then
     # try dist/linux-<arch>/waf, else build
   fi
   ```
2. **Skill change.** Document this constraint in the skill's
   "Setup — read this BEFORE running" so the operator knows up-front
   that Cowork sessions need the binary pre-built for Linux. Also
   teach `verify-waf-up.sh` to print the binary's `file(1)` output
   and bail early with a one-line operator-friendly message instead
   of dribbling out the wrong-format exec error.
3. **Sandbox change.** Plumb a host-loopback bridge into the
   Cowork bash sandbox (e.g. expose `host.docker.internal:host-gateway`
   like Docker Desktop does) so the operator can boot the WAF on
   their Mac and the skill can drive it from the sandbox. Bigger
   change, but it's what unlocks every "execute against my host
   service" workflow, not just this one.

## Severity rationale
HIGH, not CRITICAL. The WAF itself is fine — this is a tooling /
environment gap that prevents the QA skill from running in Cowork
mode at all. CRITICAL is reserved for security-vulnerability or
data-loss findings; this is "the test rig doesn't run." It's
not LOW because it stops every phase of the skill cold; an operator
who runs `/anthropic-skills:aegis-waf-tester` in Cowork today gets
zero execution-mode coverage.
