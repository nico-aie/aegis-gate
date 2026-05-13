# Audit Checklist — Per Module

Work through this list for every source file you read. Not every item
applies to every file — use judgment. The goal is to catch problems a
human reviewer would catch on a careful second read.

---

## A. Entry points and wiring

- [ ] Does `main.rs` / the binary entry-point wire the **real** implementation
      of every critical trait, not a Noop/Stub version?
- [ ] Are background tasks (timers, watchers, renewal loops) properly
      `spawn`ed or `await`ed, not just constructed and dropped?
- [ ] Is every feature-gated module reachable via at least one compile
      path that gets included in the release binary?
- [ ] Do `Default` implementations produce sensible production defaults,
      or do they silently enable/disable security-critical behaviour?

## B. Security controls

- [ ] **CAPTCHA / challenge**: Does the verification function make a real
      HTTP call to the third-party endpoint, or does it unconditionally
      return success?
- [ ] **JWT / token auth**: Is the signature bytes actually verified against
      a key, or are they read into a variable and ignored?
- [ ] **Signature / HMAC**: Is the MAC computed over the correct inputs?
      Is the comparison timing-safe (`constant_time_eq`)?
- [ ] **Nonce / replay protection**: Is the nonce generated once and stored
      as the same value, or generated twice at different instants (race)?
- [ ] **Rate limiting**: Does the rate-limit action actually call the state
      backend, or does it block 100% / allow 100% unconditionally?
- [ ] **CIDR matching**: Are CIDR ranges matched with a network-contains
      check, or with an exact string comparison?

## C. Request pipeline wiring

- [ ] Does the inbound pipeline call every registered detector?
- [ ] Does the response pipeline call DLP / body scanners?
- [ ] Are detectors that are fully implemented in their own modules
      actually called from the pipeline entrypoint?
- [ ] Is there a short-circuit path that skips the entire pipeline
      (e.g. Noop trait, feature flag, load-mode bypass) that is
      accidentally the default?

## D. Config / validation gaps

- [ ] Does a config value that passes schema validation always work at
      runtime, or can it crash / 502 on first use?
- [ ] Are all variants of a config enum handled in every match arm
      (no silent fall-through to wrong default)?
- [ ] Are reconcile / replica modes that are documented but unimplemented
      returning clear errors at config-load time rather than at
      request time?

## E. Stub and TODO patterns

Look for all of these patterns — each is a potential finding:

```rust
todo!()
unimplemented!()
panic!("not implemented")
panic!("stub")
// TODO:
// FIXME:
// stub
// Phase N work
Ok(true)  // without any logic above it
Ok(false) // without any logic above it
return false // as the entire function body
```

Also look for:
- `#[allow(dead_code)]` on a public function or whole module
- `let _foo = expensive_computation();` — result discarded intentionally
- Mutex/buffer fields that are only ever written to, never read or flushed

## F. Algorithm correctness

- [ ] **Load balancers**: Random-selection algorithms should use a proper
      RNG, not a deterministic counter. Consistent hashing should use
      a ring structure, not modulo.
- [ ] **Hashing**: Does the algorithm match the documented spec?
      (e.g. JA3 requires MD5, not blake3)
- [ ] **Encryption / obfuscation**: Is FPE using a proper FF1
      implementation, not XOR or Caesar cipher?
- [ ] **Caching**: Are TTLs actually applied to cache entries (not
      discarded via `let _ttl = ...`)? Is the cache actually
      consulted in the hot path?

## G. Data persistence and delivery

- [ ] Do audit sinks (Splunk, Kafka, Syslog, etc.) make real network
      calls, or buffer events in-memory and never flush?
- [ ] Does the rule store / config store persist to disk or a real
      backend, or is it in-memory only (lost on restart)?
- [ ] Do analytics / metrics endpoints query real counters, or always
      return `0` / placeholder data?

## H. Operator safety

- [ ] Does a bulk-mode change (e.g. `set_all(mode)`) preserve existing
      fine-grained overrides, or silently wipe them?
- [ ] Does a password / credential rotation invalidate all existing
      sessions, or leave stale sessions valid?
- [ ] Are compliance profiles enforced at the detector/runtime level,
      or only stored as intent without runtime effect?

## I. Cross-crate contracts

- [ ] Does every response shape match the interop contract document
      (field names, types, required/optional)?
- [ ] Are required observability headers emitted on every response?
- [ ] Does the `x-waf-rule-id` header carry the expected prefix format?

---

## Severity mapping guide

| What you found | Default severity |
|----------------|-----------------|
| CAPTCHA / JWT / signature stub that always passes | **Critical** |
| Pipeline that skips all detectors (Noop or disconnected) | **Critical** |
| Binary entry-point wiring Noop instead of real impl | **Critical** |
| Config option that crashes process at boot | **High** |
| Config option silently ignored at runtime | **High** or **Medium** (based on importance) |
| Audit sink that drops all events | **High** |
| Algorithm produces wrong results (CIDR match, hashing) | **High** |
| Background task dropped immediately (never runs) | **High** if security-relevant, **Medium** otherwise |
| In-memory-only store (lost on restart) | **Medium** |
| Analytics / metrics always return 0 | **Medium** |
| Dead code with `#[allow(dead_code)]` | **Low** |
| Minor doc / default mismatch | **Low** |
