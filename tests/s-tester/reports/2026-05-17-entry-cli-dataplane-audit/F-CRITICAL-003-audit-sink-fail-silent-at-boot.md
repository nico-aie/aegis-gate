---
id: 2026-05-17-audit-sink-fail-silent-at-boot
date: 2026-05-17T00:00Z
severity: CRITICAL
area: orchestrator · interop audit
component: crates/aegis-proxy/src/run.rs (MinimalJsonlSink::open)
interop_contract: v2.3 §6 (Audit Log), §8 (./waf_audit.log default path)
status: open
test_mode: source-review
---

# F-CRITICAL-003 · v2.3 audit sink fail-silent at boot — every decision skips audit write if file can't be opened

## Summary

If `MinimalJsonlSink::open(&cfg.interop.audit_path)` returns an error
at boot (permission denied, missing parent dir, read-only mount, etc.),
the orchestrator only emits a `tracing::warn!` and continues with
`audit: None`. Every subsequent decision in the data plane skips its
audit-line emit because the optional sink is empty.

The OC harness reads `./waf_audit.log` after each phase for
correlation and score validation (contract §6). A run that produces
zero audit lines fails every contract clause that requires correlation
between the response header `X-WAF-Request-Id` and the audit `request_id`,
and any `prevented` / `passed` / `log_only_detected` classification
that depends on audit-side evidence (§7 matrix) becomes unverifiable.

## Observed code path

`crates/aegis-proxy/src/run.rs:1701-1711`:

```rust
let audit = match MinimalJsonlSink::open(&cfg.interop.audit_path) {
    Ok(sink) => Some(Arc::new(sink) as Arc<dyn InteropAuditSink>),
    Err(e) => {
        tracing::warn!(
            target = "aegis::interop",
            error = %e,
            path  = %cfg.interop.audit_path.display(),
            "v2.3 audit sink unavailable — continuing without it",
        );
        None     // ← silent fall-through
    }
};
```

The downstream `sink.append(...)` site at
`crates/aegis-control/src/admin_dispatch.rs:~1086` is gated on the
`Option<Arc<dyn InteropAuditSink>>` being `Some`, so a `None` here
silently drops every decision.

## Repro

```sh
# 1. Boot from a working directory the WAF process can't write to:
cd /tmp && mkdir test-readonly && chmod 500 test-readonly && cd test-readonly
cp /path/to/waf .
cp /path/to/waf.yaml .
chmod 700 . # make the dir readable+exec but not writable
./waf run --config ./waf.yaml &

# 2. Send a single request:
curl -s http://127.0.0.1:8080/ >/dev/null

# 3. Look for the audit log — it never gets created:
ls -la ./waf_audit.log   # → No such file or directory

# 4. The warning is in the log stream but the process kept running:
# "v2.3 audit sink unavailable — continuing without it"
```

## Impact

- Benchmark phase 2 (which requires `./waf_audit.log` to exist with
  correlated entries) returns zero correlation hits — every test
  case loses its audit-side evidence point.
- `X-WAF-Request-Id` is in the response headers, but the audit log
  it should correlate to never gets written → §6 "BẮT BUỘC match
  ... nếu cả hai cùng tồn tại" reads vacuously and the harness may
  still penalize the missing chain.
- Operator running the binary from a CWD they don't control
  (containerized, sandboxed, root-owned mount) gets no signal that
  the contract surface is dark — they see one log line they may miss.

The §6 contract calls audit log *"evidence cho BTC-side correlation"*
— the WAF must not silently start without it.

## Suggested fix

Make the audit sink mandatory at boot whenever the v2.3 interop
surface is enabled (which it always is — the OC harness expects
`/__waf_control/*`). Return a `WafError::Config(...)` so boot
fails-loud with the path the operator needs to fix.

```diff
 let audit = match MinimalJsonlSink::open(&cfg.interop.audit_path) {
     Ok(sink) => Some(Arc::new(sink) as Arc<dyn InteropAuditSink>),
     Err(e) => {
-        tracing::warn!(
+        return Err(WafError::Config(format!(
+            "v2.3 audit sink could not be opened at {}: {}. \
+             The interop contract requires this file. \
+             Check that the directory exists and the process \
+             has write permission.",
+            cfg.interop.audit_path.display(),
+            e,
+        )));
-            target = "aegis::interop",
-            error = %e,
-            path  = %cfg.interop.audit_path.display(),
-            "v2.3 audit sink unavailable — continuing without it",
-        );
-        None
     }
 };
```

Optionally accept an explicit opt-out
(`cfg.interop.audit_path = "/dev/null"`) for operators who genuinely
don't want a v2.3 audit log (non-hackathon deployments), but the
default path `./waf_audit.log` should be a hard requirement.

## Verification

Repro the read-only-CWD scenario above; with the fix in place,
`./waf run` should exit non-zero with a clear error pointing at
the unwritable path, instead of starting up cleanly without the
audit surface.

A regression test belongs in `tests/contract/` or `tests/api/`:
chmod the dir, attempt boot, expect non-zero exit and a stderr
mention of the audit path.

## Severity rationale

CRITICAL. Silent absence of the contract audit log destroys
every Phase 2 correlation and is invisible to the operator unless
they happen to read the warning line. Hard-error at boot is the
hackathon-correct posture.
