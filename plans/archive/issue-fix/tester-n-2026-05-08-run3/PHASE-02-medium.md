# Phase 2 — MEDIUM (Run-3)

> **Branch:** all changes target `develop`.

---

## RUN3-NEW-2 · `GET /__waf_control/healthz` returns 404 on data plane

**Source:** Run-3 §NEW-2.

### Verified state (2026-05-08, on `develop`)

`crates/aegis-proxy/src/admin_dispatch.rs:699-755` dispatcher arms:

```rust
match (method, path.as_str()) {
    (hyper::Method::GET,  "/__waf_control/capabilities")     => { ... }
    (hyper::Method::POST, "/__waf_control/reset_state")      => { ... }
    (hyper::Method::POST, "/__waf_control/set_profile")      => { ... }
    (hyper::Method::POST, "/__waf_control/flush_cache")      => { ... }
    (hyper::Method::POST, "/__waf_control/challenge_verify") => { ... }
    _ => json_response(404, &serde_json::json!({"ok": false, "error": "unknown control endpoint"})),
}
```

No `healthz` arm. `GET /__waf_control/healthz` → 404. The QA Run-2 report's claim that this returned 200 was incorrect (likely a transcription mistake — the admin port's `/healthz/live` does return 200, but that's a different path on a different port).

The interop contract v2.3 §8 says the benchmarker polls "the configured health endpoint" — the path is operator-configured, not hard-coded to `/__waf_control/healthz`. So this isn't strictly a contract violation. But:

- Automated harnesses commonly probe `<base>/__waf_control/healthz` as the discoverable convention.
- It's a natural completion of the `/__waf_control/*` namespace.
- Adding it is a one-arm dispatcher edit.

### Plan

**Step 1 — add the dispatcher arm in `admin_dispatch.rs`.**

```rust
match (method, path.as_str()) {
    (hyper::Method::GET, "/__waf_control/capabilities") => { ... }
    (hyper::Method::GET, "/__waf_control/healthz") => {
        // 2026-05-08 RUN3-NEW-2 — liveness endpoint for the
        // automated interop harness. Returns 200 + minimal body
        // as soon as the data-plane dispatcher can respond.
        // Auth via X-Benchmark-Secret stays enforced (already
        // checked above before the match), so this isn't an
        // unauthenticated probe surface.
        //
        // Deeper readiness (Redis reachable, audit sink open,
        // upstream pools registered) lives at the admin port's
        // /healthz/ready — that endpoint exposes the actual
        // /api/state probes. This one is just "the WAF process
        // is alive and serving requests on this listener."
        json_body_response(
            200,
            serde_json::json!({"ok": true, "status": "alive"}).to_string(),
            "no-store",
        )
    }
    (hyper::Method::POST, "/__waf_control/reset_state") => { ... }
    ...
}
```

**Step 2 — extend the existing `/__waf_control/*` integration test** in `crates/aegis-proxy/tests/interop_data_plane.rs` (created during Run-1's C001 fix) with a healthz check:

```rust
#[tokio::test]
async fn waf_control_healthz_returns_200() {
    let app = boot_test_data_plane().await;
    let resp = app.get("/__waf_control/healthz")
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .send().await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], "alive");
}

#[tokio::test]
async fn waf_control_healthz_requires_secret() {
    let app = boot_test_data_plane().await;
    let resp = app.get("/__waf_control/healthz")
        .send().await; // no X-Benchmark-Secret
    assert_eq!(resp.status(), 403);
}
```

If the integration-test harness doesn't exist as a single file (it may be inlined in `admin_dispatch.rs` tests, given Run-1 didn't create the integration test in the end), add the test in the same place as the existing capabilities/reset_state arm tests so the shape is consistent.

**Step 3 — manual verification.**

```sh
make bench-dev   # in another terminal
SECRET="waf-hackathon-2026-ctrl"

curl -ks -H "X-Benchmark-Secret: $SECRET" "http://127.0.0.1:8080/__waf_control/healthz"
# Expect: {"ok":true,"status":"alive"}

curl -ks "http://127.0.0.1:8080/__waf_control/healthz"
# Expect: {"ok":false,"error":"missing or invalid X-Benchmark-Secret header"}

# Same on TLS data plane and admin port
curl -ksk -H "X-Benchmark-Secret: $SECRET" "https://127.0.0.1:8443/__waf_control/healthz"
curl -ksk -H "X-Benchmark-Secret: $SECRET" "https://127.0.0.1:9443/__waf_control/healthz"
```

**Step 4 — `STAGING-BENCHMARK.md` doc update.** Add `healthz` to the "v2.3 control surface" listing emitted by `make bench-dev`.

```diff
@@ Makefile bench-dev banner @@
   GET    /__waf_control/capabilities
+  GET    /__waf_control/healthz
   POST   /__waf_control/reset_state
   POST   /__waf_control/set_profile
   POST   /__waf_control/flush_cache
+  POST   /__waf_control/challenge_verify
```

(The `challenge_verify` line was added in Run-2 NEW-2 but never made it into the bench-dev banner — fold both updates here.)

### Acceptance

- [ ] `GET /__waf_control/healthz` with valid `X-Benchmark-Secret` → 200 `{"ok":true,"status":"alive"}` on `:8080`, `:8443`, `:9443`
- [ ] Without the secret → 403 (auth still enforced)
- [ ] Two new unit tests pass
- [ ] Bench-dev banner lists `healthz` + `challenge_verify` alongside the other control endpoints
- [ ] No regression in existing `/__waf_control/*` arms

**Effort:** ~30 min. One dispatcher arm + 2 tests + 4-line doc update.

---

## Sequencing

Single PR: `feat(interop): GET /__waf_control/healthz on data plane (RUN3-NEW-2)`.
