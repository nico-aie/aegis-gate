# F-CRITICAL-002 · AI detector threshold too low + observe mode removed

**Severity:** CRITICAL  
**Component:** `waf.yaml` (dev config), `crates/aegis-core/src/config.rs`, `crates/aegis-security/src/detectors/ai.rs`  
**Found:** 2026-05-07  

---

## Summary

The dev config sets `ai.confidence_threshold: 0.5`, but the ONNX model fires on approximately 77% of all traffic at this threshold — including health check endpoints, static assets, and clean API paths. The `mode: observe` safety field that would prevent enforcement during calibration has been removed from the codebase, leaving no way to run the AI detector without it enforcing blocks.

## Observed behaviour

```
GET /api/status   (clean, no attack indicators) → 403 (detector: ai)
GET /api/health   (clean)                       → 403 (detector: ai)
GET /favicon.ico  (clean)                       → 403 (detector: ai)
GET /static/app.js (clean)                      → 403 (detector: ai)
GET /api/list     (clean, legit Mozilla UA)     → 403 (detector: ai)
```

Performance page shows average block ratio **77.3%** over 24h — the overwhelming majority of that is AI false positives, not real attacks.

Health & SLOs page:  
- `data_plane_availability` SLO: **16.00%** — **0% error budget remaining**  
- 3 `DataPlaneAvailability` alerts firing (PAGE + 2 × TICKET)

## Root cause

`waf.yaml` (dev config):
```yaml
ai:
  enabled: true
  model_path: data/ai_model/waf_model.onnx
  confidence_threshold: 0.5   # code default is 0.85
```

`crates/aegis-core/src/config.rs` default:
```rust
fn default_ai_confidence_threshold() -> f32 { 0.85 }
```

The code default (0.85) is calibrated correctly. The dev config overrides it to 0.5, which the `Implement-Progress.md` itself notes "fires on ~68% of all traffic".

Additionally, the `mode: observe | enforce` fields that existed in earlier versions have been removed from `AiConfig`. There is no way to run the AI in observe-only mode (log without blocking) via config.

## Impact

- Legitimate health checks, static assets, and API paths are blocked.
- SLO error budget exhausted — SLO alerts firing permanently in dev.
- Makes it impossible to distinguish real AI detections from false positives in the audit log.
- Benchmark data is dominated by AI false positives, masking true WAF effectiveness.

## Recommended fix

1. **Immediate:** Change `waf.yaml` to use the correct calibrated threshold:
   ```yaml
   ai:
     confidence_threshold: 0.85
   ```

2. **Short-term:** Re-implement `mode: observe | enforce` in `AiConfig`:
   ```rust
   pub enum AiMode { Observe, Enforce }
   pub struct AiConfig {
       pub mode: AiMode,  // default: Observe during calibration
       pub confidence_threshold: f32,
       ...
   }
   ```
   When `mode: observe`, log the AI detection in audit fields but do not add it to the block decision.

3. **Dev default:** Change the dev config default mode to `observe` so new deployments don't immediately over-block.
