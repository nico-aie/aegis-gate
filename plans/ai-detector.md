# AI-T — ML-based Detector Integration

> **Status:** design-only, ready to implement. Track ID prefix
> `AI-T<n>`. Adds an ONNX-runtime-backed multi-class detector
> alongside the existing regex/heuristic detectors. Built on
> the dataset + model documented at
> [`data/ai_model/WAF_DATASET_REPORT_VI.md`](../data/ai_model/WAF_DATASET_REPORT_VI.md):
> 11-class classifier, 36.8 MB ONNX, 4,600 req/s @ batch=1 in
> Rust, p99 0.5 ms.

## 0 · One-line summary

Plug the trained ONNX model into the existing `Detector` trait
as a regular detector (`AiDetector`) — Cargo-feature gated,
runtime-config gated, per-tier gated, with a confidence
threshold and a strict CPU/latency budget that surfaces in
metrics so operators can revert with one config flip.

## 1 · Why this design (vs. alternatives)

Three integration shapes considered:

| Approach | Verdict |
|---|---|
| **A. AiDetector as a regular `Detector` impl** | **Pick.** Zero new control plumbing — already-built tier mask, audit, rate-limit, hot-reload all work. Operator turns it on/off via the same `/api/detectors` UI as any other class. |
| **B. Parallel "ML decision pipeline" alongside the detector chain** | Reject. Doubles the per-request branch cost; needs new `mask` semantics; new admin endpoints. ~3× the integration LOC for no functional gain — a detector IS already "thing that returns a verdict on a request". |
| **C. Async background scoring (queue + workers)** | Reject for v1. Adds queueing latency, complicates audit timing. May make sense as a follow-up for batch-only operators (e.g. monthly retraining feedback loop), but not the hot path. |

## 2 · The on/off matrix (key requirement)

Five independent levels, finest to coarsest:

| Level | Knob | Granularity | Restart? | Notes |
|---|---|---|---|---|
| 1 | **Cargo feature `ai`** | compile-time | yes (rebuild) | Off → no `tract` dep, no 37 MB model bytes, no AiDetector trait impl. Slim images stay slim. |
| 2 | **Config `ai.enabled: bool`** | per-deployment | no (hot-reload) | When false, the boot path skips loading the model; AiDetector returns `mask::Off` semantics. |
| 3 | **Per-tier scope `ai.tiers: [critical, high]`** | per-route via tier | no (hot-reload) | Inference only runs on requests resolving to listed tiers. Default: `[critical, high]` — Tier-Lite skipped to save CPU on bulk traffic. |
| 4 | **Detector mask `/api/detectors`** | per-class runtime | no (live) | Existing UI; `ai_*` rule_ids muted via `mute_class("ai_injection")` etc. Same plumbing as muting `sqli`. |
| 5 | **Confidence threshold `ai.confidence_threshold: 0.85`** | per-deployment | no (hot-reload) | Predictions below threshold → no-op (don't override regex detector verdicts on low-confidence calls). |

**Default deployment:** Cargo feature off. Operators flip
`FEATURES="redis geoip ai"` at build time + `ai.enabled: true`
in YAML. Two flips between "no AI in the binary" and "AI live
on all critical routes" — symmetric off → on and on → off.

## 3 · Performance budget (key requirement)

From the dataset report's measured numbers:
- **batch=1 latency:** Rust p99 0.5 ms, mean ~0.2 ms
- **throughput:** 4,600 req/s @ batch=1 single-threaded
- **model size:** 36.8 MB on disk

Targets the AI integration must hit:

| Metric | Budget | Enforcement |
|---|---|---|
| Per-request added latency | ≤ 1 ms p99 | `inference_latency_ms` histogram; SLO alert if p99 > 1 ms for 5 min |
| Per-request added latency | ≤ 5 ms hard cap | `tokio::time::timeout(5ms)` around `tract.run()`; on timeout → fall back to regex detectors only, increment `ai_inference_timeout_total` |
| CPU at 5k RPS | ≤ 30% of one core | metrics + load test |
| Boot-time cost | Model loads in < 500 ms | benchmarked at boot; if > 500 ms log a warning |
| Model file footprint | ≤ 50 MB | dataset report says 36.8 MB; +13 MB headroom |

**Cold-start mitigation:** model loads at boot, not first
request. The boot path's `AiDetector::new()` runs `tract`'s
graph optimization once and caches the optimized model.

**No batching in v1:** WAF is request-scoped; queueing for a
batch adds latency that exceeds the per-batch saving from the
report's 13,860 req/s figure. Single-request inference is the
right model.

**Per-IP cache:** small LRU keyed on `(method, path, body_hash)`
to dedupe identical requests in a tight window. Cache hit ratio
expected ~10-30% on real traffic from the same source IP. Off
by default; enable via `ai.cache_size: 10000`.

## 4 · Architecture

```
┌─ aegis-bin / aegis-proxy boot path ───────────────────────────┐
│  cfg.ai.enabled? ──no──> skip                                 │
│      │ yes                                                    │
│      ▼                                                        │
│  AiDetector::new(model_path, threshold, tiers)                │
│      ├─ tract::onnx::load_model(path)                         │
│      ├─ features::extract_schema()                            │
│      └─ Arc<dyn Detector>                                     │
│      │                                                        │
└──────┼────────────────────────────────────────────────────────┘
       │
       ▼ pushed onto detectors Vec alongside SQLi, XSS, etc.
       │
┌─ data-plane request handler (per request) ────────────────────┐
│  for det in detectors:                                        │
│      let view = RequestView { method, path, body, headers };  │
│      let result = det.inspect(&view);                         │
│      ↓ AiDetector::inspect:                                   │
│        ├─ check tier ∈ ai.tiers (else return Pass)            │
│        ├─ extract 26 features from RequestView                │
│        ├─ tokio::time::timeout(5ms, tract.run(features))      │
│        ├─ softmax → max class + confidence                    │
│        ├─ if confidence < threshold → return Pass             │
│        └─ if class != Normal → return Block(rule_id="ai_<cls>")│
└───────────────────────────────────────────────────────────────┘
```

### File layout

```
crates/
├── aegis-security/
│   ├── src/detectors/
│   │   ├── ai/                       # NEW
│   │   │   ├── mod.rs                # AiDetector struct + Detector impl
│   │   │   ├── features.rs           # 26 features ← matches features.py
│   │   │   ├── model.rs              # tract loader + inference primitive
│   │   │   ├── classes.rs            # u32 → "Normal"|"Injection"|... mapping
│   │   │   └── tests.rs
│   │   └── mod.rs                    # re-export gated by `ai` feature
│   └── Cargo.toml                    # `ai = ["dep:tract-onnx"]`
│
├── aegis-core/
│   └── src/config.rs                 # AiConfig struct
│
└── aegis-bin/Cargo.toml              # `ai = ["aegis-security/ai"]`
```

### Model file management

- **Path-only config**, mirroring geoip:
  ```yaml
  ai:
    enabled: true
    model_path: "data/ai_model/waf_model.onnx"
    confidence_threshold: 0.85
    tiers: [critical, high]
    cache_size: 0   # 0 = disabled
  ```
- `data/ai_model/.gitignore` excludes `*.onnx` (37 MB binary
  blob — same reasoning as geoip's `.mmdb` files; license-
  unclear at minimum).
- `make ai-link MODEL=/path/to/waf_model.onnx` symlinks like
  `make geoip-link`.
- Operator follow-up: hot-reload of the model via
  `notify`-watched file change (out of scope for v1).

## 5 · Detector contract on AI predictions

The 11 classes from the dataset report:

| Class | Rule ID | HTTP status | Block? |
|---|---|---:|---|
| Normal | (no rule) | passthrough | — |
| Injection | `ai_injection` | 403 | yes |
| XSS | `ai_xss` | 403 | yes |
| XXE | `ai_xxe` | 403 | yes |
| Manipulation | `ai_manipulation` | 403 | yes |
| HTTP abusion | `ai_http_abusion` | 403 | yes |
| Log4Shell | `ai_log4shell` | 403 | yes |
| Scanning | `ai_scanning` | 429 | yes (treat as recon) |
| Fake the Source of Data | `ai_source_spoofing` | 403 | yes |
| Dictionary Attack | `ai_dictionary_attack` | 429 | yes |
| SSTI | `ai_ssti` | 403 | yes |

**Audit shape** (existing AuditEvent):
```jsonc
{
  "action": "block",
  "rule_id": "ai_injection",
  "fields": {
    "ai_class": "Injection",
    "ai_confidence": 0.97,
    "ai_inference_us": 412,
    "ai_features_top3": ["len_url", "ratio_special", "n_unicode_escape"]
  }
}
```

The `ai_features_top3` field surfaces the top-3 contributing
features (by absolute SHAP-like score from a one-step
finite-difference) so operators can debug why a request was
flagged. Optional — gated by `ai.explain: true` because it
adds ~50 µs per request.

## 6 · Implementation slices

| Slice | Scope | Estimate |
|---|---|---|
| **AI-T1** | Cargo feature `ai` + `tract-onnx` workspace dep + `AiConfig` in aegis-core. No code yet — just the dep tree + cfg block. Validate that `cargo build --features ai` produces a 50-MB-bigger binary and `cargo build` (default) is unchanged. | ~2h |
| **AI-T2** | `features.rs` — port the 26 features from the Python `features.py` referenced in the dataset report. Pure function `extract(req: &RequestView) -> [f32; 26]`. Unit-tested against fixed payloads with expected feature vectors. | ~4h |
| **AI-T3** | `model.rs` — `Model::load(path) -> Result<Self>` via tract; `Model::predict(&[f32; 26]) -> Prediction { class, confidence, all_probs }`. Includes the 5ms timeout wrapper. | ~3h |
| **AI-T4** | `AiDetector` struct + `Detector` trait impl. Wires the per-tier gate, threshold check, and audit field emission. | ~3h |
| **AI-T5** | Boot wiring in `aegis-proxy::run` — read `cfg.ai`, build `AiDetector`, push into `detectors` vec. Behind `#[cfg(feature = "ai")]`. | ~2h |
| **AI-T6** | Metrics: `aegis_ai_inference_duration_seconds` (histogram), `aegis_ai_predictions_total{class}`, `aegis_ai_fallback_total{reason}` (timeout / threshold-too-low / model-error). Same Prometheus registry as the other latency histograms. | ~2h |
| **AI-T7** | `make ai-link`, `data/ai_model/.gitignore`, `data/ai_model/README.md` operator-docs. Mirrors geoip pattern. | ~1h |
| **AI-T8** | Integration test: load real ONNX, fire 100 known-bad payloads, assert ≥ 90% blocked with correct class. Plus a perf test that asserts p99 latency ≤ 1 ms over 1000 inferences. | ~3h |
| **AI-T9** | Dashboard surface: AI Detector card on the Detectors page (toggle, threshold slider, prediction-class breakdown bar chart from `/api/detectors/ai/stats`). | ~3h |

Total: ~23h. Slice order is strict — T1 → T2 → T3 → T4 → T5 are sequential. T6, T7, T8, T9 are independent follow-ups.

## 7 · Test plan

| Layer | Test | Outcome |
|---|---|---|
| Unit | `features::extract_url_length_matches_python` | feature[0] for known URL == 47 |
| Unit | `features::extracts_all_26_features_for_minimal_request` | vec is 26 f32, no NaNs |
| Unit | `model::load_invalid_path_returns_err` | clear error message |
| Unit | `model::predict_returns_normalised_softmax` | sum(probs) == 1.0 ± 1e-6 |
| Integration | `ai_detector_blocks_known_sqli_payload` | UNION SELECT request → block + rule_id=`ai_injection` + confidence > 0.85 |
| Integration | `ai_detector_passes_clean_traffic` | 100 random benign requests → 0 false-positive blocks |
| Integration | `ai_detector_falls_back_when_inference_times_out` | mock model that sleeps 10 ms → fallback path fires; metric increments |
| Integration | `ai_detector_skips_when_disabled_per_config` | `ai.enabled: false` → no predictions, no perf cost |
| Integration | `ai_detector_skips_low_tier_when_tier_filter_set` | tier=lite + `ai.tiers: [critical]` → bypass |
| Perf | `ai_inference_p99_under_1ms` | 1000 sequential predictions, p99 ≤ 1 ms (dataset report says 0.5 ms; allow 2× headroom) |

## 8 · Out of scope (deferred to AI-T10+)

- **Online learning / drift detection** — model is a static
  artifact; rebuild + re-deploy when retrained. No live
  weight updates.
- **Hot-reload of the model file** — restart-only in v1; the
  audit chain doesn't need to survive a model swap.
- **Per-route confidence threshold overrides** — global
  threshold for v1; per-route tuning is a CC-track follow-up.
- **GPU inference** — overkill for 4,600 req/s; CPU is plenty.
- **Adversarial-input detection** — separate research track;
  v1 trusts the regex detectors to catch evasion patterns the
  ML model misses.
- **Explainability beyond top-3 features** — full SHAP /
  LIME requires a 100×-larger compute budget; defer until an
  operator asks.
- **Multi-model ensembles** — single model in v1.

## 9 · Operator footguns (designed-out)

- **Model file missing at boot** — boot fails with a clear
  `WafError::Config("ai.model_path 'X' not found")`. No
  silent fall-through that pretends AI is on.
- **Model file is wrong shape** (different feature count) —
  tract's load returns a clear shape-mismatch error; boot
  fails at config-validation time, not at first request.
- **Threshold too low** (e.g. 0.5) — every cleanish-looking
  attack triggers a block, false-positive rate explodes.
  Boot logs a warning if `confidence_threshold < 0.7`.
- **Forgetting to rebuild after `FEATURES="redis"`** — the
  binary loses the `ai` feature; boot logs
  `ai.enabled: true but binary built without --features ai`
  and refuses to start (loud, not silent).
- **CPU spike under attack load** — every prediction is
  bounded by 5 ms timeout; metrics catch sustained timeouts
  before they DoS the WAF itself.

## 10 · Done-when

- `cargo test --workspace --features ai` passes with all
  AI-T* tests.
- `cargo build` (default features) produces a binary
  byte-identical to pre-AI-T (no AI bytes leak in via
  unconditional dep).
- `make build FEATURES="redis geoip ai"` produces a binary
  ≤ 50 MB larger than the default.
- `RUST_LOG=info make run-dev` with `ai.enabled: true` logs
  `ai detector wired: <model_path> threshold=0.85 tiers=[...]`
  at boot.
- A live `make run-dev` + curl with a SQLi payload returns
  403 with `x-waf-rule-id: ai_injection` AND with
  `x-waf-rule-id: sqli` (depending on which fired first;
  both detectors run, the first verdict wins).
- `data/ai_model/README.md` covers `make ai-link`, the env
  / config block, and the on/off matrix.
- `Implement-Progress.md` flips AI-T from open → closed with
  the SHA of AI-T8.

## 11 · Open questions for the user

1. **Model artifact source.** The report describes the
   training pipeline (`build_dataset.py`, `train.py`) but the
   `.onnx` file isn't in the repo and isn't referenced as a
   downloadable artifact. Where does the operator get it?
   - Option A: ship it via a make target that downloads from
     a release URL (S3 / GitHub release).
   - Option B: require operators to train themselves
     (`make ai-train` runs the python pipeline).
   - Option C: hand-shipped per-deployment (USB stick / S3
     bucket per customer).
2. **Default Cargo feature?** Mirroring the geoip choice
   (default-on, no-op when disabled), or default-off (slim
   image, opt-in)? My instinct is **default-off** because of
   the 37 MB binary bloat, but the geoip-style tradeoff could
   apply if the model becomes mandatory.
3. **Confidence threshold default.** 0.85 in this design;
   the dataset report's overall accuracy is 94.3% but doesn't
   give a precision/recall curve at varying thresholds.
   Need a calibration pass to pick the operating point that
   balances false-positive rate against detection rate.
4. **Should AI verdicts be advisory or authoritative?**
   Advisory: AI emits a low-priority signal that contributes
   to the risk score (existing P6 risk subsystem); the
   request gets blocked only if the cumulative risk crosses
   threshold. Authoritative: AI verdict triggers an immediate
   block. This design assumes authoritative; the advisory
   alternative needs a separate plan.
