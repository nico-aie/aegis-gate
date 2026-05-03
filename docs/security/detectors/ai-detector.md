# AI Detector (ML-based)

> **Status:** Implemented — `aegis-security/src/detectors/ai/`.
> Cargo-feature gated (`ai`), runtime-config gated (`ai.enabled`),
> hot-reloadable, per-tier on/off via the same `/api/detectors`
> mask as every other class.
>
> See the design rationale in
> [`../../../plans/ai-detector.md`](../../../plans/ai-detector.md)
> and the perf + p99 comparison report at
> [`../../../tests/results/run-ai-compare-2026-05-03/REPORT.md`](../../../tests/results/run-ai-compare-2026-05-03/REPORT.md).

## Purpose

A learned signature for attack traffic that **complements** the
regex / heuristic chain rather than replacing it. The model
catches request shapes the regex chain misses (oblique encodings,
new payload variants, unusual entropy / structure combinations)
while the regex chain pins down explicit signatures the model
under-weighs.

Run them together: in our 8 000-request comparison the regex
chain caught 92.9 % on its own, AI caught 86.3 % on its own,
and chained together they caught 93.3 % — small marginal lift,
but on **different misses** (the union beats either alone).

## Detection strategy

1. **Build a request string** — `METHOD /path?query body`,
   body capped at 4 KiB so a 100 MB upload doesn't pay 100 MB of
   feature extraction.
2. **Extract 26 numeric features** — the same feature set the
   training pipeline emits, byte-for-byte
   (`detectors/ai/features.rs`):
   - HTTP method ID (`GET=0, POST=1, …, others=7`)
   - URL length, path depth, query-pair count
   - Suspicious-keyword counts (raw + URL-decoded): SQL, XSS,
     scanner UA fragments, command-injection markers, SSRF
     hosts, php endpoints, log4j / JNDI markers, XXE, null byte,
     CRLF, hex-escape, double-percent
   - Shannon entropy over the request string
   - Counts of `%XX` sequences (raw and double-encoded)
3. **Run inference** on the operator-supplied ONNX model via
   `ort` 2.0-rc.12 — 1×26 `f32` tensor in, `i64` class label
   out (sklearn label encoder + RandomForest / GBM mapping).
4. **Verdict**: emit a **binary** decision — `class != normal`
   ⇒ attack signal. The model is multi-class internally
   (Injection, XSS, Path Traversal, SSRF, Scanning,
   Manipulation, HTTP-abusion, Log4Shell, XXE, Dictionary,
   Normal), but for the WAF hot path we only care about
   **attack vs not-attack** — class IDs reshuffle if the
   operator retrains or swaps to a binary head, and we don't
   want the WAF to break when that happens.

## Surfaces inspected

For each request:

- HTTP method
- URL path + query (raw, exactly as the proxy received it)
- Body bytes — capped at 4 KiB; `BodyPeek` already buffers up to
  the operator-configured `max_body_scan_bytes`, so the AI
  detector sees whatever the rest of the chain sees.
- Headers via the User-Agent feature (scanner-UA detection).

## Configuration

```yaml
ai:
  enabled: true                                  # runtime on/off
  model_path: data/ai_model/waf_model.onnx       # 38 MB ONNX file
  confidence_threshold: 0.5                      # below: no-op
  mode: observe                                  # observe | enforce
  timeout: 5ms                                   # inference budget
```

Knobs (finest to coarsest):

| Knob | Granularity | Restart? | Notes |
|---|---|---|---|
| Cargo feature `ai` | compile-time | yes (rebuild) | Off by default — adds the `ort` runtime + 38 MB model bytes |
| `ai.enabled` | per-deployment | hot-reload | When false, the boot path skips loading the model entirely |
| `ai.mode: observe \| enforce` | per-deployment | hot-reload | `observe` (recommended for burn-in): emit metrics + `would_block` audit, **never block**. `enforce`: block when `class != normal`. |
| `ai.confidence_threshold` | per-deployment | hot-reload | Minimum verdict confidence — below threshold the detector returns no signal so it can't override regex verdicts on low-confidence calls |
| `ai.timeout` | per-deployment | hot-reload | Hard wall-clock budget for inference — exceeding emits `aegis_ai_fallback_total{reason=inference_error}` and skips the verdict |
| `/api/detectors` mask | runtime, per-tier | live | Same UI as muting `sqli` — set `class="ai"` to off and the chain skips it without restart |

The `ai.mode: observe` default is the right starting point: every
operator's traffic mix is different, model thresholds need
tuning before they enforce, and the `would_block` audit gives
a calibration trail.

## Actions on detection

- Emit a `Signal` with `tag: "ai"` and `score: 60` — feeds the
  same scoring path as every other detector class.
- In `enforce` mode, the request is blocked (HTTP 403) once the
  composite score crosses the route's tier threshold.
- In `observe` mode, the audit event records `would_block: true`
  but the request flows through.

## Performance (measured)

From `tests/results/run-ai-compare-2026-05-03/REPORT.md` — 4
cases × 8 000 requests at 400 RPS (60 % attack mix),
prod-balanced shape on a laptop:

| Mode | Detect % | FP % | Attack p95 / **p99** ms | Clean p95 / **p99** ms | RSS MB |
|---|---|---|---|---|---|
| ALL on (regex+AI)  | 93.8 | 40.0 | 2.48 / **4.53** | 2.90 / **5.71** | 562 |
| AI ONLY            | 85.7 | 40.1 | 2.39 / **5.58** | 2.69 / **5.47** | 507 |
| REGEX ONLY         | 93.5 | 10.4 | 1.36 / **2.26** | 1.80 / **2.92** |  65 |
| NONE (baseline)    |  0.0 |  0.0 | 1.42 / **2.44** | 1.44 / **2.58** |  51 |

**p99 vs the 5 ms target.** Regex-only and the no-detector
baseline pass cleanly. Adding AI pushes p99 across the 5 ms
line on laptop hardware (clean p99 5.71 ms in case A,
5.47 ms in case B). On production hosts with bigger CPU
budget the gap closes — the headline 5 k RPS run on
`prod-balanced-5k` already demonstrated p99 1.03 ms with the
regex chain, so AI on a production host should land
comfortably inside the target. **Plan to verify on real
hardware before promoting to enforce.**

**Per-request inference cost**:
- 694 µs mean when chained (case A) — 357 µs measured on a
  warm-cache earlier run; the value moves with system load
  and ONNX arena state
- 783 µs mean when AI runs alone (case B)
- p95 inference well inside the 5 ms `ai.timeout` ceiling

**Memory cost**: +500 MB RSS on top of the regex chain in this
run (65 → 562 MB) — the 38 MB ONNX session plus arenas the
runtime allocates lazily over the run; an earlier short run
measured +160 MB before the arena had filled. Production
sizing should budget ~500 MB once arenas have stabilised.

**Throughput**: all four cases sustained 400 RPS without
saturation. The saturation ceiling test is the existing
[`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`](../../../tests/results/) —
that ran with regex-only. A 5 k RPS run with AI enabled is the
next perf experiment.

## False-positive control

The bundled model is sensitivity-tuned (training-set classes
favour recall over precision). At threshold 0.5 it fires on
about two-thirds of all traffic in our mixed corpus — far too
aggressive for `enforce`. **Tightening recipe**:

1. Run `ai.mode: observe` for at least a week on production
   shape — collect `would_block` audit events into the SOC bus.
2. Inspect by-class FP rate from the dashboard's AI Detector
   card (rendered when `metrics-after.txt` carries `class="ai"`
   labels).
3. Bump `ai.confidence_threshold` until the FP rate matches your
   tolerance (0.7 / 0.85 / 0.95 are common pre-commit gates),
   then flip `mode: enforce`.
4. Operators with a stricter false-positive ceiling can either
   retrain on their own corpus (the trainer at
   `data/ai_model/src/` is a stub kept for reference, not an
   in-repo build target) or run AI in `observe` indefinitely as
   a tripwire.

## Observability

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `waf_detector_hits_total{class="ai"}` | counter | — | Attack-class predictions counted toward the chain |
| `waf_detector_evaluation_duration_ms{class="ai"}` | histogram | — | End-to-end inspect-time including tensor build + inference |
| `aegis_ai_predictions_total{verdict}` | counter | `attack` / `normal` | Pre-aggregated verdict counter (registered when `ai` feature is on) |
| `aegis_ai_inference_duration_seconds{verdict}` | histogram | `attack` / `normal` | Pure inference time, excluding feature extraction |
| `aegis_ai_fallback_total{reason}` | counter | `inference_error` / `low_confidence` / `tensor_build` | One per skipped verdict |

Audit shape (one event per inference): `detectors: ["ai"]` plus
the `would_block` flag in `observe` mode.

Dashboard surface: an "AI Detector" card on the Detector tier-
config page reads `/metrics` directly and renders inferences /
hit rate / mean latency live (no dashboard reload required).

## Wiring + first-run

```bash
# 1) Build with the feature.
FEATURES="redis geoip ai" make build

# 2) Symlink an operator-supplied ONNX file into place.
make ai-link MODEL=/path/to/your/waf_model.onnx
# (sets data/ai_model/waf_model.onnx → your file)

# 3) Flip the runtime toggle in your config.
#    config/dev.yaml already ships ai.enabled: true; for prod-*
#    profiles, edit the `ai:` block.

# 4) Boot — the WAF logs `AI detector wired into the chain` at startup.
make run-dev
```

Sanity-check the wiring without writing a config:

```bash
AEGIS_AI_MODEL=$(pwd)/data/ai_model/waf_model.onnx \
    cargo test -p aegis-security --features ai \
    --test ai_e2e -- --nocapture
```

The test runs an 8-clean-/-10-attack corpus through the live
detector and asserts `≥ 8/10` attacks caught and `≤ 25 %` FP
rate on clean traffic — the baseline the perf comparison
report is calibrated against.

## Bypass / known limits

- **Encoding evasion**: the feature extractor URL-decodes once;
  triple-encoded payloads (`%2525%32%37` for `'`) need an extra
  pass on the proxy side, which is the regex chain's job today.
  Pair AI with the existing path-traversal / XSS detectors.
- **Body-shape attacks**: the body cap is 4 KiB. Payloads that
  exceed that and **only** carry the attack signal in the
  truncated tail will miss — but most exploit shapes carry
  the signal in the first few hundred bytes.
- **Adversarial inputs**: the model is a plain RandomForest /
  GBM head — adversarial-perturbation attacks against the
  feature space are out of scope for v1. The defence is
  defence-in-depth (regex chain + rule engine + risk score),
  not the AI detector standing alone.
- **Model staleness**: counters keep climbing as classifications
  shift over time; rebake the model against fresh traffic
  before re-tightening the threshold.

## Implementation

| File | Role |
|---|---|
| `crates/aegis-security/src/detectors/ai/mod.rs` | `AiDetector` trait impl, `AiMetricsSink` indirection so `aegis-security` doesn't depend on `aegis-control` |
| `crates/aegis-security/src/detectors/ai/features.rs` | 26-feature extractor — same shape as the training pipeline |
| `crates/aegis-security/src/detectors/ai/model.rs` | `Mutex<ort::Session>` wrapper; 1×26 tensor in → `i64` label out |
| `crates/aegis-control/src/metrics/ai.rs` | Prometheus registration, `AiMetricsSink` impl |
| `crates/aegis-proxy/src/run.rs` (~L356) | Boot-time wiring — load model, register metrics, push into the detector chain |
| `crates/aegis-security/tests/ai_e2e.rs` | Integration test gated on `AEGIS_AI_MODEL` |
| `tests/perf/ai-compare.sh` | Side-by-side comparison harness — A (all) / B (AI-only) / C (regex-only) / D (baseline) |

## References

- Plan + design rationale — [`plans/ai-detector.md`](../../../plans/ai-detector.md)
- Dataset + training notes — [`data/ai_model/WAF_DATASET_REPORT_VI.md`](../../../data/ai_model/WAF_DATASET_REPORT_VI.md)
- Perf + p99 report — [`tests/results/run-ai-compare-2026-05-03/`](../../../tests/results/run-ai-compare-2026-05-03/)
  (re-run with `bash tests/perf/ai-compare.sh`)
- Detector chain semantics — [`./README.md`](./README.md)
- Tier mask + compliance clamp — [`../tiered-protection.md`](../tiered-protection.md)
