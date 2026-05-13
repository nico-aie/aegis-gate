# AI Detector (ML-based)

> **Status:** Implemented — `aegis-security/src/detectors/ai/`.
> Cargo-feature gated (`ai`), runtime-config gated (`ai.enabled`),
> hot-reloadable, per-tier on/off via the same `/api/detectors`
> mask as every other class.
>
> See the design rationale in
> [`../../../plans/ai-detector.md`](../../../plans/ai-detector.md)
> and the latest perf + p99 comparison report at
> [`../../../tests/results/run-ai-compare-2026-05-13-175615/REPORT.md`](../../../tests/results/run-ai-compare-2026-05-13-175615/REPORT.md)
> (expanded 3 227-case corpus, 24 000 reqs / case).
> Prior runs are preserved for reference:
> - [`run-ai-compare-2026-05-13-172226`](../../../tests/results/run-ai-compare-2026-05-13-172226/REPORT.md) — new model, smaller 25-case corpus
> - [`run-ai-compare-2026-05-03`](../../../tests/results/run-ai-compare-2026-05-03/REPORT.md) — old 11-class model

## Purpose

A learned signature for attack traffic that **complements** the
regex / heuristic chain rather than replacing it. The model
catches request shapes the regex chain misses (oblique encodings,
new payload variants, unusual entropy / structure combinations)
while the regex chain pins down explicit signatures the model
under-weighs.

Run them together: in our 24 000-request expanded-corpus
comparison (3 227 unique cases — 2 203 attack shapes + 1 024
clean shapes), the regex chain caught **88.6 %** on its own, AI
alone caught **50.3 %** at the calibrated 0.85 threshold, and
chained together they caught **90.4 %** at **0.44 % FP** —
a real +1.8 pp marginal lift over regex with only +0.27 pp
extra false positives. Compared to the old 11-class model on
the same harness, FP rate dropped roughly **100×** (40.0 % →
0.44 %).

## Detection strategy

1. **Build a request string** — multi-line, matching the training
   pipeline byte-for-byte:

   ```text
   METHOD /path?query body
   User-Agent: …
   Cookie: …
   Referer: …
   ```

   Only the three headers the training pipeline saw (`User-Agent`,
   `Cookie`, `Referer`) are folded in; other headers are
   intentionally ignored so the feature distribution stays close
   to training. Body is capped at 4 KiB so a 100 MB upload
   doesn't pay 100 MB of feature extraction. The legacy
   single-line shape (`"METHOD /url body"`) still parses cleanly.
2. **Extract 27 numeric features** — the same feature set the
   training pipeline emits, byte-for-byte
   (`detectors/ai/features.rs`):
   - HTTP method ID (`GET=0, POST=1, …, others=7`)
   - URL / path / query / body lengths, param count
   - Shannon entropy over the request string
   - Digit / uppercase ratios, special-char count
   - Quote / angle-bracket / semicolon counts
   - Suspicious-keyword counts (raw + URL-decoded): SQL, XSS,
     scanner UA fragments, command-injection markers, SSRF
     hosts, php endpoints, null byte, CRLF, hex-escape,
     double-percent
   - **SSTI markers** (new in 2026-05-13) — Jinja `{{...}}`,
     SpEL `${...}`, Velocity `#{...}`, JSP `<%=…%>`, Python
     sandbox-escape (`__class__`, `__mro__`, `__subclasses__`,
     `__globals__`, …), template-engine names.
3. **Run inference** on the operator-supplied ONNX model via
   `ort` 2.0-rc.12 — 1×27 `f32` tensor in, two outputs back:
   - `label`         — `i64` class index (0 = Normal, 1 = Attack)
   - `probabilities` — `f32` `[batch, 2]` (P(Normal), P(Attack))

   The binary model exports `probabilities` as a dense tensor,
   so the detector reads the top-1 softmax probability directly
   and applies the `confidence_threshold` gate. (The old
   sklearn `Sequence<Map<i64,f32>>` shape used `1.0` as a
   fall-back; the new shape gives us real confidence to gate
   on.)
4. **Verdict**: emit a **binary** decision — `class != normal`
   ⇒ attack signal. The model is now genuinely binary; the
   code path is unchanged from when we shipped against an
   11-class head (`Model::predict` always returned
   `is_attack: bool`), so future model swaps stay drop-in.

## Surfaces inspected

For each request:

- HTTP method
- URL path + query (raw, exactly as the proxy received it)
- Body bytes — capped at 4 KiB; `BodyPeek` already buffers up to
  the operator-configured `max_body_scan_bytes`, so the AI
  detector sees whatever the rest of the chain sees.
- `User-Agent`, `Cookie`, and `Referer` headers — folded into
  the request string as separate lines so the regex features
  (scanner-UA, SSRF in Referer, session-shape in Cookie) all
  trigger the way the training pipeline saw them.

## Configuration

```yaml
ai:
  enabled: true                                  # runtime on/off
  model_path: data/ai_model/waf_model.onnx       # 19 MB ONNX file (binary head)
  confidence_threshold: 0.85                     # below: no-op
```

Simplified 2026-05-04 — AI is treated like any other detector
class now. The earlier `mode: observe | enforce`, `tiers:`,
`timeout:`, and `explain:` knobs were declared but never read
in the runtime; they're gone.

**2026-05-13 — model swap.** The bundled model went from an
11-class RandomForest to a binary LightGBM head (Normal=0 /
Attack=1, see `data/ai_model/label_map.json`). Feature count
grew from 26 to 27 (added SSTI marker count). Input shape now
multi-line so `User-Agent` / `Cookie` / `Referer` headers are
visible to the model. ONNX file shrank from 38 MB to 19 MB.

Knobs:

| Knob | Granularity | Restart? | Notes |
|---|---|---|---|
| Cargo feature `ai` | compile-time | yes (rebuild) | Adds `ort` runtime + 38 MB model bytes. Included in the default `make build` target. |
| `ai.model_path` (YAML) | per-deployment | restart | Path to the ONNX model. Boot loads the model whenever this is set + the file exists, regardless of `ai.enabled`. **2026-05-10** — the loader is hot-tolerant: missing / malformed model with `ai.enabled: false` boots cleanly with AI un-installed; same condition with `ai.enabled: true` is a hard error. |
| `ai.enabled` (YAML) | per-deployment | seed only | Seeds the **initial** state of the runtime toggle at boot. `false` → boots with AI loaded but toggle off. Operators flip on from the Detectors & Tiers page without a restart. |
| `PUT /api/ai/enabled` | runtime | hot | Audit-mutated runtime toggle. Shipped as the **Detectors & Tiers** page → AI row → Enable/Disable button. When off, `inspect()` short-circuits — zero inference cost. **Works in any deployment where the model loaded at boot**, regardless of the YAML `enabled` flag. |
| `ai.confidence_threshold` | per-deployment | restart | Minimum verdict confidence — below threshold the detector returns no signal so it can't override regex verdicts on low-confidence calls. |

## Actions on detection

- Emit a `Signal` with `tag: "ai"` and `score: 60` — feeds the
  same scoring path as every other detector class.
- The route's tier threshold + composite request score decide
  whether the request is blocked (403) or just risk-scored.
  Same flow as every other detector — there's no AI-specific
  block path.

## Performance (measured)

From `tests/results/run-ai-compare-2026-05-13-175615/REPORT.md`
— 4 cases × **24 000 requests** at 400 RPS (60 % attack mix),
**3 227 unique cases** (2 203 attacks + 1 024 clean), threshold
0.85, Linux x86_64:

| Mode | Detect % | FP % | Attack p95 / **p99** ms | Clean p95 / **p99** ms | RSS MB |
|---|---|---|---|---|---|
| ALL on (regex+AI)  | **90.4** | **0.44** | 2.33 / **3.12** | 2.48 / **3.22** | 373 |
| AI ONLY            | 50.3     | 0.39     | 2.26 / **2.58** | 2.31 / **2.64** | 337 |
| REGEX ONLY         | 88.6     | **0.18** | 1.37 / **1.63** | 1.53 / **1.77** | 361 |
| NONE (baseline)    |  0.0     | 0.00     | 1.31 / **1.55** | 1.32 / **1.57** | 326 |

**p99 vs the 5 ms target.** All four cases pass — including the
AI-enabled configurations, which failed the budget on the old
11-class model. Chain p99 dropped further than on the smaller
corpus (3.12 ms vs 3.81 ms in Case A) because the rate-limit
gate that contaminated the 25-case run is now neutralised in
the harness, letting all 24 k requests reach the detector
chain cleanly.

**AI's marginal lift over regex (Case A vs Case C)**: +1.8 pp
detection (90.4 % vs 88.6 %) at only +0.27 pp FP (0.44 % vs
0.18 %). The AI detector catches **166 attacks the regex chain
missed**, adding only **26 extra false positives** — a clean
precision/recall trade.

**Per-request inference cost**:
- 992 µs mean when chained (case A) — down from 1 262 µs on
  the smaller-corpus run as the ONNX arena has had more
  inferences to stabilise.
- 947 µs mean when AI runs alone (case B).
- p95 inference comfortably inside the 5 ms request budget.

**Memory cost**: +47 MB RSS on top of the regex chain in this
run (326 → 373 MB) — the 19 MB ONNX session plus arenas the
runtime allocates lazily. Still **−189 MB** vs the old
model's 562 MB.

**Throughput**: all four cases sustained 400 RPS without
saturation. The saturation ceiling test is still the existing
[`tests/results/run-perf-5krps-prod-balanced-2026-05-02-v3/`](../../../tests/results/) —
that ran with regex-only. A 5 k RPS run with AI enabled is the
next perf experiment.

## False-positive control

The new binary model is **precision-tuned** out of the box —
at the calibrated 0.85 threshold AI-alone (Case B) fires on
**0 % of benign traffic** in the bundled corpus. Tightening
no longer trades recall for precision the way the old 11-class
head did; the recipe below is now about confirming the budget
holds on real traffic shapes, not about chasing a runaway FP
rate.

**Confirmation recipe** (run before promoting to enforce on a
new corpus):

1. Boot with `ai.enabled: true` and the default
   `ai.confidence_threshold: 0.85`. Flip enforce-mode off so AI
   verdicts only land in audit (`would_block: true`).
2. Watch `waf_detector_hits_total{class="ai"}` against real
   traffic for a week. Compare against the cardinality of
   benign requests in the same window — anything > 5 %
   suggests the bundled model's feature distribution drifted
   from your traffic.
3. Tighten to 0.9 / 0.95 if needed. Loosening below 0.85 is
   not recommended without retraining — the binary model's
   confidence below 0.85 is mostly noise.
4. If the corpus shifts hard (new product launch, integration
   that adds traffic shape the model hasn't seen), retrain.
   The trainer at `data/ai_model/src/` is a working reference
   implementation now (binary head, LightGBM, multi-line
   features) — not just a stub.

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
| `crates/aegis-security/src/detectors/ai/mod.rs` | `AiDetector` trait impl, `AiMetricsSink` indirection so `aegis-security` doesn't depend on `aegis-control`; builds the multi-line request string with User-Agent / Cookie / Referer |
| `crates/aegis-security/src/detectors/ai/features.rs` | 27-feature extractor — same shape as the training pipeline, supports both single-line and multi-line input |
| `crates/aegis-security/src/detectors/ai/model.rs` | `Mutex<ort::Session>` wrapper; 1×27 tensor in → (`i64` label, `f32` probabilities) out |
| `crates/aegis-control/src/metrics/ai.rs` | Prometheus registration, `AiMetricsSink` impl |
| `crates/aegis-proxy/src/run.rs` (~L390) | Boot-time wiring — load model, register metrics, push into the detector chain |
| `crates/aegis-security/tests/ai_e2e.rs` | Integration test gated on `AEGIS_AI_MODEL` |
| `tests/perf/ai-compare.sh` | Side-by-side comparison harness — A (all) / B (AI-only) / C (regex-only) / D (baseline) |
| `data/ai_model/src/` | Reference trainer + inference benchmark (LightGBM binary head) |

## References

- Plan + design rationale — [`plans/ai-detector.md`](../../../plans/ai-detector.md)
- Dataset + training notes — [`data/ai_model/WAF_DATASET_REPORT_VI.md`](../../../data/ai_model/WAF_DATASET_REPORT_VI.md)
- **Perf + p99 report (current — expanded corpus)** — [`tests/results/run-ai-compare-2026-05-13-175615/`](../../../tests/results/run-ai-compare-2026-05-13-175615/)
  (re-run with `bash tests/perf/ai-compare.sh`; corpus is
  regenerated from `tests/perf/gen-ai-corpus.py` on demand)
- Perf + p99 report (new model, small corpus) — [`tests/results/run-ai-compare-2026-05-13-172226/`](../../../tests/results/run-ai-compare-2026-05-13-172226/)
- Perf + p99 report (old 11-class model) — [`tests/results/run-ai-compare-2026-05-03/`](../../../tests/results/run-ai-compare-2026-05-03/)
- Detector chain semantics — [`./README.md`](./README.md)
- Tier mask — [`../tiered-protection.md`](../tiered-protection.md)
  (compliance lock-by-mode is deferred; see [`plans/future/compliance-profiles.md`](../../../plans/future/compliance-profiles.md))
