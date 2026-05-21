---
id: 2026-05-17-security-contract-gaps
date: 2026-05-17T00:00Z
severity: contract-gap (semantic)
area: AI detector mode · scoring ladder calibration · README↔code disagreement
component: crates/aegis-security/src/detectors/ai/mod.rs · detectors/scores.rs · aegis-core/src/config.rs (RiskThresholds)
interop_contract: official rules §5.2 #04 + §5.5 + README claims
status: open
test_mode: source-review
---

# F-CONTRACT-GAPS · 3 semantic gaps where code disagrees with the README / spec

These are not bugs in the "code does the wrong thing" sense — code
does what its author intended. They are gaps where the WAF's
behavior diverges from documented expectations.

---

## C-01 · AI detector has no `observe | enforce` mode despite README claim

**Component:** [detectors/ai/mod.rs:84-117](../../../../crates/aegis-security/src/detectors/ai/mod.rs#L84-L117)

The README explicitly advertises:

> *AI detector — operator-supplied ONNX model loaded via `ort`,
> 26-feature extractor, binary attack-vs-normal verdict, hybrid
> `mode: observe | enforce` for safe rollouts.*

The code has only `runtime_enabled: AtomicBool` (on/off). When on,
the AI verdict ALWAYS emits a `Signal` (score 60) that feeds the
risk total. There is no observe-only mode that records the
prediction without influencing the decision.

The closest thing is `record_prediction` to the metrics sink — but
the `Signal` emit is in parallel, not gated by mode.

A judge probing AI "safe rollout" behavior (set mode=observe, send
a payload that would predict-attack, verify request reaches upstream
unblocked while metrics record the prediction) gets unexpected
enforcement.

### Fix

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AiMode {
    Observe,
    Enforce,
}

pub struct AiDetectorConfig {
    pub enabled: bool,
    pub mode: AiMode,                 // NEW
    pub confidence_threshold: f32,
    ...
}

impl Detector for AiDetector {
    fn inspect(&self, req: &Request) -> Vec<Signal> {
        let prediction = match self.predict(req) {
            Ok(p) => p,
            Err(e) => { record_inference_error(e); return vec![]; }
        };

        // Always record prediction for observability.
        self.metrics.record_prediction(&prediction);

        // Mode gate: observe = don't emit Signal.
        match self.cfg.mode {
            AiMode::Enforce if prediction.confidence >= self.cfg.confidence_threshold => {
                vec![Signal {
                    tag: "ai_detector".into(),
                    score: SCORE_AI_DETECTION,
                    ...
                }]
            }
            _ => vec![],
        }
    }
}
```

Update README to describe the mode semantics precisely.

---

## C-02 · AI confidence extraction `.unwrap_or(1.0)` bypasses the `confidence_threshold` for legacy sklearn shape models

**Component:** [detectors/ai/model.rs:126, 163-176](../../../../crates/aegis-security/src/detectors/ai/model.rs#L126)

`extract_confidence()` returns `None` when the model emits the
legacy sklearn `Sequence<Map<i64, f32>>` output shape. The caller
does `.unwrap_or(1.0)`. The downstream check
`if p.confidence >= self.threshold` (default 0.85) then ALWAYS
passes because 1.0 >= 0.85.

Operators tuning `confidence_threshold` to (e.g.) 0.95 to reduce
false positives observe NO behaviour change when their model is the
legacy shape. The knob is silently a no-op.

### Fix

Fail-safe: `.unwrap_or(0.0)` — below any positive threshold:

```diff
-let confidence = extract_confidence(&output).unwrap_or(1.0);
+let confidence = extract_confidence(&output).unwrap_or(0.0);
```

OR, better: detect the shape mismatch at model-load time, log a
warning, and refuse to load the model:

```rust
if probe_legacy_shape(&model) {
    tracing::warn!(
        "AI model emits legacy sklearn Sequence<Map> output shape — \
         confidence extraction will not work. Re-export the model \
         with dense probability output."
    );
    return Err(ModelLoadError::UnsupportedOutputShape);
}
```

---

## C-03 · Scoring ladder ceiling (60) doesn't reach default block threshold (80) → no single regex detector blocks alone

**Component:** [detectors/scores.rs](../../../../crates/aegis-security/src/detectors/scores.rs) · [aegis-core/src/config.rs:1990-1995](../../../../crates/aegis-core/src/config.rs#L1990-L1995)

Per-detector deltas (representative):

| Detector class | Score delta |
|---|---|
| AI detection (high confidence) | 60 |
| Command injection | 50 |
| SSTI / NoSQL / SSRF | 50 |
| SQLi / XSS (high confidence) | 50 |
| Open-redirect | 30 |

Default `RiskThresholds`: `challenge_at: 40, block_at: 80`.

A single hit on the most-severe detector (`60`) gets the request to
"Challenge" but NEVER to "Block". The rubric expects high-confidence
injection (cmdi, log4shell, SQLi) to BLOCK on first hit. As shipped:
no single regex detector blocks on its own — block requires ≥2
signals.

(The README claims thresholds 30/70 per spec, so with that fix
[F-CRITICAL-006] a 60 signal reaches Challenge but still doesn't
block — same issue.)

This is "fine" if the design philosophy is "always require 2 signals
to block" — but that's not documented anywhere, and contradicts
both the rubric and the spec table (§3.1 maps high-confidence
injection to `block` as an acceptable action).

### Fix

Two options.

**Option A — Raise critical-detector scores to single-hit-block**:

```rust
// detectors/scores.rs
pub const SCORE_SQLI_HIGH:      u32 = 80;   // single hit → block
pub const SCORE_CMDI_HIGH:      u32 = 80;
pub const SCORE_XSS_HIGH:       u32 = 80;
pub const SCORE_LOG4SHELL:      u32 = 90;
pub const SCORE_AI_DETECTION:   u32 = 60;   // chained with others to block
pub const SCORE_HEURISTIC:      u32 = 35;   // single hit → challenge
```

**Option B — Add a per-detector `force_block: bool` flag**: when
true, the detector emits a Decision::Block directly instead of
contributing a score. Maps cleanly to the "high confidence" wording
in §3.1.

Recommend Option A — keeps the additive-score model intact;
operators can still tune thresholds.

Cross-fix with F-CRITICAL-006 (align defaults to 30/70). The combined
shape: thresholds `30/70`, top detector score `80` → top-tier
detector single-hit blocks (80 > 70), heuristic single-hit challenges
(35 between 30 and 70).

---

## Severity classification

Contract-gap level (semantic). Each is a documented expectation that
the code doesn't deliver. Combined effect: an operator following the
README's configuration knobs (mode, confidence_threshold, default
thresholds) observes behaviors different from what the docs imply.
