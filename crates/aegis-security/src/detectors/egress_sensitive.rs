//! EG-2 T2/T3 (2026-07-05) — response **sensitive-data** sampling.
//!
//! Detects secret material (T2) and cardholder sweeps (T3) *leaving* through
//! the response body: private-key/cloud-credential/token markers, and
//! high-density runs of Luhn-valid card numbers. The observability twin of
//! the shipped `redact_dlp` rung (`Pipeline::on_body_frame`): it **reports**
//! the `dlp::scan()` match set that the redact path today computes and
//! discards.
//!
//! ## v1 scope (owner decision, design §6.2): PAN + secret markers ONLY
//!
//! The full `dlp` pattern set also covers SSN / IBAN / email / phone (bulk-
//! PII shapes), but those are FP-prone (density heuristics on random digits)
//! and are deferred until the FPM corpus exists. v1 reports only:
//! - **secret markers** (T2): `aws_key`, `aws_secret`, `github_token`,
//!   `stripe_key`, `slack_token`, `pem_private_key`, `jwt`, `env_secret` —
//!   single occurrence is signal (a secret should never be in a response).
//! - **card PANs** (T3): `credit_card` (Luhn-validated) — but only above a
//!   **density threshold**, since one PAN in a receipt is normal business
//!   and only a *sweep* (many PANs in one body) is the exfil shape.
//!
//! ## Hard rules (design §4)
//!
//! - **Content-type-gated** (json/html/csv/text) + **size-capped** (only the
//!   first `max_scan_bytes` are scanned).
//! - **Sampled** — 1-in-`sample_rate` responses per detector, ALWAYS-on for
//!   already-risky (challenge/block-band) clients, so the hot path pays the
//!   body scan rarely while suspicious clients are always inspected.
//! - **Observe-before-redact.** Must run BEFORE the `redact_dlp` rewrite or
//!   it would only ever see `[REDACTED]`. The redact path is left full-body
//!   and unchanged; only this EG-2 read is capped (design §"max_scan_bytes"
//!   decision: cap the EG-2 read, don't change the shipped redact rung).
//! - **Observability only.** Emits a Detection-class audit row per hit; per
//!   the owner decision (2026-07-05) it does **not** touch the risk score.
//!   **Default OFF** until FP-tuned.

use super::Signal;
use crate::dlp::{self, DlpMatch};
use std::sync::atomic::{AtomicU64, Ordering};

/// Score carried on a secret-marker signal (high signal — a credential in a
/// response body is almost never legitimate). Audit context only; the
/// detector does not feed risk today.
pub const SECRET_SCORE: u32 = 40;
/// Score carried on a card-PAN density signal.
pub const PAN_SCORE: u32 = 30;

/// Default body-scan cap (64 KiB) — the design's suggested default.
pub const DEFAULT_MAX_SCAN_BYTES: usize = 64 * 1024;
/// Default sampling: scan 1-in-8 responses (risky clients always scan).
pub const DEFAULT_SAMPLE_RATE: u32 = 8;
/// Default PAN-density threshold — a single card is normal; a sweep isn't.
pub const DEFAULT_PAN_DENSITY: usize = 5;

/// The `dlp` pattern names T2 treats as secret markers (v1 scope).
const SECRET_PATTERNS: &[&str] = &[
    "aws_key",
    "aws_secret",
    "github_token",
    "stripe_key",
    "slack_token",
    "pem_private_key",
    "jwt",
    "env_secret",
];

pub struct SensitiveDataDetector {
    max_scan_bytes: usize,
    sample_rate: u32,
    pan_density: usize,
    /// Monotonic response counter driving the 1-in-N sampler.
    counter: AtomicU64,
}

impl SensitiveDataDetector {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_MAX_SCAN_BYTES, DEFAULT_SAMPLE_RATE, DEFAULT_PAN_DENSITY)
    }

    pub fn with_config(max_scan_bytes: usize, sample_rate: u32, pan_density: usize) -> Self {
        Self {
            max_scan_bytes,
            sample_rate: sample_rate.max(1),
            pan_density,
            counter: AtomicU64::new(0),
        }
    }

    /// Response-side entry point. Returns a [`Signal`] per secret marker plus
    /// one PAN-density signal when the card count clears the threshold —
    /// empty when the content-type/sampling gate rejects the response or
    /// nothing sensitive is present. `always_scan` forces the scan
    /// (challenge/block-band clients) regardless of the sampler.
    pub fn observe(
        &self,
        content_type: Option<&str>,
        body: &[u8],
        always_scan: bool,
    ) -> Vec<Signal> {
        // Content-type gate first (cheap) — reject before the sampler so a
        // non-scannable body doesn't consume sample budget.
        if !content_type.is_some_and(is_scannable_ct) {
            return Vec::new();
        }
        if !self.should_scan(always_scan) {
            return Vec::new();
        }
        // Bound the read, decode lossily once, run the single dlp scan.
        let window = &body[..body.len().min(self.max_scan_bytes)];
        let text = String::from_utf8_lossy(window);
        let (secrets, pan_count) = v1_matches(dlp::scan(&text));

        let mut signals = Vec::new();
        for m in secrets {
            // `dlp::scan` captures the KEY only for `env_secret` and the
            // marker token for the rest — never the full secret value — so
            // the audit `field` stays safe to log.
            signals.push(Signal {
                score: SECRET_SCORE,
                tag: "egress_sensitive".into(),
                field: format!("kind:{}", m.pattern_name),
            });
        }
        if pan_count >= self.pan_density {
            signals.push(Signal {
                score: PAN_SCORE,
                tag: "egress_sensitive".into(),
                field: format!("kind:pan_density,count:{pan_count}"),
            });
        }
        signals
    }

    /// 1-in-`sample_rate` sampler; `always` bypasses it. Every call advances
    /// the counter so the sample cadence is stable regardless of `always`.
    fn should_scan(&self, always: bool) -> bool {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        always || self.sample_rate <= 1 || n % (self.sample_rate as u64) == 0
    }
}

impl Default for SensitiveDataDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Content-type gate: structured text the origin renders as a page / data.
/// Drops any `; charset=…` param and normalises case.
fn is_scannable_ct(ct: &str) -> bool {
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct.ends_with("+json")
        || ct == "text/csv"
}

/// Filter a full `dlp::scan()` result to the v1 scope (PAN + secret markers),
/// dropping the deferred PII shapes (ssn/iban/email/phone).
fn v1_matches(all: Vec<DlpMatch>) -> (Vec<DlpMatch>, usize) {
    let mut secrets = Vec::new();
    let mut pan_count = 0usize;
    for m in all {
        if m.pattern_name == "credit_card" {
            pan_count += 1;
        } else if SECRET_PATTERNS.contains(&m.pattern_name.as_str()) {
            secrets.push(m);
        }
        // else: deferred PII shape — ignored in v1.
    }
    (secrets, pan_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = "application/json";

    // Always-scan (sample_rate 1) so tests are deterministic.
    fn detector() -> SensitiveDataDetector {
        SensitiveDataDetector::with_config(64 * 1024, 1, 5)
    }

    #[test]
    fn aws_key_in_response_scores_secret() {
        let d = detector();
        let body = br#"{"config":{"key":"AKIAIOSFODNN7EXAMPLE"}}"#;
        let sigs = d.observe(Some(JSON), body, false);
        assert!(
            sigs.iter().any(|s| s.tag == "egress_sensitive" && s.field.contains("aws_key")),
            "an AWS key leaving in a JSON body must score: {:?}",
            sigs.iter().map(|s| s.field.clone()).collect::<Vec<_>>(),
        );
        assert_eq!(sigs[0].score, SECRET_SCORE);
    }

    #[test]
    fn pem_private_key_scores() {
        let d = detector();
        let body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        let sigs = d.observe(Some("text/plain"), body, false);
        assert!(sigs.iter().any(|s| s.field.contains("pem_private_key")));
    }

    #[test]
    fn single_pan_does_not_score() {
        // One card in a receipt is normal business — below the density gate.
        let d = detector();
        let body = br#"{"receipt":{"card":"4111-1111-1111-1111"}}"#;
        let sigs = d.observe(Some(JSON), body, false);
        assert!(
            !sigs.iter().any(|s| s.field.contains("pan")),
            "a single PAN must not score: {:?}",
            sigs.iter().map(|s| s.field.clone()).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn pan_sweep_scores_density() {
        // Many Luhn-valid PANs in one body = a cardholder sweep (T3).
        let d = detector();
        let cards = [
            "4111 1111 1111 1111",
            "5500 0000 0000 0004",
            "4111-1111-1111-1111",
            "5500-0000-0000-0004",
            "4111111111111111",
            "5500000000000004",
        ];
        let body = cards.join("\n");
        let sigs = d.observe(Some("text/csv"), body.as_bytes(), false);
        assert!(
            sigs.iter().any(|s| s.tag == "egress_sensitive" && s.field.contains("pan_density")),
            "a PAN sweep must score density: {:?}",
            sigs.iter().map(|s| s.field.clone()).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn deferred_pii_shapes_do_not_score_in_v1() {
        // Emails / SSNs are in the dlp set but deferred (owner §6.2). A body
        // full of emails must NOT score in v1.
        let d = detector();
        let body = b"alice@example.com bob@example.com carol@example.com 123-45-6789";
        let sigs = d.observe(Some("text/plain"), body, false);
        assert!(sigs.is_empty(), "deferred PII must not score in v1: {sigs:?}");
    }

    #[test]
    fn clean_body_does_not_score() {
        let d = detector();
        let body = br#"{"status":"ok","items":[1,2,3]}"#;
        assert!(d.observe(Some(JSON), body, false).is_empty());
    }

    #[test]
    fn binary_content_type_not_scanned() {
        let d = detector();
        let body = b"AKIAIOSFODNN7EXAMPLE";
        assert!(d.observe(Some("application/octet-stream"), body, false).is_empty());
        assert!(d.observe(Some("image/png"), body, false).is_empty());
    }

    #[test]
    fn missing_content_type_not_scanned() {
        let d = detector();
        assert!(d.observe(None, b"AKIAIOSFODNN7EXAMPLE", false).is_empty());
    }

    #[test]
    fn scan_capped_at_max_bytes() {
        // A secret past the cap must not be seen.
        let d = SensitiveDataDetector::with_config(16, 1, 5);
        let mut body = vec![b' '; 64];
        body.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        assert!(d.observe(Some("text/plain"), &body, false).is_empty());
    }

    #[test]
    fn sampling_skips_but_always_scan_forces() {
        // sample_rate 1000 → the first call (n=0) scans, subsequent calls skip
        // (1000 ∤ n), but `always_scan=true` forces a scan every time.
        let d = SensitiveDataDetector::with_config(64 * 1024, 1000, 5);
        let body = br#"{"k":"AKIAIOSFODNN7EXAMPLE"}"#;
        // Burn the n=0 always-samples slot.
        let _ = d.observe(Some(JSON), body, false);
        // Next few sampled-out calls: no scan → no signal even though the body
        // carries a secret.
        let mut sampled_out = false;
        for _ in 0..10 {
            if d.observe(Some(JSON), body, false).is_empty() {
                sampled_out = true;
                break;
            }
        }
        assert!(sampled_out, "high sample_rate must skip some responses");
        // always_scan bypasses the sampler.
        assert!(
            !d.observe(Some(JSON), body, true).is_empty(),
            "always_scan must force the scan regardless of sampling",
        );
    }
}
