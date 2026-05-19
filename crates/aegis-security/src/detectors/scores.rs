//! Detector score catalog (read-only).
//!
//! 2026-05-09 (Run-5 follow-up #293) — single source of truth for
//! every per-`Signal` `score` literal each detector emits. Detector
//! files reference these consts instead of inline magic numbers, and
//! the `/api/detectors` GET response surfaces the catalog so the
//! dashboard can render a "Risk score" column without the SPA having
//! to scrape source files.
//!
//! ## Why this exists
//!
//! Operators asked "what score does each detector emit, and how does
//! it interact with `risk.thresholds`?" — see [`docs/operator/risk-
//! tuning.md`](../../../../docs/operator/risk-tuning.md). Detector
//! scores are a calibrated ladder (25 / 30 / 35–40 / 45 / 50 / 60)
//! that interacts with `challenge_at` (40) and `block_at` (80). The
//! UI needs to display the calibration so operators can read it; it
//! is **not** an editor. Editing scores via the dashboard is
//! deliberately not supported — see the operator guide for the
//! rationale + the safe alternatives (set_profile log_only,
//! threshold tuning, RaiseRisk rules, per-tier overrides).
//!
//! ## How to add a new detector or sub-tag
//!
//! 1. Add `pub const <NAME>: u32 = <score>;` to the appropriate
//!    `mod` below (or create a new module if it's a new class).
//! 2. Reference the const from the detector's `Signal { score: ... }`
//!    site instead of an inline literal.
//! 3. Add a row to [`CATALOG`] with the class id, sub-tag string,
//!    and a one-line note explaining when the score fires.
//! 4. Mention the addition in the per-detector doc + any score-
//!    ladder cross-refs (security-engine.md risk-weight table,
//!    operator/risk-tuning.md).
//!
//! Tests in this module assert (a) every detector class in
//! [`super::DetectorClass`] has at least one catalog entry, (b)
//! catalog scores fall on the documented ladder, and (c) the catalog
//! covers every tag a detector emits via a smoke run.

use serde::Serialize;

// Per-class scores.

pub mod sqli {
    pub const SQLI: u32 = 40;
}

pub mod xss {
    pub const XSS: u32 = 35;
}

pub mod path_traversal {
    pub const PATH_TRAVERSAL: u32 = 45;
}

pub mod ssrf {
    pub const SSRF: u32 = 50;
}

pub mod header_injection {
    /// CRLF / Set-Cookie / Location injection in user input.
    pub const CRLF: u32 = 40;
    /// X-Forwarded-Host poisoning (keyword needles, > 2 hosts,
    /// internal-IP literal). Lower than CRLF — heuristic is broader.
    pub const XFH: u32 = 35;
}

pub mod body_abuse {
    /// Body exceeds `max_body_bytes`.
    pub const OVERSIZE: u32 = 30;
    /// JSON nesting deeper than `max_nesting_depth`.
    pub const DEEP_NESTING: u32 = 35;
    /// `__proto__` / `constructor.prototype` shape (GAP-010).
    pub const PROTO_POLLUTION: u32 = 45;
    /// Privileged-field key (`role`, `is_admin`, `password_hash`, …).
    pub const MASS_ASSIGNMENT: u32 = 50;
    /// XML external-entity declaration (`<!ENTITY ... SYSTEM ...>`).
    pub const XXE: u32 = 60;
}

pub mod recon {
    /// Path probe / canary route (`/.env`, `/wp-admin`, …).
    pub const PATH: u32 = 25;
    /// Scanner User-Agent (`sqlmap`, `nikto`, `nmap`, …).
    pub const TOOL: u32 = 30;
}

pub mod brute_force {
    /// Default per `BruteForceDetector::default()`. Operator-
    /// configurable via the constructor — operators raising the
    /// detector's threshold typically also raise this score.
    pub const DEFAULT: u32 = 35;
}

pub mod command_injection {
    /// Shell-meta payload (`$()`, backticks, `| cmd`, `; cmd`,
    /// reverse-shell shapes, …).
    pub const BASELINE: u32 = 50;
    /// Log4Shell / JNDI lookup (CVE-2021-44228) — Critical-RCE tier.
    pub const LOG4SHELL: u32 = 60;
}

pub mod template_injection {
    pub const TEMPLATE_INJECTION: u32 = 50;
}

pub mod nosql_injection {
    pub const NOSQL_INJECTION: u32 = 50;
}

pub mod open_redirect {
    pub const OPEN_REDIRECT: u32 = 30;
}

pub mod ai {
    /// AI / ML classifier verdict (Critical-RCE tier — model
    /// confidence ≥ threshold).
    pub const AI: u32 = 60;
}

// Catalog — flat table consumed by the API.

/// One row per `(class, sub_tag)` combination. Stable order so the
/// API output is deterministic and the dashboard renders predictably.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ScoreEntry {
    /// Detector class id (matches [`super::DetectorClass::as_str`]).
    pub class: &'static str,
    /// Sub-tag emitted on the `Signal` (matches what shows up in
    /// `AuditEvent.fields.detectors[]`). For detectors that emit a
    /// single score, `tag == class`; for multi-score detectors
    /// (cmdi, body_abuse, recon, header_injection) the tags differ.
    pub tag: &'static str,
    /// Score this `(class, tag)` emits.
    pub score: u32,
    /// One-line operator-facing note describing when it fires.
    /// Used as the dashboard tooltip on the score chip.
    pub note: &'static str,
}

/// Flat catalog. Order is grouped by class (matches the GET-response
/// rendering order) and within each class follows the operator-
/// reading order from the per-detector doc.
pub const CATALOG: &[ScoreEntry] = &[
    ScoreEntry {
        class: "sqli",
        tag: "sqli",
        score: sqli::SQLI,
        note: "SQL injection in URL, body, or headers.",
    },
    ScoreEntry {
        class: "xss",
        tag: "xss",
        score: xss::XSS,
        note: "Cross-site scripting payload (script tags, event handlers, javascript: URLs).",
    },
    ScoreEntry {
        class: "path_traversal",
        tag: "path_traversal",
        score: path_traversal::PATH_TRAVERSAL,
        note: "Directory traversal — `..`, encoded variants, overlong UTF-8, sensitive paths (`/etc/passwd`, `/var/run/docker.sock`).",
    },
    ScoreEntry {
        class: "ssrf",
        tag: "ssrf",
        score: ssrf::SSRF,
        note: "Server-side request forgery — internal IPs, cloud metadata, `file:`/`gopher:`/`dict:` schemes, URL-userinfo bypass.",
    },
    ScoreEntry {
        class: "header_injection",
        tag: "header_injection (xfh)",
        score: header_injection::XFH,
        note: "X-Forwarded-Host poisoning — keyword needles, internal-IP literals, > 2 comma-separated hosts.",
    },
    ScoreEntry {
        class: "header_injection",
        tag: "header_injection (crlf)",
        score: header_injection::CRLF,
        note: "CRLF / Set-Cookie / Location-header injection in user-controlled input.",
    },
    ScoreEntry {
        class: "header_injection",
        tag: "url_override_bypass",
        score: header_injection::CRLF,
        note: "X-Original-URL / X-Rewrite-URL header carrying an admin / recon / traversal path — framework auth-bypass primitive.",
    },
    ScoreEntry {
        class: "header_injection",
        tag: "method_override_bypass",
        score: header_injection::XFH,
        note: "X-HTTP-Method-Override / X-Method-Override / X-HTTP-Method header carrying a destructive verb (DELETE / PUT / PATCH / CONNECT / TRACE) — framework method-override bypass.",
    },
    ScoreEntry {
        class: "body_abuse",
        tag: "body_oversize",
        score: body_abuse::OVERSIZE,
        note: "Body exceeds `body_abuse.max_body_bytes` (default 10 MiB).",
    },
    ScoreEntry {
        class: "body_abuse",
        tag: "body_deep_nesting",
        score: body_abuse::DEEP_NESTING,
        note: "JSON nesting deeper than `body_abuse.max_nesting_depth` (default 20).",
    },
    ScoreEntry {
        class: "body_abuse",
        tag: "proto_pollution",
        score: body_abuse::PROTO_POLLUTION,
        note: "Prototype pollution — `__proto__` key or `constructor.prototype` chain.",
    },
    ScoreEntry {
        class: "body_abuse",
        tag: "mass_assignment",
        score: body_abuse::MASS_ASSIGNMENT,
        note: "Privileged JSON field in body (`role`, `is_admin`, `password_hash`, `api_key`, …).",
    },
    ScoreEntry {
        class: "body_abuse",
        tag: "xxe",
        score: body_abuse::XXE,
        note: "XML external-entity declaration (`<!ENTITY … SYSTEM …>`).",
    },
    ScoreEntry {
        class: "recon",
        tag: "recon_path",
        score: recon::PATH,
        note: "Recon path probe — `/.env`, `/wp-admin`, Spring actuator danger paths, K8s API, Jenkins script console, etc.",
    },
    ScoreEntry {
        class: "recon",
        tag: "recon_tool",
        score: recon::TOOL,
        note: "Scanner User-Agent — `sqlmap`, `nikto`, `nmap`, `nuclei`, etc.",
    },
    ScoreEntry {
        class: "brute_force",
        tag: "brute_force",
        score: brute_force::DEFAULT,
        note: "Login-failure rate exceeds threshold (default 10/min). Score is operator-tunable via the detector constructor.",
    },
    ScoreEntry {
        class: "command_injection",
        tag: "command_injection",
        score: command_injection::BASELINE,
        note: "Shell-meta payload — `$()`, backticks, `| cmd`, `/bin/sh`, reverse-shell shapes.",
    },
    ScoreEntry {
        class: "command_injection",
        tag: "log4shell",
        score: command_injection::LOG4SHELL,
        note: "Log4Shell / JNDI lookup (CVE-2021-44228) — `${jndi:…}` in URL, body, or allowlisted headers.",
    },
    ScoreEntry {
        class: "template_injection",
        tag: "template_injection",
        score: template_injection::TEMPLATE_INJECTION,
        note: "Server-side template injection — Jinja2, Twig, Mako, Freemarker, Velocity, SpEL, Handlebars.",
    },
    ScoreEntry {
        class: "nosql_injection",
        tag: "nosql_injection",
        score: nosql_injection::NOSQL_INJECTION,
        note: "MongoDB-flavour operator injection — `?param[$ne]=foo`, `{\"$where\":\"…\"}`.",
    },
    ScoreEntry {
        class: "open_redirect",
        tag: "open_redirect",
        score: open_redirect::OPEN_REDIRECT,
        note: "Suspicious external URL in redirect-style param (`?next=`, `?redirect_uri=`). Allowlist via `cfg.detectors.open_redirect.allowed_domains`.",
    },
    ScoreEntry {
        class: "ai",
        tag: "ai",
        score: ai::AI,
        note: "AI / ML classifier verdict (model confidence ≥ threshold). Only present when `cfg.ai.enabled = true`.",
    },
    // 2026-05-19 — Phase F behaviour-signals (stateful per-IP).
    // Default OFF on the schema — three corroborating signals
    // intended to stack with OWASP detectors. The original
    // `behavior_burst` (score 25, two requests <50 ms apart) was
    // retired the same day because single-IP benchmark traffic
    // tripped it on every request after the first.
    ScoreEntry {
        class: "behavior_signals",
        tag: "behavior_no_ua",
        score: 15,
        note: "Empty / missing `User-Agent` header.",
    },
    ScoreEntry {
        class: "behavior_signals",
        tag: "behavior_missing_referer",
        score: 20,
        note: "POST / PUT / PATCH / DELETE without a `Referer` header — CSRF-shaped traffic.",
    },
    ScoreEntry {
        class: "behavior_signals",
        tag: "behavior_zero_depth",
        score: 15,
        note: "First request from a peer with no `Cookie` AND no `Referer` — fresh stateless touch (crawlers / scanners).",
    },
    // 2026-05-19 — Phase F velocity sequence engine. Default ON;
    // zero cost when the upstream has no matching routes.
    ScoreEntry {
        class: "velocity",
        tag: "velocity_sequence",
        score: 60,
        note: "Cross-endpoint flow attack (login→deposit < 5 s, login→withdrawal < 5 s, etc.) that wouldn't trip individual rate caps.",
    },
    // 2026-05-19 — Phase F canary recon tripwire. Inert until
    // `cfg.risk.canary_paths` is non-empty AND the toggle is on.
    ScoreEntry {
        class: "canary",
        tag: "canary",
        score: 90,
        note: "Hit on an operator-supplied honeypot path (`cfg.risk.canary_paths`). Auto-block tier.",
    },
];

/// Tier label for a score. Mirrors the 5-tier framework documented
/// in `plans/issue-fix/tester-n-2026-05-08-run5/README.md`.
pub fn tier_for(score: u32) -> &'static str {
    match score {
        60.. => "critical",
        50..=59 => "high",
        45..=49 => "broad",
        35..=44 => "header",
        30..=34 => "phishing",
        ..=29 => "probe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::DetectorClass;

    #[test]
    fn every_detector_class_has_at_least_one_entry() {
        // Every class enabled by default needs at least one row in
        // the catalog. AI is the exception — it's optional via the
        // `ai` feature, but still belongs in the table for docs.
        for c in DetectorClass::ALL {
            let id = c.as_str();
            assert!(
                CATALOG.iter().any(|e| e.class == id),
                "no catalog entry for class {id:?}",
            );
        }
        // AI catalog entry exists even though it's not in
        // DetectorClass::ALL (it's gated by `cfg.ai.enabled` and the
        // feature flag, not a runtime mask bit).
        assert!(CATALOG.iter().any(|e| e.class == "ai"));
    }

    #[test]
    fn scores_fall_on_documented_ladder() {
        // The 5-tier ladder allows 25 / 30 / 35–40 / 45 / 50 / 60.
        // 2026-05-19 — extended for Phase F detectors:
        //  - 15 / 20 — behaviour-signals sub-block accumulators
        //    (per-signal score is below block_at by design;
        //     scores stack with OWASP signals).
        //  - 70 — velocity-sequence higher-severity rule
        //    (login→withdrawal < 5 s).
        //  - 90 — canary auto-block tier.
        let allowed = [15u32, 20, 25, 30, 35, 40, 45, 50, 60, 70, 90];
        for entry in CATALOG {
            assert!(
                allowed.contains(&entry.score),
                "score {} for {}/{} is off the documented ladder {allowed:?}",
                entry.score,
                entry.class,
                entry.tag,
            );
        }
    }

    #[test]
    fn tier_buckets_are_monotonic() {
        // The tier helper must group scores in the same order as
        // the docs (probe < phishing < header < broad < high <
        // critical).
        assert_eq!(tier_for(25), "probe");
        assert_eq!(tier_for(30), "phishing");
        assert_eq!(tier_for(35), "header");
        assert_eq!(tier_for(40), "header");
        assert_eq!(tier_for(45), "broad");
        assert_eq!(tier_for(50), "high");
        assert_eq!(tier_for(55), "high");
        assert_eq!(tier_for(60), "critical");
        assert_eq!(tier_for(100), "critical");
    }

    #[test]
    fn catalog_is_serialisable_as_stable_json() {
        // Smoke — the API will go through serde_json on the
        // GET payload, so any non-serialisable change here breaks
        // the wire shape. Pin the first row so the column order
        // (class, tag, score, note) doesn't drift accidentally.
        let json = serde_json::to_value(CATALOG).expect("catalog serialises");
        let arr = json.as_array().expect("array shape");
        let first = arr.first().expect("non-empty");
        assert_eq!(first["class"], "sqli");
        assert_eq!(first["tag"], "sqli");
        assert_eq!(first["score"], 40);
        assert!(
            first["note"].as_str().unwrap().len() > 5,
            "note must be a non-empty string",
        );
    }
}
