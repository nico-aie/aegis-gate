// aegis-security: security pipeline (M2)
//
// Owns: rule engine, rate limiter, DDoS, attack detectors,
//       risk scoring, challenge ladder, device fingerprinting,
//       IP reputation, bot management, DLP, API guard, content scan.

pub mod noop;
pub mod pipeline;
pub mod rules;

pub use noop::NoopPipeline;
pub use pipeline::{classify_tier, Pipeline};
pub use rules::RuleSet;

// Future modules:
// pub mod rate_limit;
// pub mod ddos;
// pub mod detectors;
// pub mod risk;
// pub mod challenge;
// pub mod fingerprint;
// pub mod ip_rep;
// pub mod bots;
// pub mod dlp;
// pub mod api_security;
// pub mod content;
// pub mod auth;
