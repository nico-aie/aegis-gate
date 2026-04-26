// aegis-security: security pipeline (M2)
//
// Owns: rule engine, rate limiter, DDoS, attack detectors,
//       risk scoring, challenge ladder, device fingerprinting,
//       IP reputation, bot management, DLP, API guard, content scan.

pub mod api_security;
pub mod auth;
pub mod behavior;
pub mod bots;
pub mod challenge;
pub mod content;
pub mod ddos;
pub mod detectors;
pub mod dlp;
pub mod fingerprint;
pub mod ip_rep;
pub mod noop;
pub mod pipeline;
pub mod rate_limit;
pub mod response_filter;
pub mod risk;
pub mod rules;
pub mod threat_intel;
pub mod velocity;

pub use noop::NoopPipeline;
pub use pipeline::{classify_tier, Pipeline};
pub use rules::RuleSet;
