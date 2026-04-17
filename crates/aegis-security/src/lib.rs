// aegis-security: security pipeline (M2)
//
// Owns: rule engine, rate limiter, DDoS, attack detectors,
//       risk scoring, challenge ladder, device fingerprinting,
//       IP reputation, bot management, DLP, API guard, content scan.

pub mod noop;

pub use noop::NoopPipeline;

// Future modules (stubs):
// pub mod rules;
// pub mod ratelimit;
// pub mod ddos;
// pub mod detect;
// pub mod risk;
// pub mod challenge;
// pub mod fingerprint;
// pub mod reputation;
// pub mod bot;
// pub mod dlp;
// pub mod apiguard;
// pub mod scan;
// pub mod auth;
