pub mod bucket;
pub mod ip_limiter;
pub mod sliding;

// Both `ip_limiter` and `sliding` define a `RateDecision`
// type; the distributed `sliding::RateDecision` is the
// pre-existing public name. Re-export the new in-memory
// per-IP one under a disambiguated name so the proxy can
// pick whichever fits.
pub use ip_limiter::{
    IpRateLimitConfig, IpRateLimiter, RateDecision as IpRateDecision,
};

pub use bucket::take as bucket_take;
pub use sliding::{build_key as sliding_key, check as sliding_check, RateDecision};
