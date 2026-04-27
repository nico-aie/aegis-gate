//! `/api/whitelist` (D-M4-T4.5..T4.6).
//!
//! Re-exports the shared access-list types from [`super::blacklist`]
//! and provides a `WhitelistStore` alias so the proxy can dispatch
//! to a separate instance with whitelist-specific compliance clamps.

pub use super::blacklist::{
    AccessListEntry, AccessListStore as WhitelistStore, BulkOutcome, BulkResponse,
    ComplianceClamp, ListResponse,
};
