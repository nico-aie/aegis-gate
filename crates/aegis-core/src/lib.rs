// aegis-core: shared types and cross-crate contracts

pub mod audit;
pub mod cache;
pub mod cluster;
pub mod config;
pub mod context;
pub mod decision;
pub mod error;
pub mod health;
pub mod pipeline;
pub mod risk;
pub mod sd;
pub mod secrets;
pub mod state;
pub mod tier;

pub use audit::{AuditBus, AuditClass, AuditEvent};
pub use cache::{CacheKey, CacheProvider, CachedResponse};
pub use cluster::{ClusterMembership, Lease, NodeInfo};
pub use config::{load_config, load_config_str, ConfigBroadcast, ConfigEvent, WafConfig};
pub use context::{ClientInfo, FieldValue, RequestCtx, RouteCtx, TlsFingerprint};
pub use decision::{Action, ChallengeLevel, Decision};
pub use error::{Result, WafError};
pub use health::ReadinessSignal;
pub use pipeline::{
    BodyPeek, DetectorLimits, OutboundAction, RequestView, SecurityPipeline,
};
pub use risk::RiskKey;
pub use sd::{MemberAddr, ServiceDiscovery};
pub use secrets::{Secret, SecretProvider};
pub use state::{SlidingWindowResult, StateBackend};
pub use tier::{FailureMode, Tier};
