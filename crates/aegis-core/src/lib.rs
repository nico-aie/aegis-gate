// aegis-core: shared types and cross-crate contracts

pub mod audit;
pub mod break_glass;
pub mod cache;
pub mod cluster;
pub mod config;
pub mod config_backend;
pub mod context;
pub mod decision;
pub mod error;
pub mod fleet;
pub mod health;
pub mod identity;
pub mod load_mode;
pub mod normalize;
pub mod pipeline;
pub mod risk;
pub mod sd;
pub mod secrets;
pub mod state;
pub mod tcp_destination;
pub mod tier;
pub mod verbosity;

pub use audit::{AuditBus, AuditClass, AuditEvent};
pub use cache::{CacheKey, CacheProvider, CachedResponse};
pub use cluster::{ClusterMembership, Lease, LeaseHandle, LeaseStore, NodeId, NodeInfo};
pub use config::{
    load_config, load_config_str, load_dynamic_str, merge_bootstrap_keys,
    strip_legacy_bootstrap_keys, yaml_has_legacy_bootstrap_keys, BootstrapConfig,
    ConfigBroadcast, ConfigEvent, DynamicConfig, WafConfig, LEGACY_BOOTSTRAP_KEYS,
};
pub use config_backend::{
    ConfigBackend, ConfigWatch, FleetBusConfigWatch, SharedStateConfigBackend,
};
pub use context::{ClientInfo, FieldValue, RequestCtx, RouteCtx, TlsFingerprint};
pub use decision::{Action, ChallengeLevel, Decision};
pub use error::{Result, WafError};
pub use health::ReadinessSignal;
pub use identity::ClientIdentity;
pub use load_mode::{LoadGauge, LoadMode, LoadModeConfig, LoadModeSnapshot};
pub use verbosity::{LoggingConfig, SharedVerbosity, VerbosityLevel, VerbositySnapshot};
pub use pipeline::{
    BodyPeek, DetectorLimits, OutboundAction, RequestView, SecurityPipeline,
};
pub use risk::RiskKey;
pub use sd::{MemberAddr, ServiceDiscovery};
pub use secrets::{Secret, SecretProvider};
pub use state::{SlidingWindowResult, StateBackend};
pub use tier::{FailureMode, Tier};
