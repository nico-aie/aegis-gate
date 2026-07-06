pub mod password;
pub mod session;
pub mod csrf;
pub mod rate_limit;
pub mod totp;
pub mod totp_store;
pub mod account_store;
// 2026-05-17 F-CRITICAL-009 (control audit): `admin_auth::mtls`
// deleted — `verify_client_cert` had zero production callers
// (the live TLS-handshake-layer mTLS lives in
// `crates/aegis-proxy/src/listener/tls.rs`). The unrelated
// `api::zero_trust::downstream::MtlsConfigView` (the dashboard's config-rendering
// view) is unaffected.
// pub mod mtls;
