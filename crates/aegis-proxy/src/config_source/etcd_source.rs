//! ETCD-T1 — load `WafConfig` from etcd v3 instead of a YAML file.
//!
//! ## Wire shape
//!
//! The etcd value at `key` (default `/aegis/config/waf`) is the
//! same YAML document the file loader accepts — verbatim. The
//! loader fetches the key via `/v3/kv/range` (single-key range
//! `[key, key+1)`), base64-decodes the value, and feeds the
//! result through `aegis_core::load_config_str` so the same
//! validation runs.
//!
//! ## Why range-poll, not gRPC Watch
//!
//! Same trade-off as `sd::etcd` — a streaming Watch RPC would
//! drag `tonic` + `prost` into the dep tree for one call. The
//! REST gateway covers the same ground at the cost of up to
//! `poll_interval` extra latency on a config change. Operators
//! who need <5 s reload latency can drop the interval; those
//! who want push-style updates can use the file source with a
//! sidecar that writes the YAML.
//!
//! ## Auth + TLS
//!
//! Token auth + mTLS reuse the same env vars as `sd::etcd`
//! (`AEGIS_ETCD_USER` / `_PASSWORD` / `_CA_CERT_PATH` /
//! `_CLIENT_CERT_PATH` / `_CLIENT_KEY_PATH`) so an operator
//! configuring etcd for SD picks up config-from-etcd for free.
//! Per-source overrides (`AEGIS_CONFIG_ETCD_*`) take precedence
//! when set.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine;
use serde::{Deserialize, Serialize};

use aegis_core::audit::{AuditBus, AuditClass, AuditEvent};
use aegis_core::config::WafConfig;

/// Default key holding the YAML blob.
pub const DEFAULT_KEY: &str = "/aegis/config/waf";

/// Default poll interval for the watcher loop.
const DEFAULT_POLL_MS: u64 = 5_000;

/// Backoff bounds for transient errors.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// HTTP timeout for a single round-trip.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolved etcd config-source settings.
///
/// Constructed from environment via [`EtcdConfigSource::from_env`].
/// All fields are public for tests; in production paths use the
/// constructor.
#[derive(Debug, Clone)]
pub struct EtcdConfigSource {
    pub endpoints: Vec<String>,
    pub key: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub poll_interval: Duration,
}

impl EtcdConfigSource {
    /// Build from environment.
    ///
    /// `AEGIS_CONFIG_ETCD_*` overrides take precedence over the
    /// shared `AEGIS_ETCD_*` vars so operators can run the SD
    /// watcher against one cluster and config-from-etcd against
    /// another. Defaults: `http://127.0.0.1:2379` /
    /// [`DEFAULT_KEY`] / 5 s poll interval.
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Build from an arbitrary lookup function. Pure — useful
    /// for tests that don't want to mutate process-wide env
    /// vars (which races against `sd::etcd::tests`).
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let first = |keys: &[&str]| first_non_empty(keys, &lookup);

        let endpoints = first(&[
            "AEGIS_CONFIG_ETCD_ENDPOINTS",
            "AEGIS_ETCD_ENDPOINTS",
        ])
        .map(|s| {
            s.split(',')
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["http://127.0.0.1:2379".to_string()]);

        let key = first(&["AEGIS_CONFIG_ETCD_KEY"])
            .unwrap_or_else(|| DEFAULT_KEY.to_string());

        let poll_interval = first(&[
            "AEGIS_CONFIG_ETCD_POLL_INTERVAL_MS",
            "AEGIS_ETCD_POLL_INTERVAL_MS",
        ])
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_POLL_MS));

        Self {
            endpoints,
            key,
            user: first(&["AEGIS_CONFIG_ETCD_USER", "AEGIS_ETCD_USER"]),
            password: first(&[
                "AEGIS_CONFIG_ETCD_PASSWORD",
                "AEGIS_ETCD_PASSWORD",
            ]),
            ca_cert_path: first(&[
                "AEGIS_CONFIG_ETCD_CA_CERT_PATH",
                "AEGIS_ETCD_CA_CERT_PATH",
            ]),
            client_cert_path: first(&[
                "AEGIS_CONFIG_ETCD_CLIENT_CERT_PATH",
                "AEGIS_ETCD_CLIENT_CERT_PATH",
            ]),
            client_key_path: first(&[
                "AEGIS_CONFIG_ETCD_CLIENT_KEY_PATH",
                "AEGIS_ETCD_CLIENT_KEY_PATH",
            ]),
            poll_interval,
        }
    }

    /// Fetch the YAML blob at [`Self::key`] and decode it through
    /// `aegis_core::load_config_str`. Returns the validated
    /// [`WafConfig`] ready to wrap in an `Arc`.
    pub async fn load(&self) -> Result<WafConfig, EtcdLoadError> {
        let http = build_client(self).map_err(EtcdLoadError::Transport)?;
        let yaml = fetch_key(&http, self, None)
            .await
            .map_err(|e| match e {
                FetchError::Auth(m) => EtcdLoadError::Auth(m),
                FetchError::Transient(m) => EtcdLoadError::Transport(m),
                FetchError::Missing => EtcdLoadError::MissingKey(self.key.clone()),
            })?
            .0;

        aegis_core::load_config_str(&yaml).map_err(|e| EtcdLoadError::Decode(e.to_string()))
    }
}

/// Error returned by [`EtcdConfigSource::load`].
#[derive(Debug)]
pub enum EtcdLoadError {
    Transport(String),
    Auth(String),
    MissingKey(String),
    Decode(String),
}

impl std::fmt::Display for EtcdLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "etcd transport: {m}"),
            Self::Auth(m) => write!(f, "etcd auth: {m}"),
            Self::MissingKey(k) => write!(f, "etcd key {k:?} is empty or absent"),
            Self::Decode(m) => write!(f, "config decode: {m}"),
        }
    }
}

impl std::error::Error for EtcdLoadError {}

/// Spawn a background task that polls [`Self::key`] every
/// [`Self::poll_interval`] and atomic-swaps `cfg` when the value
/// changes. On parse / validate failure the previous config
/// stays loaded and an `AuditClass::Admin` event is emitted with
/// `action: config_reload_failed`. On a successful reload the
/// event has `action: config_reload`.
///
/// `detector_mask`, when supplied, is re-derived from
/// `new_cfg.detectors` after every successful reload and run
/// through the compliance clamp via the shared
/// [`crate::config_source::reload::apply_cfg_change_to_mask`]
/// helper. Symmetrical with the file-watcher path so the same
/// guarantees hold for both sources. Pass `None` for tests that
/// don't have a mask in scope.
///
/// `proxy_ctx`, when supplied, gets its `route_table` rebuilt
/// from `new_cfg.routes` via
/// [`crate::config_source::reload::apply_cfg_change_to_routes`]
/// — same hot-swap contract as the file watcher.
///
/// `ip_rate_limiter`, when supplied, has its config re-derived
/// from `new_cfg.rate_limit.buckets` via
/// [`crate::config_source::reload::apply_cfg_change_to_rate_limit`]
/// — preserves per-IP timestamp state across the swap.
///
/// `tls_resolver`, when supplied, has its `CertStore` rebuilt
/// from `new_cfg.tls.certificates` via
/// [`crate::config_source::reload::apply_cfg_change_to_tls`]
/// — symmetrical with the file watcher's tls path.
///
/// The watcher exits when `cfg`'s last strong reference is
/// dropped — wrap it in an `Arc<ArcSwap<…>>` you also keep alive
/// in the proxy runtime.
#[allow(clippy::too_many_arguments)]
pub fn spawn_watcher(
    src: EtcdConfigSource,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    // 2026-05-28 (Phase B fold parity) — folded-store handles so an
    // etcd-delivered config re-derives them too (parity with the redis
    // config-plane watcher).
    folded: crate::config_source::reload::FoldedReloadTargets,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = watch_loop(
            src,
            cfg,
            bus,
            detector_mask,
            proxy_ctx,
            ip_rate_limiter,
            tls_resolver,
            folded,
        )
        .await
        {
            tracing::error!(error = %e, "etcd config watcher exited");
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn watch_loop(
    src: EtcdConfigSource,
    cfg: Arc<ArcSwap<WafConfig>>,
    bus: AuditBus,
    detector_mask: Option<aegis_security::detectors::SharedDetectorMask>,
    proxy_ctx: Option<Arc<crate::proxy::ProxyContext>>,
    ip_rate_limiter: Option<Arc<aegis_security::rate_limit::IpRateLimiter>>,
    tls_resolver: Option<Arc<crate::listener::tls::DynamicResolver>>,
    folded: crate::config_source::reload::FoldedReloadTargets,
) -> Result<(), String> {
    let http = build_client(&src)?;
    let mut last_yaml: Option<String> = None;
    let mut auth_token: Option<String> = None;
    let mut backoff = BACKOFF_MIN;

    tracing::info!(
        endpoints = ?src.endpoints,
        key = %src.key,
        poll_interval_ms = src.poll_interval.as_millis() as u64,
        "etcd config watcher started",
    );

    loop {
        match fetch_key(&http, &src, auth_token.as_deref()).await {
            Ok((yaml, refreshed_token)) => {
                if let Some(t) = refreshed_token {
                    auth_token = Some(t);
                }
                backoff = BACKOFF_MIN;

                if last_yaml.as_deref() == Some(yaml.as_str()) {
                    tokio::time::sleep(src.poll_interval).await;
                    continue;
                }

                match aegis_core::load_config_str(&yaml) {
                    Ok(new_cfg) => {
                        // Symmetrical with the file watcher: re-derive the
                        // detector base from the new cfg, run the compliance
                        // clamp, and emit a `compliance_clamp_applied` event
                        // when the clamp had to force classes back on.
                        if let crate::config_source::reload::ReloadOutcome::AppliedWithCompliance {
                            forced,
                        } = crate::config_source::reload::apply_cfg_change_to_mask(
                            &new_cfg,
                            detector_mask.as_ref(),
                        ) {
                            tracing::warn!(
                                key = %src.key,
                                forced = ?forced,
                                "etcd config reload: cfg.detectors had classes disabled that compliance modes pin to ON; forcing them back on",
                            );
                            bus.emit(AuditEvent {
                                schema_version: 1,
                                ts: chrono::Utc::now(),
                                request_id: String::new(),
                                class: AuditClass::Admin,
                                tenant_id: None,
                                tier: None,
                                action: "compliance_clamp_applied".into(),
                                reason: format!(
                                    "etcd config reload forced classes back on: {}",
                                    forced.join(", "),
                                ),
                                client_ip: String::new(),
                                route_id: None,
                                rule_id: None,
                                risk_score: None,
                                method: None,
                                path: None,
                                mode: None,
                                fields: serde_json::json!({
                                    "source": "etcd",
                                    "key": src.key,
                                    "forced": forced,
                                }),
                            });
                        }

                        // Symmetrical with the file watcher:
                        // rebuild + atomic-swap the route table
                        // from `new_cfg.routes`. Validation
                        // failure leaves the live table intact.
                        if let crate::config_source::reload::RouteReloadOutcome::Failed {
                            reason,
                        } = crate::config_source::reload::apply_cfg_change_to_routes(
                            &new_cfg,
                            proxy_ctx.as_ref(),
                        ) {
                            tracing::error!(
                                key = %src.key,
                                reason = %reason,
                                "etcd config reload: route table rebuild failed; live routes unchanged",
                            );
                            bus.emit(AuditEvent {
                                schema_version: 1,
                                ts: chrono::Utc::now(),
                                request_id: String::new(),
                                class: AuditClass::Admin,
                                tenant_id: None,
                                tier: None,
                                action: "routes_reload_failed".into(),
                                reason: reason.clone(),
                                client_ip: String::new(),
                                route_id: None,
                                rule_id: None,
                                risk_score: None,
                                method: None,
                                path: None,
                                mode: None,
                                fields: serde_json::json!({
                                    "source": "etcd",
                                    "key": src.key,
                                    "reason": reason,
                                }),
                            });
                        }

                        // Rate-limit hot-reload — re-derive the
                        // IP limiter cfg from `new_cfg.rate_limit.buckets`.
                        if let crate::config_source::reload::RateLimitReloadOutcome::Applied {
                            limit,
                            window_secs,
                        } = crate::config_source::reload::apply_cfg_change_to_rate_limit(
                            &new_cfg,
                            ip_rate_limiter.as_ref(),
                        ) {
                            tracing::info!(
                                key = %src.key,
                                limit,
                                window_secs,
                                "etcd config reload: ip rate-limit cfg swapped",
                            );
                            bus.emit(AuditEvent {
                                schema_version: 1,
                                ts: chrono::Utc::now(),
                                request_id: String::new(),
                                class: AuditClass::Admin,
                                tenant_id: None,
                                tier: None,
                                action: "rate_limit_reloaded".into(),
                                reason: format!(
                                    "ip rate-limit reloaded: {limit} per {window_secs}s",
                                ),
                                client_ip: String::new(),
                                route_id: None,
                                rule_id: None,
                                risk_score: None,
                                method: None,
                                path: None,
                                mode: None,
                                fields: serde_json::json!({
                                    "source": "etcd",
                                    "key": src.key,
                                    "limit": limit,
                                    "window_secs": window_secs,
                                }),
                            });
                        }

                        // TLS cert hot-reload — symmetrical with
                        // the file watcher.
                        match crate::config_source::reload::apply_cfg_change_to_tls(
                            &new_cfg,
                            tls_resolver.as_ref(),
                        ) {
                            crate::config_source::reload::TlsReloadOutcome::NoResolver
                            | crate::config_source::reload::TlsReloadOutcome::SkippedEmpty => {}
                            crate::config_source::reload::TlsReloadOutcome::Applied {
                                cert_count,
                            } => {
                                tracing::info!(
                                    key = %src.key,
                                    cert_count,
                                    "etcd config reload: tls cert store swapped",
                                );
                                bus.emit(AuditEvent {
                                    schema_version: 1,
                                    ts: chrono::Utc::now(),
                                    request_id: String::new(),
                                    class: AuditClass::Admin,
                                    tenant_id: None,
                                    tier: None,
                                    action: "tls_reloaded".into(),
                                    reason: format!(
                                        "tls cert store rebuilt with {cert_count} certificate(s)",
                                    ),
                                    client_ip: String::new(),
                                    route_id: None,
                                    rule_id: None,
                                    risk_score: None,
                                    method: None,
                                    path: None,
                                    mode: None,
                                    fields: serde_json::json!({
                                        "source": "etcd",
                                        "key": src.key,
                                        "cert_count": cert_count,
                                    }),
                                });
                            }
                            crate::config_source::reload::TlsReloadOutcome::Failed { reason } => {
                                tracing::error!(
                                    key = %src.key,
                                    reason = %reason,
                                    "etcd config reload: tls cert load failed; live certs unchanged",
                                );
                                bus.emit(AuditEvent {
                                    schema_version: 1,
                                    ts: chrono::Utc::now(),
                                    request_id: String::new(),
                                    class: AuditClass::Admin,
                                    tenant_id: None,
                                    tier: None,
                                    action: "tls_reload_failed".into(),
                                    reason: reason.clone(),
                                    client_ip: String::new(),
                                    route_id: None,
                                    rule_id: None,
                                    risk_score: None,
                                    method: None,
                                    path: None,
                                    mode: None,
                                    fields: serde_json::json!({
                                        "source": "etcd",
                                        "key": src.key,
                                        "reason": reason,
                                    }),
                                });
                            }
                        }

                        // 2026-05-28 (Phase B fold parity) — re-derive
                        // the folded stores (AI / response-filter / tiers
                        // / rules / upstream pools) from the etcd-delivered
                        // config, matching the redis config-plane watcher.
                        crate::config_source::reload::apply_folded_stores(&new_cfg, &folded).await;
                        cfg.store(Arc::new(new_cfg));
                        last_yaml = Some(yaml);
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "config_reload".into(),
                            reason: "etcd value changed".into(),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({"source": "etcd", "key": src.key}),
                        });
                        tracing::info!(key = %src.key, "config reloaded from etcd");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            key = %src.key,
                            "etcd config reload failed; keeping previous",
                        );
                        bus.emit(AuditEvent {
                            schema_version: 1,
                            ts: chrono::Utc::now(),
                            request_id: String::new(),
                            class: AuditClass::Admin,
                            tenant_id: None,
                            tier: None,
                            action: "config_reload_failed".into(),
                            reason: format!("{e}"),
                            client_ip: String::new(),
                            route_id: None,
                            rule_id: None,
                            risk_score: None,
                            method: None,
                            path: None,
                            mode: None,
                            fields: serde_json::json!({"source": "etcd", "key": src.key}),
                        });
                    }
                }
                tokio::time::sleep(src.poll_interval).await;
            }
            Err(FetchError::Missing) => {
                tracing::warn!(
                    key = %src.key,
                    "etcd config key missing; keeping previous config",
                );
                tokio::time::sleep(src.poll_interval).await;
            }
            Err(FetchError::Auth(msg)) => {
                return Err(format!("etcd auth error: {msg}"));
            }
            Err(FetchError::Transient(msg)) => {
                tracing::debug!(
                    error = %msg,
                    backoff_ms = backoff.as_millis() as u64,
                    "etcd config fetch transient error; backing off",
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

#[derive(Debug)]
enum FetchError {
    Auth(String),
    Transient(String),
    Missing,
}

/// Run one range-query for `src.key` and return the decoded YAML
/// string. Returns `Missing` when etcd answers but `kvs` is
/// empty (key absent).
async fn fetch_key(
    http: &reqwest::Client,
    src: &EtcdConfigSource,
    cached_token: Option<&str>,
) -> Result<(String, Option<String>), FetchError> {
    let mut current_token = cached_token.map(|s| s.to_string());
    let refreshed_token = if current_token.is_none()
        && src.user.is_some()
        && src.password.is_some()
    {
        let token = authenticate(http, src).await?;
        current_token = Some(token.clone());
        Some(token)
    } else {
        None
    };

    let endpoint = src
        .endpoints
        .first()
        .ok_or_else(|| FetchError::Transient("no endpoints configured".into()))?;
    let url = format!("{}/v3/kv/range", endpoint.trim_end_matches('/'));

    let body = RangeRequest {
        key: base64::engine::general_purpose::STANDARD.encode(src.key.as_bytes()),
        range_end: base64::engine::general_purpose::STANDARD
            .encode(prefix_to_range_end(&src.key)),
    };

    let mut req = http.post(&url).json(&body);
    if let Some(token) = &current_token {
        req = req.header("Authorization", token);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| FetchError::Transient(format!("transport: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        let body = resp.text().await.unwrap_or_default();
        return Err(FetchError::Auth(format!("etcd returned {status}: {body}")));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(FetchError::Transient(format!(
            "etcd returned {status}: {body}"
        )));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| FetchError::Transient(format!("read body: {e}")))?;

    match parse_range_value(&body) {
        Ok(Some(yaml)) => Ok((yaml, refreshed_token)),
        Ok(None) => Err(FetchError::Missing),
        Err(e) => Err(FetchError::Transient(format!("parse: {e}"))),
    }
}

async fn authenticate(
    http: &reqwest::Client,
    src: &EtcdConfigSource,
) -> Result<String, FetchError> {
    let endpoint = src
        .endpoints
        .first()
        .ok_or_else(|| FetchError::Transient("no endpoints configured".into()))?;
    let url = format!("{}/v3/auth/authenticate", endpoint.trim_end_matches('/'));

    let body = AuthRequest {
        name: src.user.clone().unwrap_or_default(),
        password: src.password.clone().unwrap_or_default(),
    };
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| FetchError::Transient(format!("auth transport: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(FetchError::Auth(format!(
            "etcd /authenticate returned {status}: {body}"
        )));
    }
    let parsed: AuthResponse = resp
        .json()
        .await
        .map_err(|e| FetchError::Auth(format!("auth response not JSON: {e}")))?;
    Ok(parsed.token)
}

/// Pure: parse an etcd v3 range response and return the decoded
/// UTF-8 value, or `Ok(None)` when the key is absent.
pub fn parse_range_value(body: &str) -> Result<Option<String>, String> {
    let parsed: RangeResponse =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Some(kvs) = parsed.kvs else {
        return Ok(None);
    };
    let Some(kv) = kvs.into_iter().next() else {
        return Ok(None);
    };
    let value_bytes = base64::engine::general_purpose::STANDARD
        .decode(kv.value.as_bytes())
        .map_err(|e| format!("value base64 decode: {e}"))?;
    let value_str = std::str::from_utf8(&value_bytes)
        .map_err(|e| format!("value not UTF-8: {e}"))?;
    Ok(Some(value_str.to_string()))
}

/// Open-end byte sequence for a single-key range. Same algorithm
/// as `sd::etcd::prefix_to_range_end`, copied for readability.
fn prefix_to_range_end(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return bytes;
        }
        bytes.pop();
    }
    Vec::new()
}

fn build_client(src: &EtcdConfigSource) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(HTTP_TIMEOUT);

    if let Some(ca_path) = &src.ca_cert_path {
        let pem = std::fs::read(ca_path)
            .map_err(|e| format!("reading CA cert {ca_path}: {e}"))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("parsing CA at {ca_path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_path), Some(key_path)) =
        (&src.client_cert_path, &src.client_key_path)
    {
        let mut combined = std::fs::read(cert_path)
            .map_err(|e| format!("reading client cert {cert_path}: {e}"))?;
        let mut key_pem = std::fs::read(key_path)
            .map_err(|e| format!("reading client key {key_path}: {e}"))?;
        combined.extend_from_slice(b"\n");
        combined.append(&mut key_pem);
        let identity = reqwest::Identity::from_pem(&combined)
            .map_err(|e| format!("parsing client identity: {e}"))?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

/// Pure: scan `keys` in order and return the first non-empty
/// value the lookup yields. Empty strings are treated as unset
/// so a `KEY=` (empty) export doesn't shadow a non-empty
/// fallback later in the list.
fn first_non_empty<F>(keys: &[&str], lookup: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    for k in keys {
        if let Some(v) = lookup(k) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[derive(Serialize)]
struct RangeRequest {
    key: String,
    range_end: String,
}

#[derive(Deserialize)]
struct RangeResponse {
    #[serde(default)]
    kvs: Option<Vec<KeyValue>>,
}

#[derive(Deserialize)]
struct KeyValue {
    #[allow(dead_code)]
    key: String,
    value: String,
}

#[derive(Serialize)]
struct AuthRequest {
    name: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build a pure lookup over `pairs`. `None` values mean the
    /// var is unset; `Some("")` means it's set-but-empty (which
    /// `from_lookup` treats as unset).
    fn lookup(pairs: &[(&str, Option<&str>)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, Option<String>> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(|s| s.to_string())))
            .collect();
        move |k: &str| map.get(k).cloned().unwrap_or(None)
    }

    #[test]
    fn defaults_when_no_env() {
        let src = EtcdConfigSource::from_lookup(lookup(&[]));
        assert_eq!(src.endpoints, vec!["http://127.0.0.1:2379".to_string()]);
        assert_eq!(src.key, DEFAULT_KEY);
        assert!(src.user.is_none());
        assert!(src.password.is_none());
        assert_eq!(src.poll_interval, Duration::from_millis(DEFAULT_POLL_MS));
    }

    #[test]
    fn config_specific_overrides_take_precedence_over_shared() {
        let src = EtcdConfigSource::from_lookup(lookup(&[
            ("AEGIS_ETCD_ENDPOINTS", Some("http://shared:2379")),
            ("AEGIS_CONFIG_ETCD_ENDPOINTS", Some("http://config-only:2379")),
        ]));
        assert_eq!(src.endpoints, vec!["http://config-only:2379".to_string()]);
    }

    #[test]
    fn falls_back_to_shared_when_config_specific_unset() {
        let src = EtcdConfigSource::from_lookup(lookup(&[
            ("AEGIS_ETCD_ENDPOINTS", Some("http://shared:2379")),
            ("AEGIS_ETCD_USER", Some("u")),
            ("AEGIS_ETCD_PASSWORD", Some("p")),
        ]));
        assert_eq!(src.endpoints, vec!["http://shared:2379".to_string()]);
        assert_eq!(src.user.as_deref(), Some("u"));
        assert_eq!(src.password.as_deref(), Some("p"));
    }

    #[test]
    fn empty_string_env_treated_as_unset() {
        let src = EtcdConfigSource::from_lookup(lookup(&[
            ("AEGIS_CONFIG_ETCD_USER", Some("")),
            ("AEGIS_ETCD_USER", Some("real")),
        ]));
        assert_eq!(src.user.as_deref(), Some("real"));
    }

    #[test]
    fn parses_comma_separated_endpoints_with_whitespace() {
        let src = EtcdConfigSource::from_lookup(lookup(&[(
            "AEGIS_CONFIG_ETCD_ENDPOINTS",
            Some("http://e1:2379, http://e2:2379 , ,http://e3:2379"),
        )]));
        assert_eq!(
            src.endpoints,
            vec![
                "http://e1:2379".to_string(),
                "http://e2:2379".to_string(),
                "http://e3:2379".to_string(),
            ],
        );
    }

    #[test]
    fn poll_interval_parses_and_invalid_falls_back() {
        let src = EtcdConfigSource::from_lookup(lookup(&[(
            "AEGIS_CONFIG_ETCD_POLL_INTERVAL_MS",
            Some("1234"),
        )]));
        assert_eq!(src.poll_interval, Duration::from_millis(1234));

        let src = EtcdConfigSource::from_lookup(lookup(&[(
            "AEGIS_CONFIG_ETCD_POLL_INTERVAL_MS",
            Some("not-a-number"),
        )]));
        assert_eq!(src.poll_interval, Duration::from_millis(DEFAULT_POLL_MS));
    }

    #[test]
    fn key_default_and_override() {
        let src = EtcdConfigSource::from_lookup(lookup(&[]));
        assert_eq!(src.key, DEFAULT_KEY);

        let src = EtcdConfigSource::from_lookup(lookup(&[(
            "AEGIS_CONFIG_ETCD_KEY",
            Some("/custom/path"),
        )]));
        assert_eq!(src.key, "/custom/path");
    }

    #[test]
    fn from_env_reads_process_env() {
        // Smoke test: from_env() at minimum must not panic
        // and must return defaults when no AEGIS_*ETCD* vars
        // are set (which is the test-runner's expected state).
        let _src = EtcdConfigSource::from_env();
    }

    #[test]
    fn parse_range_value_decodes_yaml_blob() {
        let yaml = "listeners:\n  data:\n    - bind: \"127.0.0.1:8080\"\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(yaml.as_bytes());
        let body = format!(
            "{{\"kvs\":[{{\"key\":\"L2FlZ2lzL2NvbmZpZy93YWY=\",\"value\":\"{encoded}\"}}]}}"
        );
        let out = parse_range_value(&body).unwrap();
        assert_eq!(out.as_deref(), Some(yaml));
    }

    #[test]
    fn parse_range_value_returns_none_when_kvs_missing() {
        let body = "{}";
        assert_eq!(parse_range_value(body).unwrap(), None);
    }

    #[test]
    fn parse_range_value_returns_none_when_kvs_empty_array() {
        let body = "{\"kvs\":[]}";
        assert_eq!(parse_range_value(body).unwrap(), None);
    }

    #[test]
    fn parse_range_value_rejects_bad_base64() {
        let body =
            "{\"kvs\":[{\"key\":\"L2FlZ2lzL2NvbmZpZy93YWY=\",\"value\":\"!@#$%not-base64\"}]}";
        assert!(parse_range_value(body).is_err());
    }

    #[test]
    fn parse_range_value_rejects_invalid_json() {
        assert!(parse_range_value("not json").is_err());
    }

    #[test]
    fn prefix_to_range_end_increments_last_byte() {
        assert_eq!(prefix_to_range_end("a"), b"b".to_vec());
        assert_eq!(prefix_to_range_end("/aegis/config/waf"), {
            let mut v = b"/aegis/config/waf".to_vec();
            *v.last_mut().unwrap() += 1;
            v
        });
    }

    #[test]
    fn etcd_load_error_display() {
        let e = EtcdLoadError::Transport("net".into());
        assert!(format!("{e}").contains("transport"));
        let e = EtcdLoadError::Auth("denied".into());
        assert!(format!("{e}").contains("auth"));
        let e = EtcdLoadError::MissingKey("/k".into());
        assert!(format!("{e}").contains("/k"));
        let e = EtcdLoadError::Decode("bad yaml".into());
        assert!(format!("{e}").contains("decode"));
    }

    #[test]
    fn build_client_succeeds_with_no_tls_overrides() {
        let src = EtcdConfigSource {
            endpoints: vec!["http://127.0.0.1:2379".into()],
            key: "/k".into(),
            user: None,
            password: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            poll_interval: Duration::from_millis(DEFAULT_POLL_MS),
        };
        assert!(build_client(&src).is_ok());
    }

    #[test]
    fn build_client_errors_on_unreadable_ca() {
        let src = EtcdConfigSource {
            endpoints: vec!["http://127.0.0.1:2379".into()],
            key: "/k".into(),
            user: None,
            password: None,
            ca_cert_path: Some("/nonexistent/path/ca.pem".into()),
            client_cert_path: None,
            client_key_path: None,
            poll_interval: Duration::from_millis(DEFAULT_POLL_MS),
        };
        let err = build_client(&src).unwrap_err();
        assert!(err.contains("CA cert"));
    }

    #[test]
    fn first_non_empty_skips_empty_and_finds_first() {
        let f = lookup(&[
            ("A", Some("")),
            ("B", Some("real")),
            ("C", Some("other")),
        ]);
        let v = first_non_empty(&["A", "B", "C"], &f);
        assert_eq!(v.as_deref(), Some("real"));
    }

    #[test]
    fn first_non_empty_returns_none_when_all_unset() {
        let f = lookup(&[("A", None), ("B", None)]);
        assert!(first_non_empty(&["A", "B"], &f).is_none());
    }
}
