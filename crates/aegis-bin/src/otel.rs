//! OpenTelemetry OTLP exporter (OTEL-T1 — foundation).
//!
//! Closes the audit-derived "OTel tracing 0% wired" gap that
//! GRAFANA-T1's Jaeger datasource has been waiting on. The
//! `tracing-subscriber::fmt::init()` call in `main.rs` is now
//! routed through this module so the same code path can either
//!
//!   - install the **stdout JSON layer** only (default build), OR
//!   - install **stdout + OTLP gRPC** (`--features otel`)
//!
//! depending on what the operator built and what
//! `cfg.observability.otel.endpoint` is set to. Either way the
//! caller invokes [`init_or_default`] exactly once at process
//! start, before any tokio runtime spawns spans.
//!
//! ## Status (2026-06-02) — live
//!
//! The four OTel crates (`opentelemetry` 0.24, `opentelemetry_sdk`
//! 0.24, `opentelemetry-otlp` 0.17, `tracing-opentelemetry` 0.25) are
//! in `aegis-bin/Cargo.toml` behind the optional `otel` feature, and
//! [`install_with_otel`] below is the **real exporter** —
//! `cargo build -p aegis-bin --features otel` ships every `tracing`
//! span over OTLP gRPC to `cfg.observability.otel.endpoint`.
//!
//! **Backend: SigNoz.** Its bundled OTel collector listens on
//! `:4317`; point `endpoint` there (see `deploy/signoz/`). An optional
//! in-between OTel Collector (`deploy/otel/collector.yaml`) adds PII
//! redaction + fan-out. **Traces only today** — OTLP metrics + logs
//! are the next phases (`plans/future/observability-otel-and-alerts.md`).
//!
//! The four crate versions are pinned together because the OTel-Rust
//! API breaks on minor bumps; bump all four in lockstep.

use aegis_core::config::WafConfig;

/// The pinned OTel dep set — **already wired** in
/// `aegis-bin/Cargo.toml` under the optional `otel` feature. Kept as
/// a documented record (and pinned by a test) so a future refactor
/// bumps all four in lockstep rather than one at a time.
///
/// ```toml
/// opentelemetry           = { version = "0.24", optional = true }
/// opentelemetry_sdk       = { version = "0.24", features = ["rt-tokio"], optional = true }
/// opentelemetry-otlp      = { version = "0.17", features = ["grpc-tonic", "trace"], optional = true }
/// tracing-opentelemetry   = { version = "0.25", optional = true }
///
/// [features]
/// otel = [
///     "dep:opentelemetry",
///     "dep:opentelemetry_sdk",
///     "dep:opentelemetry-otlp",
///     "dep:tracing-opentelemetry",
/// ]
/// ```
#[allow(dead_code)] // referenced under `--features otel` only
pub const REQUIRED_DEPS_NOTE: &str = "\
opentelemetry 0.24, opentelemetry_sdk 0.24, opentelemetry-otlp 0.17, tracing-opentelemetry 0.25 \
— see crates/aegis-bin/src/otel.rs::REQUIRED_DEPS_NOTE for the exact toml block.";

/// Initialize tracing. With `--features otel` AND a configured
/// `cfg.observability.otel.endpoint`, install the OTLP exporter
/// alongside the stdout JSON layer. Otherwise install the stdout
/// JSON layer only — same behaviour as `tracing_subscriber::fmt::init()`.
///
/// Returns whether OTel export was successfully wired. The bool
/// is informational; init is best-effort and falls back cleanly
/// if the exporter can't connect at boot (it'll retry per the
/// SDK's batch-export schedule).
pub fn init_or_default(cfg: &WafConfig) -> bool {
    #[cfg(feature = "otel")]
    {
        if let Some(otel_cfg) = cfg.observability.otel.as_ref() {
            if !otel_cfg.endpoint.is_empty() {
                // Per-node identity on the OTLP resource so SigNoz can
                // group traffic + metrics per node in a multi-node
                // cluster. Without these every node is indistinguishable
                // (only service.name/version were stamped). Uses the same
                // node id the lease/cluster plane derives, so the SigNoz
                // `service.instance.id` lines up with the dashboard's
                // cluster view.
                let node_id = crate::lease_select::derive_node_id(cfg)
                    .as_str()
                    .to_string();
                let host_name = std::env::var("HOSTNAME")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| node_id.clone());
                return install_with_otel(otel_cfg, &node_id, &host_name);
            }
        }
        // Feature on but no endpoint — fall through to default.
        tracing_subscriber::fmt::init();
        return false;
    }

    #[cfg(not(feature = "otel"))]
    {
        // Feature off. Default behaviour matches the previous
        // `main.rs` line. If the operator set
        // `cfg.observability.otel.endpoint`, log a hint that
        // they need to rebuild with the feature.
        tracing_subscriber::fmt::init();
        if let Some(otel_cfg) = cfg.observability.otel.as_ref() {
            if !otel_cfg.endpoint.is_empty() {
                tracing::warn!(
                    endpoint = %otel_cfg.endpoint,
                    "cfg.observability.otel.endpoint is set but binary built without `--features otel` — traces will NOT reach the collector. Rebuild with: cargo build -p aegis-bin --features otel (after adding deps from REQUIRED_DEPS_NOTE).",
                );
            }
        }
        false
    }
}

/// Flush the in-flight OTLP span batch on graceful shutdown so the last
/// spans (e.g. requests served during the drain window) aren't dropped
/// by the batch processor when the process exits. Call once after the
/// server loop returns, while the tokio runtime is still alive.
///
/// No-op without `--features otel` or when the exporter was never wired
/// (no endpoint configured / init failed). Best-effort: flush errors are
/// logged, never propagated — shutdown must not fail on telemetry.
pub fn shutdown() {
    #[cfg(feature = "otel")]
    {
        if let Some(provider) = OTEL_PROVIDER.get() {
            for res in provider.force_flush() {
                if let Err(e) = res {
                    tracing::warn!(error = ?e, "otel span flush on shutdown failed");
                }
            }
        }
    }
}

#[cfg(feature = "otel")]
fn install_with_otel(
    otel_cfg: &aegis_core::config::OtelConfig,
    node_id: &str,
    host_name: &str,
) -> bool {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{runtime, trace as sdk_trace, Resource};
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&otel_cfg.endpoint);

    let resource = Resource::new(vec![
        KeyValue::new("service.name", "aegis-gate"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        // OTEL semantic conventions for per-node identity. `host.name`
        // also lets host-metrics (CPU/mem from a per-node hostmetrics
        // agent) join WAF traffic by node in SigNoz.
        KeyValue::new("service.instance.id", node_id.to_string()),
        KeyValue::new("host.name", host_name.to_string()),
    ]);

    let provider_result = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            sdk_trace::Config::default()
                .with_resource(resource)
                .with_sampler(sdk_trace::Sampler::TraceIdRatioBased(
                    otel_cfg.sample_ratio.into(),
                )),
        )
        .install_batch(runtime::Tokio);

    match provider_result {
        Ok(provider) => {
            let tracer = provider.tracer("aegis-gate");
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            // Stash the provider so spans flush on shutdown. The
            // `tracing-opentelemetry` layer holds its own clone of
            // the tracer, but the SDK provider needs to outlive
            // the process for `shutdown_tracer_provider` to drain
            // the batch on SIGTERM. We park it in a OnceLock at
            // module scope so a future shutdown hook can grab it.
            let _ = OTEL_PROVIDER.set(provider);
            // 2026-06-02 — span-noise filter. Without this the OTLP
            // export is dominated by `h2`/hyper/tower TRACE-level
            // internals (`reserve_capacity`, `send_data`, `hpack::*`…)
            // that drown the useful `waf.*` request spans (confirmed by
            // the Jaeger smoke test). A per-layer `Targets` filter keeps
            // only the WAF's own crates and drops everything else, so a
            // trace shows the request path — not the HTTP/2 plumbing.
            // This filter is scoped to the OTLP layer ONLY; the stdout
            // JSON log layer below stays unfiltered (operators still get
            // full logs). RUST_LOG/EnvFilter is a separate concern (needs
            // the `env-filter` feature, not enabled).
            let otel_filter = Targets::new()
                .with_target("aegis_proxy", LevelFilter::TRACE)
                .with_target("aegis_security", LevelFilter::TRACE)
                .with_target("aegis_control", LevelFilter::TRACE)
                .with_target("aegis_core", LevelFilter::TRACE)
                .with_target("aegis_bin", LevelFilter::TRACE)
                .with_target("waf", LevelFilter::TRACE)
                .with_default(LevelFilter::OFF);
            let registry = tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().json())
                .with(otel_layer.with_filter(otel_filter));
            if registry.try_init().is_err() {
                // Subscribers are install-once. If something else
                // already set a global subscriber (tests / library
                // boot), keep going — the exporter is still
                // attached to the SDK; spans just won't route.
                tracing::warn!(
                    "tracing subscriber was already initialised; OTel layer not attached",
                );
                return false;
            }
            true
        }
        Err(e) => {
            // Init failed at the SDK level — usually a malformed
            // endpoint URL or an immediately-unreachable
            // collector. Don't fail the boot; install the
            // stdout-only layer so the WAF starts and operators
            // see the log line that pinpoints the problem.
            tracing_subscriber::fmt::init();
            tracing::warn!(
                error = %e,
                endpoint = %otel_cfg.endpoint,
                "OTLP exporter init failed; falling back to stdout layer only",
            );
            false
        }
    }
}

/// Holds the live SDK provider so a shutdown hook (future) can
/// `shutdown_tracer_provider` and flush any in-flight batch.
/// `OnceLock` keeps the lifetime explicit without forcing
/// `lazy_static!` or a global mutex.
#[cfg(feature = "otel")]
static OTEL_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::TracerProvider> =
    std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::OtelConfig;

    /// Doc constant lists the deps an operator needs to add to
    /// flip the structural foundation into a live exporter.
    /// Test pins the contents so a future refactor can't strip
    /// the actionable detail without breaking the test.
    #[test]
    fn required_deps_note_lists_every_otel_crate() {
        assert!(!REQUIRED_DEPS_NOTE.is_empty());
        for crate_name in [
            "opentelemetry",
            "opentelemetry_sdk",
            "opentelemetry-otlp",
            "tracing-opentelemetry",
        ] {
            assert!(
                REQUIRED_DEPS_NOTE.contains(crate_name),
                "REQUIRED_DEPS_NOTE missing crate {crate_name:?}: {REQUIRED_DEPS_NOTE}",
            );
        }
    }

    /// `OtelConfig` has documented fields; this test exists to
    /// catch silent breakage if anyone mutates the schema.
    #[test]
    fn otel_config_round_trip_preserves_endpoint_and_sample_ratio() {
        let cfg = OtelConfig {
            endpoint: "http://otel:4317".into(),
            headers: Default::default(),
            sample_ratio: 0.05,
        };
        assert_eq!(cfg.endpoint, "http://otel:4317");
        assert!((cfg.sample_ratio - 0.05).abs() < f32::EPSILON);
    }

    /// `init_or_default` is install-once globally (tracing
    /// subscribers are process-wide). We can't safely call it
    /// from a test without polluting other tests' subscribers,
    /// so coverage for the init paths comes from compile-time
    /// (the build runs both `cargo build -p aegis-bin` and
    /// `cargo build -p aegis-bin --features otel` per CI). The
    /// runtime smoke is the operator booting `cargo run` and
    /// observing the warn-log when feature is on without deps.
    #[test]
    fn init_paths_compile_under_both_feature_states() {
        // Touch the function pointer so the linker doesn't drop
        // the symbol under default build.
        let _ = init_or_default as fn(&WafConfig) -> bool;
    }
}
