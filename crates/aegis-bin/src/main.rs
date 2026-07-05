use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::{AuditBus, ReadinessSignal};

mod lease_select;
mod otel;
mod snapshot;
mod state_select;

fn main() {
    // OTEL-T1 — defer subscriber init until we've parsed the
    // config so the OTLP exporter can read
    // `cfg.observability.otel.endpoint`. The CLI subcommands that
    // don't need the WAF config (`version`, `help`,
    // `admin set-password`) initialise tracing eagerly via the
    // fmt layer below before they run; the `run` path falls
    // through to `run_gateway` which calls
    // `otel::init_or_default(&cfg)` after loading config.
    let needs_eager_tracing = std::env::args()
        .nth(1)
        .map(|s| !matches!(s.as_str(), "run"))
        .unwrap_or(true);
    if needs_eager_tracing {
        // Honour RUST_LOG (with a sane default) so CLI subcommands
        // don't emit the same third-party TRACE flood the `run` path
        // filters — see `otel::fmt_env_filter`.
        tracing_subscriber::fmt()
            .with_env_filter(otel::fmt_env_filter())
            .init();
    }

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    let exit_code = match command {
        "run" => {
            let config_path = parse_config_flag(&args);
            match run_gateway(&config_path) {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!("{e}");
                    1
                }
            }
        }
        "validate" => cmd_validate(&args),
        "migrate-config-plane" => cmd_migrate_config_plane(&args),
        "audit" => cmd_audit(&args),
        "admin" => cmd_admin(&args),
        "snapshot" => snapshot::cmd_snapshot(&args),
        "restore" => snapshot::cmd_restore(&args),
        "version" => {
            println!(
                "aegis-gate {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_NAME"),
            );
            0
        }
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("run `waf help` for usage");
            1
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

// ---------------------------------------------------------------------------
// Flag parsing helpers
// ---------------------------------------------------------------------------

fn parse_config_flag(args: &[String]) -> PathBuf {
    if let Some(p) = parse_flag(args, "--config") {
        return PathBuf::from(p);
    }
    // v2.3 §8 — Binary contract default config lookup. The
    // benchmarker expects `./waf.yaml` (or `./waf.toml`) in the
    // working directory. Fall back to the legacy `config/prod.yaml`
    // shipped in the repo so existing deploys keep working.
    for candidate in ["./waf.yaml", "./waf.toml"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("config/prod.yaml")
}

fn parse_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).map(String::as_str);
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// waf run
// ---------------------------------------------------------------------------

fn run_gateway(config_path: &std::path::Path) -> aegis_core::Result<()> {
    // 2026-05-28 — config loads from the local YAML file. The etcd
    // config source (`AEGIS_CONFIG_SOURCE=etcd`) was removed: it was
    // redundant with file delivery (image / ConfigMap / GitOps) plus the
    // redis config plane. Reject a stale `=etcd` so an operator's intent
    // isn't silently ignored. (etcd remains a service-discovery adapter
    // for upstream pools — unrelated to config loading.)
    if std::env::var("AEGIS_CONFIG_SOURCE")
        .ok()
        .as_deref()
        .map(str::trim)
        == Some("etcd")
    {
        return Err(aegis_core::WafError::Config(
            "AEGIS_CONFIG_SOURCE=etcd is no longer supported — distribute a \
             config file (--config) and use the redis config plane for runtime \
             edits"
                .into(),
        ));
    }
    let cfg = Arc::new(aegis_core::load_config(config_path)?);

    // Layer-1 — build the tokio runtime from `runtime:` config.
    // Restart-only by design: tokio's worker_threads is fixed at
    // builder time. The admin surface rejects hot-reload requests
    // for these fields.
    let rt = build_runtime(&cfg.runtime)?;
    rt.block_on(run_gateway_inner(cfg, config_path))
}

/// Async portion of `run_gateway`. Split out so the OTel
/// exporter pipeline can call `install_batch(runtime::Tokio)`
/// from inside a live tokio context — outside that, the
/// hyper-util batch dispatcher panics with "no reactor running".
async fn run_gateway_inner(
    cfg: Arc<aegis_core::config::WafConfig>,
    config_path: &std::path::Path,
) -> aegis_core::Result<()> {
    // OTEL-T1/T2 — init tracing now that we're inside the
    // tokio runtime. Default build installs the stdout JSON
    // layer; with `--features otel` AND
    // `cfg.observability.otel.endpoint` populated, the OTLP
    // exporter is also installed so spans ship to the
    // collector / Jaeger.
    let otel_wired = otel::init_or_default(&cfg);
    if otel_wired {
        tracing::info!(
            endpoint = ?cfg.observability.otel.as_ref().map(|o| o.endpoint.as_str()),
            "OTLP tracing exporter wired",
        );
    }

    tracing::info!("loaded config from {}", config_path.display());

    // CQF-T9 — stamp the process boot timestamp so /api/about
    // can report `started_at`; the dashboard sidebar computes
    // UPTIME from `Date.now() - started_at` rather than carry a
    // stale duration field.
    let boot_ts = aegis_control::api::about::mark_started();
    tracing::info!(boot_ts = %boot_ts, "process boot timestamp stamped");

    // 2026-05-11 PR #7 — replace NoopPipeline with the real impl.
    // The data plane bypasses `SecurityPipeline::inbound()` and
    // calls `run_all_filtered_timed(&detectors, ...)` directly, so
    // the RuleSet attached here only matters if someone wires the
    // trait's inbound path in the future. The on_body_frame
    // wire-up reads `ResponseFilterConfig` from this `Pipeline`
    // instance — that's the load-bearing piece. Defaults: scrub
    // stack traces + mask internal IPs + redact DLP, all ON.
    // PR #7 (2026-05-11) — concrete `Arc<Pipeline>` so the proxy
    // boot path can hand the same instance to both the data
    // plane (via `Arc<dyn SecurityPipeline>` coercion in
    // `ProxyContext::build`) and the dashboard
    // (`response_filter_writer`). The data plane bypasses
    // `SecurityPipeline::inbound()` and calls
    // `run_all_filtered_timed(&detectors, ...)` directly;
    // `on_body_frame` is the only hot trait method, and the
    // dashboard PUT flips its `ResponseFilterConfig` rungs.
    let pipeline: Arc<aegis_security::Pipeline> =
        Arc::new(aegis_security::Pipeline::new(Arc::new(
            aegis_security::RuleSet::new(),
        )));
    let (state, state_summary) = state_select::select(&cfg)?;
    tracing::info!("state backend = {state_summary}");

    let node_id = lease_select::derive_node_id(&cfg);
    let (lease_store, lease_summary) = lease_select::select(&cfg, node_id)?;
    tracing::info!("lease store = {lease_summary}");

    // 2026-05-17 Phase 7a: capacity surfaced as
    // `cfg.audit.bus_capacity` (default 100_000). Pre-fix the
    // hard-coded 4096 produced `Lagged(n)` drops at burst loads
    // above ~2-3k audit events/sec — the 60k-RPS 2026-05-14
    // stress run lost hundreds of events per burst. See
    // `crates/aegis-core/src/config.rs::default_audit_bus_capacity`
    // for the rationale on the new default.
    let bus = AuditBus::new(cfg.audit.bus_capacity);
    let readiness = ReadinessSignal::default();

    // Wrap cfg in an ArcSwap so the configured reload-source
    // watcher (file or etcd) can atomic-swap new revisions in.
    // The proxy takes a boot snapshot via `cfg_swap.load_full()`
    // so existing read sites stay unchanged.
    let cfg_swap = Arc::new(arc_swap::ArcSwap::from(cfg));

    let reload_source = resolve_reload_source(config_path);
    let result = aegis_proxy::run(
        cfg_swap,
        pipeline,
        state,
        lease_store,
        bus,
        readiness,
        reload_source,
    )
    .await;

    // P4 (2026-06-02) — flush the in-flight OTLP span batch before exit
    // so spans from requests served during the drain window aren't lost.
    // Runs after the server loop returns, while the runtime is still
    // alive (we're inside the runtime's block_on). No-op without `otel`.
    otel::shutdown();

    result
}

/// Pick the [`aegis_proxy::ConfigReloadSource`] for `run_gateway`.
/// Config is always loaded + watched from the local YAML file; the
/// `config_path` is both the initial-load source (in `run_gateway`)
/// and the watcher root here.
fn resolve_reload_source(
    config_path: &std::path::Path,
) -> aegis_proxy::ConfigReloadSource {
    aegis_proxy::ConfigReloadSource::File(config_path.to_path_buf())
}

/// Construct the tokio runtime from the validated [`RuntimeConfig`].
fn build_runtime(
    cfg: &aegis_core::config::RuntimeConfig,
) -> aegis_core::Result<tokio::runtime::Runtime> {
    let workers = cfg.workers.resolve();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .worker_threads(workers)
        .max_blocking_threads(cfg.blocking_threads)
        .thread_stack_size(cfg.stack_size_kb * 1024)
        .thread_name("aegis-worker");

    tracing::info!(
        workers = workers,
        blocking_threads = cfg.blocking_threads,
        stack_size_kb = cfg.stack_size_kb,
        cpu_affinity = cfg.cpu_affinity,
        "tokio runtime",
    );

    if cfg.cpu_affinity {
        #[cfg(feature = "affinity")]
        {
            apply_cpu_affinity(&mut builder, workers);
        }
        #[cfg(not(feature = "affinity"))]
        {
            tracing::warn!(
                "runtime.cpu_affinity = true but the `affinity` build \
                 feature is not enabled in this binary; ignoring",
            );
        }
    }

    builder.build().map_err(aegis_core::WafError::Io)
}

/// Pin each tokio worker thread to a distinct CPU core. The
/// `core_affinity` crate's enforcement is OS-dependent: Linux uses
/// `sched_setaffinity` (hard pin), macOS uses thread policy hints
/// (advisory), Windows uses `SetThreadAffinityMask`. On any host
/// where the call returns false we log + continue — the worker
/// just runs on whatever core the scheduler picks.
#[cfg(feature = "affinity")]
fn apply_cpu_affinity(
    builder: &mut tokio::runtime::Builder,
    workers: usize,
) {
    let cores = match core_affinity::get_core_ids() {
        Some(ids) if !ids.is_empty() => ids,
        _ => {
            tracing::warn!(
                "runtime.cpu_affinity = true but the OS reported no \
                 core IDs; threads will float across cores",
            );
            return;
        }
    };
    let cores: Vec<core_affinity::CoreId> =
        cores.into_iter().take(workers).collect();
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cores_for_callback = cores.clone();
    builder.on_thread_start(move || {
        let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(core) = cores_for_callback.get(idx % cores_for_callback.len()) {
            if !core_affinity::set_for_current(*core) {
                tracing::warn!(
                    core = ?core,
                    "core_affinity::set_for_current returned false; \
                     thread will not be pinned",
                );
            }
        }
    });
    tracing::info!(
        cores = cores.len(),
        "cpu affinity active — workers pinned round-robin to cores",
    );
}

// ---------------------------------------------------------------------------
// waf validate
// ---------------------------------------------------------------------------

fn cmd_validate(args: &[String]) -> i32 {
    let config_path = parse_config_flag(args);
    let print_priority = args.iter().any(|a| a == "--print-route-priority");

    match aegis_core::load_config(&config_path) {
        Ok(cfg) => {
            println!("config OK: {}", config_path.display());
            // 2026-05-17 (user decision): `compliance.apply` removed.
            // The v2.3 contract doesn't require regulatory
            // compliance modes; the framework files (FIPS / PCI /
            // HIPAA / SOC2 / GDPR) wired through
            // `COMPLIANCE_PINNED = &[]` were dead infrastructure.
            if print_priority {
                if let Err(e) = print_route_priority(&cfg) {
                    eprintln!("route table build failed: {e}");
                    return 1;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("config error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// waf migrate-config-plane  (H2b P3 — Redis → etcd cutover copy)
// ---------------------------------------------------------------------------

/// One-shot copy of the durable config + control plane from the live
/// shared-state store (Redis) into the etcd cluster named in
/// `config_plane.etcd.endpoints`, then verify the active version round-trips.
/// Run this once while still on `config_plane.store: shared_state`; on a
/// verified report, flip to `store: etcd` and restart. Idempotent — safe to
/// re-run. Requires the `etcd_config` (and `redis`) features.
fn cmd_migrate_config_plane(args: &[String]) -> i32 {
    let config_path = parse_config_flag(args);
    let cfg = match aegis_core::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };
    migrate_config_plane_impl(&cfg)
}

#[cfg(feature = "etcd_config")]
fn migrate_config_plane_impl(cfg: &aegis_core::config::WafConfig) -> i32 {
    use aegis_core::config_backend::{ConfigBackend, SharedStateConfigBackend};
    use aegis_proxy::config_source::etcd_backend::EtcdConfigBackend;
    use aegis_proxy::config_source::migrate::migrate_config_plane;

    let endpoints = match cfg
        .config_plane
        .etcd
        .as_ref()
        .map(|e| e.endpoints.clone())
        .filter(|e| e.iter().any(|u| !u.trim().is_empty()))
    {
        Some(e) => e,
        None => {
            eprintln!(
                "migrate-config-plane: config_plane.etcd.endpoints must list the etcd \
                 destination (e.g. [\"http://127.0.0.1:2379\"])"
            );
            return 1;
        }
    };

    // Source = the live shared-state store (Redis). state_select emits the
    // precise error if `state.backend` isn't a usable shared store.
    let (state, state_summary) = match state_select::select(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("migrate-config-plane: source state backend: {e}");
            return 1;
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("migrate-config-plane: runtime build failed: {e}");
            return 1;
        }
    };

    rt.block_on(async move {
        println!("migrate-config-plane: source = {state_summary}");
        println!("migrate-config-plane: destination = etcd @ {}", endpoints.join(","));
        let source: std::sync::Arc<dyn ConfigBackend> = SharedStateConfigBackend::arc(state);
        let dest: std::sync::Arc<dyn ConfigBackend> = match EtcdConfigBackend::connect(&endpoints).await
        {
            Ok(b) => b.into_backend(),
            Err(e) => {
                eprintln!("migrate-config-plane: etcd connect failed: {e}");
                return 1;
            }
        };

        match migrate_config_plane(&source, &dest).await {
            Ok(report) => {
                println!("migrate-config-plane: report:");
                match report.source_version {
                    Some(v) => println!("  source active version : {v}"),
                    None => println!("  source active version : <none — nothing to migrate>"),
                }
                println!("  active doc copied     : {}", report.doc_copied);
                println!("  version snapshots     : {}", report.snapshots_copied);
                println!("  control-plane keys    : {}", report.control_keys_copied);
                println!("  verified              : {}", report.verified);
                if report.verified {
                    println!(
                        "migrate-config-plane: OK — etcd holds the active version. \
                         You may now set config_plane.store: etcd and restart."
                    );
                    0
                } else if report.source_version.is_none() {
                    eprintln!(
                        "migrate-config-plane: source had no active config doc — nothing \
                         was migrated (is this the right source store?)."
                    );
                    1
                } else {
                    eprintln!("migrate-config-plane: verification FAILED — do NOT cut over.");
                    1
                }
            }
            Err(e) => {
                eprintln!("migrate-config-plane: failed: {e}");
                1
            }
        }
    })
}

#[cfg(not(feature = "etcd_config"))]
fn migrate_config_plane_impl(_cfg: &aegis_core::config::WafConfig) -> i32 {
    eprintln!(
        "migrate-config-plane requires the `etcd_config` feature. Rebuild with \
         `cargo build -p aegis-bin --features \"redis etcd_config\"`."
    );
    1
}

// PR1 — `--print-route-priority` audit. Builds the route table from a
// validated config and emits one row per route in descending priority
// order: `<priority>  <host>  <path>  <method>  <tier>  <upstream>
// <route-id>`. Lets operators diff effective routing order before/after
// PR1 lands without bouncing the proxy.
fn print_route_priority(cfg: &aegis_core::config::WafConfig) -> aegis_core::Result<()> {
    let table = aegis_proxy::route::RouteTable::build(cfg)?;
    let rows = table.priorities();

    println!();
    println!(
        "{:>16}  {:<24}  {:<28}  {:<10}  {:<9}  {:<20}  {}",
        "PRIORITY", "HOST", "PATH", "METHOD", "TIER", "UPSTREAM", "ROUTE_ID"
    );
    println!("{}", "─".repeat(150));
    for r in &rows {
        let methods = match &r.methods {
            Some(ms) if !ms.is_empty() => ms.join(","),
            _ => "*".to_string(),
        };
        let tier = format!("{:?}", r.tier).to_lowercase();
        println!(
            "{:>16}  {:<24}  {:<28}  {:<10}  {:<9}  {:<20}  {}",
            r.priority.fmt_compact(),
            truncate(&r.host, 24),
            truncate(&r.path, 28),
            truncate(&methods, 10),
            truncate(&tier, 9),
            truncate(&r.upstream, 20),
            r.route_id,
        );
    }
    println!();
    println!("{} route(s) — sorted descending by effective priority", rows.len());
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ---------------------------------------------------------------------------
// waf audit
// ---------------------------------------------------------------------------

fn cmd_audit(args: &[String]) -> i32 {
    let sub = args.get(2).map(String::as_str).unwrap_or("help");
    match sub {
        "verify" => cmd_audit_verify(args),
        "help" | "--help" => {
            println!("waf audit <subcommand>");
            println!();
            println!("SUBCOMMANDS:");
            println!("    verify --from <PATH>   Verify audit chain integrity");
            println!("    help                   Show this help");
            0
        }
        other => {
            eprintln!("unknown audit subcommand: {other}");
            1
        }
    }
}

fn cmd_audit_verify(args: &[String]) -> i32 {
    let path = match parse_flag(args, "--from") {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: waf audit verify --from <PATH>");
            return 1;
        }
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return 1;
        }
    };

    use aegis_control::audit::verify::{verify_ndjson, VerifyResult};
    match verify_ndjson(&content) {
        VerifyResult::Clean { entries } => {
            println!("OK: chain is clean ({entries} entries)");
            0
        }
        VerifyResult::Broken {
            line,
            expected,
            actual,
        } => {
            eprintln!(
                "TAMPERED at line {line}: expected hash {expected}, got {actual}"
            );
            1
        }
        VerifyResult::ParseError { line, message } => {
            eprintln!("PARSE ERROR at line {line}: {message}");
            1
        }
        VerifyResult::Empty => {
            println!("EMPTY: no entries to verify");
            0
        }
    }
}

// ---------------------------------------------------------------------------
// waf admin
// ---------------------------------------------------------------------------

fn cmd_admin(args: &[String]) -> i32 {
    let sub = args.get(2).map(String::as_str).unwrap_or("help");
    match sub {
        "set-password" => cmd_admin_set_password(),
        "create-account" => cmd_admin_create_account(args),
        "enroll-totp" => cmd_admin_enroll_totp(args),
        "service-account" => cmd_admin_service_account(args),
        "help" | "--help" => {
            println!("waf admin <subcommand>");
            println!();
            println!("SUBCOMMANDS:");
            println!("    set-password           Hash a password (interactive prompt)");
            println!("    create-account --username <NAME> [--with-totp]");
            println!("                           Hash a password and print a ready-to-paste");
            println!("                           cfg.admin.dashboard_auth.accounts entry");
            println!("                           (--with-totp: also enroll a TOTP secret +");
            println!("                           otpauth:// URI + QR for Google Authenticator)");
            println!("    enroll-totp --issuer <ISSUER> --account <ACCOUNT>");
            println!("                           Generate TOTP secret + provisioning URI");
            println!("    service-account mint --name <NAME> [--scopes read,write]");
            println!("                           Mint a service-account bearer token");
            println!("    help                   Show this help");
            0
        }
        other => {
            eprintln!("unknown admin subcommand: {other}");
            1
        }
    }
}

/// AM-0c — read a password without echoing it. `rpassword` suppresses
/// terminal echo when stdin is a TTY and reads a piped line unchanged
/// otherwise (the prod path — `deploy/create-admin.sh` pipes it), so
/// interactive entry no longer leaks the secret to the screen / scrollback /
/// `script` logs. The prompt goes to stderr so a piped
/// `waf admin set-password` keeps stdout clean for the hash.
fn read_admin_password(prompt: &str) -> Option<String> {
    use std::io::Write;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    match rpassword::read_password() {
        Ok(p) => Some(p.trim().to_string()),
        Err(e) => {
            eprintln!("failed to read password: {e}");
            None
        }
    }
}

fn cmd_admin_set_password() -> i32 {
    let Some(password) = read_admin_password("Enter password (input hidden): ") else {
        return 1;
    };
    if password.is_empty() {
        eprintln!("password cannot be empty");
        return 1;
    }
    match aegis_control::admin_auth::password::hash_password(&password) {
        Ok(hash) => {
            println!("{hash}");
            0
        }
        Err(e) => {
            eprintln!("hashing error: {e}");
            1
        }
    }
}

fn cmd_admin_enroll_totp(args: &[String]) -> i32 {
    let issuer = parse_flag(args, "--issuer").unwrap_or("Aegis-Gate");
    let account = parse_flag(args, "--account").unwrap_or("admin");

    // 2026-05-17 F-CRITICAL-003 follow-up + TOTP-3: the CSPRNG secret
    // generation (2×UUIDv4 → 32 bytes → real RFC 4648 base32) moved to
    // `admin_auth::totp::generate_secret_b32` so this CLI and the web
    // enrollment endpoint (`POST /api/admin/totp/enroll`) share one
    // generator. History of the two bugs that construction fixed
    // (predictable blake3(nanos:pid) seed; fake byte-modulo-32 "base32")
    // lives on that function's doc.
    let b32 = aegis_control::admin_auth::totp::generate_secret_b32();
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &b32)
        .expect("generated secret must round-trip");

    let uri = aegis_control::admin_auth::totp::provisioning_uri(&b32, issuer, account);

    // Generate recovery codes.
    let recovery = aegis_control::admin_auth::totp::generate_recovery_codes(&secret);

    println!("TOTP Secret (base32): {b32}");
    println!("Provisioning URI:     {uri}");
    println!();
    // TOTP-4 — terminal QR so headless setup matches the web flow: scan
    // straight off the terminal with Google Authenticator.
    match aegis_control::api::totp_enrollment::render_qr_ascii(&uri) {
        Ok(art) => {
            println!("Scan with Google Authenticator / Authy / 1Password:");
            println!("{art}");
        }
        Err(e) => eprintln!("(QR render failed: {e} — use the URI/secret above)"),
    }
    println!();
    println!("Paste this into cfg.admin.dashboard_auth:");
    println!("  totp_enabled: true");
    println!("  totp_secret_b32: \"{b32}\"");
    println!();
    println!("(multi-admin configs: set the same two fields on the matching");
    println!(" cfg.admin.dashboard_auth.accounts entry instead)");
    println!();
    // AM-0e — recovery-code LOGIN is not wired yet (ships with TF-2), so do
    // not advertise these as "usable once". For v1, lost-device recovery is
    // an existing admin resetting your 2FA from the dashboard
    // (POST /api/admin/accounts/<user>/totp/reset). Codes are printed for
    // forward-compatibility only.
    println!("Recovery codes (NOT yet usable for login — reserved for a future");
    println!("release; if you lose your device, another admin resets your 2FA):");
    for (i, code) in recovery.iter().enumerate() {
        println!("  {}: {code}", i + 1);
    }
    0
}

/// TOTP-4 — the ready-to-paste `accounts:` entry `create-account`
/// prints. Kept as a pure helper so the shape is unit-testable.
fn account_yaml_fragment(username: &str, password_hash: &str, totp_b32: Option<&str>) -> String {
    let mut frag = String::new();
    frag.push_str("  accounts:\n");
    frag.push_str(&format!("    - username: \"{username}\"\n"));
    frag.push_str(&format!("      password_hash_ref: \"{password_hash}\"\n"));
    if let Some(b32) = totp_b32 {
        frag.push_str(&format!("      totp_secret_b32: \"{b32}\"\n"));
        frag.push_str("      totp_enabled: true\n");
    }
    frag
}

/// TOTP-4 — `waf admin create-account --username <NAME> [--with-totp]`.
/// Reuses the `set-password` hashing flow (argon2id) and, with
/// `--with-totp`, the shared secret generator + QR so one command
/// bootstraps a fully-enrolled admin account. Without `--with-totp`
/// the account enrolls at first login instead (require_totp flow).
fn cmd_admin_create_account(args: &[String]) -> i32 {
    let Some(username) = parse_flag(args, "--username") else {
        eprintln!("missing --username <NAME> (e.g. --username alice)");
        return 1;
    };
    if username.trim().is_empty() {
        eprintln!("--username cannot be empty");
        return 1;
    }
    let with_totp = args.iter().any(|a| a == "--with-totp");

    let Some(password) = read_admin_password(&format!(
        "Enter password for `{username}` (input hidden): "
    )) else {
        return 1;
    };
    if password.is_empty() {
        eprintln!("password cannot be empty");
        return 1;
    }
    let hash = match aegis_control::admin_auth::password::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hashing error: {e}");
            return 1;
        }
    };

    let totp_b32 = with_totp.then(aegis_control::admin_auth::totp::generate_secret_b32);

    println!();
    println!("Paste this into cfg.admin.dashboard_auth (merge with existing accounts):");
    println!();
    print!("{}", account_yaml_fragment(username, &hash, totp_b32.as_deref()));
    println!();

    if let Some(b32) = &totp_b32 {
        let uri = aegis_control::admin_auth::totp::provisioning_uri(b32, "Aegis-Gate", username);
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, b32)
            .expect("generated secret must round-trip");
        println!("TOTP Secret (base32): {b32}");
        println!("Provisioning URI:     {uri}");
        match aegis_control::api::totp_enrollment::render_qr_ascii(&uri) {
            Ok(art) => {
                println!("Scan with Google Authenticator / Authy / 1Password:");
                println!("{art}");
            }
            Err(e) => eprintln!("(QR render failed: {e} — use the URI/secret above)"),
        }
        // AM-0e — see cmd_admin_enroll_totp: recovery-code login is deferred
        // (TF-2); v1 recovery is an admin-driven 2FA reset. Not "usable once".
        println!("Recovery codes (NOT yet usable for login — reserved for a future");
        println!("release; if you lose your device, another admin resets your 2FA):");
        for (i, code) in
            aegis_control::admin_auth::totp::generate_recovery_codes(&secret).iter().enumerate()
        {
            println!("  {}: {code}", i + 1);
        }
    } else {
        println!("No TOTP enrolled: with require_totp (the default), `{username}`'s");
        println!("first login lands in the enrollment flow — scan the QR there,");
        println!("or re-run with --with-totp to enroll now.");
    }
    0
}

// ---------------------------------------------------------------------------
// waf admin service-account
// ---------------------------------------------------------------------------

fn cmd_admin_service_account(args: &[String]) -> i32 {
    let sub = args.get(3).map(String::as_str).unwrap_or("help");
    match sub {
        "mint" => cmd_admin_service_account_mint(args),
        "help" | "--help" => {
            println!("waf admin service-account <subcommand>");
            println!();
            println!("SUBCOMMANDS:");
            println!("    mint --name <NAME> [--scopes read,write]");
            println!("                 Mint a bearer token + print the YAML fragment");
            println!("                 to paste into cfg.admin.dashboard_auth.");
            println!("                 The plaintext token is printed ONCE; the");
            println!("                 stored hash is argon2id so the token cannot");
            println!("                 be recovered from the config.");
            0
        }
        other => {
            eprintln!("unknown admin service-account subcommand: {other}");
            1
        }
    }
}

fn cmd_admin_service_account_mint(args: &[String]) -> i32 {
    let Some(name) = parse_flag(args, "--name") else {
        eprintln!("missing --name <NAME> (e.g. --name ci-pipeline)");
        return 1;
    };
    let scopes_raw = parse_flag(args, "--scopes").unwrap_or("read");
    let scopes: Vec<&str> = scopes_raw.split(',').map(str::trim).collect();
    for s in &scopes {
        if !matches!(*s, "read" | "write") {
            eprintln!("invalid scope `{s}` — supported: read, write");
            return 1;
        }
    }

    // 2026-05-17 F-CRITICAL-002 Option B — service-account bearer
    // tokens (Phase 3 step 4+5). The token is 32 random bytes
    // (~256 bits of entropy) encoded as hex. Argon2id'd before
    // landing in YAML so a config leak doesn't disclose the
    // bearer secret.
    let raw_a = uuid::Uuid::new_v4().into_bytes();
    let raw_b = uuid::Uuid::new_v4().into_bytes();
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&raw_a);
    bytes[16..].copy_from_slice(&raw_b);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let hash = match aegis_control::admin_auth::password::hash_password(&token) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("argon2 hash failed: {e}");
            return 1;
        }
    };

    println!("Service-account token minted for `{name}` (scopes: {})", scopes.join(","));
    println!();
    println!("--- COPY THIS TOKEN (won't be shown again) ---");
    println!("Token: {token}");
    println!("---");
    println!();
    println!("Paste this fragment into cfg.admin.dashboard_auth.service_accounts:");
    println!();
    println!("  - name: \"{name}\"");
    println!("    token_hash: \"{hash}\"");
    print!("    scopes: [");
    for (i, s) in scopes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("\"{s}\"");
    }
    println!("]");
    println!();
    println!("Use the token via:  Authorization: Bearer {token}");
    println!("Reload the config (file edit + watch, or restart) for it to take effect.");
    0
}

// ---------------------------------------------------------------------------
// waf help
// ---------------------------------------------------------------------------

fn print_help() {
    println!("aegis-gate — Production WAF / Security Gateway");
    println!();
    println!("USAGE:");
    println!("    waf <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("    run       --config <path>      Start the WAF gateway");
    println!("    validate  --config <path>      Dry-run config validation + compliance check");
    println!("              [--print-route-priority]   Also print the effective route eval order (PR1)");
    println!("    migrate-config-plane --config <path>   Copy the live config+control plane Redis→etcd");
    println!("                                    (H2b cutover; needs the `etcd_config` feature)");
    println!("    audit     verify --from <path> Verify audit chain integrity");
    println!("    admin     set-password          Hash admin password (argon2id)");
    println!("    admin     create-account        Create a named admin account (accounts: fragment)");
    println!("    admin     enroll-totp           Generate TOTP secret + recovery codes + QR");
    println!("    snapshot  --output <path>       Bundle effective config + rules into a JSON snapshot");
    println!("    restore   --from <path>         Restore config + rules from a snapshot (validates first)");
    println!("    version                         Show version");
    println!("    help                            Show this help");
    println!();
    println!("See docs/operator/cli.md for the full subcommand reference.");
}


#[cfg(test)]
mod create_account_tests {
    // TOTP-4 — `waf admin create-account` prints a ready-to-paste
    // `accounts:` fragment (multi-admin model, TOTP-1). RED-first for
    // the fragment builder; the interactive prompt stays untested glue.
    use super::account_yaml_fragment;

    #[test]
    fn fragment_contains_username_hash_and_no_totp_by_default() {
        let frag = account_yaml_fragment("alice", "$argon2id$test-hash", None);
        assert!(frag.contains("- username: \"alice\""));
        assert!(frag.contains("password_hash_ref: \"$argon2id$test-hash\""));
        assert!(
            !frag.contains("totp_secret_b32"),
            "no TOTP block unless --with-totp: {frag}",
        );
    }

    #[test]
    fn fragment_with_totp_carries_secret_and_enabled_flag() {
        let frag =
            account_yaml_fragment("bob", "$argon2id$test-hash", Some("JBSWY3DPEHPK3PXP"));
        assert!(frag.contains("- username: \"bob\""));
        assert!(frag.contains("totp_secret_b32: \"JBSWY3DPEHPK3PXP\""));
        assert!(frag.contains("totp_enabled: true"));
    }
}
