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
        tracing_subscriber::fmt::init();
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
    // ETCD-T1 — `AEGIS_CONFIG_SOURCE=etcd` switches the boot path
    // to fetch `WafConfig` from an etcd v3 key (default
    // `/aegis/config/waf`) instead of reading the local YAML
    // file. Falls through to the file loader for the default
    // (unset / `file`) case.
    let cfg = match resolve_config_source() {
        ConfigSource::File => aegis_core::load_config(config_path)?,
        #[cfg(feature = "etcd")]
        ConfigSource::Etcd => load_config_from_etcd()?,
        #[cfg(not(feature = "etcd"))]
        ConfigSource::Etcd => {
            return Err(aegis_core::WafError::Config(
                "AEGIS_CONFIG_SOURCE=etcd requires `--features etcd` build"
                    .into(),
            ));
        }
    };
    let cfg = Arc::new(cfg);

    // Layer-1 — build the tokio runtime from `runtime:` config.
    // Restart-only by design: tokio's worker_threads is fixed at
    // builder time. The admin surface rejects hot-reload requests
    // for these fields.
    let rt = build_runtime(&cfg.runtime)?;
    rt.block_on(run_gateway_inner(cfg, config_path))
}

/// What the `AEGIS_CONFIG_SOURCE` env var resolves to. `file`
/// (or unset) keeps the existing YAML-from-disk path; `etcd`
/// switches to the etcd v3 loader (requires `--features etcd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSource {
    File,
    Etcd,
}

fn resolve_config_source() -> ConfigSource {
    match std::env::var("AEGIS_CONFIG_SOURCE")
        .ok()
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some("etcd") => ConfigSource::Etcd,
        _ => ConfigSource::File,
    }
}

#[cfg(feature = "etcd")]
fn load_config_from_etcd() -> aegis_core::Result<aegis_core::config::WafConfig> {
    use aegis_proxy::config_source::etcd_source::EtcdConfigSource;

    let src = EtcdConfigSource::from_env();
    tracing::info!(
        endpoints = ?src.endpoints,
        key = %src.key,
        "loading config from etcd",
    );

    // Build a small bootstrap runtime just for the fetch; the
    // real `runtime:`-shaped runtime is built afterwards from
    // the loaded config.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(aegis_core::WafError::Io)?;

    rt.block_on(async {
        src.load()
            .await
            .map_err(|e| aegis_core::WafError::Config(format!("{e}")))
    })
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
    aegis_proxy::run(
        cfg_swap,
        pipeline,
        state,
        lease_store,
        bus,
        readiness,
        reload_source,
    )
    .await
}

/// Pick the [`aegis_proxy::ConfigReloadSource`] for `run_gateway`
/// based on `AEGIS_CONFIG_SOURCE`. The file path is used both for
/// the initial load (in `run_gateway`) and as the watcher root
/// here. The etcd source mirrors `load_config_from_etcd`'s env
/// resolution so a single set of vars drives both initial fetch
/// and ongoing watch.
fn resolve_reload_source(
    config_path: &std::path::Path,
) -> aegis_proxy::ConfigReloadSource {
    match resolve_config_source() {
        ConfigSource::File => {
            aegis_proxy::ConfigReloadSource::File(config_path.to_path_buf())
        }
        #[cfg(feature = "etcd")]
        ConfigSource::Etcd => aegis_proxy::ConfigReloadSource::Etcd(
            aegis_proxy::config_source::etcd_source::EtcdConfigSource::from_env(),
        ),
        #[cfg(not(feature = "etcd"))]
        ConfigSource::Etcd => {
            // Should be unreachable — `load_config_from_etcd`
            // would have already errored at boot. Fall through
            // to no watcher just in case.
            aegis_proxy::ConfigReloadSource::None
        }
    }
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
        Ok(mut cfg) => {
            println!("config OK: {}", config_path.display());
            // If compliance profiles are set, apply and report.
            if let Some(profile) = cfg.compliance.as_ref() {
                if !profile.modes.is_empty() {
                    let modes = profile.modes.clone();
                    match aegis_control::compliance::apply(&modes, &mut cfg) {
                        Ok(()) => {
                            println!(
                                "compliance profiles applied: {:?}",
                                modes
                            );
                        }
                        Err(e) => {
                            eprintln!("compliance error: {e}");
                            return 1;
                        }
                    }
                }
            }
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
        "enroll-totp" => cmd_admin_enroll_totp(args),
        "service-account" => cmd_admin_service_account(args),
        "help" | "--help" => {
            println!("waf admin <subcommand>");
            println!();
            println!("SUBCOMMANDS:");
            println!("    set-password           Hash a password (interactive prompt)");
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

fn cmd_admin_set_password() -> i32 {
    println!("Enter password (will echo — pipe from stdin in prod):");
    let mut password = String::new();
    if std::io::stdin().read_line(&mut password).is_err() {
        eprintln!("failed to read password");
        return 1;
    }
    let password = password.trim();
    if password.is_empty() {
        eprintln!("password cannot be empty");
        return 1;
    }
    match aegis_control::admin_auth::password::hash_password(password) {
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

    // 2026-05-17 F-CRITICAL-003 follow-up: this CLI is the operator-
    // facing half of the TOTP wire-up. Pre-fix `secret_bytes` was
    // derived from `blake3(nanos:pid)` — predictable enough to
    // brute-force the secret given approximate clock skew, even
    // though the per-call output looks random. UUID v4 is what we
    // standardised on for tokens (see `csrf.rs`, `session.rs`);
    // reuse it here as the CSPRNG source.
    let mut secret = [0u8; 32];
    let id_bytes_a = uuid::Uuid::new_v4().into_bytes();
    let id_bytes_b = uuid::Uuid::new_v4().into_bytes();
    secret[..16].copy_from_slice(&id_bytes_a);
    secret[16..].copy_from_slice(&id_bytes_b);

    // Pre-fix `b32` came from a byte-modulo-32 character mapping —
    // not real RFC 4648 base32. Authenticator apps decoded the
    // string back to bytes expecting a round-trip, got garbage,
    // and generated TOTP codes that never matched the WAF's
    // expected codes. The whole feature was end-to-end broken even
    // after the SHA-256 → SHA-1 fix in Phase 3 step 3. Now use the
    // `base32` crate (RFC 4648, no padding — matches what
    // `api::login::authenticate` decodes with).
    let b32 = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &secret,
    );

    let uri = aegis_control::admin_auth::totp::provisioning_uri(&b32, issuer, account);

    // Generate recovery codes.
    let recovery = aegis_control::admin_auth::totp::generate_recovery_codes(&secret);

    println!("TOTP Secret (base32): {b32}");
    println!("Provisioning URI:     {uri}");
    println!();
    println!("Paste this into cfg.admin.dashboard_auth:");
    println!("  totp_enabled: true");
    println!("  totp_secret_b32: \"{b32}\"");
    println!();
    println!("Recovery codes (store securely, each usable once):");
    for (i, code) in recovery.iter().enumerate() {
        println!("  {}: {code}", i + 1);
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
    println!("    audit     verify --from <path> Verify audit chain integrity");
    println!("    admin     set-password          Hash admin password (argon2id)");
    println!("    admin     enroll-totp           Generate TOTP secret + recovery codes");
    println!("    snapshot  --output <path>       Bundle effective config + rules into a JSON snapshot");
    println!("    restore   --from <path>         Restore config + rules from a snapshot (validates first)");
    println!("    version                         Show version");
    println!("    help                            Show this help");
    println!();
    println!("See docs/operator/cli.md for the full subcommand reference.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-wide mutex serialising tests that mutate
    /// `AEGIS_CONFIG_SOURCE`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<F: FnOnce()>(value: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("AEGIS_CONFIG_SOURCE").ok();
        match value {
            Some(v) => std::env::set_var("AEGIS_CONFIG_SOURCE", v),
            None => std::env::remove_var("AEGIS_CONFIG_SOURCE"),
        }
        f();
        match prior {
            Some(v) => std::env::set_var("AEGIS_CONFIG_SOURCE", v),
            None => std::env::remove_var("AEGIS_CONFIG_SOURCE"),
        }
    }

    #[test]
    fn config_source_defaults_to_file_when_unset() {
        with_env(None, || {
            assert_eq!(resolve_config_source(), ConfigSource::File);
        });
    }

    #[test]
    fn config_source_defaults_to_file_when_empty() {
        with_env(Some(""), || {
            assert_eq!(resolve_config_source(), ConfigSource::File);
        });
        with_env(Some("   "), || {
            assert_eq!(resolve_config_source(), ConfigSource::File);
        });
    }

    #[test]
    fn config_source_resolves_etcd() {
        with_env(Some("etcd"), || {
            assert_eq!(resolve_config_source(), ConfigSource::Etcd);
        });
    }

    #[test]
    fn config_source_unknown_value_falls_back_to_file() {
        with_env(Some("redis"), || {
            assert_eq!(resolve_config_source(), ConfigSource::File);
        });
        with_env(Some("file"), || {
            assert_eq!(resolve_config_source(), ConfigSource::File);
        });
    }
}
