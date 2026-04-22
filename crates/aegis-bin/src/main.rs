use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::{AuditBus, ReadinessSignal};

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "run" => {
            let config_path = parse_config_flag(&args);
            if let Err(e) = run_gateway(&config_path) {
                tracing::error!("{e}");
                std::process::exit(1);
            }
        }
        "validate" => {
            let config_path = parse_config_flag(&args);
            match aegis_core::load_config(&config_path) {
                Ok(_) => println!("config OK: {}", config_path.display()),
                Err(e) => {
                    eprintln!("config error: {e}");
                    std::process::exit(1);
                }
            }
        }
        "version" => {
            println!(
                "aegis-gate {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_NAME"),
            );
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("run `waf help` for usage");
            std::process::exit(1);
        }
    }
}

fn parse_config_flag(args: &[String]) -> PathBuf {
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--config" {
            if let Some(path) = args.get(i + 1) {
                return PathBuf::from(path);
            }
        }
        i += 1;
    }
    PathBuf::from("config/waf.yaml")
}

fn run_gateway(config_path: &std::path::Path) -> aegis_core::Result<()> {
    let cfg = aegis_core::load_config(config_path)?;
    let cfg = Arc::new(cfg);

    tracing::info!("loaded config from {}", config_path.display());

    let pipeline: Arc<dyn aegis_core::SecurityPipeline> =
        Arc::new(aegis_security::NoopPipeline);
    let state: Arc<dyn aegis_core::StateBackend> =
        Arc::new(aegis_proxy::state::InMemoryBackend::new());
    let bus = AuditBus::new(4096);
    let readiness = ReadinessSignal::default();

    let rt = tokio::runtime::Runtime::new().map_err(aegis_core::WafError::Io)?;
    rt.block_on(aegis_proxy::run(cfg, pipeline, state, bus, readiness))
}

fn print_help() {
    println!("aegis-gate — WAF / Security Gateway");
    println!();
    println!("USAGE:");
    println!("    waf <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("    run  --config <path>   Start the WAF (default: config/waf.yaml)");
    println!("    validate --config <path>  Dry-run config validation");
    println!("    version                Show version");
    println!("    help                   Show this help");
}
