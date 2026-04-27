use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::{AuditBus, ReadinessSignal};

fn main() {
    tracing_subscriber::fmt::init();

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
    parse_flag(args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/waf.yaml"))
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

// ---------------------------------------------------------------------------
// waf validate
// ---------------------------------------------------------------------------

fn cmd_validate(args: &[String]) -> i32 {
    let config_path = parse_config_flag(args);
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
            0
        }
        Err(e) => {
            eprintln!("config error: {e}");
            1
        }
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
        "help" | "--help" => {
            println!("waf admin <subcommand>");
            println!();
            println!("SUBCOMMANDS:");
            println!("    set-password           Hash a password (interactive prompt)");
            println!("    enroll-totp --issuer <ISSUER> --account <ACCOUNT>");
            println!("                           Generate TOTP secret + provisioning URI");
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

    // Generate a random secret (32 bytes).
    let secret_bytes = blake3::hash(
        format!(
            "totp:{}:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            std::process::id()
        )
        .as_bytes(),
    );
    let secret = secret_bytes.as_bytes();

    // Base32-encode the secret for the provisioning URI.
    let b32: String = secret
        .iter()
        .map(|b| {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            ALPHABET[(*b as usize) % ALPHABET.len()] as char
        })
        .collect();

    let uri = aegis_control::admin_auth::totp::provisioning_uri(&b32, issuer, account);

    // Generate recovery codes.
    let recovery = aegis_control::admin_auth::totp::generate_recovery_codes(secret);

    println!("TOTP Secret (base32): {b32}");
    println!("Provisioning URI: {uri}");
    println!();
    println!("Recovery codes (store securely, each usable once):");
    for (i, code) in recovery.iter().enumerate() {
        println!("  {}: {code}", i + 1);
    }
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
    println!("    audit     verify --from <path> Verify audit chain integrity");
    println!("    admin     set-password          Hash admin password (argon2id)");
    println!("    admin     enroll-totp           Generate TOTP secret + recovery codes");
    println!("    version                         Show version");
    println!("    help                            Show this help");
    println!();
    println!("See docs/cli.md for the full subcommand reference.");
}
