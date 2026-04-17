use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "run" => {
            let config_path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("config/waf.yaml");
            println!("aegis-gate starting with config: {config_path}");
            println!("(not yet implemented — crate skeleton only)");
        }
        "validate" => {
            let config_path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("config/waf.yaml");
            println!("validating config: {config_path}");
            println!("(not yet implemented)");
        }
        "version" => {
            println!(
                "aegis-gate {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_NAME"),
            );
        }
        "help" | "--help" | "-h" => {
            println!("aegis-gate — WAF / Security Gateway");
            println!();
            println!("USAGE:");
            println!("    waf <command> [options]");
            println!();
            println!("COMMANDS:");
            println!("    run [config]       Start the WAF (default: config/waf.yaml)");
            println!("    validate [config]  Dry-run config validation");
            println!("    version            Show version");
            println!("    help               Show this help");
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("run `waf help` for usage");
            std::process::exit(1);
        }
    }
}
