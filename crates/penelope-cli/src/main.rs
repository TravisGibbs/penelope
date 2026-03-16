mod audit;
mod config;
mod exec;
mod hook;
mod install;
mod normalize;
mod pipeline;
mod session;
mod shell;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use penelope_rules::builtins::{builtin_allow_rules, builtin_block_rules};
use penelope_rules::Tier1Engine;

use audit::AuditLog;
use config::Config;
use pipeline::Pipeline;

#[derive(Parser)]
#[command(
    name = "penelope",
    about = "CLI proxy that screens agent commands for harm",
    version
)]
struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Arguments passed in shell mode (when used as SHELL).
    /// Captures all trailing args like: penelope -c "command"
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    shell_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a command through the proxy
    Exec {
        /// The command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Check a command without executing it
    Check {
        /// The command string to check
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run as a Claude Code PreToolUse hook (reads JSON from stdin)
    Hook,
    /// Install penelope hooks into agent tools
    Install {
        /// Targets to install: claude, codex (default: claude)
        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },
    /// Remove penelope hooks from agent tools
    Uninstall {
        /// Targets to uninstall: claude, codex (default: claude)
        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },
}

fn main() -> ExitCode {
    // Initialize tracing (always to stderr so stdout is clean for hook JSON output)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("penelope=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    // Detect shell mode: when invoked as SHELL, first arg after binary name
    // is typically -c followed by the command string.
    let raw_args: Vec<String> = std::env::args().collect();

    // Check if we're being invoked in shell mode (e.g., -c "command")
    // This happens before clap parsing because -c isn't a clap argument.
    let is_shell_mode = raw_args.len() >= 2 && raw_args[1] == "-c";

    if is_shell_mode {
        let config = Config::load(None);
        let (pipeline, audit) = build_pipeline(&config);
        let args: Vec<String> = raw_args[1..].to_vec();
        return shell::shell_mode(&args, &config.general.real_shell, &pipeline, &audit);
    }

    // Normal CLI mode — use clap
    let cli = Cli::parse();
    let config_path = cli.config.as_ref().map(std::path::Path::new);
    let config = Config::load(config_path);
    let (pipeline, audit) = build_pipeline(&config);

    match cli.command {
        Some(Commands::Exec { command }) => {
            exec::exec_mode(&command, &config.general.real_shell, &pipeline, &audit)
        }
        Some(Commands::Check { command }) => {
            let cmd = command.join(" ");
            let result = pipeline.evaluate(&cmd);
            match result.decision {
                pipeline::Decision::Execute => {
                    println!("ALLOW: command would be permitted");
                    println!("  Tier 1: {}", result.tier1_verdict);
                    println!("  Segments: {:?}", result.normalized.segments);
                    if result.normalized.has_evasion() {
                        println!("  ⚠ Evasion techniques detected");
                    }
                    println!("  Evaluation time: {}μs", result.duration_us);
                    ExitCode::SUCCESS
                }
                pipeline::Decision::Block { reason } => {
                    println!("BLOCK: {}", reason);
                    println!("  Tier 1: {}", result.tier1_verdict);
                    println!("  Segments: {:?}", result.normalized.segments);
                    if result.normalized.has_evasion() {
                        println!("  Evasion techniques detected");
                    }
                    println!("  Evaluation time: {}μs", result.duration_us);
                    ExitCode::from(1)
                }
            }
        }
        Some(Commands::Hook) => {
            hook::hook_mode(&pipeline, &audit)
        }
        Some(Commands::Install { targets }) => {
            install::install_mode(&targets)
        }
        Some(Commands::Uninstall { targets }) => {
            install::uninstall_mode(&targets)
        }
        None => {
            // If no subcommand and we have shell_args, try shell mode
            if !cli.shell_args.is_empty() {
                shell::shell_mode(
                    &cli.shell_args,
                    &config.general.real_shell,
                    &pipeline,
                    &audit,
                )
            } else {
                eprintln!("penelope: no command provided. Use --help for usage.");
                ExitCode::from(1)
            }
        }
    }
}

fn build_pipeline(config: &Config) -> (Pipeline, AuditLog) {
    // Combine built-in rules with config rules
    let mut block_rules = builtin_block_rules();
    let mut allow_rules = builtin_allow_rules();

    block_rules.extend(config.tier1.block.clone());
    allow_rules.extend(config.tier1.allow.clone());

    let engine = Tier1Engine::new(block_rules, allow_rules).unwrap_or_else(|e| {
        eprintln!("penelope: failed to compile rules: {}", e);
        std::process::exit(1);
    });

    let pipeline = Pipeline::new(engine);
    let audit = AuditLog::new(&config.log_file_path());

    (pipeline, audit)
}
