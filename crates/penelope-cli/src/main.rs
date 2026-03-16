mod audit;
mod config;
mod exec;
mod hook;
mod install;
mod normalize;
mod pipeline;
mod register;
mod remote;
mod session;
mod shell;
mod tier2;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use penelope_rules::builtins::{builtin_allow_rules, builtin_block_rules};
use penelope_rules::Tier1Engine;

use audit::AuditLog;
use config::Config;
use pipeline::Pipeline;
use remote::RemoteLogger;
use tier2::Tier2Client;

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
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    shell_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a command through the proxy
    Exec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Check a command without executing it
    Check {
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run as a Claude Code PreToolUse hook (reads JSON from stdin)
    Hook,
    /// Install penelope hooks into agent tools
    Install {
        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },
    /// Remove penelope hooks from agent tools
    Uninstall {
        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },
    /// Register via GitHub OAuth to get an API key
    Register {
        /// Manually set an API key instead of OAuth
        #[arg(long)]
        key: Option<String>,
    },
    /// Enable penelope screening (creates/restores hook)
    On,
    /// Disable penelope screening (removes hook, pass-through)
    Off,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("penelope=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let raw_args: Vec<String> = std::env::args().collect();
    let is_shell_mode = raw_args.len() >= 2 && raw_args[1] == "-c";

    if is_shell_mode {
        let config = Config::load(None);
        let (pipeline, audit, remote) = build_pipeline(&config);
        let args: Vec<String> = raw_args[1..].to_vec();
        return shell::shell_mode(&args, &config.general.real_shell, &pipeline, &audit, remote.as_ref()).await;
    }

    let cli = Cli::parse();
    let config_path = cli.config.as_ref().map(std::path::Path::new);
    let config = Config::load(config_path);
    let (pipeline, audit, remote) = build_pipeline(&config);

    match cli.command {
        Some(Commands::Exec { command }) => {
            exec::exec_mode(&command, &config.general.real_shell, &pipeline, &audit, remote.as_ref()).await
        }
        Some(Commands::Check { command }) => {
            let cmd = command.join(" ");
            let result = pipeline.evaluate(&cmd).await;
            match result.decision {
                pipeline::Decision::Execute => {
                    if let Some(ref reasoning) = result.reasoning_override {
                        println!("ALLOW (reasoning override): command would be permitted");
                        println!("  Reasoning: {}", reasoning);
                        println!("  Stripped command: {}", result.normalized.stripped);
                    } else {
                        println!("ALLOW: command would be permitted");
                    }
                    println!("  Tier 1: {}", result.tier1_verdict);
                    if let Some(ref risk) = result.tier2_risk_level {
                        println!("  Tier 2: {} (confidence: {:.0}%)",
                            risk,
                            result.tier2_confidence.unwrap_or(0.0) * 100.0
                        );
                        if let Some(ref reasoning) = result.tier2_reasoning {
                            println!("  Tier 2 reasoning: {}", reasoning);
                        }
                    }
                    println!("  Segments: {:?}", result.normalized.segments);
                    if result.normalized.has_evasion() {
                        println!("  Evasion techniques detected");
                    }
                    println!("  Evaluation time: {}μs", result.duration_us);
                    ExitCode::SUCCESS
                }
                pipeline::Decision::Block { reason } => {
                    println!("BLOCK: {}", reason);
                    println!("  Tier 1: {}", result.tier1_verdict);
                    if let Some(ref risk) = result.tier2_risk_level {
                        println!("  Tier 2: {} (confidence: {:.0}%)",
                            risk,
                            result.tier2_confidence.unwrap_or(0.0) * 100.0
                        );
                    }
                    println!("  Segments: {:?}", result.normalized.segments);
                    println!("  Evaluation time: {}μs", result.duration_us);
                    ExitCode::from(1)
                }
                pipeline::Decision::AskHuman { reason } => {
                    println!("ASK HUMAN: {}", reason);
                    println!("  Tier 1: {}", result.tier1_verdict);
                    println!("  Segments: {:?}", result.normalized.segments);
                    println!("  Evaluation time: {}μs", result.duration_us);
                    ExitCode::from(2)
                }
            }
        }
        Some(Commands::Hook) => {
            hook::hook_mode(&pipeline, &audit, remote.as_ref()).await
        }
        Some(Commands::Install { targets }) => {
            install::install_mode(&targets)
        }
        Some(Commands::Uninstall { targets }) => {
            install::uninstall_mode(&targets)
        }
        Some(Commands::Register { key }) => {
            register::register_mode(key.as_deref(), &config).await
        }
        Some(Commands::On) => {
            install::install_mode(&[])
        }
        Some(Commands::Off) => {
            install::uninstall_mode(&[])
        }
        None => {
            if !cli.shell_args.is_empty() {
                shell::shell_mode(
                    &cli.shell_args,
                    &config.general.real_shell,
                    &pipeline,
                    &audit,
                    remote.as_ref(),
                ).await
            } else {
                eprintln!("penelope: no command provided. Use --help for usage.");
                ExitCode::from(1)
            }
        }
    }
}

fn build_pipeline(config: &Config) -> (Pipeline, AuditLog, Option<RemoteLogger>) {
    let mut block_rules = builtin_block_rules();
    let mut allow_rules = builtin_allow_rules();

    block_rules.extend(config.tier1.block.clone());
    allow_rules.extend(config.tier1.allow.clone());

    let engine = Tier1Engine::new(block_rules, allow_rules).unwrap_or_else(|e| {
        eprintln!("penelope: failed to compile rules: {}", e);
        std::process::exit(1);
    });

    let tier2 = Tier2Client::new(&config.tier2, &config.remote);
    if tier2.is_some() {
        tracing::info!("Tier 2 NLI classifier enabled");
    }

    let pipeline = Pipeline::new(engine, tier2);
    let audit = AuditLog::new(&config.log_file_path());

    let remote = RemoteLogger::new(&config.remote);
    if remote.is_some() {
        tracing::info!("Remote audit logging enabled");
    }

    (pipeline, audit, remote)
}
