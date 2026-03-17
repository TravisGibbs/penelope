mod audit;
mod config;
mod exec;
mod hook;
mod install;
mod learner;
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
    /// Give feedback on the last escalation
    Feedback {
        /// "ok" (correct escalation) or "bad" (shouldn't have asked)
        signal: String,
    },
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
        Some(Commands::Feedback { signal }) => {
            feedback_mode(&signal, &config)
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

fn feedback_mode(signal: &str, config: &Config) -> ExitCode {
    let is_correct = match signal.to_lowercase().as_str() {
        "ok" | "good" | "yes" | "correct" | "true" => true,
        "bad" | "no" | "wrong" | "false" | "fp" => false,
        _ => {
            eprintln!("penelope: unknown feedback signal '{}'. Use 'ok' or 'bad'.", signal);
            return ExitCode::from(1);
        }
    };

    // Find the last escalated entry in the audit log
    let log_path = config.log_file_path();
    let contents = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("penelope: no audit log found at {}", log_path.display());
            return ExitCode::from(1);
        }
    };

    // Find the last entry with tier2 features
    let mut last_features: Option<learner::RiskFeatures> = None;
    let mut last_command = String::new();

    for line in contents.lines().rev() {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            // Look for entries that went through tier2 or were escalated
            let verdict = entry.get("tier1_verdict").and_then(|v| v.as_str()).unwrap_or("");
            if verdict.starts_with("tier2_") || verdict.contains("escalate") {
                // Try to extract features from tier2 fields
                let is_destructive = entry.get("tier2_risk_level").is_some();
                if is_destructive {
                    // We have tier2 data — reconstruct features
                    // For now, use a simple feature extraction from what's logged
                    last_command = entry.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    // Check if we have the raw features (from tier2 response)
                    // Fall back to approximating from what we have
                    let risk_level = entry.get("tier2_risk_level").and_then(|v| v.as_str()).unwrap_or("medium");
                    let confidence = entry.get("tier2_confidence").and_then(|v| v.as_f64()).unwrap_or(0.5);

                    last_features = Some(learner::RiskFeatures {
                        is_destructive: if risk_level == "block" || risk_level == "high" { confidence } else { 0.1 },
                        is_exfiltration: 0.0,
                        is_privilege_escalation: 0.0,
                        is_normal_dev: if risk_level == "low" { confidence } else { 0.1 },
                        overall_risk: match risk_level {
                            "block" => 0.95,
                            "high" => 0.75,
                            "medium" => 0.5,
                            _ => 0.2,
                        },
                    });
                    break;
                }

                // No tier2 data but was escalated — use defaults for the escalation
                if verdict.contains("escalate") {
                    last_command = entry.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    last_features = Some(learner::RiskFeatures {
                        is_destructive: 0.3,
                        is_exfiltration: 0.1,
                        is_privilege_escalation: 0.1,
                        is_normal_dev: 0.3,
                        overall_risk: 0.5,
                    });
                    break;
                }
            }
        }
    }

    let features = match last_features {
        Some(f) => f,
        None => {
            eprintln!("penelope: no recent escalation found in audit log");
            return ExitCode::from(1);
        }
    };

    // Load user model, update, save
    let user_id = session::get_or_create_session_id();
    let model_path = learner::UserModel::model_path(&user_id);
    let mut model = learner::UserModel::load(&model_path);

    let before = model.predict(&features);
    model.update(&features, is_correct);
    let after = model.predict(&features);

    if let Err(e) = model.save(&model_path) {
        eprintln!("penelope: failed to save model: {}", e);
        return ExitCode::from(1);
    }

    let label = if is_correct { "correct" } else { "false positive" };
    println!("penelope: feedback recorded as '{}'", label);
    println!("  Command: {}", last_command);
    println!("  Risk score: {:.1}% → {:.1}%", before * 100.0, after * 100.0);
    println!("  Model updates: {}", model.n_updates);
    println!("  Saved to: {}", model_path.display());

    ExitCode::SUCCESS
}
