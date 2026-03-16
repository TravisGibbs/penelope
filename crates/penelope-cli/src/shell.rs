use std::process::ExitCode;

use crate::audit::{AuditEntry, AuditLog};
use crate::pipeline::{Decision, Pipeline};
use crate::session::get_or_create_session_id;

/// Shell wrapper mode.
/// Called when Penelope is set as SHELL and receives -c "command".
pub fn shell_mode(
    args: &[String],
    real_shell: &str,
    pipeline: &Pipeline,
    audit: &AuditLog,
) -> ExitCode {
    // Find -c argument
    let cmd = match find_dash_c_command(args) {
        Some(cmd) => cmd,
        None => {
            // Not a -c invocation — exec the real shell directly with all args.
            // This handles interactive shell requests.
            let err = exec_real_shell(real_shell, args);
            eprintln!("penelope: failed to exec {}: {}", real_shell, err);
            return ExitCode::from(126);
        }
    };

    evaluate_and_exec(cmd, args, real_shell, pipeline, audit)
}

/// Extract the command string after -c.
fn find_dash_c_command(args: &[String]) -> Option<&str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-c" {
            return iter.next().map(|s| s.as_str());
        }
    }
    None
}

/// Evaluate a command through the pipeline and either exec or block.
pub fn evaluate_and_exec(
    cmd: &str,
    original_args: &[String],
    real_shell: &str,
    pipeline: &Pipeline,
    audit: &AuditLog,
) -> ExitCode {
    let session_id = get_or_create_session_id();
    let result = pipeline.evaluate(cmd);

    // Use the stripped command (without --penelope-reasoning) for execution
    let stripped_cmd = &result.normalized.stripped;

    let mut audit_entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        session_id,
        command: cmd.to_string(),
        normalized_segments: result.normalized.segments.clone(),
        has_evasion: result.normalized.has_evasion(),
        tier1_verdict: result.tier1_verdict.clone(),
        tier1_matched_rule: result.tier1_matched_rule.clone(),
        final_decision: String::new(),
        reason: None,
        exit_code: None,
        duration_us: Some(result.duration_us),
        agent_reasoning: result.normalized.reasoning.clone(),
        overridden_block: if result.reasoning_override.is_some() {
            result.tier1_matched_rule.clone()
        } else {
            None
        },
        tier2_risk_level: result.tier2_risk_level.clone(),
        tier2_confidence: result.tier2_confidence,
        tier2_reasoning: result.tier2_reasoning.clone(),
        tier2_latency_us: result.tier2_latency_us,
    };

    match result.decision {
        Decision::Block { reason } => {
            eprintln!("penelope: BLOCKED — {}", reason);
            eprintln!("penelope: command: {}", cmd);
            audit_entry.final_decision = "block".into();
            audit_entry.reason = Some(reason);
            audit_entry.exit_code = Some(126);
            audit.write(&audit_entry);
            ExitCode::from(126)
        }
        Decision::AskHuman { reason } => {
            // Prompt the user via /dev/tty
            eprintln!("penelope: REVIEW REQUIRED — {}", reason);
            eprintln!("penelope: command: {}", cmd);

            let approved = prompt_human(cmd);
            if approved {
                audit_entry.final_decision = "execute_human_approved".into();
                audit_entry.reason = Some(reason);
                audit.write(&audit_entry);
                exec_command(stripped_cmd, cmd, original_args, real_shell)
            } else {
                audit_entry.final_decision = "block_human_denied".into();
                audit_entry.reason = Some(reason);
                audit_entry.exit_code = Some(126);
                audit.write(&audit_entry);
                ExitCode::from(126)
            }
        }
        Decision::Execute => {
            if result.reasoning_override.is_some() {
                audit_entry.final_decision = "execute_reasoning_override".into();
            } else {
                audit_entry.final_decision = "execute".into();
            }
            audit.write(&audit_entry);
            exec_command(stripped_cmd, cmd, original_args, real_shell)
        }
    }
}

/// Prompt the user for approval via /dev/tty.
fn prompt_human(cmd: &str) -> bool {
    use std::io::{BufRead, Write};

    // Open /dev/tty directly so it works even when stdin/stdout are captured
    let tty_out = std::fs::OpenOptions::new().write(true).open("/dev/tty");
    let tty_in = std::fs::File::open("/dev/tty");

    match (tty_out, tty_in) {
        (Ok(mut out), Ok(input)) => {
            let _ = writeln!(out, "\npenelope: approve this command? [y/N] {}", cmd);
            let _ = write!(out, "> ");
            let _ = out.flush();

            let reader = std::io::BufReader::new(input);
            if let Some(Ok(line)) = reader.lines().next() {
                matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
            } else {
                false
            }
        }
        _ => {
            // Can't open /dev/tty — deny by default
            eprintln!("penelope: cannot open /dev/tty for human approval, denying");
            false
        }
    }
}

/// Execute a command via the real shell.
fn exec_command(
    stripped_cmd: &str,
    original_cmd: &str,
    original_args: &[String],
    real_shell: &str,
) -> ExitCode {
    let exec_args: Vec<String> = if stripped_cmd != original_cmd {
        original_args
            .iter()
            .map(|a| if a == original_cmd { stripped_cmd.to_string() } else { a.clone() })
            .collect()
    } else {
        original_args.to_vec()
    };

    let status = std::process::Command::new(real_shell)
        .args(&exec_args)
        .status();

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("penelope: failed to exec {}: {}", real_shell, e);
            ExitCode::from(126)
        }
    }
}

/// Exec the real shell, replacing the current process.
/// This is used for interactive shell mode.
fn exec_real_shell(real_shell: &str, args: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    // This replaces the current process
    std::process::Command::new(real_shell).args(args).exec()
}
