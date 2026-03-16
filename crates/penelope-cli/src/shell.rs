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
        Decision::Execute => {
            if result.reasoning_override.is_some() {
                audit_entry.final_decision = "execute_reasoning_override".into();
            } else {
                audit_entry.final_decision = "execute".into();
            }
            audit.write(&audit_entry);

            // Build shell args with the stripped command (no --penelope-reasoning)
            let exec_args: Vec<String> = if stripped_cmd != cmd {
                // Replace the command in -c args with the stripped version
                original_args
                    .iter()
                    .map(|a| if a == cmd { stripped_cmd.clone() } else { a.clone() })
                    .collect()
            } else {
                original_args.to_vec()
            };

            // Execute the command via the real shell
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
    }
}

/// Exec the real shell, replacing the current process.
/// This is used for interactive shell mode.
fn exec_real_shell(real_shell: &str, args: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    // This replaces the current process
    std::process::Command::new(real_shell).args(args).exec()
}
