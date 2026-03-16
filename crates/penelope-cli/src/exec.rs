use std::process::ExitCode;

use crate::audit::AuditLog;
use crate::pipeline::Pipeline;
use crate::shell::evaluate_and_exec;

/// Exec mode: `penelope exec -- <command> [args...]`
/// Joins all args after -- into a single command string and evaluates.
pub fn exec_mode(
    command_args: &[String],
    real_shell: &str,
    pipeline: &Pipeline,
    audit: &AuditLog,
) -> ExitCode {
    if command_args.is_empty() {
        eprintln!("penelope: exec mode requires a command");
        return ExitCode::from(1);
    }

    // Join all args into a single command string
    let cmd = command_args.join(" ");

    // Build the shell args: -c "command string"
    let shell_args = vec!["-c".to_string(), cmd.clone()];

    evaluate_and_exec(&cmd, &shell_args, real_shell, pipeline, audit)
}
