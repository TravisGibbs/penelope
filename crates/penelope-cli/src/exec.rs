use std::process::ExitCode;

use crate::audit::AuditLog;
use crate::pipeline::Pipeline;
use crate::remote::RemoteLogger;
use crate::shell::evaluate_and_exec;

pub async fn exec_mode(
    command_args: &[String],
    real_shell: &str,
    pipeline: &Pipeline,
    audit: &AuditLog,
    remote: Option<&RemoteLogger>,
) -> ExitCode {
    if command_args.is_empty() {
        eprintln!("penelope: exec mode requires a command");
        return ExitCode::from(1);
    }

    let cmd = command_args.join(" ");
    let shell_args = vec!["-c".to_string(), cmd.clone()];

    evaluate_and_exec(&cmd, &shell_args, real_shell, pipeline, audit, remote).await
}
