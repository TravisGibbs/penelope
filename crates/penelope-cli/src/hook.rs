use std::io::Read;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::audit::{AuditEntry, AuditLog};
use crate::pipeline::{Decision, Pipeline};
use crate::session::get_or_create_session_id;

/// Input format from Claude Code PreToolUse hook (received on stdin).
#[derive(Debug, Deserialize)]
struct HookInput {
    tool_name: Option<String>,
    tool_input: Option<ToolInput>,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    command: Option<String>,
}

/// Output format for Claude Code hook decisions (written to stdout).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookOutput {
    hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    hook_event_name: String,
    permission_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
    /// Rewritten command with --penelope-reasoning stripped
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_command: Option<String>,
}

/// Hook mode: reads Claude Code PreToolUse JSON from stdin, evaluates, outputs decision.
pub fn hook_mode(pipeline: &Pipeline, audit: &AuditLog) -> ExitCode {
    // Read JSON from stdin
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("penelope: failed to read stdin: {}", e);
        return ExitCode::from(2);
    }

    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("penelope: failed to parse hook input: {}", e);
            return ExitCode::from(2);
        }
    };

    // Only screen Bash tool calls
    let tool_name = hook_input.tool_name.as_deref().unwrap_or("");
    if tool_name != "Bash" {
        // Not a Bash command — allow
        return ExitCode::SUCCESS;
    }

    let cmd = match hook_input.tool_input.as_ref().and_then(|t| t.command.as_deref()) {
        Some(c) => c,
        None => {
            // No command field — allow
            return ExitCode::SUCCESS;
        }
    };

    let session_id = hook_input
        .session_id
        .unwrap_or_else(get_or_create_session_id);

    let result = pipeline.evaluate(cmd);

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
        Decision::Execute => {
            if result.reasoning_override.is_some() {
                audit_entry.final_decision = "execute_reasoning_override".into();
            } else {
                audit_entry.final_decision = "execute".into();
            }
            audit.write(&audit_entry);

            // If command had reasoning stripped, rewrite the command for execution
            if result.normalized.stripped != cmd {
                let output = HookOutput {
                    hook_specific_output: HookSpecificOutput {
                        hook_event_name: "PreToolUse".into(),
                        permission_decision: "allow".into(),
                        permission_decision_reason: None,
                        updated_command: Some(result.normalized.stripped.clone()),
                    },
                };
                let _ = serde_json::to_writer(std::io::stdout(), &output);
                println!();
            }

            ExitCode::SUCCESS
        }
        Decision::Block { reason } => {
            audit_entry.final_decision = "block".into();
            audit_entry.reason = Some(reason.clone());
            audit_entry.exit_code = Some(2);
            audit.write(&audit_entry);

            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse".into(),
                    permission_decision: "deny".into(),
                    permission_decision_reason: Some(format!("penelope: {}", reason)),
                    updated_command: None,
                },
            };
            let _ = serde_json::to_writer(std::io::stdout(), &output);
            println!();

            eprintln!("penelope: BLOCKED — {}", reason);
            ExitCode::from(2)
        }
        Decision::AskHuman { reason } => {
            audit_entry.final_decision = "escalate_human".into();
            audit_entry.reason = Some(reason.clone());
            audit.write(&audit_entry);

            // Return "ask" — Claude Code will prompt the user for approval
            let output = HookOutput {
                hook_specific_output: HookSpecificOutput {
                    hook_event_name: "PreToolUse".into(),
                    permission_decision: "ask".into(),
                    permission_decision_reason: Some(format!(
                        "penelope: {} — please review this command",
                        reason
                    )),
                    updated_command: None,
                },
            };
            let _ = serde_json::to_writer(std::io::stdout(), &output);
            println!();

            ExitCode::SUCCESS
        }
    }
}
