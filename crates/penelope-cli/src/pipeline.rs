use penelope_rules::{Tier1Engine, Verdict};
use std::time::Instant;

use crate::normalize::{self, NormalizedCommand};
use crate::tier2::OfflineAction;

/// The final decision after evaluating a command.
#[derive(Debug)]
pub enum Decision {
    /// Command is safe to execute.
    Execute,
    /// Command is blocked.
    Block { reason: String },
    /// Command needs human approval (offline escalation).
    AskHuman { reason: String },
}

/// Result of pipeline evaluation with metadata for audit logging.
pub struct EvalResult {
    pub decision: Decision,
    pub normalized: NormalizedCommand,
    pub tier1_verdict: String,
    pub tier1_matched_rule: Option<String>,
    /// Agent-provided reasoning that overrode a block (if any)
    pub reasoning_override: Option<String>,
    /// Tier 2 classification results (None if tier2 not invoked)
    pub tier2_risk_level: Option<String>,
    pub tier2_confidence: Option<f64>,
    pub tier2_reasoning: Option<String>,
    pub tier2_latency_us: Option<u64>,
    pub duration_us: u64,
}

/// The evaluation pipeline.
pub struct Pipeline {
    tier1: Tier1Engine,
    /// What to do when a command is escalated and tier2 is unavailable.
    offline_action: OfflineAction,
}

impl Pipeline {
    pub fn new(tier1: Tier1Engine, offline_action: OfflineAction) -> Self {
        Self {
            tier1,
            offline_action,
        }
    }

    /// Evaluate a raw command string through the pipeline.
    pub fn evaluate(&self, raw_cmd: &str) -> EvalResult {
        let start = Instant::now();
        let normalized = normalize::normalize(raw_cmd);
        let has_reasoning = normalized.reasoning.is_some();

        let mut result = self.evaluate_inner(&normalized, raw_cmd, start);

        // If agent provided reasoning, override blocks → allow
        if has_reasoning {
            if let Decision::Block { ref reason } = result.decision {
                tracing::info!(
                    command = raw_cmd,
                    reasoning = normalized.reasoning.as_deref().unwrap_or(""),
                    original_block = reason.as_str(),
                    "Block overridden by agent reasoning"
                );
                result.reasoning_override = normalized.reasoning.clone();
                result.decision = Decision::Execute;
            }
        }

        result
    }

    /// Apply offline action when a command is escalated and tier2 is unavailable.
    fn apply_offline_action(&self, reason: &str) -> Decision {
        match self.offline_action {
            OfflineAction::Allow => Decision::Execute,
            OfflineAction::Block => Decision::Block {
                reason: reason.to_string(),
            },
            OfflineAction::Escalate => Decision::AskHuman {
                reason: reason.to_string(),
            },
        }
    }

    fn make_result(
        &self,
        decision: Decision,
        tier1_verdict: &str,
        tier1_matched_rule: Option<String>,
        normalized: &NormalizedCommand,
        start: Instant,
    ) -> EvalResult {
        EvalResult {
            decision,
            tier1_verdict: tier1_verdict.into(),
            tier1_matched_rule,
            reasoning_override: None,
            tier2_risk_level: None,
            tier2_confidence: None,
            tier2_reasoning: None,
            tier2_latency_us: None,
            normalized: normalized.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        }
    }

    fn evaluate_inner(
        &self,
        normalized: &NormalizedCommand,
        raw_cmd: &str,
        start: Instant,
    ) -> EvalResult {
        // If evasion was detected, be conservative
        if normalized.has_evasion() {
            for segment in &normalized.segments {
                if let Verdict::Block(reason) = self.tier1.evaluate(segment) {
                    return self.make_result(
                        Decision::Block {
                            reason: format!("{} (detected through evasion technique)", reason),
                        },
                        "block",
                        Some(reason),
                        normalized,
                        start,
                    );
                }
            }

            tracing::warn!(
                command = raw_cmd,
                "Evasion technique detected but no blocked content found"
            );

            let decision = self.apply_offline_action(
                "Evasion technique detected, requires review",
            );
            return self.make_result(decision, "escalate_evasion", None, normalized, start);
        }

        // Evaluate each segment — block if ANY segment is blocked
        let mut worst_verdict = Verdict::Allow;

        for segment in &normalized.segments {
            match self.tier1.evaluate(segment) {
                Verdict::Block(reason) => {
                    return self.make_result(
                        Decision::Block { reason: reason.clone() },
                        "block",
                        Some(reason),
                        normalized,
                        start,
                    );
                }
                Verdict::Escalate => {
                    worst_verdict = Verdict::Escalate;
                }
                Verdict::Allow => {}
            }
        }

        match worst_verdict {
            Verdict::Allow => {
                self.make_result(Decision::Execute, "allow", None, normalized, start)
            }
            Verdict::Escalate => {
                // Tier 2 would go here when wired up.
                // For now, apply offline action.
                let decision = self.apply_offline_action(
                    "Command requires review (no Tier 2 classifier available)",
                );
                let verdict_str = match &decision {
                    Decision::Execute => "escalate_allowed",
                    Decision::Block { .. } => "escalate_blocked",
                    Decision::AskHuman { .. } => "escalate_human",
                };
                self.make_result(decision, verdict_str, None, normalized, start)
            }
            Verdict::Block(ref reason) => self.make_result(
                Decision::Block { reason: reason.clone() },
                "block",
                None,
                normalized,
                start,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use penelope_rules::builtins::{builtin_allow_rules, builtin_block_rules};

    fn pipeline() -> Pipeline {
        pipeline_with_offline(OfflineAction::Allow)
    }

    fn pipeline_with_offline(action: OfflineAction) -> Pipeline {
        let engine =
            Tier1Engine::new(builtin_block_rules(), builtin_allow_rules()).unwrap();
        Pipeline::new(engine, action)
    }

    #[test]
    fn allows_safe_command() {
        let p = pipeline();
        let r = p.evaluate("ls -la");
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[test]
    fn blocks_dangerous_command() {
        let p = pipeline();
        let r = p.evaluate("rm -rf /");
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[test]
    fn blocks_chained_dangerous_command() {
        let p = pipeline();
        let r = p.evaluate("echo hello && rm -rf /");
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[test]
    fn allows_safe_chain() {
        let p = pipeline();
        let r = p.evaluate("ls && pwd && echo done");
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[test]
    fn detects_evasion_with_blocked_payload() {
        let p = pipeline();
        // bash -c triggers nested shell detection + the inner rm -rf / is blocked
        let r = p.evaluate("bash -c 'rm -rf /'");
        // The inner command should be caught
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[test]
    fn reasoning_overrides_block() {
        let p = pipeline();
        let r = p.evaluate("rm -rf / --penelope-reasoning \"Cleaning up test environment\"");
        assert!(matches!(r.decision, Decision::Execute));
        assert!(r.reasoning_override.is_some());
        assert_eq!(r.reasoning_override.unwrap(), "Cleaning up test environment");
    }

    #[test]
    fn reasoning_strips_from_segments() {
        let p = pipeline();
        let r = p.evaluate("git push --force --penelope-reasoning 'Rebased feature branch'");
        assert!(matches!(r.decision, Decision::Execute));
        // The --penelope-reasoning should not appear in segments
        assert!(!r.normalized.segments.iter().any(|s| s.contains("penelope-reasoning")));
    }

    #[test]
    fn no_reasoning_still_blocks() {
        let p = pipeline();
        let r = p.evaluate("rm -rf /");
        assert!(matches!(r.decision, Decision::Block { .. }));
        assert!(r.reasoning_override.is_none());
    }

    #[test]
    fn offline_escalate_asks_human() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("terraform apply");
        assert!(matches!(r.decision, Decision::AskHuman { .. }));
        assert_eq!(r.tier1_verdict, "escalate_human");
    }

    #[test]
    fn offline_allow_passes_through() {
        let p = pipeline_with_offline(OfflineAction::Allow);
        let r = p.evaluate("terraform apply");
        assert!(matches!(r.decision, Decision::Execute));
        assert_eq!(r.tier1_verdict, "escalate_allowed");
    }

    #[test]
    fn offline_block_blocks() {
        let p = pipeline_with_offline(OfflineAction::Block);
        let r = p.evaluate("terraform apply");
        assert!(matches!(r.decision, Decision::Block { .. }));
        assert_eq!(r.tier1_verdict, "escalate_blocked");
    }

    #[test]
    fn offline_mode_doesnt_affect_tier1_allow() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("ls -la");
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[test]
    fn offline_mode_doesnt_affect_tier1_block() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("rm -rf /");
        assert!(matches!(r.decision, Decision::Block { .. }));
    }
}
