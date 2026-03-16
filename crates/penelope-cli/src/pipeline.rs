use penelope_rules::{Tier1Engine, Verdict};
use std::time::Instant;

use crate::normalize::{self, NormalizedCommand};

/// The final decision after evaluating a command.
#[derive(Debug)]
pub enum Decision {
    /// Command is safe to execute.
    Execute,
    /// Command is blocked.
    Block { reason: String },
}

/// Result of pipeline evaluation with metadata for audit logging.
pub struct EvalResult {
    pub decision: Decision,
    pub normalized: NormalizedCommand,
    pub tier1_verdict: String,
    pub tier1_matched_rule: Option<String>,
    /// Agent-provided reasoning that overrode a block (if any)
    pub reasoning_override: Option<String>,
    pub duration_us: u64,
}

/// The evaluation pipeline. Currently Tier 1 only; Tier 2 will be added later.
pub struct Pipeline {
    tier1: Tier1Engine,
    /// When true, unknown commands (Escalate) are allowed.
    /// When Tier 2 is wired up, this will change.
    allow_on_escalate: bool,
}

impl Pipeline {
    pub fn new(tier1: Tier1Engine) -> Self {
        Self {
            tier1,
            // MVP: allow unknown commands since Tier 2 isn't available
            allow_on_escalate: true,
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

    fn evaluate_inner(
        &self,
        normalized: &NormalizedCommand,
        raw_cmd: &str,
        start: Instant,
    ) -> EvalResult {
        // If evasion was detected, be conservative
        if normalized.has_evasion() {
            // Evaluate all segments (including decoded payloads) against Tier 1
            // If any segment is blocked, block the whole command
            for segment in &normalized.segments {
                if let Verdict::Block(reason) = self.tier1.evaluate(segment) {
                    return EvalResult {
                        decision: Decision::Block {
                            reason: format!("{} (detected through evasion technique)", reason),
                        },
                        tier1_verdict: "block".into(),
                        tier1_matched_rule: Some(reason),
                        reasoning_override: None,
                        normalized: normalized.clone(),
                        duration_us: start.elapsed().as_micros() as u64,
                    };
                }
            }

            // Evasion detected but no blocked content found.
            // For MVP, we still allow but log the evasion.
            tracing::warn!(
                command = raw_cmd,
                "Evasion technique detected but no blocked content found"
            );

            return EvalResult {
                decision: if self.allow_on_escalate {
                    Decision::Execute
                } else {
                    Decision::Block {
                        reason: "Evasion technique detected, escalation required".into(),
                    }
                },
                tier1_verdict: "escalate_evasion".into(),
                tier1_matched_rule: None,
                reasoning_override: None,
                normalized: normalized.clone(),
                duration_us: start.elapsed().as_micros() as u64,
            };
        }

        // Evaluate each segment — block if ANY segment is blocked
        let mut worst_verdict = Verdict::Allow;

        for segment in &normalized.segments {
            match self.tier1.evaluate(segment) {
                Verdict::Block(reason) => {
                    return EvalResult {
                        decision: Decision::Block {
                            reason: reason.clone(),
                        },
                        tier1_verdict: "block".into(),
                        tier1_matched_rule: Some(reason),
                        reasoning_override: None,
                        normalized: normalized.clone(),
                        duration_us: start.elapsed().as_micros() as u64,
                    };
                }
                Verdict::Escalate => {
                    worst_verdict = Verdict::Escalate;
                }
                Verdict::Allow => {}
            }
        }

        let (decision, verdict_str) = match worst_verdict {
            Verdict::Allow => (Decision::Execute, "allow"),
            Verdict::Escalate => {
                if self.allow_on_escalate {
                    (Decision::Execute, "escalate_allowed")
                } else {
                    (
                        Decision::Block {
                            reason: "Command requires Tier 2 evaluation (not available)".into(),
                        },
                        "escalate_blocked",
                    )
                }
            }
            Verdict::Block(ref reason) => (
                Decision::Block {
                    reason: reason.clone(),
                },
                "block",
            ),
        };

        EvalResult {
            decision,
            tier1_verdict: verdict_str.into(),
            tier1_matched_rule: None,
            reasoning_override: None,
            normalized: normalized.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use penelope_rules::builtins::{builtin_allow_rules, builtin_block_rules};

    fn pipeline() -> Pipeline {
        let engine =
            Tier1Engine::new(builtin_block_rules(), builtin_allow_rules()).unwrap();
        Pipeline::new(engine)
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
}
