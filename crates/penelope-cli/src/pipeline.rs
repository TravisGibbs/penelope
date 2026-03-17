use penelope_rules::{Tier1Engine, Verdict};
use std::time::Instant;

use crate::normalize::{self, NormalizedCommand};
use crate::tier2::{ClassifyRequest, EscalationTarget, Tier2Client};

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
    /// True if Tier 2 evaluated the agent's reasoning and still blocked.
    /// When this is set, reasoning cannot override the block.
    pub tier2_reasoning_rejected: bool,
    pub duration_us: u64,
}

/// The evaluation pipeline.
pub struct Pipeline {
    tier1: Tier1Engine,
    tier2: Option<Tier2Client>,
}

impl Pipeline {
    pub fn new(tier1: Tier1Engine, tier2: Option<Tier2Client>) -> Self {
        Self { tier1, tier2 }
    }

    /// Evaluate a raw command string through the pipeline.
    ///
    /// Flow:
    /// 1. Tier 1: allow / block / escalate
    /// 2. If escalated + no reasoning → ask agent for --penelope-reasoning
    /// 3. If escalated + reasoning → send to Tier 2 for model evaluation
    /// 4. Tier 1 blocks can be overridden by reasoning (without model)
    /// 5. Tier 2 blocks respect escalation_target (agent retry or human review)
    pub async fn evaluate(&self, raw_cmd: &str) -> EvalResult {
        let start = Instant::now();
        let normalized = normalize::normalize(raw_cmd);
        let has_reasoning = normalized.reasoning.is_some();

        let mut result = self.evaluate_inner(&normalized, raw_cmd, start).await;

        // Handle reasoning overrides for Tier 1 blocks
        if has_reasoning {
            if let Decision::Block { ref reason } = result.decision {
                if result.tier2_reasoning_rejected {
                    // Tier 2 evaluated reasoning and still blocked — hard block
                    tracing::warn!(
                        command = raw_cmd,
                        reasoning = normalized.reasoning.as_deref().unwrap_or(""),
                        original_block = reason.as_str(),
                        "Agent reasoning rejected by Tier 2, maintaining block"
                    );
                    result.reasoning_override = normalized.reasoning.clone();
                } else if result.tier2_risk_level.is_none() {
                    // Tier 1 block, no Tier 2 involved — reasoning overrides
                    tracing::info!(
                        command = raw_cmd,
                        reasoning = normalized.reasoning.as_deref().unwrap_or(""),
                        original_block = reason.as_str(),
                        "Tier 1 block overridden by agent reasoning"
                    );
                    result.reasoning_override = normalized.reasoning.clone();
                    result.decision = Decision::Execute;
                }
                // If Tier 2 was involved and didn't reject, decision already set correctly
            }
        }

        result
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
            tier2_reasoning_rejected: false,
            normalized: normalized.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Handle an escalated command.
    ///
    /// Flow:
    /// - No reasoning attached → always ask agent for reasoning
    /// - Reasoning attached → send to Tier 2 if available
    /// - Tier 2 unavailable but has reasoning → allow (agent already explained)
    async fn handle_escalation(
        &self,
        normalized: &NormalizedCommand,
        start: Instant,
    ) -> EvalResult {
        // Step 1: No reasoning? Always ask the agent first.
        if normalized.reasoning.is_none() {
            return self.make_result(
                Decision::AskHuman {
                    reason: "Command not recognized — provide reasoning to proceed".into(),
                },
                "escalate_ask_agent",
                None,
                normalized,
                start,
            );
        }

        // Step 2: Reasoning attached — send to Tier 2 if available.
        if let Some(ref tier2) = self.tier2 {
            let mut evasion_types = Vec::new();
            if normalized.has_eval { evasion_types.push("eval".into()); }
            if normalized.has_substitution { evasion_types.push("substitution".into()); }
            if normalized.has_base64 { evasion_types.push("base64".into()); }
            if normalized.has_nested_shell { evasion_types.push("nested_shell".into()); }

            let req = ClassifyRequest {
                command: normalized.stripped.clone(),
                segments: normalized.segments.clone(),
                has_evasion: normalized.has_evasion(),
                evasion_types,
                agent_reasoning: normalized.reasoning.clone(),
                tier1_verdict: "escalate".into(),
            };

            match tier2.classify(&req).await {
                Ok(tier2_result) => {
                    let reason_str = format!(
                        "Tier 2: {} (confidence: {:.0}%): {}",
                        tier2_result.risk_level,
                        tier2_result.confidence * 100.0,
                        tier2_result.reasoning
                    );

                    let decision = if tier2_result.risk_level.should_block() {
                        match tier2_result.escalation_target {
                            EscalationTarget::Human => Decision::AskHuman {
                                reason: reason_str,
                            },
                            EscalationTarget::Agent => Decision::Block {
                                reason: reason_str,
                            },
                            EscalationTarget::None => Decision::Block {
                                reason: reason_str,
                            },
                        }
                    } else {
                        Decision::Execute
                    };

                    let verdict_str = format!("tier2_{}", tier2_result.risk_level);

                    EvalResult {
                        decision,
                        tier1_verdict: verdict_str,
                        tier1_matched_rule: None,
                        reasoning_override: None,
                        tier2_risk_level: Some(tier2_result.risk_level.to_string()),
                        tier2_confidence: Some(tier2_result.confidence),
                        tier2_reasoning: Some(tier2_result.reasoning),
                        tier2_latency_us: Some(tier2_result.latency_us),
                        tier2_reasoning_rejected: tier2_result.reasoning_rejected,
                        normalized: normalized.clone(),
                        duration_us: start.elapsed().as_micros() as u64,
                    }
                }
                Err(e) => {
                    // Tier 2 failed — escalate to human, don't silently allow
                    tracing::warn!("Tier 2 unavailable ({}), escalating to human", e);
                    self.make_result(
                        Decision::AskHuman {
                            reason: format!("Classification unavailable ({}). Human review required.", e),
                        },
                        "tier2_fallback_human",
                        None,
                        normalized,
                        start,
                    )
                }
            }
        } else {
            // No Tier 2 configured — agent provided reasoning, allow through.
            // This is the "no classifier" path: user hasn't set up Tier 2 yet,
            // so we trust the agent's description/reasoning. Once they enable
            // Tier 2, the model validates the reasoning instead.
            tracing::info!("No Tier 2 configured, allowing with agent reasoning");
            self.make_result(
                Decision::Execute,
                "escalate_reasoning_allowed",
                None,
                normalized,
                start,
            )
        }
    }

    async fn evaluate_inner(
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

            // Evasion detected but no blocked content found in any segment.
            // Without Tier 2 to semantically analyze, allow it through —
            // common patterns like git commit -m "$(cat <<EOF ...)" trigger
            // evasion detection but are harmless.
            tracing::info!(
                command = raw_cmd,
                "Evasion technique detected but no blocked content found, allowing"
            );

            return self.make_result(Decision::Execute, "escalate_evasion_allowed", None, normalized, start);
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
                self.handle_escalation(normalized, start).await
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
        let engine =
            Tier1Engine::new(builtin_block_rules(), builtin_allow_rules()).unwrap();
        Pipeline::new(engine, None)
    }

    #[tokio::test]
    async fn allows_safe_command() {
        let p = pipeline();
        let r = p.evaluate("ls -la").await;
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[tokio::test]
    async fn blocks_dangerous_command() {
        let p = pipeline();
        let r = p.evaluate("rm -rf /").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn blocks_chained_dangerous_command() {
        let p = pipeline();
        let r = p.evaluate("echo hello && rm -rf /").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn allows_safe_chain() {
        let p = pipeline();
        let r = p.evaluate("ls && pwd && echo done").await;
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[tokio::test]
    async fn detects_evasion_with_blocked_payload() {
        let p = pipeline();
        let r = p.evaluate("bash -c 'rm -rf /'").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn reasoning_overrides_block() {
        let p = pipeline();
        let r = p.evaluate("rm -rf / --penelope-reasoning \"Cleaning up test environment\"").await;
        assert!(matches!(r.decision, Decision::Execute));
        assert!(r.reasoning_override.is_some());
        assert_eq!(r.reasoning_override.unwrap(), "Cleaning up test environment");
    }

    #[tokio::test]
    async fn reasoning_strips_from_segments() {
        let p = pipeline();
        let r = p.evaluate("git push --force --penelope-reasoning 'Rebased feature branch'").await;
        assert!(matches!(r.decision, Decision::Execute));
        assert!(!r.normalized.segments.iter().any(|s| s.contains("penelope-reasoning")));
    }

    #[tokio::test]
    async fn no_reasoning_still_blocks() {
        let p = pipeline();
        let r = p.evaluate("rm -rf /").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
        assert!(r.reasoning_override.is_none());
    }

    #[tokio::test]
    async fn unknown_command_asks_agent_for_reasoning() {
        let p = pipeline();
        let r = p.evaluate("some-unknown-tool --dangerous-flag").await;
        assert!(matches!(r.decision, Decision::AskHuman { .. }));
        assert_eq!(r.tier1_verdict, "escalate_ask_agent");
    }

    #[tokio::test]
    async fn unknown_command_with_reasoning_allowed_without_tier2() {
        let p = pipeline();
        let r = p.evaluate("some-unknown-tool --flag --penelope-reasoning \"safe internal tool\"").await;
        // Without Tier 2 configured, trust the reasoning
        assert!(matches!(r.decision, Decision::Execute));
        assert_eq!(r.tier1_verdict, "escalate_reasoning_allowed");
    }

    #[tokio::test]
    async fn tier1_allow_not_affected() {
        let p = pipeline();
        let r = p.evaluate("ls -la").await;
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[tokio::test]
    async fn tier1_block_not_affected() {
        let p = pipeline();
        let r = p.evaluate("rm -rf /").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
    }
}
