use penelope_rules::{Tier1Engine, Verdict};
use std::time::Instant;

use crate::normalize::{self, NormalizedCommand};
use crate::tier2::{ClassifyRequest, OfflineAction, Tier2Client};

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
    /// What to do when a command is escalated and tier2 is unavailable.
    offline_action: OfflineAction,
}

impl Pipeline {
    pub fn new(
        tier1: Tier1Engine,
        offline_action: OfflineAction,
        tier2: Option<Tier2Client>,
    ) -> Self {
        Self {
            tier1,
            tier2,
            offline_action,
        }
    }

    /// Evaluate a raw command string through the pipeline.
    pub async fn evaluate(&self, raw_cmd: &str) -> EvalResult {
        let start = Instant::now();
        let normalized = normalize::normalize(raw_cmd);
        let has_reasoning = normalized.reasoning.is_some();

        let mut result = self.evaluate_inner(&normalized, raw_cmd, start).await;

        // If agent provided reasoning, attempt to override blocks.
        // Tier 1 blocks are overridable by reasoning (agent explains why it's safe).
        // Tier 2 blocks (when wired up) will re-evaluate with reasoning as context
        // and can reject the override — indicated by tier2_reasoning_rejected.
        if has_reasoning {
            if let Decision::Block { ref reason } = result.decision {
                if result.tier2_reasoning_rejected {
                    // Tier 2 saw the reasoning and still said block — hard block.
                    tracing::warn!(
                        command = raw_cmd,
                        reasoning = normalized.reasoning.as_deref().unwrap_or(""),
                        original_block = reason.as_str(),
                        "Agent reasoning rejected by Tier 2, maintaining block"
                    );
                    // Keep the block, but record that reasoning was provided
                    result.reasoning_override = normalized.reasoning.clone();
                } else {
                    // No Tier 2 rejection — reasoning overrides the block
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
            tier2_reasoning_rejected: false,
            normalized: normalized.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Handle an escalated command — call Tier 2 if available, otherwise apply offline action.
    async fn handle_escalation(
        &self,
        normalized: &NormalizedCommand,
        start: Instant,
    ) -> EvalResult {
        if let Some(ref tier2) = self.tier2 {
            // Build classification request
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
                    let decision = if tier2_result.risk_level.should_block() {
                        Decision::Block {
                            reason: format!(
                                "Tier 2 classified as {} (confidence: {:.0}%): {}",
                                tier2_result.risk_level,
                                tier2_result.confidence * 100.0,
                                tier2_result.reasoning
                            ),
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
                    tracing::warn!("Tier 2 classification failed: {}, applying offline action", e);
                    let decision = self.apply_offline_action(
                        &format!("Tier 2 unavailable ({})", e),
                    );
                    let verdict_str = match &decision {
                        Decision::Execute => "tier2_fallback_allowed",
                        Decision::Block { .. } => "tier2_fallback_blocked",
                        Decision::AskHuman { .. } => "tier2_fallback_human",
                    };
                    self.make_result(decision, verdict_str, None, normalized, start)
                }
            }
        } else {
            // No Tier 2 configured — apply offline action
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
        pipeline_with_offline(OfflineAction::Allow)
    }

    fn pipeline_with_offline(action: OfflineAction) -> Pipeline {
        let engine =
            Tier1Engine::new(builtin_block_rules(), builtin_allow_rules()).unwrap();
        Pipeline::new(engine, action, None)
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
    async fn offline_escalate_asks_human() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("some-unknown-tool --dangerous-flag").await;
        assert!(matches!(r.decision, Decision::AskHuman { .. }));
        assert_eq!(r.tier1_verdict, "escalate_human");
    }

    #[tokio::test]
    async fn offline_allow_passes_through() {
        let p = pipeline_with_offline(OfflineAction::Allow);
        let r = p.evaluate("some-unknown-tool --dangerous-flag").await;
        assert!(matches!(r.decision, Decision::Execute));
        assert_eq!(r.tier1_verdict, "escalate_allowed");
    }

    #[tokio::test]
    async fn offline_block_blocks() {
        let p = pipeline_with_offline(OfflineAction::Block);
        let r = p.evaluate("some-unknown-tool --dangerous-flag").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
        assert_eq!(r.tier1_verdict, "escalate_blocked");
    }

    #[tokio::test]
    async fn offline_mode_doesnt_affect_tier1_allow() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("ls -la").await;
        assert!(matches!(r.decision, Decision::Execute));
    }

    #[tokio::test]
    async fn offline_mode_doesnt_affect_tier1_block() {
        let p = pipeline_with_offline(OfflineAction::Escalate);
        let r = p.evaluate("rm -rf /").await;
        assert!(matches!(r.decision, Decision::Block { .. }));
    }
}
