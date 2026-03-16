use serde::{Deserialize, Serialize};

/// Risk level classification from the Tier 2 NLI model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Block,
}

impl RiskLevel {
    /// Whether this risk level should result in blocking the command.
    pub fn should_block(&self) -> bool {
        matches!(self, RiskLevel::High | RiskLevel::Block)
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Block => write!(f, "block"),
        }
    }
}

/// Request sent to the NLI classification endpoint.
/// POST /classify
#[derive(Debug, Serialize)]
pub struct ClassifyRequest {
    pub command: String,
    pub segments: Vec<String>,
    pub has_evasion: bool,
    pub evasion_types: Vec<String>,
    pub agent_reasoning: Option<String>,
    pub tier1_verdict: String,
}

/// Response from the NLI classification endpoint.
#[derive(Debug, Deserialize)]
pub struct ClassifyResponse {
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reasoning: String,
}

/// Result of a Tier 2 evaluation (includes metadata for audit).
#[derive(Debug)]
pub struct Tier2Result {
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reasoning: String,
    pub latency_us: u64,
}

/// What to do when the NLI model is unavailable.
#[derive(Debug, Clone, PartialEq)]
pub enum OfflineAction {
    /// Push back to human for approval
    Escalate,
    /// Allow the command
    Allow,
    /// Block the command
    Block,
}

impl OfflineAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => OfflineAction::Allow,
            "block" => OfflineAction::Block,
            _ => OfflineAction::Escalate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_should_block() {
        assert!(!RiskLevel::Low.should_block());
        assert!(!RiskLevel::Medium.should_block());
        assert!(RiskLevel::High.should_block());
        assert!(RiskLevel::Block.should_block());
    }

    #[test]
    fn offline_action_parsing() {
        assert_eq!(OfflineAction::from_str("allow"), OfflineAction::Allow);
        assert_eq!(OfflineAction::from_str("block"), OfflineAction::Block);
        assert_eq!(OfflineAction::from_str("escalate"), OfflineAction::Escalate);
        assert_eq!(OfflineAction::from_str("anything"), OfflineAction::Escalate);
    }

    #[test]
    fn classify_request_serializes() {
        let req = ClassifyRequest {
            command: "docker run ubuntu".into(),
            segments: vec!["docker run ubuntu".into()],
            has_evasion: false,
            evasion_types: vec![],
            agent_reasoning: None,
            tier1_verdict: "escalate".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("docker run ubuntu"));
    }

    #[test]
    fn classify_response_deserializes() {
        let json = r#"{"risk_level":"low","confidence":0.92,"reasoning":"Safe container operation"}"#;
        let resp: ClassifyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.risk_level, RiskLevel::Low);
        assert!((resp.confidence - 0.92).abs() < f64::EPSILON);
    }
}
