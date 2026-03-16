use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::config::Tier2Config;

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
#[derive(Debug, Serialize)]
pub struct ClassifyRequest {
    pub command: String,
    pub segments: Vec<String>,
    pub has_evasion: bool,
    pub evasion_types: Vec<String>,
    pub agent_reasoning: Option<String>,
    pub tier1_verdict: String,
}

/// Who should handle escalation feedback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTarget {
    /// Ask the agent to explain via --penelope-reasoning
    Agent,
    /// Hard escalate to the human user
    Human,
    /// No escalation needed (allow or hard block)
    None,
}

impl std::fmt::Display for EscalationTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscalationTarget::Agent => write!(f, "agent"),
            EscalationTarget::Human => write!(f, "human"),
            EscalationTarget::None => write!(f, "none"),
        }
    }
}

/// Response from the NLI classification endpoint.
#[derive(Debug, Deserialize)]
pub struct ClassifyResponse {
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reasoning: String,
    /// Who should handle this if escalated: "agent", "human", or "none"
    #[serde(default = "default_escalation_target")]
    pub escalation_target: EscalationTarget,
}

fn default_escalation_target() -> EscalationTarget {
    EscalationTarget::Agent
}

/// Result of a Tier 2 evaluation.
#[derive(Debug)]
pub struct Tier2Result {
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reasoning: String,
    pub latency_us: u64,
    /// Whether the model rejected agent-provided reasoning.
    pub reasoning_rejected: bool,
    /// Who should handle escalation feedback.
    pub escalation_target: EscalationTarget,
}

/// What to do when the NLI model is unavailable.
#[derive(Debug, Clone, PartialEq)]
pub enum OfflineAction {
    Escalate,
    Allow,
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

/// HTTP client for the Tier 2 NLI classification endpoint.
pub struct Tier2Client {
    client: reqwest::Client,
    endpoint: String,
    offline_action: OfflineAction,
}

impl Tier2Client {
    /// Create a new client from config. Returns None if tier2 is disabled.
    pub fn new(config: &Tier2Config) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let endpoint = config.endpoint.as_ref()?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .ok()?;

        Some(Self {
            client,
            endpoint: endpoint.clone(),
            offline_action: OfflineAction::from_str(&config.offline_action),
        })
    }

    pub fn offline_action(&self) -> &OfflineAction {
        &self.offline_action
    }

    /// Classify a command via the NLI endpoint.
    pub async fn classify(&self, req: &ClassifyRequest) -> Result<Tier2Result, Tier2Error> {
        let start = Instant::now();

        let response = self
            .client
            .post(&self.endpoint)
            .json(req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    Tier2Error::Timeout
                } else if e.is_connect() {
                    Tier2Error::Unavailable(e.to_string())
                } else {
                    Tier2Error::Request(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            return Err(Tier2Error::BadStatus(response.status().as_u16()));
        }

        let body: ClassifyResponse = response
            .json()
            .await
            .map_err(|e| Tier2Error::Parse(e.to_string()))?;

        let latency_us = start.elapsed().as_micros() as u64;

        // If the agent provided reasoning but the model still says block,
        // that means the reasoning was rejected.
        let reasoning_rejected = req.agent_reasoning.is_some() && body.risk_level.should_block();

        Ok(Tier2Result {
            risk_level: body.risk_level,
            confidence: body.confidence,
            reasoning: body.reasoning,
            latency_us,
            reasoning_rejected,
            escalation_target: body.escalation_target,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Tier2Error {
    #[error("NLI endpoint timed out")]
    Timeout,
    #[error("NLI endpoint unavailable: {0}")]
    Unavailable(String),
    #[error("NLI request failed: {0}")]
    Request(String),
    #[error("NLI returned status {0}")]
    BadStatus(u16),
    #[error("Failed to parse NLI response: {0}")]
    Parse(String),
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

    #[test]
    fn client_returns_none_when_disabled() {
        let config = Tier2Config {
            endpoint: Some("http://localhost:8000/classify".into()),
            timeout_ms: 100,
            enabled: false,
            offline_action: "escalate".into(),
        };
        assert!(Tier2Client::new(&config).is_none());
    }

    #[test]
    fn client_returns_none_when_no_endpoint() {
        let config = Tier2Config {
            endpoint: None,
            timeout_ms: 100,
            enabled: true,
            offline_action: "escalate".into(),
        };
        assert!(Tier2Client::new(&config).is_none());
    }

    #[test]
    fn client_creates_when_configured() {
        let config = Tier2Config {
            endpoint: Some("http://localhost:8000/classify".into()),
            timeout_ms: 100,
            enabled: true,
            offline_action: "escalate".into(),
        };
        assert!(Tier2Client::new(&config).is_some());
    }
}
