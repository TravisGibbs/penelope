use serde::Deserialize;

/// The outcome of evaluating a command against the Tier 1 rule engine.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Command is known-safe, skip Tier 2.
    Allow,
    /// Command is catastrophic, block immediately.
    Block(String),
    /// Command is unknown, escalate to Tier 2.
    Escalate,
}

/// A single rule that maps a regex pattern to a verdict.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub reason: Option<String>,
}
