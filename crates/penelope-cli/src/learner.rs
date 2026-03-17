//! Per-user SGD logistic regression model for adaptive risk scoring.
//!
//! Learns from user feedback on Tier 2 decisions:
//! - "shouldn't have asked" (false positive) → learn to allow similar commands
//! - "good catch" (true positive) → reinforce blocking
//!
//! The model takes TypeSafe features as input and outputs a calibrated
//! probability (0.0 = safe, 1.0 = dangerous). Runs in ~100ns on CPU.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The feature vector from TypeSafe evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFeatures {
    pub is_destructive: f64,
    pub is_exfiltration: f64,
    pub is_privilege_escalation: f64,
    pub is_normal_dev: f64,
    pub overall_risk: f64, // normalized to 0-1 by dividing by 5
}

impl RiskFeatures {
    /// Create from the raw TypeSafe features map.
    pub fn from_map(features: &std::collections::HashMap<String, f64>) -> Self {
        Self {
            is_destructive: *features.get("is_destructive").unwrap_or(&0.0),
            is_exfiltration: *features.get("is_exfiltration").unwrap_or(&0.0),
            is_privilege_escalation: *features.get("is_privilege_escalation").unwrap_or(&0.0),
            is_normal_dev: *features.get("is_normal_dev").unwrap_or(&0.0),
            overall_risk: features.get("overall_risk").unwrap_or(&0.0) / 5.0,
        }
    }

    /// Convert to a fixed-size array for dot product.
    fn as_array(&self) -> [f64; 5] {
        [
            self.is_destructive,
            self.is_exfiltration,
            self.is_privilege_escalation,
            self.is_normal_dev,
            self.overall_risk,
        ]
    }
}

/// Per-user learned weights for risk scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModel {
    /// Feature weights (same order as RiskFeatures)
    pub weights: [f64; 5],
    /// Bias term
    pub bias: f64,
    /// Learning rate for SGD updates
    pub learning_rate: f64,
    /// Number of training examples seen
    pub n_updates: u64,
}

impl Default for UserModel {
    fn default() -> Self {
        Self {
            // Start with sensible priors:
            // destructive, exfil, privesc → positive (risky)
            // normal_dev → negative (safe)
            // overall_risk → positive (risky)
            weights: [2.0, 2.0, 1.5, -2.0, 2.0],
            bias: -0.5,
            learning_rate: 0.1,
            n_updates: 0,
        }
    }
}

impl UserModel {
    /// Predict risk probability from features. Returns 0.0-1.0.
    /// ~100ns on CPU — just a dot product + sigmoid.
    pub fn predict(&self, features: &RiskFeatures) -> f64 {
        let x = features.as_array();
        let z: f64 = self
            .weights
            .iter()
            .zip(x.iter())
            .map(|(w, x)| w * x)
            .sum::<f64>()
            + self.bias;
        sigmoid(z)
    }

    /// Update weights from feedback.
    /// label = true means "this was correctly flagged as risky" (true positive)
    /// label = false means "this was a false alarm, shouldn't have asked" (false positive)
    pub fn update(&mut self, features: &RiskFeatures, label: bool) {
        let x = features.as_array();
        let y = if label { 1.0 } else { 0.0 };
        let pred = self.predict(features);
        let error = pred - y;

        // SGD update: w -= lr * error * x
        // Decay learning rate over time for stability
        let lr = self.learning_rate / (1.0 + 0.01 * self.n_updates as f64);

        for i in 0..5 {
            self.weights[i] -= lr * error * x[i];
        }
        self.bias -= lr * error;

        self.n_updates += 1;
    }

    /// Load a user model from disk. Returns default if not found.
    pub fn load(path: &Path) -> Self {
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(model) = serde_json::from_str(&contents) {
                    return model;
                }
            }
        }
        Self::default()
    }

    /// Save the model to disk.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Get the model file path for a user/session.
    pub fn model_path(user_id: &str) -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".penelope")
            .join("models")
            .join(format!("{}.json", user_id))
    }
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dangerous_features() -> RiskFeatures {
        RiskFeatures {
            is_destructive: 0.95,
            is_exfiltration: 0.1,
            is_privilege_escalation: 0.2,
            is_normal_dev: 0.05,
            overall_risk: 0.9,
        }
    }

    fn safe_features() -> RiskFeatures {
        RiskFeatures {
            is_destructive: 0.05,
            is_exfiltration: 0.02,
            is_privilege_escalation: 0.01,
            is_normal_dev: 0.85,
            overall_risk: 0.2,
        }
    }

    fn ambiguous_features() -> RiskFeatures {
        RiskFeatures {
            is_destructive: 0.3,
            is_exfiltration: 0.1,
            is_privilege_escalation: 0.05,
            is_normal_dev: 0.4,
            overall_risk: 0.5,
        }
    }

    #[test]
    fn default_model_scores_dangerous_high() {
        let model = UserModel::default();
        let score = model.predict(&dangerous_features());
        assert!(score > 0.8, "dangerous should score high, got {}", score);
    }

    #[test]
    fn default_model_scores_safe_low() {
        let model = UserModel::default();
        let score = model.predict(&safe_features());
        assert!(score < 0.3, "safe should score low, got {}", score);
    }

    #[test]
    fn learning_reduces_false_positives() {
        let mut model = UserModel::default();
        let features = ambiguous_features();

        let before = model.predict(&features);

        // User says "shouldn't have asked" 5 times for similar commands
        for _ in 0..5 {
            model.update(&features, false);
        }

        let after = model.predict(&features);
        assert!(
            after < before,
            "score should decrease after false positive feedback: {} -> {}",
            before, after
        );
    }

    #[test]
    fn learning_increases_true_positives() {
        let mut model = UserModel::default();
        let features = ambiguous_features();

        let before = model.predict(&features);

        // User says "good catch" 5 times for similar commands
        for _ in 0..5 {
            model.update(&features, true);
        }

        let after = model.predict(&features);
        assert!(
            after > before,
            "score should increase after true positive feedback: {} -> {}",
            before, after
        );
    }

    #[test]
    fn prediction_is_bounded() {
        let model = UserModel::default();
        let score1 = model.predict(&dangerous_features());
        let score2 = model.predict(&safe_features());
        assert!((0.0..=1.0).contains(&score1));
        assert!((0.0..=1.0).contains(&score2));
    }

    #[test]
    fn model_serialization_roundtrip() {
        let mut model = UserModel::default();
        model.update(&dangerous_features(), true);
        model.update(&safe_features(), false);

        let json = serde_json::to_string(&model).unwrap();
        let loaded: UserModel = serde_json::from_str(&json).unwrap();

        assert_eq!(model.weights, loaded.weights);
        assert_eq!(model.bias, loaded.bias);
        assert_eq!(model.n_updates, loaded.n_updates);
    }
}
