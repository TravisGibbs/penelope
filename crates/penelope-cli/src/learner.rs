//! Per-repo SGD logistic regression model for adaptive risk scoring.
//!
//! Learns from user feedback on escalation decisions. Each repo gets its own
//! model so risk tolerance adapts to the context (test repo vs production).
//!
//! Features are extracted from the command, TypeSafe response, and context.
//! The model runs in ~100ns on CPU — just a dot product + sigmoid.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Number of features in the model.
pub const NUM_FEATURES: usize = 22;

/// Feature names for debugging/logging.
pub const FEATURE_NAMES: [&str; NUM_FEATURES] = [
    // TypeSafe features (5)
    "ts_destructive",
    "ts_exfiltration",
    "ts_privilege_escalation",
    "ts_normal_dev",
    "ts_overall_risk",
    // Command structure features (10)
    "cmd_length_norm",
    "cmd_num_segments",
    "cmd_has_redirect",
    "cmd_has_sudo",
    "cmd_targets_system_path",
    "cmd_targets_home_dir",
    "cmd_num_flags",
    "cmd_has_wildcard",
    "cmd_has_network",
    "cmd_has_pipe",
    // Context features (5)
    "ctx_has_description",
    "ctx_has_reasoning",
    "ctx_has_evasion",
    "ctx_session_command_idx",
    "ctx_hour_of_day",
    // Binary feature (2)
    "bin_is_common",
    "bin_is_package_manager",
];

/// Full feature vector for the learner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFeatures {
    pub values: [f64; NUM_FEATURES],
}

impl RiskFeatures {
    /// Extract features from command + TypeSafe response + context.
    pub fn extract(
        command: &str,
        segments: &[String],
        typesafe_features: Option<&std::collections::HashMap<String, f64>>,
        has_description: bool,
        has_reasoning: bool,
        has_evasion: bool,
    ) -> Self {
        let mut values = [0.0; NUM_FEATURES];

        // TypeSafe features (0-4)
        if let Some(tf) = typesafe_features {
            values[0] = *tf.get("is_destructive").unwrap_or(&0.0);
            values[1] = *tf.get("is_exfiltration").unwrap_or(&0.0);
            values[2] = *tf.get("is_privilege_escalation").unwrap_or(&0.0);
            values[3] = *tf.get("is_normal_dev").unwrap_or(&0.0);
            values[4] = tf.get("overall_risk").unwrap_or(&0.0) / 5.0;
        }

        // Command structure features (5-14)
        values[5] = (command.len() as f64 / 200.0).min(1.0); // normalized length
        values[6] = (segments.len() as f64 / 5.0).min(1.0); // normalized segment count
        values[7] = if command.contains('>') { 1.0 } else { 0.0 }; // redirect
        values[8] = if command.starts_with("sudo ") || command.contains(" sudo ") { 1.0 } else { 0.0 };
        values[9] = if has_system_path(command) { 1.0 } else { 0.0 };
        values[10] = if command.contains("~/") || command.contains("$HOME") { 1.0 } else { 0.0 };
        values[11] = (count_flags(command) as f64 / 10.0).min(1.0);
        values[12] = if command.contains('*') || command.contains('?') { 1.0 } else { 0.0 };
        values[13] = if has_network_indicators(command) { 1.0 } else { 0.0 };
        values[14] = if command.contains('|') { 1.0 } else { 0.0 };

        // Context features (15-19)
        values[15] = if has_description { 1.0 } else { 0.0 };
        values[16] = if has_reasoning { 1.0 } else { 0.0 };
        values[17] = if has_evasion { 1.0 } else { 0.0 };
        // session_command_idx and hour_of_day set externally if available
        values[18] = 0.0; // session_command_idx (caller can set)
        values[19] = {
            let hour = chrono::Local::now().hour() as f64;
            hour / 24.0
        };

        // Binary features (20-21)
        let binary = extract_binary(command);
        values[20] = if is_common_binary(&binary) { 1.0 } else { 0.0 };
        values[21] = if is_package_manager(&binary) { 1.0 } else { 0.0 };

        Self { values }
    }
}

/// Per-repo learned weights for risk scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModel {
    pub weights: [f64; NUM_FEATURES],
    pub bias: f64,
    pub learning_rate: f64,
    pub n_updates: u64,
    /// Repo identifier this model is for
    pub repo_id: String,
}

impl UserModel {
    pub fn new(repo_id: &str) -> Self {
        Self {
            weights: default_weights(),
            bias: -0.5,
            learning_rate: 0.1,
            n_updates: 0,
            repo_id: repo_id.to_string(),
        }
    }

    /// Predict risk probability. Returns 0.0 (safe) to 1.0 (dangerous).
    pub fn predict(&self, features: &RiskFeatures) -> f64 {
        let z: f64 = self
            .weights
            .iter()
            .zip(features.values.iter())
            .map(|(w, x)| w * x)
            .sum::<f64>()
            + self.bias;
        sigmoid(z)
    }

    /// Update weights from feedback.
    /// label = true: correct escalation (reinforce)
    /// label = false: false positive, shouldn't have asked (reduce)
    pub fn update(&mut self, features: &RiskFeatures, label: bool) {
        let y = if label { 1.0 } else { 0.0 };
        let pred = self.predict(features);
        let error = pred - y;

        let lr = self.learning_rate / (1.0 + 0.01 * self.n_updates as f64);

        for i in 0..NUM_FEATURES {
            self.weights[i] -= lr * error * features.values[i];
        }
        self.bias -= lr * error;
        self.n_updates += 1;
    }

    /// Load model for a repo. Returns default if not found.
    pub fn load(path: &Path) -> Option<Self> {
        let contents = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    /// Save model to disk.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Get model path for a repo.
    pub fn model_path(repo_id: &str) -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".penelope")
            .join("models")
            .join(format!("{}.json", sanitize_filename(repo_id)))
    }
}

/// Detect the current repo from git or cwd.
pub fn detect_repo_id() -> String {
    // Try git remote origin
    if let Ok(output) = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
    {
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !url.is_empty() {
            // Normalize: git@github.com:user/repo.git → user/repo
            return normalize_repo_url(&url);
        }
    }

    // Fall back to cwd basename
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

fn normalize_repo_url(url: &str) -> String {
    url.trim_end_matches(".git")
        .replace("git@github.com:", "")
        .replace("https://github.com/", "")
        .replace("http://github.com/", "")
        .to_string()
}

fn sanitize_filename(s: &str) -> String {
    s.replace('/', "_").replace('\\', "_").replace(':', "_")
}

fn default_weights() -> [f64; NUM_FEATURES] {
    let mut w = [0.0; NUM_FEATURES];
    // TypeSafe priors
    w[0] = 2.0;   // ts_destructive → risky
    w[1] = 2.0;   // ts_exfiltration → risky
    w[2] = 1.5;   // ts_privilege_escalation → risky
    w[3] = -2.0;  // ts_normal_dev → safe
    w[4] = 2.0;   // ts_overall_risk → risky
    // Command structure priors
    w[7] = 0.5;   // cmd_has_redirect → slightly risky
    w[8] = 1.0;   // cmd_has_sudo → risky
    w[9] = 1.0;   // cmd_targets_system_path → risky
    w[12] = 0.3;  // cmd_has_wildcard → slightly risky
    w[13] = 0.5;  // cmd_has_network → slightly risky
    // Context priors
    w[15] = -0.5; // ctx_has_description → safer (agent explained)
    w[17] = 0.5;  // ctx_has_evasion → riskier
    // Binary priors
    w[20] = -0.5; // bin_is_common → safer
    w[21] = -0.3; // bin_is_package_manager → safer
    w
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

fn has_system_path(cmd: &str) -> bool {
    cmd.contains("/etc/")
        || cmd.contains("/usr/")
        || cmd.contains("/var/")
        || cmd.contains("/sys/")
        || cmd.contains("/proc/")
        || cmd.contains("/boot/")
}

fn has_network_indicators(cmd: &str) -> bool {
    cmd.contains("http://")
        || cmd.contains("https://")
        || cmd.contains("://")
        || cmd.contains("localhost")
        || cmd.contains("0.0.0.0")
        || cmd.contains("127.0.0.1")
}

fn count_flags(cmd: &str) -> usize {
    cmd.split_whitespace()
        .filter(|w| w.starts_with('-') && w.len() > 1)
        .count()
}

fn extract_binary(cmd: &str) -> String {
    cmd.split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn is_common_binary(bin: &str) -> bool {
    matches!(
        bin,
        "ls" | "cd" | "cat" | "echo" | "grep" | "find" | "sed" | "awk"
            | "git" | "make" | "cargo" | "npm" | "yarn" | "python"
            | "python3" | "node" | "docker" | "kubectl" | "curl"
            | "wget" | "cp" | "mv" | "mkdir" | "rm" | "touch"
            | "chmod" | "head" | "tail" | "wc" | "sort" | "uniq"
            | "jq" | "gh" | "go" | "rustc" | "bun"
    )
}

fn is_package_manager(bin: &str) -> bool {
    matches!(
        bin,
        "npm" | "yarn" | "pnpm" | "pip" | "pip3" | "cargo"
            | "brew" | "apt" | "apt-get" | "apk" | "dnf"
            | "yum" | "pacman" | "gem" | "go"
    )
}

use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_typesafe_features(destructive: f64, normal_dev: f64, risk: f64) -> HashMap<String, f64> {
        let mut m = HashMap::new();
        m.insert("is_destructive".into(), destructive);
        m.insert("is_exfiltration".into(), 0.05);
        m.insert("is_privilege_escalation".into(), 0.05);
        m.insert("is_normal_dev".into(), normal_dev);
        m.insert("overall_risk".into(), risk);
        m
    }

    #[test]
    fn dangerous_command_scores_high() {
        let tf = make_typesafe_features(0.95, 0.02, 4.8);
        let features = RiskFeatures::extract("rm -rf /", &["rm -rf /".into()], Some(&tf), false, false, false);
        let model = UserModel::new("test/repo");
        let score = model.predict(&features);
        assert!(score > 0.8, "dangerous should score high, got {}", score);
    }

    #[test]
    fn safe_command_scores_low() {
        let tf = make_typesafe_features(0.02, 0.9, 1.1);
        let features = RiskFeatures::extract("ls -la", &["ls -la".into()], Some(&tf), true, false, false);
        let model = UserModel::new("test/repo");
        let score = model.predict(&features);
        assert!(score < 0.3, "safe should score low, got {}", score);
    }

    #[test]
    fn learning_reduces_false_positives() {
        let tf = make_typesafe_features(0.3, 0.4, 2.5);
        let features = RiskFeatures::extract("docker build .", &["docker build .".into()], Some(&tf), true, false, false);
        let mut model = UserModel::new("test/repo");

        let before = model.predict(&features);
        for _ in 0..5 {
            model.update(&features, false);
        }
        let after = model.predict(&features);

        assert!(after < before, "should decrease: {} -> {}", before, after);
    }

    #[test]
    fn learning_increases_true_positives() {
        let tf = make_typesafe_features(0.3, 0.4, 2.5);
        let features = RiskFeatures::extract("docker build .", &["docker build .".into()], Some(&tf), true, false, false);
        let mut model = UserModel::new("test/repo");

        let before = model.predict(&features);
        for _ in 0..5 {
            model.update(&features, true);
        }
        let after = model.predict(&features);

        assert!(after > before, "should increase: {} -> {}", before, after);
    }

    #[test]
    fn per_repo_models_are_independent() {
        let tf = make_typesafe_features(0.5, 0.3, 3.0);
        let features = RiskFeatures::extract("terraform apply", &["terraform apply".into()], Some(&tf), true, false, false);

        let mut prod_model = UserModel::new("company/production");
        let mut test_model = UserModel::new("company/test-sandbox");

        // In test repo: user says "don't ask me about terraform"
        for _ in 0..10 {
            test_model.update(&features, false);
        }

        let prod_score = prod_model.predict(&features);
        let test_score = test_model.predict(&features);

        assert!(test_score < prod_score, "test repo should be more lenient: test={} prod={}", test_score, prod_score);
    }

    #[test]
    fn feature_extraction_detects_system_paths() {
        let features = RiskFeatures::extract("cat /etc/passwd", &["cat /etc/passwd".into()], None, false, false, false);
        assert_eq!(features.values[9], 1.0); // cmd_targets_system_path
    }

    #[test]
    fn feature_extraction_detects_sudo() {
        let features = RiskFeatures::extract("sudo rm -rf /tmp", &["sudo rm -rf /tmp".into()], None, false, false, false);
        assert_eq!(features.values[8], 1.0); // cmd_has_sudo
    }

    #[test]
    fn feature_extraction_detects_network() {
        let features = RiskFeatures::extract("curl https://example.com", &["curl https://example.com".into()], None, false, false, false);
        assert_eq!(features.values[13], 1.0); // cmd_has_network
    }

    #[test]
    fn serialization_roundtrip() {
        let mut model = UserModel::new("test/repo");
        let tf = make_typesafe_features(0.5, 0.5, 3.0);
        let features = RiskFeatures::extract("test cmd", &["test cmd".into()], Some(&tf), true, false, false);
        model.update(&features, true);

        let json = serde_json::to_string(&model).unwrap();
        let loaded: UserModel = serde_json::from_str(&json).unwrap();
        for (a, b) in model.weights.iter().zip(loaded.weights.iter()) {
            assert!((a - b).abs() < 1e-10, "weights differ: {} vs {}", a, b);
        }
        assert_eq!(model.repo_id, loaded.repo_id);
    }

    #[test]
    fn repo_detection_normalizes_urls() {
        assert_eq!(normalize_repo_url("git@github.com:user/repo.git"), "user/repo");
        assert_eq!(normalize_repo_url("https://github.com/user/repo.git"), "user/repo");
        assert_eq!(normalize_repo_url("https://github.com/user/repo"), "user/repo");
    }
}
