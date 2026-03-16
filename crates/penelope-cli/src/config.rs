use penelope_rules::Rule;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub tier1: Tier1Config,
    #[serde(default)]
    pub tier2: Tier2Config,
    #[serde(default)]
    pub human_in_the_loop: HumanConfig,
}

#[derive(Debug, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_real_shell")]
    pub real_shell: String,
    #[serde(default = "default_log_file")]
    pub log_file: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_context_size")]
    pub session_context_size: usize,
}

#[derive(Debug, Deserialize, Default)]
pub struct Tier1Config {
    #[serde(default)]
    pub block: Vec<Rule>,
    #[serde(default)]
    pub allow: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Tier2Config {
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_timeout_action")]
    pub timeout_action: String,
    #[serde(default)]
    pub sidecar_auto_start: bool,
}

#[derive(Debug, Deserialize)]
pub struct HumanConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_deny")]
    pub default_action: String,
}

fn default_real_shell() -> String {
    std::env::var("PENELOPE_REAL_SHELL").unwrap_or_else(|_| "/bin/bash".into())
}
fn default_log_file() -> String { "~/.penelope/audit.jsonl".into() }
fn default_log_level() -> String { "info".into() }
fn default_context_size() -> usize { 20 }
fn default_socket_path() -> String { "/tmp/penelope-sidecar.sock".into() }
fn default_timeout_ms() -> u64 { 100 }
fn default_timeout_action() -> String { "allow".into() }
fn default_true() -> bool { true }
fn default_timeout_seconds() -> u64 { 30 }
fn default_deny() -> String { "deny".into() }

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            real_shell: default_real_shell(),
            log_file: default_log_file(),
            log_level: default_log_level(),
            session_context_size: default_context_size(),
        }
    }
}

impl Default for Tier2Config {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            timeout_ms: default_timeout_ms(),
            timeout_action: default_timeout_action(),
            sidecar_auto_start: false,
        }
    }
}

impl Default for HumanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_seconds: default_timeout_seconds(),
            default_action: default_deny(),
        }
    }
}

impl Config {
    /// Load config from a TOML file, falling back to defaults if not found.
    pub fn load(path: Option<&Path>) -> Self {
        if let Some(p) = path {
            if p.exists() {
                if let Ok(contents) = std::fs::read_to_string(p) {
                    if let Ok(config) = toml::from_str(&contents) {
                        return config;
                    }
                    tracing::warn!("Failed to parse config at {}, using defaults", p.display());
                }
            }
        }

        // Try default locations
        let candidates = vec![
            PathBuf::from("penelope.toml"),
            dirs::home_dir()
                .map(|h| h.join(".config/penelope/penelope.toml"))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|h| h.join(".penelope/config.toml"))
                .unwrap_or_default(),
        ];

        for candidate in candidates {
            if candidate.exists() {
                if let Ok(contents) = std::fs::read_to_string(&candidate) {
                    if let Ok(config) = toml::from_str(&contents) {
                        tracing::info!("Loaded config from {}", candidate.display());
                        return config;
                    }
                }
            }
        }

        tracing::debug!("No config file found, using defaults");
        Config {
            general: GeneralConfig::default(),
            tier1: Tier1Config::default(),
            tier2: Tier2Config::default(),
            human_in_the_loop: HumanConfig::default(),
        }
    }

    /// Expand ~ in log file path.
    pub fn log_file_path(&self) -> PathBuf {
        let path = &self.general.log_file;
        if path.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(&path[2..]);
            }
        }
        PathBuf::from(path)
    }
}
