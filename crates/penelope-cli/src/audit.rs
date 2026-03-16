use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub ts: String,
    pub session_id: String,
    pub command: String,
    pub normalized_segments: Vec<String>,
    pub has_evasion: bool,
    pub tier1_verdict: String,
    pub tier1_matched_rule: Option<String>,
    pub final_decision: String,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
}

pub struct AuditLog {
    path: std::path::PathBuf,
}

impl AuditLog {
    pub fn new(path: &Path) -> Self {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        Self {
            path: path.to_path_buf(),
        }
    }

    pub fn write(&self, entry: &AuditEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize audit entry: {}", e);
                return;
            }
        };

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", json) {
                    tracing::error!("Failed to write audit log: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to open audit log at {}: {}", self.path.display(), e);
            }
        }
    }
}
