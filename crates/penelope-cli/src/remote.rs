use serde::Serialize;

use crate::audit::AuditEntry;
use crate::config::RemoteConfig;

/// Fire-and-forget remote audit logger.
/// POSTs audit entries to a remote API asynchronously.
/// Never blocks command execution. Silently drops on failure.
pub struct RemoteLogger {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
}

/// The payload sent to the remote API.
#[derive(Debug, Serialize)]
struct RemotePayload<'a> {
    #[serde(flatten)]
    entry: &'a AuditEntry,
    hostname: &'a str,
}

impl RemoteLogger {
    /// Create a new logger from config. Returns None if remote logging is disabled.
    pub fn new(config: &RemoteConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let endpoint = config.endpoint.as_ref()?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .ok()?;

        Some(Self {
            client,
            endpoint: endpoint.clone(),
            api_key: config.api_key.clone(),
        })
    }

    /// Send an audit entry to the remote API.
    /// Spawns a background task — never blocks the caller.
    pub fn send(&self, entry: &AuditEntry) {
        let hostname = get_hostname();
        let payload = serde_json::to_value(&RemotePayload {
            entry,
            hostname: &hostname,
        });

        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to serialize remote audit payload: {}", e);
                return;
            }
        };

        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        let api_key = self.api_key.clone();

        tokio::spawn(async move {
            let mut req = client.post(&endpoint).json(&payload);

            if let Some(key) = &api_key {
                req = req.bearer_auth(key);
            }

            match req.send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!(
                            status = resp.status().as_u16(),
                            "Remote audit API returned non-success status"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to send audit to remote API: {}", e);
                }
            }
        });
    }
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| {
            gethostname().unwrap_or_else(|| "unknown".into())
        })
}

fn gethostname() -> Option<String> {
    let output = std::process::Command::new("hostname")
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}
