use std::env;
use uuid::Uuid;

const SESSION_ENV_VAR: &str = "PENELOPE_SESSION_ID";

/// Get or create a session ID.
/// If PENELOPE_SESSION_ID is set in the environment, use it.
/// Otherwise, generate a new one.
pub fn get_or_create_session_id() -> String {
    env::var(SESSION_ENV_VAR).unwrap_or_else(|_| {
        let id = Uuid::new_v4().to_string()[..8].to_string();
        env::set_var(SESSION_ENV_VAR, &id);
        id
    })
}
