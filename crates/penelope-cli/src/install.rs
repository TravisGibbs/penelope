use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{json, Map, Value};

const HOOK_ENTRY: &str = r#"{"matcher":"Bash","hooks":[{"type":"command","command":"PENELOPE_BIN hook"}]}"#;

pub fn install_mode(targets: &[String]) -> ExitCode {
    let bin_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            eprintln!("penelope: cannot determine binary path: {}", e);
            return ExitCode::from(1);
        }
    };

    let targets: Vec<&str> = if targets.is_empty() {
        vec!["claude"]
    } else {
        targets.iter().map(|s| s.as_str()).collect()
    };

    let mut any_failed = false;

    for target in &targets {
        match *target {
            "claude" => {
                if !install_claude_code(&bin_path) {
                    any_failed = true;
                }
            }
            "codex" => {
                if !install_codex(&bin_path) {
                    any_failed = true;
                }
            }
            other => {
                eprintln!("penelope: unknown target '{}'. Supported: claude, codex", other);
                any_failed = true;
            }
        }
    }

    if any_failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub fn uninstall_mode(targets: &[String]) -> ExitCode {
    let targets: Vec<&str> = if targets.is_empty() {
        vec!["claude"]
    } else {
        targets.iter().map(|s| s.as_str()).collect()
    };

    let mut any_failed = false;

    for target in &targets {
        match *target {
            "claude" => {
                if !uninstall_claude_code() {
                    any_failed = true;
                }
            }
            "codex" => {
                if !uninstall_codex() {
                    any_failed = true;
                }
            }
            other => {
                eprintln!("penelope: unknown target '{}'. Supported: claude, codex", other);
                any_failed = true;
            }
        }
    }

    if any_failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// --- Claude Code ---

fn claude_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn install_claude_code(bin_path: &str) -> bool {
    let settings_path = match claude_settings_path() {
        Some(p) => p,
        None => {
            eprintln!("penelope: cannot determine home directory");
            return false;
        }
    };

    // Read existing settings or start fresh
    let mut settings = read_json_file(&settings_path).unwrap_or_else(|| json!({}));

    let hook_command = format!("{} hook", bin_path);
    let post_hook_command = format!("{} post-hook", bin_path);

    // Build the PreToolUse hook entry
    let hook_obj = json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": hook_command
        }]
    });

    // Build the PostToolUse hook entry (for learning from user feedback)
    let post_hook_obj = json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": post_hook_command
        }]
    });

    // Navigate to hooks.PreToolUse, creating if needed
    let obj = settings.as_object_mut().unwrap();
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut();

    let hooks = match hooks {
        Some(h) => h,
        None => {
            eprintln!("penelope: settings.json 'hooks' field is not an object");
            return false;
        }
    };

    let pre_tool_use = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut();

    let pre_tool_use = match pre_tool_use {
        Some(a) => a,
        None => {
            eprintln!("penelope: settings.json 'hooks.PreToolUse' is not an array");
            return false;
        }
    };

    // Check if penelope hook is already installed
    let already_installed = pre_tool_use.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("penelope"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });

    if already_installed {
        // Update the existing entry with new binary path
        for entry in pre_tool_use.iter_mut() {
            if let Some(hooks) = entry.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                for h in hooks.iter_mut() {
                    if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                        if cmd.contains("penelope") {
                            h.as_object_mut()
                                .unwrap()
                                .insert("command".into(), json!(hook_command));
                        }
                    }
                }
            }
        }
        println!("penelope: updated existing hook in Claude Code settings");
    } else {
        pre_tool_use.push(hook_obj);
        println!("penelope: added hook to Claude Code settings");
    }

    // Also install PostToolUse hook for learning
    let post_tool_use = hooks
        .entry("PostToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut();

    if let Some(post_arr) = post_tool_use {
        let post_installed = post_arr.iter().any(|entry| {
            entry
                .get("hooks")
                .and_then(|h| h.as_array())
                .map(|hooks| hooks.iter().any(|h| {
                    h.get("command").and_then(|c| c.as_str()).map(|c| c.contains("penelope")).unwrap_or(false)
                }))
                .unwrap_or(false)
        });

        if post_installed {
            for entry in post_arr.iter_mut() {
                if let Some(hooks) = entry.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                    for h in hooks.iter_mut() {
                        if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("penelope") {
                                h.as_object_mut().unwrap().insert("command".into(), json!(post_hook_command));
                            }
                        }
                    }
                }
            }
        } else {
            post_arr.push(post_hook_obj);
        }
    }

    write_json_file(&settings_path, &settings)
}

fn uninstall_claude_code() -> bool {
    let settings_path = match claude_settings_path() {
        Some(p) => p,
        None => {
            eprintln!("penelope: cannot determine home directory");
            return false;
        }
    };

    let mut settings = match read_json_file(&settings_path) {
        Some(s) => s,
        None => {
            println!("penelope: no Claude Code settings found, nothing to uninstall");
            return true;
        }
    };

    let removed_pre = remove_penelope_hooks(&mut settings, "PreToolUse");
    let removed_post = remove_penelope_hooks(&mut settings, "PostToolUse");

    if removed_pre || removed_post {
        println!("penelope: removed hooks from Claude Code settings");
        write_json_file(&settings_path, &settings)
    } else {
        println!("penelope: no penelope hooks found in Claude Code settings");
        true
    }
}

// --- Codex ---

fn codex_config_path() -> Option<PathBuf> {
    // Codex CLI uses ~/.codex/config.json or similar
    // OpenAI Codex CLI uses instructions file but hooks aren't standardized yet
    // For now, use the SHELL wrapper approach via a profile script
    dirs::home_dir().map(|h| h.join(".codex").join("config.json"))
}

fn install_codex(bin_path: &str) -> bool {
    let config_path = match codex_config_path() {
        Some(p) => p,
        None => {
            eprintln!("penelope: cannot determine home directory");
            return false;
        }
    };

    // Codex doesn't have the same hook system as Claude Code.
    // Instead, we create a wrapper script that sets SHELL=penelope
    // and write instructions to the codex config.
    let wrapper_dir = dirs::home_dir()
        .map(|h| h.join(".penelope"))
        .unwrap_or_else(|| PathBuf::from("/tmp/penelope"));

    if let Err(e) = std::fs::create_dir_all(&wrapper_dir) {
        eprintln!("penelope: failed to create {}: {}", wrapper_dir.display(), e);
        return false;
    }

    let wrapper_path = wrapper_dir.join("codex-wrapper.sh");
    let wrapper_content = format!(
        r#"#!/bin/bash
# Penelope wrapper for Codex CLI
# This script sets SHELL to penelope so all agent commands are screened.
export PENELOPE_REAL_SHELL="${{SHELL:-/bin/bash}}"
export SHELL="{bin_path}"
exec codex "$@"
"#,
        bin_path = bin_path
    );

    if let Err(e) = std::fs::write(&wrapper_path, &wrapper_content) {
        eprintln!("penelope: failed to write wrapper: {}", e);
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755));
    }

    println!("penelope: installed Codex wrapper at {}", wrapper_path.display());
    println!("penelope: run Codex through penelope with:");
    println!("  {} [codex args...]", wrapper_path.display());
    println!("  or: alias codex='{}'", wrapper_path.display());
    true
}

fn uninstall_codex() -> bool {
    let wrapper_path = dirs::home_dir()
        .map(|h| h.join(".penelope").join("codex-wrapper.sh"))
        .unwrap_or_else(|| PathBuf::from("/tmp/penelope/codex-wrapper.sh"));

    if wrapper_path.exists() {
        if let Err(e) = std::fs::remove_file(&wrapper_path) {
            eprintln!("penelope: failed to remove wrapper: {}", e);
            return false;
        }
        println!("penelope: removed Codex wrapper");
    } else {
        println!("penelope: no Codex wrapper found, nothing to uninstall");
    }
    true
}

// --- Helpers ---

fn read_json_file(path: &PathBuf) -> Option<Value> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn write_json_file(path: &PathBuf, value: &Value) -> bool {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("penelope: failed to create {}: {}", parent.display(), e);
            return false;
        }
    }

    let json = match serde_json::to_string_pretty(value) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("penelope: failed to serialize JSON: {}", e);
            return false;
        }
    };

    match std::fs::write(path, format!("{}\n", json)) {
        Ok(_) => {
            println!("penelope: wrote {}", path.display());
            true
        }
        Err(e) => {
            eprintln!("penelope: failed to write {}: {}", path.display(), e);
            false
        }
    }
}

fn remove_penelope_hooks(settings: &mut Value, hook_event: &str) -> bool {
    let pre_tool_use = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut(hook_event))
        .and_then(|p| p.as_array_mut());

    let pre_tool_use = match pre_tool_use {
        Some(a) => a,
        None => return false,
    };

    let before_len = pre_tool_use.len();
    pre_tool_use.retain(|entry| {
        !entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("penelope"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });

    pre_tool_use.len() < before_len
}
