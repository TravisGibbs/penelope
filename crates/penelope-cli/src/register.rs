use std::process::ExitCode;

use crate::config::Config;

/// Register via GitHub OAuth or manually set an API key.
pub async fn register_mode(key: Option<&str>, config: &Config) -> ExitCode {
    if let Some(api_key) = key {
        // Manual key registration
        return save_key(api_key, config);
    }

    // OAuth flow: open browser to the API's /auth/github endpoint
    let api_base = match config.remote.endpoint.as_ref() {
        Some(endpoint) => {
            // Strip /api/v1/events to get the base URL
            endpoint
                .trim_end_matches('/')
                .trim_end_matches("/api/v1/events")
                .to_string()
        }
        None => {
            eprintln!("penelope: no remote API endpoint configured.");
            eprintln!("penelope: set [remote] endpoint in your config, or use:");
            eprintln!("  penelope register --key <your-api-key>");
            return ExitCode::from(1);
        }
    };

    let auth_url = format!("{}/auth/github", api_base);

    println!("Opening browser for GitHub authentication...");
    println!("If the browser doesn't open, visit: {}", auth_url);
    println!();

    // Open browser
    if let Err(e) = open_browser(&auth_url) {
        eprintln!("penelope: failed to open browser: {}", e);
        eprintln!("Please visit the URL above manually.");
    }

    println!("After authenticating, copy your API key and run:");
    println!("  penelope register --key pen_<your-key>");

    ExitCode::SUCCESS
}

fn save_key(api_key: &str, _config: &Config) -> ExitCode {
    let config_path = dirs::home_dir()
        .map(|h| h.join(".penelope").join("config.toml"))
        .unwrap_or_else(|| {
            eprintln!("penelope: cannot determine home directory");
            std::path::PathBuf::from("penelope.toml")
        });

    // Read existing config
    let mut contents = std::fs::read_to_string(&config_path).unwrap_or_default();

    // Update or add the [remote] section with the API key
    if contents.contains("api_key") {
        // Replace existing api_key line
        let mut new_contents = String::new();
        for line in contents.lines() {
            if line.trim_start().starts_with("api_key") && !line.trim_start().starts_with('#') {
                new_contents.push_str(&format!("api_key = \"{}\"", api_key));
            } else {
                new_contents.push_str(line);
            }
            new_contents.push('\n');
        }
        contents = new_contents;
    } else if contents.contains("[remote]") {
        // Add api_key under [remote]
        contents = contents.replace(
            "[remote]",
            &format!("[remote]\napi_key = \"{}\"", api_key),
        );
    } else {
        // Append [remote] section
        contents.push_str(&format!(
            "\n[remote]\napi_key = \"{}\"\nenabled = true\n",
            api_key
        ));
    }

    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::write(&config_path, &contents) {
        Ok(_) => {
            println!("penelope: API key saved to {}", config_path.display());
            println!("penelope: remote logging enabled");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("penelope: failed to write config: {}", e);
            ExitCode::from(1)
        }
    }
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .status()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .status()
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}
