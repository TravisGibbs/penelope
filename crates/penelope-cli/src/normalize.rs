use regex::Regex;
use std::sync::LazyLock;

/// Result of normalizing a raw command string.
#[derive(Debug, Clone)]
pub struct NormalizedCommand {
    pub original: String,
    /// The command with --penelope-reasoning stripped out (ready for execution)
    pub stripped: String,
    /// Individual command segments after splitting on ;, &&, ||, |
    pub segments: Vec<String>,
    /// Whether eval was detected
    pub has_eval: bool,
    /// Whether command substitution ($() or ``) was detected
    pub has_substitution: bool,
    /// Whether base64 encoding was detected
    pub has_base64: bool,
    /// Whether nested shell invocation (sh -c, bash -c) was detected
    pub has_nested_shell: bool,
    /// Any decoded base64 payloads found
    pub decoded_payloads: Vec<String>,
    /// Agent-provided reasoning for why this command is safe (from --penelope-reasoning)
    pub reasoning: Option<String>,
}

impl NormalizedCommand {
    /// Whether any evasion techniques were detected.
    pub fn has_evasion(&self) -> bool {
        self.has_eval || self.has_substitution || self.has_base64 || self.has_nested_shell
    }
}

static SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s*(\|\||&&|;)\s*").unwrap()
});

static PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s*\|\s*").unwrap()
});

static BASE64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:base64\s+(?:-d|--decode)|base64\s+-D)").unwrap()
});

static EVAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beval\s+").unwrap()
});

static SUBST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\$\(|`)").unwrap()
});

static NESTED_SHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ba)?sh\s+-c\s+").unwrap()
});

static NESTED_SHELL_EXTRACT_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Extract the inner command from: sh -c 'cmd' or sh -c "cmd" or sh -c cmd
    Regex::new(r#"\b(?:ba)?sh\s+-c\s+(?:["'](.+?)["']|(\S+))"#).unwrap()
});

static REASONING_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Match --penelope-reasoning "..." or --penelope-reasoning '...' or --penelope-reasoning word
    Regex::new(r#"--penelope-reasoning\s+(?:"([^"]+)"|'([^']+)'|(\S+))"#).unwrap()
});

static BACKSLASH_ESCAPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\(.)").unwrap()
});

static BASE64_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Match base64-encoded strings in common patterns like: echo "XXX" | base64 -d
    // or base64 -d <<< "XXX"
    Regex::new(r#"(?:<<<\s*["']?|echo\s+["']?)([A-Za-z0-9+/]{4,}={0,2})["']?"#).unwrap()
});

/// Normalize a raw command string for evaluation.
pub fn normalize(raw: &str) -> NormalizedCommand {
    let trimmed = raw.trim();

    // Extract --penelope-reasoning before any other processing
    let reasoning = REASONING_RE.captures(trimmed).and_then(|cap| {
        cap.get(1)
            .or_else(|| cap.get(2))
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().to_string())
    });

    // Strip --penelope-reasoning from the command for evaluation and execution
    let stripped = REASONING_RE.replace(trimmed, "").trim().to_string();
    let trimmed = stripped.as_str();

    // Detect evasion techniques on the full command
    let has_eval = EVAL_RE.is_match(trimmed);
    let has_substitution = SUBST_RE.is_match(trimmed);
    let has_base64 = BASE64_RE.is_match(trimmed);
    let has_nested_shell = NESTED_SHELL_RE.is_match(trimmed);

    // Try to decode base64 payloads
    let mut decoded_payloads = Vec::new();
    if has_base64 {
        for cap in BASE64_LITERAL_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                if let Ok(bytes) = base64_decode(m.as_str()) {
                    if let Ok(s) = String::from_utf8(bytes) {
                        decoded_payloads.push(s);
                    }
                }
            }
        }
    }

    // Strip backslash escapes for evaluation (e.g., \r\m → rm)
    let cleaned = BACKSLASH_ESCAPE_RE.replace_all(trimmed, "$1").to_string();

    // Split on ;, &&, ||
    let chain_segments: Vec<&str> = SPLIT_RE.split(&cleaned).collect();

    // Further split each segment on | (pipe)
    let mut segments = Vec::new();
    for seg in chain_segments {
        for pipe_seg in PIPE_RE.split(seg) {
            let s = pipe_seg.trim().to_string();
            if !s.is_empty() {
                segments.push(s);
            }
        }
    }

    // Also add decoded payloads as segments to evaluate
    for payload in &decoded_payloads {
        let payload_normalized = normalize_inner(payload);
        segments.extend(payload_normalized);
    }

    // Extract inner commands from nested shell invocations
    if has_nested_shell {
        for cap in NESTED_SHELL_EXTRACT_RE.captures_iter(&cleaned) {
            let inner = cap.get(1).or_else(|| cap.get(2));
            if let Some(m) = inner {
                let inner_segments = normalize_inner(m.as_str());
                segments.extend(inner_segments);
            }
        }
    }

    NormalizedCommand {
        original: raw.to_string(),
        stripped,
        segments,
        has_eval,
        has_substitution,
        has_base64,
        has_nested_shell,
        decoded_payloads,
        reasoning,
    }
}

/// Inner normalization for decoded payloads — just split into segments.
fn normalize_inner(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let chain_segments: Vec<&str> = SPLIT_RE.split(trimmed).collect();
    let mut segments = Vec::new();
    for seg in chain_segments {
        for pipe_seg in PIPE_RE.split(seg) {
            let s = pipe_seg.trim().to_string();
            if !s.is_empty() {
                segments.push(s);
            }
        }
    }
    segments
}

/// Simple base64 decoding without external dependency.
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u8, ()> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(()),
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(());
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = val(chunk[2])?;
        let d = val(chunk[3])?;

        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_chain_operators() {
        let n = normalize("ls && echo hello ; pwd");
        assert_eq!(n.segments, vec!["ls", "echo hello", "pwd"]);
    }

    #[test]
    fn splits_pipes() {
        let n = normalize("cat file.txt | grep error | wc -l");
        assert_eq!(n.segments, vec!["cat file.txt", "grep error", "wc -l"]);
    }

    #[test]
    fn detects_eval() {
        let n = normalize("eval 'rm -rf /'");
        assert!(n.has_eval);
        assert!(n.has_evasion());
    }

    #[test]
    fn detects_command_substitution() {
        let n = normalize("echo $(whoami)");
        assert!(n.has_substitution);
    }

    #[test]
    fn detects_backtick_substitution() {
        let n = normalize("echo `whoami`");
        assert!(n.has_substitution);
    }

    #[test]
    fn detects_base64() {
        let n = normalize("echo 'cm0gLXJmIC8=' | base64 -d | sh");
        assert!(n.has_base64);
        assert!(n.has_evasion());
    }

    #[test]
    fn detects_nested_shell() {
        let n = normalize("bash -c 'rm -rf /'");
        assert!(n.has_nested_shell);
        assert!(n.has_evasion());
    }

    #[test]
    fn strips_backslash_escapes() {
        let n = normalize(r"\r\m -rf /");
        // After stripping backslashes, segments should contain "rm -rf /"
        assert!(n.segments.iter().any(|s| s.contains("rm")));
    }

    #[test]
    fn decodes_base64_payload() {
        // "rm -rf /" in base64 is "cm0gLXJmIC8="
        let n = normalize("echo 'cm0gLXJmIC8=' | base64 -d | sh");
        assert!(!n.decoded_payloads.is_empty());
        assert!(n.decoded_payloads[0].contains("rm"));
    }

    #[test]
    fn simple_command_no_evasion() {
        let n = normalize("git status");
        assert!(!n.has_evasion());
        assert_eq!(n.segments, vec!["git status"]);
    }

    #[test]
    fn extracts_reasoning_double_quotes() {
        let n = normalize("rm -rf /tmp/build --penelope-reasoning \"Cleaning build artifacts\"");
        assert_eq!(n.reasoning.as_deref(), Some("Cleaning build artifacts"));
        assert_eq!(n.stripped, "rm -rf /tmp/build");
        assert!(!n.segments.iter().any(|s| s.contains("penelope")));
    }

    #[test]
    fn extracts_reasoning_single_quotes() {
        let n = normalize("git push --force --penelope-reasoning 'Rebased branch'");
        assert_eq!(n.reasoning.as_deref(), Some("Rebased branch"));
        assert_eq!(n.stripped, "git push --force");
    }

    #[test]
    fn extracts_reasoning_unquoted() {
        let n = normalize("rm -rf /tmp --penelope-reasoning cleanup");
        assert_eq!(n.reasoning.as_deref(), Some("cleanup"));
        assert_eq!(n.stripped, "rm -rf /tmp");
    }

    #[test]
    fn no_reasoning_returns_none() {
        let n = normalize("ls -la");
        assert!(n.reasoning.is_none());
        assert_eq!(n.stripped, "ls -la");
    }
}
