use crate::rules::Rule;

/// Built-in block rules for catastrophic commands.
pub fn builtin_block_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "recursive-force-delete-root".into(),
            pattern: r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\s+/\s*$".into(),
            reason: Some("Recursive force delete on root filesystem".into()),
        },
        Rule {
            name: "rm-rf-slash".into(),
            pattern: r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/[^/\s]*/?\.\.\s*$".into(),
            reason: Some("Path traversal in rm command".into()),
        },
        Rule {
            name: "drop-table".into(),
            pattern: r"(?i)DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s".into(),
            reason: Some("SQL DROP statement".into()),
        },
        Rule {
            name: "truncate-table".into(),
            pattern: r"(?i)TRUNCATE\s+TABLE\s".into(),
            reason: Some("SQL TRUNCATE statement".into()),
        },
        Rule {
            name: "curl-to-shell".into(),
            pattern: r"curl\s.*\|\s*(ba)?sh".into(),
            reason: Some("Piping remote content to shell".into()),
        },
        Rule {
            name: "wget-to-shell".into(),
            pattern: r"wget\s.*\|\s*(ba)?sh".into(),
            reason: Some("Piping remote content to shell".into()),
        },
        Rule {
            name: "mkfs".into(),
            pattern: r"mkfs\.\w+\s+/dev/".into(),
            reason: Some("Formatting a disk device".into()),
        },
        Rule {
            name: "dd-of-device".into(),
            pattern: r"dd\s+.*of=/dev/[sh]d".into(),
            reason: Some("Writing directly to disk device with dd".into()),
        },
        Rule {
            name: "chmod-777-recursive".into(),
            pattern: r"chmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?777\s+/".into(),
            reason: Some("Recursive chmod 777 on system path".into()),
        },
        Rule {
            name: "fork-bomb".into(),
            pattern: r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:".into(),
            reason: Some("Fork bomb detected".into()),
        },
        Rule {
            name: "etc-passwd-write".into(),
            pattern: r">\s*/etc/(passwd|shadow|sudoers)".into(),
            reason: Some("Writing to critical auth file".into()),
        },
        Rule {
            name: "iptables-flush".into(),
            pattern: r"iptables\s+-F".into(),
            reason: Some("Flushing all firewall rules".into()),
        },
        Rule {
            name: "systemctl-disable-firewall".into(),
            pattern: r"systemctl\s+(stop|disable)\s+(firewalld|ufw|iptables)".into(),
            reason: Some("Disabling system firewall".into()),
        },
        // curl POST removed from block list — too many false positives
        // with legitimate API calls. TypeSafe Tier 2 handles this now.
        Rule {
            name: "nc-reverse-shell".into(),
            pattern: r"(nc|ncat|netcat)\s+.*-e\s+/(bin|usr)/(ba)?sh".into(),
            reason: Some("Reverse shell via netcat".into()),
        },
        Rule {
            name: "python-reverse-shell".into(),
            pattern: r"python[23]?\s+-c\s+.*socket.*connect".into(),
            reason: Some("Reverse shell via Python".into()),
        },
        Rule {
            name: "shutdown-reboot".into(),
            pattern: r"(shutdown|reboot|halt|poweroff)\s".into(),
            reason: Some("System shutdown/reboot command".into()),
        },
        Rule {
            name: "kill-all".into(),
            pattern: r"(killall|pkill)\s+-9\s".into(),
            reason: Some("Force killing processes".into()),
        },
        Rule {
            name: "git-force-push".into(),
            pattern: r"git\s+push\s+.*--force".into(),
            reason: Some("Force pushing to git remote".into()),
        },
        Rule {
            name: "git-reset-hard".into(),
            pattern: r"git\s+reset\s+--hard".into(),
            reason: Some("Hard reset of git history".into()),
        },
    ]
}

/// Built-in allow rules for known-safe commands.
pub fn builtin_allow_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "git-read-only".into(),
            pattern: r"^git\s+(status|log|diff|branch|show|remote|fetch|tag|stash\s+list|rev-parse|describe)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "ls-family".into(),
            pattern: r"^(ls|ll|la|dir|tree|exa|eza)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "file-inspection".into(),
            pattern: r"^(cat|head|tail|less|more|wc|file|stat|md5|sha256sum|shasum)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "search-tools".into(),
            pattern: r"^(find|fd|rg|grep|ag|ack|which|where|type|whereis|locate)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "echo-printf".into(),
            pattern: r"^(echo|printf)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "env-inspection".into(),
            pattern: r"^(env|printenv|set|export|whoami|id|hostname|uname|date|uptime|df|du|free|top|ps|pwd)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "cargo-read".into(),
            pattern: r"^cargo\s+(check|test|clippy|doc|bench|build|run|fmt|tree|metadata)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "npm-yarn-read".into(),
            pattern: r"^(npm|yarn|pnpm)\s+(test|run|build|lint|check|list|ls|outdated|info|why)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "python-tools".into(),
            pattern: r"^(python[23]?|pip|pytest|mypy|ruff|black|isort|flake8)\s".into(),
            reason: None,
        },
        Rule {
            name: "make".into(),
            pattern: r"^make(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "cd".into(),
            pattern: r"^cd(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "true-false-noop".into(),
            pattern: r"^(true|false|:)$".into(),
            reason: None,
        },
        Rule {
            name: "penelope-self".into(),
            pattern: r"penelope\s+(install|uninstall|check|hook|on|off|register)".into(),
            reason: None,
        },
        Rule {
            name: "process-management".into(),
            pattern: r"^(pkill|pgrep|kill|killall|ps|jobs|fg|bg|wait|lsof)\s".into(),
            reason: None,
        },
        Rule {
            name: "cp-mv-mkdir-touch".into(),
            pattern: r"^(cp|mv|mkdir|touch|chmod|ln)\s".into(),
            reason: None,
        },
        Rule {
            name: "tar-zip".into(),
            pattern: r"^(tar|zip|unzip|gzip|gunzip|bzip2|xz)\s".into(),
            reason: None,
        },
        Rule {
            name: "curl".into(),
            pattern: r"^curl\s".into(),
            reason: None,
        },
        Rule {
            name: "docker-inspect".into(),
            pattern: r"^docker\s+(ps|images|logs|inspect|stats|info|version)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "git-write".into(),
            pattern: r"^git\s+(add|commit|checkout|switch|merge|rebase|pull|push|stash|restore|rm|mv|clone|init|config)(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "pip-install".into(),
            pattern: r"^pip[23]?\s+install\s".into(),
            reason: None,
        },
        Rule {
            name: "npm-install".into(),
            pattern: r"^(npm|yarn|pnpm)\s+install(\s|$)".into(),
            reason: None,
        },
        Rule {
            name: "cargo-install".into(),
            pattern: r"^cargo\s+install\s".into(),
            reason: None,
        },
        Rule {
            name: "sed-awk-sort".into(),
            pattern: r"^(sed|awk|sort|uniq|cut|tr|tee|xargs|diff|patch|jq|yq)\s".into(),
            reason: None,
        },
        Rule {
            name: "gh-cli".into(),
            pattern: r"^gh\s".into(),
            reason: None,
        },
        Rule {
            name: "docker".into(),
            pattern: r"^docker\s".into(),
            reason: None,
        },
        Rule {
            name: "docker-compose".into(),
            pattern: r"^docker[-\s]compose\s".into(),
            reason: None,
        },
        Rule {
            name: "kubectl".into(),
            pattern: r"^kubectl\s".into(),
            reason: None,
        },
        Rule {
            name: "terraform".into(),
            pattern: r"^terraform\s".into(),
            reason: None,
        },
        Rule {
            name: "ruby-node-bun".into(),
            pattern: r"^(ruby|node|bun|deno|go|java|javac|rustc|gcc|g\+\+|clang)\s".into(),
            reason: None,
        },
        Rule {
            name: "rm-local".into(),
            pattern: r"^rm\s+(-[a-zA-Z]*\s+)*\.".into(),
            reason: None,
        },
        Rule {
            name: "chmod-chown-local".into(),
            pattern: r"^(chmod|chown)\s".into(),
            reason: None,
        },
        Rule {
            name: "source-dot".into(),
            pattern: r"^(\.|source)\s".into(),
            reason: None,
        },
        Rule {
            name: "open-macos".into(),
            pattern: r"^open\s".into(),
            reason: None,
        },
        Rule {
            name: "cat-heredoc-write".into(),
            pattern: r"^cat\s".into(),
            reason: None,
        },
        Rule {
            name: "render-cli".into(),
            pattern: r"^render\s".into(),
            reason: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn all_builtin_patterns_compile() {
        for rule in builtin_block_rules().iter().chain(builtin_allow_rules().iter()) {
            Regex::new(&rule.pattern)
                .unwrap_or_else(|e| panic!("Rule '{}' has invalid pattern: {}", rule.name, e));
        }
    }
}
