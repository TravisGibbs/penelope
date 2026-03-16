# Penelope

Penelope is a CLI wrapper that attempts to prevent disaster while autonomous agents wreak havoc in the command line.

## How it works

Penelope sits between your AI agent and the shell. Every command the agent tries to run passes through a two-tier evaluation pipeline:

```
Agent command
    │
    ▼
┌─────────────────────────────────────────┐
│  Tier 1: Rust regex engine (~1μs)       │
│  Compiled RegexSet — single-pass match  │
│  against all block + allow rules        │
│  99%+ of commands resolve here          │
└────────┬──────────────┬─────────────────┘
     allow           escalate
     (~1μs)             │
         │              ▼
         │   ┌──────────────────────────┐
         │   │  Tier 2: NLI classifier  │
         │   │  Semantic risk analysis  │
         │   │  ~5-10ms                 │
         │   └──────────┬───────────────┘
         │          allow / block
         ▼              ▼
      Execute    Block (exit 126)
```

**Tier 1** is a Rust binary using compiled `RegexSet` patterns. It evaluates every command in **~1 microsecond** — invisible latency. Known-safe commands (git, ls, cargo, docker, etc.) pass instantly. Known-dangerous commands (rm -rf /, DROP TABLE, curl|sh, fork bombs, reverse shells) are blocked immediately. The vast majority of agent commands never leave Tier 1.

**Tier 2** handles the long tail — commands Tier 1 doesn't recognize. An NLI classification model evaluates the command semantically, considering the full context (what the command does, recent command history, agent-provided reasoning). This adds ~5-10ms when invoked.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/TravisGibbs/penelope/main/install.sh | bash
```

This downloads a prebuilt binary, installs to `~/.penelope/bin`, adds to PATH, and hooks into Claude Code automatically.

### Manual install

```bash
git clone https://github.com/TravisGibbs/penelope.git
cd penelope
cargo install --path crates/penelope-cli
penelope install claude
```

## Commands

```bash
penelope on                  # Enable screening
penelope off                 # Disable screening (full pass-through)
penelope install claude      # Hook into Claude Code
penelope install codex       # Hook into Codex
penelope uninstall           # Remove all hooks
penelope check "rm -rf /"   # Dry-run a command
penelope register            # Sign in with GitHub for remote logging
penelope register --key KEY  # Set API key manually
```

## How agents interact with Penelope

When Penelope blocks or escalates a command, it tells the agent why and how to proceed:

```
penelope: Command requires review. To proceed, re-run the command with
--penelope-reasoning "<explain why this command is safe>" appended.
```

The agent can resubmit with reasoning:

```bash
git push --force --penelope-reasoning "Rebased feature branch onto main"
```

Penelope strips `--penelope-reasoning` before execution, logs the reasoning as training data, and allows the command. When Tier 2 is active, the model evaluates the reasoning — if it still disagrees, the command is hard-blocked and reasoning cannot override it.

## What gets blocked

Tier 1 blocks these patterns out of the box:

- `rm -rf /` — recursive delete on root
- `DROP TABLE`, `TRUNCATE TABLE` — destructive SQL
- `curl ... | sh` — piping remote code to shell
- `:(){ :|:& };:` — fork bombs
- `nc -e /bin/sh` — reverse shells
- `mkfs`, `dd of=/dev/` — disk formatting
- `git push --force`, `git reset --hard` — destructive git ops
- `shutdown`, `reboot`, `halt` — system power commands
- Writing to `/etc/passwd`, `/etc/shadow` — critical auth files
- Flushing iptables, disabling firewalls

## What passes through instantly

- `git status/log/diff/add/commit/push/pull`
- `ls`, `cat`, `head`, `tail`, `grep`, `find`
- `cargo build/test/run`, `npm test/build`, `pip install`
- `docker ps/build/run`, `kubectl`, `terraform`
- `cp`, `mv`, `mkdir`, `chmod`, `rm ./local-paths`
- `echo`, `printf`, `cd`, `pwd`, `env`
- `sed`, `awk`, `jq`, `sort`, `xargs`
- `gh`, `curl` (GET requests)

## Evasion detection

Penelope normalizes commands before evaluation to catch obfuscation:

- **Base64 encoding** — decodes `base64 -d` payloads and evaluates the inner command
- **Nested shells** — extracts commands from `bash -c '...'` and `sh -c '...'`
- **Eval unwrapping** — flags `eval` usage
- **Command substitution** — detects `$(...)` and backticks
- **Backslash escapes** — strips `\r\m` → `rm`

## Configuration

Config is loaded from `./penelope.toml`, `~/.config/penelope/penelope.toml`, or `~/.penelope/config.toml`:

```toml
[tier2]
endpoint = "http://localhost:8000/classify"
enabled = true
timeout_ms = 100
offline_action = "escalate"  # "escalate" | "allow" | "block"

[remote]
endpoint = "https://penelope-api.onrender.com/api/v1/events"
api_key = "pen_your_key_here"
enabled = true

# Custom rules
[[tier1.block]]
name = "my-custom-block"
pattern = "some_dangerous_pattern"
reason = "Why this is blocked"

[[tier1.allow]]
name = "my-safe-tool"
pattern = "^my-internal-tool\\s"
```

## Audit log

Every command evaluation is logged to `~/.penelope/audit.jsonl`:

```json
{
  "ts": "2026-03-16T15:41:52.602Z",
  "session_id": "a1b2c3",
  "command": "rm -rf /",
  "tier1_verdict": "block",
  "final_decision": "block",
  "reason": "Recursive force delete on root filesystem",
  "duration_us": 3
}
```

## Architecture

```
penelope/
├── crates/
│   ├── penelope-cli/      # Main binary (Rust)
│   │   ├── pipeline.rs    # Tier 1 → Tier 2 orchestrator
│   │   ├── normalize.rs   # Command normalization + evasion detection
│   │   ├── tier2.rs       # NLI HTTP client
│   │   ├── hook.rs        # Claude Code PreToolUse hook
│   │   ├── shell.rs       # SHELL= wrapper mode
│   │   └── remote.rs      # Fire-and-forget audit API client
│   └── penelope-rules/    # Tier 1 regex engine (library)
│       ├── engine.rs      # RegexSet evaluation
│       └── builtins.rs    # Built-in block/allow patterns
└── install.sh             # One-command installer
```

## License

MIT
