# Penelope

Penelope is a CLI wrapper that attempts to prevent disaster while autonomous agents wreak havoc in the command line.

## How it works

Penelope sits between your AI agent and the shell. Every command passes through a fast screening layer that evaluates in microseconds — zero impact on agent performance. Dangerous commands are blocked before they ever execute. Everything is logged for full observability.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/TravisGibbs/penelope/main/install.sh | bash
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
```

## Agent interaction

When Penelope blocks a command, it tells the agent why and how to proceed. The agent can resubmit with an explanation:

```bash
git push --force --penelope-reasoning "Rebased feature branch onto main"
```

Penelope strips the reasoning flag before execution and logs it for training data.

## Configuration

```toml
# ~/.penelope/config.toml

[tier2]
endpoint = "http://localhost:8000/classify"
enabled = true

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

## License

MIT
