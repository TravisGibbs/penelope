#!/bin/bash
set -euo pipefail

# Penelope — one-command installer
# curl -fsSL https://raw.githubusercontent.com/<user>/penelope/main/install.sh | bash
# Or with targets: curl ... | bash -s -- codex
# Or both:         curl ... | bash -s -- all

REPO_URL="${PENELOPE_REPO:-https://github.com/travisgibs/penelope.git}"
INSTALL_DIR="${PENELOPE_INSTALL_DIR:-$HOME/.penelope/bin}"
SRC_DIR="${PENELOPE_SRC_DIR:-$HOME/.penelope/src}"
TARGETS="${1:-claude}"

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} ${BOLD}$1${NC}"; }
warn()  { echo -e "${YELLOW}warning:${NC} $1"; }
error() { echo -e "${RED}error:${NC} $1"; exit 1; }

echo ""
echo -e "${BOLD}penelope${NC} — CLI proxy for screening agent commands"
echo ""

# ── Prerequisites ──────────────────────────────────────────────────

if ! command -v git &>/dev/null; then
    error "git is required but not found"
fi

# Install Rust if missing
if ! command -v cargo &>/dev/null; then
    info "Rust not found — installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
    if ! command -v cargo &>/dev/null; then
        error "Rust installation failed. Install manually from https://rustup.rs"
    fi
    info "Rust installed"
fi

# ── Clone / update source ─────────────────────────────────────────

if [ -d "$SRC_DIR/.git" ]; then
    info "Updating source..."
    git -C "$SRC_DIR" pull --quiet 2>/dev/null || true
else
    info "Cloning penelope..."
    rm -rf "$SRC_DIR"
    git clone --quiet --depth 1 "$REPO_URL" "$SRC_DIR"
fi

# ── Build ──────────────────────────────────────────────────────────

info "Building (release)..."
cargo build --release --manifest-path "$SRC_DIR/Cargo.toml" 2>&1 | tail -1

# ── Install binary ─────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR"
cp "$SRC_DIR/target/release/penelope" "$INSTALL_DIR/penelope"
chmod +x "$INSTALL_DIR/penelope"
info "Installed to $INSTALL_DIR/penelope"

# ── Add to PATH ────────────────────────────────────────────────────

add_to_path() {
    local shell_rc=""
    case "${SHELL:-/bin/bash}" in
        */zsh)  shell_rc="$HOME/.zshrc" ;;
        */bash) shell_rc="$HOME/.bashrc" ;;
        */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
        *)      shell_rc="$HOME/.profile" ;;
    esac

    local export_line="export PATH=\"$INSTALL_DIR:\$PATH\""
    if [ -n "$shell_rc" ] && ! grep -qF "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
        echo "" >> "$shell_rc"
        echo "# penelope" >> "$shell_rc"
        echo "$export_line" >> "$shell_rc"
        info "Added to PATH in $shell_rc"
    fi
    export PATH="$INSTALL_DIR:$PATH"
}

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    add_to_path
fi

# ── Install hooks ──────────────────────────────────────────────────

echo ""
if [ "$TARGETS" = "all" ]; then
    "$INSTALL_DIR/penelope" install claude codex
else
    "$INSTALL_DIR/penelope" install $TARGETS
fi

# ── Done ───────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}Done!${NC} Penelope is now screening agent commands."
echo ""
echo "  penelope check \"rm -rf /\"   Test a command"
echo "  penelope uninstall           Remove hooks"
echo "  tail -f ~/.penelope/audit.jsonl  Watch decisions"
echo ""
