#!/bin/bash
set -euo pipefail

# Penelope — one-command installer
# curl -fsSL https://raw.githubusercontent.com/TravisGibbs/penelope/main/install.sh | bash
# Or with targets: curl ... | bash -s -- codex
# Or both:         curl ... | bash -s -- all

REPO="TravisGibbs/penelope"
INSTALL_DIR="${PENELOPE_INSTALL_DIR:-$HOME/.penelope/bin}"
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

# ── Detect platform ───────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) PLATFORM="apple-darwin" ;;
    Linux)  PLATFORM="unknown-linux-gnu" ;;
    *)      error "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  TARGET="x86_64-$PLATFORM" ;;
    arm64|aarch64) TARGET="aarch64-$PLATFORM" ;;
    *)             error "Unsupported architecture: $ARCH" ;;
esac

# ── Try prebuilt binary first ─────────────────────────────────────

RELEASE_URL="https://github.com/$REPO/releases/latest/download/penelope-$TARGET.tar.gz"
INSTALLED=false

info "Checking for prebuilt binary ($TARGET)..."
if curl -fsSL --head "$RELEASE_URL" &>/dev/null; then
    info "Downloading prebuilt binary..."
    mkdir -p "$INSTALL_DIR"
    curl -fsSL "$RELEASE_URL" | tar xz -C "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/penelope"
    INSTALLED=true
    info "Installed prebuilt binary to $INSTALL_DIR/penelope"
else
    warn "No prebuilt binary found — building from source"
fi

# ── Fallback: build from source ───────────────────────────────────

if [ "$INSTALLED" = false ]; then
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

    info "Installing from source (this takes ~30s)..."
    cargo install --git "https://github.com/$REPO.git" --bin penelope --root "$HOME/.penelope" 2>&1 | tail -3
    INSTALLED=true
    info "Built and installed to $INSTALL_DIR/penelope"
fi

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
