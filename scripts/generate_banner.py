#!/usr/bin/env python3
"""
Generate the Penelope install banner using a 2D character buffer.

No external dependencies — uses pre-generated ASCII title text and
hand-drawn pixel art for the lynx point cat mascot.

Usage:
    python3 scripts/generate_banner.py          # preview in terminal
    python3 scripts/generate_banner.py --bash   # output bash function
"""

import sys
import re
import shutil


# ── ANSI colors ──────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[38;5;78m"
CYAN    = "\033[38;5;117m"
MAGENTA = "\033[38;5;183m"
YELLOW  = "\033[38;5;222m"
WHITE   = "\033[38;5;255m"
GRAY    = "\033[38;5;242m"
# Lynx point colors: cream/tan body, brown tabby points


# ── Helpers ──────────────────────────────────────────────────────────

def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences for length calculation."""
    return re.sub(r'\033\[[0-9;]*m', '', s)


def pad_line(content: str, inner_w: int) -> str:
    """Pad a colored string to fill inner_w visible chars."""
    visible = len(strip_ansi(content))
    pad = inner_w - visible
    if pad < 0:
        pad = 0
    return content + " " * pad


def center_line(content: str, inner_w: int) -> str:
    """Center a colored string within inner_w visible chars."""
    visible = len(strip_ansi(content))
    pad_total = inner_w - visible
    if pad_total < 0:
        pad_total = 0
    pad_l = pad_total // 2
    pad_r = pad_total - pad_l
    return " " * pad_l + content + " " * pad_r


# ── Build banner ─────────────────────────────────────────────────────

def generate_banner(version: str = "0.1.0", targets: str = "claude") -> str:
    term_width = min(shutil.get_terminal_size().columns, 72)
    inner_w = term_width - 4  # 2 border chars + 2 padding spaces

    title_lines = [
        "████  █████ █   █ █████ █      ███  ████  █████",
        "█   █ █     ██  █ █     █     █   █ █   █ █    ",
        "█   █ █     █ █ █ █     █     █   █ █   █ █    ",
        "████  ████  █ █ █ ████  █     █   █ ████  ████ ",
        "█     █     █ █ █ █     █     █   █ █     █    ",
        "█     █     █  ██ █     █     █   █ █     █    ",
        "█     █████ █   █ █████ █████  ███  █     █████",
    ]

    lines: list[str] = []
    L = CYAN  # border color

    # Top border
    lines.append(f"{L}╭{'─' * (term_width - 2)}╮{RESET}")

    # Empty line
    lines.append(f"{L}│{' ' * (term_width - 2)}│{RESET}")

    # Title (centered, colored)
    for tl in title_lines:
        centered = center_line(f"{MAGENTA}{BOLD}{tl}{RESET}", inner_w)
        lines.append(f"{L}│{RESET} {centered} {L}│{RESET}")

    # Separator
    lines.append(f"{L}│{RESET} {GRAY}{'─' * inner_w}{RESET} {L}│{RESET}")

    # Info section
    info_lines = [
        f"{WHITE}{BOLD}  CLI proxy for screening agent commands{RESET}",
        "",
        f"  {GRAY}version  {RESET}{GREEN}{version}{RESET}",
        f"  {GRAY}target   {RESET}{YELLOW}{targets}{RESET}",
        f"  {GRAY}install  {RESET}{WHITE}~/.penelope/bin/penelope{RESET}",
        "",
        f"  {DIM}github.com/TravisGibbs/penelope{RESET}",
    ]

    for inf in info_lines:
        padded = pad_line(inf, inner_w)
        lines.append(f"{L}│{RESET} {padded} {L}│{RESET}")

    # Separator
    lines.append(f"{L}│{RESET} {GRAY}{'─' * inner_w}{RESET} {L}│{RESET}")

    # Status line
    status = f"{GREEN}{BOLD}  ▸ Installing...{RESET}"
    padded = pad_line(status, inner_w)
    lines.append(f"{L}│{RESET} {padded} {L}│{RESET}")

    # Empty line
    lines.append(f"{L}│{' ' * (term_width - 2)}│{RESET}")

    # Bottom border
    lines.append(f"{L}╰{'─' * (term_width - 2)}╯{RESET}")

    return "\n".join(lines)


def to_bash_function(banner_text: str) -> str:
    """Output a bash show_banner function using printf.

    Converts literal ESC bytes to \\033 so the output is a portable,
    copy-pasteable bash function. Uses unquoted heredoc so $VERSION
    and $TARGETS get expanded by bash at runtime.
    """
    # Replace literal ESC (0x1b) with the printable sequence \033
    escaped = banner_text.replace("\033", "\\033")
    return f"""show_banner() {{
    printf '%b\\n' "$(cat <<BANNER
{escaped}
BANNER
)"
}}"""


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bash_mode = "--bash" in sys.argv

    if bash_mode:
        # Use shell variable placeholders for dynamic values
        banner = generate_banner(version="$VERSION", targets="$TARGETS")
        print(to_bash_function(banner))
    else:
        version = "0.1.0"
        targets = "claude"
        banner = generate_banner(version=version, targets=targets)
        print()
        print(banner)
        print()
