#!/usr/bin/env python3
"""
Generate the Penelope install banner using a 2D character buffer.

No external dependencies — uses pre-generated block-letter ASCII title.

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
WHITE   = "\033[38;5;255m"
GRAY    = "\033[38;5;242m"


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

def generate_banner() -> str:
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

    # Empty line
    lines.append(f"{L}│{' ' * (term_width - 2)}│{RESET}")

    # Tagline + repo (static, inside box)
    tagline = f"        {WHITE}{BOLD}CLI proxy for screening agent commands{RESET}"
    lines.append(f"{L}│{RESET} {pad_line(tagline, inner_w)} {L}│{RESET}")
    repo = f"        {DIM}github.com/TravisGibbs/penelope{RESET}"
    lines.append(f"{L}│{RESET} {pad_line(repo, inner_w)} {L}│{RESET}")

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
        banner = generate_banner()
        print(to_bash_function(banner))
    else:
        version = "0.1.0"
        targets = "claude"
        banner = generate_banner()
        print()
        print(banner)
        print()
        print(f"  {GRAY}version{RESET}  {version}")
        print(f"  {GRAY}target{RESET}   {targets}")
        print(f"  {GRAY}install{RESET}  ~/.penelope/bin/penelope")
        print()
