#!/usr/bin/env python3
"""
AdByG0d - Banner & UI Components
The most brutal AD pentesting framework ever forged.
"""

import sys
import time
import random
import shutil
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  ANSI Color Codes - Raw power, no dependencies
# ═══════════════════════════════════════════════════════════════

class C:
    """Color codes for terminal output."""
    RST     = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDER   = "\033[4m"
    BLINK   = "\033[5m"
    STRIKE  = "\033[9m"

    # Regular
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    PURPLE  = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    # Bright
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BPURPLE = "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    # Backgrounds
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"
    BG_PURPLE = "\033[45m"
    BG_CYAN   = "\033[46m"

    # 256 color
    @staticmethod
    def rgb(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def bg_rgb(r, g, b):
        return f"\033[48;2;{r};{g};{b}m"


# Fire gradient colors
FIRE = [
    C.rgb(255, 50, 0),
    C.rgb(255, 80, 0),
    C.rgb(255, 120, 0),
    C.rgb(255, 160, 0),
    C.rgb(255, 200, 0),
    C.rgb(255, 220, 50),
    C.rgb(255, 240, 100),
]

# Cyber gradient
CYBER = [
    C.rgb(0, 255, 255),
    C.rgb(0, 200, 255),
    C.rgb(0, 150, 255),
    C.rgb(50, 100, 255),
    C.rgb(100, 50, 255),
    C.rgb(150, 0, 255),
    C.rgb(200, 0, 255),
]

# Blood red gradient
BLOOD = [
    C.rgb(180, 0, 0),
    C.rgb(200, 0, 0),
    C.rgb(220, 10, 0),
    C.rgb(240, 20, 0),
    C.rgb(255, 40, 10),
    C.rgb(255, 60, 20),
    C.rgb(255, 80, 30),
]

SKULL = C.rgb(200, 200, 200)


def gradient_text(text, colors):
    """Apply gradient coloring to text."""
    if not text:
        return text
    result = ""
    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        result += f"{color}{char}"
    return result + C.RST


def fire_text(text):
    return gradient_text(text, FIRE)


def cyber_text(text):
    return gradient_text(text, CYBER)


def blood_text(text):
    return gradient_text(text, BLOOD)


MAIN_BANNER = r"""
                ╔══════════════════════════════════════════════════════════════╗
                ║                                                              ║
                ║        ░█████╗░██████╗░██████╗░██╗░░░██╗░██████╗░░█████╗░   ║
                ║        ██╔══██╗██╔══██╗██╔══██╗╚██╗░██╔╝██╔════╝░██╔══██╗   ║
                ║        ███████║██║░░██║██████╦╝░╚████╔╝░██║░░██╗░██║░░██║   ║
                ║        ██╔══██║██║░░██║██╔══██╗░░╚██╔╝░░██║░░╚██╗██║░░██║   ║
                ║        ██║░░██║██████╔╝██████╦╝░░░██║░░░╚██████╔╝╚█████╔╝   ║
                ║        ╚═╝░░╚═╝╚═════╝░╚═════╝░░░░╚═╝░░░░╚═════╝░░╚════╝   ║
                ║                                                              ║
                ╚══════════════════════════════════════════════════════════════╝
"""

SUB_BANNER = """
        ┌─────────────────────────────────────────────────────────────────────────┐
        │  {tagline}  │
        │                                                                         │
        │    ██████   Active Directory Penetration Testing Framework   ██████     │
        │    ░░░░░░   "Your Domain. My Rules."                        ░░░░░░     │
        └─────────────────────────────────────────────────────────────────────────┘
"""

SKULL_ART = r"""
                                    ░░░░░░░░░░░
                                 ░░░░░░░░░░░░░░░░░
                               ░░░░░░░░░░░░░░░░░░░░░
                              ░░░░░░░░░░░░░░░░░░░░░░░
                              ░░░░░▓▓▓░░░░░░░▓▓▓░░░░░
                              ░░░░░▓▓▓░░░░░░░▓▓▓░░░░░
                              ░░░░░░░░░░▓▓▓░░░░░░░░░░
                               ░░░░░░░░░░░░░░░░░░░░░
                                ░░░▓▓▓▓▓▓▓▓▓▓▓░░░░
                                   ░░░░░░░░░░░
"""


def typewriter(text, delay=0.002, color=""):
    """Print text with typewriter effect."""
    for char in text:
        sys.stdout.write(f"{color}{char}{C.RST}")
        sys.stdout.flush()
        if char == '\n':
            time.sleep(delay * 3)
        else:
            time.sleep(delay)


def print_banner(fast=False):
    """Display the main AdByG0d banner with effects."""
    shutil.get_terminal_size().columns

    sys.stdout.write("\033[2J\033[H")  # Clear screen
    sys.stdout.flush()

    # Skull art
    for line in SKULL_ART.split('\n'):
        if line.strip():
            print(f"{SKULL}{line}{C.RST}")
            if not fast:
                time.sleep(0.03)

    # Main banner with fire gradient
    for i, line in enumerate(MAIN_BANNER.split('\n')):
        if line.strip():
            color_idx = i % len(FIRE)
            print(f"{FIRE[color_idx]}{C.BOLD}{line}{C.RST}")
            if not fast:
                time.sleep(0.04)

    # Tagline
    taglines = [
        "  Bow before the Domain Controller, for AdByG0d has arrived!  ",
        "  Kerberos trembles. LDAP weeps. Your AD is already mine.    ",
        "  Every ticket. Every hash. Every trust. All mine.           ",
        "  I don't break into domains. Domains break for me.          ",
        "  From AS-REP to DA — it's not a question of if, but when.   ",
    ]
    tagline = random.choice(taglines)

    sub = SUB_BANNER.format(tagline=tagline)
    for line in sub.split('\n'):
        if line.strip():
            print(f"{C.CYAN}{line}{C.RST}")
            if not fast:
                time.sleep(0.02)

    # Info line
    print()
    info_parts = [
        f"  {C.rgb(255,100,0)}╔{'═'*68}╗{C.RST}",
        f"  {C.rgb(255,100,0)}║{C.RST}  {C.BWHITE}{C.BOLD}Version:{C.RST} {C.BGREEN}1.0.0{C.RST}  {C.DIM}│{C.RST}  {C.BWHITE}{C.BOLD}Author:{C.RST} {C.BRED}White0xdi3{C.RST}  {C.DIM}│{C.RST}  {C.BWHITE}{C.BOLD}Date:{C.RST} {C.BCYAN}{datetime.now().strftime('%Y-%m-%d %H:%M')}{C.RST}  {C.rgb(255,100,0)}║{C.RST}",
        f"  {C.rgb(255,100,0)}╚{'═'*68}╝{C.RST}",
    ]
    for p in info_parts:
        print(p)
    print()


def section_header(title, icon=""):
    """Print a styled section header."""
    width = 70
    print()
    print(f"  {C.rgb(255,100,0)}{'━'*width}{C.RST}")
    padding = (width - len(title) - len(icon) - 4) // 2
    print(f"  {C.rgb(255,100,0)}┃{C.RST}{' '*padding}{C.BOLD}{C.BWHITE}{icon} {title}{C.RST}{' '*padding}{C.rgb(255,100,0)}┃{C.RST}")
    print(f"  {C.rgb(255,100,0)}{'━'*width}{C.RST}")
    print()


def subsection(title):
    """Print a subsection header."""
    print(f"\n  {C.BCYAN}{C.BOLD}  [{title}]{C.RST}")
    print(f"  {C.DIM}  {'─'*50}{C.RST}")


def finding(severity, title, detail=""):
    """Print a finding with severity coloring."""
    sev_colors = {
        "CRITICAL": (C.BOLD + C.BWHITE + C.BG_RED, " CRITICAL "),
        "HIGH":     (C.BOLD + C.BRED,               "   HIGH   "),
        "MEDIUM":   (C.BOLD + C.BYELLOW,            "  MEDIUM  "),
        "LOW":      (C.BOLD + C.BGREEN,             "    LOW   "),
        "INFO":     (C.BOLD + C.BCYAN,              "   INFO   "),
    }
    color, label = sev_colors.get(severity, (C.WHITE, severity))
    print(f"    {color}[{label}]{C.RST} {C.BWHITE}{title}{C.RST}")
    if detail:
        for line in detail.split('\n'):
            print(f"    {C.DIM}         ↳ {line}{C.RST}")


def status(icon, message, color=C.BCYAN):
    """Print a status message."""
    print(f"  {color}{C.BOLD}  [{icon}]{C.RST} {message}")


def success(message):
    status("✓", message, C.BGREEN)


def error(message):
    status("✗", message, C.BRED)


def warning(message):
    status("!", message, C.BYELLOW)


def info(message):
    status("*", message, C.BCYAN)


def progress_bar(current, total, width=40, label=""):
    """Display a progress bar."""
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar_fill = "█" * filled
    bar_empty = "░" * (width - filled)

    # Color gradient based on progress
    if pct < 0.3:
        color = C.BRED
    elif pct < 0.7:
        color = C.BYELLOW
    else:
        color = C.BGREEN

    bar = f"{color}{bar_fill}{C.DIM}{bar_empty}{C.RST}"
    pct_str = f"{pct*100:5.1f}%"

    sys.stdout.write(f"\r  {C.DIM}  [{C.RST}{bar}{C.DIM}]{C.RST} {C.BOLD}{pct_str}{C.RST} {C.DIM}{label}{C.RST}")
    sys.stdout.flush()
    if current >= total:
        print()


def print_table(headers, rows, title=""):
    """Print a formatted table."""
    if not rows:
        return

    # Calculate column widths
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    sum(col_widths) + 3 * len(col_widths) + 1

    if title:
        print(f"\n    {C.BOLD}{C.BWHITE}{title}{C.RST}")

    # Header
    header_line = f"    {C.rgb(255,100,0)}┌"
    for w in col_widths:
        header_line += "─" * (w + 2) + "┬"
    header_line = header_line[:-1] + f"┐{C.RST}"
    print(header_line)

    header_row = f"    {C.rgb(255,100,0)}│{C.RST}"
    for i, h in enumerate(headers):
        header_row += f" {C.BOLD}{C.BWHITE}{str(h).ljust(col_widths[i])}{C.RST} {C.rgb(255,100,0)}│{C.RST}"
    print(header_row)

    sep_line = f"    {C.rgb(255,100,0)}├"
    for w in col_widths:
        sep_line += "─" * (w + 2) + "┼"
    sep_line = sep_line[:-1] + f"┤{C.RST}"
    print(sep_line)

    # Rows
    for row in rows:
        row_str = f"    {C.rgb(255,100,0)}│{C.RST}"
        for i, cell in enumerate(row):
            if i < len(col_widths):
                cell_str = str(cell).ljust(col_widths[i])
                # Color critical cells
                if "CRITICAL" in str(cell).upper():
                    cell_str = f"{C.BRED}{C.BOLD}{cell_str}{C.RST}"
                elif "HIGH" in str(cell).upper():
                    cell_str = f"{C.BRED}{cell_str}{C.RST}"
                elif "MEDIUM" in str(cell).upper():
                    cell_str = f"{C.BYELLOW}{cell_str}{C.RST}"
                elif "TRUE" == str(cell).upper() or "YES" == str(cell).upper():
                    cell_str = f"{C.BGREEN}{cell_str}{C.RST}"
                elif "FALSE" == str(cell).upper() or "NO" == str(cell).upper():
                    cell_str = f"{C.BRED}{cell_str}{C.RST}"
                else:
                    cell_str = f"{C.WHITE}{cell_str}{C.RST}"
                row_str += f" {cell_str} {C.rgb(255,100,0)}│{C.RST}"
        print(row_str)

    # Footer
    footer_line = f"    {C.rgb(255,100,0)}└"
    for w in col_widths:
        footer_line += "─" * (w + 2) + "┴"
    footer_line = footer_line[:-1] + f"┘{C.RST}"
    print(footer_line)


def print_summary(stats):
    """Print the final summary with stats."""
    print()
    print(f"  {C.rgb(255,50,0)}{'═'*70}{C.RST}")
    print(f"  {C.rgb(255,50,0)}║{C.RST}  {C.BOLD}{C.BWHITE}SCAN SUMMARY — AdByG0d has spoken.{C.RST}")
    print(f"  {C.rgb(255,50,0)}{'═'*70}{C.RST}")
    print()

    categories = [
        ("CRITICAL", stats.get("critical", 0), C.BOLD + C.BWHITE + C.BG_RED),
        ("HIGH",     stats.get("high", 0),     C.BRED),
        ("MEDIUM",   stats.get("medium", 0),   C.BYELLOW),
        ("LOW",      stats.get("low", 0),      C.BGREEN),
        ("INFO",     stats.get("info", 0),      C.BCYAN),
    ]

    total = sum(c[1] for c in categories)

    for name, count, color in categories:
        bar_len = min(count * 2, 40)
        bar = "█" * bar_len
        print(f"    {color}{name:>10}{C.RST}  {color}{bar}{C.RST} {C.BOLD}{count}{C.RST}")

    print(f"\n    {C.BOLD}{C.BWHITE}Total Findings: {total}{C.RST}")
    print(f"    {C.DIM}Modules Executed: {stats.get('modules', 0)}{C.RST}")
    print(f"    {C.DIM}Scan Duration: {stats.get('duration', 'N/A')}{C.RST}")
    print()

    if stats.get("critical", 0) > 0:
        print(f"    {C.BRED}{C.BOLD}  *** DOMAIN COMPROMISED — CRITICAL FINDINGS DETECTED ***{C.RST}")
    elif stats.get("high", 0) > 0:
        print(f"    {C.BYELLOW}{C.BOLD}  *** HIGH-RISK FINDINGS — DOMAIN AT RISK ***{C.RST}")
    else:
        print(f"    {C.BGREEN}{C.BOLD}  *** DOMAIN APPEARS HARDENED — NICE TRY BLUE TEAM ***{C.RST}")

    print()
    print(f"  {C.rgb(255,50,0)}{'═'*70}{C.RST}")
    print()


def module_header(name, description):
    """Print module execution header."""
    print()
    print(f"  {C.rgb(0,200,255)}╔{'═'*68}╗{C.RST}")
    print(f"  {C.rgb(0,200,255)}║{C.RST}  {C.BOLD}{C.BWHITE} MODULE: {name.upper()}{C.RST}")
    print(f"  {C.rgb(0,200,255)}║{C.RST}  {C.DIM}{description}{C.RST}")
    print(f"  {C.rgb(0,200,255)}╚{'═'*68}╝{C.RST}")
    print()
