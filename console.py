#!/usr/bin/env python3
import sys
import os
import subprocess
import platform

# ─────────────────────────────────────────────────────────────
# Cross-Platform Auto-Venv & Dependency Installation Bootstrap
# ─────────────────────────────────────────────────────────────
def bootstrap():
    # Detect if we are running inside a virtual environment
    is_venv = (
        sys.prefix != sys.base_prefix or 
        hasattr(sys, 'real_prefix') or 
        os.environ.get('VIRTUAL_ENV') is not None
    )
    
    workspace_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(workspace_dir, ".venv")
    
    # Path to virtual environment's python executable
    if platform.system() == "Windows":
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")
        
    if not is_venv:
        # If we are not in a venv, check if .venv exists.
        if not os.path.exists(venv_dir) or not os.path.exists(venv_python):
            print("[*] First-time setup detected. Creating virtual environment (.venv)...")
            try:
                subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
                print("[+] Virtual environment created successfully.")
            except Exception as e:
                print(f"[!] Error creating virtual environment: {e}")
                print("[!] Falling back to system python...")
                return # fallback to system python
                
        # Re-execute this script using the virtual environment's python
        try:
            if platform.system() == "Windows":
                sys.exit(subprocess.call([venv_python] + sys.argv))
            else:
                os.execv(venv_python, [venv_python] + sys.argv)
        except Exception as e:
            print(f"[!] Failed to restart script in virtual environment: {e}")
            print("[!] Falling back to system python...")
            return

    # If we are here, we are running inside the virtual environment!
    # Let's verify and install dependencies if any are missing.
    dependencies = [
        ("flask", "Flask"),
        ("flask_cors", "Flask-Cors"),
        ("requests", "requests"),
        ("phonenumbers", "phonenumbers"),
        ("dns.resolver", "dnspython"),
        ("httpx", "httpx"),
        ("socks", "PySocks"),
        ("cryptography", "cryptography"),
        ("truecallerpy", "truecallerpy"),
        ("holehe", "holehe"),
        ("PyPDF2", "PyPDF2"),
        ("termcolor", "termcolor")
    ]
    
    missing_any = False
    for mod_name, _ in dependencies:
        try:
            __import__(mod_name)
        except ImportError:
            missing_any = True
            break
            
    if missing_any:
        print("[*] Installing required OSINT framework packages...")
        req_file = os.path.join(workspace_dir, "requirements.txt")
        try:
            # Upgrade pip first
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if os.path.exists(req_file):
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], check=True)
            else:
                # Fallback inline install if requirements.txt is missing
                packages = [pkg for _, pkg in dependencies]
                subprocess.run([sys.executable, "-m", "pip", "install"] + packages, check=True)
            print("[+] All dependencies configured successfully!")
        except Exception as e:
            print(f"[!] Error installing dependencies: {e}")
            print("[!] The application might fail to import modules.")

# Run bootstrap before importing other modules.
# Guarded so multiprocessing 'spawn' children (which re-import this module under
# a different name) never re-trigger venv creation / dependency installation.
if __name__ == '__main__':
    bootstrap()

# Standard imports
import cmd
import threading
import time
import webbrowser
import requests
import logging
import re
import uuid
import random
import shutil
from typing import Dict, Tuple, Optional
from termcolor import colored

# Flag to country names mapping
REGIONS_WITH_FLAGS = {
    'IN': 'India 🇮🇳',
    'US': 'United States 🇺🇸',
    'GB': 'United Kingdom 🇬🇧',
    'CA': 'Canada 🇨🇦',
    'AU': 'Australia 🇦🇺',
    'ID': 'Indonesia 🇮🇩',
    'BR': 'Brazil 🇧🇷',
    'DE': 'Germany 🇩🇪',
    'FR': 'France 🇫🇷',
    'JP': 'Japan 🇯🇵',
    'CN': 'China 🇨🇳',
    'RU': 'Russia 🇷🇺',
    'ZA': 'South Africa 🇿🇦',
    'SG': 'Singapore 🇸🇬',
    'NZ': 'New Zealand 🇳🇿',
    'AE': 'United Arab Emirates 🇦🇪',
    'NL': 'Netherlands 🇳🇱',
}

def _ensure_api_path() -> None:
    """Put api/ on sys.path so auth modules can import paths before Flask loads."""
    api_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api")
    if api_path not in sys.path:
        sys.path.insert(0, api_path)


def find_free_port(start_port=5000, max_port=5010):
    import socket
    for port in range(start_port, max_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except socket.error:
            continue
    raise IOError("Could not find a free port in range 5000-5010.")


def ensure_wordlists():
    """Verify rockyou.txt is available and print dictionary status on startup."""
    try:
        from api.wordlists import get_default_wordlist_path, get_wordlist_info
        path = get_default_wordlist_path()
        if not path:
            print(colored("  [!] Dictionary: rockyou.txt NOT FOUND — place it in project root", "red"))
            return
        info = get_wordlist_info(path)
        print(colored(
            f"  Dictionary: {info['name']} ready ({info['line_count']:,} passwords, {info['size_mb']} MB)",
            "green",
        ))
    except Exception as exc:
        print(colored(f"  [!] Dictionary check failed: {exc}", "yellow"))


def poll_crack_job(api_url, status_path, headers=None):
    """Poll a crack job and print live \\r progress. Returns final JSON response."""
    import sys
    hdrs = headers or {}
    while True:
        res = requests.get(f"{api_url}{status_path}", timeout=30, headers=hdrs)
        data = res.json()
        line = data.get('progress_line') or ''
        if line:
            sys.stdout.write('\r' + colored(f"  {line}", "white"))
            sys.stdout.flush()
        status = data.get('status')
        if status in ('success', 'failed', 'error', 'done'):
            sys.stdout.write('\n')
            sys.stdout.flush()
            return data
        time.sleep(0.5)

def get_api_keys():
    try:
        from api.vault import get_identity_keys
        keys = get_identity_keys()
        return {
            'vt': keys.get('VT_API_KEY', ''),
            'abuse': keys.get('ABUSE_IPDB_KEY', ''),
            'truecaller': keys.get('TRUECALLER_ID', '')
        }
    except Exception:
        return {'vt': '', 'abuse': '', 'truecaller': ''}

def check_key_status(k_name, key_val, is_tc=False):
    if not key_val:
        return '⚠ NOT CONFIGURED', f"To set: keys set {k_name.lower().replace('_api_key','').replace('_installation_id','truecaller')}"
    key_str = str(key_val).strip()
    if is_tc:
        if len(key_str) > 5:
            return '✓ CONFIGURED', ''
        return '⚠ NOT CONFIGURED', 'To set: keys set truecaller <installation_id>'
    return '✓ CONFIGURED', ''

def get_api_details_for_command(cmd_name):
    keys = get_api_keys()

    if cmd_name == 'ip':
        vt_status, vt_setup = check_key_status('VIRUSTOTAL_API_KEY', keys['vt'])
        abuse_status, abuse_setup = check_key_status('ABUSEIPDB_API_KEY', keys['abuse'])
        return [
            {'name': 'VirusTotal API', 'status': vt_status, 'limit': '4 req/min, 500 req/day', 'setup': vt_setup},
            {'name': 'AbuseIPDB API', 'status': abuse_status, 'limit': '1000 checks/day', 'setup': abuse_setup},
            {'name': 'ipwho.is Geolocator', 'status': '✓ FREE / NATIVE', 'limit': '10,000 req/month', 'setup': ''}
        ]
    elif cmd_name == 'phone':
        tc_status, tc_setup = check_key_status('TRUECALLER_INSTALLATION_ID', keys['truecaller'], is_tc=True)
        return [
            {'name': 'Truecaller Trace', 'status': tc_status, 'limit': '500 req/day', 'setup': tc_setup},
            {'name': 'Phonenumbers Geocoder', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    elif cmd_name == 'username':
        return [
            {'name': 'WhatsMyName Deep Scan', 'status': '✓ FREE / NATIVE', 'limit': '600+ sites (wmn-data.json)', 'setup': ''}
        ]
    elif cmd_name == 'email':
        return [
            {'name': 'Holehe Passive Recovery', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited checks', 'setup': ''},
            {'name': 'Supplementary Probes', 'status': '✓ FREE / NATIVE', 'limit': 'Komoot · Polarsteps · Letterboxd · GitHub · Eventbrite', 'setup': ''},
        ]
    elif cmd_name == 'infostealer':
        return [
            {'name': 'Hudson Rock Infostealer Intel', 'status': '✓ FREE / NATIVE', 'limit': 'Public API — no key', 'setup': ''},
        ]
    elif cmd_name == 'breach':
        return [
            {'name': 'XposedOrNot Leaks', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited / Public API', 'setup': ''}
        ]
    elif cmd_name == 'portscan':
        return [
            {'name': 'Local Port Scanner', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    elif cmd_name == 'subdomain':
        return [
            {'name': 'crt.sh CT Logs', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited public API', 'setup': ''}
        ]
    elif cmd_name == 'netscan':
        return [
            {'name': 'ICMP network scanner', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    elif cmd_name == 'hashcrack':
        return [
            {'name': 'Offline Hash Cracker', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    elif cmd_name == 'pdfprotect':
        return [
            {'name': 'Offline PDF Cryptography', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    elif cmd_name == 'pdfcrack':
        return [
            {'name': 'Offline PDF Crack', 'status': '✓ FREE / NATIVE', 'limit': 'Unlimited offline', 'setup': ''}
        ]
    return []

def print_feature_header(title, description, api_details=None):
    print(colored("╔" + "═" * 78 + "╗", "yellow"))
    print(colored(f"║ {title.upper().ljust(76)} ║", "yellow", attrs=["bold"]))
    print(colored(f"║ {description.ljust(76)} ║", "white"))
    if api_details:
        print(colored("╠" + "═" * 78 + "╣", "yellow"))
        for detail in api_details:
            name = detail.get('name', 'API')
            status = detail.get('status', '⚠ NOT CONFIGURED')
            limit = detail.get('limit', 'N/A')
            setup = detail.get('setup', '')
            
            # Format status color
            if "✓" in status:
                status_colored = colored(status, "green", attrs=["bold"])
            elif "DEMO" in status:
                status_colored = colored(status, "yellow", attrs=["bold"])
            else:
                status_colored = colored(status, "red", attrs=["bold"])
            
            raw_line = f"║   • {name}: {status} | Quota: {limit}"
            # Check printable characters width to pad correctly
            pad = 76 - len(f"  • {name}: {status} | Quota: {limit}")
            if pad < 0: pad = 0
            print(colored("║", "yellow") + f"  • {name}: " + status_colored + f" | Quota: {limit}" + " " * pad + colored("║", "yellow"))
            
            if setup:
                setup_pad = 76 - len(f"    └─ {setup}")
                if setup_pad < 0: setup_pad = 0
                print(colored("║", "yellow") + colored(f"    └─ {setup}", "yellow") + " " * setup_pad + colored("║", "yellow"))
    print(colored("╚" + "═" * 78 + "╝", "yellow"))

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def pad_colored_string(text, width, alignment='left'):
    visual_len = len(strip_ansi(text))
    padding = width - visual_len
    if padding <= 0:
        return text
    if alignment == 'left':
        return text + " " * padding
    elif alignment == 'right':
        return " " * padding + text
    else:
        left_pad = padding // 2
        right_pad = padding - left_pad
        return " " * left_pad + text + " " * right_pad

# ── Box-drawing result table helpers ──────────────────────────
# Total line width = _BW + 4 = 60 chars (including 2-char indent)
_BW = 56

def _box_top(title):
    fill = max(0, _BW - 3 - len(title))
    return colored(f"  ┌─ {title} {'─' * fill}┐", "yellow")

def _box_row(key, value, key_w=14, val_color="white"):
    val_str = str(value)
    max_val = _BW - 1 - key_w - 2
    stripped = strip_ansi(val_str)
    if len(stripped) > max_val:
        val_str = stripped[:max_val - 1] + "…"
        stripped = val_str
    pad = max(0, _BW - 1 - key_w - 2 - len(stripped))
    return (colored("  │", "yellow") +
            colored(f" {key:<{key_w}}", "white") +
            "  " +
            colored(val_str, val_color) +
            " " * pad +
            colored("│", "yellow"))

def _box_hint(text):
    stripped = strip_ansi(text)
    pad = max(0, _BW - 4 - len(stripped))
    return (colored("  │", "yellow") +
            "    " +
            colored(stripped, "yellow") +
            " " * pad +
            colored("│", "yellow"))

def _box_section(label):
    fill = max(0, _BW - 3 - len(label))
    return (colored("  ├─", "yellow") +
            colored(f" {label} ", "yellow", attrs=["bold"]) +
            colored("─" * fill + "┤", "yellow"))

def _box_bot():
    return colored(f"  └{'─' * _BW}┘", "yellow")

# ── Premium CLI theme ─────────────────────────────────────────
UI_W = 70

# ANSI Shadow block-letter title — single colored() call, no gradient
ARGUS_BANNER = (
    " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗\n"
    "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝\n"
    "███████║██████╔╝██║  ███╗██║   ██║███████╗\n"
    "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║\n"
    "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║\n"
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
)

# Premium howling wolf portrait — 17 lines, U+25CF/U+25CB bead-pattern style (green slot)
_PORTRAIT_RAW = [
    "                  ●  ● ",
    " ○  ○ ○  ○         ○ ● ",
    "    ● ○  ● ●●    ●   ● ",
    "    ○   ●     ● ●      ",
    "       ●○  ● ●●    ●  ●",
    "    ● ●       ●   ○    ",
    "      ●                ",
    "   ○●      ●●        ●○",
    " ○  ○ ●    ○  ○ ○      ",
    " ● ○● ● ●●      ○ ●  ● ",
    "    ○    ● ●     ●     ",
    " ●●○       ●           ",
    " ●●                   ○",
    "             ○         ",
    "    ●●  ○  ○          ○",
    "    ●                  ",
    "    ●                  ",
]

_BANNER_INNER_W = 79
_BANNER_TITLE_DELAY: Tuple[float, float] = (0.002, 0.005)
_BANNER_LINE_DELAY: Tuple[float, float] = (0.003, 0.010)
_PRELUDE_CHAR_DELAY: Tuple[float, float] = (0.006, 0.018)
_PORTRAIT_STAGGER_S = 0.020
_ANALYST_READY_LINE = "  (🐺)  analyst session ready"
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")

_CMD_VERBS: Dict[str, str] = {
    "ip": "scanning target",
    "phone": "tracing number",
    "username": "deep footprinting handle",
    "email": "probing email",
    "breach": "checking breaches",
    "infostealer": "querying infostealer intel",
    "portscan": "scanning ports",
    "netscan": "discovering hosts",
    "subdomain": "enumerating subdomains",
    "deepuser": "deep username scan",
    "emailgoogle": "google profile probe",
    "emailsmtp": "smtp validation",
    "portscan-async": "async port scan",
    "maclookup": "mac vendor lookup",
    "dork": "building dork URLs",
    "hashcrack": "cracking hash",
    "pdfprotect": "encrypting pdf",
    "pdfcrack": "recovering pdf password",
    "tor": "configuring tor route",
}

def _banner_row(left_text, right_art_line, inner_w=_BANNER_INNER_W):
    """Bordered box row: left metadata + auto-gap + right portrait, properly aligned."""
    left_vis = len(strip_ansi(left_text))
    right_vis = len(strip_ansi(right_art_line))
    gap = inner_w - left_vis - right_vis
    if gap < 1:
        gap = 1
    return colored('│', 'yellow') + left_text + ' ' * gap + right_art_line + colored('│', 'yellow')

def ui_rule(color="yellow"):
    print(colored("─" * UI_W, color))

def ui_title(text, color="yellow"):
    print(colored(f"  {text}", color, attrs=["bold"]))

def ui_hint(text):
    print(colored(f"  {text}", "white"))


# ── Startup animation (typewriter prelude) ───────────────────────
_PRELUDE_LINES: Tuple[Tuple[str, bool, bool], ...] = (
    # (message, use_dot_progress, show_ok_pop)
    ("Initializing secure intelligence kernel...", False, False),
    ("Loading recon modules", True, True),
    ("Verifying chain-of-custody engine", False, True),
    ("Establishing analyst session...", False, False),
)


def animation_disabled() -> bool:
    """True when startup typewriter animation should be skipped."""
    flag = os.environ.get("ARGUS_NO_ANIMATION", "").strip().lower()
    if flag in ("1", "true", "yes"):
        return True
    return "--no-animation" in sys.argv


def _blink_cursor(blinks: int = 2, on_ms: float = 0.10) -> None:
    """Brief blinking underscore cursor at end of a typed line."""
    for _ in range(blinks):
        sys.stdout.write(colored("_", "white"))
        sys.stdout.flush()
        time.sleep(on_ms)
        sys.stdout.write("\b \b")
        sys.stdout.flush()
        time.sleep(on_ms * 0.45)


def _pop_ok() -> None:
    """Green [OK] pop-in with a short pause."""
    time.sleep(0.12)
    sys.stdout.write(colored(" [OK]", "green", attrs=["bold"]))
    sys.stdout.flush()
    time.sleep(0.10)


def _write_argus_prefix() -> None:
    sys.stdout.write(colored("[ARGUS] ", "yellow", attrs=["bold"]))
    sys.stdout.flush()


def _type_plain_colored(text: str, color: str = "white", delay: Tuple[float, float] = _PRELUDE_CHAR_DELAY) -> None:
    for ch in text:
        sys.stdout.write(colored(ch, color))
        sys.stdout.flush()
        time.sleep(random.uniform(*delay))


def _type_prelude_line(message: str, use_dots: bool = False, show_ok: bool = False) -> None:
    """Type one prelude line with cursor blink, dot progress, and optional [OK]."""
    _write_argus_prefix()
    text = message.rstrip(".")
    _type_plain_colored(text if use_dots else message)
    if use_dots:
        for _ in range(3):
            time.sleep(0.07)
            sys.stdout.write(colored(".", "white"))
            sys.stdout.flush()
    if show_ok:
        _pop_ok()
    else:
        _blink_cursor(2 if not use_dots else 1)
    sys.stdout.write("\n")
    sys.stdout.flush()


def run_startup_animation() -> None:
    """Cinematic typewriter prelude — skipped when animation_disabled()."""
    if animation_disabled():
        return
    print()
    for message, use_dots, show_ok in _PRELUDE_LINES:
        _type_prelude_line(message, use_dots=use_dots, show_ok=show_ok)
    print()


def _type_colored_line(body: str, suffix: str = "") -> None:
    """Legacy helper — delegates to enhanced prelude typing."""
    _write_argus_prefix()
    _type_plain_colored(body)
    if suffix.strip() == "OK":
        _pop_ok()
    elif suffix:
        sys.stdout.write(colored(suffix, "green", attrs=["bold"]))
        sys.stdout.flush()
    else:
        _blink_cursor(2)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _type_ansi_line(
    line: str,
    delay_range: Tuple[float, float] = _BANNER_LINE_DELAY,
    newline: bool = True,
) -> None:
    """Type a fully formatted ANSI line char-by-char (escapes emit instantly)."""
    i = 0
    while i < len(line):
        if line[i] == "\x1b":
            m = _ANSI_ESCAPE_RE.match(line, i)
            if m:
                sys.stdout.write(m.group(0))
                sys.stdout.flush()
                i = m.end()
                continue
        sys.stdout.write(line[i])
        sys.stdout.flush()
        time.sleep(random.uniform(*delay_range))
        i += 1
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _emit_line(line: str, animate: bool, delay_range: Tuple[float, float] = _BANNER_LINE_DELAY) -> None:
    """Print instantly or typewriter-animate a single banner line."""
    if animate:
        _type_ansi_line(line, delay_range=delay_range)
    else:
        print(line)


def _emit_banner_block(title: str, animate: bool) -> None:
    """Type the big ARGUS ASCII title line-by-line in yellow bold."""
    for raw_line in title.split("\n"):
        colored_line = colored(raw_line, "yellow", attrs=["bold"])
        _emit_line(colored_line, animate, delay_range=_BANNER_TITLE_DELAY)


def _emit_analyst_ready(animate: bool) -> None:
    """Cute post-banner analyst-ready line (ASCII, no emoji)."""
    line = colored(_ANALYST_READY_LINE, "green")
    if animate:
        _emit_line(line, True, delay_range=(0.003, 0.009))
    else:
        print(line)


def _animate_launch_message(cmd_name: str) -> None:
    """Brief typed confirmation when user picks a tool by number."""
    if animation_disabled():
        return
    msg = f"  ▸ launching {cmd_name}..."
    for ch in msg:
        color = "yellow" if ch in "▸" else "white"
        sys.stdout.write(colored(ch, color, attrs=["bold"] if ch == "▸" else []))
        sys.stdout.flush()
        time.sleep(random.uniform(0.004, 0.012))
    sys.stdout.write("\n")
    sys.stdout.flush()
    time.sleep(0.20)


def _animate_cmd_prefix(verb: str) -> None:
    """One-line [ARGUS] prefix before a command module banner."""
    if animation_disabled():
        return
    _write_argus_prefix()
    _type_plain_colored(f" {verb}...", "white", delay=(0.004, 0.011))
    _blink_cursor(1, on_ms=0.08)
    sys.stdout.write("\n")
    sys.stdout.flush()


def run_interactive_setup() -> None:
    """First-run wizard: create the first investigator profile (no password)."""
    _ensure_api_path()
    from auth import create_admin_profile, has_profiles
    from paths import ensure_data_dirs

    ensure_data_dirs()
    if has_profiles():
        return

    if not sys.stdin.isatty():
        print(colored("[!] No investigator profiles configured.", "red", attrs=["bold"]))
        print(colored("    Run interactively once to create your first profile:", "yellow"))
        print(colored("    python3 console.py", "white"))
        sys.exit(1)

    print()
    print(colored("  ╔" + "═" * 54 + "╗", "yellow"))
    print(colored("  ║  ARGUS — Initial Configuration                    ║", "yellow", attrs=["bold"]))
    print(colored("  ║  Create your first investigator profile           ║", "white"))
    print(colored("  ╚" + "═" * 54 + "╝", "yellow"))
    print()

    try:
        while True:
            display_name = input(colored("  Display name › ", "yellow")).strip()
            if len(display_name) >= 2:
                break
            print(colored("  [!] Enter at least 2 characters.", "red"))

        create_admin_profile(display_name)
        print(colored(f"\n  ✓ Profile saved for '{display_name}' (admin). Starting ARGUS.\n", "green"))
    except (KeyboardInterrupt, EOFError):
        print(colored("\n  Setup cancelled — no profile written.", "yellow"))
        sys.exit(0)
    except ValueError as exc:
        print(colored(f"  ✗ {exc}", "red"))
        sys.exit(1)


def ensure_first_run_setup() -> None:
    """Run interactive setup when no investigator profiles exist."""
    _ensure_api_path()
    from auth import has_profiles
    from paths import ensure_data_dirs

    ensure_data_dirs()
    if has_profiles():
        return
    run_interactive_setup()


class LEAConsole(cmd.Cmd):
    intro = ''
    prompt = colored('  argus › ', 'yellow', attrs=['bold'])

    def __init__(self, port):
        super().__init__()
        self.port = port
        self._suppress_header = False
        self.session_id = time.strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:6]
        self.api_url = f'http://127.0.0.1:{port}/api'
        self.cli_profile = None
        self.active_case_id = None
        self.case_mode_enabled = False
        self.truecaller_phone_enabled = None
        self._fresh_profile = False
        self._start_server()
        if animation_disabled():
            print(colored(f"  Initializing ARGUS intelligence API on port {port}...", "white"))
        else:
            run_startup_animation()
        self._wait_for_api()
        self._bootstrap_lea()
        ensure_wordlists()
        self._prompt_case_mode()
        self.show_welcome_banner()
        # Auto-render the full numbered tool menu on startup so the user never
        # has to type /menu or /help to discover the available tools.
        self.do_menu('')

        if self._fresh_profile:
            print(colored(
                "  New to ARGUS? Type guide or /help for full reference.",
                "green",
            ))
            print()

    def _api_headers(self, json_body=False):
        hdrs = {'X-Interface': 'CLI'}
        if self.cli_profile:
            hdrs['X-Profile-Id'] = self.cli_profile.get('id', '')
            hdrs['X-Profile-Name'] = self.cli_profile.get('display_name', '')
        if self.case_mode_enabled:
            hdrs['X-Case-Mode'] = 'on'
            if self.active_case_id:
                hdrs['X-Case-Id'] = self.active_case_id
        else:
            hdrs['X-Case-Mode'] = 'off'
        if json_body:
            hdrs['Content-Type'] = 'application/json'
        return hdrs

    def _api_get(self, path, params=None, timeout=60, **kwargs):
        hdrs = self._api_headers()
        hdrs.update(kwargs.pop('headers', {}))
        return requests.get(
            f"{self.api_url}{path}",
            params=params,
            timeout=timeout,
            headers=hdrs,
            **kwargs,
        )

    def _api_post(self, path, json_body=None, data=None, files=None, timeout=120, **kwargs):
        hdrs = self._api_headers(json_body=json_body is not None and not files)
        hdrs.update(kwargs.pop('headers', {}))
        return requests.post(
            f"{self.api_url}{path}",
            json=json_body,
            data=data,
            files=files,
            timeout=timeout,
            headers=hdrs,
            **kwargs,
        )

    def _api_patch(self, path, json_body=None, timeout=30, **kwargs):
        hdrs = self._api_headers(json_body=json_body is not None)
        hdrs.update(kwargs.pop('headers', {}))
        return requests.patch(
            f"{self.api_url}{path}",
            json=json_body,
            timeout=timeout,
            headers=hdrs,
            **kwargs,
        )

    def _wait_for_api(self, timeout: float = 10.0) -> None:
        """Poll /api/health until the background Flask thread is ready."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                res = requests.get(f"{self.api_url}/health", timeout=1)
                if res.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(0.12)

    def _bootstrap_lea(self):
        """LEA acknowledgment and investigator profile selection."""
        try:
            from api.auth import get_or_create_secret_key, is_lea_acknowledged, acknowledge_lea
            get_or_create_secret_key()
        except Exception as exc:
            print(colored(f"  [!] Auth bootstrap warning: {exc}", "yellow"))
            return

        # LEA authorization notice
        print(colored("  ╔" + "═" * 66 + "╗", "red"))
        print(colored("  ║  LEA AUTHORIZATION NOTICE — AUTHORIZED USE ONLY              ║", "red", attrs=["bold"]))
        print(colored("  ║  ARGUS is restricted to sworn law enforcement personnel      ║", "white"))
        print(colored("  ║  acting under valid warrant, court order, or statutory       ║", "white"))
        print(colored("  ║  authority. Unauthorized access is prohibited.               ║", "white"))
        print(colored("  ╚" + "═" * 66 + "╝", "red"))
        try:
            if not is_lea_acknowledged():
                ans = input(colored("  Acknowledge and continue? [yes/NO]: ", "yellow")).strip().lower()
                if ans not in ('yes', 'y'):
                    print(colored("  Session aborted — acknowledgment required.", "red"))
                    sys.exit(1)
                acknowledge_lea('cli', 'CLI')
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

        try:
            health = requests.get(f"{self.api_url}/health", timeout=5).json()
            if not health.get('auth_enabled', True):
                return
        except Exception:
            pass

        self._select_cli_profile()

    def _select_cli_profile(self) -> None:
        """Pick or create an investigator profile for this CLI session."""
        env_name = os.environ.get('ARGUS_PROFILE', '').strip()
        env_id = os.environ.get('ARGUS_PROFILE_ID', '').strip()

        try:
            r = requests.get(f"{self.api_url}/auth/profiles", timeout=5)
            profiles = r.json().get('profiles', []) if r.status_code == 200 else []
        except Exception:
            profiles = []

        if not sys.stdin.isatty():
            picked = None
            if env_id:
                picked = next((p for p in profiles if p.get('id') == env_id), None)
            elif env_name:
                picked = next(
                    (p for p in profiles if p.get('display_name', '').lower() == env_name.lower()),
                    None,
                )
            elif profiles:
                picked = profiles[0]
            if picked:
                self.cli_profile = picked
                return
            print(colored("  [!] No profile selected (set ARGUS_PROFILE or run interactively).", "red"))
            sys.exit(1)

        if env_id or env_name:
            picked = None
            if env_id:
                picked = next((p for p in profiles if p.get('id') == env_id), None)
            elif env_name:
                picked = next(
                    (p for p in profiles if p.get('display_name', '').lower() == env_name.lower()),
                    None,
                )
            if picked:
                self.cli_profile = picked
                print(colored(f"  ✓ Profile: {picked.get('display_name')} ({picked.get('role')})", "green"))
                return

        print()
        print(colored("  Investigator profile", "yellow", attrs=["bold"]))
        print(colored("  1) Use existing profile", "white"))
        print(colored("  2) Create new profile", "white"))
        try:
            choice = input(colored("  Choose [1/2]: ", "yellow")).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

        if choice == '2':
            self._create_cli_profile_interactive()
            return

        if not profiles:
            print(colored("  No profiles yet — creating one now.", "yellow"))
            self._create_cli_profile_interactive()
            return

        print()
        for idx, profile in enumerate(profiles, start=1):
            print(colored(
                f"  {idx}) {profile.get('display_name')} ({profile.get('role', 'investigator')})",
                "white",
            ))
        try:
            pick = input(colored("  Select profile number: ", "yellow")).strip()
            sel = int(pick)
            if sel < 1 or sel > len(profiles):
                raise ValueError("out of range")
            self.cli_profile = profiles[sel - 1]
            self._fresh_profile = True
            print(colored(
                f"  ✓ Profile: {self.cli_profile.get('display_name')} ({self.cli_profile.get('role')})",
                "green",
            ))
        except (ValueError, KeyboardInterrupt, EOFError):
            print(colored("  ✗ Invalid selection.", "red"))
            sys.exit(1)

    def _create_cli_profile_interactive(self) -> None:
        """Create a new investigator profile from the CLI picker."""
        try:
            display_name = input(colored("  Display name › ", "yellow")).strip()
            if len(display_name) < 2:
                print(colored("  ✗ Display name must be at least 2 characters.", "red"))
                sys.exit(1)
            r = requests.post(
                f"{self.api_url}/auth/profiles",
                json={'display_name': display_name, 'role': 'investigator'},
                timeout=10,
            )
            if r.status_code not in (200, 201):
                print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                sys.exit(1)
            profile = r.json().get('profile', {})
            self.cli_profile = profile
            self._fresh_profile = True
            print(colored(
                f"  ✓ Profile created: {profile.get('display_name')} ({profile.get('role')})",
                "green",
            ))
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

    def _case_banner_text(self) -> str:
        if not self.case_mode_enabled:
            return 'disabled (ad-hoc mode)'
        return self.active_case_id or 'none — use: case new'

    def _prompt_case_mode(self) -> None:
        """Ask once per session whether to enable investigation case mode."""
        env_force = os.environ.get('ARGUS_CASE_MODE', '').strip().lower() in ('1', 'true', 'yes')
        if not sys.stdin.isatty():
            if env_force:
                self.case_mode_enabled = True
                self._enable_case_mode_interactive()
            else:
                self.case_mode_enabled = False
                self.active_case_id = None
            return

        print()
        print(colored("  Active Investigation Case mode?", "yellow", attrs=["bold"]))
        print(colored("  (yes) — log all actions to a case file; export evidence later", "white"))
        print(colored("  (no)  — use all tools freely; no case file created", "white"))
        print()
        try:
            ans = input(colored("  Enable case mode? [y/N] › ", "yellow")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

        if ans in ('y', 'yes'):
            self.case_mode_enabled = True
            self._enable_case_mode_interactive()
        else:
            self.case_mode_enabled = False
            self.active_case_id = None
            print(colored("  Case mode disabled — ad-hoc session (all tools available).", "white"))
            print()

    def _enable_case_mode_interactive(self) -> None:
        """Walk through case creation or opening an existing case."""
        try:
            r = self._api_get("/cases")
            open_cases = [
                c for c in r.json().get('cases', [])
                if c.get('status') == 'open'
            ] if r.status_code == 200 else []
        except Exception:
            open_cases = []

        if open_cases:
            print()
            print(colored("  1) Create new case", "white"))
            print(colored("  2) Open existing case", "white"))
            try:
                choice = input(colored("  Choose [1/2]: ", "yellow")).strip()
            except (KeyboardInterrupt, EOFError):
                print()
                sys.exit(0)
            if choice == '2':
                self._open_existing_case(open_cases)
                return

        self._create_new_case_interactive()

    def _create_new_case_interactive(self) -> None:
        username = (self.cli_profile or {}).get('display_name', 'investigator')
        try:
            title = input(colored("  Case title: ", "yellow")).strip()
            if not title:
                print(colored("  ✗ Title required.", "red"))
                self.case_mode_enabled = False
                self.active_case_id = None
                return
            lead = input(colored(f"  Lead investigator [{username}]: ", "yellow")).strip() or username
            auth_ref = input(colored("  Authorization ref (warrant/court order): ", "yellow")).strip()
            legal = input(colored("  Legal basis (optional): ", "yellow")).strip()
            notes = input(colored("  Notes (optional): ", "yellow")).strip()
            r = self._api_post("/cases", json_body={
                'title': title,
                'lead_investigator': lead,
                'authorization_ref': auth_ref,
                'legal_basis': legal,
                'notes': notes,
            })
            if r.status_code in (200, 201):
                case = r.json().get('case', {})
                self.active_case_id = case.get('case_id')
                self.case_mode_enabled = True
                self._api_post(f"/cases/{self.active_case_id}/activate")
                print(colored(f"  ✓ Case mode enabled: {self.active_case_id}", "green"))
            else:
                print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                self.case_mode_enabled = False
                self.active_case_id = None
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
        except Exception as exc:
            print(colored(f"  ✗ {exc}", "red"))
            self.case_mode_enabled = False
            self.active_case_id = None

    def _open_existing_case(self, cases=None) -> None:
        if cases is None:
            try:
                r = self._api_get("/cases")
                cases = [
                    c for c in r.json().get('cases', [])
                    if c.get('status') == 'open'
                ] if r.status_code == 200 else []
            except Exception:
                cases = []
        if not cases:
            print(colored("  No open cases. Creating new case.", "yellow"))
            self._create_new_case_interactive()
            return
        print(_box_top("OPEN CASES"))
        for c in cases:
            print(_box_row(c.get('case_id', ''), c.get('title', '')))
        print(_box_bot())
        try:
            pick = input(colored("  Case ID to open: ", "yellow")).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
        if not pick:
            self.case_mode_enabled = False
            self.active_case_id = None
            return
        try:
            r = self._api_post(f"/cases/{pick}/activate")
            if r.status_code == 200:
                self.active_case_id = pick
                self.case_mode_enabled = True
                print(colored(f"  ✓ Case mode enabled: {pick}", "green"))
            else:
                print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                self.case_mode_enabled = False
                self.active_case_id = None
        except Exception as exc:
            print(colored(f"  ✗ {exc}", "red"))
            self.case_mode_enabled = False
            self.active_case_id = None

    def _ensure_case_mode_enabled(self, action_desc: str = "continue") -> bool:
        if self.case_mode_enabled:
            return True
        try:
            ans = input(
                colored(f"  Enable case mode and {action_desc}? [y/N] › ", "yellow")
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return False
        if ans not in ('y', 'yes'):
            print(colored("  Case mode remains disabled.", "yellow"))
            return False
        self.case_mode_enabled = True
        return True

    def _start_server(self):
        from api.app import app
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        try:
            import flask.cli
            flask.cli.show_server_banner = lambda *args: None
        except Exception:
            pass

        t = threading.Thread(target=app.run, kwargs={'host': '127.0.0.1', 'port': self.port, 'use_reloader': False})
        t.daemon = True
        t.start()

    def show_welcome_banner(self):
        try:
            from api.wordlists import wordlist_summary
            wl = wordlist_summary()
            if wl['available']:
                entries = wl['entries']
                if entries >= 1_000_000:
                    count = f"{entries / 1_000_000:.1f}M"
                elif entries >= 1_000:
                    count = f"{entries / 1_000:.0f}K"
                else:
                    count = str(entries)
                dict_val = f"{wl['name']} ({count} entries)"
            else:
                dict_val = "not available"
        except Exception:
            dict_val = "not available"

        animate = not animation_disabled()

        # Build portrait: equal visual width per line so the right border stays straight
        _portrait_stripped = [ln.rstrip() for ln in _PORTRAIT_RAW]
        _pw = max(len(strip_ansi(ln)) for ln in _portrait_stripped)
        portrait = [
            colored(pad_colored_string(ln, _pw, 'left'), 'green')
            for ln in _portrait_stripped
        ]

        def _art(i: int) -> str:
            return portrait[i] if i < len(portrait) else colored(' ' * _pw, 'green')

        def _lbl(text: str) -> str:
            return colored(text, 'red', attrs=['bold'])

        def _val(text: str) -> str:
            return colored(text, 'white')

        top_border = colored('╭' + '─' * _BANNER_INNER_W + '╮', 'yellow')
        bot_border = colored('╰' + '─' * _BANNER_INNER_W + '╯', 'yellow')

        meta_rows = [
            '',
            '  ' + colored('ARGUS Intelligence Platform', 'yellow', attrs=['bold']),
            '  ' + colored('─' * 50, 'yellow'),
            '  ' + _lbl('Session') + '  ' + _val('interactive CLI'),
            '  ' + _lbl('Version') + '  ' + _val('v3.1.0 · LEA Edition'),
            '  ' + _lbl('Dict   ') + '  ' + _val(dict_val),
            '  ' + _lbl('Port   ') + '  ' + _val(str(self.port)),
            '  ' + _lbl('Audit  ') + '  ' + _val('ENABLED · audit.log'),
            '  ' + _lbl('Case   ') + '  ' + _val(self._case_banner_text()),
            '  ' + _lbl('WebUI  ') + '  ' + _val(f'http://127.0.0.1:{self.port}'),
        ]

        _tool_count = len(self.FEATURES)
        _module_count = len({f['module'] for f in self.FEATURES})
        footer_left = '  ' + colored(
            f'argus: LEA Core  \u2502  {_tool_count} tools \u00b7 {_module_count} modules \u00b7 /help',
            'yellow',
        )
        last_idx = max(len(meta_rows), len(portrait) - 1)

        box_lines = [top_border]
        for i, left in enumerate(meta_rows):
            box_lines.append(_banner_row(left, _art(i)))
        for j in range(len(meta_rows), len(portrait) - 1):
            box_lines.append(_banner_row('', _art(j)))
        box_lines.append(_banner_row(footer_left, _art(last_idx)))
        box_lines.append(bot_border)

        sid = self.session_id[:16]
        proj = os.path.dirname(os.path.abspath(__file__))
        session_line = colored(f"  Session: {sid} · {proj}", 'white')
        subtitle = colored("  · Advanced Intelligence Platform · LEA Edition", 'white')

        print()
        _emit_banner_block(ARGUS_BANNER, animate)
        _emit_line(subtitle, animate)
        print()

        portrait_row_count = len(portrait)
        for idx, line in enumerate(box_lines):
            _emit_line(line, animate)
            if animate and 0 < idx < len(box_lines) - 1:
                time.sleep(_PORTRAIT_STAGGER_S)

        _emit_line(session_line, animate)
        _emit_analyst_ready(animate)
        print()

    def precmd(self, line):
        """Normalize slash commands (/help) and short aliases (q, h, ?)."""
        s = line.strip()
        if s.startswith('/'):
            s = s[1:].strip()
        if not s:
            return s
        aliases = {
            '?': 'help', 'h': 'help',
            'q': 'exit', 'quit': 'exit',
            'ls': 'menu', 'list': 'menu',
            'cls': 'clear',
        }
        parts = s.split(None, 1)
        first = parts[0].lower()
        if first in aliases:
            s = aliases[first] + (f" {parts[1]}" if len(parts) > 1 else '')
        return s

    def emptyline(self):
        """Do not repeat the last command on blank Enter."""
        pass

    def _feature_by_cmd(self, token):
        """Return the FEATURES entry whose command matches *token* (or None)."""
        token = (token or '').strip().lower()
        return next((f for f in self.FEATURES if f['cmd'] == token), None)

    def _dispatch_feature(self, feat, arg):
        """Invoke the do_* handler for a feature (handles hyphenated names)."""
        method = getattr(self, 'do_' + feat['cmd'].replace('-', '_'), None)
        if method:
            return method(arg)
        return self.default(f"{feat['cmd']} {arg}".strip())

    def onecmd(self, line):
        """Unified launcher.

        A bare command name (e.g. ``ip``) or number is handled elsewhere; here we
        ensure that any FEATURES command — including new/hyphenated ones such as
        ``portscan-async`` — dispatches correctly with arguments, and launches an
        interactive wizard when invoked with no arguments. All non-feature
        commands fall through to the standard cmd.Cmd handling.
        """
        s = (line or '').strip()
        if not s:
            return self.emptyline()

        parts = s.split(None, 1)
        token = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ''

        feat = self._feature_by_cmd(token)
        if feat:
            is_first = True
            while True:
                if is_first and arg:
                    res = self._dispatch_feature(feat, arg)
                else:
                    self.show_feature_usage_card(feat)
                    self.run_interactive_wizard(feat['cmd'])
                    res = False
                
                is_first = False
                
                try:
                    ans = input(colored(f"\n  Do you want to reuse the {feat['label']} or see the menu? [y: reuse / n: menu] › ", "yellow")).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    ans = "n"
                
                if ans in ("y", "yes"):
                    arg = "" # Clear argument for subsequent runs to trigger interactive prompt
                    continue
                else:
                    break
            print()
            self.do_menu('')
            return res

        return super().onecmd(line)

    def _cmd_banner(self, cmd_name):
        """One-line module label when running a command directly."""
        if self._suppress_header:
            return
        feat = next((f for f in self.FEATURES if f['cmd'] == cmd_name), None)
        if feat:
            verb = _CMD_VERBS.get(cmd_name, "running module")
            _animate_cmd_prefix(verb)
            print(colored(f"\n  ▸ {feat['label']}", "yellow", attrs=["bold"]))

    def _run_quiet(self, func, *args):
        """Run a do_* handler without duplicate module banners."""
        self._suppress_header = True
        try:
            return func(*args)
        finally:
            self._suppress_header = False

    def do_help(self, arg):
        """Displays structured help index. Usage: help [command]  |  /help"""
        if arg:
            try:
                func = getattr(self, f"help_{arg}")
                func()
            except AttributeError:
                cmd_func = getattr(self, f"do_{arg}", None)
                if cmd_func and cmd_func.__doc__:
                    print(colored(f"\n  {arg}", "yellow", attrs=["bold"]))
                    for line in cmd_func.__doc__.strip().splitlines():
                        print(colored(f"  {line.strip()}", "white"))
                    print()
                else:
                    print(colored(f"  No help for '{arg}'. Try /menu or /help.", "red"))
            return

        print()
        ui_title("ARGUS — COMMAND REFERENCE")
        ui_hint("Slash syntax supported: /help  /menu  /exit  /clear  /ip 8.8.8.8")
        print()

        sections = [
            ("Identity Intelligence", [
                ("ip",        "ip <address>",       "Geodata, ISP, ASN, threat score"),
                ("phone",     "phone <number>",     "Carrier, timezone; Truecaller opt-in"),
                ("username",  "username <handle>",  "WhatsMyName 600+ site footprint"),
            ]),
            ("Passive Recon", [
                ("email",     "email <address>",    "Holehe passive account audit"),
                ("breach",    "breach <address>",   "XposedOrNot breach lookup"),
                ("infostealer","infostealer <email|username>", "Hudson Rock infostealer intel"),
                ("emailsite", "emailsite <domain>", "DDG email harvest + Google dork"),
                ("domaincrawl","domaincrawl <domain> [depth]", "Deep async domain web crawler"),
            ]),
            ("Spiderweb Network", [
                ("portscan",  "portscan <ip>",      "TCP port scan"),
                ("netscan",   "netscan <cidr>",     "ICMP host discovery"),
                ("subdomain", "subdomain <domain>","CT-log subdomain enum"),
            ]),
            ("Recon / OSINT", [
                ("emailgoogle","emailgoogle <email>",   "Google profile / Gaia ID probe"),
                ("emailsmtp", "emailsmtp <email>",      "MX + SMTP RCPT validation"),
                ("portscan-async","portscan-async <ip|cidr>","Async TCP scan + banners"),
                ("maclookup", "maclookup <mac>",        "IEEE OUI vendor lookup"),
                ("dork",      "dork <username>",        "Google dork URL generator"),
                ("githubintel","githubintel <user|domain>", "GitHub commit email extraction"),
            ]),
            ("Digital Forensics", [
                ("hashcrack", "hashcrack <h> <type> [salt=..] [mode=..]", "MD5/SHA1/SHA256/SHA512 recovery"),
                ("pdfprotect","pdfprotect <f> <pw> [owner]",  "AES-256 password-protect a PDF"),
                ("pdfcrack",  "pdfcrack <file> [wordlist]",   "Recover locked PDF password"),
            ]),
            ("Core", [
                ("case",      "case new|list|open|close|status|off", "Investigation case management"),
                ("keys",      "keys list | keys set <svc> <val>", "Encrypted API key vault"),
                ("export",    "export case|last [json|html]",     "Chain-of-custody evidence export"),
                ("gui",       "gui",                "Open web dashboard"),
                ("status",    "status",             "API key & system health"),
                ("tor",       "tor [on|off|status|rotate]","Route via Tor (auto-install Linux/macOS)"),
                ("guide",     "guide",              "First-time quick start"),
                ("tour",      "tour",               "Guided walkthrough"),
                ("menu",      "menu",               "Show numbered tool list"),
                ("exit",      "exit",               "Quit session"),
            ]),
            ("Admin", [
                ("user",      "user add|list", "Manage investigator profiles (admin)"),
                ("profile",   "profile add|list", "Alias for user add|list"),
            ]),
        ]
        for section_name, cmds in sections:
            print(colored(f"  {section_name}", "yellow", attrs=["bold"]))
            for _cmd, syntax, desc in cmds:
                print(colored(f"    {syntax:<42}", "white") + colored(desc, "white"))
            print()
        _max_num = max(f['num'] for f in self.FEATURES)
        ui_hint(f"Tip: type a number (1–{_max_num}) or command name to launch a tool interactively.")
        ui_hint("New analyst? Type guide for a condensed first-time walkthrough.")
        print()

    def do_guide(self, arg):
        """First-time quick start. Usage: guide  |  /guide"""
        print()
        ui_title("ARGUS — FIRST-TIME QUICK START")
        lines = [
            "1. First boot: python3 console.py — create your first investigator profile when prompted.",
            "2. Each session: pick an existing profile or create a new one (no passwords).",
            "3. At session start, choose Active Investigation Case mode (yes/no).",
            "   · Yes — create/open a case; actions log to per-case audit files; export evidence.",
            "   · No  — ad-hoc mode; all tools work without a case; export case requires case mode.",
            "4. Optional API keys: keys set vt|abuse|truecaller <value>  — or use Settings in the GUI.",
            "5. Run a scan: type a tool name (e.g. ip 8.8.8.8, username handle) or pick a number from the menu.",
            "6. Export evidence (case mode only): export case html  — or Export Report in the GUI case panel.",
            "",
            "Manage profiles (admin): user add <name> <role>  ·  user list  ·  profile add|list",
            "Replay GUI tour: press the ? icon in the dashboard header.",
            "Disable CLI animation: ARGUS_NO_ANIMATION=1  or  python3 console.py --no-animation",
            "",
            "Type /help for the full command reference, or tour for an interactive module walkthrough.",
        ]
        for line in lines:
            print(colored(f"  {line}", "white"))
        print()

    def _cli_role(self) -> str:
        return (self.cli_profile or {}).get('role', 'investigator')

    def _require_admin(self) -> bool:
        if self._cli_role() != 'admin':
            print(colored("  ✗ Admin privileges required.", "red"))
            return False
        return True

    def do_profile(self, arg):
        """Profile management alias. Usage: profile add|list"""
        return self.do_user(arg)

    def do_user(self, arg):
        """Profile management (admin). Usage: user add <name> <role> | user list"""
        parts = (arg or '').split()
        if not parts:
            print(colored("  Usage: user add <name> <role> | user list", "yellow"))
            print(colored("  Roles: investigator, supervisor, admin", "white"))
            return

        sub = parts[0].lower()

        if sub == 'list':
            if not self._require_admin():
                return
            try:
                r = self._api_get("/auth/profiles")
                if r.status_code != 200:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                    return
                profiles = r.json().get('profiles', [])
                if not profiles:
                    print(colored("  No profiles found.", "yellow"))
                    return
                print(_box_top("PROFILES"))
                for p in profiles:
                    print(_box_row(p.get('display_name', ''), p.get('role', '')))
                print(_box_bot())
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return

        if sub == 'add':
            if not self._require_admin():
                return
            if len(parts) < 3:
                print(colored("  Usage: user add <display_name> <investigator|supervisor|admin>", "yellow"))
                return
            display_name, role = parts[1], parts[2].lower()
            if role not in ('investigator', 'supervisor', 'admin'):
                print(colored("  ✗ Invalid role. Choose: investigator, supervisor, admin", "red"))
                return
            try:
                r = self._api_post("/auth/profiles", json_body={
                    'display_name': display_name,
                    'role': role,
                })
                if r.status_code in (200, 201):
                    print(colored(f"  ✓ Profile '{display_name}' created ({role}).", "green"))
                else:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
            except (KeyboardInterrupt, EOFError):
                print()
            return

        print(colored("  Usage: user add <name> <role> | user list", "yellow"))

    def do_gui(self, arg):
        """Launch the full Web GUI Dashboard. Usage: gui  |  /gui"""
        print(colored(f"\n  Opening dashboard at http://127.0.0.1:{self.port}/", "green"))
        webbrowser.open(f'http://127.0.0.1:{self.port}/')

    def do_tour(self, arg):
        """Take an interactive guided tour of ARGUS modules. Usage: tour  |  /tour"""
        ui_title("ARGUS GUIDED TOUR")
        ui_hint("Step through each intelligence module — press q anytime to exit.")
        steps = [
            {
                "title": "Welcome to the ARGUS Guided Tour",
                "desc": "This command-line console acts as the Command Center for the ARGUS Intelligence Platform.\nIt is designed for rapid LEA-grade execution and Metasploit-style commands."
            },
            {
                "title": "Module 1: Web GUI Interface",
                "desc": "Type 'gui' to open the stunning Web GUI Dashboard in your browser.\nThe relative routes dynamically adjust to whatever port this console binds to."
            },
            {
                "title": "Module 2: Identity Intelligence",
                "desc": "Commands under this module:\n"
                        "  - ip <ip_addr>      : Resolve geodata, connection ASN, and Threat score.\n"
                        "  - phone <number>    : Carrier, timezone, region (Truecaller opt-in; --offline skips).\n"
                        "  - username <handle> : Footprint a handle across 600+ sites via WhatsMyName."
            },
            {
                "title": "Module 3: Passive Platform Recon & Compromise Check",
                "desc": "Commands under this module:\n"
                        "  - email <address>   : Passively probe forgot-password endpoints using the Holehe framework.\n"
                        "  - breach <address>  : Run leak-compromise checks via XposedOrNot leak databases."
            },
            {
                "title": "Module 4: Network Infrastructure Reconnaissance",
                "desc": "Commands under this module:\n"
                        "  - portscan <ip>     : Quick multi-threaded TCP scanner covering standard diagnostic ports.\n"
                        "  - netscan <cidr>    : High-speed CIDR block ping scan to map active infrastructure nodes.\n"
                        "  - subdomain <dom>   : Enumerate subdomains via certificate logs."
            },
            {
                "title": "Module 5: Digital Forensics",
                "desc": "Commands under this module:\n"
                        "  - hashcrack <hash> <type>      : Run standard dictionary attacks on MD5/SHA1/SHA256.\n"
                        "  - pdfprotect <file> <password> : Encrypt a local PDF with secure password policies.\n"
                        "  - pdfcrack <file>              : Perform local dictionary password recovery on a locked PDF."
            },
            {
                "title": "Module 6: Chain of Custody Audit Log",
                "desc": "Every single action you run, including CLI execution, is securely logged with timestamps\n"
                        "and exact payload metadata in audit.log. This maintains complete Chain of Custody for LEA reviews."
            }
        ]
        while True:
            print(colored("\n=== ARGUS GUIDED TOUR ===", "yellow", attrs=['bold']))
            print("Select a topic to learn about:")
            for idx, step in enumerate(steps):
                print(f"  [{idx + 1}] {step['title']}")
            print("  [m] Step-by-step sequential mode")
            print("  [q] Exit Tour")
            
            try:
                choice = input(colored("\nEnter selection (1-7, m, q): ", "yellow")).strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                break
                
            if choice == 'q':
                print(colored("[*] Tour exited.", "yellow"))
                break
            elif choice == 'm':
                for i, step in enumerate(steps):
                    print(colored(f"\n[Step {i+1}/{len(steps)}] {step['title']}", "yellow", attrs=['bold']))
                    print(step['desc'])
                    if i < len(steps) - 1:
                        try:
                            ans = input(colored("\nPress Enter for next step (or 'q' to stop): ", "yellow")).strip().lower()
                        except (KeyboardInterrupt, EOFError):
                            print()
                            ans = 'q'
                        if ans == 'q':
                            break
                else:
                    print(colored("\n[+] Sequential walkthrough completed.", "green"))
            else:
                try:
                    val = int(choice) - 1
                    if 0 <= val < len(steps):
                        step = steps[val]
                        print(colored(f"\n--- {step['title']} ---", "yellow", attrs=['bold']))
                        print(step['desc'])
                        try:
                            input(colored("\nPress Enter to return to menu...", "yellow"))
                        except (KeyboardInterrupt, EOFError):
                            print()
                    else:
                        print(colored("[!] Invalid topic number.", "red"))
                except ValueError:
                    print(colored("[!] Invalid input. Choose a number, 'm', or 'q'.", "red"))

    # ─────────────────────────────────────────────────────────────
    # Feature registry — single source of truth for all 11 tools
    # ─────────────────────────────────────────────────────────────
    FEATURES = [
        {
            'num': 1,  'cmd': 'ip',
            'label': 'IP & Network Scan',
            'module': 'Identity Intelligence',
            'one_liner': 'Geolocation, ISP, threat intel + optional TCP port scan for any IP.',
            'usage': 'ip <ip_address>',
            'example': 'ip 8.8.8.8',
            'apis': 'VirusTotal · AbuseIPDB · ipwho.is (free) · TCP socket scan'
        },
        {
            'num': 2,  'cmd': 'phone',
            'label': 'Telecom & Carrier Trace',
            'module': 'Identity Intelligence',
            'one_liner': 'Extracts carrier, timezone, region, and Truecaller registry data for a phone number.',
            'usage': 'phone <+countrycode_number> [--offline]',
            'example': 'phone +919876543210',
            'apis': 'Truecaller (opt-in, needs installation_id) · phonenumbers (offline)'
        },
        {
            'num': 3,  'cmd': 'username',
            'label': 'Username Footprint Scan',
            'module': 'Identity Intelligence',
            'one_liner': 'Async footprint of a username across 600+ sites (WhatsMyName database).',
            'usage': 'username <handle>',
            'example': 'username johnsmith',
            'apis': 'None — free public site checks (httpx async, wmn-data.json)'
        },
        {
            'num': 4,  'cmd': 'email',
            'label': 'Email Intelligence Suite',
            'module': 'Passive Recon',
            'one_liner': 'Full email audit: registrations, breaches, SMTP, Google profile, infostealers.',
            'usage': 'email <email_address>',
            'example': 'email target@gmail.com',
            'apis': 'Holehe · XposedOrNot · SMTP · Google · Hudson Rock'
        },
        {
            'num': 5,  'cmd': 'emailsite',
            'label': 'Domain Email Harvest',
            'module': 'Passive Recon',
            'one_liner': 'Harvest public emails from a domain via DuckDuckGo + Google dork.',
            'usage': 'emailsite <domain>',
            'example': 'emailsite example.com',
            'apis': 'DuckDuckGo HTML (free) · Google dork URL (offline)'
        },
        {
            'num': 6,  'cmd': 'domaincrawl',
            'label': 'Deep Domain Crawler',
            'module': 'Passive Recon',
            'one_liner': 'Async BFS crawl of a domain — emails, phones, social links from internal pages.',
            'usage': 'domaincrawl <domain> [max_depth]',
            'example': 'domaincrawl example.com 2',
            'apis': 'None — httpx async crawl with Tor/headers via Config'
        },
        {
            'num': 7,  'cmd': 'virustotal',
            'label': 'VirusTotal Reputation Scan',
            'module': 'Passive Recon',
            'one_liner': 'Query VirusTotal multi-engine threat intel for any IP address.',
            'usage': 'virustotal <ip_address>',
            'example': 'virustotal 8.8.8.8',
            'apis': 'VirusTotal API (needs API key)'
        },
        {
            'num': 8,  'cmd': 'abuseipdb',
            'label': 'AbuseIPDB Threat Reputation',
            'module': 'Passive Recon',
            'one_liner': 'Query AbuseIPDB confidence score and reports for any IP address.',
            'usage': 'abuseipdb <ip_address>',
            'example': 'abuseipdb 8.8.8.8',
            'apis': 'AbuseIPDB API (needs API key)'
        },
        {
            'num': 9,  'cmd': 'netscan',
            'label': 'Local CIDR Host Discovery',
            'module': 'Spiderweb Network',
            'one_liner': 'High-speed ICMP ping sweep across a subnet block to map active infrastructure.',
            'usage': 'netscan <cidr_block>',
            'example': 'netscan 192.168.1.0/24',
            'apis': 'None — offline ICMP'
        },
        {
            'num': 10, 'cmd': 'subdomain',
            'label': 'Subdomain CT-Log Enumerator',
            'module': 'Spiderweb Network',
            'one_liner': 'Queries certificate transparency logs (crt.sh) to enumerate live subdomains.',
            'usage': 'subdomain <base_domain>',
            'example': 'subdomain google.com',
            'apis': 'crt.sh public API — free'
        },
        {
            'num': 11, 'cmd': 'maclookup',
            'label': 'MAC Vendor Lookup',
            'module': 'Recon / OSINT',
            'one_liner': 'Resolves a MAC address to its hardware manufacturer via the IEEE OUI DB.',
            'usage': 'maclookup <mac>',
            'example': 'maclookup 00:1A:2B:3C:4D:5E',
            'apis': 'None — local IEEE OUI database'
        },
        {
            'num': 12, 'cmd': 'dork',
            'label': 'Username Dork Generator',
            'module': 'Recon / OSINT',
            'one_liner': 'Google dork URLs + DuckDuckGo live links for a username.',
            'usage': 'dork <username>',
            'example': 'dork johnsmith',
            'apis': 'Google dork URLs (offline) · DuckDuckGo HTML (free, jittered)'
        },
        {
            'num': 13, 'cmd': 'githubintel',
            'label': 'GitHub Intel Extractor',
            'module': 'Recon / OSINT',
            'one_liner': 'Extract commit emails and repos from GitHub public API (username or domain).',
            'usage': 'githubintel <username|domain>',
            'example': 'githubintel octocat',
            'apis': 'GitHub public API — unauthenticated (60 req/hr)'
        },
        {
            'num': 14, 'cmd': 'hashcrack',
            'label': 'Cryptographic Hash Recovery',
            'module': 'Digital Forensics',
            'one_liner': 'Offline dictionary attack on MD5/SHA1/SHA256/SHA512 hashes, optional salt.',
            'usage': 'hashcrack <hash> <type> [wordlist] [salt=..] [mode=prepend|append]',
            'example': 'hashcrack 5f4dcc3b5aa765d61d8327deb882cf99 md5',
            'apis': 'None — offline dictionary (md5 / sha1 / sha256 / sha512)'
        },
        {
            'num': 15, 'cmd': 'pdfprotect',
            'label': 'PDF Cryptography Lock',
            'module': 'Digital Forensics',
            'one_liner': 'Encrypts a local PDF with AES-256 password protection (offline).',
            'usage': 'pdfprotect <pdf_file_path> <password> [owner_password]',
            'example': 'pdfprotect report.pdf mySecret123',
            'apis': 'None — offline AES-256 (PyPDF2 / pypdf 3.x)'
        },
        {
            'num': 16, 'cmd': 'pdfcrack',
            'label': 'PDF Password Recovery',
            'module': 'Digital Forensics',
            'one_liner': 'Performs offline dictionary attacks to recover passwords from locked PDFs.',
            'usage': 'pdfcrack <locked_pdf_path> [wordlist]',
            'example': 'pdfcrack locked_doc.pdf rockyou.txt',
            'apis': 'None — offline dictionary'
        },
        {
            'num': 17, 'cmd': 'tor',
            'label': 'Tor OpSec Engine',
            'module': 'Core',
            'one_liner': 'Routes outbound traffic through Tor + leak check. Auto-install on Linux/macOS.',
            'usage': 'tor [on|off|status|rotate]',
            'example': 'tor on',
            'apis': 'Local SOCKS 127.0.0.1:9050 — auto-install Linux/macOS (sudo/brew).'
        },
        {
            'num': 18, 'cmd': 'truecaller-setup',
            'label': 'Truecaller Re-Setup',
            'module': 'Core',
            'one_liner': 'Re-run Truecaller OTP login to get a fresh installation ID.',
            'usage': 'truecaller-setup',
            'example': 'truecaller-setup',
            'apis': 'Truecaller (requires internet + phone OTP)'
        },
    ]

    def do_menu(self, arg):
        """Show the numbered interactive feature menu. Usage: menu  |  /menu"""
        print()
        ui_title("INTELLIGENCE MODULES")
        ui_hint("Select module by number or name  ·  /help  /exit  /clear  /gui")
        print()

        module_order = [
            "Identity Intelligence",
            "Passive Recon",
            "Spiderweb Network",
            "Recon / OSINT",
            "Digital Forensics",
        ]

        def _print_feature(f):
            raw = f['one_liner']
            desc = (raw[:53] + '…') if len(raw) > 54 else raw
            num_str = colored(f"  {f['num']:>2})", "yellow", attrs=["bold"])
            cmd_str = colored(f"  {f['cmd']:<15}", "white", attrs=["bold"])
            print(num_str + cmd_str + colored(desc, "white"))

        for i, module_name in enumerate(module_order):
            if i > 0:
                print(colored("  " + "─" * 58, "white"))
            print(colored(f"  ▶ {module_name.upper()}", "yellow", attrs=["bold"]))
            for f in self.FEATURES:
                if f['module'] == module_name:
                    _print_feature(f)
            print()

        # ── Core: the numbered tools that live in Core (tor) plus the
        # always-available control commands. Numbered tools are pulled from
        # FEATURES so the menu never drifts from the launcher mapping.
        print(colored("  " + "─" * 58, "white"))
        print(colored("  ▶ CORE", "yellow", attrs=["bold"]))
        for f in self.FEATURES:
            if f['module'] == 'Core':
                _print_feature(f)
        for cmd_name, desc in [
            ("guide",   "First-time quick start for new analysts"),
            ("gui",     "Open web intelligence dashboard"),
            ("status",  "Show API key and system status"),
            ("menu",    "Reprint this numbered tool list"),
            ("exit",    "Terminate session"),
        ]:
            print(colored(f"       {cmd_name:<16}", "white") + colored(desc, "white"))
        print()
        print(colored(
            "  Type a number or command name to launch a tool  ·  "
            "/help for full reference  ·  /menu to reprint  ·  gui for the dashboard",
            "green",
        ))
        print()

    def run_interactive_wizard(self, cmd_name):
        """Prompt for inputs and run a tool — no duplicate banners."""
        prompts = {
            'ip':        ("IP address (IPv4/IPv6)", lambda v: self._run_quiet(self.do_ip, v)),
            'phone':     ("phone number with country code", lambda v: self._run_quiet(self.do_phone, v)),
            'username':  ("username handle", lambda v: self._run_quiet(self.do_username, v)),
            'email':     ("email address", lambda v: self._run_quiet(self.do_email, v)),
            'emailsite': ("domain name", lambda v: self._run_quiet(self.do_emailsite, v)),
            'domaincrawl': ("domain name", lambda v: self._run_quiet(self.do_domaincrawl, v)),
            'virustotal': ("IP address", lambda v: self._run_quiet(self.do_virustotal, v)),
            'abuseipdb': ("IP address", lambda v: self._run_quiet(self.do_abuseipdb, v)),
            'netscan':   ("CIDR block (e.g. 192.168.1.0/24)", lambda v: self._run_quiet(self.do_netscan, v)),
            'subdomain': ("base domain", lambda v: self._run_quiet(self.do_subdomain, v)),
            'maclookup': ("MAC address (e.g. 00:1A:2B:3C:4D:5E)", lambda v: self._run_quiet(self.do_maclookup, v)),
            'dork':      ("username handle", lambda v: self._run_quiet(self.do_dork, v)),
            'githubintel': ("GitHub username or domain", lambda v: self._run_quiet(self.do_githubintel, v)),
            'hashcrack': None,
            'pdfprotect': None,
            'pdfcrack':  None,
            'tor':       None,
            'truecaller-setup': None,
        }

        if cmd_name == 'hashcrack':
            try:
                h = input(colored("  hash › ", "yellow")).strip()
                if not h:
                    return
                t = input(colored("  type (md5/sha1/sha256/sha512) › ", "yellow")).strip()
                if not t:
                    return
                cmd_str = f"{h} {t}"
                salt = input(colored("  salt (Enter to skip) › ", "yellow")).strip()
                if salt:
                    mode = input(colored("  salt mode (prepend/append) [append] › ", "yellow")).strip().lower() or 'append'
                    cmd_str += f" salt={salt} mode={mode}"
                self._run_quiet(self.do_hashcrack, cmd_str)
            except (KeyboardInterrupt, EOFError):
                print()
            return

        if cmd_name == 'pdfprotect':
            try:
                f = input(colored("  PDF path › ", "yellow")).strip()
                if not f:
                    return
                p = input(colored("  password › ", "yellow")).strip()
                if not p:
                    return
                owner = input(colored("  owner password (Enter to reuse) › ", "yellow")).strip()
                cmd_str = f"{f} {p} {owner}" if owner else f"{f} {p}"
                self._run_quiet(self.do_pdfprotect, cmd_str)
            except (KeyboardInterrupt, EOFError):
                print()
            return

        if cmd_name == 'pdfcrack':
            try:
                f = input(colored("  locked PDF path › ", "yellow")).strip()
                if not f:
                    return
                wl = input(colored("  wordlist (Enter for rockyou.txt) › ", "yellow")).strip()
                arg = f"{f} {wl}" if wl else f
                self._run_quiet(self.do_pdfcrack, arg)
            except (KeyboardInterrupt, EOFError):
                print()
            return

        if cmd_name == 'infostealer':
            try:
                kind = input(colored("  type (email/username) › ", "yellow")).strip().lower()
                if kind not in ("email", "username"):
                    return
                target = input(colored(f"  {kind} › ", "yellow")).strip()
                if target:
                    self._run_quiet(self.do_infostealer, f"{kind} {target}")
            except (KeyboardInterrupt, EOFError):
                print()
            return

        if cmd_name == 'tor':
            try:
                action = input(colored("  action (on/off/status/rotate) › ", "yellow")).strip().lower()
                self._run_quiet(self.do_tor, action)
            except (KeyboardInterrupt, EOFError):
                print()
            return

        if cmd_name == 'truecaller-setup':
            self._run_quiet(self.do_truecaller_setup, '')
            return

        entry = prompts.get(cmd_name)
        if not entry:
            return
        label, runner = entry
        try:
            value = input(colored(f"  {label} › ", "yellow")).strip()
            if value:
                runner(value)
        except (KeyboardInterrupt, EOFError):
            print()

    # ─── command aliases & slash-command dispatch ────────────────
    def do_quit(self, arg):
        """Alias for exit. Usage: quit  |  /quit"""
        return self.do_exit(arg)

    def do_clear(self, arg):
        """Clear the terminal screen. Usage: clear  |  /clear"""
        os.system('cls' if platform.system() == 'Windows' else 'clear')
        print(colored(f"\n  ARGUS Intelligence Platform · port {self.port} · /menu · /help · /exit\n", "yellow", attrs=["bold"]))
        self.do_menu('')

    def show_feature_usage_card(self, feature: dict):
        """Brief usage guide before launching a tool interactively."""
        print()
        print(colored(f"  [{feature['num']}] {feature['label']}", "yellow", attrs=["bold"]))
        print(colored(f"      {feature['one_liner']}", "white"))
        print(colored(f"      use: {feature['usage']}", "white"))
        print(colored(f"      e.g. {feature['example']}", "white"))
        if feature.get('apis'):
            print(colored(f"      api: {feature['apis']}", "white"))
        print()

    def default(self, line):
        cleaned = line.strip()

        if cleaned.isdigit():
            num = int(cleaned)
            if num == 0:
                return self.do_menu('')
            feat = next((f for f in self.FEATURES if f['num'] == num), None)
            if feat:
                while True:
                    _animate_launch_message(feat['cmd'])
                    self.show_feature_usage_card(feat)
                    self.run_interactive_wizard(feat['cmd'])
                    
                    try:
                        ans = input(colored(f"\n  Do you want to reuse the {feat['label']} or see the menu? [y: reuse / n: menu] › ", "yellow")).strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        ans = "n"
                    
                    if ans in ("y", "yes"):
                        continue
                    else:
                        break
                print()
                self.do_menu('')
                return
            max_num = max(f['num'] for f in self.FEATURES)
            print(colored(f"  No feature #{num}. Valid: 1–{max_num}. Type /menu.", "red"))
            return

        feat = next((f for f in self.FEATURES if f['cmd'] == cleaned.lower()), None)
        if feat:
            while True:
                self.show_feature_usage_card(feat)
                self.run_interactive_wizard(feat['cmd'])
                
                try:
                    ans = input(colored(f"\n  Do you want to reuse the {feat['label']} or see the menu? [y: reuse / n: menu] › ", "yellow")).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    ans = "n"
                
                if ans in ("y", "yes"):
                    continue
                else:
                    break
            print()
            self.do_menu('')
            return

        print(colored(f"  Unknown: {line.strip()}  —  /menu for tools · /help for syntax", "red"))

    def do_ip(self, arg):
        """Analyze an IP address for geographic and threat details.
        Usage: ip <ip_address>"""
        self._cmd_banner('ip')
        if not arg:
            print(colored("  Usage: ip <ip_address>  —  or type /help ip", "yellow"))
            return

        # Check API key configuration status for VT and AbuseIPDB
        keys = get_api_keys()
        vt_configured = bool(keys.get('vt'))
        abuse_configured = bool(keys.get('abuse'))

        if not vt_configured:
            print(colored("\n  [!] VirusTotal API key is not configured.", "yellow"))
            print(colored("      To get one: Go to https://www.virustotal.com/ -> Sign up/Log in -> API key.", "white"))
            try:
                ans = input(colored("  Set VirusTotal key now? [y/N] › ", "yellow")).strip().lower()
                if ans in ("y", "yes"):
                    key_val = input(colored("  Paste VirusTotal API Key › ", "yellow")).strip()
                    if key_val:
                        r = self._api_post("/vault/keys", json_body={"service": "vt", "value": key_val})
                        if r.status_code == 200:
                            print(colored("  ✓ Saved to vault — VirusTotal is ready!", "green"))
                            vt_configured = True
            except (KeyboardInterrupt, EOFError):
                print()

        if not abuse_configured:
            print(colored("\n  [!] AbuseIPDB API key is not configured.", "yellow"))
            print(colored("      To get one: Go to https://www.abuseipdb.com/ -> Sign up/Log in -> API -> Create Key.", "white"))
            try:
                ans = input(colored("  Set AbuseIPDB key now? [y/N] › ", "yellow")).strip().lower()
                if ans in ("y", "yes"):
                    key_val = input(colored("  Paste AbuseIPDB API Key › ", "yellow")).strip()
                    if key_val:
                        r = self._api_post("/vault/keys", json_body={"service": "abuse", "value": key_val})
                        if r.status_code == 200:
                            print(colored("  ✓ Saved to vault — AbuseIPDB is ready!", "green"))
                            abuse_configured = True
            except (KeyboardInterrupt, EOFError):
                print()

        print(colored(f"  Querying {arg}...", "yellow"))
        try:
            res = self._api_get("/ip", params={'ip': arg})
            if res.status_code == 200:
                d = res.json()
                if d.get('error') or d.get('success') is False:
                    print(colored(f"  ✗ Error: {d.get('error') or d.get('message')}", "red"))
                    return
                conn = d.get('connection', {})
                loc_parts = [d.get('city',''), d.get('region',''), d.get('country','')]
                location = ', '.join(p for p in loc_parts if p) or '—'
                tz = d.get('timezone', {})
                tz_id = tz.get('id', '—') if isinstance(tz, dict) else '—'
                coords = f"{d.get('latitude', '—')}, {d.get('longitude', '—')}"
                print()
                print(_box_top("IP INTELLIGENCE"))
                print(_box_row("IP Address", f"{d.get('ip', arg)}  ({d.get('type','IPv4')})"))
                print(_box_row("Location", location))
                print(_box_row("Coordinates", coords))
                print(_box_row("Timezone", tz_id))
                print(_box_section("NETWORK"))
                print(_box_row("ISP", conn.get('isp', '—')))
                print(_box_row("Organization", conn.get('org', '—')))
                print(_box_row("ASN", str(conn.get('asn', '—'))))
                print(_box_row("Domain", conn.get('domain', '—')))
                if 'virustotal' in d:
                    vt = d['virustotal']
                    print(_box_section("VIRUSTOTAL"))
                    if 'error' in vt:
                        print(_box_row("Status", vt['error'], val_color="yellow"))
                    else:
                        mal = vt.get('malicious', 0)
                        print(_box_row("Reputation", str(vt.get('reputation', '—'))))
                        print(_box_row("Malicious", str(mal), val_color="red" if mal > 0 else "green"))
                        print(_box_row("Suspicious", str(vt.get('suspicious', 0)), val_color="yellow" if vt.get('suspicious',0) > 0 else "white"))
                        print(_box_row("Harmless", str(vt.get('harmless', 0)), val_color="green"))
                if 'abuseipdb' in d:
                    ab = d['abuseipdb']
                    print(_box_section("ABUSEIPDB"))
                    if 'error' in ab:
                        print(_box_row("Status", ab['error'], val_color="yellow"))
                    else:
                        score = ab.get('abuseConfidenceScore', 0)
                        print(_box_row("Confidence", f"{score}%", val_color="red" if score > 20 else ("yellow" if score > 0 else "green")))
                        print(_box_row("Reports", str(ab.get('totalReports', 0))))
                        print(_box_row("Domain", ab.get('domain', '—')))
                print(_box_bot())
                print()

                try:
                    ans = input(colored("  Would you like to run a port scan on this IP? [y/N] ", "yellow")).strip().lower()
                    if ans in ("y", "yes"):
                        print(colored("\n  Select port scan mode:", "yellow"))
                        print(colored("    1) Standard TCP Scan (fast)", "white"))
                        print(colored("    2) Async TCP Scan with Banner Grabbing (thorough)", "white"))
                        choice = input(colored("  Choose [1/2, default 1] › ", "yellow")).strip()
                        if choice == "2":
                            self._run_quiet(self.do_portscan_async, arg)
                        else:
                            self._run_quiet(self.do_portscan, arg)
                except (KeyboardInterrupt, EOFError):
                    print()
            else:
                print(colored(f"  ✗ Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_virustotal(self, arg):
        """Query VirusTotal threat intelligence for an IP address.
        Usage: virustotal <ip_address>"""
        self._cmd_banner('virustotal')
        if not arg:
            print(colored("  Usage: virustotal <ip_address>  —  or type /help virustotal", "yellow"))
            return

        # Check API key configuration status for VT
        keys = get_api_keys()
        vt_configured = bool(keys.get('vt'))

        if not vt_configured:
            print(colored("\n  [!] VirusTotal API key is not configured.", "yellow"))
            print(colored("      To get one: Go to https://www.virustotal.com/ -> Sign up/Log in -> API key.", "white"))
            try:
                ans = input(colored("  Set VirusTotal key now? [y/N] › ", "yellow")).strip().lower()
                if ans in ("y", "yes"):
                    key_val = input(colored("  Paste VirusTotal API Key › ", "yellow")).strip()
                    if key_val:
                        r = self._api_post("/vault/keys", json_body={"service": "vt", "value": key_val})
                        if r.status_code == 200:
                            print(colored("  ✓ Saved to vault — VirusTotal is ready!", "green"))
                            vt_configured = True
            except (KeyboardInterrupt, EOFError):
                print()

        if not vt_configured:
            print(colored("  ✗ Cannot proceed without VirusTotal key.", "red"))
            return

        print(colored(f"  Querying VirusTotal for {arg}...", "yellow"))
        try:
            res = self._api_post("/scan-virustotal", json_body={'target': arg})
            if res.status_code == 200:
                d = res.json()
                if 'error' in d:
                    print(colored(f"  ✗ Error: {d['error']}", "red"))
                    return
                print()
                print(_box_top("VIRUSTOTAL ANALYSIS"))
                print(_box_row("Target IP", arg))
                data_block = d.get('data', {})
                attr = data_block.get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                mal = stats.get('malicious', 0)
                rep = attr.get('reputation', 0)
                print(_box_row("Reputation", str(rep)))
                print(_box_row("Malicious", str(mal), val_color="red" if mal > 0 else "green"))
                print(_box_row("Suspicious", str(stats.get('suspicious', 0)), val_color="yellow" if stats.get('suspicious', 0) > 0 else "white"))
                print(_box_row("Harmless", str(stats.get('harmless', 0)), val_color="green"))
                print(_box_row("Undetected", str(stats.get('undetected', 0))))
                print(_box_bot())
                print()
            else:
                print(colored(f"  ✗ Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_abuseipdb(self, arg):
        """Query AbuseIPDB threat intelligence for an IP address.
        Usage: abuseipdb <ip_address>"""
        self._cmd_banner('abuseipdb')
        if not arg:
            print(colored("  Usage: abuseipdb <ip_address>  —  or type /help abuseipdb", "yellow"))
            return

        # Check API key configuration status for AbuseIPDB
        keys = get_api_keys()
        abuse_configured = bool(keys.get('abuse'))

        if not abuse_configured:
            print(colored("\n  [!] AbuseIPDB API key is not configured.", "yellow"))
            print(colored("      To get one: Go to https://www.abuseipdb.com/ -> Sign up/Log in -> API -> Create Key.", "white"))
            try:
                ans = input(colored("  Set AbuseIPDB key now? [y/N] › ", "yellow")).strip().lower()
                if ans in ("y", "yes"):
                    key_val = input(colored("  Paste AbuseIPDB API Key › ", "yellow")).strip()
                    if key_val:
                        r = self._api_post("/vault/keys", json_body={"service": "abuse", "value": key_val})
                        if r.status_code == 200:
                            print(colored("  ✓ Saved to vault — AbuseIPDB is ready!", "green"))
                            abuse_configured = True
            except (KeyboardInterrupt, EOFError):
                print()

        if not abuse_configured:
            print(colored("  ✗ Cannot proceed without AbuseIPDB key.", "red"))
            return

        print(colored(f"  Querying AbuseIPDB for {arg}...", "yellow"))
        try:
            res = self._api_post("/scan-abuseip", json_body={'target': arg})
            if res.status_code == 200:
                d = res.json()
                if 'error' in d:
                    print(colored(f"  ✗ Error: {d['error']}", "red"))
                    return
                print()
                print(_box_top("ABUSEIPDB ANALYSIS"))
                print(_box_row("Target IP", arg))
                data_block = d.get('data', {})
                score = data_block.get('abuseConfidenceScore', 0)
                print(_box_row("Confidence", f"{score}%", val_color="red" if score > 20 else ("yellow" if score > 0 else "green")))
                print(_box_row("Reports", str(data_block.get('totalReports', 0))))
                print(_box_row("Domain", data_block.get('domain', '—')))
                quota = d.get('quota_tracker', {})
                print(_box_row("Quota Limit", str(quota.get('limit', '—'))))
                print(_box_row("Quota Remain", str(quota.get('remaining', '—'))))
                print(_box_bot())
                print()
            else:
                print(colored(f"  ✗ Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def _ask_truecaller_phone(self) -> bool:
        """Prompt once per session; cached in self.truecaller_phone_enabled."""
        if self.truecaller_phone_enabled is not None:
            return self.truecaller_phone_enabled
        try:
            ans = input(colored("  Enable Truecaller? [y/N] ", "yellow")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        enabled = ans in ("y", "yes")
        self.truecaller_phone_enabled = enabled
        return enabled

    def _ensure_truecaller_token(self, force: bool = False) -> str:
        """Auto-run Truecaller login + installation_id via npx, then save to vault.

        Uses Popen so the user can interact (enter phone + OTP) while we also
        capture output to detect failures like "Verification failed".
        Validates the installation_id output to reject garbage (URLs, help text).
        """
        import re as _re, shutil, subprocess as _sp, sys as _sys

        keys = get_api_keys()
        tc = (keys.get("truecaller") or "").strip()
        if tc and not force:
            return tc

        npx_bin = shutil.which("npx")
        node_bin = shutil.which("node")

        if npx_bin and node_bin:
            # ── Step 1: interactive login (OTP flow) ──────────────────────
            print()
            print(colored("  ─────────────────────────────────────────────────", "yellow"))
            print(colored("  Truecaller Setup — Automated Login", "yellow", attrs=["bold"]))
            print(colored("  ⚠  You must be ONLINE. Your phone number is only", "yellow"))
            print(colored("     used to receive an OTP — it is NEVER stored.", "yellow"))
            print(colored("     The OTP is safe to enter — it only authenticates", "yellow"))
            print(colored("     with Truecaller to get your installation ID.", "yellow"))
            print(colored("  ─────────────────────────────────────────────────", "yellow"))
            print()
            print(colored("  Step 1/2 — Running: npx truecallerjs login", "cyan"))
            print(colored("             Enter your phone number (with country code)", "white"))
            print(colored("             Then enter the OTP you receive on that phone", "white"))
            print()
            try:
                # Use subprocess.run with default stdio descriptors (None) to inherit parent streams.
                # This keeps the TTY intact and interactive for OTP login.
                login_proc = _sp.run(
                    [npx_bin, "-y", "truecallerjs", "login"],
                    stdin=None,
                    stdout=None,
                    stderr=None,
                )

                if login_proc.returncode != 0:
                    print()
                    print(colored(
                        "  ✗ Truecaller login failed. Possible reasons:\n"
                        "    • Wrong phone number format (use +countrycode, e.g. +919876543210)\n"
                        "    • OTP not entered or entered incorrectly\n"
                        "    • No internet connection\n"
                        "    • Truecaller API rate limit",
                        "red",
                    ))
                    # fall through to manual entry
                else:
                    # ── Step 2: capture installation_id automatically ──────
                    print()
                    print(colored("  Step 2/2 — Fetching installation ID…", "cyan"))
                    id_proc = _sp.run(
                        [npx_bin, "-y", "truecallerjs", "installation_id"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    raw_output = (id_proc.stdout or "").strip()

                    # Parse: look for a valid installation ID in the output.
                    # A real ID is a base64 string starting with 4/ (typically 20+ chars).
                    # Reject URLs, help text, "Repository =>", etc.
                    installation_id = ""
                    for line in raw_output.splitlines():
                        line = line.strip()
                        # skip empty, URLs, labels, help text
                        if not line:
                            continue
                        if "http" in line or "=>" in line or "Repository" in line or "github" in line.lower() or "sumithemmadi" in line.lower():
                            continue
                        if line.startswith("#") or line.startswith("-"):
                            continue
                        # A valid installation ID is typically a hex/alphanumeric/base64 string, 10+ chars
                        candidate = line.split()[-1] if line.split() else ""
                        if _re.match(r'^[a-zA-Z0-9_+\-/=]{10,}$', candidate):
                            installation_id = candidate
                            break

                    if installation_id:
                        print(colored(f"  ✓ Installation ID: {installation_id}", "green"))
                        try:
                            r = self._api_post(
                                "/vault/keys",
                                json_body={"service": "truecaller", "value": installation_id},
                            )
                            if r.status_code == 200:
                                print(colored("  ✓ Saved to vault — Truecaller is ready!", "green"))
                            else:
                                print(colored(f"  ✗ Vault save failed: {r.text}", "red"))
                        except Exception as exc:
                            print(colored(f"  ✗ Vault error: {exc}", "red"))
                        return installation_id
                    else:
                        print(colored(
                            "  ✗ Login succeeded but no valid installation ID found.\n"
                            "    The login may not have completed properly.\n"
                            "    Try running: npx truecallerjs login  (manually in terminal)\n"
                            "    Then:        npx truecallerjs installation_id",
                            "red",
                        ))
            except FileNotFoundError:
                print(colored("  ✗ npx not found on PATH.", "red"))
            except _sp.TimeoutExpired:
                print(colored("  ✗ Timed out waiting for truecallerjs.", "red"))
            except (EOFError, KeyboardInterrupt):
                print()
                return ""
        else:
            print(colored(
                "  ⚠  node/npx not found — cannot run automated login.\n"
                "     Install Node.js from https://nodejs.org then re-run.",
                "yellow",
            ))

        # ── Manual fallback ───────────────────────────────────────────────
        try:
            ans = input(colored("\n  Automatic setup failed. Would you like to enter an installation ID manually? [y/N] › ", "yellow")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "n"

        if ans not in ("y", "yes"):
            return ""

        print()
        print(colored("  Manual fallback — paste a valid installation ID:", "yellow"))
        print(colored("    Run in a separate terminal:", "white"))
        print(colored("      npx truecallerjs login", "white"))
        print(colored("      npx truecallerjs installation_id", "white"))
        print()
        try:
            token = input(colored("  Truecaller Installation ID › ", "yellow")).strip()
        except (EOFError, KeyboardInterrupt):
            return ""
        if not token:
            return ""
        try:
            r = self._api_post("/vault/keys", json_body={"service": "truecaller", "value": token})
            if r.status_code == 200:
                print(colored("  ✓ Truecaller ID saved to vault", "green"))
                return token
            print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
        except Exception as exc:
            print(colored(f"  ✗ {exc}", "red"))
        return token

    def do_phone(self, arg):
        """Trace a phone number's region, carrier, and name.
        Usage: phone <phone_number_with_country_code> [--offline] [installation_id]"""
        self._cmd_banner('phone')
        raw_args = arg.split()
        offline = "--offline" in raw_args
        args = [a for a in raw_args if a != "--offline"]
        if not args:
            print(colored("  Usage: phone <number> [--offline]  —  or type /help phone", "yellow"))
            return

        phone = args[0]
        tc_override = args[1] if len(args) > 1 else ""

        if tc_override:
            use_truecaller = True
        elif offline:
            use_truecaller = False
            self.truecaller_phone_enabled = False
        else:
            use_truecaller = self._ask_truecaller_phone()

        if use_truecaller and not tc_override:
            tc_override = self._ensure_truecaller_token()

        mode = "Truecaller + phonenumbers" if use_truecaller else "phonenumbers (offline)"
        print(colored(f"  Tracing {phone} ({mode})...", "yellow"))

        payload = {"phone": phone, "truecaller": use_truecaller}
        if tc_override:
            payload["installation_id"] = tc_override

        try:
            res = self._api_post("/phone", json_body=payload)
            if res.status_code == 200:
                d = res.json()
                valid_color = "green" if d.get('is_valid', False) else "red"
                region_code = d.get('region', '—')
                region_with_flag = REGIONS_WITH_FLAGS.get(region_code, region_code)

                print()
                print(_box_top("PHONE TRACE"))
                if d.get('phonenumbers_error'):
                    print(_box_row("Parse Error", d['phonenumbers_error'], val_color="red"))
                print(_box_row("Number", f"{d.get('e164_format','—')}  ({d.get('international_format','—')})"))
                print(_box_row("Status", "valid" if d.get('is_valid', False) else "invalid", val_color=valid_color))
                print(_box_row("Region", region_with_flag))
                print(_box_row("Carrier", d.get('carrier', '—')))
                print(_box_row("Location", d.get('location', '—')))
                print(_box_row("Timezone", ', '.join(d.get('timezones', [])) or '—'))
                print(_box_row("Line Type", d.get('number_type', '—')))
                print(_box_bot())

                tc_val = d.get('truecaller')
                if isinstance(tc_val, dict) and tc_val.get("skipped"):
                    pass
                elif isinstance(tc_val, dict):
                    if tc_val.get('configured') is False:
                        print(colored(
                            "  Truecaller: NOT CONFIGURED — keys set truecaller <installation_id>",
                            "yellow",
                        ))
                    else:
                        print()
                        print(_box_top("TRUECALLER INTELLIGENCE DOSSIER"))
                        if tc_val.get('alert'):
                            print(_box_row("Alert", tc_val['alert'], val_color="red"))
                        if not tc_val.get('available', True):
                            print(_box_row("Status", tc_val.get('error', 'lookup failed'), val_color="red"))
                        else:
                            name = tc_val.get('primary_name') or '—'
                            print(_box_row("Primary Name", name, val_color="green" if name != '—' else "white"))
                            alts = tc_val.get('alternate_names') or []
                            if alts:
                                print(_box_row("Alt Names", ', '.join(alts), val_color="green"))
                            if tc_val.get('carrier'):
                                print(_box_row("Carrier", tc_val['carrier']))
                            if tc_val.get('email'):
                                print(_box_row("Email", tc_val['email'], val_color="green"))
                            if tc_val.get('tags'):
                                print(_box_row("Tags", ', '.join(tc_val['tags'])))
                            verified = tc_val.get('verified')
                            if verified is not None:
                                print(_box_row(
                                    "Verified",
                                    "yes" if verified else "no",
                                    val_color="green" if verified else "white",
                                ))
                            loc_parts = [p for p in (tc_val.get('city'), tc_val.get('country')) if p]
                            if loc_parts:
                                print(_box_row("Location", ', '.join(loc_parts)))
                            if tc_val.get('timezone'):
                                print(_box_row("Timezone", tc_val['timezone']))
                            spam = tc_val.get('spam_score')
                            if spam is not None:
                                spam_color = "red" if spam > 25 else "yellow" if spam > 0 else "green"
                                spam_line = str(spam)
                                if tc_val.get('spam_type'):
                                    spam_line += f" — {tc_val['spam_type']}"
                                print(_box_row("Spam Score", spam_line, val_color=spam_color))
                        print(_box_bot())

                print()
            else:
                print(colored(f"  ✗ Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_username(self, arg):
        """Footprint a username across 600+ sites (WhatsMyName).
        Usage: username <handle>  |  username <pattern>  (wildcard: john[0-9]{0-2})"""
        self._cmd_banner('username')
        if not arg:
            print(colored("  Usage: username <handle>  —  or type /help username", "yellow"))
            return

        handle = arg.strip().lstrip('@')
        use_pattern = '[' in handle and ']' in handle
        if use_pattern:
            print(colored(f"  Pattern scan: {handle} (up to 25 permutations)...", "yellow"))
        else:
            print(colored(f"  Scanning @{handle} across 600+ sites + 185+ extended platforms (this can take 2–5 min)...", "yellow"))
        try:
            body = {'username': handle}
            if use_pattern:
                body['pattern'] = True
                body['limit'] = 25
            res = self._api_post("/recon/username", json_body=body, timeout=600).json()
            if not res.get('success'):
                print(colored(f"  ✗ {res.get('error', 'Scan failed')}", "red"))
                return
            if use_pattern:
                found = res.get('found', [])
                print()
                print(_box_top("USERNAME PATTERN SCAN"))
                print(_box_row("Pattern", handle))
                print(_box_row("Total Permutations", str(res.get('pattern_total', 0))))
                print(_box_row("Scanned", str(res.get('pattern_scanned', 0))))
                print(_box_row("Matches", str(res.get('found_count', 0)),
                               val_color="green" if res.get('found_count', 0) > 0 else "white"))
                for site in found:
                    label = f"{site.get('name', 'Unknown')} (@{site.get('matched_username', '?')})"
                    print(_box_row(label[:14], site.get('url', ''), val_color="green"))
                print(_box_bot())
                print()
                return
            found = res.get('found', [])
            print()
            print(_box_top("USERNAME FOOTPRINT SCAN"))
            print(_box_row("Handle", f"@{handle}"))
            print(_box_row("Sites Checked", str(res.get('sites_checked', 0))))
            print(_box_row("Matches", str(res.get('found_count', 0)),
                           val_color="green" if res.get('found_count', 0) > 0 else "white"))
            if found:
                current_cat = None
                for site in found:
                    cat = site.get('category', 'unknown')
                    if cat != current_cat:
                        current_cat = cat
                        print(_box_section(str(cat).upper()[:_BW - 5]))
                    src = site.get('source', 'wmn')
                    label = site.get('name', 'Unknown')[:14]
                    if src == 'user-scanner':
                        label = f"{label}*"
                    print(_box_row(label, site.get('url', ''), val_color="green"))
            us_only = res.get('user_scanner_found') or []
            wmn_names = {(s.get('name') or '').lower() for s in found}
            extra_us = [s for s in us_only if (s.get('name') or '').lower() not in wmn_names]
            if extra_us:
                print(_box_section("EXTENDED (USER-SCANNER)"))
                for site in extra_us:
                    print(_box_row(site.get('name', 'Unknown')[:14], site.get('url', ''), val_color="cyan"))
            elif not found:
                print(_box_hint("No accounts found on scanned sites"))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def _format_email_hit(self, reg: dict, color: str = "green") -> None:
        """Print one email registration hit with link type and metadata."""
        platform = reg.get("name") or reg.get("site_name") or reg.get("domain") or "Unknown"
        url = reg.get("url", "")
        link_type = reg.get("link_type") or ""
        type_label = {
            "profile": "profile",
            "recovery": "recovery",
            "platform_home": "registered",
        }.get(link_type, "")
        label = f"{platform} ({type_label})" if type_label else platform
        print(colored(f"    [+] {label}", color), end="")
        if url:
            print(colored(f"  →  {url}", "white"))
        else:
            print()
        sub_parts = []
        if link_type == "recovery":
            sub_parts.append("email confirmed registered on this platform")
        if reg.get("username"):
            sub_parts.append(f"username: {reg['username']}")
        if reg.get("extra_summary"):
            sub_parts.append(reg["extra_summary"])
        elif reg.get("extra"):
            preview = ", ".join(
                f"{k}: {v}" for k, v in list(reg["extra"].items())[:3]
            )
            if preview:
                sub_parts.append(preview)
        if sub_parts:
            print(colored(f"         ↳ {' | '.join(sub_parts)}", "white"))

    def do_email(self, arg):
        """Identify registered social platform accounts for an email using passive probes.
        Usage: email <email_address>"""
        self._cmd_banner('email')
        if not arg:
            print(colored("  Usage: email <address>  —  or type /help email", "yellow"))
            return
        
        print(colored(f"  Auditing {arg}...", "yellow"))
        print(colored("  Extended scan: checking 100+ platforms via user-scanner (may take 2–5 min)...", "yellow"))
        try:
            res = self._api_get("/email", params={'email': arg, 'supplementary': '1'}, timeout=600)
            if res.status_code == 200:
                d = res.json()
                if d.get('error') and not d.get('registered_on'):
                    print(colored(f"[-] Passive check error: {d['error']}", "red"))
                    if d.get('mock_response'):
                        print(colored("    Demonstration matches (Holehe not installed):", "yellow"))
                        for match in d['mock_response']['registered_on']:
                            print(f"      - {match['name']}")
                else:
                    print(colored(f"[+] Total Platforms Checked: {d.get('platforms_checked', 0)}", "white"))
                    print(colored(f"[+] Active Registrations Detected: {d.get('registered_count', 0)}", "green"))
                    for reg in d.get('registered_on', []):
                        self._format_email_hit(reg, color="green")
                    supp = d.get('supplementary') or {}
                    if supp.get('registered_on'):
                        print(colored(f"[+] Supplementary Probes (+{supp.get('registered_count', 0)}):", "cyan"))
                        for reg in supp.get('registered_on', []):
                            self._format_email_hit(reg, color="cyan")
                    us = d.get('user_scanner') or {}
                    us_reg = us.get('registered_unique') or us.get('registered') or []
                    if us_reg:
                        print(colored(
                            f"[+] Extended Platform Scan (user-scanner, +{len(us_reg)}):",
                            "cyan",
                        ))
                        for reg in us_reg:
                            self._format_email_hit(reg, color="cyan")
                    elif us.get('error'):
                        print(colored(f"    [-] Extended scan: {us['error']}", "yellow"))
                    if d.get('rate_limited_count', 0) > 0:
                        print(colored(f"    [-] Rate limited platforms: {d['rate_limited_count']}", "yellow"))
            else:
                print(colored(f"[-] Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

        # Chain other email reconnaissance tools sequentially
        print(colored("\n  ─────────────────────────────────────────────────", "yellow"))
        print(colored("  BREACH INTELLIGENCE SCAN", "yellow", attrs=["bold"]))
        print(colored("  ─────────────────────────────────────────────────", "yellow"))
        self._run_quiet(self.do_breach, arg)

        print(colored("\n  ─────────────────────────────────────────────────", "yellow"))
        print(colored("  GOOGLE ACCOUNT PROFILE LOOKUP", "yellow", attrs=["bold"]))
        print(colored("  ─────────────────────────────────────────────────", "yellow"))
        self._run_quiet(self.do_emailgoogle, arg)

        print(colored("\n  ─────────────────────────────────────────────────", "yellow"))
        print(colored("  SMTP MAILBOX DELIVERY VALIDATION", "yellow", attrs=["bold"]))
        print(colored("  ─────────────────────────────────────────────────", "yellow"))
        self._run_quiet(self.do_emailsmtp, arg)

        print(colored("\n  ─────────────────────────────────────────────────", "yellow"))
        print(colored("  INFOSTEALER MALWARE EXPOSURE SCAN", "yellow", attrs=["bold"]))
        print(colored("  ─────────────────────────────────────────────────", "yellow"))
        self._run_quiet(self.do_infostealer, f"email {arg}")

    def do_breach(self, arg):
        """Cross-reference email against known compromised data breach repositories.
        Usage: breach <email_address>"""
        self._cmd_banner('breach')
        if not arg:
            print(colored("  Usage: breach <address>  —  or type /help breach", "yellow"))
            return
        
        print(colored(f"  Checking breaches for {arg}...", "yellow"))
        try:
            res = self._api_get("/breach", params={'email': arg})
            if res.status_code == 200:
                d = res.json()
                if d.get('error'):
                    print(colored(f"  ✗ Check failed: {d['error']}", "red"))
                    return
                status = d.get('status', 'safe')
                breaches = d.get('breach_data', [])
                print()
                print(_box_top("BREACH LOOKUP"))
                print(_box_row("Email", arg))
                if status == 'safe':
                    print(_box_row("Status", "SECURE  ·  no known breach records", val_color="green"))
                else:
                    print(_box_row("Status", f"COMPROMISED  ·  {len(breaches)} breach(es) found", val_color="red"))
                for i, b in enumerate(breaches, 1):
                    name = b.get('breach') or b.get('name') or 'Unknown'
                    leak_date = str(b.get('xposed_date') or 'Unknown')
                    records = str(b.get('xposed_records') or 'Unknown')
                    label = f"BREACH {i}: {name}"
                    print(_box_section(label[:_BW - 5]))
                    print(_box_row("Date", leak_date))
                    print(_box_row("Records", records))
                print(_box_bot())
                print()
            else:
                print(colored(f"  ✗ Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_infostealer(self, arg):
        """Query Hudson Rock for infostealer malware log exposure.
        Usage: infostealer email <address>  |  infostealer username <handle>"""
        self._cmd_banner('infostealer')
        parts = (arg or "").split()
        if len(parts) < 2:
            print(colored("  Usage: infostealer email <address>  |  infostealer username <handle>", "yellow"))
            return
        kind, target = parts[0].lower(), " ".join(parts[1:]).strip()
        if kind not in ("email", "username"):
            print(colored("  First argument must be 'email' or 'username'.", "yellow"))
            return
        params = {'email': target} if kind == 'email' else {'username': target.lstrip('@')}
        print(colored(f"  Querying Hudson Rock for {kind} '{target}'...", "yellow"))
        try:
            res = self._api_get("/infostealer", params=params)
            d = res.json()
            if not d.get('success'):
                print(colored(f"  ✗ {d.get('error', 'Query failed')}", "red"))
                return
            print()
            print(_box_top("INFOSTEALER INTELLIGENCE"))
            print(_box_row("Target", target))
            print(_box_row("Source", "Hudson Rock"))
            status = d.get('status', 'unknown')
            if status in ('clean', 'not_found'):
                print(_box_row("Status", "No infostealer infections found", val_color="green"))
            else:
                print(_box_row("Infections", str(d.get('infection_count', 0)), val_color="red"))
                for i, inf in enumerate(d.get('infections', []), 1):
                    print(_box_section(f"INFECTION {i}"[:_BW - 5]))
                    print(_box_row("Stealer", str(inf.get('stealer_family', 'Unknown'))))
                    print(_box_row("Date", str(inf.get('date_compromised', 'Unknown'))))
                    print(_box_row("OS", str(inf.get('operating_system', 'Unknown'))))
                    if inf.get('top_logins'):
                        print(_box_row("Logins", ", ".join(inf['top_logins'][:3])))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_portscan(self, arg):
        """Run a TCP port scan against an IP.
        Usage: portscan <ip>"""
        self._cmd_banner('portscan')
        if not arg:
            print(colored("  Usage: portscan <ip>  —  or type /help portscan", "yellow"))
            return
        
        print(colored(f"  Scanning {arg}...", "yellow"))
        try:
            res = self._api_post("/scan/ports", json_body={'ip': arg}).json()
            results = res.get('results', [])
            if not results:
                print(colored("[-] No open ports found.", "red"))
            for p in results:
                print(colored(f"[+] Port {p['port']} ({p['service']}) is {p['status']}", "green"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

    def do_subdomain(self, arg):
        """Enumerate active subdomains.
        Usage: subdomain <domain>"""
        self._cmd_banner('subdomain')
        if not arg:
            print(colored("  Usage: subdomain <domain>  —  or type /help subdomain", "yellow"))
            return
        
        print(colored(f"  Enumerating {arg}...", "yellow"))
        try:
            res = self._api_post("/subdomain", json_body={'domain': arg}).json()
            results = res.get('results') or res.get('ct_subdomains') or []
            total = res.get('subdomain_count') or res.get('total') or len(results)
            live = res.get('live_subdomain_count', 0)
            if res.get('error') and not results:
                print(colored(f"[-] {res['error']}", "red"))
                return
            if not results:
                print(colored("[-] No subdomains found in CT logs.", "red"))
                return
            print(colored(f"[+] CT log subdomains: {total}  (live DNS: {live})", "green"))
            for s in results[:100]:
                host = s.get('subdomain') or s.get('url', '').replace('https://', '').replace('http://', '')
                url = s.get('url') or f"https://{host}"
                live_tag = "LIVE" if s.get('live') else "CT"
                tag_color = "green" if s.get('live') else "white"
                src = s.get('source')
                src_str = f" ({src})" if src else ""
                print(colored(f"    [{live_tag}] ", tag_color) + colored(host, "green") + colored(f"  →  {url}", "white") + colored(src_str, "yellow"))
            if total > 100:
                print(colored(f"    … and {total - 100} more (showing first 100)", "yellow"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

    def do_netscan(self, arg):
        """Scan a CIDR block for active hosts using ICMP ping.
        Usage: netscan <cidr>"""
        self._cmd_banner('netscan')
        if not arg:
            print(colored("  Usage: netscan <cidr>  —  or type /help netscan", "yellow"))
            return
        
        print(colored(f"  Scanning {arg}...", "yellow"))
        try:
            res = self._api_post("/scan/network", json_body={'cidr': arg})
            if res.status_code == 200:
                data = res.json()
                results = data.get('results', [])
                if not results:
                    print(colored("[-] No active hosts found.", "red"))
                for h in results:
                    print(colored(f"[+] Active: {h['ip']} ({h['hostname']})", "green"))
            else:
                print(colored(f"[-] Error: {res.text}", "red"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

    def do_hashcrack(self, arg):
        """Run dictionary attack against a hash.
        Usage: hashcrack <hash> <type> [wordlist] [salt=<salt>] [mode=prepend|append]
        type: md5 / sha1 / sha256 / sha512   (mode defaults to append when a salt is given)"""
        self._cmd_banner('hashcrack')
        args = arg.split()
        if len(args) < 2:
            print(colored("  Usage: hashcrack <hash> <type> [wordlist] [salt=..] [mode=prepend|append]  —  or /help hashcrack", "yellow"))
            return

        h, t = args[0], args[1].lower()
        if t not in ('md5', 'sha1', 'sha256', 'sha512'):
            print(colored("  [-] Invalid type. Supported: md5 / sha1 / sha256 / sha512.", "red"))
            return

        # Remaining tokens: salt=<value>, mode=<prepend|append>, or a bare wordlist path.
        wordlist_arg = None
        salt = None
        salt_mode = 'append'
        for tok in args[2:]:
            low = tok.lower()
            if low.startswith('salt='):
                salt = tok[len('salt='):]
            elif low.startswith('salt_mode='):
                salt_mode = tok[len('salt_mode='):].lower()
            elif low.startswith('mode='):
                salt_mode = tok[len('mode='):].lower()
            else:
                wordlist_arg = tok
        if salt_mode not in ('prepend', 'append'):
            print(colored("  [-] Invalid mode. Supported: prepend / append.", "red"))
            return

        try:
            from api.wordlists import get_wordlist_info
            wl = get_wordlist_info(wordlist_arg)
            if not wl['available']:
                print(colored("  [-] No wordlist found. Place rockyou.txt in project root.", "red"))
                return
            print(colored(f"  Using dictionary: {wl['name']} ({wl['line_count']:,} passwords)", "white"))
        except FileNotFoundError as exc:
            print(colored(f"  [-] {exc}", "red"))
            return
        if salt:
            print(colored(f"  Salt mode: {salt_mode} (salt applied to each candidate)", "white"))
        print(colored(f"  Cracking {t} hash...", "yellow"))
        try:
            payload = {'hash': h, 'type': t}
            if wordlist_arg:
                payload['wordlist'] = wordlist_arg
            if salt:
                payload['salt'] = salt
                payload['salt_mode'] = salt_mode
            res = self._api_post("/crack/hash", json_body=payload).json()
            if not res.get('job_id'):
                print(colored(f"[-] {res.get('error') or res.get('message') or 'Failed to start job'}", "red"))
                return
            data = poll_crack_job(self.api_url, f"/crack/hash/status/{res['job_id']}", self._api_headers())
            if data.get('status') == 'success':
                print(colored(f"[+] CRACKED: {data.get('password')}", "green", attrs=['bold']))
            else:
                print(colored(f"[-] {data.get('message') or data.get('error') or 'Not found'}", "red"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

    def do_pdfprotect(self, arg):
        """Secure PDF files with AES-256 password protection.
        Usage: pdfprotect <pdf_file_path> <password> [owner_password]
        owner_password is optional and defaults to the user password."""
        self._cmd_banner('pdfprotect')
        args = arg.split()
        if len(args) < 2:
            print(colored("  Usage: pdfprotect <file> <password> [owner_password]  —  or type /help pdfprotect", "yellow"))
            return

        filepath, password = args[0], args[1]
        owner_password = args[2] if len(args) > 2 else ''
        if not os.path.exists(filepath):
            print(colored(f"[-] File not found: {filepath}", "red"))
            return

        try:
            with open(filepath, 'rb') as f:
                files = {'file': f}
                data = {'password': password}
                if owner_password:
                    data['owner_password'] = owner_password
                res = self._api_post("/pdf/protect", files=files, data=data)
            if res.status_code == 200:
                out_path = os.path.splitext(filepath)[0] + "_protected.pdf"
                with open(out_path, 'wb') as out_f:
                    out_f.write(res.content)
                print(colored(f"[+] Protected PDF written to: {out_path}", "green"))
            else:
                print(colored(f"[-] Encryption failed: {res.text}", "red"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))

    def do_pdfcrack(self, arg):
        """Attempt to crack a PDF password using local dictionary attack.
        Usage: pdfcrack <pdf_file_path> [wordlist]"""
        self._cmd_banner('pdfcrack')
        if not arg:
            print(colored("  Usage: pdfcrack <file> [wordlist]  —  or type /help pdfcrack", "yellow"))
            return

        parts = arg.split(maxsplit=1)
        filepath = parts[0]
        wordlist_arg = parts[1] if len(parts) > 1 else None

        if not os.path.exists(filepath):
            print(colored(f"[-] File not found: {filepath}", "red"))
            return

        try:
            from api.wordlists import get_wordlist_info
            wl = get_wordlist_info(wordlist_arg)
            if not wl['available']:
                print(colored("  [-] No wordlist found. Place rockyou.txt in project root.", "red"))
                return
            print(colored(f"  Using dictionary: {wl['name']} ({wl['line_count']:,} passwords)", "white"))
        except FileNotFoundError as exc:
            print(colored(f"  [-] {exc}", "red"))
            return

        try:
            with open(filepath, 'rb') as f:
                files = {'file': f}
                data = {'wordlist': wordlist_arg} if wordlist_arg else {}
                res = self._api_post("/pdf/crack", files=files, data=data).json()
            if not res.get('job_id'):
                print(colored(f"[-] {res.get('error') or res.get('message') or 'Failed to start job'}", "red"))
                return
            data = poll_crack_job(self.api_url, f"/pdf/crack/status/{res['job_id']}", self._api_headers())
            if data.get('status') == 'success':
                print(colored(f"[+] SUCCESS! Recovered Password: {data.get('password')}", "green", attrs=['bold']))
            else:
                print(colored(f"[-] Failed: {data.get('message') or data.get('error') or 'Password not found'}", "red"))
        except Exception as e:
            print(colored(f"[-] Error: {str(e)}", "red"))
            
    # ─────────────────────────────────────────────────────────────
    # Recon / OSINT commands
    # ─────────────────────────────────────────────────────────────
    def do_deepuser(self, arg):
        """[Deprecated] Merged into username. Usage: username <handle>"""
        print(colored("  ⚠ deepuser merged into username — use: username <handle>", "yellow"))
        self.do_username(arg)

    def do_emailgoogle(self, arg):
        """Probe Google's public profile data (Gaia ID / name / avatar) for an email.
        Usage: emailgoogle <email>"""
        self._cmd_banner('emailgoogle')
        if not arg:
            print(colored("  Usage: emailgoogle <email>  —  or type /help emailgoogle", "yellow"))
            return
        email = arg.strip()
        print(colored(f"  Probing Google profile for {email}...", "yellow"))
        try:
            d = self._api_post("/recon/email/google", json_body={'email': email}, timeout=30).json()
            if not d.get('success'):
                print(colored(f"  ✗ {d.get('error', 'Probe failed')}", "red"))
                return
            print()
            print(_box_top("GOOGLE ACCOUNT PROBE"))
            print(_box_row("Email", email))
            print(_box_row("Found", "yes" if d.get('found') else "no",
                           val_color="green" if d.get('found') else "yellow"))
            print(_box_row("Name", d.get('name') or '—'))
            print(_box_row("Gaia ID", str(d.get('gaia_id') or '—')))
            print(_box_row("Avatar", d.get('photo_url') or '—'))
            if d.get('note'):
                print(_box_hint(f"↳ {d['note']}"))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_emailsmtp(self, arg):
        """Validate a mailbox via MX lookup + SMTP RCPT TO (sends no mail).
        Usage: emailsmtp <email>"""
        self._cmd_banner('emailsmtp')
        if not arg:
            print(colored("  Usage: emailsmtp <email>  —  or type /help emailsmtp", "yellow"))
            return
        email = arg.strip()
        print(colored(f"  Validating {email} via SMTP...", "yellow"))
        try:
            d = self._api_post("/recon/email/smtp", json_body={'email': email}, timeout=40).json()
            if not d.get('success'):
                print(colored(f"  ✗ {d.get('error', 'Validation failed')}", "red"))
                return
            deliverable = d.get('deliverable')
            if deliverable is True:
                dv, dc = "deliverable", "green"
            elif deliverable is False:
                dv, dc = "undeliverable", "red"
            else:
                dv, dc = "inconclusive", "yellow"
            print()
            print(_box_top("SMTP MAILBOX VALIDATION"))
            print(_box_row("Email", email))
            print(_box_row("Domain", d.get('domain', '—')))
            print(_box_row("MX Records", ', '.join(d.get('mx_records', [])) or '—'))
            print(_box_row("Deliverable", dv, val_color=dc))
            if d.get('smtp_code') is not None:
                print(_box_row("SMTP Code", str(d.get('smtp_code'))))
            if d.get('smtp_message'):
                print(_box_hint(f"↳ {d['smtp_message'][:_BW - 8]}"))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_portscan_async(self, arg):
        """Native asyncio TCP scan of an IP or CIDR with banner grabbing.
        Usage: portscan-async <ip|cidr> [ports]"""
        self._cmd_banner('portscan-async')
        if not arg:
            print(colored("  Usage: portscan-async <ip|cidr> [ports]  —  or type /help portscan-async", "yellow"))
            return
        parts = arg.split(maxsplit=1)
        target = parts[0]
        payload = {'ip': target}
        if len(parts) > 1:
            payload['ports'] = parts[1]
        print(colored(f"  Async-scanning {target}...", "yellow"))
        try:
            d = self._api_post("/recon/portscan-async", json_body=payload, timeout=300).json()
            if not d.get('success'):
                print(colored(f"  ✗ {d.get('error', 'Scan failed')}", "red"))
                return
            print()
            print(_box_top("ASYNC PORT SCAN"))
            print(_box_row("Target", d.get('target', target)))
            print(_box_row("Hosts", str(d.get('hosts_scanned', 0))))
            print(_box_row("Ports/host", str(d.get('ports_scanned', 0))))
            results = d.get('results', [])
            if not results:
                print(_box_hint("No responsive hosts found"))
            for host in results:
                openp = host.get('open_ports', [])
                print(_box_section(f"{host.get('ip', '?')}  ·  {host.get('status', '')}"[:_BW - 5]))
                if not openp:
                    print(_box_hint("no open ports"))
                for p in openp:
                    label = f"{p['port']}/{p.get('service', '')}"
                    banner = p.get('banner') or 'open'
                    print(_box_row(label[:14], banner, val_color="green"))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_maclookup(self, arg):
        """Resolve a MAC address to its manufacturer (IEEE OUI database).
        Usage: maclookup <mac>"""
        self._cmd_banner('maclookup')
        if not arg:
            print(colored("  Usage: maclookup <mac>  —  or type /help maclookup", "yellow"))
            return
        mac = arg.strip()
        print(colored(f"  Resolving {mac}...", "yellow"))
        try:
            d = self._api_post("/recon/mac", json_body={'mac': mac}, timeout=60).json()
            if not d.get('success'):
                print(colored(f"  ✗ {d.get('error', 'Lookup failed')}", "red"))
                return
            print()
            print(_box_top("MAC VENDOR LOOKUP"))
            print(_box_row("MAC", d.get('mac', mac)))
            print(_box_row("OUI", d.get('oui', '—')))
            print(_box_row("Manufacturer", d.get('manufacturer', '—'), val_color="green"))
            print(_box_hint(f"↳ source: {d.get('source', 'unknown')}"))
            print(_box_bot())
            print()
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))

    def do_dork(self, arg):
        """Generate ready-to-click Google dork URLs for a username (offline).
        Usage: dork <username>"""
        self._cmd_banner('dork')
        if not arg:
            print(colored("  Usage: dork <username>  —  or type /help dork", "yellow"))
            return
        handle = arg.strip().lstrip('@')
        try:
            # Pure offline string generation — no network required.
            from api.modules.recon import generate_username_dorks
            d = generate_username_dorks(handle)
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))
            return
        if not d.get('success'):
            print(colored(f"  ✗ {d.get('error', 'Generation failed')}", "red"))
            return
        print()
        print(_box_top("USERNAME DORKING"))
        print(_box_row("Username", f"@{handle}"))
        print(_box_row("Dorks", str(d.get('total', 0))))
        print(_box_bot())
        for cat in d.get('categories', []):
            print(colored(f"\n  ▸ {cat['name']}", "yellow", attrs=["bold"]))
            for dork in cat.get('dorks', []):
                print(colored(f"    {dork['label']:<18}", "white") + colored(dork['url'], "green"))

        print()
        print(colored("  Searching with random delays to avoid blocks...", "yellow"))
        print(colored(
            "  ▸ DuckDuckGo live results (may take 30-60s due to rate-limit protection)...",
            "yellow", attrs=["bold"],
        ))
        try:
            from api.modules.search_engines import DualSearchEngine
            live = DualSearchEngine().search_username(handle)
            if live.get('warnings'):
                for warn in live['warnings']:
                    print(colored(f"    ⚠ {warn}", "yellow"))
            links = live.get('combined_links', [])
            if not links:
                print(colored("    No DuckDuckGo links returned.", "white"))
            else:
                current_platform = None
                for link in links:
                    platform = link.get('platform', 'web')
                    if platform != current_platform:
                        current_platform = platform
                        print(colored(f"\n    [{platform}]", "cyan", attrs=["bold"]))
                    print(colored(f"      {link.get('url', '')}", "green"))
            print()
        except Exception as e:
            print(colored(f"  ✗ DuckDuckGo search error: {str(e)}", "red"))
            print()

    def do_emailsite(self, arg):
        """Harvest public emails from a domain via DuckDuckGo + Google dork.
        Usage: emailsite <domain>"""
        self._cmd_banner('emailsite')
        if not arg:
            print(colored("  Usage: emailsite <domain>  —  or type /help emailsite", "yellow"))
            return
        domain = arg.strip()
        print(colored("  Searching with random delays to avoid blocks...", "yellow"))
        print(colored(
            "  Harvesting public emails (may take 15-30s due to rate-limit protection)...",
            "yellow",
        ))
        try:
            from api.modules.search_engines import DualSearchEngine
            d = DualSearchEngine().search_emails_in_domain(domain)
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))
            return
        if not d.get('success'):
            print(colored(f"  ✗ {d.get('error', 'Harvest failed')}", "red"))
            return
        print()
        print(_box_top("DOMAIN EMAIL HARVEST"))
        print(_box_row("Domain", d.get('domain', domain)))
        print(_box_row("Emails Found", str(len(d.get('emails', [])))))
        print(_box_bot())
        if d.get('google_dork_url'):
            print(colored("\n  ▸ Google dork (manual fallback if CAPTCHA):", "yellow", attrs=["bold"]))
            print(colored(f"    {d['google_dork_url']}", "green"))
        if d.get('warnings'):
            for warn in d['warnings']:
                print(colored(f"  ⚠ {warn}", "yellow"))
        emails = d.get('emails', [])
        if emails:
            print(colored("\n  ▸ Emails discovered:", "yellow", attrs=["bold"]))
            for addr in emails:
                print(colored(f"    {addr}", "green"))
        else:
            print(colored("\n  No emails extracted from DuckDuckGo results.", "white"))
        print()

    def do_domaincrawl(self, arg):
        """Async deep-domain web crawler — emails, phones, social links.
        Usage: domaincrawl <domain> [max_depth]"""
        self._cmd_banner('domaincrawl')
        parts = (arg or '').split()
        if not parts:
            print(colored("  Usage: domaincrawl <domain> [max_depth]  —  or type /help domaincrawl", "yellow"))
            return
        domain = parts[0].strip()
        max_depth = 2
        if len(parts) > 1:
            try:
                max_depth = int(parts[1])
            except ValueError:
                print(colored("  ✗ max_depth must be an integer.", "red"))
                return
        print(colored("  Crawling domain (async BFS, may take 30-90s)...", "yellow"))
        try:
            from api.modules.domain_crawler import crawl_domain_sync
            d = crawl_domain_sync(domain, max_depth=max_depth, max_pages=30)
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))
            return
        if not d.get('success'):
            print(colored(f"  ✗ {d.get('error', 'Crawl failed')}", "red"))
            return
        print()
        print(_box_top("DEEP DOMAIN CRAWL"))
        print(_box_row("Domain", d.get('domain', domain)))
        print(_box_row("Pages", str(d.get('total_pages', 0))))
        print(_box_row("Emails", str(len(d.get('all_emails', [])))))
        print(_box_bot())
        for page in d.get('pages_crawled', [])[:15]:
            print(colored(f"\n  ▸ {page.get('url', '')}", "yellow", attrs=["bold"]))
            if page.get('title'):
                print(colored(f"    Title: {page['title'][:80]}", "white"))
            if page.get('emails'):
                for addr in page['emails']:
                    print(colored(f"    ✉ {addr}", "green"))
            if page.get('phones'):
                for ph in page['phones'][:5]:
                    print(colored(f"    ☎ {ph}", "cyan"))
        if len(d.get('pages_crawled', [])) > 15:
            print(colored(f"\n  … and {len(d['pages_crawled']) - 15} more pages", "white"))
        print()

    def do_githubintel(self, arg):
        """GitHub commit email / repo metadata extractor.
        Usage: githubintel <username|domain>"""
        self._cmd_banner('githubintel')
        target = (arg or '').strip()
        if not target:
            print(colored("  Usage: githubintel <username|domain>  —  or type /help githubintel", "yellow"))
            return
        try:
            from api.modules.github_intel import extract_github_by_domain, extract_github_intel
            if "." in target and not target.startswith("@"):
                d = extract_github_by_domain(target)
            else:
                d = extract_github_intel(target.lstrip("@"))
        except Exception as e:
            print(colored(f"  ✗ Error: {str(e)}", "red"))
            return
        if not d.get('success'):
            print(colored(f"  ✗ {d.get('error', 'GitHub intel failed')}", "red"))
            return
        print()
        label = d.get('username') or d.get('domain', target)
        print(_box_top("GITHUB INTEL"))
        print(_box_row("Target", label))
        print(_box_row("Emails", str(len(d.get('emails', [])))))
        if d.get('repos'):
            print(_box_row("Repos", str(len(d['repos']))))
        print(_box_bot())
        if d.get('warnings'):
            for warn in d['warnings']:
                print(colored(f"  ⚠ {warn}", "yellow"))
        for addr in d.get('emails', []):
            print(colored(f"  ✉ {addr}", "green"))
        for repo in (d.get('repos') or [])[:10]:
            print(colored(f"  📦 {repo}", "cyan"))
        print()

    # ─────────────────────────────────────────────────────────────
    # Tor OpSec engine (CLI only)
    # ─────────────────────────────────────────────────────────────
    _TOR_SOCKS_HOST = '127.0.0.1'
    _TOR_SOCKS_PORT = 9050
    _TOR_CONTROL_PORT = 9051
    _TORRC_PATH = '/etc/tor/torrc'

    @staticmethod
    def _tor_socket_open(host='127.0.0.1', port=9050, timeout=2):
        """Return True if a Tor SOCKS port is accepting connections."""
        import socket
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _tor_wait_for_port(host='127.0.0.1', port=9050, timeout=30) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if LEAConsole._tor_socket_open(host, port, timeout=1):
                return True
            time.sleep(0.5)
        return False

    @staticmethod
    def _tor_run_cmd(cmd, timeout=120):
        """Run a subprocess; return (ok, combined_output)."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = (r.stdout or '') + (r.stderr or '')
            return r.returncode == 0, out.strip()
        except subprocess.TimeoutExpired:
            return False, 'command timed out'
        except Exception as exc:
            return False, str(exc)

    def _tor_confirm(self, prompt: str, default_yes: bool = False) -> bool:
        if not sys.stdin.isatty():
            return False
        suffix = 'Y/n' if default_yes else 'y/N'
        try:
            ans = input(colored(f"  {prompt} [{suffix}] › ", "yellow")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            raise
        if not ans:
            return default_yes
        return ans in ('y', 'yes')

    @staticmethod
    def _tor_apply_torrc_settings(content: str) -> str:
        """Idempotently ensure ControlPort 9051 and CookieAuthentication 0."""
        control_re = re.compile(r'^\s*#?\s*ControlPort\s+', re.I)
        cookie_re = re.compile(r'^\s*#?\s*CookieAuthentication\s+', re.I)
        out: list[str] = []
        has_control = has_cookie = False
        for line in content.splitlines():
            if control_re.match(line):
                if not has_control:
                    out.append('ControlPort 9051')
                    has_control = True
                continue
            if cookie_re.match(line):
                if not has_cookie:
                    out.append('CookieAuthentication 0')
                    has_cookie = True
                continue
            out.append(line)
        if not has_control:
            out.append('ControlPort 9051')
        if not has_cookie:
            out.append('CookieAuthentication 0')
        text = '\n'.join(out)
        if content.endswith('\n') or not content:
            text += '\n'
        return text

    def _tor_configure_torrc_linux(self) -> bool:
        ok, current = self._tor_run_cmd(['sudo', 'cat', self._TORRC_PATH], timeout=30)
        if not ok:
            print(colored(f"  ✗ Could not read {self._TORRC_PATH}: {current}", "red"))
            return False
        updated = self._tor_apply_torrc_settings(current)
        if updated == current:
            print(colored("  Tor control port already configured in torrc.", "white"))
            return True
        tmp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.torrc.argus.tmp')
        try:
            with open(tmp_path, 'w', encoding='utf-8') as fh:
                fh.write(updated)
            ok, err = self._tor_run_cmd(['sudo', 'cp', tmp_path, self._TORRC_PATH], timeout=30)
            if not ok:
                print(colored(f"  ✗ Could not update torrc: {err}", "red"))
                return False
            print(colored("  ✓ Updated /etc/tor/torrc (ControlPort 9051, CookieAuthentication 0)", "green"))
            return True
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _tor_restart_linux(self) -> bool:
        last_err = ''
        for cmd in (
            ['sudo', 'systemctl', 'restart', 'tor'],
            ['sudo', '/etc/init.d/tor', 'restart'],
        ):
            ok, out = self._tor_run_cmd(cmd, timeout=60)
            if ok:
                print(colored(f"  ✓ Tor restarted ({cmd[1]})", "green"))
                return True
            last_err = out
        print(colored(f"  ✗ Tor restart failed: {last_err}", "red"))
        return False

    def _tor_windows_unsupported(self) -> None:
        print()
        print(colored("  Tor OpSec is not supported on Windows CLI.", "red", attrs=["bold"]))
        print(colored("  Use Kali Linux, Ubuntu, or another Linux distribution for Tor routing.", "white"))
        print(colored("  ARGUS GUI on Windows can run tools in ad-hoc mode without Tor.", "yellow"))
        print()

    def _tor_install_guidance(self) -> None:
        print(colored("  Manual Tor setup:", "yellow"))
        print(colored("    macOS:  brew install tor && brew services start tor", "white"))
        print(colored("    Debian/Ubuntu/Kali:", "white"))
        print(colored("      sudo apt install tor", "white"))
        print(colored("      # /etc/tor/torrc — ControlPort 9051, CookieAuthentication 0", "white"))
        print(colored("      sudo systemctl restart tor", "white"))
        print(colored("    Test: curl ifconfig.me  vs  torify curl ifconfig.me", "white"))
        print(colored("    Rotate: tor rotate  (SIGNAL NEWNYM on control port 9051)", "white"))

    def _tor_install_other_linux(self) -> None:
        print()
        print(colored("  Automatic Tor install requires apt (Debian/Ubuntu/Kali).", "yellow"))
        print(colored("  Install Tor with your package manager, then configure torrc:", "white"))
        print(colored("    Fedora/RHEL:  sudo dnf install tor && sudo systemctl enable --now tor", "white"))
        print(colored("    Arch:         sudo pacman -S tor && sudo systemctl enable --now tor", "white"))
        print(colored("  In /etc/tor/torrc set ControlPort 9051 and CookieAuthentication 0", "white"))
        self._tor_install_guidance()

    @staticmethod
    def _tor_brew_bin_dirs() -> list[str]:
        """Homebrew bin directories — Apple Silicon first on arm64, Intel first otherwise."""
        arm = platform.machine().lower() in ('arm64', 'aarch64')
        if arm:
            return ['/opt/homebrew/bin', '/usr/local/bin']
        return ['/usr/local/bin', '/opt/homebrew/bin']

    def _tor_refresh_brew_path(self) -> bool:
        """Prepend Homebrew bin dir to PATH for this session if brew exists there."""
        for d in self._tor_brew_bin_dirs():
            brew_exe = os.path.join(d, 'brew')
            if os.path.isfile(brew_exe) and os.access(brew_exe, os.X_OK):
                path = os.environ.get('PATH', '')
                if d not in path.split(os.pathsep):
                    os.environ['PATH'] = d + os.pathsep + path
                return True
        for d in self._tor_brew_bin_dirs():
            path = os.environ.get('PATH', '')
            if os.path.isdir(d) and d not in path.split(os.pathsep):
                os.environ['PATH'] = d + os.pathsep + path
        return bool(shutil.which('brew'))

    def _tor_ensure_homebrew(self) -> bool:
        """Install Homebrew on macOS when brew is missing. Linux/Windows never call this."""
        if shutil.which('brew') or self._tor_refresh_brew_path():
            return True

        print()
        print(colored("  Homebrew is required to install Tor on macOS.", "yellow", attrs=["bold"]))
        print(colored("  ARGUS can install Homebrew for you, or you can install it manually.", "white"))
        print()
        print(colored("  Official install command:", "white"))
        print(colored(
            '    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
            "white",
        ))
        print()

        try:
            if not self._tor_confirm('Install Homebrew now?', default_yes=False):
                print(colored("  Install Homebrew manually: https://brew.sh", "white"))
                print(colored("  Then run: brew install tor && brew services start tor", "white"))
                return False
        except (KeyboardInterrupt, EOFError):
            print()
            return False

        print(colored("  Homebrew install may take several minutes.", "yellow"))
        print(colored("  macOS may prompt for your password in this terminal.", "yellow"))
        print()

        try:
            r = subprocess.run(
                [
                    '/bin/bash', '-c',
                    'curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash',
                ],
                timeout=600,
            )
        except KeyboardInterrupt:
            print()
            print(colored("  Homebrew install cancelled.", "yellow"))
            return False
        except subprocess.TimeoutExpired:
            print(colored("  ✗ Homebrew install timed out after 10 minutes.", "red"))
            print(colored("  Install manually: https://brew.sh", "white"))
            return False

        if r.returncode != 0:
            print(colored(f"  ✗ Homebrew install failed (exit {r.returncode}).", "red"))
            print(colored("  Install manually: https://brew.sh", "white"))
            return False

        if not self._tor_refresh_brew_path():
            print(colored("  ✗ brew not found after install.", "red"))
            print(colored("  Add Homebrew to your PATH per https://brew.sh then re-run: tor on", "white"))
            return False

        print(colored("  ✓ Homebrew installed.", "green"))
        return True

    def _tor_install_macos(self, from_tor_on: bool = False) -> bool:
        if not shutil.which('brew') and not self._tor_ensure_homebrew():
            self._tor_install_guidance()
            return False
        if not self._tor_confirm('Install Tor via Homebrew now?', default_yes=from_tor_on):
            print(colored("  Tor install skipped.", "yellow"))
            self._tor_install_guidance()
            return False
        print(colored("  Installing Tor via Homebrew (may take a few minutes)...", "yellow"))
        ok, out = self._tor_run_cmd(['brew', 'install', 'tor'], timeout=600)
        if not ok:
            print(colored(f"  ✗ brew install tor failed: {out}", "red"))
            self._tor_install_guidance()
            return False
        ok, out = self._tor_run_cmd(['brew', 'services', 'start', 'tor'], timeout=60)
        if not ok:
            print(colored(f"  ✗ brew services start tor failed: {out}", "red"))
            self._tor_install_guidance()
            return False
        print(colored("  Waiting for Tor SOCKS port 9050...", "yellow"))
        if self._tor_wait_for_port(self._TOR_SOCKS_HOST, self._TOR_SOCKS_PORT, timeout=30):
            print(colored("  ✓ Tor is running on 127.0.0.1:9050", "green"))
            return True
        print(colored("  ✗ Tor installed but port 9050 not reachable within 30s.", "red"))
        print(colored("  Try: brew services restart tor", "white"))
        self._tor_install_guidance()
        return False

    def _tor_install_linux_apt(self, from_tor_on: bool = False) -> bool:
        if not shutil.which('apt-get'):
            self._tor_install_other_linux()
            return False
        if not self._tor_confirm('Install and configure Tor now?', default_yes=False):
            print(colored("  Tor install skipped.", "yellow"))
            self._tor_install_guidance()
            return False
        print(colored("  sudo may prompt for your password in this terminal.", "yellow"))
        print(colored("  Installing Tor via apt...", "yellow"))
        ok, out = self._tor_run_cmd(['sudo', 'apt-get', 'update', '-qq'], timeout=180)
        if not ok:
            print(colored(f"  ✗ apt-get update failed: {out}", "red"))
            self._tor_install_guidance()
            return False
        ok, out = self._tor_run_cmd(
            ['sudo', 'apt-get', 'install', '-y', 'tor'], timeout=600,
        )
        if not ok:
            print(colored(f"  ✗ apt-get install tor failed: {out}", "red"))
            self._tor_install_guidance()
            return False
        print(colored("  ✓ Tor package installed", "green"))
        if not self._tor_configure_torrc_linux():
            self._tor_install_guidance()
            return False
        if not self._tor_restart_linux():
            self._tor_install_guidance()
            return False
        print(colored("  Waiting for Tor SOCKS port 9050...", "yellow"))
        if self._tor_wait_for_port(self._TOR_SOCKS_HOST, self._TOR_SOCKS_PORT, timeout=30):
            print(colored("  ✓ Tor is running on 127.0.0.1:9050", "green"))
            return True
        print(colored("  ✗ Tor restarted but port 9050 not reachable within 30s.", "red"))
        print(colored("  Check: sudo systemctl status tor", "white"))
        self._tor_install_guidance()
        return False

    def _tor_ensure_running(self, from_tor_on: bool = False) -> bool:
        """Install/start Tor when missing. Returns True if SOCKS port is up."""
        if self._tor_socket_open(self._TOR_SOCKS_HOST, self._TOR_SOCKS_PORT):
            return True
        system = platform.system()
        if system == 'Windows':
            self._tor_windows_unsupported()
            return False
        if system == 'Darwin':
            return self._tor_install_macos(from_tor_on=from_tor_on)
        if system == 'Linux':
            if shutil.which('apt-get'):
                return self._tor_install_linux_apt(from_tor_on=from_tor_on)
            self._tor_install_other_linux()
            return False
        print(colored(f"  Unsupported platform for auto-install: {system}", "yellow"))
        self._tor_install_guidance()
        return False

    def _tor_leak_check(self):
        """Compare direct vs proxied exit IP. Returns (ok, exit_ip, direct_ip, err)."""
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050',
        }
        direct_ip = None
        try:
            direct_ip = requests.get('https://api.ipify.org', timeout=8).text.strip()
        except Exception:
            direct_ip = None
        try:
            exit_ip = requests.get('https://api.ipify.org', proxies=proxies, timeout=20).text.strip()
        except Exception as exc:
            return False, None, direct_ip, str(exc)
        ok = bool(exit_ip) and exit_ip != direct_ip
        return ok, exit_ip, direct_ip, None

    def _tor_rotate_via_nc(self) -> Optional[Tuple[bool, str]]:
        nc_bin = shutil.which('nc') or shutil.which('ncat') or shutil.which('netcat')
        if not nc_bin:
            return None
        wait_flag = '-w 3' if os.path.basename(nc_bin) in ('nc', 'netcat') else '--wait 3'
        script = (
            f"echo -e 'AUTHENTICATE \"\"\r\nsignal NEWNYM\r\nQUIT' | "
            f"{nc_bin} {wait_flag} {self._TOR_SOCKS_HOST} {self._TOR_CONTROL_PORT}"
        )
        ok, out = self._tor_run_cmd(['/bin/sh', '-c', script], timeout=10)
        if ok and '250' in out:
            return True, 'SIGNAL NEWNYM accepted (control port)'
        if '250' in out:
            return True, out
        return False, out or 'nc control port command failed'

    def _tor_rotate(self):
        """Best-effort circuit rotation via control port 9051 (SIGNAL NEWNYM)."""
        nc_result = self._tor_rotate_via_nc()
        if nc_result is not None:
            return nc_result
        import socket
        try:
            with socket.create_connection(
                (self._TOR_SOCKS_HOST, self._TOR_CONTROL_PORT), timeout=3,
            ) as s:
                s.sendall(b'AUTHENTICATE ""\r\n')
                if b'250' not in s.recv(1024):
                    return False, "control port auth failed (cookie/password set?)"
                s.sendall(b'SIGNAL NEWNYM\r\n')
                resp = s.recv(1024)
                return (b'250' in resp), resp.decode('utf-8', errors='ignore').strip()
        except Exception as exc:
            return False, f"control port {self._TOR_CONTROL_PORT} unavailable: {exc}"

    def _tor_enable_proxy(self) -> None:
        from api.config import Config
        if not self._tor_socket_open(self._TOR_SOCKS_HOST, self._TOR_SOCKS_PORT):
            if not self._tor_ensure_running(from_tor_on=True):
                return
        Config.set_proxy_enabled(True)
        print(colored("  Tor proxy ENABLED. Running leak check...", "yellow"))
        ok, exit_ip, direct_ip, err = self._tor_leak_check()
        if ok:
            print(colored(f"  ✓ OPSEC OK — traffic routed via Tor exit node {exit_ip}", "green", attrs=["bold"]))
            if direct_ip:
                print(colored(f"    (your real IP {direct_ip} is masked)", "white"))
                print(colored("    Compare: curl ifconfig.me  vs  torify curl ifconfig.me", "white"))
        else:
            Config.set_proxy_enabled(False)
            if err:
                print(colored(f"  ✗ CRITICAL OPSEC BREACH — proxy unreachable: {err}", "red", attrs=["bold"]))
                print(colored("    Is PySocks installed and Tor running? Proxy DISABLED for safety.", "yellow"))
            else:
                print(colored(f"  ✗ CRITICAL OPSEC BREACH — real IP {direct_ip} leaked! Proxy DISABLED.", "red", attrs=["bold"]))

    def do_tor(self, arg):
        """Tor OpSec engine — route outbound traffic through Tor (CLI only).
        Usage: tor [on|off|status|rotate]"""
        self._cmd_banner('tor')
        from api.config import Config
        action = (arg or '').strip().lower()

        if action in ('', 'status'):
            running = self._tor_socket_open(self._TOR_SOCKS_HOST, self._TOR_SOCKS_PORT)
            print()
            print(_box_top("TOR OPSEC STATUS"))
            print(_box_row("Proxy", "ENABLED" if Config.is_proxy_enabled() else "DISABLED",
                           val_color="green" if Config.is_proxy_enabled() else "yellow"))
            print(_box_row("Tor daemon", "detected (127.0.0.1:9050)" if running else "not detected",
                           val_color="green" if running else "red"))
            print(_box_row("Route", Config.TOR_PROXY if Config.is_proxy_enabled() else "direct (clearnet)"))
            if platform.system() == 'Windows':
                print(_box_hint("Windows CLI: Tor not supported — use Kali/Ubuntu/Linux"))
            else:
                print(_box_hint("tor on auto-installs on Linux/macOS · tor rotate for NEWNYM"))
            print(_box_hint("Commands: tor on · tor off · tor status · tor rotate"))
            print(_box_bot())
            print()
            return

        if action == 'on':
            if platform.system() == 'Windows':
                self._tor_windows_unsupported()
                return
            self._tor_enable_proxy()
            return

        if action == 'off':
            Config.set_proxy_enabled(False)
            print(colored("  Tor proxy DISABLED — outbound traffic now goes direct (clearnet).", "yellow"))
            return

        if action in ('rotate', 'newnym', 'new'):
            ok, msg = self._tor_rotate()
            if ok:
                print(colored("  ✓ New Tor circuit requested (SIGNAL NEWNYM).", "green"))
            else:
                print(colored(f"  Circuit rotation unavailable: {msg}", "yellow"))
                print(colored("  Ensure ControlPort 9051 and CookieAuthentication 0 in torrc.", "white"))
            return

        print(colored("  Usage: tor [on|off|status|rotate]", "yellow"))
        print(colored("  Auto-install: Linux (apt) and macOS (Homebrew). Windows: use Linux.", "white"))

    def do_status(self, arg):
        """Show API key configuration and system health. Usage: status  |  /status"""
        keys = get_api_keys()
        print()
        print(_box_top("SYSTEM STATUS"))
        print(_box_row("Platform", "ARGUS  ·  Advanced Intelligence Platform"))
        print(_box_row("Version", "v3.0.0  ·  LEA Edition"))
        print(_box_row("API Server", f"http://127.0.0.1:{self.port}"))
        print(_box_row("Session ID", self.session_id[:16]))
        _tool_count = len(self.FEATURES)
        _mod_count = len({f['module'] for f in self.FEATURES})
        print(_box_row("Modules", f"{_tool_count} tools across {_mod_count} modules"))
        print(_box_section("API KEY STATUS"))

        checks = [
            ("VIRUSTOTAL_API_KEY",         keys['vt'],        False, "VirusTotal"),
            ("ABUSEIPDB_API_KEY",          keys['abuse'],     False, "AbuseIPDB"),
            ("TRUECALLER_INSTALLATION_ID", keys['truecaller'],True,  "Truecaller"),
        ]
        for k_name, k_val, is_tc, display in checks:
            status, hint = check_key_status(k_name, k_val, is_tc=is_tc)
            if "✓" in status and "DEMO" not in status:
                sc = "green"
            elif "DEMO" in status:
                sc = "yellow"
            else:
                sc = "red"
            print(_box_row(display, status, val_color=sc))
            if hint:
                short = hint if len(hint) <= _BW - 8 else hint[:_BW - 9] + '…'
                print(_box_hint(f"↳ {short}"))

        print(_box_section("CHAIN OF CUSTODY"))
        print(_box_row("Audit Log", "audit.log  ·  active"))
        print(_box_row("Logging", "all operations captured"))
        print(_box_bot())
        print()

    def do_case(self, arg):
        """Investigation case management. Usage: case new|list|open <id>|close <id>|status|off"""
        parts = (arg or '').split(None, 1)
        sub = parts[0].lower() if parts else 'status'
        rest = parts[1].strip() if len(parts) > 1 else ''

        if sub == 'off':
            if not self.case_mode_enabled:
                print(colored("  Case mode is already disabled (ad-hoc mode).", "yellow"))
                return
            try:
                ans = input(colored("  Disable case mode for this session? [y/N] › ", "yellow")).strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                return
            if ans in ('y', 'yes'):
                self.case_mode_enabled = False
                self.active_case_id = None
                print(colored("  Case mode disabled — ad-hoc mode for remainder of session.", "green"))
            return

        if sub == 'new':
            if not self.case_mode_enabled:
                if not self._ensure_case_mode_enabled("create case"):
                    return
            try:
                title = rest or input(colored("  Case title: ", "yellow")).strip()
                auth_ref = input(colored("  Authorization ref (warrant/court order): ", "yellow")).strip()
                legal = input(colored("  Legal basis: ", "yellow")).strip()
                r = self._api_post("/cases", json_body={
                    'title': title,
                    'authorization_ref': auth_ref,
                    'legal_basis': legal,
                })
                if r.status_code in (200, 201):
                    case = r.json().get('case', {})
                    self.active_case_id = case.get('case_id')
                    self.case_mode_enabled = True
                    self._api_post(f"/cases/{self.active_case_id}/activate")
                    print(colored(f"  ✓ Case created: {self.active_case_id}", "green"))
                else:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return

        if sub == 'list':
            try:
                r = self._api_get("/cases")
                if r.status_code != 200:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                    return
                cases = r.json().get('cases', [])
                if not cases:
                    print(colored("  No cases. Create one with: case new", "yellow"))
                    return
                print(_box_top("CASES"))
                for c in cases:
                    active = ' *' if c.get('case_id') == self.active_case_id else ''
                    print(_box_row(c.get('case_id', ''), f"{c.get('status','')} — {c.get('title','')}{active}"))
                print(_box_bot())
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return

        if sub == 'open':
            if not self.case_mode_enabled:
                if not self._ensure_case_mode_enabled("open case"):
                    return
            if not rest:
                print(colored("  Usage: case open <case_id>", "yellow"))
                return
            try:
                r = self._api_post(f"/cases/{rest}/activate")
                if r.status_code == 200:
                    self.active_case_id = rest
                    self.case_mode_enabled = True
                    print(colored(f"  ✓ Active case: {rest}", "green"))
                else:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return

        if sub == 'close':
            if not rest:
                print(colored("  Usage: case close <case_id>", "yellow"))
                return
            try:
                r = self._api_patch(f"/cases/{rest}", json_body={'status': 'closed'})
                if r.status_code == 200:
                    print(colored(f"  ✓ Case closed: {rest}", "green"))
                    if self.active_case_id == rest:
                        self.active_case_id = None
                else:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return

        if sub == 'status':
            if not self.case_mode_enabled:
                print(colored("  Case mode: disabled (ad-hoc mode)", "white"))
                print(colored("  Use 'case new' to enable case mode mid-session.", "yellow"))
                return
            if self.active_case_id:
                try:
                    r = self._api_get(f"/cases/{self.active_case_id}")
                    if r.status_code == 200:
                        c = r.json().get('case', {})
                        print(_box_top("ACTIVE CASE"))
                        print(_box_row("Case ID", c.get('case_id', '')))
                        print(_box_row("Title", c.get('title', '')))
                        print(_box_row("Auth Ref", c.get('authorization_ref', '—')))
                        print(_box_row("Status", c.get('status', '')))
                        print(_box_bot())
                    else:
                        print(colored(f"  Active: {self.active_case_id}", "white"))
                except Exception:
                    print(colored(f"  Active: {self.active_case_id}", "white"))
            else:
                print(colored("  No active case. Use: case new", "yellow"))
            return

        print(colored("  Usage: case new | list | open <id> | close <id> | status | off", "yellow"))

    def do_keys(self, arg):
        """API key vault. Usage: keys list | keys set <service> <value> | keys reset truecaller"""
        parts = (arg or '').split()
        if not parts or parts[0].lower() == 'list':
            try:
                from api.vault import list_key_status
                status = list_key_status()
                print(_box_top("API VAULT"))
                for k, v in status.items():
                    sc = "green" if v == "CONFIGURED" else "red"
                    print(_box_row(k, v, val_color=sc))
                print(_box_bot())
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return
        if parts[0].lower() == 'set' and len(parts) >= 3:
            service, value = parts[1], ' '.join(parts[2:])
            try:
                r = self._api_post("/vault/keys", json_body={'service': service, 'value': value})
                if r.status_code == 200:
                    print(colored(f"  ✓ Key stored for {service}", "green"))
                else:
                    print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
            except Exception as exc:
                print(colored(f"  ✗ {exc}", "red"))
            return
        # ── keys reset truecaller  ──────────────────────────────────────
        if parts[0].lower() == 'reset' and len(parts) >= 2 and parts[1].lower() == 'truecaller':
            print(colored("  Clearing saved Truecaller ID and re-running setup…", "yellow"))
            # wipe existing vault entry first
            try:
                self._api_post("/vault/keys", json_body={'service': 'truecaller', 'value': ''})
            except Exception:
                pass
            self.truecaller_phone_enabled = None  # reset session cache
            self._ensure_truecaller_token(force=True)
            return
        print(colored("  Usage: keys list | keys set <vt|abuse|truecaller> <value> | keys reset truecaller", "yellow"))

    def do_truecaller_setup(self, arg):
        """Re-run the Truecaller login/OTP flow to obtain a fresh installation ID.
        Usage: truecaller-setup"""
        self._cmd_banner('truecaller-setup')
        print(colored("  This will re-run the Truecaller login flow.", "yellow"))
        print(colored("  ⚠  You need to be ONLINE — an OTP will be sent to your number.", "yellow"))
        print(colored("     Your number is only used to get the installation ID, nothing else.", "white"))
        print()
        try:
            confirm = input(colored("  Continue? [y/N] › ", "yellow")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if confirm not in ("y", "yes"):
            print(colored("  Cancelled.", "white"))
            return
        # clear old vault entry so _ensure_truecaller_token runs the full flow
        try:
            self._api_post("/vault/keys", json_body={'service': 'truecaller', 'value': ''})
        except Exception:
            pass
        self.truecaller_phone_enabled = None
        token = self._ensure_truecaller_token(force=True)
        if token:
            print(colored("  ✓ Truecaller setup complete — ready to use.", "green"))
        else:
            print(colored("  ✗ Setup did not complete. Try again or check your internet.", "red"))

    def do_export(self, arg):
        """Export evidence. Usage: export case | export last [json|html]"""
        parts = (arg or 'last').split()
        scope = parts[0].lower() if parts else 'last'
        fmt = parts[1].lower() if len(parts) > 1 else 'json'
        if scope not in ('case', 'last'):
            print(colored("  Usage: export case [json|html] | export last [json|html]", "yellow"))
            return
        if scope == 'case':
            if not self.case_mode_enabled:
                print(colored(
                    "  Case mode was disabled this session. Re-start and choose yes to enable exports.",
                    "yellow",
                ))
                return
            if not self.active_case_id:
                print(colored("  No active case. Use: case open <id>", "red"))
                return
        try:
            payload = {'scope': scope, 'format': fmt}
            if scope == 'case':
                payload['case_id'] = self.active_case_id
            r = self._api_post("/evidence/export", json_body=payload)
            if r.status_code != 200:
                print(colored(f"  ✗ {r.json().get('error', r.text)}", "red"))
                return
            if fmt == 'html':
                out = f"evidence_{scope}_{self.active_case_id or 'last'}.html"
                with open(out, 'w', encoding='utf-8') as fh:
                    fh.write(r.text)
                print(colored(f"  ✓ HTML report saved: {out}", "green"))
            else:
                out = f"evidence_{scope}_{self.active_case_id or 'last'}.json"
                with open(out, 'w', encoding='utf-8') as fh:
                    import json
                    json.dump(r.json(), fh, indent=2)
                print(colored(f"  ✓ JSON bundle saved: {out}", "green"))
        except Exception as exc:
            print(colored(f"  ✗ {exc}", "red"))

    def do_exit(self, arg):
        """Exit the ARGUS console. Usage: exit  |  /exit"""
        print(colored("  Session terminated. All actions logged.", "white"))
        return True

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

if __name__ == '__main__':
    try:
        import termcolor
    except ImportError:
        print("[!] Missing 'termcolor' module. Please install it with 'pip install termcolor'")
        sys.exit(1)
        
    try:
        import flask
    except ImportError:
        print("[!] Missing 'flask'. Please run 'pip install -r requirements.txt'")
        sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        try:
            ensure_first_run_setup()
            port = find_free_port()
            console = LEAConsole(port)
            console.do_gui('')
            print(colored(f"[*] Server running in background on port {port}. Press Ctrl+C to exit.", "yellow"))
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Exiting.")
            sys.exit(0)
        except Exception as e:
            print(colored(f"[!] Initialization error: {str(e)}", "red"))
            sys.exit(1)
    else:
        try:
            ensure_first_run_setup()
            port = find_free_port()
            console = LEAConsole(port)
            console.cmdloop()
        except Exception as e:
            print(colored(f"[!] Initialization error: {str(e)}", "red"))
            sys.exit(1)
