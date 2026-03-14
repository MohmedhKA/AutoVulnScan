"""
main.py - AutoVulnScan Interactive CLI
========================================
A page-based terminal user interface (TUI) for AutoVulnScan.

Each step is a full "screen" that clears and replaces the previous,
like a real CLI application. Arrow keys to navigate, Enter to select.

RUN:  python main.py
"""

import sys
import os
import re
import io
import time
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import Settings, STEALTH_PROFILES
from scanner.port_scan import run_port_scan
from scanner.network_sweep import run_network_sweep
from scanner.service_id import run_service_id
from scanner.os_detect import detect_os_version
from cve_lookup.nvd_api import load_api_key
from cve_lookup.cve_match import match_cves, deduplicate_cve_results
from exploits.validator import run_validators
from report.generate import generate_report


# ============================================================
# ANSI CONSTANTS
# ============================================================

RED = "\033[91m";  GREEN = "\033[92m";  YELLOW = "\033[93m"
BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
WHITE = "\033[97m"; GRAY = "\033[90m";   DIM = "\033[2m"
BOLD = "\033[1m";  UNDERLINE = "\033[4m"; RESET = "\033[0m"
HIDE_CUR = "\033[?25l"; SHOW_CUR = "\033[?25h"
BG_SEL = "\033[48;5;236m"


# ============================================================
# PLATFORM SETUP
# ============================================================

def enable_ansi():
    """Enable ANSI escape codes on Windows 10+."""
    if os.name == 'nt':
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def get_key():
    """Read one keypress → 'UP','DOWN','ENTER','ESC','BACKSPACE' or char."""
    try:
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b'\x00', b'\xe0'):
            ch2 = msvcrt.getch()
            return {b'H':'UP',b'P':'DOWN',b'K':'LEFT',b'M':'RIGHT'}.get(ch2,'')
        if ch == b'\r':       return 'ENTER'
        if ch == b'\x1b':     return 'ESC'
        if ch == b'\x08':     return 'BACKSPACE'
        return ch.decode('utf-8', errors='ignore')
    except ImportError:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                c2 = sys.stdin.read(1)
                if c2 == '[':
                    c3 = sys.stdin.read(1)
                    return {'A':'UP','B':'DOWN','C':'RIGHT','D':'LEFT'}.get(c3,'ESC')
                return 'ESC'
            if ch in ('\r','\n'): return 'ENTER'
            if ch in ('\x7f','\x08'): return 'BACKSPACE'
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ============================================================
# TERMINAL HELPERS
# ============================================================

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def tw():
    try:    return os.get_terminal_size().columns
    except: return 80

def sa(text):
    """Strip ANSI codes for length calculation."""
    return re.sub(r'\033\[[^m]*m', '', text)

def wait_key(msg=""):
    if msg:
        sys.stdout.write(f"\n  {DIM}{msg}{RESET}")
        sys.stdout.flush()
    get_key()


# ============================================================
# DRAWING PRIMITIVES
# ============================================================

def draw_header():
    """Persistent app header on every screen."""
    w = min(tw() - 2, 68)
    print(f"  {CYAN}{'━' * w}{RESET}")
    left = f"  {BOLD}{WHITE}AUTO{GREEN}VULN{GRAY}SCAN{RESET}"
    right = f"{DIM}v1.0 │ Educational{RESET}"
    gap = w - len(sa(left)) - len(sa(right))
    print(f"{left}{' ' * max(gap, 2)}{right}")
    print(f"  {CYAN}{'━' * w}{RESET}\n")


def draw_phase(num, label, color=CYAN):
    """Phase title bar."""
    w = min(tw() - 6, 56)
    print(f"\n  {color}{'━' * w}{RESET}")
    print(f"  {BOLD}{WHITE}  PHASE {num} {GRAY}│{color} {label}{RESET}")
    print(f"  {color}{'━' * w}{RESET}\n")


def draw_box(lines, title="", color=CYAN, width=56):
    """Bordered box with optional title."""
    inner = width - 4
    print(f"  {color}┌{'─' * (width - 2)}┐{RESET}")
    if title:
        print(f"  {color}│{RESET}  {BOLD}{WHITE}{title:<{inner}}{RESET}{color}│{RESET}")
        print(f"  {color}├{'─' * (width - 2)}┤{RESET}")
    for line in lines:
        pad = inner - len(sa(line))
        print(f"  {color}│{RESET}  {line}{' ' * max(0, pad)}{color}│{RESET}")
    print(f"  {color}└{'─' * (width - 2)}┘{RESET}")


def st(msg, kind="info"):
    """Colored status line."""
    icons = {
        "info": f"{CYAN}[*]{RESET}", "ok": f"{GREEN}[✓]{RESET}",
        "warn": f"{YELLOW}[!]{RESET}", "err": f"{RED}[✗]{RESET}",
        "run":  f"{BLUE}[~]{RESET}",  "step": f"{MAGENTA}[→]{RESET}",
    }
    print(f"  {icons.get(kind, icons['info'])} {msg}")


# ============================================================
# INTERACTIVE SELECTOR (arrow keys, full-screen redraw)
# ============================================================

def select(title, options, descriptions=None, allow_back=True):
    """
    Full-screen arrow-key menu. Clears screen, draws fresh each move.
    Returns index or -1 for ESC/back.
    """
    sel = 0
    n = len(options)

    while True:
        clear()
        draw_header()

        w = min(tw() - 6, 58)
        inner = w - 4

        print(f"  {CYAN}┌{'─' * (w-2)}┐{RESET}")
        print(f"  {CYAN}│{RESET}  {BOLD}{WHITE}{title:<{inner}}{RESET}{CYAN}│{RESET}")
        print(f"  {CYAN}├{'─' * (w-2)}┤{RESET}")

        for i, opt in enumerate(options):
            if i == sel:
                line = f"  {GREEN}►{RESET} {BG_SEL}{WHITE}{BOLD} {opt} {RESET}"
            else:
                line = f"    {GRAY}{opt}{RESET}"
            pad = inner - len(sa(line))
            print(f"  {CYAN}│{RESET}{line}{' ' * max(0, pad)}{CYAN}│{RESET}")

        if descriptions and sel < len(descriptions):
            print(f"  {CYAN}├{'─' * (w-2)}┤{RESET}")
            desc = descriptions[sel][:inner]
            dpad = inner - len(desc)
            print(f"  {CYAN}│{RESET}  {DIM}{desc}{RESET}{' ' * max(0, dpad)}{CYAN}│{RESET}")

        print(f"  {CYAN}└{'─' * (w-2)}┘{RESET}")

        hint = "  ↑↓ Navigate   ↵ Select"
        if allow_back:
            hint += "   ESC Back"
        print(f"\n  {DIM}{hint}{RESET}")

        sys.stdout.write(HIDE_CUR)
        sys.stdout.flush()

        key = get_key()
        if key == 'UP':     sel = (sel - 1) % n
        elif key == 'DOWN': sel = (sel + 1) % n
        elif key == 'ENTER':
            sys.stdout.write(SHOW_CUR); sys.stdout.flush()
            return sel
        elif key == 'ESC' and allow_back:
            sys.stdout.write(SHOW_CUR); sys.stdout.flush()
            return -1


def text_prompt(label, default="", validator=None):
    """Inline text input with validation."""
    sys.stdout.write(SHOW_CUR); sys.stdout.flush()
    while True:
        if default:
            prompt = f"  {CYAN}▸{RESET} {label} {DIM}[{default}]{RESET}: "
        else:
            prompt = f"  {CYAN}▸{RESET} {label}: "
        try:
            val = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(); return default
        if not val:
            val = default
        if validator and val:
            r = validator(val)
            if r is not True:
                print(f"    {RED}✗ {r}{RESET}")
                continue
        return val


def confirm(label="Continue?"):
    """Yes/No selector. Returns True/False."""
    return select(label, ["Yes", "No"], allow_back=False) == 0


# ============================================================
# VALIDATORS
# ============================================================

def v_ip(val):
    import socket
    try: socket.inet_aton(val); return True
    except socket.error: return "Invalid IP address"

def v_cidr(val):
    import ipaddress
    try: ipaddress.ip_network(val, strict=False); return True
    except ValueError: return "Invalid CIDR (e.g. 192.168.100.0/24)"

def v_ports(val):
    try:
        if '-' in val:
            s, e = val.split('-'); s, e = int(s), int(e)
        else:
            s = e = int(val)
        if 1 <= s <= 65535 and 1 <= e <= 65535 and s <= e: return True
        return "Range must be 1-65535, start ≤ end"
    except: return "Use format: start-end (e.g. 1-1024)"


# ============================================================
# CAPTURE HELPER — run a module, capture its stdout, still print
# ============================================================

class _Tee:
    """Write to multiple streams at once."""
    def __init__(self, *s): self.s = s
    def write(self, d):
        for x in self.s: x.write(d)
    def flush(self):
        for x in self.s: x.flush()

def run_captured(func, *a, **kw):
    """Run func while capturing print output. Returns (result, text)."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = _Tee(old, buf)
    try:
        result = func(*a, **kw)
    finally:
        sys.stdout = old
    return result, buf.getvalue()


# ============================================================
# PAGE: WELCOME
# ============================================================

def page_welcome():
    clear()
    banner = f"""
  {CYAN}╔═════════════════════════════════════════════════════════╗
  ║                                                         ║
  ║   {WHITE}{BOLD} █████╗ ██╗   ██╗████████╗ ██████╗                   {CYAN}║
  ║   {WHITE}{BOLD}██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗                  {CYAN}║
  ║   {WHITE}{BOLD}███████║██║   ██║   ██║   ██║   ██║                  {CYAN}║
  ║   {WHITE}{BOLD}██╔══██║██║   ██║   ██║   ██║   ██║                  {CYAN}║
  ║   {WHITE}{BOLD}██║  ██║╚██████╔╝   ██║   ╚██████╔╝                  {CYAN}║
  ║   {WHITE}{BOLD}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝                   {CYAN}║
  ║                                                         ║
  ║  {GREEN}██╗   ██╗██╗   ██╗██╗     ███╗   ██╗{GRAY}███████╗██████╗ █████╗ ███╗  ██╗{CYAN}║
  ║  {GREEN}██║   ██║██║   ██║██║     ████╗  ██║{GRAY}██╔════╝██╔═══╝██╔══██╗████╗ ██║{CYAN}║
  ║  {GREEN}██║   ██║██║   ██║██║     ██╔██╗ ██║{GRAY}███████╗██║    ███████║██╔██╗██║{CYAN}║
  ║  {GREEN}╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║{GRAY}╚════██║██║    ██╔══██║██║╚██╗██║{CYAN}║
  ║  {GREEN} ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║{GRAY}███████║╚█████╗██║  ██║██║ ╚████║{CYAN}║
  ║  {GREEN}  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝{GRAY}╚══════╝ ╚════╝╚═╝  ╚═╝╚═╝  ╚═══╝{CYAN}║
  ║                                                         ║
  ║   {DIM}Automated Vulnerability Scanner │ v1.0 │ Educational{CYAN}   ║
  ╚═════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)

    st("Initializing...", "run")
    Settings.load_api_key()
    if Settings.api_key:
        st("CVE API key loaded from .env", "ok")
    else:
        st("No API key — CVE lookups will be rate-limited", "warn")

    time.sleep(0.8)
    wait_key("Press any key to continue...")


# ============================================================
# PAGE: TARGET SELECTION
# ============================================================

def page_target():
    """
    Ask how to find the target. Returns (ip, subnet_used) or (None, None).
    """
    choice = select(
        "HOW DO YOU WANT TO FIND YOUR TARGET?",
        [
            "🔍  Discover hosts on a network",
            "🎯  I already know the target IP",
            "🚪  Exit",
        ],
        [
            "Sweep a subnet with stealth TCP probes, then pick a host",
            "Skip discovery and scan a known IP address directly",
            "Quit AutoVulnScan",
        ],
        allow_back=False,
    )

    if choice == 2 or choice == -1:
        return None, None
    if choice == 0:
        return page_discover()
    return page_enter_ip()


def page_discover():
    """Subnet sweep → pick a host. Returns (ip, subnet) or (None, None)."""
    clear()
    draw_header()
    print(f"  {BOLD}{WHITE}NETWORK DISCOVERY{RESET}\n")

    subnet = text_prompt("Enter subnet (CIDR)", "192.168.100.0/24", v_cidr)
    if not subnet:
        return None, None

    # Stealth for discovery
    stealth_key = page_stealth("DISCOVERY STEALTH")
    if stealth_key is None:
        return None, None
    profile = STEALTH_PROFILES[stealth_key]

    # Run sweep
    clear()
    draw_header()
    draw_phase(0, "Network Discovery", BLUE)
    st(f"Sweeping {WHITE}{subnet}{RESET} with stealth TCP probes...", "run")
    print()

    live_hosts, _ = run_captured(
        run_network_sweep, subnet,
        timeout=profile["timeout"],
        max_threads=profile["threads"],
        delay=profile["delay"],
        jitter=profile["jitter"],
    )

    if not live_hosts:
        st("No live hosts found on this subnet.", "warn")
        wait_key("Press any key to go back...")
        return None, None

    # Pick a host from the results
    host_opts = [f"  {ip}" for ip in live_hosts]
    host_descs = ["Select this host as the scan target"] * len(live_hosts)

    idx = select(f"FOUND {len(live_hosts)} LIVE HOST(S) — PICK YOUR TARGET",
                 host_opts, host_descs)
    if idx == -1:
        return None, None

    return live_hosts[idx], subnet


def page_enter_ip():
    """Type in a target IP. Returns (ip, None) or (None, None)."""
    clear()
    draw_header()
    print(f"  {BOLD}{WHITE}ENTER TARGET{RESET}\n")
    ip = text_prompt("Target IP address", "192.168.100.50", v_ip)
    if not ip:
        return None, None
    return ip, None


# ============================================================
# PAGE: STEALTH PICKER
# ============================================================

def page_stealth(title="STEALTH LEVEL"):
    """Arrow-key stealth selector. Returns key or None."""
    keys = ["normal", "quiet", "ghost"]
    opts, descs = [], []
    for k in keys:
        p = STEALTH_PROFILES[k]
        opts.append(f"{p['icon']}  {p['label']}")
        descs.append(f"{p['description']}  "
                     f"[delay:{p['delay']}s  jitter:{p['jitter']}s  "
                     f"threads:{p['threads']}]")

    idx = select(title, opts, descs)
    return keys[idx] if idx >= 0 else None


# ============================================================
# PAGE: SCAN CONFIG
# ============================================================

def page_config(target_ip):
    """Configure ports and stealth. Returns (start, end, stealth) or None."""
    clear()
    draw_header()
    draw_box(
        [f"{GRAY}Target:{RESET}  {WHITE}{BOLD}{target_ip}{RESET}"],
        title="SCAN CONFIGURATION", width=52,
    )

    print()
    ports_str = text_prompt("Port range", "1-1024", v_ports)
    parts = ports_str.split('-')
    ps = int(parts[0])
    pe = int(parts[1]) if len(parts) > 1 else ps

    stealth_key = page_stealth()
    if stealth_key is None:
        return None

    Settings.stealth_level = stealth_key
    Settings.apply_stealth()

    # Confirmation
    profile = STEALTH_PROFILES[stealth_key]
    clear()
    draw_header()
    draw_box([
        f"{GRAY}Target:{RESET}    {WHITE}{BOLD}{target_ip}{RESET}",
        f"{GRAY}Ports:{RESET}     {WHITE}{ps}–{pe}{RESET}",
        f"{GRAY}Stealth:{RESET}   {YELLOW}{profile['icon']} {profile['label']}{RESET}",
        f"{GRAY}Threads:{RESET}   {WHITE}{profile['threads']}{RESET}",
        f"{GRAY}Timing:{RESET}    {WHITE}{profile['delay']}s + 0–{profile['jitter']}s jitter{RESET}",
    ], title="CONFIRM SCAN", width=52)

    print()
    if not confirm("Launch scan?"):
        return None

    return ps, pe, stealth_key


# ============================================================
# PAGE: RUNNING THE PIPELINE
# ============================================================

def page_pipeline(target_ip, port_start, port_end, stealth_key):
    """
    Runs all phases one after another, each on a clean screen.
    Returns the complete scan_data dict.
    """
    profile = STEALTH_PROFILES[stealth_key]
    t0 = time.time()

    scan_data = {
        "target": target_ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stealth_level": stealth_key,
        "port_range": f"{port_start}-{port_end}",
        "open_ports": [], "services": {},
        "os_info": {},
        "cve_results": {}, "validation_results": {},
    }

    # ── PHASE 1: PORT SCAN ──────────────────────────────────
    clear(); draw_header()
    draw_phase(1, "TCP Port Scan", CYAN)
    st(f"Scanning {WHITE}{target_ip}{RESET}  ports {WHITE}{port_start}–{port_end}{RESET}", "run")
    print()

    open_ports, _ = run_captured(
        run_port_scan, target_ip, port_start, port_end,
        timeout=profile["timeout"], max_threads=profile["threads"],
        delay=profile["delay"], jitter=profile["jitter"],
    )

    scan_data["open_ports"] = open_ports

    if not open_ports:
        print()
        st("No open ports found.", "warn")
        scan_data["duration"] = f"{round(time.time()-t0,1)}s"
        wait_key("Press any key...")
        return scan_data

    port_nums = [p[0] if isinstance(p,(list,tuple)) else p for p in open_ports]
    print()
    st(f"Found {GREEN}{BOLD}{len(open_ports)}{RESET} open port(s): "
       f"{WHITE}{', '.join(str(p) for p in sorted(port_nums))}{RESET}", "ok")
    wait_key("Press any key for next phase...")

    # ── PHASE 2: SERVICE ID ─────────────────────────────────
    clear(); draw_header()
    draw_phase(2, "Service Identification", GREEN)
    st(f"Grabbing banners from {WHITE}{len(port_nums)}{RESET} port(s)...", "run")
    print()

    services, _ = run_captured(
        run_service_id, target_ip, port_nums,
        timeout=profile["timeout"]+2.0,
        max_threads=min(profile["threads"], 10),
        delay=profile["delay"], jitter=profile["jitter"],
    )

    scan_data["services"] = services

    print()
    if services:
        lines = []
        for port in sorted(services.keys()):
            lines.append(f"{CYAN}{port:<7}{RESET} {WHITE}{services[port]}{RESET}")
        draw_box(lines, title="PORT   SERVICE", width=52)
    else:
        st("Could not identify any services.", "warn")

    wait_key("Press any key for next phase...")

    # ── PHASE 2.5: OS DETECTION ─────────────────────────────
    clear(); draw_header()
    draw_phase(2, "OS Detection", MAGENTA)
    st("Detecting target operating system via SMB negotiate...", "run")
    st(f"{DIM}Binary protocol handshake — normal network traffic{RESET}", "info")
    print()

    # Pick the best SMB port for OS detection (prefer 445, then 139)
    smb_port = 445 if 445 in port_nums else (139 if 139 in port_nums else 445)
    os_info, _ = run_captured(
        detect_os_version, target_ip,
        port=smb_port, timeout=profile["timeout"]+2.0,
    )

    scan_data["os_info"] = os_info or {}

    print()
    if os_info and os_info.get("os_family", "unknown") != "unknown":
        os_lines = [
            f"  {GRAY}OS Family:{RESET}    {WHITE}{BOLD}{os_info.get('os_family', 'unknown').capitalize()}{RESET}",
            f"  {GRAY}Version:{RESET}      {WHITE}{os_info.get('os_version', 'N/A')}{RESET}",
        ]
        if os_info.get("smb_version"):
            os_lines.append(f"  {GRAY}SMB Dialect:{RESET}  {WHITE}{os_info['smb_version']}{RESET}")
        if os_info.get("confidence"):
            os_lines.append(f"  {GRAY}Confidence:{RESET}   {YELLOW}{os_info['confidence']}{RESET}")
        draw_box(os_lines, title="DETECTED OS", width=52)
    else:
        st("Could not determine OS (no SMB service or probe failed).", "info")
        os_info = os_info or {"os_family": "unknown", "os_version": "", "confidence": "none"}

    wait_key("Press any key for next phase...")

    # ── PHASE 3: CVE LOOKUP ─────────────────────────────────
    clear(); draw_header()
    draw_phase(3, "CVE Lookup (NVD API)", YELLOW)
    st("Querying NIST NVD for known vulnerabilities...", "run")
    st(f"{DIM}This may take a moment due to API rate limits{RESET}", "info")
    print()

    api_key = Settings.api_key or load_api_key()
    cve_results, _ = run_captured(match_cves, services, api_key=api_key, os_info=os_info)
    scan_data["cve_results"] = cve_results
    scan_data["deduplicated_cves"] = deduplicate_cve_results(cve_results)

    all_cves = scan_data["deduplicated_cves"]
    crit = len([c for c in all_cves if c.get("severity")=="CRITICAL"])
    high = len([c for c in all_cves if c.get("severity")=="HIGH"])

    print()
    if all_cves:
        lines = []
        for c in all_cves:
            sev = c["severity"]
            col = RED if sev=="CRITICAL" else YELLOW if sev=="HIGH" else GRAY
            lines.append(f"{col}{c['id']:<20}{RESET} CVSS {WHITE}{c['cvss']:<5}{RESET} {col}{sev}{RESET}")
        draw_box(lines, title=f"CVEs — {crit} Critical, {high} High", width=56)
    else:
        st("No high/critical CVEs found.", "ok")

    wait_key("Press any key for next phase...")

    # ── PHASE 4: EXPLOIT VALIDATION ─────────────────────────
    clear(); draw_header()
    draw_phase(4, "Exploit Validation", RED)
    st("Running non-destructive CVE validators...", "run")
    st(f"{DIM}Connection checks only — no commands are executed{RESET}", "info")
    print()

    validation, _ = run_captured(
        run_validators, target_ip,
        service_map=services, cve_results=cve_results,
    )
    scan_data["validation_results"] = validation

    print()
    if validation:
        for cve_id, vd in validation.items():
            s = vd.get("status","UNKNOWN")
            if s == "CONFIRMED":
                st(f"{RED}{BOLD}{cve_id}{RESET}  →  {RED}{BOLD}⚠ CONFIRMED VULNERABLE{RESET}", "err")
            else:
                st(f"{GRAY}{cve_id}{RESET}  →  {DIM}{s}{RESET}", "ok")
    else:
        st("No applicable validators for discovered services.", "info")

    scan_data["duration"] = f"{round(time.time()-t0,1)}s"

    wait_key("Press any key to see results...")
    return scan_data


# ============================================================
# PAGE: RESULTS DASHBOARD
# ============================================================

def page_results(scan_data):
    """Beautiful summary dashboard on a clean screen."""
    clear()
    draw_header()

    target   = scan_data["target"]
    duration = scan_data["duration"]
    stealth  = scan_data["stealth_level"].upper()
    ports    = scan_data["open_ports"]
    services = scan_data.get("services", {})
    cve_res  = scan_data.get("cve_results", {})
    val      = scan_data.get("validation_results", {})
    os_info  = scan_data.get("os_info", {})

    n_ports = len(ports)
    n_svc   = len([s for s in services.values() if s != "Unknown"])

    # Build OS display string
    os_display = "Unknown"
    if os_info:
        ov = os_info.get("os_version", "")
        of = os_info.get("os_family", "unknown")
        if ov:
            os_display = ov
        elif of != "unknown":
            os_display = of.capitalize()

    all_cves = scan_data.get("deduplicated_cves")
    if all_cves is None:
        all_cves = deduplicate_cve_results(cve_res)
    n_crit = len([c for c in all_cves if c.get("severity")=="CRITICAL"])
    n_high = len([c for c in all_cves if c.get("severity")=="HIGH"])
    n_conf = len([v for v in val.values() if v.get("status")=="CONFIRMED"])

    w = 56

    # ── SUMMARY BOX ──
    print(f"  {CYAN}╔{'═'*(w-2)}╗{RESET}")
    tl = f"  {BOLD}{WHITE}SCAN COMPLETE — RESULTS{RESET}"
    tp = (w-4) - len(sa(tl))
    print(f"  {CYAN}║{RESET}{tl}{' '*max(0,tp)}  {CYAN}║{RESET}")
    print(f"  {CYAN}╠{'═'*(w-2)}╣{RESET}")

    rows = [
        f"  {GRAY}Target:{RESET}    {WHITE}{BOLD}{target}{RESET}",
        f"  {GRAY}OS:{RESET}        {MAGENTA}{BOLD}{os_display}{RESET}",
        f"  {GRAY}Duration:{RESET}  {WHITE}{duration}{RESET}",
        f"  {GRAY}Stealth:{RESET}   {YELLOW}{stealth}{RESET}",
        "",
        f"  {CYAN}{'─'*(w-6)}{RESET}",
        f"  {GREEN}►{RESET} Open Ports      {WHITE}{BOLD}{n_ports}{RESET}",
        f"  {BLUE}►{RESET} Services ID'd   {WHITE}{BOLD}{n_svc}{RESET}",
        (f"  {RED}►{RESET} Critical CVEs   {RED}{BOLD}{n_crit}{RESET}" if n_crit else
         f"  {GRAY}► Critical CVEs   0{RESET}"),
        (f"  {YELLOW}►{RESET} High CVEs       {YELLOW}{BOLD}{n_high}{RESET}" if n_high else
         f"  {GRAY}► High CVEs       0{RESET}"),
        (f"  {RED}⚠ CONFIRMED      {RED}{BOLD}{n_conf}{RESET}" if n_conf else
         f"  {GRAY}► Confirmed       0{RESET}"),
    ]

    for row in rows:
        pad = (w-4) - len(sa(row))
        print(f"  {CYAN}║{RESET}{row}{' '*max(0,pad)}  {CYAN}║{RESET}")
    print(f"  {CYAN}╚{'═'*(w-2)}╝{RESET}")

    # ── PORT / SERVICE TABLE ──
    if ports:
        print()
        lines = []
        for pinfo in ports:
            pn = pinfo[0] if isinstance(pinfo,(list,tuple)) else pinfo
            rt = f"{pinfo[1]}ms" if isinstance(pinfo,(list,tuple)) and len(pinfo)>1 else "—"
            sv = services.get(pn, "Unknown")
            lines.append(f"{CYAN}{pn:<7}{RESET} {WHITE}{sv:<24}{RESET} {DIM}{rt}{RESET}")
        draw_box(lines, title="PORT   SERVICE                  RESP", width=56)

    # ── CVE TABLE ──
    if all_cves:
        print()
        lines = []
        for c in all_cves:
            sev = c["severity"]
            col = RED if sev=="CRITICAL" else YELLOW if sev=="HIGH" else GRAY
            vid = c["id"]
            mark = ""
            if vid in val and val[vid].get("status")=="CONFIRMED":
                mark = f" {RED}⚠{RESET}"
            lines.append(f"{col}{vid:<18}{RESET} {WHITE}{c['cvss']:<5}{RESET} {col}{sev:<10}{RESET}{mark}")
        draw_box(lines, title="CVE ID             CVSS  SEVERITY", width=56)

        # ── DISCLAIMER ──
        print()
        os_confidence = os_info.get("confidence", "") if os_info else ""
        os_family_d   = os_info.get("os_family", "unknown") if os_info else "unknown"
        uncertain_os  = os_confidence == "low" or os_family_d == "unknown"
        disc_lines = [
            "Results are based on service banners and version strings",
            "detected during scanning. Accuracy depends on:",
            "  \u2022 Whether the target reports its real version",
            "  \u2022 OS detection confidence (shown above)",
            "  \u2022 CVE applicability to your specific OS/distro",
            "",
            "Always cross-check findings before acting on them.",
            "False positives are possible \u2014 verify each CVE manually.",
        ]
        if uncertain_os:
            disc_lines.append(
                f"{YELLOW}\u26a0 OS detection was uncertain \u2014 some CVEs may not apply.{RESET}"
            )
        draw_box(disc_lines, title="\u26a0  DISCLAIMER", color=YELLOW, width=63)


# ============================================================
# PAGE: SAVE REPORT
# ============================================================

def page_save(scan_data):
    """Ask whether to save, then generate reports."""
    print()
    if not confirm("Save HTML & JSON reports?"):
        st("Reports not saved.", "info")
        return

    clear()
    draw_header()
    print(f"  {BOLD}{WHITE}SAVE REPORTS{RESET}\n")

    out = text_prompt("Output directory", "reports")

    print()
    deduplicated_cves = scan_data.get("deduplicated_cves")
    if deduplicated_cves is None:
        deduplicated_cves = deduplicate_cve_results(scan_data.get("cve_results", {}))
    reports = generate_report(scan_data, out, deduplicated_cves=deduplicated_cves)
    print()

    if reports.get("html"):
        st(f"HTML → {UNDERLINE}{reports['html']}{RESET}", "ok")
    if reports.get("json"):
        st(f"JSON → {UNDERLINE}{reports['json']}{RESET}", "ok")


# ============================================================
# PAGE: GOODBYE
# ============================================================

def page_bye():
    clear()
    draw_header()
    print(f"  {DIM}Thanks for using AutoVulnScan. Stay stealthy. {GREEN}👻{RESET}\n")
    time.sleep(1)


# ============================================================
# MAIN — APPLICATION LOOP
# ============================================================

def main():
    """
    Page-based flow:
      Welcome → Target → Config → Pipeline → Results → Save → Loop/Exit
    """
    enable_ansi()
    page_welcome()

    while True:
        # 1. Pick target
        target_ip, subnet = page_target()
        if target_ip is None:
            page_bye(); break

        # 2. Configure scan
        config = page_config(target_ip)
        if config is None:
            continue  # back to target selection

        ps, pe, sk = config

        # 3. Run all phases
        scan_data = page_pipeline(target_ip, ps, pe, sk)

        # 4. Show results
        page_results(scan_data)

        # 5. Save reports?
        page_save(scan_data)

        # 6. Again?
        print()
        if not confirm("Run another scan?"):
            page_bye(); break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write(SHOW_CUR)
        print(f"\n\n  {DIM}Interrupted. Exiting.{RESET}\n")
        sys.exit(0)
