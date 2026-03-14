"""
service_id.py - Stealthy Service Banner Grabber
=================================================
This module connects to open ports and identifies what service
is running by reading the "banner" the service sends back.

WHAT IS A BANNER?
When you connect to a server, many services immediately send back
a greeting message. For example:
  - FTP on port 21 might send: "220 (vsFTPd 2.3.4)"
  - SSH on port 22 might send: "SSH-2.0-OpenSSH_4.7p1"
  - HTTP on port 80 needs a request first, then responds with headers

STEALTH APPROACH:
- Passive first: just connect and LISTEN (many services talk first)
- Only send a minimal probe if the service stays silent
- Protocol-aware probes: send the right thing for HTTP, FTP, etc.
- Short timeouts so we don't linger on any port
- Clean socket teardown after every grab
- Randomized port order for grabbing

USAGE (standalone):
    python scanner/service_id.py <target_ip> <port1> <port2> ...
    python scanner/service_id.py 192.168.100.50 21 22 80 445
"""

import socket       # For connecting to services
import threading    # For grabbing banners from multiple ports at once
import time         # For delays and timing
import random       # For randomizing order
import sys          # For command line arguments
import os           # For path operations
import re           # For banner pattern matching


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 3.0       # Seconds to wait for a banner response
DEFAULT_MAX_THREADS = 10    # Fewer threads = quieter on the network
DEFAULT_DELAY = 0.0         # Base delay between each grab
DEFAULT_JITTER = 0.0        # Random extra delay (stealth)

# How long to wait passively before sending a probe
PASSIVE_WAIT = 2.0          # Seconds to just listen before poking

# Maximum bytes to read from a banner
MAX_BANNER_SIZE = 1024


# ============================================================
# PROTOCOL-SPECIFIC PROBES
# ============================================================
# Some services don't send a banner until you talk first.
# These are minimal probes tailored to each protocol.
# We only send these if passive listening gets nothing.

PROTOCOL_PROBES = {
    # HTTP: send a tiny HEAD request (smallest valid HTTP request)
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",

    # Port 8180 is Apache Tomcat's alternate HTTP port on Metasploitable2.
    # A GET request returns the Tomcat welcome page which contains "Tomcat".
    # HEAD returns minimal headers without page body, so use GET here.
    8180: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",

    # For anything else, a bare carriage-return-line-feed
    # Many text-based protocols respond to this
    "default": b"\r\n",
}


# ============================================================
# KNOWN SERVICE SIGNATURES
# ============================================================
# After grabbing a banner, we try to match it against known patterns
# to identify the service name and version.

SERVICE_SIGNATURES = [
    # (search_string, service_name)
    # Check these in order - first match wins

    # Tomcat MUST appear before "Apache" to prevent Tomcat HTTP responses
    # (which contain both "Apache-Coyote" and "Apache") from matching as
    # "Apache HTTP" instead of "Apache Tomcat".
    ("Apache-Coyote", "Apache Tomcat"),
    ("Tomcat",        "Apache Tomcat"),

    ("vsftpd",      "vsftpd"),
    ("FileZilla",   "FileZilla FTP"),
    ("ProFTPD",     "ProFTPD"),
    ("Pure-FTPd",   "Pure-FTPd"),
    ("OpenSSH",     "OpenSSH"),
    ("dropbear",    "Dropbear SSH"),
    ("Apache",      "Apache HTTP"),
    ("nginx",       "nginx"),
    ("lighttpd",    "lighttpd"),
    ("Microsoft-IIS", "Microsoft IIS"),
    ("Samba",       "Samba"),
    ("mysql",       "MySQL"),
    ("MariaDB",     "MariaDB"),
    ("PostgreSQL",  "PostgreSQL"),
    ("Postfix",     "Postfix SMTP"),
    ("Exim",        "Exim SMTP"),
    ("Sendmail",    "Sendmail"),
    ("IMAP",        "IMAP"),
    ("POP3",        "POP3"),
    ("Dovecot",     "Dovecot"),
    ("Courier",     "Courier"),
    ("OpenLDAP",    "OpenLDAP"),
    # RFB is the Remote Framebuffer protocol used by VNC.
    # "RFB 003.003" is the exact banner sent by VNC on port 5900.
    ("RFB",         "VNC"),
    ("VNC",         "VNC"),
    ("RDP",         "RDP"),
    ("Telnet",      "Telnet"),
    ("UnrealIRCd",  "UnrealIRCd"),
    ("IRC",         "IRC"),
    ("distccd",     "distccd"),
    ("Java RMI",    "Java RMI"),
    ("rmiregistry", "Java RMI"),
    ("Jetty",       "Jetty HTTP"),
    ("PHP",         "PHP"),
    ("X11",         "X11"),
]

# Well-known port-to-service name mapping (fallback)
# Used when we can't grab a banner but know what usually runs there
PORT_SERVICE_NAMES = {
    21: "FTP",      22: "SSH",      23: "Telnet",   25: "SMTP",
    53: "DNS",      80: "HTTP",     110: "POP3",    111: "RPCbind",
    135: "MSRPC",   139: "NetBIOS", 143: "IMAP",    443: "HTTPS",
    445: "SMB",     993: "IMAPS",   995: "POP3S",   1099: "Java RMI",
    1433: "MSSQL",  1521: "Oracle", 2049: "NFS",    2121: "FTP",
    3306: "MySQL",  3389: "RDP",    3632: "distccd", 5432: "PostgreSQL",
    5900: "VNC",    5901: "VNC",    6000: "X11",    6667: "IRC",
    8009: "AJP",    8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8180: "HTTP-Alt",
}

# Ports that need protocol-specific probes instead of banner grabbing
# These services don't send plain-text banners; we use binary protocol probes
PROTOCOL_PROBE_PORTS = {445, 139, 135, 3632}


# ============================================================
# SMB VERSION DETECTION
# ============================================================
# For SMB ports (445, 139), we use the os_detect module to send
# a proper SMB negotiate and get the exact protocol version.
# This is FAR more accurate than banner grabbing for Windows services.

# Global storage for SMB probe results (set by run_service_id)
_smb_probe_result = {}


def _probe_smb_service(target_ip, port, timeout):
    """
    Use SMB protocol negotiation to detect the exact SMB version.

    Instead of grabbing a text banner (which SMB doesn't send),
    we send a real SMB negotiate packet and parse the binary response
    to extract the dialect version (e.g., SMB 3.1.1).

    Args:
        target_ip (str): Target IP address
        port (int):      Port number (445 or 139)
        timeout (float): Socket timeout in seconds

    Returns:
        str: Service string like "SMB 3.1.1" or fallback name
    """
    global _smb_probe_result

    try:
        # Import the OS detection module which has SMB negotiate logic
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from scanner.os_detect import detect_os_version

        smb_info = detect_os_version(target_ip, port=port, timeout=timeout)
        _smb_probe_result = smb_info

        if smb_info and smb_info.get("smb_version") and smb_info["smb_version"] != "Unknown":
            return smb_info["smb_version"]

    except Exception as e:
        print(f"  [!] SMB probe failed: {e}")

    # Fallback to port-based name
    return PORT_SERVICE_NAMES.get(port, "SMB")


def _probe_msrpc_service(target_ip, port, timeout):
    """
    Identify Microsoft RPC service on port 135.

    MSRPC doesn't send a text banner. We identify it by:
    1. Connecting and checking if the port accepts connections
    2. Sending an RPC bind request and checking for valid response
    3. Using the OS detection result from SMB (if available)

    Args:
        target_ip (str): Target IP address
        port (int):      Port number (135)
        timeout (float): Socket timeout

    Returns:
        str: Service string like "Microsoft Windows RPC"
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # RPC Endpoint Mapper bind request (DCE/RPC over TCP)
        # This is the first 5 bytes that identify a valid DCE/RPC response
        rpc_bind = (
            b'\x05'                # Version: 5
            b'\x00'                # Version Minor: 0
            b'\x0b'                # Packet Type: Bind (11)
            b'\x03'                # Packet Flags: First + Last fragment
            b'\x10\x00\x00\x00'   # Data Representation: Little-endian
            b'\x48\x00'           # Frag Length: 72
            b'\x00\x00'           # Auth Length: 0
            b'\x01\x00\x00\x00'   # Call ID: 1
            b'\xb8\x10'           # Max Xmit Frag: 4280
            b'\xb8\x10'           # Max Recv Frag: 4280
            b'\x00\x00\x00\x00'   # Assoc Group: 0
            b'\x01'               # Num Context Items: 1
            b'\x00\x00\x00'       # Reserved
            # Context item: EPM (Endpoint Mapper)
            b'\x00\x00'           # Context ID: 0
            b'\x01\x00'           # Num Trans Items: 1
            # Abstract Syntax: EPM UUID
            b'\xe1\xaf\x8d\xe0\xc0\x4d\xd0\x11'
            b'\xa7\x65\x00\xa0\xc9\x1c\x6e\x99'
            b'\x03\x00\x00\x00'   # Version: 3.0
            # Transfer Syntax: NDR
            b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11'
            b'\x9f\xe8\x08\x00\x2b\x10\x48\x60'
            b'\x02\x00\x00\x00'   # Version: 2.0
        )

        sock.sendall(rpc_bind)
        response = sock.recv(1024)

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

        # Check if we got a valid DCE/RPC Bind Ack response
        if len(response) >= 4 and response[0:1] == b'\x05' and response[2:3] == b'\x0c':
            # It's a DCE/RPC Bind Ack — confirmed Microsoft RPC
            return "Microsoft Windows RPC"

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return "Microsoft Windows RPC"


def _probe_distccd_service(target_ip, port, timeout):
    """
    Identify distccd on its default port (3632) using a safe minimal probe.

    Non-destructive behavior:
      - connect and optionally read passive response
      - send a tiny protocol preamble (not a compile/command request)
      - classify service based on response hints
    """
    passive_text = ""
    probe_text = ""
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # Passive read first
        try:
            sock.settimeout(min(timeout, 1.5))
            data = sock.recv(256)
            if data:
                passive_text = data.decode("utf-8", errors="ignore").strip()
        except (socket.timeout, OSError):
            pass

        # Safe distcc protocol preamble (compile frame prefix only, no payload)
        try:
            sock.settimeout(min(timeout, 1.5))
            sock.sendall(b"DIST00000001ARGC00000000")
            data = sock.recv(256)
            if data:
                probe_text = data.decode("utf-8", errors="ignore").strip()
        except (socket.timeout, OSError):
            pass

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    evidence = probe_text or passive_text
    if evidence:
        clean = evidence.replace("\r", " ").replace("\n", " ").strip()
        clean = clean[:140] + "..." if len(clean) > 140 else clean
        lower = clean.lower()
        if clean.startswith("DIST") or "distcc" in lower:
            return "distccd", f"[distcc probe] {clean}"
        return "distccd", f"[port 3632 response] {clean}"

    return "distccd", "[distcc default port 3632 open]"


# ============================================================
# SHARED DATA
# ============================================================

service_results = {}                    # {port: "service version string"}
service_results_lock = threading.Lock() # Thread safety


def clean_banner(raw_banner):
    """
    Clean up a raw banner string for display and analysis.

    Banners often contain messy characters like newlines, tabs,
    null bytes, and other control characters. This function
    strips them out to get a clean, readable string.

    Args:
        raw_banner (str): The raw banner text from the server

    Returns:
        str: Cleaned up banner text (max 200 chars)
    """
    # Remove common junk characters
    cleaned = raw_banner.replace("\r", " ").replace("\n", " ")
    cleaned = cleaned.replace("\t", " ").replace("\x00", "")

    # Collapse multiple spaces into one
    while "  " in cleaned:
        cleaned = cleaned.replace("  ", " ")

    # Trim whitespace from both ends
    cleaned = cleaned.strip()

    # Truncate if too long (banners can be huge)
    if len(cleaned) > 200:
        cleaned = cleaned[:200] + "..."

    return cleaned


def identify_service(banner_text, port):
    """
    Try to identify the service name and version from a banner.

    Strategy:
    1. Check the banner text against known service signatures
    2. Try to extract a version number from the banner
    3. If no banner, fall back to well-known port names

    Args:
        banner_text (str): The cleaned banner from the server
        port (int):        The port number (for fallback identification)

    Returns:
        str: Identified service string like "vsftpd 2.3.4" or "Unknown"
    """
    if not banner_text:
        # No banner received - use port-based guess as fallback
        return PORT_SERVICE_NAMES.get(port, "Unknown")

    # MySQL sends a binary protocol greeting on port 3306.
    # The word "MySQL" never appears in the raw banner; instead the server
    # sends: <4-byte packet header> <0x0a protocol version> <null-terminated
    # version string> <null-terminated garbage>.  The version string IS
    # present as printable ASCII digits/dots somewhere in the banner.
    # We detect it by port number and extract the version with a regex.
    if port == 3306:
        m = re.search(r'(\d+\.\d+\.\d+[\w.-]*)', banner_text)
        if m:
            return f"MySQL {m.group(1)}"
        return "MySQL"

    # UnrealIRCd-specific detection to avoid collapsing into generic "IRC".
    banner_lower = banner_text.lower()
    if (
        "unreal" in banner_lower
        or "irc.metasploitable" in banner_lower
        or re.search(r':irc\.[a-z0-9._-]+', banner_lower)
    ):
        version = (
            extract_version(banner_text, "UnrealIRCd")
            or extract_version(banner_text, "Unreal")
        )
        if version:
            return f"UnrealIRCd {version}"
        return "UnrealIRCd"

    # Check against our known signatures
    for signature, service_name in SERVICE_SIGNATURES:
        if signature.lower() in banner_text.lower():
            # Found a match - now try to extract version number
            version = extract_version(banner_text, signature)
            if version:
                return f"{service_name} {version}"
            return service_name

    # No signature matched - return the raw banner (truncated)
    if len(banner_text) > 60:
        return banner_text[:60] + "..."
    return banner_text if banner_text else PORT_SERVICE_NAMES.get(port, "Unknown")


def extract_version(banner_text, service_hint):
    """
    Try to pull a version number out of a banner string.

    Looks for common version patterns near the service name:
      "vsftpd 2.3.4"  →  "2.3.4"
      "OpenSSH_4.7p1"  →  "4.7p1"
      "Apache/2.2.8"   →  "2.2.8"

    Args:
        banner_text (str):  The full banner text
        service_hint (str): The service name we already matched

    Returns:
        str or None: Version string if found, None otherwise
    """
    # Find where the service name appears in the banner
    lower_banner = banner_text.lower()
    lower_hint = service_hint.lower()
    pos = lower_banner.find(lower_hint)

    if pos == -1:
        return None

    # Look at the text right after the service name
    after_service = banner_text[pos + len(service_hint):]

    # Strip common separators: space, /, _, -
    after_service = after_service.lstrip(" /-_")

    # Extract version-like string (digits, dots, letters like "p1")
    version = ""
    for char in after_service:
        if char.isdigit() or char == '.' or char.isalpha():
            version += char
        elif char in ('-', '_', '+'):
            version += char
        else:
            break  # Stop at first non-version character

    # Clean up trailing separators
    version = version.strip(".-_+")

    # Only return if it looks like a version (starts with a digit)
    if version and version[0].isdigit():
        return version

    return None


def grab_banner(target_ip, port, timeout):
    """
    Connect to a port and try to grab its service banner.

    STEALTH STRATEGY (three-phase approach):
    Phase 0 - PROTOCOL PROBE: For ports that use binary protocols
              (SMB 445, NetBIOS 139, MSRPC 135), use protocol-specific
              probes that speak the native protocol. This returns
              actual version info instead of garbled binary data.

    Phase 1 - PASSIVE: Just connect and listen. Many services
              (FTP, SSH, SMTP, etc.) immediately send a greeting.
              This is the quietest approach - we send NOTHING.

    Phase 2 - ACTIVE: If the service stays silent (like HTTP),
              send a minimal protocol-appropriate probe.
              Only triggers if passive listening got nothing.

    Args:
        target_ip (str): IP address to connect to
        port (int):      Port number to grab banner from
        timeout (float): Max seconds to wait for a response
    """

    # ---- PHASE 0: PROTOCOL-SPECIFIC PROBES ----
    # For binary protocol ports, use dedicated probes that understand
    # the protocol and extract version info properly
    if port in PROTOCOL_PROBE_PORTS:
        service_name = ""
        banner_text = ""

        if port == 445:
            # SMB: use binary negotiate to detect exact dialect version
            service_name = _probe_smb_service(target_ip, port, timeout)
            banner_text = f"[SMB Negotiate] {service_name}"
        elif port == 139:
            # NetBIOS: related to SMB, use SMB probe result if available
            if _smb_probe_result and _smb_probe_result.get("smb_version", "Unknown") != "Unknown":
                service_name = f"NetBIOS-SSN ({_smb_probe_result['smb_version']})"
            else:
                service_name = "NetBIOS-SSN"
            banner_text = f"[NetBIOS Session Service]"
        elif port == 135:
            # MSRPC: send RPC bind to confirm Microsoft RPC
            service_name = _probe_msrpc_service(target_ip, port, timeout)
            banner_text = f"[DCE/RPC Endpoint Mapper]"
        elif port == 3632:
            # distccd: default port with safe protocol preamble check
            service_name, banner_text = _probe_distccd_service(target_ip, port, timeout)

        with service_results_lock:
            service_results[port] = {
                "service": service_name,
                "banner": banner_text,
            }
        return

    # ---- Standard banner grabbing for all other ports ----
    banner_text = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # ---- PHASE 1: PASSIVE LISTEN ----
        # Many services send a banner immediately on connect
        # Just sit quietly and see if they talk first
        try:
            sock.settimeout(PASSIVE_WAIT)
            raw_data = sock.recv(MAX_BANNER_SIZE)
            if raw_data:
                banner_text = raw_data.decode("utf-8", errors="ignore")
        except socket.timeout:
            # Service didn't talk first - that's ok, move to phase 2
            pass
        except OSError:
            pass

        # ---- PHASE 2: MINIMAL ACTIVE PROBE ----
        # Only if we got nothing from passive listening
        if not banner_text.strip():
            # Pick the right probe for this port's protocol
            probe = PROTOCOL_PROBES.get(port, PROTOCOL_PROBES["default"])

            try:
                sock.settimeout(timeout)
                sock.sendall(probe)
                raw_data = sock.recv(MAX_BANNER_SIZE)
                if raw_data:
                    banner_text = raw_data.decode("utf-8", errors="ignore")
            except socket.timeout:
                pass
            except OSError:
                pass

        # Clean socket teardown (stealth - no lingering connections)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        # Port was open during scan but closed now - race condition
        pass
    except OSError:
        pass

    # Clean up and identify the service
    banner_clean = clean_banner(banner_text)
    service_name = identify_service(banner_clean, port)

    # Store the result
    with service_results_lock:
        service_results[port] = {
            "service": service_name,
            "banner": banner_clean
        }


def run_service_id(target_ip, open_ports, timeout=DEFAULT_TIMEOUT,
                   max_threads=DEFAULT_MAX_THREADS,
                   delay=DEFAULT_DELAY, jitter=DEFAULT_JITTER):
    """
    Grab banners and identify services on all open ports.

    How it works:
    1. Takes the list of open ports from the port scanner
    2. For binary protocol ports (SMB/RPC), uses protocol-specific probes
    3. For other ports, does standard banner grabbing
    4. Shuffles port order (stealth - no sequential access pattern)
    5. Returns a clean dict of results

    Args:
        target_ip (str):    Target IP address
        open_ports (list):  List of open port numbers [21, 22, 80, ...]
        timeout (float):    Seconds to wait for banner per port
        max_threads (int):  Max simultaneous banner grabs
        delay (float):      Base delay between each grab
        jitter (float):     Random extra delay for stealth

    Returns:
        dict: {port: "service version"} — simplified service map
              Also stores SMB probe result in module-level _smb_probe_result
    """
    global service_results, _smb_probe_result

    # Reset shared data
    service_results = {}
    _smb_probe_result = {}

    if not open_ports:
        print("[*] No open ports to identify services on.")
        return {}

    # Separate protocol-probe ports from standard banner-grab ports
    # Protocol probes (SMB, RPC) should run first and sequentially
    # because the SMB probe result is shared with NetBIOS identification
    protocol_ports = [p for p in open_ports if p in PROTOCOL_PROBE_PORTS]
    standard_ports = [p for p in open_ports if p not in PROTOCOL_PROBE_PORTS]

    print(f"\n[*] Service identification on {target_ip}")
    print(f"[*] Grabbing banners from {len(open_ports)} open port(s)")
    print(f"[*] Strategy: protocol probes → passive listen → minimal probe")
    print(f"[*] Max threads: {max_threads} | Timeout: {timeout}s")
    if delay > 0 or jitter > 0:
        print(f"[*] Delay: {delay}s + 0-{jitter}s jitter")
    print()

    # ---- Phase A: Protocol-specific probes (sequential, SMB first) ----
    # Run SMB probe before NetBIOS/RPC because its result is shared
    smb_first = sorted(protocol_ports, key=lambda p: (p != 445, p))
    for port in smb_first:
        if delay > 0 or jitter > 0:
            time.sleep(delay + random.uniform(0, jitter))
        print(f"  [*] Protocol probe on port {port}...")
        grab_banner(target_ip, port, timeout)

    # ---- Phase B: Standard banner grabbing (threaded) ----
    random.shuffle(standard_ports)

    thread_limiter = threading.Semaphore(max_threads)
    threads = []
    scan_start = time.time()

    for port in standard_ports:
        thread_limiter.acquire()

        # Stealth delay between grabs
        if delay > 0 or jitter > 0:
            wait_time = delay + random.uniform(0, jitter)
            time.sleep(wait_time)

        def thread_worker(p):
            """Wrapper that releases semaphore when done."""
            try:
                grab_banner(target_ip, p, timeout)
            finally:
                thread_limiter.release()

        t = threading.Thread(target=thread_worker, args=(port,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all grabs to finish
    for t in threads:
        t.join()

    scan_duration = round(time.time() - scan_start, 2)

    # Print results table
    print(f"[+] Service ID complete in {scan_duration} seconds")
    print(f"[+] Identified {len(service_results)} service(s)\n")

    if service_results:
        print(f"  {'PORT':<8} {'SERVICE':<30} {'BANNER':<50}")
        print(f"  {'-'*8} {'-'*30} {'-'*50}")
        # Sort by port number for clean display
        for port in sorted(service_results.keys()):
            info = service_results[port]
            svc = info["service"][:28] if len(info["service"]) > 28 else info["service"]
            ban = info["banner"][:48] if len(info["banner"]) > 48 else info["banner"]
            print(f"  {port:<8} {svc:<30} {ban:<50}")
        print()

    # Build simplified output dict: {port: "service version"}
    # This is what other modules expect
    simple_results = {}
    for port in sorted(service_results.keys()):
        simple_results[port] = service_results[port]["service"]

    return simple_results


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":
    """
    Run from command line:
        python scanner/service_id.py <target_ip> <port1> <port2> ...
        python scanner/service_id.py 192.168.100.50 21 22 80 445
    """

    if len(sys.argv) < 3:
        print("Usage: python scanner/service_id.py <target_ip> <port1> <port2> ...")
        print("Example: python scanner/service_id.py 192.168.100.50 21 22 80 445")
        sys.exit(1)

    target = sys.argv[1]

    # Validate IP
    try:
        socket.inet_aton(target)
    except socket.error:
        print(f"[!] Invalid IP address: {target}")
        sys.exit(1)

    # Parse port numbers from remaining arguments
    ports = []
    for arg in sys.argv[2:]:
        try:
            p = int(arg)
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                print(f"[!] Skipping invalid port: {arg}")
        except ValueError:
            print(f"[!] Skipping non-numeric port: {arg}")

    if not ports:
        print("[!] No valid ports provided")
        sys.exit(1)

    results = run_service_id(target, ports)

    if results:
        sys.exit(0)
    else:
        print("[*] Could not identify any services.")
        sys.exit(1)
