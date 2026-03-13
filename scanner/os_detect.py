"""
os_detect.py - OS & SMB Protocol Version Detection
====================================================
Detects the target operating system by sending a raw SMB negotiate
packet and parsing the response.  This is the same handshake every
Windows machine performs when opening a file share, so it blends in
perfectly with normal network traffic (very stealthy).

HOW IT WORKS:
  1. Connect to port 445 (SMB direct TCP)
  2. Send an SMB2 Negotiate Request offering all dialects up to 3.1.1
  3. The server picks the highest dialect it supports and responds
  4. We parse the dialect and capabilities from the response
  5. Map the dialect to a Windows version range

DIALECT → OS MAPPING:
  SMB 3.1.1  → Windows 10 / 11 / Server 2016+
  SMB 3.0.2  → Windows 8.1 / Server 2012 R2
  SMB 3.0    → Windows 8 / Server 2012
  SMB 2.1    → Windows 7 / Server 2008 R2
  SMB 2.0.2  → Windows Vista / Server 2008
  SMB 1.0    → Windows XP / 2003 / Samba (Linux)

STEALTH:
  - SMB negotiate is a single round-trip (2 packets)
  - Looks identical to normal Windows file sharing
  - Clean socket teardown immediately after
  - No authentication attempted

USAGE:
  from scanner.os_detect import detect_os_version
  result = detect_os_version("10.98.22.174")
"""

import socket       # For raw TCP connections
import struct       # For building/parsing binary SMB packets
import os as _os    # For random salt generation
import time         # For timing


# ============================================================
# SMB DIALECT DEFINITIONS
# ============================================================

SMB_DIALECTS = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x02FF: "SMB 2.x (wildcard)",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# Maps SMB dialect to likely OS version
DIALECT_OS_MAP = {
    0x0311: {"os_family": "windows", "os_version": "Windows 10/11 or Server 2016+",
             "os_gen": "modern"},
    0x0302: {"os_family": "windows", "os_version": "Windows 8.1 or Server 2012 R2",
             "os_gen": "modern"},
    0x0300: {"os_family": "windows", "os_version": "Windows 8 or Server 2012",
             "os_gen": "modern"},
    0x0210: {"os_family": "windows", "os_version": "Windows 7 or Server 2008 R2",
             "os_gen": "legacy"},
    0x0202: {"os_family": "windows", "os_version": "Windows Vista or Server 2008",
             "os_gen": "legacy"},
}


# ============================================================
# SMB PACKET BUILDERS
# ============================================================

def _build_smb2_negotiate():
    """
    Build an SMB2 Negotiate Request packet with dialects up to 3.1.1.

    The packet structure:
      [NetBIOS Session Header (4 bytes)]
      [SMB2 Header (64 bytes)]
      [Negotiate Request Body (36 bytes fixed + dialects + contexts)]

    We include SMB 3.1.1 Negotiate Contexts (Preauth Integrity +
    Encryption Capabilities) so the server can pick dialect 3.1.1.

    Returns:
        bytes: Complete packet ready to send over TCP
    """
    # Dialects we offer (lowest to highest)
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    dialect_count = len(dialects)

    # ---- Negotiate Contexts for SMB 3.1.1 ----

    # Preauth Integrity Capabilities (context type 0x0001)
    # Required for SMB 3.1.1 — tells server which hash algorithm to use
    preauth_data = struct.pack('<H', 1)        # HashAlgorithmCount: 1
    preauth_data += struct.pack('<H', 32)      # SaltLength: 32 bytes
    preauth_data += struct.pack('<H', 0x0001)  # Algorithm: SHA-512
    preauth_data += _os.urandom(32)            # Random salt

    # Context header: type (2) + data_len (2) + reserved (4)
    preauth_ctx = struct.pack('<HHI', 0x0001, len(preauth_data), 0)
    preauth_ctx += preauth_data
    # Pad to 8-byte alignment (required between contexts)
    preauth_pad = (8 - len(preauth_ctx) % 8) % 8
    preauth_ctx += b'\x00' * preauth_pad

    # Encryption Capabilities (context type 0x0002)
    encrypt_data = struct.pack('<H', 2)        # CipherCount: 2
    encrypt_data += struct.pack('<H', 0x0002)  # AES-128-GCM
    encrypt_data += struct.pack('<H', 0x0001)  # AES-128-CCM

    encrypt_ctx = struct.pack('<HHI', 0x0002, len(encrypt_data), 0)
    encrypt_ctx += encrypt_data
    # Last context: no padding needed

    all_contexts = preauth_ctx + encrypt_ctx
    context_count = 2

    # ---- Calculate NegotiateContextOffset ----
    # Offset from the start of the SMB2 header to the first context
    header_size = 64
    body_fixed_size = 36               # Negotiate request structure size
    dialects_size = dialect_count * 2  # Each dialect is 2 bytes
    before_contexts = body_fixed_size + dialects_size
    # Pad to 8-byte alignment
    ctx_padding = (8 - before_contexts % 8) % 8
    negotiate_ctx_offset = header_size + before_contexts + ctx_padding

    # ---- SMB2 Header (64 bytes) ----
    header = b'\xfeSMB'                         # Protocol ID
    header += struct.pack('<H', 64)              # Structure Size
    header += struct.pack('<H', 0)               # Credit Charge
    header += struct.pack('<I', 0)               # Status
    header += struct.pack('<H', 0)               # Command: NEGOTIATE
    header += struct.pack('<H', 31)              # Credit Request
    header += struct.pack('<I', 0)               # Flags
    header += struct.pack('<I', 0)               # Next Command
    header += struct.pack('<Q', 0)               # Message ID
    header += struct.pack('<I', 0)               # Reserved
    header += struct.pack('<I', 0)               # Tree ID
    header += struct.pack('<Q', 0)               # Session ID
    header += b'\x00' * 16                       # Signature

    # ---- Negotiate Request Body ----
    body = struct.pack('<H', 36)                 # Structure Size
    body += struct.pack('<H', dialect_count)      # Dialect Count
    body += struct.pack('<H', 0x01)              # Security Mode: signing enabled
    body += struct.pack('<H', 0)                 # Reserved
    body += struct.pack('<I', 0x7F)              # Capabilities (all)
    body += b'\x00' * 16                         # Client GUID (zeros for stealth)
    body += struct.pack('<I', negotiate_ctx_offset)
    body += struct.pack('<H', context_count)
    body += struct.pack('<H', 0)                 # Reserved2

    # Append dialect values
    for d in dialects:
        body += struct.pack('<H', d)

    # Padding before contexts
    body += b'\x00' * ctx_padding

    # Append negotiate contexts
    body += all_contexts

    # ---- Assemble full packet ----
    smb2_msg = header + body

    # NetBIOS Session header: type (1 byte) + length (3 bytes big-endian)
    nb_header = b'\x00' + struct.pack('>I', len(smb2_msg))[1:]

    return nb_header + smb2_msg


def _build_smb1_negotiate():
    """
    Build an SMB1 Negotiate Request as fallback for older targets.

    Offers both SMB1 and SMB2 dialects. If the server supports SMB2,
    it responds with an SMB2 Negotiate Response (protocol upgrade).

    Returns:
        bytes: Complete packet ready to send over TCP
    """
    # Dialect strings: format is 0x02 + ASCII string + 0x00
    dialect_names = [
        b'NT LM 0.12',     # SMB1 NT LM 0.12 (the most common SMB1 dialect)
        b'SMB 2.002',      # SMB 2.0.2
        b'SMB 2.???',      # Wildcard: server picks highest supported SMB2
    ]
    dialect_buf = b''
    for name in dialect_names:
        dialect_buf += b'\x02' + name + b'\x00'

    # SMB1 Header (32 bytes)
    header = b'\xff\x53\x4d\x42'                # Protocol: \xffSMB
    header += b'\x72'                             # Command: Negotiate (0x72)
    header += b'\x00\x00\x00\x00'                # Status: SUCCESS
    header += b'\x18'                             # Flags
    header += struct.pack('<H', 0xC853)           # Flags2: Unicode + NT Status + Extended Sec
    header += b'\x00\x00'                         # PID High
    header += b'\x00' * 8                         # Security Features
    header += b'\x00\x00'                         # Reserved
    header += b'\xff\xff'                         # Tree ID
    header += struct.pack('<H', 0xFEFF)           # Process ID
    header += b'\x00\x00'                         # User ID
    header += b'\x00\x00'                         # Multiplex ID

    # Negotiate body
    body = b'\x00'                                # Word Count: 0
    body += struct.pack('<H', len(dialect_buf))   # Byte Count
    body += dialect_buf

    smb1_msg = header + body

    # NetBIOS Session header
    nb_header = b'\x00' + struct.pack('>I', len(smb1_msg))[1:]

    return nb_header + smb1_msg


# ============================================================
# SMB RESPONSE PARSER
# ============================================================

def _parse_smb_response(data):
    """
    Parse an SMB Negotiate Response to extract dialect and capabilities.

    The response could be SMB1 (magic \\xffSMB) or SMB2 (magic \\xfeSMB).
    We handle both cases.

    Args:
        data (bytes): Raw response bytes from the server

    Returns:
        dict: Parsed info including dialect, version name, capabilities
              or None if parsing failed
    """
    if not data or len(data) < 8:
        return None

    # Skip NetBIOS header (4 bytes)
    smb_data = data[4:]

    # Check which SMB version the server responded with
    magic = smb_data[:4]

    if magic == b'\xfeSMB':
        # SMB2/3 response
        return _parse_smb2_response(smb_data)

    elif magic == b'\xffSMB':
        # SMB1 response — server only supports SMB1
        return {
            "protocol": "SMB1",
            "dialect": 0x0000,
            "dialect_name": "SMB 1.0 (NT LM 0.12)",
            "os_family": "unknown",
            "os_version": "Legacy Windows (XP/2003) or Samba",
            "os_gen": "legacy",
        }

    return None


def _parse_smb2_response(smb2_data):
    """
    Parse an SMB2 Negotiate Response.

    Layout (offsets relative to start of SMB2 data):
      Byte 0-3:   Protocol ID (\\xfeSMB)
      Byte 4-63:  SMB2 Header
      Byte 64+:   Negotiate Response Body
        Body offsets (relative to byte 64):
          0-1:  StructureSize (65)
          2-3:  SecurityMode
          4-5:  DialectRevision  ← the key field
          6-7:  NegotiateContextCount / Reserved
          8-23: ServerGuid (16 bytes)
          24-27: Capabilities
          28-31: MaxTransactSize
          32-35: MaxReadSize
          36-39: MaxWriteSize
          40-47: SystemTime (Windows FILETIME)
          48-55: ServerStartTime

    Args:
        smb2_data (bytes): SMB2 data (after NetBIOS header)

    Returns:
        dict: Parsed SMB2 negotiate response info
    """
    # Need at least header (64) + first 6 bytes of body
    if len(smb2_data) < 70:
        return {
            "protocol": "SMB2",
            "dialect": 0,
            "dialect_name": "SMB 2.x (response too short)",
            "error": "truncated response",
        }

    # Parse key fields from the negotiate response body
    body_offset = 64
    dialect_revision = struct.unpack_from('<H', smb2_data, body_offset + 4)[0]
    dialect_name = SMB_DIALECTS.get(dialect_revision,
                                     f"SMB 2.x (0x{dialect_revision:04x})")

    result = {
        "protocol": "SMB2",
        "dialect": dialect_revision,
        "dialect_name": dialect_name,
    }

    # Parse additional fields if data is long enough
    if len(smb2_data) >= body_offset + 56:
        security_mode = struct.unpack_from('<H', smb2_data, body_offset + 2)[0]
        server_guid = smb2_data[body_offset + 8 : body_offset + 24]
        capabilities = struct.unpack_from('<I', smb2_data, body_offset + 24)[0]
        system_time = struct.unpack_from('<Q', smb2_data, body_offset + 40)[0]

        result["security_mode"] = security_mode
        result["capabilities"] = capabilities
        result["signing_required"] = bool(security_mode & 0x02)
        result["encryption_supported"] = bool(capabilities & 0x0040)

        # Convert Windows FILETIME to readable timestamp
        if system_time > 0:
            try:
                epoch_diff = 116444736000000000  # 100ns ticks between 1601 and 1970
                unix_ts = (system_time - epoch_diff) / 10000000
                from datetime import datetime
                result["server_time"] = datetime.utcfromtimestamp(unix_ts).strftime(
                    "%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError, OverflowError):
                pass

    # Map dialect to OS info
    os_info = DIALECT_OS_MAP.get(dialect_revision, {
        "os_family": "unknown",
        "os_version": "Unknown",
        "os_gen": "unknown",
    })
    result.update(os_info)

    return result


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect_os_version(target_ip, port=445, timeout=5.0):
    """
    Detect OS version by performing an SMB negotiate handshake.

    This is the main function other modules should call.

    Strategy:
      1. Try SMB2 negotiate directly (works on Vista+)
      2. If that fails, try SMB1 negotiate (works on XP/2003/Samba)
      3. If port 445 is closed, try port 139 for NetBIOS
      4. Combine SMB results with service-based heuristics

    Args:
        target_ip (str):  Target IP address
        port (int):       SMB port (default 445)
        timeout (float):  Socket timeout in seconds

    Returns:
        dict: Detection results with keys:
              - os_family: "windows", "linux", or "unknown"
              - os_version: Human-readable version string
              - os_gen: "modern", "legacy", or "unknown"
              - smb_dialect: Hex dialect code
              - smb_version: Human-readable SMB version
              - details: Dict of all parsed SMB fields
    """
    result = {
        "os_family": "unknown",
        "os_version": "Unknown",
        "os_gen": "unknown",
        "smb_dialect": None,
        "smb_version": "Unknown",
        "details": {},
    }

    # ---- Step 1: Try SMB2 Negotiate directly ----
    smb_info = _try_smb2_negotiate(target_ip, port, timeout)

    if smb_info and smb_info.get("dialect", 0) > 0:
        result["os_family"] = smb_info.get("os_family", "unknown")
        result["os_version"] = smb_info.get("os_version", "Unknown")
        result["os_gen"] = smb_info.get("os_gen", "unknown")
        result["smb_dialect"] = smb_info.get("dialect")
        result["smb_version"] = smb_info.get("dialect_name", "Unknown")
        result["details"] = smb_info
        return result

    # ---- Step 2: Fallback to SMB1 negotiate ----
    smb1_info = _try_smb1_negotiate(target_ip, port, timeout)

    if smb1_info:
        # If SMB1 negotiate triggered SMB2 response (server supports both)
        if smb1_info.get("protocol") == "SMB2":
            result["os_family"] = smb1_info.get("os_family", "windows")
            result["os_version"] = smb1_info.get("os_version", "Windows (version unknown)")
            result["os_gen"] = smb1_info.get("os_gen", "unknown")
            result["smb_dialect"] = smb1_info.get("dialect")
            result["smb_version"] = smb1_info.get("dialect_name", "SMB 2.x")
        else:
            result["os_family"] = smb1_info.get("os_family", "unknown")
            result["os_version"] = smb1_info.get("os_version", "Legacy OS")
            result["os_gen"] = "legacy"
            result["smb_dialect"] = 0x0000
            result["smb_version"] = "SMB 1.0"
        result["details"] = smb1_info
        return result

    return result


def _try_smb2_negotiate(target_ip, port, timeout):
    """Send SMB2 negotiate and parse response. Returns dict or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        packet = _build_smb2_negotiate()
        sock.sendall(packet)

        response = sock.recv(4096)

        # Clean shutdown
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

        return _parse_smb_response(response)

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _try_smb1_negotiate(target_ip, port, timeout):
    """Send SMB1 negotiate (with SMB2 dialects) and parse response. Returns dict or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        packet = _build_smb1_negotiate()
        sock.sendall(packet)

        response = sock.recv(4096)

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

        return _parse_smb_response(response)

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


# ============================================================
# SERVICE-BASED OS HEURISTICS (no SMB required)
# ============================================================

def infer_os_from_services(service_map):
    """
    Infer OS from service identification results (fallback when SMB
    negotiation is not available, e.g., port 445 is closed).

    Enhanced: Also parses SMB version strings from service_id to
    infer Windows version (e.g., "SMB 3.1.1" → Windows 10/11).

    Args:
        service_map (dict): {port: "service version"} from service_id.py

    Returns:
        dict: {"os_family": str, "os_version": str, "os_gen": str}
    """
    import re

    win_score = 0
    lin_score = 0
    smb_version = None

    win_hints = [
        "msrpc", "netbios", "microsoft", "rdp", "remote desktop",
        "winrm", "iis", "mssql", "windows",
    ]
    lin_hints = [
        "vsftpd", "proftpd", "openssh", "nginx", "apache",
        "dovecot", "postfix", "sendmail", "samba", "ubuntu",
        "debian", "centos", "fedora",
    ]

    # SMB dialect → OS version mapping (same as detect_os_version)
    dialect_os_map = {
        "3.1.1": ("Windows 10/11 or Server 2016+", "modern"),
        "3.0.2": ("Windows 8.1 or Server 2012 R2", "8.1"),
        "3.0":   ("Windows 8 or Server 2012", "8"),
        "2.1":   ("Windows 7 or Server 2008 R2", "7"),
        "2.0.2": ("Windows Vista or Server 2008", "vista"),
    }

    for svc in service_map.values():
        svc_lower = str(svc).lower()
        for hint in win_hints:
            if hint in svc_lower:
                win_score += 1
        for hint in lin_hints:
            if hint in svc_lower:
                lin_score += 1

        # Check for SMB version in service string (e.g., "SMB 3.1.1 (Windows 11)")
        smb_match = re.search(r'smb\s+([\d.]+)', svc_lower)
        if smb_match:
            smb_version = smb_match.group(1)
            win_score += 2  # SMB version detection strongly indicates Windows

    if win_score > 0 and win_score >= lin_score:
        os_ver = "Windows (version unknown from services)"
        os_gen = "unknown"
        if smb_version and smb_version in dialect_os_map:
            os_ver, os_gen = dialect_os_map[smb_version]
        return {
            "os_family": "windows",
            "os_version": os_ver,
            "os_gen": os_gen,
            "smb_version": smb_version or "",
        }
    if lin_score > 0:
        return {
            "os_family": "linux",
            "os_version": "Linux (distribution unknown)",
            "os_gen": "unknown",
        }

    return {"os_family": "unknown", "os_version": "Unknown", "os_gen": "unknown"}


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    """
    Run from command line:
        python scanner/os_detect.py <target_ip>
        python scanner/os_detect.py 10.98.22.174
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scanner/os_detect.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"\n[*] Detecting OS on {target} via SMB negotiate...")

    info = detect_os_version(target)

    print(f"\n[+] Results:")
    print(f"    OS Family:   {info['os_family']}")
    print(f"    OS Version:  {info['os_version']}")
    print(f"    SMB Version: {info['smb_version']}")
    print(f"    Generation:  {info['os_gen']}")

    if info.get("details"):
        print(f"\n    Details:")
        for k, v in info["details"].items():
            if k not in ("os_family", "os_version", "os_gen"):
                print(f"      {k}: {v}")
    print()
