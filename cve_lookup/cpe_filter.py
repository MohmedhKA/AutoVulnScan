"""
cpe_filter.py - CPE-based CVE Relevance Filtering (Enhanced)
=============================================================
Filters CVE results to only those actually applicable to the detected
service, version, and operating system.

THE PROBLEM:
  NVD keyword search for "SMB" returns every CVE that *mentions* SMB anywhere
  in its description — Samba (Linux), Ethereal/Wireshark dissectors,
  FreeRADIUS rlm_smb module, SMBCMS (a PHP CMS), phpWebSite, etc.
  Most are irrelevant to a Windows machine running the Windows SMB service.

HOW WE FIX IT (5 layers of filtering):
  1. OS detection — infer Windows/Linux from the service map
     (MSRPC + NetBIOS + SMB 3.x = definitely Windows)

  2. CPE platform check — each CVE in the NVD response includes
     'configurations' with CPE strings that name the vulnerable vendor
     and product.  We check:
       - Samba CVEs → drop if OS is Windows
       - Ethereal/Wireshark dissector CVEs → always drop (not a server)
       - Third-party SMB module CVEs (FreeRADIUS, pam_smb, SMBCMS) → drop

  3. Description fallback — for old CVEs without CPE data, we scan
     the description text for Samba/Ethereal/third-party keywords.

  4. Version range check — if we have a version string (e.g. "2.3.4"),
     we verify it falls within the CPE versionStart/End range.

  5. Age + OS version check — CVEs targeting ancient OS versions
     (Windows NT/2000/XP) are dropped when target runs modern Windows.
"""

import re


# ============================================================
# OS DETECTION
# ============================================================

WINDOWS_INDICATORS = {
    "msrpc", "netbios", "microsoft-ds", "rdp", "remote desktop",
    "winrm", "ldap", "windows", "smb 2", "smb 3",
    "microsoft windows rpc",
}
LINUX_INDICATORS = {
    "vsftpd", "proftpd", "sshd", "openssh", "nginx", "apache httpd",
    "dovecot", "postfix", "sendmail", "samba",
}


def detect_os(service_map):
    """
    Infer the target OS from the service identification results.

    Enhanced: Also checks for SMB version strings (SMB 3.x = Windows 10+)
    and "Microsoft Windows RPC" from our protocol probes.

    Args:
        service_map (dict): {port: "service version"} from service_id.py

    Returns:
        str: "windows", "linux", or "unknown"
    """
    win = 0
    lin = 0
    for svc in service_map.values():
        svc_l = str(svc).lower()
        for h in WINDOWS_INDICATORS:
            if h in svc_l:
                win += 1
        for h in LINUX_INDICATORS:
            if h in svc_l:
                lin += 1

    if win > 0 and win >= lin:
        return "windows"
    if lin > 0:
        return "linux"
    return "unknown"


# ============================================================
# SERVICE STRING PARSING
# ============================================================

def parse_service_version(service_string):
    """
    Split "vsftpd 2.3.4"              → ("vsftpd", "2.3.4")
    Split "SMB"                        → ("SMB", "")
    Split "SMB 3.1.1 (Windows 11)"    → ("SMB", "3.1.1")
    Split "Apache 2.2.8"              → ("Apache", "2.2.8")
    Split "OpenSSH 4.7p1"             → ("OpenSSH", "4.7p1")

    Returns:
        tuple: (service_name, version_string)
    """
    # Handle our enhanced SMB strings like "SMB 3.1.1 (Windows 11)"
    smb_match = re.match(r'^(SMB)\s+([\d.]+)', service_string, re.I)
    if smb_match:
        return smb_match.group(1), smb_match.group(2)

    parts = service_string.strip().split()
    if len(parts) == 1:
        return parts[0], ""
    # Version token = last part that starts with a digit
    for i in range(len(parts) - 1, 0, -1):
        if re.match(r'^\d', parts[i]):
            return " ".join(parts[:i]), parts[i]
    return service_string, ""


# ============================================================
# CPE PARSING
# ============================================================

def parse_cpe(cpe_str):
    """
    Parse a CPE 2.3 URI into components.
    Format: cpe:2.3:<type>:<vendor>:<product>:<version>:...

    Returns:
        dict with keys: type, vendor, product, version
    """
    parts = cpe_str.split(":")
    if len(parts) < 6:
        return {"type": "", "vendor": "", "product": "", "version": ""}
    return {
        "type":    parts[2],       # a=app, o=os, h=hardware
        "vendor":  parts[3].lower(),
        "product": parts[4].lower(),
        "version": parts[5].lower(),
    }


def _vendors_products(cpe_list):
    """Return sets of (vendor, product) pairs from a CPE list."""
    pairs, vendors, products = set(), set(), set()
    for entry in cpe_list:
        cpe = parse_cpe(entry.get("criteria", ""))
        if cpe["vendor"]:
            pairs.add((cpe["vendor"], cpe["product"]))
            vendors.add(cpe["vendor"])
            products.add(cpe["product"])
    return pairs, vendors, products


# ============================================================
# PLATFORM RELEVANCE
# ============================================================

# Linux Samba implementation of SMB
_SAMBA = {("samba", "samba")}

# Packet analyzers — CVEs about their "SMB dissector" are NOT about the SMB service
_ANALYZER_VENDORS = {"ethereal_project", "wireshark", "tcpdump", "gerald_combs"}
_ANALYZER_PRODUCTS = {"ethereal", "wireshark"}

# Third-party tools that happen to use SMB as a module/library
# This list catches products like "SMBCMS" (a PHP CMS), FreeRADIUS rlm_smb, etc.
_THIRDPARTY = {
    "freeradius", "pam_smb_project", "smb2www", "smbcms_project", "smbcms",
    "smartblog", "smblog", "netpbm", "ibm", "iss",
    "phpwebsite_project", "phpwebsite", "netmon",
    "apache", "apache_http_server",
}

# Third-party products (by product name in CPE)
_THIRDPARTY_PRODUCTS = {
    "smbcms", "phpwebsite", "pam_smb", "rlm_smb", "smb2www",
    "smartblog", "smblog", "netmon", "network_monitor",
    "apache_http_server", "smbvalid",
}

# Old Windows versions — CVEs only affecting these are irrelevant for modern targets
_OLD_WINDOWS_PRODUCTS = {
    "windows_nt", "windows_2000", "windows_xp",
    "windows_server_2003", "windows_me", "windows_98", "windows_95",
}

# Modern Windows products (Windows 10, 11, Server 2016+)
_MODERN_WINDOWS_PRODUCTS = {
    "windows_10", "windows_11", "windows_server_2016",
    "windows_server_2019", "windows_server_2022",
}

# Fallback: description keyword patterns for CVEs with no CPE data
_DESC_SAMBA = re.compile(
    r'\b(samba|smbd|smbmnt|nmbd|smb\.conf|samba\s+before)\b', re.I
)
_DESC_ANALYZER = re.compile(r'\b(ethereal|wireshark)\b', re.I)
_DESC_THIRDPARTY = re.compile(
    r'\b(freeradius|rlm_smb|pam_smb|smb2www|smbcms|smartblog|smblog|'
    r'phpwebsite|smbvalid|smbval|netmon|protocol\s+analysis\s+module|'
    r'Apache::AuthenSmb|network\s+monitor|smb\s*cms)\b', re.I
)
_DESC_WINDOWS = re.compile(r'\b(windows\s+(nt|2000|xp|server|vista|7|8|10|11))\b', re.I)

# Old Windows version pattern in descriptions — used to detect ancient CVEs
_DESC_OLD_WINDOWS_ONLY = re.compile(
    r'\b(windows\s+(nt|2000|xp|95|98|me|server\s+2003))\b', re.I
)
_DESC_MODERN_WINDOWS = re.compile(
    r'\b(windows\s+(10|11|server\s+201[6-9]|server\s+202[0-9]))\b', re.I
)


def _is_platform_relevant_by_cpe(cpe_list, svc_lower, detected_os):
    """Check CPE data for platform relevance. Returns (ok, reason) or None."""
    if not cpe_list:
        return None  # No CPE data → fall through to description check

    pairs, vendors, products = _vendors_products(cpe_list)

    # Always drop packet-analyzer CVEs
    if vendors & _ANALYZER_VENDORS or products & _ANALYZER_PRODUCTS:
        return False, "packet analyzer CVE (Ethereal/Wireshark dissector)"

    # Always drop third-party tool CVEs (by vendor)
    tp_hit = vendors & _THIRDPARTY
    if tp_hit:
        return False, f"third-party tool CVE ({', '.join(sorted(tp_hit))})"

    # Also check by product name (catches SMBCMS etc.)
    tp_prod_hit = products & _THIRDPARTY_PRODUCTS
    if tp_prod_hit:
        return False, f"third-party product ({', '.join(sorted(tp_prod_hit))})"

    # If OS is Windows and CVE is Samba-only → drop
    if detected_os == "windows" and ("smb" in svc_lower or "netbios" in svc_lower):
        is_samba_only = bool(pairs & _SAMBA) and not bool(
            vendors & {"microsoft"}
        )
        if is_samba_only:
            return False, "Samba (Linux) CVE, target is Windows"

    # If OS is Linux and CVE is Windows-only → drop
    if detected_os == "linux" and "smb" in svc_lower:
        is_win_only = bool(vendors & {"microsoft"}) and not bool(pairs & _SAMBA)
        if is_win_only:
            return False, "Windows-only CVE, target is Linux"

    # Check for ancient Windows versions when target is modern Windows
    if detected_os == "windows" and ("smb" in svc_lower or "rpc" in svc_lower):
        only_old_windows = all(
            p in _OLD_WINDOWS_PRODUCTS
            for v, p in pairs
            if v == "microsoft" and p.startswith("windows")
        )
        has_any_windows = any(
            p.startswith("windows") for v, p in pairs if v == "microsoft"
        )
        if has_any_windows and only_old_windows:
            return False, "CVE only affects legacy Windows (NT/2000/XP)"

    return True, "platform matches"


def _is_platform_relevant_by_desc(description, svc_lower, detected_os):
    """Fallback: check description text for platform clues."""
    desc = description or ""

    # Always drop packet-analyzer CVEs
    if _DESC_ANALYZER.search(desc):
        return False, "packet analyzer CVE (Ethereal/Wireshark dissector)"

    # Always drop clearly third-party CVEs
    if _DESC_THIRDPARTY.search(desc):
        m = _DESC_THIRDPARTY.search(desc)
        return False, f"third-party tool CVE ({m.group(1) if m else 'module'})"

    # SMB on Windows target → drop Samba description CVEs
    if detected_os == "windows" and "smb" in svc_lower:
        mentions_samba = bool(_DESC_SAMBA.search(desc))
        mentions_windows = bool(_DESC_WINDOWS.search(desc))
        if mentions_samba and not mentions_windows:
            return False, "Samba (Linux) CVE (by description), target is Windows"

    # For Windows targets: drop CVEs that ONLY mention old Windows versions
    if detected_os == "windows" and ("smb" in svc_lower or "rpc" in svc_lower):
        mentions_old = bool(_DESC_OLD_WINDOWS_ONLY.search(desc))
        mentions_modern = bool(_DESC_MODERN_WINDOWS.search(desc))
        if mentions_old and not mentions_modern:
            # Double-check: see if it mentions ANY version after XP/2003
            mentions_vista_plus = re.search(
                r'\b(windows\s+(vista|7|8|8\.1|10|11|server\s+200[89]|'
                r'server\s+201[0-9]|server\s+202[0-9]))\b', desc, re.I
            )
            if not mentions_vista_plus:
                return False, "CVE targets only legacy Windows versions"

    return True, "no CPE data, passed description check"


# ============================================================
# VERSION RANGE CHECKING
# ============================================================

def _parse_ver(v_str):
    """Convert "2.3.4" or "4.7p1" → (2, 3, 4) for comparison. None if invalid."""
    if not v_str or v_str in ("*", "-", ""):
        return None
    clean = re.split(r'[_\-]', v_str)[0]  # strip _sp6a, -rc1 suffixes
    parts = re.findall(r'\d+', clean)
    return tuple(int(p) for p in parts) if parts else None


def _ver_in_range(sv, start_incl, start_excl, end_incl, end_excl):
    """Check if sv (version tuple) is within a CPE version range."""
    if sv is None:
        return True  # Can't compare → assume in range

    si = _parse_ver(start_incl)
    sx = _parse_ver(start_excl)
    ei = _parse_ver(end_incl)
    ex = _parse_ver(end_excl)

    if si and sv < si:   return False
    if sx and sv <= sx:  return False
    if ei and sv > ei:   return False
    if ex and sv >= ex:  return False

    return True


def is_version_relevant(cpe_list, service_version):
    """
    Check if the detected service version falls within any vulnerable range.

    Returns: (relevant: bool, reason: str)
    """
    if not service_version or service_version.lower() in ("unknown", "*", ""):
        return True, "no version to check"

    ranged = [
        e for e in cpe_list
        if any([
            e.get("versionStartIncluding"),
            e.get("versionStartExcluding"),
            e.get("versionEndIncluding"),
            e.get("versionEndExcluding"),
        ])
    ]

    if not ranged:
        return True, "no version ranges in CVE"

    sv = _parse_ver(service_version)
    for entry in ranged:
        if _ver_in_range(
            sv,
            entry.get("versionStartIncluding", ""),
            entry.get("versionStartExcluding", ""),
            entry.get("versionEndIncluding", ""),
            entry.get("versionEndExcluding", ""),
        ):
            return True, f"version {service_version} in vulnerable range"

    return False, f"version {service_version} outside all vulnerable ranges"


# ============================================================
# MAIN APPLICABILITY CHECK
# ============================================================

def is_cve_applicable(cve, service_name, service_version, detected_os):
    """
    Determine if a CVE is truly applicable to the detected service/OS.

    Args:
        cve (dict):           CVE record (must have 'cpe_list' if available)
        service_name (str):   e.g. "SMB", "vsftpd"
        service_version (str): e.g. "2.3.4" or ""
        detected_os (str):    "windows", "linux", or "unknown"

    Returns:
        (applicable: bool, reason: str)
    """
    cpe_list = cve.get("cpe_list", [])
    description = cve.get("description", "")
    svc_lower = service_name.lower()

    # 1. Platform check via CPE
    cpe_result = _is_platform_relevant_by_cpe(cpe_list, svc_lower, detected_os)

    if cpe_result is not None:
        ok, reason = cpe_result
        if not ok:
            return False, reason
    else:
        # 2. Fallback: platform check via description text
        ok, reason = _is_platform_relevant_by_desc(description, svc_lower, detected_os)
        if not ok:
            return False, reason

    # 3. Version range check
    ok, reason = is_version_relevant(cpe_list, service_version)
    if not ok:
        return False, reason

    return True, "applicable"


def filter_cves(cves, service_name, service_version, detected_os):
    """
    Filter a CVE list to only those applicable to the detected service.

    Args:
        cves (list):           CVE records from nvd_api.py
        service_name (str):    e.g. "SMB"
        service_version (str): e.g. "2.3.4" or ""
        detected_os (str):     "windows", "linux", or "unknown"

    Returns:
        tuple: (applicable_list, filtered_out_list)
               Each CVE gets an 'applicability_note' field.
    """
    applicable, filtered_out = [], []

    for cve in cves:
        ok, reason = is_cve_applicable(cve, service_name, service_version, detected_os)
        cve_copy = dict(cve)
        cve_copy["applicability_note"] = reason
        if ok:
            applicable.append(cve_copy)
        else:
            cve_copy["filter_reason"] = reason
            filtered_out.append(cve_copy)

    return applicable, filtered_out
