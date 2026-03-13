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
    "elinks_project", "links_project", "links",
    "phpmyadmin", "basilix", "logicworks", "pam_mysql",
    "axent", "pccs-linux", "teapop", "mysql_administrator",
}

# Third-party products (by product name in CPE)
_THIRDPARTY_PRODUCTS = {
    "smbcms", "phpwebsite", "pam_smb", "rlm_smb", "smb2www",
    "smartblog", "smblog", "netmon", "network_monitor",
    "apache_http_server", "http_server", "smbvalid",
    "elinks", "links",
    "phpmyadmin", "mysqldatabaseadmintool", "pam_mysql", "basilixwebmail",
    "weberp", "netprowler", "teapop",
}

# NFS: non-Linux OS vendors — CVEs targeting these are irrelevant
# when the target is a Linux NFS server (nfs-utils / knfsd)
_NFS_NON_LINUX_OS_VENDORS = {
    "apple", "sgi", "sun", "digital", "novell", "ibm",
    "freebsd", "netbsd", "openbsd", "bsdi",
}

# NFS: packet-sniffer/client tools — not the NFS server
_NFS_TOOL_VENDORS = {"lbl", "tcpdump", "ethereal_project", "wireshark"}
_NFS_TOOL_PRODUCTS = {"tcpdump", "ethereal", "wireshark"}

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

# Service-topic relevance patterns
_DESC_SMB_TOPIC = re.compile(
    r'\b(smb(?:v\d+(?:\.\d+)*)?|server\s+message\s+block|cifs|netbios)\b', re.I
)
_DESC_RPC_TOPIC = re.compile(
    r'\b(rpc|remote\s+procedure\s+call|msrpc|dcom)\b', re.I
)
_DESC_RMI_TOPIC = re.compile(
    r'\b(java\s+rmi|java\.rmi|rmi\s+registry|rmiregistry|'
    r'remote\s+method\s+invocation)\b', re.I
)
_RMI_CORE_VENDORS = {"oracle", "sun", "openjdk"}
_RMI_CORE_PRODUCTS = {"jre", "jdk", "java_se", "openjdk"}

_X11_SERVER_VENDORS = {"x.org", "x_consortium", "xfree86", "x11"}
_X11_SERVER_PRODUCTS = {
    "x11r6", "x11r7", "xorg-server", "xfree86",
    "x.org", "x11", "x_window_system",
}
_DESC_X11_SERVER = re.compile(
    r'\b(x\.?org\s+server|xorg.server|x11\s+server|x\s+server|'
    r'x\.?org\s+x11|xfree86\s+server)\b', re.I
)
_NFS_NON_LINUX_DESC = re.compile(
    r'\b(irix|solaris|sunos|mac\s*os|macosx|ultrix|netware|'
    r'aix|hp-?ux|tru64)\b', re.I
)
_NFS_LINUX_DESC = re.compile(r'\b(linux|nfs-utils|knfsd|rpc\.nfsd)\b', re.I)

# IRC client products that should not be matched against IRC daemon services.
_IRC_CLIENT_PRODUCTS = {
    "xchat", "trillian", "bitchx", "muh", "pirch", "pirch_irc",
    "ircit", "irssi", "epic4", "kicq", "ircii",
}

# SMB ecosystem products that are not Linux Samba server vulnerabilities.
_SMB_NON_SAMBA_VENDORS = {"owncloud", "sysaid", "sap"}


def _is_irc_daemon_service(svc_lower):
    """True when scanned service appears to be an IRC server/daemon."""
    return any(token in svc_lower for token in ("unrealircd", "ircd", "irc"))


def is_irc_client_product(cpe_string):
    """
    Return True when a CPE string refers to known IRC client software.

    This helps avoid server-side false positives on IRC daemon ports.
    """
    cpe = parse_cpe(cpe_string or "")
    vendor = cpe.get("vendor", "")
    product = cpe.get("product", "")
    blob = f"{vendor}:{product}:{str(cpe_string).lower()}"
    return any(token in blob for token in _IRC_CLIENT_PRODUCTS)


def _is_linux_samba_context(svc_lower, detected_os, os_info=None, service_map=None):
    """
    Heuristic for Linux/Samba SMB context.

    Treat SMB services as Samba-like when:
      - detected OS is linux, OR
      - detected OS is unknown, SMB dialect is SMB 1.0, and a Samba
        service hint is present in the service map.
    """
    if "smb" not in svc_lower and "netbios" not in svc_lower:
        return False

    if detected_os == "linux":
        return True

    if detected_os != "unknown" or not os_info:
        return False

    smb_version = str(os_info.get("smb_version", "")).strip().lower()
    if smb_version != "smb 1.0":
        return False

    if "samba" in svc_lower:
        return True

    if service_map:
        for svc in service_map.values():
            if "samba" in str(svc).lower():
                return True

    return False


def _is_service_relevant(cpe_list, description, svc_lower):
    """
    Ensure CVE topic matches the scanned service, not just the OS platform.

    Example false positive this blocks:
      service = "Microsoft Windows RPC"
      CVE    = "Windows Encrypting File System RCE"
    """
    desc = description or ""
    _, vendors, products = _vendors_products(cpe_list) if cpe_list else (set(), set(), set())

    # SMB / NetBIOS ports should only keep SMB-related CVEs.
    if "smb" in svc_lower or "netbios" in svc_lower:
        if _DESC_SMB_TOPIC.search(desc):
            return True, "service-topic matches SMB/NetBIOS"
        if any("smb" in p or "netbios" in p for p in products):
            return True, "service-topic matches SMB/NetBIOS (by CPE product)"
        return False, "CVE not related to SMB/NetBIOS service"

    # RPC (port 135) should only keep RPC/DCOM-related CVEs.
    if "rpc" in svc_lower:
        if _DESC_RPC_TOPIC.search(desc):
            return True, "service-topic matches RPC"
        if any("rpc" in p or "dcom" in p for p in products):
            return True, "service-topic matches RPC (by CPE product)"
        return False, "CVE not related to RPC service"

    # Java RMI port should only keep genuine Java RMI CVEs.
    if "rmi" in svc_lower:
        if cpe_list and (vendors & _RMI_CORE_VENDORS or products & _RMI_CORE_PRODUCTS):
            return True, "service-topic matches Java RMI (core JDK/JRE)"
        if _DESC_RMI_TOPIC.search(desc):
            return True, "service-topic matches Java RMI (by description)"
        return False, "CVE not related to Java RMI service"

    # AJP connector port: only keep Tomcat and AJP-connector CVEs.
    if "ajp" in svc_lower:
        _AJP_CORE_VENDORS = {"apache", "vmware", "redhat", "pivotal"}
        _AJP_CORE_PRODUCTS = {
            "tomcat", "tc-server", "spring_framework",
            "ajp", "jk_connector", "mod_jk",
        }
        _AJP_DROP_PRODUCTS = {
            "undertow", "http_server", "jboss_eap",
            "enterprise_security_manager",
        }
        _DESC_AJP = re.compile(
            r'\b(ajp|tomcat|jk.?connector|mod.?jk|ghostcat|cve.2020.1938)\b',
            re.I
        )
        if cpe_list:
            _, vs, ps = _vendors_products(cpe_list)
            drop_hits = ps & _AJP_DROP_PRODUCTS
            if drop_hits:
                return False, f"CVE targets non-Tomcat AJP product ({drop_hits})"
            if ps & _AJP_CORE_PRODUCTS:
                return True, "service-topic matches Tomcat/AJP"
            if vs & _AJP_CORE_VENDORS and _DESC_AJP.search(desc):
                return True, "service-topic matches AJP (vendor+description)"
        if _DESC_AJP.search(desc):
            return True, "service-topic matches AJP (by description)"
        return False, "CVE not related to AJP/Tomcat service"

    # MySQL port: only keep CVEs about the MySQL/MariaDB server itself.
    if "mysql" in svc_lower:
        _MYSQL_CORE_VENDORS = {"oracle", "mysql", "mariadb", "percona"}
        _MYSQL_CORE_PRODUCTS = {"mysql", "mariadb", "mysql_server", "percona_server"}
        if cpe_list:
            _, vs, ps = _vendors_products(cpe_list)
            # If ANY CPE is from a core vendor, it's relevant
            if vs & _MYSQL_CORE_VENDORS or ps & _MYSQL_CORE_PRODUCTS:
                return True, "service-topic matches MySQL core server"
            # If CPE list exists but NO core vendor matched → drop
            if vs:
                return False, "CVE not about MySQL server (third-party CPE)"
        # No CPE — check description
        _DESC_MYSQL = re.compile(
            r'\b(mysql\s+server|mysqld|mysqlcheck|mysql\s+\d|'
            r'mysql\s+before\s+\d|mysql\s+\d\.\d)\b', re.I
        )
        if _DESC_MYSQL.search(desc):
            return True, "service-topic matches MySQL (by description)"
        return False, "CVE not about MySQL server (by description)"

    return True, "service-topic check not needed"


def _is_platform_relevant_by_cpe(cpe_list, svc_lower, detected_os, os_info=None, service_map=None):
    """Check CPE data for platform relevance. Returns (ok, reason) or None."""
    if not cpe_list:
        return None  # No CPE data → fall through to description check

    pairs, vendors, products = _vendors_products(cpe_list)

    # X11/X Display Server port: only keep genuine X.Org server CVEs
    if "x11" in svc_lower or "x display" in svc_lower:
        is_xorg = bool(vendors & _X11_SERVER_VENDORS) or bool(products & _X11_SERVER_PRODUCTS)
        if not is_xorg:
            return False, "non-X11-server CVE on X11 port"

    # NFS port: only keep Linux / nfs-utils CVEs
    if "nfs" in svc_lower:
        pairs_local, vendors_local, products_local = _vendors_products(cpe_list)

        # Drop packet-tool CVEs (tcpdump NFS parser bugs etc.)
        if vendors_local & _NFS_TOOL_VENDORS or products_local & _NFS_TOOL_PRODUCTS:
            return False, "NFS packet-tool CVE (tcpdump/Wireshark), not nfs-utils"

        # Drop CVEs that ONLY target non-Linux OS vendors
        if vendors_local:
            non_linux = vendors_local & _NFS_NON_LINUX_OS_VENDORS
            has_linux = bool(
                vendors_local - _NFS_NON_LINUX_OS_VENDORS - {"nfs"}
            )
            if non_linux and not has_linux:
                sample = ", ".join(sorted(non_linux)[:3])
                return False, f"NFS CVE targets non-Linux OS ({sample})"

    # IRC daemon ports should not keep IRC client-side CVEs.
    if _is_irc_daemon_service(svc_lower):
        irc_client_hits = []
        non_client_entries = 0
        for entry in cpe_list:
            criteria = entry.get("criteria", "")
            if not criteria:
                continue
            if is_irc_client_product(criteria):
                parsed = parse_cpe(criteria)
                pname = parsed.get("product") or criteria
                irc_client_hits.append(pname)
            else:
                non_client_entries += 1
        if irc_client_hits and non_client_entries == 0:
            hit_preview = ", ".join(sorted(set(irc_client_hits))[:4])
            return False, f"IRC client-side CVE ({hit_preview})"

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

    # Linux/Samba SMB context: drop non-Samba SMB ecosystem products.
    # Example false positives: novell:netware, ownCloud SMB app, SysAid, SAP.
    if _is_linux_samba_context(svc_lower, detected_os, os_info=os_info, service_map=service_map):
        non_samba_hits = []
        other_platform_seen = False
        for vendor, product in pairs:
            if vendor == "novell" and product == "netware":
                non_samba_hits.append(f"{vendor}:{product}")
                continue
            if vendor in _SMB_NON_SAMBA_VENDORS:
                non_samba_hits.append(f"{vendor}:{product}")
                continue
            other_platform_seen = True
        if non_samba_hits and not other_platform_seen:
            preview = ", ".join(sorted(set(non_samba_hits))[:4])
            return False, f"non-Samba SMB ecosystem CVE ({preview})"

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


def _is_platform_relevant_by_desc(description, svc_lower, detected_os, cpe_list=None):
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

    if "x11" in svc_lower or "x display" in svc_lower:
        if not _DESC_X11_SERVER.search(desc):
            return False, "non-X11-server CVE on X11 port (by description)"

    if "nfs" in svc_lower and not cpe_list:
        if _NFS_NON_LINUX_DESC.search(desc) and not _NFS_LINUX_DESC.search(desc):
            return False, "NFS CVE targets non-Linux OS (by description)"

    return True, "no CPE data, passed description check"


# ============================================================
# VERSION RANGE CHECKING
# ============================================================

def _parse_ver(v_str):
    """Convert version text into a tuple of numeric components."""
    if not v_str or v_str in ("*", "-", ""):
        return None
    # Keep all numeric components so tokens like 1.6.0_131 are
    # comparable against 1.6.0_18.
    parts = re.findall(r'\d+', str(v_str))
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

def is_cve_applicable(cve, service_name, service_version, detected_os, os_info=None, service_map=None):
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
    cpe_result = _is_platform_relevant_by_cpe(
        cpe_list,
        svc_lower,
        detected_os,
        os_info=os_info,
        service_map=service_map,
    )

    if cpe_result is not None:
        ok, reason = cpe_result
        if not ok:
            return False, reason
    else:
        # 2. Fallback: platform check via description text
        ok, reason = _is_platform_relevant_by_desc(
            description,
            svc_lower,
            detected_os,
            cpe_list=cpe_list,
        )
        if not ok:
            return False, reason

    # 3. Service-topic check (avoid generic OS CVEs on SMB/RPC ports)
    ok, reason = _is_service_relevant(cpe_list, description, svc_lower)
    if not ok:
        return False, reason

    # 4. Version range check
    ok, reason = is_version_relevant(cpe_list, service_version)
    if not ok:
        return False, reason

    return True, "applicable"


def filter_cves(cves, service_name, service_version, detected_os, os_info=None, service_map=None):
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
        ok, reason = is_cve_applicable(
            cve,
            service_name,
            service_version,
            detected_os,
            os_info=os_info,
            service_map=service_map,
        )
        cve_copy = dict(cve)
        cve_copy["applicability_note"] = reason
        if ok:
            applicable.append(cve_copy)
        else:
            cve_copy["filter_reason"] = reason
            filtered_out.append(cve_copy)

    return applicable, filtered_out
