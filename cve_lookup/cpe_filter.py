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
_RMI_CORE_PRODUCTS = {
    "jre", "jdk", "java_se", "openjdk",
    "java_runtime_environment",   # legacy NVD naming pre-2013
    "java_development_kit",       # legacy NVD naming pre-2013
    "java_se_embedded",           # Oracle embedded JRE variant
}
# Vendors whose products *host* an RMI port but are NOT the JVM RMI runtime itself.
# A CVE about these is a product bug, not a JRE bug; always a false positive on port 1099.
_RMI_HOST_VENDORS = {
    "cisco", "emc", "dell", "zte", "smartbear",
    "broadcom", "netapp", "bmc", "microfocus",
}
_RMI_HOST_PRODUCTS = {
    # Cisco
    "unified_communications_manager", "prime_infrastructure",
    "identity_services_engine", "secure_access_control_system",
    "unity_connection", "unified_contact_center",
    # EMC / Dell
    "networker", "data_domain_os", "storage_center", "vplex",
    "networker_management_console", "avamar",
    # ZTE
    "zxcdn", "zxr10",
    # SmartBear / API testing tools
    "soapui", "swagger_ui", "readyapi",
}
# Confirms the JRE/JDK runtime is directly at fault (used when CPE is ambiguous)
_DESC_RMI_RUNTIME = re.compile(
    r'\b(jdk|jre|java\s+(?:se|runtime(?:\s+environment)?|virtual\s+machine|vm)\b'
    r'|sun\s+java|oracle\s+java|openjdk'
    r'|java\s+(?:1\.\d+|[7-9]|1[0-9])(?:\.\d+)*)',
    re.I,
)

# ============================================================
# AJP CONNECTOR CONSTANTS (module-level, not inside function)
# ============================================================
# AJP port 8009: Tomcat only. JBoss/Undertow (redhat) and wrong-version
# Tomcat CVEs must be dropped.
_AJP_CORE_VENDORS  = {"apache", "vmware", "pivotal"}  # NOT redhat
_AJP_CORE_PRODUCTS = {
    "tomcat", "tc-server", "spring_framework",
    "ajp", "jk_connector", "mod_jk",
}
# Vendors/products that have an AJP implementation but are NOT Tomcat.
_AJP_DROP_VENDORS  = {"redhat"}   # redhat AJP → JBoss/Undertow, not Tomcat
_AJP_DROP_PRODUCTS = {
    "undertow", "jboss_eap", "jboss_web_server",
    "wildfly", "http_server", "enterprise_security_manager",
}
# Tomcat major versions newer than any 5.x/6.x/7.x/8.x-before-patch target.
_TOMCAT_TOO_NEW_MAJORS = frozenset({9, 10, 11})
# Within 8.5.x, versions ≥ this patch level are "post-fix for legacy targets".
# Metasploitable2 runs 5.5.x; 8.5.88 fixes are irrelevant to it.
_TOMCAT_85_PATCH_GATE = 88
_DESC_AJP_TOPIC = re.compile(
    r'\b(ajp|tomcat|jk.?connector|mod.?jk|ghostcat|cve.2020.1938)\b', re.I
)

_X11_SERVER_VENDORS = {"x.org", "x_consortium", "xfree86", "x11"}
_X11_SERVER_PRODUCTS = {
    "x11r6", "x11r7", "xorg-server", "xfree86",
    "x.org", "x11", "x_window_system",
}
_DESC_X11_SERVER = re.compile(
    r'\b(x\.?org\s+server|xorg.server|x11\s+server|x\s+server|'
    r'x\.?org\s+x11|xfree86\s+server)\b', re.I
)
# ============================================================
# NFS CONSTANTS
# ============================================================
_NFS_NON_LINUX_DESC = re.compile(
    r'\b(irix|solaris|sunos|mac\s*os|macosx|ultrix|netware|'
    r'aix|hp-?ux|tru64)\b', re.I
)
_NFS_LINUX_DESC = re.compile(r'\b(linux|nfs-utils|knfsd|rpc\.nfsd)\b', re.I)
# Genuine NFS server products (keep CVEs that name these).
_NFS_SERVER_PRODUCTS = {
    "nfs-utils", "nfs_utils", "knfsd", "nfsd", "nfs",
    "linux_kernel",     # kernel-land NFS server (knfsd)
    "mountd",
}
# Pattern: NFS is only the *attack surface*, used by another service (SSH, Kerberos…).
# Fires on "NFS-mounted home dir", "authorized_keys via NFS", "SSH over NFS", etc.
# Does NOT fire on genuine nfs-utils / knfsd vulnerability descriptions.
_NFS_SURFACE_ONLY = re.compile(
    r'(?:'
    r'nfs.{0,25}mount(?:ed|s)?'            # "NFS-mounted", "via NFS mounts"
    r'|mount(?:ed|s)?.{0,15}(?:nfs|via\s+nfs)\b'  # "mounted via NFS"
    r'|(?:ssh|rsh|rlogin|ftp|kerberos)'    # another service...
    r'.{0,60}(?:nfs|network\s*file)'        # ...that involves NFS
    r'|(?:nfs|network\s*file).{0,60}(?:ssh|rsh|rlogin|ftp|kerberos)'
    r'|authorized_keys'                     # SSH key injection via NFS
    r')',
    re.I,
)
# Pattern: CVE truly is about an NFS *server* component.
_NFS_SERVER_VULN = re.compile(
    r'\b(nfsd|rpc\.(?:nfsd|mountd)|nfs.?utils|nfs\s+server|nfs\s+daemon|'
    r'knfsd|exportfs|/etc/exports|nfs\s+export)\b',
    re.I,
)

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


def _is_tomcat_version_applicable(cpe_list, sv):
    """
    Return False only when every explicit (non-ranged) Tomcat CPE version in this
    CVE is strictly newer than the detected service version *sv* (a version tuple).

    Rationale: NVD sometimes stores exact version CPEs without versionStart/End
    range fields.  In that case is_version_relevant() sees "no version ranges"
    and conservatively keeps the CVE.  This helper fills that gap for Tomcat/AJP
    by inspecting the CPE version component directly.

    Rules (applied only to unranged Tomcat CPE entries):
      - major ≥ 9                       → always newer
      - major == 8, minor == 5, patch ≥ _TOMCAT_85_PATCH_GATE → newer for 5/6/7 targets
      - version == "*" / "-" / ""        → unknown, conservatively KEEP
    If ANY entry is not "too new" the function returns True (keep).
    """
    if sv is None:
        return True

    tomcat_entries = [
        e for e in cpe_list
        if parse_cpe(e.get("criteria", "")).get("product") == "tomcat"
    ]
    # Only examine entries that have no range metadata (ranges are handled by
    # is_version_relevant(), which is correct for that data).
    unranged = [
        e for e in tomcat_entries
        if not any([
            e.get("versionStartIncluding"), e.get("versionStartExcluding"),
            e.get("versionEndIncluding"),  e.get("versionEndExcluding"),
        ])
    ]
    if not unranged:
        return True  # Nothing extra to check here

    for entry in unranged:
        cv_str = parse_cpe(entry.get("criteria", "")).get("version", "")
        if not cv_str or cv_str in ("*", "-"):
            return True  # Unknown version → cannot safely exclude
        cv = _parse_ver(cv_str)
        if cv is None:
            return True
        major = cv[0] if cv else 0
        minor = cv[1] if len(cv) > 1 else 0
        patch = cv[2] if len(cv) > 2 else 0
        # Is this CPE version "too new" relative to the service version's family?
        too_new = (
            major in _TOMCAT_TOO_NEW_MAJORS
            or (major == 8 and minor == 5 and patch >= _TOMCAT_85_PATCH_GATE)
        )
        if not too_new:
            return True  # At least one CPE version is applicable → keep
    # Every unranged Tomcat CPE is newer than the service → drop
    return False


def _is_service_relevant(cpe_list, description, svc_lower, service_version=None):
    """
    Ensure CVE topic matches the scanned service, not just the OS platform.

    service_version is forwarded here so that service-specific version gates
    (e.g., Tomcat 9.x CVE on a Tomcat 5.5 target) can be applied before the
    generic is_version_relevant() pass — covering CVEs with no range metadata.

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

    # ------------------------------------------------------------------ #
    # Java RMI (port 1099)                                                #
    # ------------------------------------------------------------------ #
    # We only want CVEs where the *vulnerable component IS* the Oracle/Sun/
    # OpenJDK JRE RMI runtime, NOT vendor-specific products (Cisco UCM,
    # EMC NetWorker, ZTE appliances, SmartBear SoapUI, …) that merely
    # expose an RMI port.  When CPE data exists it is authoritative;
    # we never fall through to the description when CPE is present.
    if "rmi" in svc_lower:
        if cpe_list:
            # CPE data present → trust it exclusively.
            core_v = vendors & _RMI_CORE_VENDORS
            core_p = products & _RMI_CORE_PRODUCTS

            # ---- STEP 1: core JRE pair wins unconditionally ----
            # A CVE may carry BOTH an oracle:jre CPE and a vendor-product CPE
            # (e.g. cisco:ucm also ships an affected JRE).  When both a core
            # vendor AND a core product are present, the JRE runtime itself is
            # the vulnerable component — keep regardless of any host CPEs.
            if core_v and core_p:
                return True, "service-topic matches Java RMI (core JDK/JRE)"

            # ---- STEP 2: host-vendor/product check (no core pair found) ----
            # Only reached when there is NO oracle:jre / sun:jdk / openjdk:openjdk
            # core pair.  Exclude any vendor that merely hosts an RMI port inside
            # their own product; that product bug is NOT a JRE runtime bug.
            host_v_hit = vendors & _RMI_HOST_VENDORS
            host_p_hit = products & _RMI_HOST_PRODUCTS
            if host_v_hit or host_p_hit:
                hit = ", ".join(sorted((host_v_hit | host_p_hit))[:3])
                return False, (
                    f"RMI port but CVE targets vendor-specific product ({hit}), "
                    "not the JRE runtime"
                )

            # ---- STEP 3: partial match — require description confirmation ----
            # CPE data exists (so the description path is not in play) but no
            # clean core vendor+product pair was found.  Accept only when the
            # description explicitly names the JRE runtime as the faulty component
            # (guards against e.g. oracle:database CVEs slipping through).
            if (core_v or core_p) and _DESC_RMI_TOPIC.search(desc) and _DESC_RMI_RUNTIME.search(desc):
                return True, "service-topic matches Java RMI (partial CPE + description)"
            return False, "CVE has CPE data but no JDK/JRE component matched"
        else:
            # No CPE data (pre-2008 era CVEs) — description-only fallback is safe
            # because old JRE RMI bugs don't have NVD CPE entries.
            if _DESC_RMI_TOPIC.search(desc):
                return True, "service-topic matches Java RMI (by description)"
        return False, "CVE not related to Java RMI service"

    # ------------------------------------------------------------------ #
    # AJP connector (port 8009)                                           #
    # ------------------------------------------------------------------ #
    # Keep Tomcat-only CVEs.  Drop:
    #   • JBoss / Undertow CVEs (redhat vendor with non-Tomcat products)
    #   • CVEs that only target Tomcat 8.5.88+, 9.x, 10.x, 11.x when the
    #     detected service is an older branch (e.g. Metasploitable2 → 5.5.x)
    if "ajp" in svc_lower:
        if cpe_list:
            _, vs, ps = _vendors_products(cpe_list)
            # Hard-drop: known non-Tomcat AJP products (Undertow, JBoss EAP, …)
            drop_prod_hits = ps & _AJP_DROP_PRODUCTS
            if drop_prod_hits:
                return False, (
                    "CVE targets non-Tomcat AJP product "
                    f"({', '.join(sorted(drop_prod_hits))})"
                )
            # Hard-drop: redhat vendor entries that are NOT a Tomcat product
            if vs & _AJP_DROP_VENDORS and not (ps & _AJP_CORE_PRODUCTS):
                return False, (
                    "CVE targets RedHat non-Tomcat AJP implementation "
                    "(JBoss/Undertow/WildFly)"
                )
            # Version gate — hoisted here so it fires for ALL CPE-bearing
            # Tomcat/AJP CVEs, not only those whose product field is "tomcat".
            # A CVE may reach the vendor+description branch below (apache vendor,
            # no explicit tomcat product CPE) and still carry CPE version data
            # pointing at Tomcat 9/10/11 — this check catches that gap.
            # _is_tomcat_version_applicable() is a no-op (returns True) when
            # there are no unranged Tomcat CPE entries, so it is safe to call
            # unconditionally here.
            if service_version:
                sv = _parse_ver(service_version)
                if sv is not None and not _is_tomcat_version_applicable(cpe_list, sv):
                    return False, (
                        f"Tomcat CVE version too new for detected service "
                        f"version {service_version}"
                    )
            if ps & _AJP_CORE_PRODUCTS:
                return True, "service-topic matches Tomcat/AJP"
            if vs & _AJP_CORE_VENDORS and _DESC_AJP_TOPIC.search(desc):
                return True, "service-topic matches AJP (vendor+description)"
        if _DESC_AJP_TOPIC.search(desc):
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


def _is_platform_relevant_by_cpe(
    cpe_list, svc_lower, detected_os,
    os_info=None, service_map=None, description=None,
):
    """Check CPE data for platform relevance. Returns (ok, reason) or None."""
    if not cpe_list:
        return None  # No CPE data → fall through to description check

    pairs, vendors, products = _vendors_products(cpe_list)

    # X11/X Display Server port: only keep genuine X.Org server CVEs
    if "x11" in svc_lower or "x display" in svc_lower:
        is_xorg = bool(vendors & _X11_SERVER_VENDORS) or bool(products & _X11_SERVER_PRODUCTS)
        if not is_xorg:
            return False, "non-X11-server CVE on X11 port"

    # ------------------------------------------------------------------ #
    # NFS (port 2049)                                                      #
    # ------------------------------------------------------------------ #
    # Keep: nfs-utils / knfsd / linux_kernel CVEs, AND CVEs that cover
    #        multiple platforms (Linux + Solaris together).
    # Drop: CVEs that only target non-Linux OS vendors (sun/sgi/bsdi/…),
    #        packet-tool CVEs (tcpdump/Wireshark NFS dissectors),
    #        and CVEs where NFS is only the *attack surface* for another
    #        service (e.g. SSH root via NFS-mounted authorized_keys —
    #        CVE-2000-0575 style).
    if "nfs" in svc_lower:
        pairs_local, vendors_local, products_local = _vendors_products(cpe_list)

        # Drop packet-tool CVEs (tcpdump NFS parser bugs etc.)
        if vendors_local & _NFS_TOOL_VENDORS or products_local & _NFS_TOOL_PRODUCTS:
            return False, "NFS packet-tool CVE (tcpdump/Wireshark), not nfs-utils"

        # Drop CVEs where NFS is the attack surface for another service.
        # Fired unconditionally when description is available — the old guard
        # `products_local and not (products_local & _NFS_SERVER_PRODUCTS)` was
        # wrong because pre-2002 CVEs often have zero CPE product entries, which
        # caused the surface-only regex to be silently skipped entirely.
        # _NFS_SERVER_VULN acts as a safe override: a genuine nfsd/knfsd bug
        # will always mention one of those tokens and will not be dropped.
        if description:
            if (_NFS_SURFACE_ONLY.search(description)
                    and not _NFS_SERVER_VULN.search(description)):
                return False, (
                    "NFS is only the attack surface, not the vulnerable component"
                )

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

    # NFS (port 2049) — description-path filters
    # This code path is reached ONLY when cpe_list is empty (old CVEs).
    if "nfs" in svc_lower:
        # Drop CVEs where NFS is only the *attack surface* for another service.
        # Canonical example: CVE-2000-0575 — "SSH allows root access via
        # NFS-mounted authorized_keys files."  The vulnerable component is SSH,
        # not the NFS server; it is a false positive on port 2049.
        if _NFS_SURFACE_ONLY.search(desc) and not _NFS_SERVER_VULN.search(desc):
            return False, (
                "NFS is only the attack surface for another service "
                "(not an NFS server vulnerability)"
            )
        # Drop CVEs that explicitly target non-Linux operating systems when
        # the description contains no Linux / nfs-utils signal.
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
        description=description,   # enables NFS surface-only check in CPE path
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
    ok, reason = _is_service_relevant(
        cpe_list, description, svc_lower,
        service_version=service_version,   # enables Tomcat/RMI version gates
    )
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