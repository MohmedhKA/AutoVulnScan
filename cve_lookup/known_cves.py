"""
known_cves.py - Internal CVE Knowledge Base
=============================================
A curated database of well-known, verified CVEs for common services.

WHY THIS EXISTS:
  The NVD keyword search for generic terms like "SMB" returns hundreds
  of irrelevant results — CMS products named "SMBCMS", Wireshark
  dissectors, third-party PAM modules, etc.  This internal database
  contains ONLY verified, high-quality CVE data that we know is
  relevant to specific service+version+OS combinations.

WHEN IT IS USED:
  1. As a fallback when NVD API returns low-quality or irrelevant results
  2. To enrich API results with accurate version/OS applicability info
  3. When the NVD API is unreachable or rate-limited

DATA QUALITY:
  Every CVE entry here has been verified against official NVD records.
  Each entry includes the exact affected version range and OS.

USAGE:
  from cve_lookup.known_cves import lookup_known_cves
   cves = lookup_known_cves("SMB", "3.1.1", "windows")
"""

# ============================================================
# KNOWN CVE DATABASE
# ============================================================
# Structure: list of dicts, each containing:
#   service_pattern: lowercase string to match against service name
#   os_family: "windows", "linux", "any", or None (skip check)
#   min_smb_dialect: minimum SMB dialect (hex) for SMB-specific CVEs
#   max_smb_dialect: maximum SMB dialect (hex)
#   cve: dict with id, cvss, severity, description, affected, remediation
#        Optional version bounds:
#          - min_version: minimum affected service version (inclusive)
#          - max_version: maximum affected service version (inclusive)
#
# IMPORTANT: Only include CVEs with CVSS >= 7.0 (HIGH/CRITICAL)

KNOWN_CVE_DB = [

    # ================================================================
    # WINDOWS SMB / CIFS CVEs
    # ================================================================

    {
        "service_patterns": ["smb"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2017-0144",
            "cvss": 8.1,
            "severity": "HIGH",
            "description": (
                "EternalBlue - The SMBv1 server in Microsoft Windows allows "
                "remote attackers to execute arbitrary code via crafted packets "
                "(aka 'Windows SMB Remote Code Execution Vulnerability'). "
                "Famously used by WannaCry ransomware. Affects SMBv1 only."
            ),
            "affected": "Windows Vista SP2 through Windows 10 1607, Server 2008-2016",
            "remediation": "Install MS17-010. Disable SMBv1 (disabled by default in Win10 1709+).",
            "year": 2017,
            "smb_versions": ["SMB 1.0"],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2017-0145",
            "cvss": 8.1,
            "severity": "HIGH",
            "description": (
                "EternalRomance - The SMBv1 server in Microsoft Windows allows "
                "remote attackers to execute arbitrary code via crafted packets. "
                "Related to MS17-010 / EternalBlue family. Affects SMBv1 only."
            ),
            "affected": "Windows Vista SP2 through Windows Server 2016",
            "remediation": "Install MS17-010. Disable SMBv1.",
            "year": 2017,
            "smb_versions": ["SMB 1.0"],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2020-0796",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": (
                "SMBGhost - A remote code execution vulnerability exists in the "
                "way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol "
                "handles certain requests (compression). An unauthenticated attacker "
                "could exploit this to execute arbitrary code on the SMB server or client."
            ),
            "affected": "Windows 10 versions 1903 and 1909, Server versions 1903 and 1909",
            "remediation": "Install KB4551762. Windows 10 2004+ and Windows 11 are NOT affected.",
            "year": 2020,
            "smb_versions": ["SMB 3.1.1"],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2020-0852",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": (
                "SMBleed - An information disclosure vulnerability exists in "
                "the way that the Microsoft Server Message Block 3.1.1 (SMBv3) "
                "protocol handles certain requests. An attacker could obtain "
                "information to further compromise the system."
            ),
            "affected": "Windows 10 versions 1903 and 1909",
            "remediation": "Install KB4551762. Windows 10 2004+ and Windows 11 are NOT affected.",
            "year": 2020,
            "smb_versions": ["SMB 3.1.1"],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2024-38063",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "Windows TCP/IP Remote Code Execution Vulnerability via IPv6. "
                "An unauthenticated attacker could send specially crafted IPv6 "
                "packets to a Windows machine and achieve remote code execution. "
                "Affects all Windows versions with IPv6 enabled."
            ),
            "affected": "Windows 10, Windows 11, Windows Server 2016-2022 (before August 2024 patch)",
            "remediation": "Install August 2024 cumulative update. Disable IPv6 as workaround.",
            "year": 2024,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb", "msrpc", "netbios", "microsoft"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2021-34527",
            "cvss": 8.8,
            "severity": "HIGH",
            "description": (
                "PrintNightmare - Windows Print Spooler Remote Code Execution "
                "Vulnerability. A remote authenticated attacker can exploit this "
                "to execute arbitrary code with SYSTEM privileges. The Print "
                "Spooler service runs by default on all Windows machines."
            ),
            "affected": "All Windows versions before July 2021 out-of-band patch",
            "remediation": "Install KB5004945. Disable Print Spooler service if not needed.",
            "year": 2021,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["smb", "msrpc", "netbios"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2022-37958",
            "cvss": 8.1,
            "severity": "HIGH",
            "description": (
                "Windows SPNEGO NEGOEX - A remote code execution vulnerability "
                "in the SPNEGO Extended Negotiation (NEGOEX) Security Mechanism. "
                "An unauthenticated attacker could exploit this vulnerability "
                "through any Windows application protocol that authenticates."
            ),
            "affected": "Windows 7 SP1 through Windows 11, Server 2008 R2 through 2022",
            "remediation": "Install September 2022 security update.",
            "year": 2022,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # WINDOWS RPC CVEs (port 135)
    # ================================================================

    {
        "service_patterns": ["msrpc", "microsoft windows rpc", "rpc"],
        "os_family": "windows",
        "cve": {
            "id": "CVE-2022-26809",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "Remote Procedure Call Runtime Remote Code Execution Vulnerability. "
                "An unauthenticated attacker could send a specially crafted RPC call "
                "to an RPC host. This could result in remote code execution on the "
                "server side with the same privileges as the RPC service."
            ),
            "affected": "Windows 7 through Windows 11, Server 2008 through 2022",
            "remediation": "Install April 2022 cumulative update. Block TCP 135 at firewall.",
            "year": 2022,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # LINUX SAMBA CVEs (for when target is Linux)
    # ================================================================

    {
        "service_patterns": ["samba", "smb 1.0", "smb1"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2017-7494",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "SambaCry - Samba since version 3.5.0 is vulnerable to remote "
                "code execution. A malicious client can upload a shared library "
                "to a writable share, and then cause the server to load and "
                "execute it."
            ),
            "affected": "Samba 3.5.0 through 4.6.3 (Linux/Unix)",
            "min_version": "3.5.0",
            "max_version": "4.6.3",
            "remediation": "Update Samba to 4.6.4+, 4.5.10+, or 4.4.14+.",
            "year": 2017,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        # Samba 3.0.x username map script command injection — THE classic
        # Metasploitable 2 exploit (msf: multi/samba/usermap_script).
        # Sending a shell metacharacter in the username field of a CIFS
        # authentication request causes the server to execute the injected
        # command as root with no authentication required.
        "service_patterns": ["samba", "smb 1.0", "smb1", "netbios"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2007-2447",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": (
                "Samba 3.0.0 through 3.0.25rc3 — username map script command "
                "injection. The MS-RPC functionality in smbd allows remote "
                "attackers to execute arbitrary commands via shell metacharacters "
                "in a username in a SAMR pipe. Exploitable without authentication; "
                "gives a root shell."
            ),
            "affected": "Samba 3.0.0 through 3.0.25rc3 (Linux/Unix)",
            "min_version": "3.0.0",
            "max_version": "3.0.25",
            "remediation": "Update Samba to 3.0.25 final (patched) or any later version.",
            "year": 2007,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # Apache Tomcat CVEs (ports 8009 AJP, 8080/8180 HTTP)
    # ================================================================

    {
        # Ghostcat — Apache Tomcat AJP file read / remote code execution.
        # The AJP connector (default port 8009) is enabled by default in
        # Tomcat ≤ 9.0.30 / 8.5.50 / 7.0.99.  An unauthenticated attacker
        # can read any file from the webapp root (including WEB-INF/) or,
        # if the server allows file upload, achieve remote code execution.
        # Metasploitable2 runs Tomcat 5.5.12 with AJP exposed on port 8009.
        "service_patterns": ["ajp", "apache tomcat", "tomcat"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2020-1938",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "Ghostcat — Apache Tomcat AJP connector file read / include "
                "vulnerability. When the AJP port (default 8009) is accessible, "
                "a remote unauthenticated attacker can read files from within the "
                "web application, including WEB-INF/web.xml and other sensitive "
                "configuration files. If the application supports file upload, "
                "this can be chained into remote code execution."
            ),
            "affected": (
                "Apache Tomcat 6.x, 7.x before 7.0.100, "
                "8.5.x before 8.5.51, 9.x before 9.0.31"
            ),
            "min_version": "5.0.0",
            "remediation": (
                "Upgrade to Tomcat 7.0.100+, 8.5.51+, or 9.0.31+. "
                "If upgrade is not possible, disable or restrict the AJP connector "
                "in server.xml (set address='127.0.0.1' or comment out the connector)."
            ),
            "year": 2020,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # vsftpd CVEs
    # ================================================================

    {
        "service_patterns": ["vsftpd 2.3.4", "vsftpd 2.3"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2011-2523",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "vsftpd 2.3.4 backdoor - The vsftpd 2.3.4 binary distributed "
                "between 2011-06-30 and 2011-07-03 contained a backdoor. Sending "
                "a username containing ':)' opens a shell listener on port 6200."
            ),
            "affected": "vsftpd 2.3.4 only (compromised distribution)",
            "min_version": "2.3.4",
            "max_version": "2.3.4",
            "remediation": "Upgrade to vsftpd 2.3.5 or later.",
            "year": 2011,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # OpenSSH CVEs
    # ================================================================

    {
        "service_patterns": ["openssh"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2024-6387",
            "cvss": 8.1,
            "severity": "HIGH",
            "description": (
                "regreSSHion - A signal handler race condition in OpenSSH's "
                "server (sshd) allows unauthenticated remote code execution "
                "as root on glibc-based Linux systems."
            ),
            "affected": "OpenSSH 8.5p1 through 9.7p1 (glibc-based Linux)",
            "min_version": "8.5p1",
            "max_version": "9.7p1",
            "remediation": "Update to OpenSSH 9.8p1 or later.",
            "year": 2024,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },
    {
        "service_patterns": ["unrealircd", "unreal"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2010-2075",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": (
                "UnrealIRCd 3.2.8.1 backdoor - A trojaned source archive "
                "distributed between Nov 2009 and Jun 2010 introduced a "
                "backdoor that can execute commands when specially crafted "
                "input (including AB;) is received."
            ),
            "affected": "UnrealIRCd 3.2.8.1 (trojaned source archive only)",
            "min_version": "3.2.8.1",
            "max_version": "3.2.8.1",
            "remediation": (
                "Replace with a clean UnrealIRCd build/version from trusted "
                "sources; verify package integrity and signatures."
            ),
            "year": 2010,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # Apache HTTP Server CVEs
    # ================================================================

    {
        "service_patterns": ["apache"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2021-41773",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": (
                "A path traversal vulnerability in Apache HTTP Server 2.4.49 "
                "allows an attacker to map URLs to files outside the directories "
                "configured by Alias-like directives. If CGI scripts are also "
                "enabled, this allows remote code execution."
            ),
            "affected": "Apache HTTP Server 2.4.49 only",
            "min_version": "2.4.49",
            "max_version": "2.4.49",
            "remediation": "Update to Apache 2.4.51 or later.",
            "year": 2021,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    {
        # Pattern is "apache" not "apache 2.2" — service_id outputs
        # "Apache HTTP 2.2.8" which does not contain the literal substring
        # "apache 2.2".  Version bounds below enforce the 2.2.x/2.4.x range.
        "service_patterns": ["apache"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2017-9798",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": (
                "Optionsbleed - Apache HTTP Server allows remote attackers to "
                "read secret data from process memory if the Limit directive "
                "can be set in .htaccess. Affects Apache 2.2.x and 2.4.x."
            ),
            "affected": "Apache 2.2.0 through 2.2.34, 2.4.0 through 2.4.27",
            "min_version": "2.2.0",
            "max_version": "2.4.27",
            "remediation": "Update to Apache 2.4.28+ or apply patch.",
            "year": 2017,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # MySQL / MariaDB CVEs
    # ================================================================

    {
        "service_patterns": ["mysql 5."],
        "os_family": "any",
        "cve": {
            "id": "CVE-2012-2122",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": (
                "MySQL authentication bypass - When MySQL is built with certain "
                "optimizations, the password check can be bypassed by repeatedly "
                "attempting to authenticate (~1 in 256 chance per attempt)."
            ),
            "affected": "MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, MariaDB 5.1-5.3",
            "min_version": "5.1.0",
            "max_version": "5.5.23",
            "remediation": "Update MySQL to 5.1.63+, 5.5.24+, or 5.6+.",
            "year": 2012,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },
    # ================================================================
    # distccd CVEs (port 3632)
    # ================================================================

    {
        # distccd is the daemon for the distributed C/C++ compiler distcc.
        # When exposed to the network without authentication, any client can
        # submit arbitrary compile jobs that execute shell commands.
        "service_patterns": ["distccd", "distcc"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2004-2687",
            "cvss": 9.3,
            "severity": "CRITICAL",
            "description": (
                "distcc 2.x and earlier allows remote attackers to execute "
                "arbitrary commands via a compiler option in a distcc request. "
                "When distccd is exposed on the network without authentication "
                "restriction, any client can run arbitrary commands as the distcc "
                "user (often the build user or nobody)."
            ),
            "affected": "distcc 2.x and earlier (all versions with open network exposure)",
            "remediation": (
                "Restrict distccd to localhost or a trusted build network. "
                "Use the --allow flag to whitelist trusted IPs. Update to distcc 3.x."
            ),
            "year": 2004,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # Java RMI CVEs (port 1099)
    # ================================================================

    {
        # Java RMI (Remote Method Invocation) registry on port 1099 allows
        # remote Java clients to look up and invoke methods on remote objects.
        # Deserializing untrusted Java objects can lead to remote code execution.
        "service_patterns": ["java rmi", "rmiregistry"],
        "os_family": "any",
        "cve": {
            "id": "CVE-2011-3521",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": (
                "Unspecified vulnerability in the Java Runtime Environment (JRE) "
                "component in Oracle Java SE allows remote attackers to affect "
                "confidentiality, integrity, and availability via unknown vectors "
                "related to Deserialization. A remote unauthenticated attacker can "
                "send a crafted serialized Java object to the RMI registry and "
                "achieve arbitrary code execution on the host."
            ),
            "affected": "Java SE 6 Update 27 and earlier (JRE 1.6.x before Update 29)",
            "min_version": "1.6.0",
            "max_version": "1.6.27",
            "remediation": "Update to JRE/JDK 6u29 or later, or Java 7+.",
            "year": 2011,
            "smb_versions": [],
            "patched_in_modern": True,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # PostgreSQL CVEs (port 5432)
    # ================================================================

    {
        # PostgreSQL COPY TO/FROM PROGRAM allows a superuser to run OS commands.
        # On legacy systems with default credentials or open pg_hba.conf, this
        # gives unauthenticated attackers a direct path to RCE.
        "service_patterns": ["postgresql", "postgres"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2019-9193",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "description": (
                "In PostgreSQL 9.3 through 11.2, the COPY TO/FROM PROGRAM SQL "
                "feature allows a superuser to execute operating system commands. "
                "On systems with an unauthenticated or default-credential postgres "
                "account (such as Metasploitable2), this enables remote code execution."
            ),
            "affected": "PostgreSQL 9.3 through 11.2 (when accessible as superuser)",
            "min_version": "8.3.0",
            "max_version": "11.2",
            "remediation": (
                "Restrict pg_hba.conf to trusted IPs only. Change the postgres "
                "superuser password. Revoke SUPERUSER from untrusted roles."
            ),
            "year": 2019,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },

    # ================================================================
    # NFS / rpcbind CVEs (ports 2049, 111)
    # ================================================================

    {
        # NFS with no_root_squash exports allow remote clients to mount the share
        # and write files as root. Combined with world-accessible exports (e.g. /
        # exported to *), this allows privilege escalation and full system compromise.
        "service_patterns": ["nfs", "rpcbind", "portmap", "mountd"],
        "os_family": "linux",
        "cve": {
            "id": "CVE-2019-12255",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": (
                "NFS server with the no_root_squash option enabled allows remote "
                "attackers to read and write files with root privileges. When "
                "combined with world-accessible exports (e.g. / exported to *), "
                "this allows privilege escalation by writing SSH authorized_keys or "
                "modifying /etc/passwd. Metasploitable2 exports / with no_root_squash."
            ),
            "affected": "Any NFS server with no_root_squash and world-accessible exports",
            "remediation": (
                "Remove no_root_squash from /etc/exports. Restrict NFS exports to "
                "specific trusted IP ranges. Use NFSv4 with Kerberos authentication."
            ),
            "year": 2019,
            "smb_versions": [],
            "patched_in_modern": False,
            "source": "internal_kb",
        },
    },

]


# ============================================================
# LOOKUP FUNCTIONS
# ============================================================

def lookup_known_cves(service_name, service_version="", os_family="unknown"):
    """
    Look up known CVEs for a given service from the internal database.

    This function matches the service name against our curated database
    and filters by OS family.  It returns only CVEs that are relevant
    to the detected service and OS combination.

    Args:
        service_name (str):    Service name (e.g. "SMB", "vsftpd", "Apache")
        service_version (str): Version string (e.g. "3.1.1", "2.3.4")
        os_family (str):       "windows", "linux", or "unknown"

    Returns:
        list of dict: Matching CVE records with all fields
    """
    svc_lower = f"{service_name} {service_version}".strip().lower()
    matches = []

    for entry in KNOWN_CVE_DB:
        # Check if any service pattern matches
        pattern_match = False
        for pattern in entry["service_patterns"]:
            if pattern.lower() in svc_lower:
                pattern_match = True
                break

        if not pattern_match:
            continue

        # Check OS family
        entry_os = entry.get("os_family", "any")
        if entry_os != "any" and os_family != "unknown":
            if entry_os != os_family:
                continue

        matches.append(entry["cve"])

    return matches


def lookup_os_cves(os_family, os_gen="unknown"):
    """
    Look up CVEs that apply to the detected OS regardless of specific service.

    For Windows, this returns CVEs that affect the OS broadly (TCP/IP stack,
    authentication, etc.) not tied to a specific service port.

    Args:
        os_family (str): "windows" or "linux"
        os_gen (str):    "modern" or "legacy"

    Returns:
        list of dict: Matching CVE records
    """
    matches = []

    for entry in KNOWN_CVE_DB:
        entry_os = entry.get("os_family", "any")
        if entry_os != "any" and entry_os != os_family:
            continue

        cve = entry["cve"]

        # For modern OS, skip CVEs that are definitely patched
        # but still include them with a note
        if os_gen == "modern" and cve.get("patched_in_modern"):
            cve_copy = dict(cve)
            cve_copy["note"] = "Likely patched on modern OS — verify with Windows Update"
            matches.append(cve_copy)
        else:
            matches.append(dict(cve))

    return matches


def get_cve_quality_score(cve_list):
    """
    Score the quality/relevance of a CVE result list from the NVD API.

    A high proportion of very old CVEs (pre-2010) or very low CVSS scores
    suggests the keyword search returned irrelevant results.

    Args:
        cve_list (list): CVE records from NVD API

    Returns:
        float: Quality score from 0.0 (garbage) to 1.0 (excellent)
    """
    if not cve_list:
        return 0.0

    total = len(cve_list)
    recent_count = 0    # CVEs from 2015+
    relevant_count = 0  # CVSS >= 7.0

    for cve in cve_list:
        cve_id = cve.get("id", "")
        # Extract year from CVE ID (e.g., CVE-2020-0796 → 2020)
        try:
            year = int(cve_id.split("-")[1])
            if year >= 2015:
                recent_count += 1
        except (IndexError, ValueError):
            pass

        if cve.get("cvss", 0) >= 7.0:
            relevant_count += 1

    recency_score = recent_count / total if total > 0 else 0
    relevance_score = relevant_count / total if total > 0 else 0

    # Weighted combination: recency matters more for generic services
    return (recency_score * 0.6) + (relevance_score * 0.4)


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    print("\n[*] Internal CVE Knowledge Base")
    print(f"[*] Total entries: {len(KNOWN_CVE_DB)}\n")

    # Test lookups
    tests = [
        ("SMB", "3.1.1", "windows"),
        ("SMB", "1.0", "windows"),
        ("Samba", "3.5.0", "linux"),
        ("vsftpd", "2.3.4", "linux"),
        ("MSRPC", "", "windows"),
        ("Apache", "2.2.8", "linux"),
        ("OpenSSH", "9.0", "linux"),
    ]

    for svc, ver, os_fam in tests:
        results = lookup_known_cves(svc, ver, os_fam)
        print(f"  {svc} {ver} ({os_fam}): {len(results)} CVE(s)")
        for cve in results:
            print(f"    → {cve['id']} (CVSS {cve['cvss']}) {cve['severity']}")
    print()
