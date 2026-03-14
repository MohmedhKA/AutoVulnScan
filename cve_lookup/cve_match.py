"""
cve_match.py - Smart CVE Matching with OS Awareness
=====================================================
This module takes the service identification results and looks up
CVEs using the best available strategy:

QUERY STRATEGY (in order of preference):
  1. CPE-based NVD query — for well-known services with CPE mappings
     (most precise, fewest false positives)
  2. Keyword NVD query — for services without CPE mappings
     (broader, may include some irrelevant results)
  3. Internal Knowledge Base — fallback when NVD returns garbage
     (curated, always accurate, but limited coverage)

OS AWARENESS:
  - Detects target OS from service signatures + SMB negotiate
  - Filters CVEs by OS (e.g., no Samba CVEs on Windows targets)
  - Uses OS-specific CPE strings for precise queries

QUALITY CONTROL:
  - Checks result quality (too many old/irrelevant CVEs = bad query)
  - Falls back to internal KB when API quality is poor
  - Cross-references results with OS and version info

USAGE (standalone):
    python cve_lookup/cve_match.py <target_ip> <port:service> [port:service ...]
"""

import time         # For rate limiting delays between queries
import sys          # For command line arguments
import os           # For path operations
import re           # For version parsing

# Import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cve_lookup.nvd_api import query_nvd, query_nvd_by_cpe, get_cpe_for_service, load_api_key
from cve_lookup.cpe_filter import detect_os, filter_cves, parse_service_version
from cve_lookup.known_cves import lookup_known_cves, get_cve_quality_score

# Metasploitable2-oriented service version fallbacks.
# Used only when service_id did not extract a version token.
KNOWN_SERVICE_VERSIONS = {
    "java rmi": "1.6.0_18",
    "mysql": "5.0.51",
    "postgresql": "8.3.1",
    "nfs": "",
    "rpcbind": "0.2.0",
    "ajp": "5.5.12",
    "unrealircd": "3.2.8.1",
}

# Service version overrides: map a normalized service string to the *software*
# version when the banner only contains a protocol version, not the software
# version.  This is needed because service_id.py may report "SMB 1.0" (the
# SMB dialect) for a host running "Samba 3.0.20" (the actual software).
# Keys are lowercase-stripped service strings as they appear in the service map.
SERVICE_VERSION_OVERRIDES = {
    # Metasploitable 2: Samba 3.0.20 on Linux reports SMB dialect 1.0
    "smb 1.0":              "3.0.20",
    "smb1":                 "3.0.20",
    "netbios-ssn (smb 1.0)": "3.0.20",
    "netbios-ssn":          "3.0.20",
}


def _resolve_svc_version(svc_name: str, svc_ver: str, service_string: str) -> str:
    """
    Return the best available version string for KB bounds checking.

    Priority:
      1. Version extracted by service_id (svc_ver) — only if it is NOT a
         well-known protocol dialect that would mislead version bounds.
         For SMB the dialect ("1.0", "2.0", "3.1.1") is NOT the Samba
         software version; we override it using SERVICE_VERSION_OVERRIDES.
      2. SERVICE_VERSION_OVERRIDES keyed on the full service string.
      3. KNOWN_SERVICE_VERSIONS keyed on the service name.
      4. Empty string (version unknown).
    """
    # Check full service string override first (e.g. "SMB 1.0" -> "3.0.20")
    key_full = service_string.lower().strip()
    if key_full in SERVICE_VERSION_OVERRIDES:
        return SERVICE_VERSION_OVERRIDES[key_full]

    # Check service name override
    key_name = svc_name.lower().strip()
    if key_name in SERVICE_VERSION_OVERRIDES:
        return SERVICE_VERSION_OVERRIDES[key_name]

    # Use extracted version if present and not overridden
    if svc_ver:
        return svc_ver

    # Fall back to KNOWN_SERVICE_VERSIONS
    return KNOWN_SERVICE_VERSIONS.get(key_name, "")


# ============================================================
# CONFIGURATION
# ============================================================

# Minimum CVSS score to include in results
MIN_CVSS_SCORE = 7.0

# Delay between NVD API queries (seconds)
# CIRCL has no hard rate limit; 1 s is enough to be polite.
# (Old value was 6 s — required only for the legacy NVD v2 API.)
QUERY_DELAY = 1

# Services to skip (generic names that produce too many irrelevant results)
# These are handled by OS-level CVE lookup instead
SKIP_SERVICES = [
    "Unknown",
    "unknown",
    "FTP",          # Too generic without a version
    "SSH",          # Too generic without a version
    "HTTP",         # Too generic without a version
    "SMTP",         # Too generic without a version
    "Telnet",       # Too generic without a version
    "DNS",          # Too generic without a version
]

# Services that should use OS-level CPE query instead of keyword search
# These are native OS services where keyword search returns garbage
OS_LEVEL_SERVICES = [
    "MSRPC", "Microsoft Windows RPC",
    "NetBIOS", "NetBIOS-SSN",
]

# Quality threshold: if API results score below this, use internal KB
QUALITY_THRESHOLD = 0.25


# ============================================================
# BINARY GARBAGE GUARD
# ============================================================

def _is_garbage_service(service_string):
    """
    Detect whether a service string is binary garbage from a failed banner grab.

    When service_id.py connects to a port and the remote service sends back
    raw binary bytes (e.g. Telnet IAC sequences like  #', or rexec
    'Where are you?' control strings), the decoder produces a short string
    that contains non-printable characters or no alphabetic letters at all.
    Sending that string to NVD as a keyword produces completely irrelevant
    CVE matches (false positives).

    Detection criteria — a string is 'garbage' if it meets ANY of these:
      1. Contains any non-ASCII character (ord > 127)
      2. Starts with a control character (ASCII 0x00-0x1F)
      3. Has no alphabetic characters at all
      4. More than 30% of characters are non-printable

    Args:
        service_string (str): The service name/banner string to check

    Returns:
        bool: True if the string looks like binary garbage, False if it is safe
    """
    if not service_string:
        return False

    text = str(service_string)

    # Criterion 1: any non-ASCII character means raw bytes leaked through
    for ch in text:
        if ord(ch) > 127:
            return True

    # Criterion 2: starts with a control character (0x00 - 0x1f)
    if text and ord(text[0]) < 32:
        return True

    # Criterion 3: no alphabetic characters at all (pure punctuation/digits/symbols)
    if not any(ch.isalpha() for ch in text):
        return True

    # Criterion 4: more than 30% of characters are non-printable (ord < 32)
    non_printable = sum(1 for ch in text if ord(ch) < 32)
    if len(text) > 0 and non_printable / len(text) > 0.30:
        return True

    return False

# ============================================================
# INTERNAL KB VERSION GUARDS
# ============================================================

def _parse_loose_version(version_text):
    """
    Parse loose versions like:
      "4.7p1" -> (4, 7, 1)
      "2.4.49" -> (2, 4, 49)
      "unknown" -> None
    """
    if version_text is None:
        return None
    text = str(version_text).strip().lower()
    if not text or text in {"unknown", "n/a", "*", "-"}:
        return None
    nums = re.findall(r"\d+", text)
    if not nums:
        return None
    return tuple(int(n) for n in nums[:4])


def _normalize_version_len(a, b):
    """Pad version tuples so lexicographic comparisons are stable."""
    max_len = max(len(a), len(b))
    return a + (0,) * (max_len - len(a)), b + (0,) * (max_len - len(b))


def _kb_version_in_bounds(cve, service_version):
    """
    Check whether an internal KB CVE applies to the detected service version.

    The check is only enforced when the CVE includes min/max bounds.
    """
    min_v = cve.get("min_version")
    max_v = cve.get("max_version")

    if not min_v and not max_v:
        return True, "no internal KB version bounds"

    sv = _parse_loose_version(service_version)
    if sv is None:
        return False, "service version unknown for bounded internal KB CVE"

    if min_v:
        min_t = _parse_loose_version(min_v)
        if min_t:
            sv_n, min_n = _normalize_version_len(sv, min_t)
            if sv_n < min_n:
                return False, f"version {service_version} below {min_v}"

    if max_v:
        max_t = _parse_loose_version(max_v)
        if max_t:
            sv_n, max_n = _normalize_version_len(sv, max_t)
            if sv_n > max_n:
                return False, f"version {service_version} above {max_v}"

    return True, "within internal KB version bounds"


# ============================================================
# MAIN MATCHING FUNCTION
# ============================================================

def match_cves(service_map, min_cvss=MIN_CVSS_SCORE, api_key=None, os_info=None):
    """
    Look up CVEs for all identified services using the best strategy.

    This is the MAIN function of this module. It:
    1. Detects the target OS from service signatures
    2. For each service, chooses the best query strategy:
       a. CPE-based query for services with CPE mappings
       b. Keyword query for unknown services
       c. Internal KB fallback when API returns garbage
    3. Filters results by OS, version, and CVSS score
    4. Returns organized results per port

    Args:
        service_map (dict):  {port: "service version"} from service_id.py
        min_cvss (float):    Minimum CVSS score (default 7.0)
        api_key (str):       NVD API key (or None)
        os_info (dict):      OS detection result from os_detect.py (optional)

    Returns:
        dict: Organized CVE results per port
    """
    if not service_map:
        print("[*] No services to look up CVEs for.")
        return {}

    # Load API key if not provided
    if api_key is None:
        api_key = load_api_key()

    # Detect OS from service map (enhanced with os_info if available)
    if os_info and os_info.get("os_family", "unknown") != "unknown":
        detected_os = os_info["os_family"]
    else:
        detected_os = detect_os(service_map)

    results = {}
    query_count = 0
    already_queried = {}
    seen_service_results = {}

    print(f"\n[*] CVE matching for {len(service_map)} service(s)")
    print(f"[*] Detected OS: {detected_os.upper()}")
    if os_info and os_info.get("os_version"):
        print(f"[*] OS Version:  {os_info['os_version']}")
    print(f"[*] Minimum CVSS threshold: {min_cvss}")
    print(f"[*] Strategy: CPE query → keyword query → internal KB fallback")
    print()

    # Track if we've already done an OS-level query
    os_level_done = False
    os_level_cves = []

    for port in sorted(service_map.keys()):
        service_string = service_map[port]
        print(f"  [{port}] Service: {service_string}", end="")

        service_key = " ".join(str(service_string).strip().lower().split())
        if service_key in seen_service_results:
            source_port, source_result = seen_service_results[service_key]
            print(f" → REUSING result from port {source_port}")
            results[port] = {
                "service": service_string,
                "cves": [dict(c) for c in source_result.get("cves", [])],
                "total_found": source_result.get("total_found", 0),
                "high_critical": source_result.get("high_critical", 0),
                "not_applicable": source_result.get("not_applicable", 0),
                "skipped": source_result.get("skipped", False),
                "query_method": source_result.get("query_method", "cache"),
                "using_internal_kb": source_result.get("using_internal_kb", False),
            }
            continue

        # Skip binary garbage banners — raw bytes from failed banner grabs
        # (e.g. Telnet IAC sequences, rexec control strings) would produce
        # completely irrelevant NVD keyword matches if sent as-is.
        if _is_garbage_service(service_string):
            print(f" -> SKIPPED (binary garbage banner — not a valid service name)")
            results[port] = {
                "service": service_string,
                "cves": [], "total_found": 0, "high_critical": 0,
                "not_applicable": 0, "skipped": True,
                "skip_reason": "binary_garbage",
            }
            seen_service_results[service_key] = (port, results[port])
            continue

        # Skip completely generic/unknown services
        if service_string in SKIP_SERVICES:
            print(f" → SKIPPED (too generic)")
            results[port] = {
                "service": service_string,
                "cves": [], "total_found": 0, "high_critical": 0,
                "not_applicable": 0, "skipped": True
            }
            seen_service_results[service_key] = (port, results[port])
            continue

        # Check if this is an OS-level service (SMB, RPC, NetBIOS)
        is_os_service = any(s.lower() in service_string.lower() for s in OS_LEVEL_SERVICES)
        is_smb = "smb" in service_string.lower()

        # ---- STRATEGY SELECTION ----
        all_cves = []
        query_method = "none"

        if service_key in already_queried:
            print(f" → REUSING cached query")
            all_cves = already_queried[service_key]
            query_method = "cache"
        else:
            if query_count > 0:
                print(f"\n  [*] Waiting {QUERY_DELAY}s (rate limit)...", end="")
                time.sleep(QUERY_DELAY)
            print()

            # Strategy 1: CPE-based query (most precise)
            cpe_string = get_cpe_for_service(service_string, os_info)

            if cpe_string:
                # For OS-level services, add a keyword filter
                keyword = None
                if is_smb:
                    keyword = "SMB"
                elif "rpc" in service_string.lower():
                    keyword = "RPC"
                elif "netbios" in service_string.lower():
                    keyword = "NetBIOS"

                all_cves = query_nvd_by_cpe(cpe_string, keyword_filter=keyword,
                                             api_key=api_key)
                query_method = "cpe"
                query_count += 1

            # Strategy 2: Keyword query (broader)
            if not all_cves and not is_os_service:
                all_cves = query_nvd(service_string, api_key=api_key)
                query_method = "keyword"
                query_count += 1

            already_queried[service_key] = all_cves

        # ---- QUALITY CHECK ----
        # If keyword search returned mostly old/irrelevant results, use internal KB
        quality = get_cve_quality_score(all_cves)
        using_internal_kb = False

        if (quality < QUALITY_THRESHOLD and all_cves) or (not all_cves and query_method != "none"):
            svc_name, svc_ver = parse_service_version(service_string)

            # Resolve the best available version — handles SMB dialect vs. Samba
            # software version mismatch and other protocol/software version gaps.
            resolved_ver = _resolve_svc_version(svc_name, svc_ver, service_string)
            if resolved_ver != svc_ver:
                print(f"  [*] Port {port}: version override '{svc_ver}' → '{resolved_ver}' for '{svc_name}'")
            elif not svc_ver and resolved_ver:
                print(f"  [*] Port {port}: using known version fallback '{resolved_ver}' for '{svc_name}'")
            svc_ver = resolved_ver

            kb_cves = lookup_known_cves(service_string, "", detected_os)

            # Enforce internal KB version bounds to avoid false positives
            # (e.g., OpenSSH 4.7p1 should not match CVE-2024-6387).
            kb_in_range = []
            kb_skipped = 0
            for cve in kb_cves:
                in_range, reason = _kb_version_in_bounds(cve, svc_ver)
                if not in_range:
                    kb_skipped += 1
                    print(f"  [~] Port {port}: {cve.get('id', 'UNKNOWN')} skipped ({reason})")
                    continue
                kb_in_range.append(cve)
            kb_cves = kb_in_range

            if kb_cves:
                print(f"  [*] Port {port}: API quality low ({quality:.2f}), "
                      f"using internal KB ({len(kb_cves)} CVEs)")
                all_cves = kb_cves
                using_internal_kb = True
            elif kb_skipped > 0:
                print(f"  [~] Port {port}: all internal KB CVEs skipped by version bounds")
                all_cves = []
                using_internal_kb = True

        # ---- FILTERING ----
        svc_name, svc_ver = parse_service_version(service_string)
        # Resolve version (handles SMB dialect vs. software version, fallbacks)
        svc_ver = _resolve_svc_version(svc_name, svc_ver, service_string)
        applicable, filtered_out = filter_cves(
            all_cves,
            svc_name,
            svc_ver,
            detected_os,
            os_info=os_info,
            service_map=service_map,
        )

        if filtered_out and not using_internal_kb:
            print(f"  [~] Port {port}: filtered {len(filtered_out)} irrelevant CVE(s)")
            for c in filtered_out[:3]:
                print(f"        → {c['id']}: {c.get('filter_reason', '?')}")
            if len(filtered_out) > 3:
                print(f"        → ... and {len(filtered_out)-3} more")

        # CVSS threshold filter
        filtered_cves = [c for c in applicable if c.get("cvss", 0) >= min_cvss]

        # Modern Windows patch-state filter (internal KB signal)
        # If a CVE is marked patched_in_modern=True and the detected OS generation
        # is modern, we skip it from actionable findings.
        if os_info and os_info.get("os_gen") == "modern":
            remaining_cves = []
            for cve in filtered_cves:
                if cve.get("patched_in_modern"):
                    cve["applicability_note"] = "PATCHED - already fixed in modern Windows"
                    print(f"  [~] Port {port}: {cve.get('id', 'UNKNOWN')} skipped (patched in modern Windows)")
                    cve_copy = dict(cve)
                    cve_copy["filter_reason"] = "patched in modern Windows"
                    filtered_out.append(cve_copy)
                    continue
                remaining_cves.append(cve)
            filtered_cves = remaining_cves

        results[port] = {
            "service": service_string,
            "cves": filtered_cves,
            "total_found": len(all_cves),
            "high_critical": len(filtered_cves),
            "not_applicable": len(filtered_out),
            "skipped": False,
            "query_method": query_method,
            "using_internal_kb": using_internal_kb,
        }
        seen_service_results[service_key] = (port, results[port])

        if filtered_cves:
            src = " (internal KB)" if using_internal_kb else ""
            print(f"  [+] Port {port}: {len(filtered_cves)} HIGH/CRITICAL CVE(s){src}")
        else:
            print(f"  [-] Port {port}: No applicable CVEs above CVSS {min_cvss}")

    # ---- SUMMARY ----
    print(f"\n[+] CVE matching complete")
    total_high = sum(r["high_critical"] for r in results.values())
    total_all = sum(r["total_found"] for r in results.values())
    total_filtered = sum(r.get("not_applicable", 0) for r in results.values())
    print(f"[+] {total_high} applicable HIGH/CRITICAL CVE(s) "
          f"(from {total_all} raw results, {total_filtered} filtered)")

    if total_high > 0:
        print(f"\n  {'PORT':<8} {'SERVICE':<25} {'CVE ID':<20} "
              f"{'CVSS':<8} {'SEVERITY':<12}")
        print(f"  {'-'*8} {'-'*25} {'-'*20} {'-'*8} {'-'*12}")
        for port in sorted(results.keys()):
            port_data = results[port]
            for cve in port_data["cves"]:
                svc = port_data["service"][:23]
                print(f"  {port:<8} {svc:<25} {cve['id']:<20} "
                      f"{cve['cvss']:<8} {cve['severity']:<12}")
        print()

    return results


# ============================================================
# CVE RESULT HELPERS
# ============================================================

def deduplicate_cve_results(cve_results: dict) -> list:
    """
    Flatten all CVEs from all ports into a single deduplicated list.
    When the same CVE appears on multiple ports, merge the port numbers
    into a 'ports' field e.g. [139, 445].
    Returns list of unique CVE dicts, each with a 'ports' field.
    """
    if not cve_results:
        return []

    unique = {}

    def _port_sort_key(val):
        try:
            return int(val)
        except (TypeError, ValueError):
            return 999999

    for port_key in sorted(cve_results.keys(), key=_port_sort_key):
        port_data = cve_results[port_key]
        if not isinstance(port_data, dict):
            continue

        is_internal_kb = port_data.get("using_internal_kb", False)
        query_method = port_data.get("query_method", "keyword")
        source_label = "internal_kb" if is_internal_kb else (
            "NVD (CPE)" if query_method == "cpe" else "NVD"
        )

        try:
            port_num = int(port_key)
        except (TypeError, ValueError):
            port_num = port_key

        for cve in port_data.get("cves", []):
            cve_id = cve.get("id", "UNKNOWN")
            if cve_id not in unique:
                merged = dict(cve)
                merged["ports"] = [port_num]
                if not merged.get("source"):
                    merged["source"] = source_label
                unique[cve_id] = merged
                continue

            if port_num not in unique[cve_id]["ports"]:
                unique[cve_id]["ports"].append(port_num)

    def _mixed_sort_key(val):
        if isinstance(val, int):
            return (0, val)
        sval = str(val)
        return (0, int(sval)) if sval.isdigit() else (1, sval)

    deduped = list(unique.values())
    for cve in deduped:
        cve["ports"] = sorted(cve.get("ports", []), key=_mixed_sort_key)

    deduped.sort(key=lambda c: (-float(c.get("cvss", 0)), str(c.get("id", ""))))
    return deduped


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":
    """
    Run from command line:
        python cve_lookup/cve_match.py 192.168.100.50 21:vsftpd_2.3.4 80:Apache_2.2.8

    Port:service pairs use underscores instead of spaces.
    """

    if len(sys.argv) < 3:
        print("Usage: python cve_lookup/cve_match.py <target_ip> "
              "<port:service> [port:service ...]")
        print("Example: python cve_lookup/cve_match.py 192.168.100.50 "
              "21:vsftpd_2.3.4 80:Apache_2.2.8")
        print("\nUse underscores for spaces in service names.")
        sys.exit(1)

    target = sys.argv[1]

    # Parse port:service pairs
    service_map = {}
    for arg in sys.argv[2:]:
        if ":" not in arg:
            print(f"[!] Invalid format '{arg}' - use port:service_version")
            continue
        parts = arg.split(":", 1)
        try:
            port = int(parts[0])
            service = parts[1].replace("_", " ")  # Underscores → spaces
            service_map[port] = service
        except ValueError:
            print(f"[!] Invalid port number in '{arg}'")

    if not service_map:
        print("[!] No valid port:service pairs provided")
        sys.exit(1)

    print(f"\n[*] Target: {target}")
    print(f"[*] Services to look up: {len(service_map)}")

    results = match_cves(service_map)

    # Check if we found anything critical
    total = sum(r["high_critical"] for r in results.values())
    if total > 0:
        sys.exit(0)
    else:
        print("[*] No high/critical CVEs found.")
        sys.exit(1)
