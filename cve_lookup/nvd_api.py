"""
nvd_api.py - NIST NVD CVE Lookup with Local Caching
=====================================================
This module queries the NIST National Vulnerability Database (NVD)
to find known CVEs (Common Vulnerabilities and Exposures) for a
given software service and version.

API DETAILS:
- Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
- Rate limit: 50 requests per 30 seconds WITH an API key
              5 requests per 30 seconds WITHOUT a key
- We use a 6-second delay between requests to stay well under limits

STEALTH / EFFICIENCY:
- Results are cached locally in a JSON file so we never re-query
  the same service string twice (fewer requests = less noise)
- API key is loaded from api.txt for higher rate limits
- Minimal data is extracted from the large NVD response

USAGE (standalone):
    python cve_lookup/nvd_api.py "vsftpd 2.3.4"
    python cve_lookup/nvd_api.py "Apache 2.2.8"
"""

import requests     # For making HTTP requests to the NVD API
import json         # For parsing API responses and cache files
import time         # For rate limiting delays
import os           # For file path operations
import sys          # For command line arguments

# Load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    _env_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".env")
    )
    load_dotenv(_env_path)
except ImportError:
    pass


# ============================================================
# CONFIGURATION
# ============================================================

# NVD API v2.0 endpoint for CVE search
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Delay between API requests (seconds) to respect rate limits
REQUEST_DELAY = 6

# Path to the API key file (relative to project root)
API_KEY_FILE = "api.txt"

# Path to the local cache file
# Results are stored here so we don't re-query the same service
CACHE_FILE = "cve_cache.json"

# Maximum number of CVE results to fetch per query
MAX_RESULTS = 50

# Request timeout in seconds
REQUEST_TIMEOUT = 30

# Cache format version — bump this whenever the stored data structure changes.
# If the saved cache uses an older version it is automatically discarded so
# the next run re-fetches full CPE configuration data from the NVD API.
CACHE_VERSION = 3


# ============================================================
# CPE STRING BUILDERS
# ============================================================
# CPE (Common Platform Enumeration) strings uniquely identify
# software products. Using CPE-based queries gives FAR more
# accurate results than keyword searches for generic services.

# Maps detected service names to NVD CPE strings for precise queries
SERVICE_CPE_MAP = {
    # Windows OS-level services (SMB, RPC, NetBIOS)
    # These should be queried by OS CPE, not service keyword
    "windows_11":       "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*",
    "windows_10":       "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
    "windows_server_2022": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
    "windows_server_2019": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",

    # Specific software products
    "vsftpd":           "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
    "openssh":          "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    "apache":           "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "nginx":            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    "samba":            "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
    "mysql":            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    "mariadb":          "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*",
    "postgresql":       "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    "iis":              "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
}


# ============================================================
# API KEY LOADING
# ============================================================

def load_api_key():
    """
    Load the NVD API key using this priority order:
      1. NVD_API_KEY environment variable (loaded from .env by dotenv)
      2. api.txt file in the project root (legacy fallback)

    Returns:
        str or None: The API key string, or None if not found
    """
    # Priority 1: environment variable (set via .env file)
    env_key = os.environ.get("NVD_API_KEY", "").strip()
    if env_key:
        masked = env_key[:8] + "..." + env_key[-4:]
        print(f"[*] NVD API key loaded from .env: {masked}")
        return env_key

    # Priority 2: api.txt file (legacy fallback)
    possible_paths = [
        API_KEY_FILE,
        os.path.join(os.path.dirname(__file__), "..", API_KEY_FILE),
    ]

    for path in possible_paths:
        try:
            full_path = os.path.abspath(path)
            if os.path.exists(full_path):
                with open(full_path, "r") as f:
                    key = f.read().strip()
                if key:
                    masked = key[:8] + "..." + key[-4:]
                    print(f"[*] NVD API key loaded from api.txt: {masked}")
                    return key
        except Exception:
            continue

    print("[!] No API key found in api.txt - using unauthenticated access")
    print("    (Rate limit: 5 requests per 30 seconds)")
    return None


# ============================================================
# CACHE MANAGEMENT
# ============================================================

def load_cache():
    """
    Load the local CVE cache from disk.

    The cache stores previous query results so we don't hit the
    NVD API for the same service twice. This saves time and
    reduces our network footprint.

    Returns:
        dict: Cached results {service_string: [cve_list]}
    """
    # Check multiple possible locations for the cache file
    possible_paths = [
        CACHE_FILE,
        os.path.join(os.path.dirname(__file__), "..", CACHE_FILE),
    ]

    for path in possible_paths:
        full_path = os.path.abspath(path)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r") as f:
                    cache = json.load(f)
                # Discard cache if it was built by an older code version
                if cache.get("_version") != CACHE_VERSION:
                    print(f"[*] Cache format updated to v{CACHE_VERSION}, "
                          f"clearing stale cache (will re-query NVD)")
                    return {"_version": CACHE_VERSION}
                print(f"[*] Loaded {len(cache)-1} cached queries from {CACHE_FILE}")
                return cache
            except (json.JSONDecodeError, IOError):
                # Cache file is corrupted, start fresh
                print(f"[!] Cache file corrupted, starting fresh")
                return {"_version": CACHE_VERSION}

    return {"_version": CACHE_VERSION}


def save_cache(cache):
    """
    Save the CVE cache to disk.

    Args:
        cache (dict): The cache dictionary to save
    """
    # Save to project root
    try:
        cache_path = os.path.join(os.path.dirname(__file__), "..", CACHE_FILE)
        full_path = os.path.abspath(cache_path)
        cache["_version"] = CACHE_VERSION
        with open(full_path, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"[!] Could not save cache: {e}")


# ============================================================
# CVE DATA EXTRACTION
# ============================================================

def extract_cve_info(cve_item):
    """
    Extract the important fields from a single NVD CVE record.

    The NVD API returns a LOT of data per CVE. We only need:
    - CVE ID (e.g. "CVE-2011-2523")
    - CVSS score (severity number 0-10)
    - Severity label (CRITICAL, HIGH, MEDIUM, LOW)
    - Short description of the vulnerability

    Args:
        cve_item (dict): One CVE record from the NVD API response

    Returns:
        dict: Simplified CVE info with id, cvss, severity, description
    """
    cve_data = cve_item.get("cve", {})

    # Get the CVE ID
    cve_id = cve_data.get("id", "UNKNOWN")

    # Get the description (English version)
    description = "No description available"
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", description)
            break

    # Truncate long descriptions
    if len(description) > 300:
        description = description[:300] + "..."

    # Get CVSS score - try v3.1 first, then v3.0, then v2.0
    cvss_score = 0.0
    severity = "UNKNOWN"

    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")

    # Try CVSS v3.0 if v3.1 not available
    if cvss_score == 0.0:
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")

    # Try CVSS v2.0 as last resort
    if cvss_score == 0.0:
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            # v2 doesn't have baseSeverity, derive from score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"

    # Extract CPE configuration data (vendor/product/version ranges).
    # cpe_filter.py uses this to determine platform and version applicability.
    cpe_list = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", True):
                    cpe_list.append({
                        "criteria":              cpe_match.get("criteria", ""),
                        "versionStartIncluding": cpe_match.get("versionStartIncluding", ""),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding", ""),
                        "versionEndIncluding":   cpe_match.get("versionEndIncluding", ""),
                        "versionEndExcluding":   cpe_match.get("versionEndExcluding", ""),
                    })

    return {
        "id": cve_id,
        "cvss": cvss_score,
        "severity": severity,
        "description": description,
        "cpe_list": cpe_list,
    }

# ============================================================
# MAIN API QUERY
# ============================================================

def query_nvd(service_string, api_key=None, use_cache=True):
    """
    Query the NVD API for CVEs related to a service string.

    How it works:
    1. Check the local cache first (avoid unnecessary requests)
    2. Build a keyword search query from the service string
    3. Send the request to NVD API v2.0
    4. Parse the response and extract relevant CVE data
    5. Cache the results for future use

    Args:
        service_string (str): Service to search, e.g. "vsftpd 2.3.4"
        api_key (str):        NVD API key (or None for unauthenticated)
        use_cache (bool):     Whether to use/update the local cache

    Returns:
        list of dict: CVE records, each with id, cvss, severity, description
    """
    # Normalize the search string (lowercase, trimmed)
    search_key = service_string.strip().lower()

    if not search_key:
        print("[!] Empty service string, skipping")
        return []

    # Check cache first
    cache = {}
    if use_cache:
        cache = load_cache()
        if search_key in cache:
            cached_results = cache[search_key]
            print(f"  [CACHE HIT] '{service_string}' → "
                  f"{len(cached_results)} CVE(s)")
            return cached_results

    print(f"  [API QUERY] Searching NVD for: '{service_string}'")

    # Build the API request parameters
    # keywordSearch does a full-text search across CVE descriptions
    params = {
        "keywordSearch": service_string,
        "resultsPerPage": MAX_RESULTS,
    }

    # Build request headers
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    # Make the API request
    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        # If API key causes issues (404/403), retry without it
        # Some API keys expire or get rejected silently
        if response.status_code in (403, 404) and api_key:
            print(f"  [!] API key rejected (HTTP {response.status_code}), "
                  f"retrying without key...")
            headers_no_key = {}
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers_no_key,
                timeout=REQUEST_TIMEOUT
            )

        # Handle rate limiting
        if response.status_code == 429:
            print(f"  [!] Rate limited (429). Waiting 30 seconds...")
            time.sleep(30)
            # Retry once
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )

        if response.status_code != 200:
            print(f"  [!] NVD API error: HTTP {response.status_code}")
            return []

        # Parse the JSON response
        data = response.json()

    except requests.exceptions.Timeout:
        print(f"  [!] NVD API request timed out after {REQUEST_TIMEOUT}s")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  [!] Could not connect to NVD API (no internet?)")
        return []
    except json.JSONDecodeError:
        print(f"  [!] Invalid JSON response from NVD API")
        return []

    # Extract CVE data from the response
    vulnerabilities = data.get("vulnerabilities", [])
    total_results = data.get("totalResults", 0)

    print(f"  [+] NVD returned {total_results} result(s)")

    cve_list = []
    for vuln_item in vulnerabilities:
        cve_info = extract_cve_info(vuln_item)
        cve_list.append(cve_info)

    # Sort by CVSS score (highest first = most dangerous first)
    cve_list.sort(key=lambda x: x["cvss"], reverse=True)

    # Cache the results
    if use_cache:
        cache[search_key] = cve_list
        save_cache(cache)

    return cve_list


def query_nvd_by_cpe(cpe_name, keyword_filter=None, api_key=None, use_cache=True):
    """
    Query NVD using a CPE name for precise results.

    Unlike keyword search, CPE-based queries return only CVEs that
    are specifically linked to the identified product/OS in the NVD
    database.  This eliminates false positives like "SMBCMS" when
    searching for the SMB protocol.

    Args:
        cpe_name (str):        CPE 2.3 string (e.g. "cpe:2.3:o:microsoft:windows_11:...")
        keyword_filter (str):  Optional keyword to narrow results (e.g. "SMB")
        api_key (str):         NVD API key (or None)
        use_cache (bool):      Whether to use local cache

    Returns:
        list of dict: CVE records with id, cvss, severity, description
    """
    # Build a unique cache key from the CPE + keyword combination
    cache_key = f"cpe:{cpe_name}"
    if keyword_filter:
        cache_key += f"+{keyword_filter}"
    cache_key = cache_key.strip().lower()

    # Check cache
    cache = {}
    if use_cache:
        cache = load_cache()
        if cache_key in cache:
            cached = cache[cache_key]
            print(f"  [CACHE HIT] CPE query → {len(cached)} CVE(s)")
            return cached

    print(f"  [API QUERY] CPE: {cpe_name[:60]}...")
    if keyword_filter:
        print(f"              + keyword: '{keyword_filter}'")

    # Build API parameters
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": MAX_RESULTS,
    }
    if keyword_filter:
        params["keywordSearch"] = keyword_filter

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL, params=params, headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code in (403, 404) and api_key:
            print(f"  [!] API key issue ({response.status_code}), retrying without key...")
            response = requests.get(
                NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT
            )

        if response.status_code == 429:
            print(f"  [!] Rate limited. Waiting 30s...")
            time.sleep(30)
            response = requests.get(
                NVD_API_URL, params=params, headers=headers,
                timeout=REQUEST_TIMEOUT
            )

        if response.status_code != 200:
            print(f"  [!] NVD API error: HTTP {response.status_code}")
            return []

        data = response.json()

    except requests.exceptions.Timeout:
        print(f"  [!] NVD API request timed out")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  [!] Could not connect to NVD API")
        return []
    except json.JSONDecodeError:
        print(f"  [!] Invalid JSON from NVD API")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    total_results = data.get("totalResults", 0)
    print(f"  [+] NVD returned {total_results} result(s) (CPE query)")

    cve_list = []
    for vuln_item in vulnerabilities:
        cve_info = extract_cve_info(vuln_item)
        cve_list.append(cve_info)

    cve_list.sort(key=lambda x: x["cvss"], reverse=True)

    if use_cache:
        cache[cache_key] = cve_list
        save_cache(cache)

    return cve_list


def get_cpe_for_service(service_name, os_info=None):
    """
    Map a detected service name to a CPE string for precise NVD queries.

    Args:
        service_name (str): Service name from service_id.py
        os_info (dict):     OS detection result from os_detect.py

    Returns:
        str or None: CPE string if we have a mapping, None otherwise
    """
    svc_lower = service_name.lower()

    # For Windows OS-level services, use the OS CPE
    if os_info and os_info.get("os_family") == "windows":
        os_version = os_info.get("os_version", "").lower()
        if "windows 11" in os_version or "windows 10/11" in os_version:
            return SERVICE_CPE_MAP.get("windows_11")
        elif "windows 10" in os_version:
            return SERVICE_CPE_MAP.get("windows_10")
        elif "server 2022" in os_version:
            return SERVICE_CPE_MAP.get("windows_server_2022")
        elif "server 2019" in os_version or "server 2016" in os_version:
            return SERVICE_CPE_MAP.get("windows_server_2019")

    # For specific software products
    for key, cpe in SERVICE_CPE_MAP.items():
        if key in svc_lower:
            return cpe

    return None


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":
    """
    Run from command line:
        python cve_lookup/nvd_api.py "vsftpd 2.3.4"
        python cve_lookup/nvd_api.py "Apache 2.2.8"
    """

    if len(sys.argv) < 2:
        print("Usage: python cve_lookup/nvd_api.py \"<service_string>\"")
        print("Example: python cve_lookup/nvd_api.py \"vsftpd 2.3.4\"")
        sys.exit(1)

    # Join all arguments in case the user forgot quotes
    service = " ".join(sys.argv[1:])

    print(f"\n[*] Looking up CVEs for: {service}")

    # Load API key
    api_key = load_api_key()

    # Query NVD
    results = query_nvd(service, api_key=api_key)

    if results:
        print(f"\n[+] Found {len(results)} CVE(s):\n")
        print(f"  {'CVE ID':<20} {'CVSS':<8} {'SEVERITY':<12} {'DESCRIPTION':<60}")
        print(f"  {'-'*20} {'-'*8} {'-'*12} {'-'*60}")
        for cve in results:
            desc = cve['description'][:58] if len(cve['description']) > 58 else cve['description']
            print(f"  {cve['id']:<20} {cve['cvss']:<8} {cve['severity']:<12} {desc}")
        print()
    else:
        print("\n[*] No CVEs found for this service.")
        sys.exit(1)
