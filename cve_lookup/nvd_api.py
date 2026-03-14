"""
nvd_api.py - Multi-Source CVE Lookup with Local Caching
========================================================
Primary source : CIRCL CVE Search API (https://cve.circl.lu/api/)
                 No API key required.  No hard per-request rate limit.
Fallback source: VulnCheck NVD++ (https://api.vulncheck.com/v3/index/nist-nvd2)
                 Bearer token read from .env (preferred) or api.txt (legacy).
                 Triggered automatically on ANY CIRCL failure:
                   • timeout / connection error
                   • HTTP error status
                   • empty result set

TOKEN CONFIGURATION (preferred — .env file in project root):
  VULNCHECK_TOKEN=vulncheck_xxxxxxxxxxxx
  Legacy fallback: api.txt in the project root (deprecated — migrate to .env)

CIRCL endpoints used:
  Vendor/product : GET /api/search/{vendor}/{product}   (from _CIRCL_VP_MAP)
  Keyword browse : GET /api/browse/{keyword}  →  products  →  /api/search/{v}/{p}
  CVE by ID      : GET /api/cve/{CVE-ID}      (KB enrichment)

VulnCheck NVD++ endpoint:
  GET https://api.vulncheck.com/v3/index/nist-nvd2?keyword={kw}
  Authorization: Bearer <token>
  Response format mirrors NVD v2.0, so extract_cve_info() reused as-is.

STEALTH / EFFICIENCY:
  - QUERY_DELAY = 1 s (down from 6 s — CIRCL is not rate-limited)
  - MIN_CVSS_FILTER = 7.0  (drops known-LOW/MEDIUM noise before caching)
  - CACHE_VERSION = 4  (forces cache invalidation; old NVD-format entries
    are incompatible with CIRCL's CPE-2.2 format)
  - timeout=10 s on every HTTP call (fast-fail, never stall the scan)
  - api_key parameter kept for backward-compat — now used only as the
    VulnCheck Bearer token override (.env / api.txt is the default source)

USAGE (standalone):
    python cve_lookup/nvd_api.py "vsftpd 2.3.4"
    python cve_lookup/nvd_api.py "Apache 2.2.8"
"""

import requests
import json
import time
import os
import sys
from urllib.parse import quote as _urlquote

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

# Primary source — CIRCL CVE Search (no auth required)
CIRCL_BASE_URL = "https://cve.circl.lu/api"

# Fallback source — VulnCheck NVD++ (mirrors NVD v2.0 response schema)
VULNCHECK_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"

# Path to the API key file — now holds the VulnCheck Bearer token
API_KEY_FILE = "api.txt"

# Local cache file path (relative to project root)
CACHE_FILE = "cve_cache.json"

# Inter-query delay in seconds (1 s is safe for CIRCL; no hard limit)
QUERY_DELAY = 1

# Drop CVEs whose CVSS score is *known* and *below* this value.
# CVEs with score == 0.0 (no published score) are kept — unknown ≠ safe.
MIN_CVSS_FILTER = 7.0

# Maximum CVEs to keep per query (after CVSS filter + sort)
MAX_RESULTS = 100

# HTTP timeout for every request — fast-fail, never stall the scanner
REQUEST_TIMEOUT = 10

# Cache format version — bump this whenever the stored data structure changes.
# v4: switched from NVD v2.0 CPE range format to CIRCL CPE-2.2/2.3 format.
CACHE_VERSION = 4


# ============================================================
# SERVICE → CPE MAP  (unchanged; used by get_cpe_for_service)
# ============================================================

SERVICE_CPE_MAP = {
    # Windows OS-level services (SMB, RPC, NetBIOS)
    "windows_11":          "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*",
    "windows_10":          "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
    "windows_server_2022": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
    "windows_server_2019": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",

    # Specific software products
    "vsftpd":       "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
    "openssh":      "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    "apache":       "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "nginx":        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    "samba":        "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
    "mysql":        "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    "mariadb":      "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*",
    "postgresql":   "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    "iis":          "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
}

# Maps service keyword → (vendor, product) for the CIRCL /search/{v}/{p} endpoint.
# Covers products whose CPE vendor differs from the common service name.
_CIRCL_VP_MAP = {
    "vsftpd":       ("vsftpd_project",  "vsftpd"),
    "openssh":      ("openbsd",         "openssh"),
    "sshd":         ("openbsd",         "openssh"),
    "apache":       ("apache",          "http_server"),
    "httpd":        ("apache",          "http_server"),
    "nginx":        ("nginx",           "nginx"),
    "samba":        ("samba",           "samba"),
    "mysql":        ("oracle",          "mysql"),
    "mariadb":      ("mariadb",         "mariadb"),
    "postgresql":   ("postgresql",      "postgresql"),
    "postgres":     ("postgresql",      "postgresql"),
    "iis":          ("microsoft",       "internet_information_services"),
    "proftpd":      ("proftpd_project", "proftpd"),
    "sendmail":     ("sendmail",        "sendmail"),
    "postfix":      ("postfix",         "postfix"),
    "dovecot":      ("dovecot",         "dovecot"),
    "tomcat":       ("apache",          "tomcat"),
    "unrealircd":   ("unrealircd",      "unrealircd"),
    "ircd":         ("ircd",            "ircd"),
    "php":          ("php",             "php"),
    "samba":        ("samba",           "samba"),
    "smb":          ("samba",           "samba"),
    "windows_11":   ("microsoft",       "windows_11"),
    "windows_10":   ("microsoft",       "windows_10"),
    "windows":      ("microsoft",       "windows_10"),
}


# ============================================================
# API KEY / TOKEN LOADING
# ============================================================

def load_api_key():
    """
    Load the VulnCheck Bearer token (or legacy NVD API key) using this
    priority order:
      1. VULNCHECK_TOKEN or NVD_API_KEY environment variable  ← PREFERRED
         Set this in a .env file at the project root:
             VULNCHECK_TOKEN=vulncheck_xxxxxxxxxxxx
      2. api.txt file in the project root  ← DEPRECATED LEGACY FALLBACK

    The returned value is used as the VulnCheck Bearer token when CIRCL
    fails.  The 'api_key' parameter on public functions is kept for
    backward-compatibility; passing it explicitly overrides this loader.

    Returns:
        str or None
    """
    # Priority 1: environment variable (.env or real env) — preferred method
    for env_var in ("VULNCHECK_TOKEN", "NVD_API_KEY"):
        env_key = os.environ.get(env_var, "").strip()
        if env_key:
            masked = env_key[:12] + "..." + env_key[-4:]
            print(f"[*] VulnCheck token loaded from env ({env_var}): {masked}")
            return env_key

    # Priority 2: api.txt — DEPRECATED, kept only for backward compatibility
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
                    masked = key[:12] + "..." + key[-4:]
                    print(f"[!] DEPRECATED: VulnCheck token loaded from api.txt: {masked}")
                    print(f"[!]   Migrate to .env — add this line to .env in the project root:")
                    print(f"[!]     VULNCHECK_TOKEN={key}")
                    return key
        except Exception:
            continue

    print("[!] No VulnCheck token found — fallback disabled if CIRCL fails")
    print("[!]   To enable VulnCheck fallback, add to .env in the project root:")
    print("[!]     VULNCHECK_TOKEN=<your_token>")
    return None


# ============================================================
# CACHE MANAGEMENT
# ============================================================

def load_cache():
    """
    Load the local CVE cache from disk.

    Returns:
        dict: {cache_key: [cve_list], "_version": CACHE_VERSION}
    """
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
                if cache.get("_version") != CACHE_VERSION:
                    print(
                        f"[*] Cache format updated to v{CACHE_VERSION}, "
                        f"clearing stale cache (will re-query)"
                    )
                    return {"_version": CACHE_VERSION}
                print(f"[*] Loaded {len(cache) - 1} cached queries from {CACHE_FILE}")
                return cache
            except (json.JSONDecodeError, IOError):
                print("[!] Cache file corrupted, starting fresh")
                return {"_version": CACHE_VERSION}
    return {"_version": CACHE_VERSION}


def save_cache(cache):
    """
    Persist the CVE cache to disk.

    Args:
        cache (dict): Cache dictionary to save
    """
    try:
        cache_path = os.path.join(os.path.dirname(__file__), "..", CACHE_FILE)
        full_path  = os.path.abspath(cache_path)
        cache["_version"] = CACHE_VERSION
        with open(full_path, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"[!] Could not save cache: {e}")


# ============================================================
# CVE DATA EXTRACTION — NVD v2.0 format (VulnCheck fallback)
# ============================================================

def extract_cve_info(cve_item):
    """
    Extract important fields from a single NVD v2.0-format CVE record.

    VulnCheck NVD++ returns items in this exact schema, so this function
    is used unchanged for the VulnCheck fallback path.

    Args:
        cve_item (dict): One CVE record from NVD/VulnCheck API response

    Returns:
        dict with keys: id, cvss (float), severity, description, cpe_list
    """
    cve_data = cve_item.get("cve", {})

    # CVE ID
    cve_id = cve_data.get("id", "UNKNOWN")

    # English description
    description = "No description available"
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", description)
            break
    if len(description) > 300:
        description = description[:300] + "..."

    # CVSS score — try v3.1, v3.0, then v2.0
    cvss_score = 0.0
    severity   = "UNKNOWN"
    metrics    = cve_data.get("metrics", {})

    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        d = cvss_v31[0].get("cvssData", {})
        cvss_score = d.get("baseScore", 0.0)
        severity   = d.get("baseSeverity", "UNKNOWN")

    if cvss_score == 0.0:
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            d = cvss_v30[0].get("cvssData", {})
            cvss_score = d.get("baseScore", 0.0)
            severity   = d.get("baseSeverity", "UNKNOWN")

    if cvss_score == 0.0:
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            d = cvss_v2[0].get("cvssData", {})
            cvss_score = d.get("baseScore", 0.0)
            if cvss_score >= 9.0:   severity = "CRITICAL"
            elif cvss_score >= 7.0: severity = "HIGH"
            elif cvss_score >= 4.0: severity = "MEDIUM"
            elif cvss_score > 0:    severity = "LOW"

    # CPE configuration data (version ranges where present)
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
        "id":          cve_id,
        "cvss":        cvss_score,
        "severity":    severity,
        "description": description,
        "cpe_list":    cpe_list,
    }


# ============================================================
# CPE FORMAT HELPERS
# ============================================================

def _cpe22_to_cpe23(cpe22):
    """
    Convert a CIRCL CPE 2.2 string to CPE 2.3 format so that
    cpe_filter.parse_cpe() can process it correctly.

    cpe:/a:vsftpd_project:vsftpd:2.3.4
        → cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*

    Already CPE 2.3 strings are returned unchanged.
    """
    if not cpe22:
        return ""
    if cpe22.startswith("cpe:2.3:"):
        return cpe22

    # Strip leading "cpe:/" or "cpe:"
    if cpe22.startswith("cpe:/"):
        rest = cpe22[5:]
    elif cpe22.startswith("cpe:"):
        rest = cpe22[4:]
    else:
        rest = cpe22

    # rest is now like "a:vendor:product:version" (first char may be the type)
    parts = rest.split(":")
    # Some CIRCL strings start with "/a" after the cpe: prefix was stripped
    if parts and parts[0].startswith("/"):
        parts[0] = parts[0][1:]

    # Pad out to type, vendor, product, version
    while len(parts) < 4:
        parts.append("*")

    cpe_type = parts[0] or "a"
    vendor   = parts[1] if len(parts) > 1 else "*"
    product  = parts[2] if len(parts) > 2 else "*"
    version  = parts[3] if len(parts) > 3 else "*"

    return f"cpe:2.3:{cpe_type}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _cpe23_to_vendor_product(cpe23):
    """
    Extract (vendor, product) from a CPE 2.3 string.

    cpe:2.3:a:vsftpd_project:vsftpd:*:...  →  ("vsftpd_project", "vsftpd")

    Returns:
        tuple(str, str) or (None, None) if parsing fails
    """
    parts = cpe23.split(":")
    if len(parts) < 5:
        return None, None
    vendor  = parts[3].strip() or None
    product = parts[4].strip() or None
    return vendor, product


# ============================================================
# CIRCL CVE EXTRACTION
# ============================================================

def _extract_circl_cve(item):
    """
    Convert a CIRCL CVE Search API item into our standard CVE dict.

    CIRCL fields used:
      id          → CVE ID
      summary     → description
      cvss        → CVSS v2.0 score (string)
      cvss3       → CVSS v3.x score (string, may be absent)
      vulnerable_configuration → list of CPE 2.2 strings (or dicts)

    Returns:
        dict with keys: id, cvss (float), severity, description, cpe_list
    """
    cve_id = item.get("id", "UNKNOWN")

    description = item.get("summary", "No description available") or "No description available"
    if len(description) > 300:
        description = description[:300] + "..."

    # Prefer CVSS v3 score, fall back to CVSS v2
    cvss_score = 0.0
    for key in ("cvss3", "cvss-score", "cvss"):
        raw = item.get(key)
        if raw is not None:
            try:
                val = float(raw)
                if val > 0.0:
                    cvss_score = val
                    break
            except (ValueError, TypeError):
                continue

    # Derive severity from score
    if cvss_score >= 9.0:    severity = "CRITICAL"
    elif cvss_score >= 7.0:  severity = "HIGH"
    elif cvss_score >= 4.0:  severity = "MEDIUM"
    elif cvss_score > 0.0:   severity = "LOW"
    else:                     severity = "UNKNOWN"

    # Build CPE list — CIRCL returns CPE 2.2 strings (or dicts with an "id" key)
    # Convert everything to CPE 2.3 so cpe_filter.parse_cpe() works correctly.
    # Version range fields are absent from CIRCL data; is_version_relevant()
    # handles this gracefully by returning True when no ranges are present.
    cpe_list = []
    for entry in item.get("vulnerable_configuration", []):
        if isinstance(entry, str):
            raw_cpe = entry
        elif isinstance(entry, dict):
            raw_cpe = entry.get("id", "") or entry.get("title", "")
        else:
            continue
        cpe23 = _cpe22_to_cpe23(raw_cpe)
        if cpe23:
            cpe_list.append({
                "criteria":              cpe23,
                "versionStartIncluding": "",
                "versionStartExcluding": "",
                "versionEndIncluding":   "",
                "versionEndExcluding":   "",
            })

    return {
        "id":          cve_id,
        "cvss":        cvss_score,
        "severity":    severity,
        "description": description,
        "cpe_list":    cpe_list,
    }


def _parse_circl_response(raw):
    """
    Normalise a CIRCL API response into a flat list of raw CVE dicts.

    CIRCL can return:
      • A JSON list of CVE objects directly
      • A dict with a "data" or "cves" key wrapping the list
      • A single CVE object dict (for /api/cve/{ID})
    """
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("data", "cves", "results"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        # Single CVE dict
        if "id" in raw:
            return [raw]
    return []


# ============================================================
# CVSS FILTER
# ============================================================

def _apply_cvss_filter(cve_list):
    """
    Drop CVEs whose CVSS score is *known* and below MIN_CVSS_FILTER.

    CVEs with score == 0.0 (no published score) are kept because
    unknown severity must not be treated as "not critical".

    Args:
        cve_list (list): List of standard CVE dicts

    Returns:
        list: Filtered CVE list
    """
    return [
        cve for cve in cve_list
        if cve["cvss"] == 0.0 or cve["cvss"] >= MIN_CVSS_FILTER
    ]


# ============================================================
# CIRCL API QUERIES
# ============================================================

def _query_circl_by_vendor_product(vendor, product):
    """
    Query CIRCL CVE Search using the /api/search/{vendor}/{product} endpoint.

    Returns:
        list of standard CVE dicts, or empty list on any failure
    """
    url = f"{CIRCL_BASE_URL}/search/{_urlquote(vendor)}/{_urlquote(product)}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            print(f"  [CIRCL] HTTP {resp.status_code} for {vendor}/{product}")
            return []
        raw = resp.json()
    except requests.exceptions.Timeout:
        print(f"  [CIRCL] Timeout querying {vendor}/{product}")
        return []
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        print(f"  [CIRCL] Connection error: {e}")
        return []
    except json.JSONDecodeError:
        print(f"  [CIRCL] Invalid JSON response")
        return []

    items = _parse_circl_response(raw)
    results = [_extract_circl_cve(item) for item in items if isinstance(item, dict)]
    return results


def _query_circl_keyword(keyword):
    """
    Fallback CIRCL query for services not in _CIRCL_VP_MAP.

    CIRCL has NO single-segment keyword search endpoint — GET /api/search/{kw}
    returns HTTP 404.  The correct approach is a two-step browse:

      Step 1: GET /api/browse/{keyword}
              Returns {"vendor": "<name>", "product": ["p1", "p2", ...]}
              for vendor-name discovery.

      Step 2: For each discovered product call
              _query_circl_by_vendor_product(vendor, product)
              and return the first non-empty result set.

    Returns empty list (triggering VulnCheck fallback at caller level) when:
      - browse returns HTTP error / timeout
      - browse finds no products for this vendor keyword
    """
    kw  = keyword.strip().lower()
    url = f"{CIRCL_BASE_URL}/browse/{_urlquote(kw)}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            print(f"  [CIRCL] browse/{kw} → HTTP {resp.status_code} (no vendor found)")
            return []
        data = resp.json()
    except requests.exceptions.Timeout:
        print(f"  [CIRCL] browse/{kw} → timeout")
        return []
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        print(f"  [CIRCL] browse/{kw} → connection error: {e}")
        return []
    except json.JSONDecodeError:
        print(f"  [CIRCL] browse/{kw} → invalid JSON")
        return []

    # Parse the browse response — may be dict or bare list of products
    if isinstance(data, dict):
        vendor   = data.get("vendor", kw)
        products = data.get("product", [])
    elif isinstance(data, list):
        vendor   = kw
        products = data
    else:
        print(f"  [CIRCL] browse/{kw} → unexpected response type")
        return []

    if not products:
        print(f"  [CIRCL] browse/{kw} → no products listed for this vendor")
        return []

    print(f"  [CIRCL] browse/{kw} → vendor='{vendor}', {len(products)} product(s)")

    # Query each discovered product; stop at the first non-empty hit
    # (cap at 3 products to avoid N×HTTP overhead — the first is almost
    # always the canonical product for a single-product vendor like vsftpd).
    for product in products[:3]:
        results = _query_circl_by_vendor_product(vendor, str(product))
        if results:
            return results

    return []


def _circl_query(keyword):
    """
    High-level CIRCL query: tries vendor/product lookup first,
    falls back to plain keyword search if no mapping found.

    Returns:
        list of standard CVE dicts (may be empty)
    """
    kw = keyword.strip().lower().split()[0] if keyword.strip() else ""
    if not kw:
        return []

    # Prefer the precise vendor/product endpoint
    vp = _CIRCL_VP_MAP.get(kw)
    if vp:
        vendor, product = vp
        print(f"  [CIRCL] search/{vendor}/{product}")
        results = _query_circl_by_vendor_product(vendor, product)
        if results:
            return results
        print(f"  [CIRCL] VP search empty, trying keyword fallback")

    # Generic keyword search
    print(f"  [CIRCL] search/{kw} (keyword)")
    return _query_circl_keyword(kw)


def _circl_query_cpe(cpe23):
    """
    CIRCL query for a specific CPE: extracts vendor/product and uses
    the /search/{vendor}/{product} endpoint.

    Returns:
        list of standard CVE dicts (may be empty)
    """
    vendor, product = _cpe23_to_vendor_product(cpe23)
    if not vendor or not product or vendor == "*" or product == "*":
        # Wildcard CPE — extract a useful keyword instead
        kw = (product or vendor or "").replace("_", " ").split()[0] if (product or vendor) else ""
        if not kw:
            return []
        return _circl_keyword_only(kw)

    # Skip wildcard products
    if product == "*":
        return []

    print(f"  [CIRCL] CPE → search/{vendor}/{product}")
    results = _query_circl_by_vendor_product(vendor, product)
    return results


def _circl_keyword_only(kw):
    """Thin wrapper: browse-then-query CIRCL for a single keyword."""
    print(f"  [CIRCL] browse/{kw}")
    return _query_circl_keyword(kw)


# ============================================================
# CIRCL CVE-BY-ID ENRICHMENT
# ============================================================

def _fetch_circl_cve_by_id(cve_id):
    """
    Fetch a single CVE record by ID from CIRCL's CVE-by-ID endpoint.

        GET https://cve.circl.lu/api/cve/{CVE-ID}

    Purpose: enrich internal Knowledge Base entries (from known_cves.py)
    with live CVSS scores and descriptions pulled from CIRCL, keeping
    cached KB data fresh without a full re-scan.

    This endpoint is free, requires no authentication, and is extremely
    reliable — it returns a single object that CIRCL always has indexed
    if the CVE was ever published by NVD or MITRE.

    Args:
        cve_id (str): e.g. "CVE-2011-2523"

    Returns:
        dict: Standard CVE dict (id, cvss, severity, description, cpe_list)
              or None on any failure / unrecognised CVE ID
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    url = f"{CIRCL_BASE_URL}/cve/{_urlquote(cve_id.upper())}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            # CVE not in CIRCL index — not necessarily an error
            return None
        if resp.status_code != 200:
            print(f"  [CIRCL] cve/{cve_id} → HTTP {resp.status_code}")
            return None
        data = resp.json()
    except requests.exceptions.Timeout:
        print(f"  [CIRCL] cve/{cve_id} → timeout")
        return None
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        print(f"  [CIRCL] cve/{cve_id} → connection error: {e}")
        return None
    except json.JSONDecodeError:
        print(f"  [CIRCL] cve/{cve_id} → invalid JSON")
        return None

    if not data or not isinstance(data, dict) or "id" not in data:
        return None

    return _extract_circl_cve(data)




def _query_vulncheck(keyword, token):
    """
    Query VulnCheck NVD++ for CVEs matching a keyword.

    VulnCheck NVD++ response wraps NVD v2.0-format items in a "data"
    array, so extract_cve_info() is used directly on each element.

    Args:
        keyword (str): Product/service keyword to search
        token   (str): VulnCheck Bearer token

    Returns:
        list of standard CVE dicts, or empty list on any failure
    """
    if not token:
        print("  [VulnCheck] No token available, skipping fallback")
        return []

    headers = {"Authorization": f"Bearer {token}"}
    params  = {"keyword": keyword}

    try:
        resp = requests.get(
            VULNCHECK_URL, params=params, headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 401:
            print("  [VulnCheck] Token rejected (401)")
            return []
        if resp.status_code != 200:
            print(f"  [VulnCheck] HTTP {resp.status_code}")
            return []
        data = resp.json()
    except requests.exceptions.Timeout:
        print("  [VulnCheck] Timeout")
        return []
    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
        print(f"  [VulnCheck] Connection error: {e}")
        return []
    except json.JSONDecodeError:
        print("  [VulnCheck] Invalid JSON response")
        return []

    items = data.get("data", [])
    results = []
    for item in items:
        try:
            results.append(extract_cve_info(item))
        except Exception:
            continue
    return results


def _query_vulncheck_cpe(cpe_name, token):
    """
    VulnCheck NVD++ fallback for CPE-based queries.

    Extracts the product name from the CPE string and runs a keyword
    search — VulnCheck's product-level coverage is strong enough that
    this yields equivalent results to a full CPE query.

    Args:
        cpe_name (str): CPE 2.3 string
        token    (str): VulnCheck Bearer token

    Returns:
        list of standard CVE dicts
    """
    vendor, product = _cpe23_to_vendor_product(cpe_name)
    # Use product name as keyword; strip wildcard tokens
    kw = (product or vendor or "").replace("_", " ").replace("*", "").strip()
    kw = kw.split()[0] if kw else ""
    if not kw:
        return []

    print(f"  [VulnCheck] keyword='{kw}' (derived from CPE)")
    return _query_vulncheck(kw, token)


# ============================================================
# MAIN API QUERY FUNCTIONS  (public — signatures preserved)
# ============================================================

def query_nvd(service_string, api_key=None, use_cache=True):
    """
    Query for CVEs related to a service string.

    Flow:
      1. Cache hit?  Return immediately.
      2. CIRCL primary query (vendor/product lookup, then keyword).
      3. If CIRCL returns nothing → VulnCheck NVD++ fallback.
      4. Apply MIN_CVSS_FILTER, sort by CVSS desc, cache + return.

    Args:
        service_string (str): e.g. "vsftpd 2.3.4", "SMB", "Apache 2.2.8"
        api_key        (str): VulnCheck Bearer token override (or None)
        use_cache     (bool): Whether to check/update the local cache

    Returns:
        list of dict: CVE records with id, cvss, severity, description, cpe_list
    """
    search_key = service_string.strip().lower()
    if not search_key:
        print("[!] Empty service string, skipping")
        return []

    # 1 — Cache check
    cache = {}
    if use_cache:
        cache = load_cache()
        if search_key in cache:
            cached = cache[search_key]
            print(f"  [CACHE HIT] '{service_string}' → {len(cached)} CVE(s)")
            return cached

    print(f"  [QUERY] '{service_string}'")
    token = api_key or load_api_key()

    # 2 — CIRCL primary
    results = _circl_query(search_key)
    source  = "CIRCL"

    # 3 — VulnCheck fallback (any CIRCL failure including empty result)
    if not results:
        print(f"  [CIRCL] No results — trying VulnCheck fallback")
        kw = search_key.split()[0]
        results = _query_vulncheck(kw, token)
        source  = "VulnCheck"

    print(f"  [+] {source} returned {len(results)} raw result(s)")

    # 4 — Filter, sort, limit, cache
    results = _apply_cvss_filter(results)
    results.sort(key=lambda x: x["cvss"], reverse=True)
    results = results[:MAX_RESULTS]

    if use_cache:
        cache[search_key] = results
        save_cache(cache)

    time.sleep(QUERY_DELAY)
    return results


def query_nvd_by_cpe(cpe_name, keyword_filter=None, api_key=None, use_cache=True):
    """
    Query for CVEs linked to a specific CPE string.

    CPE-based queries are more precise than keyword searches: they map
    directly to a vendor/product pair in CIRCL, eliminating keyword
    noise from the start.

    Args:
        cpe_name       (str):  CPE 2.3 string
        keyword_filter (str):  Optional extra keyword (unused in routing,
                               kept for backward-compat)
        api_key        (str):  VulnCheck Bearer token override
        use_cache     (bool):  Whether to check/update the local cache

    Returns:
        list of dict: CVE records with id, cvss, severity, description, cpe_list
    """
    cache_key = f"cpe:{cpe_name}"
    if keyword_filter:
        cache_key += f"+{keyword_filter}"
    cache_key = cache_key.strip().lower()

    # 1 — Cache check
    cache = {}
    if use_cache:
        cache = load_cache()
        if cache_key in cache:
            cached = cache[cache_key]
            print(f"  [CACHE HIT] CPE query → {len(cached)} CVE(s)")
            return cached

    print(f"  [QUERY CPE] {cpe_name[:70]}{'...' if len(cpe_name) > 70 else ''}")
    if keyword_filter:
        print(f"             + keyword: '{keyword_filter}'")

    token = api_key or load_api_key()

    # 2 — CIRCL primary (by vendor/product extracted from CPE)
    results = _circl_query_cpe(cpe_name)
    source  = "CIRCL"

    # 3 — VulnCheck fallback
    if not results:
        print(f"  [CIRCL] No results — trying VulnCheck fallback")
        results = _query_vulncheck_cpe(cpe_name, token)
        source  = "VulnCheck"

    print(f"  [+] {source} returned {len(results)} raw result(s) (CPE query)")

    # 4 — Filter, sort, limit, cache
    results = _apply_cvss_filter(results)
    results.sort(key=lambda x: x["cvss"], reverse=True)
    results = results[:MAX_RESULTS]

    if use_cache:
        cache[cache_key] = results
        save_cache(cache)

    time.sleep(QUERY_DELAY)
    return results


def get_cpe_for_service(service_name, os_info=None):
    """
    Map a detected service name to a CPE string for precise queries.

    Args:
        service_name (str): Service name from service_id.py
        os_info      (dict): OS detection result from os_detect.py

    Returns:
        str or None: CPE 2.3 string if we have a mapping, None otherwise
    """
    svc_lower = service_name.lower()

    # Windows OS-level services — use OS CPE
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

    # Specific software products
    for key, cpe in SERVICE_CPE_MAP.items():
        if key in svc_lower:
            return cpe

    return None


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cve_lookup/nvd_api.py \"<service_string>\"")
        print("Example: python cve_lookup/nvd_api.py \"vsftpd 2.3.4\"")
        sys.exit(1)

    service = " ".join(sys.argv[1:])
    print(f"\n[*] Looking up CVEs for: {service}")

    api_key = load_api_key()
    results = query_nvd(service, api_key=api_key)

    if results:
        print(f"\n[+] Found {len(results)} CVE(s) (CVSS >= {MIN_CVSS_FILTER} or unknown):\n")
        print(f"  {'CVE ID':<20} {'CVSS':<8} {'SEVERITY':<12} {'DESCRIPTION'}")
        print(f"  {'-'*20} {'-'*8} {'-'*12} {'-'*60}")
        for cve in results:
            desc = cve["description"]
            desc = desc[:58] if len(desc) > 58 else desc
            print(f"  {cve['id']:<20} {cve['cvss']:<8} {cve['severity']:<12} {desc}")
        print()
    else:
        print(f"\n[*] No CVEs found (or all below CVSS {MIN_CVSS_FILTER}).")
        sys.exit(1)
