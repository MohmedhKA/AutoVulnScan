<p align="center">
  <picture>
    <img src="assets/Logo.png" alt="AutoVulnScan" width="700">
  </picture>
</p>

<p align="center">
  <strong>Stealth-first automated vulnerability scanner — pure Python.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform Windows and Linux">
  <img src="https://img.shields.io/badge/CVE%20Source-CIRCL%20%2F%20VulnCheck-orange?style=flat-square" alt="CVE Source: CIRCL / VulnCheck">
  <img src="https://img.shields.io/badge/Use-Educational%20Only-red?style=flat-square" alt="Educational use only">
</p>

---

## Overview

AutoVulnScan automates a practical vulnerability assessment workflow from a single terminal interface. It performs host discovery, port scanning, service and OS fingerprinting, CVE correlation against public databases, optional exploit validation, and produces clean HTML and JSON reports — all without installing Nmap or any binary dependencies.

The interface is a **page-based TUI** with full arrow-key navigation, not a flags-driven CLI.

---

## Pipeline

```
Host Discovery (optional)
      │
      ▼
  Port Scan  ──────────────────────────────── stealth profile applied
      │
      ▼
  Service Identification  ─────────────────── protocol-aware banner probes
      │
      ▼
  OS Detection  ───────────────────────────── SMB negotiate handshake
      │
      ▼
  CVE Matching  ───────────────────────────── CIRCL → VulnCheck → internal KB
      │
      ▼
  Exploit Validation  ─────────────────────── non-destructive checks only
      │
      ▼
  Report Generation  ──────────────────────── HTML + JSON
```

---

## Features

### Stealth-First Scanning

Every scan is designed to minimize noise on the wire:

- Randomized probe and port ordering
- Per-profile delay and jitter controls
- Bounded thread concurrency
- Passive-first banner grabbing
- Clean socket teardown on every connection
- TCP-based host liveness — no ICMP dependency

### Stealth Profiles

| Profile  | Delay  | Jitter  | Threads | Timeout | Intended Use         |
|----------|-------:|--------:|--------:|--------:|----------------------|
| `normal` | 0.0 s  | 0.0 s   | 50      | 0.5 s   | Fast internal audits |
| `quiet`  | 0.05 s | 0.05 s  | 25      | 1.0 s   | Balanced stealth     |
| `ghost`  | 0.2 s  | 0.15 s  | 10      | 1.5 s   | Maximum evasion      |

### Windows Service and OS Accuracy

Standard banner grabbing fails on Windows RPC/SMB/NetBIOS. AutoVulnScan uses protocol-aware probing:

- SMB dialect extraction (e.g., `SMB 3.1.1`)
- OS generation classification (`modern` vs `legacy`) via SMB negotiate
- RPC, NetBIOS, and SMB identified through actual protocol handshakes, not text patterns

### CVE Intelligence with False-Positive Controls

`cve_lookup/cve_match.py` applies a layered matching strategy:

1. **CIRCL CVE Search** (`cve.circl.lu`) — primary source, no API key required  
   Queries `GET /api/search/{vendor}/{product}` using CPE mappings for well-known services.
2. **VulnCheck NVD++** — fallback when CIRCL fails, times out, or returns empty results  
   Token-authenticated. Returns NVD v2.0-compatible JSON.
3. **Internal curated KB** (`known_cves.py`) — final fallback  
   Used when both APIs are unreachable or return low-quality results. Always accurate; curated per service/version/OS.

Supporting components:

- **`cve_lookup/cpe_filter.py`**: filters raw CVE candidates by platform relevance, service topic relevance, and version-range relevance to reduce noisy matches.
- **`cve_lookup/known_cves.py`**: internal curated knowledge base used when API responses are weak, missing, or overly broad for practical service-level matching.

Each result then passes through:

- Platform relevance filtering via `cpe_filter.py`
- Service-topic checks (SMB, RPC, NetBIOS topic gating)
- Version range filtering where CPE range data is available
- CVSS threshold gate (`>= 7.0` by default; `0.0` passes through as unknown severity)
- **Protocol/software version resolution** — e.g. SMB dialect `"1.0"` is recognized as Samba `3.0.20` for correct CVE bounds checking
- **Modern patch-state suppression** — CVEs flagged `patched_in_modern=true` are suppressed when the detected OS generation is `modern`

### Internal KB Coverage (as of current version)

The internal KB covers the following services against Metasploitable 2 and common Linux/Windows targets:

| Service | CVE | CVSS | Notes |
|---------|-----|------|-------|
| vsftpd 2.3.4 | CVE-2011-2523 | 9.8 | Backdoor |
| Samba 3.0.0–3.0.25 | CVE-2007-2447 | 10.0 | Username map script RCE |
| Samba 3.5.0–4.6.3 | CVE-2017-7494 | 9.8 | SambaCry |
| Apache HTTP 2.2–2.4.27 | CVE-2017-9798 | 7.5 | Optionsbleed |
| Apache HTTP 2.4.49 | CVE-2021-41773 | 7.5 | Path traversal |
| Apache Tomcat (AJP) | CVE-2020-1938 | 9.8 | Ghostcat |
| MySQL 5.1–5.5.23 | CVE-2012-2122 | 7.5 | Auth bypass |
| PostgreSQL 8.3–11.2 | CVE-2019-9193 | 9.0 | COPY PROGRAM RCE |
| Java RMI ≤ 1.6.27 | CVE-2011-3521 | 10.0 | Deserialization RCE |
| UnrealIRCd 3.2.8.1 | CVE-2010-2075 | 10.0 | Backdoor |
| distccd | CVE-2004-2687 | 9.3 | Arbitrary command exec |
| NFS (no_root_squash) | CVE-2019-12255 | 9.8 | Root file access |
| OpenSSH 8.5p1–9.7p1 | CVE-2024-6387 | 8.1 | regreSSHion |
| Windows SMB 1.0 | CVE-2017-0144 | 8.1 | EternalBlue |
| Windows SMB 3.1.1 | CVE-2020-0796 | 10.0 | SMBGhost |
| Windows RPC | CVE-2022-26809 | 9.8 | RCE via RPC |

### Deduplicated Reporting

The per-port CVE structure is preserved in full in JSON for downstream tooling. A deduplicated view is computed for display via `deduplicate_cve_results()`, merging duplicate CVE IDs across ports. The HTML report shows one CVE row per unique ID with a merged ports column (e.g., `139, 445`).

### Safe Exploit Validation

- Validation is **non-destructive** and **confidence-oriented** (not exploitation)
- No payload execution, no command execution on target, no shell/persistence behavior
- Uses connection/protocol checks and service-era fingerprinting only

Currently supported validators:

- `CVE-2011-2523` — vsftpd 2.3.4 backdoor pattern check
- `CVE-2004-2687` — distcc exposure check (safe protocol preamble only)
- `CVE-2007-2447` — Samba legacy username-map-script era risk check

More protocol-aware validators are planned in future releases.

---

## Installation

**Requires:** Python 3.8+

```bash
git clone https://github.com/MohmedhKA/AutoVulnScan.git
cd AutoVulnScan
pip install -r requirements.txt
```

Dependencies: `requests`, `python-dotenv`

---

## Docker

You can run AutoVulnScan in a container using the included `Dockerfile`.

### Build image

```bash
docker build -t autovulnscan .
```

### Run interactive TUI

```bash
docker run --rm -it --env-file .env -v "$(pwd)/reports:/app/reports" autovulnscan
```

PowerShell example:

```powershell
docker run --rm -it --env-file .env -v "${PWD}\reports:/app/reports" autovulnscan
```

### Network note for LAN scanning

For scanning hosts on your local network, use host networking when available:

```bash
docker run --rm -it --network host --env-file .env -v "$(pwd)/reports:/app/reports" autovulnscan
```

On Docker Desktop, host networking behavior can differ by platform/version. If needed, run with bridge networking and ensure routing/firewall rules allow access to your targets.

---

## Configuration

### CVE API Setup

The scanner uses **CIRCL CVE Search** as its primary CVE source — no API key required. If CIRCL fails (timeout, HTTP error, or empty results), the scanner automatically falls back to **VulnCheck NVD++**, which requires a free token.

**To configure the VulnCheck fallback token:**

```bash
cp .env.example .env
```

Edit `.env`:

```env
VULNCHECK_TOKEN=your_token_here
```

Obtain a free token at [vulncheck.com](https://vulncheck.com).

Token resolution order:

1. `VULNCHECK_TOKEN` from `.env` (recommended)
2. `api.txt` in the project root (deprecated — prints a migration warning)

If VulnCheck is not configured or returns an error, the scanner falls back entirely to the **internal knowledge base** (`known_cves.py`), which covers the most common vulnerable services out of the box.

---

## Usage

### Launch

```bash
python main.py
```

### TUI Flow

```
1. Welcome screen
2. Select target mode:
     a. Discover hosts on subnet  →  sweep + select from live hosts
     b. Enter target IP directly
3. Set port range and stealth profile
4. Pipeline runs phase by phase with live output
5. Results dashboard
6. Save HTML / JSON report
```

### Keyboard Controls

| Key        | Action              |
|------------|---------------------|
| `↑` / `↓` | Navigate menu       |
| `Enter`    | Confirm / select    |
| `ESC`      | Go back             |

---

## Running Modules Directly

Each module can be invoked standalone for testing:

```bash
# Host discovery
python scanner/network_sweep.py 192.168.1.0/24

# Port scan
python scanner/port_scan.py 192.168.1.10 1 1024

# Service identification
python scanner/service_id.py 192.168.1.10 135 139 445

# OS detection
python scanner/os_detect.py 192.168.1.10

# NVD keyword lookup
python cve_lookup/nvd_api.py "OpenSSH 8.2"

# CVE matching from synthetic service map
python cve_lookup/cve_match.py 192.168.1.10 445:SMB_3.1.1 135:Microsoft_Windows_RPC
```

---

## Report Output

| File | Contents |
|------|----------|
| `scan_<target>_<timestamp>.json` | Full per-port data — services, CVEs, OS info, validation |
| `scan_<target>_<timestamp>.html` | Deduplicated CVE table, optimized for readability |

---

## Roadmap / Future Work

- Add more protocol-aware non-destructive validators for additional services/CVEs
- Improve OS and service fingerprint depth (while preserving stealth defaults)
- Expand curated CVE coverage for services with noisy public metadata
- Enhance confidence scoring and prioritization for remediation workflows

---

## Project Structure

```
AutoVulnScan/
├── Dockerfile                # Container runtime definition
├── .dockerignore             # Keeps secrets/cache/reports out of build context
├── main.py                   # TUI application entry point
├── config.py                 # Stealth profiles, settings, API key loader
├── assets/
│   └── Logo.png              # Project logo
├── scanner/
│   ├── network_sweep.py      # TCP-based host discovery
│   ├── port_scan.py          # Stealth port scanner
│   ├── service_id.py         # Protocol-aware banner grabbing + MySQL/RFB/Tomcat detection
│   └── os_detect.py          # SMB OS fingerprinting
├── cve_lookup/
│   ├── nvd_api.py            # CIRCL primary + VulnCheck NVD++ fallback client
│   ├── cve_match.py          # Multi-strategy CVE matching with version overrides
│   ├── cpe_filter.py         # CPE-based relevance filtering
│   └── known_cves.py         # Internal curated CVE knowledge base
├── exploits/
│   └── validator.py          # Non-destructive exploit validators
├── report/
│   └── generate.py           # HTML + JSON report generator
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Security Notes

Never commit sensitive runtime files. The `.gitignore` is preconfigured to exclude:

```
.env
api.txt
cve_cache.json
scan_*.html
scan_*.json
```

---

## Disclaimer

AutoVulnScan is built for **educational purposes and authorized security assessments only**. Scanning systems without explicit permission is illegal. Use responsibly and only on infrastructure you own or have written authorization to test.
