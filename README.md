# AutoVulnScan

**Automated Vulnerability Scanner** — A pure Python CLI tool that automates network vulnerability assessment. Built as an educational portfolio project to replicate and extend manual penetration testing steps performed in a GNS3 lab environment.

---

## Overview

AutoVulnScan automates the following workflow end-to-end:

```
Discover Hosts → Scan Ports → Identify Services → Look Up CVEs → Validate Exploits → Generate Report
```

Everything is implemented in pure Python — no Nmap, no Metasploit, no external CLI tools. Every module teaches the underlying mechanics: raw sockets, threading, HTTP APIs, and exploit triggering.

**Lab environment this was built and tested against:**

```
Kali Linux (192.168.100.2)
    └── GNS3 Switch
            └── Metasploitable2 (192.168.100.50)
```

---

## Features

### Stealth-First Design
Every phase operates in stealth mode by default:
- **Randomized port and host order** — avoids sequential sweep detection
- **No ICMP ping** — host discovery uses TCP connect probes (less noisy)
- **Configurable jitter** — random delays between probes break timing patterns
- **Passive-first banner grabbing** — just listens before sending any data
- **Clean socket teardown** — `shutdown()` before `close()` on every connection

### Three Stealth Profiles

| Profile | Delay | Jitter | Threads | Use Case |
|---------|-------|--------|---------|----------|
| ⚡ Normal | 0ms | 0ms | 50 | Fast scan, IDS will see it |
| 🤫 Quiet | 50ms | 50ms | 25 | Balanced — default |
| 👻 Ghost | 200ms | 150ms | 10 | Maximum stealth, slow |

### Scan Pipeline (6 Phases)

**Phase 1 — TCP Port Scanner** (`scanner/port_scan.py`)
- Raw socket TCP connect scan via `socket.connect_ex()`
- Up to 50 concurrent threads with a semaphore limiter
- Ports scanned in randomized order
- Records response time per open port

**Phase 2 — Service Identification** (`scanner/service_id.py`)
- Connects to each open port and reads the service banner
- Two-phase approach: passive listen first, minimal probe second
- Protocol-aware probes (HTTP HEAD, raw CRLF for others)
- Identifies 30+ services with version extraction (e.g. `vsftpd 2.3.4`, `Apache 2.2.8`)

**Phase 2 — Network Discovery** (`scanner/network_sweep.py`)
- Finds live hosts on a subnet using TCP connect probes
- Probes 4 random ports from a list of 12 common ones
- A "connection refused" response counts as alive — no ICMP needed
- Input: CIDR notation (e.g. `192.168.100.0/24`)

**Phase 3 — CVE Lookup** (`cve_lookup/nvd_api.py` + `cve_lookup/cve_match.py`)
- Queries the NIST NVD REST API v2.0 for CVEs by service string
- Caches results locally in `cve_cache.json` (no redundant requests)
- Filters to HIGH and CRITICAL severity only (CVSS ≥ 7.0)
- 6-second delay between requests to respect NVD rate limits
- Supports CVSS v3.1, v3.0, and v2.0

**Phase 4 — Exploit Validation** (`exploits/validator.py`)
- Non-destructive confirmation of specific CVEs
- Currently supports: **CVE-2011-2523** (vsftpd 2.3.4 backdoor)
  - Sends `USER test:)` trigger → checks if port 6200 opens
  - **Never executes commands** — connection check only
- Extensible: add new validators to the `VALIDATORS` registry

**Phase 5 — Report Generation** (`report/generate.py`)
- Outputs `scan_<target>_<timestamp>.html` and `.json`
- HTML: dark-themed professional report with severity dashboard, CVE table, validation results
- JSON: raw structured data for scripting or tool integration

**Phase 6 — Interactive CLI** (`main.py`)
- Full TUI with arrow-key menu navigation
- Color-coded terminal output with box-drawing borders
- Also supports direct CLI flags for scripted use

---

## Installation

**Requirements:** Python 3.8+

```bash
# Clone or copy the project
cd AutoVulnScan

# Install dependencies (only 2 external packages)
pip install requests python-dotenv
```

---

## Configuration

### API Key Setup (Required for CVE lookups)

1. Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
2. Copy the example env file:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` and add your key:
   ```
   NVD_API_KEY=your_actual_key_here
   ```

> **Without an API key** the scanner still works but NVD rate limits you to 5 requests per 30 seconds instead of 50.

---

## Usage

### Interactive Mode (default)

```bash
python main.py
```

Launches a full TUI. Navigate with **arrow keys**, confirm with **Enter**, go back with **ESC**.

**Menu options:**
- Full Automated Scan — runs all phases end-to-end
- Network Discovery — find live hosts on a subnet
- Port Scan Only — scan ports on a single target
- Service Identification — grab banners from specific ports
- CVE Lookup — look up CVEs for a service string
- Exploit Validation — run non-destructive CVE validators
- Settings — configure stealth, threads, timeout, output dir

### CLI Mode (flags)

Run with arguments to skip the interactive menus:

```bash
# Full pipeline — discover hosts first, then scan the target
python main.py --subnet 192.168.100.0/24 --target 192.168.100.50 --ports 1-1024

# Direct scan — skip discovery, known target
python main.py --target 192.168.100.50 --ports 1-1024

# Full pipeline with ghost stealth
python main.py --subnet 192.168.100.0/24 --target 192.168.100.50 --stealth ghost

# Discovery only — find live hosts and exit
python main.py --discover 192.168.100.0/24

# Save reports to a specific directory
python main.py --target 192.168.100.50 --output ./reports
```

### CLI Flags Reference

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | — | Target IP address to scan (required for full scan) |
| `--subnet` | — | — | CIDR subnet for Phase 0 host discovery before scanning |
| `--ports` | `-p` | `1-1024` | Port range in `start-end` format |
| `--discover` | `-d` | — | Discovery only — find live hosts and exit |
| `--stealth` | `-s` | `quiet` | Stealth level: `normal`, `quiet`, `ghost` |
| `--threads` | — | Profile default | Override max concurrent threads |
| `--output` | `-o` | `.` (current dir) | Directory to save report files |

### Running Individual Modules

Each module works standalone for testing:

```bash
# Port scan
python scanner/port_scan.py 192.168.100.50 1 1024

# Network discovery
python scanner/network_sweep.py 192.168.100.0/24

# Service identification
python scanner/service_id.py 192.168.100.50 21 22 80 445

# CVE lookup
python cve_lookup/nvd_api.py "vsftpd 2.3.4"

# CVE match (port:service pairs)
python cve_lookup/cve_match.py 192.168.100.50 21:vsftpd_2.3.4 80:Apache_2.2.8

# Exploit validation
python exploits/validator.py 192.168.100.50
```

---

## Project Structure

```
AutoVulnScan/
├── main.py                  ← Interactive CLI + argparse entry point
├── config.py                ← Global settings, stealth profiles
│
├── scanner/
│   ├── port_scan.py         ← Threaded TCP connect scan
│   ├── service_id.py        ← Banner grabbing + service identification
│   └── network_sweep.py     ← TCP-based host discovery (no ICMP)
│
├── cve_lookup/
│   ├── nvd_api.py           ← NIST NVD API v2.0 client + local cache
│   └── cve_match.py         ← Service → CVE matching with CVSS filter
│
├── exploits/
│   └── validator.py         ← Non-destructive CVE confirmation
│
├── report/
│   └── generate.py          ← HTML + JSON report generation
│
├── .env                     ← Your API key (NOT committed to Git)
├── .env.example             ← Template — copy this to .env
├── .gitignore               ← Excludes .env, api.txt, reports, cache
├── cve_cache.json           ← Auto-generated CVE cache (gitignored)
└── requirements.txt         ← requests, python-dotenv
```

---

## Security Notes

Before pushing to GitHub:

| File | Status | Why |
|------|--------|-----|
| `.env` | ✅ Gitignored | Contains your NVD API key |
| `api.txt` | ✅ Gitignored | Legacy key file — do not commit |
| `cve_cache.json` | ✅ Gitignored | Auto-rebuilt, no need to share |
| `scan_*.html` | ✅ Gitignored | Contains scan results of real targets |
| `scan_*.json` | ✅ Gitignored | Contains scan results of real targets |
| `.env.example` | ✅ Committed | Template without real key — safe to share |

The API key is loaded from the environment variable `NVD_API_KEY` (set via `.env`). It is **never** hardcoded in any source file.

---

## Disclaimer

This tool is built for **educational and academic purposes only**. Run it exclusively against systems you own or have explicit written permission to test. Unauthorized scanning of systems is illegal in most jurisdictions.

The exploit validator (`exploits/validator.py`) performs **connection-only checks** — it never executes commands, uploads payloads, or modifies anything on the target.
