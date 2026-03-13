# AutoVulnScan

**Stealth-first automated vulnerability scanner (pure Python).**

AutoVulnScan is an educational project that automates a practical vuln-assessment workflow: host discovery, port scanning, service and OS fingerprinting, CVE correlation, optional exploit validation, and report generation.

---

## Current Pipeline (latest)

```text
Optional Host Discovery
    -> Port Scan
    -> Service Identification (with protocol-aware probes)
    -> OS Detection (SMB negotiate)
    -> CVE Matching (NVD + internal KB fallback)
    -> Exploit Validation (non-destructive checks)
    -> HTML + JSON Report
```

The UI is a **page-based TUI** (arrow-key navigation), not argparse-style flags.

---

## Core Features

### 1) Stealth-first scanning

- Randomized probe/port order
- Delay + jitter controls
- Limited concurrency via profile
- Passive-first banner grabbing
- Clean socket teardown on every connection
- No ICMP requirement for discovery (TCP-based host liveness)

### 2) Stealth profiles

| Profile | Delay | Jitter | Threads | Timeout | Purpose |
|---|---:|---:|---:|---:|---|
| `normal` | 0.0s | 0.0s | 50 | 0.5s | Fast, noisier |
| `quiet` | 0.05s | 0.05s | 25 | 1.0s | Balanced |
| `ghost` | 0.2s | 0.15s | 10 | 1.5s | Maximum stealth |

### 3) Better Windows service/OS accuracy

- SMB/NetBIOS/RPC are identified with protocol-aware probing (not only text banners)
- SMB dialect extraction (e.g., `SMB 3.1.1`)
- OS detection using SMB negotiate (`scanner\os_detect.py`)
- OS generation classification (`modern` vs `legacy`)

### 4) CVE intelligence with false-positive controls

`cve_lookup\cve_match.py` uses a multi-step strategy:

1. **NVD CPE query** (most precise)
2. **NVD keyword query** fallback
3. **Internal curated CVE KB** (`known_cves.py`) when API quality is low or empty

Then it applies:

- Platform relevance filtering (`cpe_filter.py`)
- Service-topic relevance filtering (SMB/RPC topic checks)
- Version range relevance filtering (when range data exists)
- CVSS threshold (`>= 7.0`)
- **Modern patch-state skip:** CVEs marked `patched_in_modern=true` are skipped when detected OS generation is `modern`

### 5) Deduplicated reporting

- Matching remains **per-port** in JSON (`cve_results` dict by port)
- A deduplicated view is generated for display/reporting via:
  - `deduplicate_cve_results(cve_results)`
- HTML CVE section shows one CVE row with merged ports (example: `139, 445`)

### 6) Safe exploit validation

- Non-destructive validation only
- No payload execution
- Current validator includes `CVE-2011-2523` (vsftpd backdoor check pattern)

---

## Installation

**Requirements:** Python 3.8+

```bash
cd AutoVulnScan
pip install -r requirements.txt
```

Current dependencies:

- `requests`
- `python-dotenv`

---

## Configuration

### NVD API Key

Preferred setup:

```bash
cp .env.example .env
```

Then set:

```env
NVD_API_KEY=your_key_here
```

Key loading order:

1. `NVD_API_KEY` from environment / `.env`
2. `api.txt` (legacy fallback)

### NVD endpoint used

`https://services.nvd.nist.gov/rest/json/cves/2.0`

If your API key gets rejected (some keys return `403`/`404`), the code automatically retries unauthenticated mode.

---

## Usage

### Launch the TUI

```bash
python main.py
```

### TUI flow

1. Welcome screen
2. Choose target mode:
   - Discover hosts on subnet
   - Enter target IP directly
3. Set port range + stealth profile
4. Run pipeline phases
5. Review results dashboard
6. Save HTML/JSON report (optional)

### Keyboard controls

- `↑` / `↓`: navigate
- `Enter`: select
- `ESC`: back (where applicable)

---

## Running Modules Directly (for testing)

```bash
# Host discovery
python scanner/network_sweep.py 192.168.1.0/24

# Port scan
python scanner/port_scan.py 192.168.1.10 1 1024

# Service ID
python scanner/service_id.py 192.168.1.10 135 139 445

# OS detect
python scanner/os_detect.py 192.168.1.10

# NVD lookup by keyword
python cve_lookup/nvd_api.py "OpenSSH 8.2"

# CVE match from synthetic service map input
python cve_lookup/cve_match.py 192.168.1.10 445:SMB_3.1.1 135:Microsoft_Windows_RPC
```

---

## Report Output

Generated files:

- `scan_<target>_<timestamp>.json` (raw per-port results)
- `scan_<target>_<timestamp>.html` (deduplicated CVE presentation)

JSON keeps full per-port detail for tooling; HTML is optimized for readability.

---

## Project Structure

```text
AutoVulnScan/
├── main.py
├── config.py
├── scanner/
│   ├── network_sweep.py
│   ├── port_scan.py
│   ├── service_id.py
│   └── os_detect.py
├── cve_lookup/
│   ├── nvd_api.py
│   ├── cve_match.py
│   ├── cpe_filter.py
│   └── known_cves.py
├── exploits/
│   └── validator.py
├── report/
│   └── generate.py
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Security / Git Hygiene

Do **not** commit sensitive/runtime files:

- `.env`
- `api.txt`
- `cve_cache.json`
- `scan_*.html`
- `scan_*.json`

(`.gitignore` is already configured for these.)

---

## Disclaimer

For **educational and authorized** testing only. Scan systems you own or are explicitly permitted to assess.

