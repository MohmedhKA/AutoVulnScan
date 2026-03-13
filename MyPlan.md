PROJECT BRIEF: AutoVulnScan
================================
I am a pre-final year CS student building a cybersecurity portfolio 
project. I am a BEGINNER in Python - I understand variables, loops, 
and functions at a basic level but have never built a real project.

BACKGROUND (what I already know practically):
- I have run nmap manually against Metasploitable2 and found open ports
- I have used Metasploit to exploit CVE-2011-2523 (vsftpd backdoor) 
  and got root shell
- I understand what open ports, services, and CVEs mean from hands-on 
  lab experience
- My lab: Kali (192.168.100.2) → GNS3 Switch → Metasploitable2 
  (192.168.100.50)

WHAT I AM BUILDING:
AutoVulnScan - a Python CLI tool that automates what I did manually:
  1. Discover live hosts on a subnet
  2. Scan open TCP ports on the target
  3. Grab service banners (identify service name + version)
  4. Look up known CVEs for found services using NIST NVD API
  5. Validate if specific CVEs are confirmed on the target
  6. Generate an HTML + JSON report of findings

PROJECT STRUCTURE:
AutoVulnScan/
├── scanner/
│   ├── network_sweep.py    ← ICMP host discovery
│   ├── port_scan.py        ← TCP port scanner using sockets
│   └── service_id.py       ← banner grabbing per open port
├── cve_lookup/
│   ├── nvd_api.py          ← query NIST NVD REST API v2.0
│   └── cve_match.py        ← match service+version to CVEs
├── exploits/
│   └── validator.py        ← non-destructive CVE confirmation
├── report/
│   └── generate.py         ← HTML + JSON report output
├── main.py                 ← CLI entry point
├── config.py               ← settings (target IP, API key etc)
└── README.md

BUILD RULES (IMPORTANT - follow these strictly):
1. Add a clear comment on EVERY function explaining what it does
2. Add inline comments on any line that is not obvious
3. Use the SIMPLEST possible Python - no advanced tricks
4. Each module must work independently and be testable alone
5. Print progress messages so I can see what is happening live
6. Handle errors gracefully - if something fails, print WHY
7. Never use subprocess to call nmap or metasploit - 
   implement everything in pure Python so I learn the mechanics
8. Use only these libraries: socket, threading, requests, 
   json, os, sys, argparse, ipaddress, datetime, html

WE WILL BUILD IN THESE PHASES - WAIT FOR MY SIGNAL EACH PHASE:

PHASE 1 (ask me to confirm before starting):
  Build scanner/port_scan.py
  - socket.connect_ex() based TCP connect scan
  - Threading with max 50 threads
  - Input: target IP, start port, end port
  - Output: list of open ports with response time
  - Test command: python scanner/port_scan.py 192.168.100.50 1 1024

PHASE 2 (after I confirm Phase 1 works):
  Build scanner/service_id.py  
  - Connect to each open port, recv(1024) bytes
  - Decode banner, clean it up
  - Try to identify service name from banner text
  - Input: target IP, list of open ports
  - Output: dict like {21: "vsftpd 2.3.4", 80: "Apache 2.2.8"}

  Build scanner/network_sweep.py
  - subprocess ping to check if host is alive
  - Input: subnet in CIDR like "192.168.100.0/24"  
  - Output: list of live host IPs

PHASE 3 (after I confirm Phase 2 works):
  Build cve_lookup/nvd_api.py
  - Query https://services.nvd.nist.gov/rest/json/cves/2.0
  - Input: service string like "vsftpd 2.3.4"
  - Output: list of CVEs with ID, CVSS score, severity, description
  - Add 6 second sleep between requests (NVD rate limit!)
  - Cache results in a local JSON file to avoid re-requesting

  Build cve_lookup/cve_match.py
  - Input: dict of {port: "service version"} from Phase 2
  - For each service, call nvd_api
  - Filter: only keep CVEs with CVSS score 7.0 or higher
  - Output: {port: {service: [list of CVEs]}}

PHASE 4 (after I confirm Phase 3 works):
  Build exploits/validator.py
  - CVE-2011-2523 (vsftpd 2.3.4 backdoor):
    Connect to port 21, send "USER test:)\r\n" + "PASS x\r\n"
    Then try connecting to port 6200
    If port 6200 responds → print "CONFIRMED VULNERABLE"
    Do NOT execute any commands - connection check only!
  - Output: {"CVE-2011-2523": "CONFIRMED" or "NOT_CONFIRMED"}

PHASE 5 (after I confirm Phase 4 works):
  Build report/generate.py
  - Input: all results from previous phases
  - Output scan_report.json (raw data)
  - Output scan_report.html with:
    * Summary table at top
    * Per-port findings
    * CVE table: ID | Service | CVSS | Severity | Status
    * Color: red=Critical, orange=High, yellow=Medium
  - Pure Python only, no external HTML libraries

PHASE 6 (final):
  Build main.py CLI entry point
  - argparse for: --target, --ports, --output, --threads
  - Call all modules in sequence
  - Show live progress output
  - Example: python main.py --target 192.168.100.50 --ports 1-1024

START: Please acknowledge you understand the full project and then 
WAIT for me to say "START PHASE 1" before writing any code.
Just confirm you understand and give me a short summary of what 
we are building.
