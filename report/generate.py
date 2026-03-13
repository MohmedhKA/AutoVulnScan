"""
generate.py - Professional HTML + JSON Report Generator
========================================================
This module takes all scan results and produces:
  1. A JSON file with raw structured data
  2. A beautiful dark-themed HTML report with:
     - Executive summary dashboard
     - Severity breakdown with color coding
     - Per-port findings with service details
     - CVE table with CVSS scores
     - Validation results

The HTML uses ONLY inline CSS (no external files needed).
The report is self-contained — open it in any browser.

USAGE (standalone):
    Typically called by main.py, but can be tested with sample data.
"""

import json         # For JSON report generation
import html         # For escaping HTML entities (security)
import os           # For file path operations
import sys          # For standalone mode
from datetime import datetime   # For timestamps


# ============================================================
# JSON REPORT
# ============================================================

def generate_json_report(scan_data, output_path):
    """
    Write all scan results to a JSON file.

    The JSON file contains the raw structured data from every
    phase of the scan. This is useful for:
    - Importing into other tools
    - Scripted analysis
    - Historical comparison

    Args:
        scan_data (dict):   All scan results (see main.py for structure)
        output_path (str):  Full path to write the JSON file

    Returns:
        str: Path to the written file
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2, default=str)
        print(f"  [+] JSON report saved: {output_path}")
        return output_path
    except IOError as e:
        print(f"  [!] Failed to write JSON report: {e}")
        return None


# ============================================================
# HTML REPORT - STYLES
# ============================================================

def _get_css():
    """Return the inline CSS for the HTML report (dark theme)."""
    return """
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: #0a0e17;
            color: #c9d1d9;
            font-family: 'Segoe UI', 'Cascadia Code', 'Consolas', monospace;
            line-height: 1.6;
            padding: 40px;
        }

        .container { max-width: 1100px; margin: 0 auto; }

        /* ---- HEADER ---- */
        .header {
            text-align: center;
            padding: 40px 20px;
            margin-bottom: 30px;
            border: 1px solid #1a2332;
            border-radius: 12px;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
        }
        .header h1 {
            font-size: 28px;
            color: #00d4aa;
            letter-spacing: 6px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .header .subtitle {
            color: #555e6b;
            font-size: 13px;
            letter-spacing: 2px;
        }
        .header .meta {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 40px;
            font-size: 13px;
            color: #6b7688;
        }
        .meta-item span { color: #00d4aa; }

        /* ---- SUMMARY CARDS ---- */
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        .card {
            background: #161b22;
            border: 1px solid #1a2332;
            border-radius: 10px;
            padding: 24px 20px;
            text-align: center;
        }
        .card .number {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 6px;
        }
        .card .label {
            font-size: 12px;
            color: #555e6b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .card.critical .number { color: #ff4757; }
        .card.high .number { color: #ff8c42; }
        .card.medium .number { color: #ffd93d; }
        .card.ports .number { color: #00d4aa; }
        .card.services .number { color: #4da6ff; }
        .card.confirmed .number { color: #ff4757; text-shadow: 0 0 20px rgba(255,71,87,0.3); }

        /* ---- SECTION ---- */
        .section {
            background: #161b22;
            border: 1px solid #1a2332;
            border-radius: 10px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .section-header {
            padding: 16px 24px;
            background: #1a2332;
            border-bottom: 1px solid #252d3a;
            font-size: 15px;
            font-weight: 600;
            color: #e6edf3;
            letter-spacing: 1px;
        }
        .section-body { padding: 20px 24px; }

        /* ---- TABLES ---- */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th {
            text-align: left;
            padding: 10px 14px;
            color: #555e6b;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 1px;
            border-bottom: 1px solid #252d3a;
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid #1a2332;
            vertical-align: top;
        }
        tr:hover { background: #1a2332; }

        /* ---- SEVERITY BADGES ---- */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .badge.critical { background: rgba(255,71,87,0.15); color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }
        .badge.high     { background: rgba(255,140,66,0.15); color: #ff8c42; border: 1px solid rgba(255,140,66,0.3); }
        .badge.medium   { background: rgba(255,217,61,0.15); color: #ffd93d; border: 1px solid rgba(255,217,61,0.3); }
        .badge.low      { background: rgba(77,166,255,0.15); color: #4da6ff; border: 1px solid rgba(77,166,255,0.3); }
        .badge.confirmed { background: rgba(255,71,87,0.2); color: #ff4757; border: 1px solid rgba(255,71,87,0.4); }
        .badge.not-confirmed { background: rgba(85,94,107,0.2); color: #6b7688; border: 1px solid rgba(85,94,107,0.3); }

        .cvss-score {
            font-weight: 700;
            font-size: 14px;
        }
        .cvss-critical { color: #ff4757; }
        .cvss-high { color: #ff8c42; }
        .cvss-medium { color: #ffd93d; }
        .cvss-low { color: #4da6ff; }

        .port-num {
            color: #00d4aa;
            font-weight: 600;
            font-size: 14px;
        }
        .service-name { color: #4da6ff; }
        .cve-id { color: #c9a0ff; font-weight: 600; }
        .description { color: #6b7688; font-size: 12px; line-height: 1.5; }

        /* ---- FOOTER ---- */
        .footer {
            text-align: center;
            padding: 30px;
            color: #333d4d;
            font-size: 12px;
            letter-spacing: 1px;
        }
        .footer a { color: #00d4aa; text-decoration: none; }
    </style>
    """


# ============================================================
# HTML REPORT - BUILDER
# ============================================================

def _severity_badge(severity):
    """Create an HTML severity badge."""
    severity_lower = severity.lower() if severity else "unknown"
    return f'<span class="badge {severity_lower}">{html.escape(severity)}</span>'


def _cvss_class(score):
    """Return CSS class for a CVSS score."""
    if score >= 9.0:
        return "cvss-critical"
    elif score >= 7.0:
        return "cvss-high"
    elif score >= 4.0:
        return "cvss-medium"
    return "cvss-low"


def _status_badge(status):
    """Create an HTML status badge for validation results."""
    if status == "CONFIRMED":
        return '<span class="badge confirmed">⚠ CONFIRMED</span>'
    return '<span class="badge not-confirmed">NOT CONFIRMED</span>'


def generate_html_report(scan_data, output_path):
    """
    Generate a professional dark-themed HTML vulnerability report.

    The report includes:
    - Executive summary with severity statistics
    - Open ports table with services
    - CVE findings with CVSS scores and descriptions
    - Exploit validation results
    - Scan metadata (target, time, stealth level)

    Args:
        scan_data (dict):  All scan results
        output_path (str): Full path to write the HTML file

    Returns:
        str: Path to the written file
    """
    # Extract data from scan_data with safe defaults
    target = scan_data.get("target", "Unknown")
    scan_time = scan_data.get("scan_time", "Unknown")
    stealth = scan_data.get("stealth_level", "Unknown")
    duration = scan_data.get("duration", "Unknown")
    open_ports = scan_data.get("open_ports", [])
    services = scan_data.get("services", {})
    cve_results = scan_data.get("cve_results", {})
    validation = scan_data.get("validation_results", {})
    os_info = scan_data.get("os_info", {})

    # Build OS display string from os_info
    os_display = "Unknown"
    if os_info:
        os_family = os_info.get("os_family", "unknown")
        os_version = os_info.get("os_version", "")
        smb_dialect = os_info.get("smb_dialect_name", "")
        if os_version:
            os_display = os_version
        elif os_family != "unknown":
            os_display = os_family.capitalize()
        if smb_dialect:
            os_display += f" ({smb_dialect})"

    # Count statistics for summary cards
    total_ports = len(open_ports)
    total_services = len([s for s in services.values() if s != "Unknown"])

    # Count CVEs by severity
    all_cves = []
    for port_data in cve_results.values():
        if isinstance(port_data, dict):
            for cve in port_data.get("cves", []):
                all_cves.append(cve)

    critical_count = len([c for c in all_cves if c.get("severity") == "CRITICAL"])
    high_count = len([c for c in all_cves if c.get("severity") == "HIGH"])
    medium_count = len([c for c in all_cves
                        if c.get("severity") in ("MEDIUM", "MODERATE")])
    confirmed_count = len([v for v in validation.values()
                           if v.get("status") == "CONFIRMED"])

    # ---- BUILD HTML ----
    parts = []

    # Document head
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoVulnScan Report - {html.escape(target)}</title>
    {_get_css()}
</head>
<body>
<div class="container">
""")

    # Header
    parts.append(f"""
    <div class="header">
        <h1>AutoVulnScan</h1>
        <div class="subtitle">AUTOMATED VULNERABILITY ASSESSMENT REPORT</div>
        <div class="meta">
            <div class="meta-item">TARGET <span>{html.escape(target)}</span></div>
            <div class="meta-item">OS <span>{html.escape(os_display)}</span></div>
            <div class="meta-item">DATE <span>{html.escape(str(scan_time))}</span></div>
            <div class="meta-item">STEALTH <span>{html.escape(str(stealth).upper())}</span></div>
            <div class="meta-item">DURATION <span>{html.escape(str(duration))}</span></div>
        </div>
    </div>
""")

    # Summary cards
    parts.append(f"""
    <div class="summary">
        <div class="card ports">
            <div class="number">{total_ports}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="card services">
            <div class="number">{total_services}</div>
            <div class="label">Services ID'd</div>
        </div>
        <div class="card critical">
            <div class="number">{critical_count}</div>
            <div class="label">Critical CVEs</div>
        </div>
        <div class="card high">
            <div class="number">{high_count}</div>
            <div class="label">High CVEs</div>
        </div>
        <div class="card confirmed">
            <div class="number">{confirmed_count}</div>
            <div class="label">Confirmed</div>
        </div>
    </div>
""")

    # Open Ports & Services table
    parts.append("""
    <div class="section">
        <div class="section-header">📡 OPEN PORTS & SERVICES</div>
        <div class="section-body">
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Response</th>
                </tr>
""")

    for port_info in open_ports:
        # port_info can be a tuple (port, response_ms) or just port number
        if isinstance(port_info, (list, tuple)):
            port_num = port_info[0]
            resp_time = f"{port_info[1]} ms" if len(port_info) > 1 else "—"
        else:
            port_num = port_info
            resp_time = "—"

        service_name = services.get(port_num, services.get(str(port_num), "Unknown"))

        parts.append(f"""
                <tr>
                    <td><span class="port-num">{port_num}</span></td>
                    <td><span class="service-name">{html.escape(str(service_name))}</span></td>
                    <td>{html.escape(str(resp_time))}</td>
                </tr>""")

    parts.append("""
            </table>
        </div>
    </div>
""")

    # CVE Findings table
    if all_cves:
        parts.append("""
    <div class="section">
        <div class="section-header">🔥 CVE FINDINGS</div>
        <div class="section-body">
            <table>
                <tr>
                    <th>Port</th>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Validation</th>
                    <th>Description</th>
                </tr>
""")

        for port_key in sorted(cve_results.keys(), key=lambda x: int(x)):
            port_data = cve_results[port_key]
            if not isinstance(port_data, dict):
                continue

            # Determine data source for this port
            is_internal_kb = port_data.get("using_internal_kb", False)
            query_method = port_data.get("query_method", "keyword")
            source_label = "Internal KB" if is_internal_kb else (
                "NVD (CPE)" if query_method == "cpe" else "NVD"
            )

            for cve in port_data.get("cves", []):
                cve_id = cve.get("id", "Unknown")
                cvss = cve.get("cvss", 0)
                severity = cve.get("severity", "UNKNOWN")
                desc = cve.get("description", "No description")

                # Check if this CVE was validated
                val_status = "—"
                if cve_id in validation:
                    val_status = _status_badge(validation[cve_id].get("status", ""))

                # Truncate description for display
                if len(desc) > 150:
                    desc = desc[:150] + "..."

                # Use per-CVE source if available, else port-level source
                cve_source = cve.get("source", source_label)

                parts.append(f"""
                <tr>
                    <td><span class="port-num">{port_key}</span></td>
                    <td><span class="cve-id">{html.escape(cve_id)}</span></td>
                    <td><span class="cvss-score {_cvss_class(cvss)}">{cvss}</span></td>
                    <td>{_severity_badge(severity)}</td>
                    <td><span class="description">{html.escape(str(cve_source))}</span></td>
                    <td>{val_status}</td>
                    <td><span class="description">{html.escape(desc)}</span></td>
                </tr>""")

        parts.append("""
            </table>
        </div>
    </div>
""")

    # Validation Results section
    if validation:
        parts.append("""
    <div class="section">
        <div class="section-header">🎯 EXPLOIT VALIDATION</div>
        <div class="section-body">
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>Service</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
""")

        for cve_id, val_data in validation.items():
            status = val_data.get("status", "UNKNOWN")
            details = val_data.get("details", "")
            service = val_data.get("service", "N/A")
            port = val_data.get("port", "N/A")

            if len(details) > 120:
                details = details[:120] + "..."

            parts.append(f"""
                <tr>
                    <td><span class="cve-id">{html.escape(cve_id)}</span></td>
                    <td><span class="service-name">{html.escape(str(service))}</span></td>
                    <td><span class="port-num">{port}</span></td>
                    <td>{_status_badge(status)}</td>
                    <td><span class="description">{html.escape(details)}</span></td>
                </tr>""")

        parts.append("""
            </table>
        </div>
    </div>
""")

    # Footer
    parts.append(f"""
    <div class="footer">
        Generated by <a href="#">AutoVulnScan</a> &mdash;
        Educational Vulnerability Scanner &mdash;
        {html.escape(str(scan_time))}
    </div>

</div>
</body>
</html>
""")

    # Write the file
    try:
        html_content = "".join(parts)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"  [+] HTML report saved: {output_path}")
        return output_path
    except IOError as e:
        print(f"  [!] Failed to write HTML report: {e}")
        return None


# ============================================================
# MAIN REPORT GENERATOR
# ============================================================

def generate_report(scan_data, output_dir="."):
    """
    Generate both JSON and HTML reports.

    This is the main entry point for report generation.
    It creates both report files in the specified directory.

    Args:
        scan_data (dict):   All scan results from the scan pipeline
        output_dir (str):   Directory to save reports in

    Returns:
        dict: {"json": json_path, "html": html_path}
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = scan_data.get("target", "unknown").replace(".", "_")

    json_filename = f"scan_{target_safe}_{timestamp}.json"
    html_filename = f"scan_{target_safe}_{timestamp}.html"

    json_path = os.path.join(output_dir, json_filename)
    html_path = os.path.join(output_dir, html_filename)

    print(f"\n[*] Generating reports...")

    json_result = generate_json_report(scan_data, json_path)
    html_result = generate_html_report(scan_data, html_path)

    return {
        "json": json_result,
        "html": html_result,
    }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    """Generate a sample report for testing the template."""

    sample_data = {
        "target": "192.168.100.50",
        "scan_time": datetime.now().isoformat(),
        "stealth_level": "quiet",
        "duration": "45.2s",
        "open_ports": [(21, 12.5), (22, 8.3), (80, 5.1), (445, 15.7)],
        "services": {
            21: "vsftpd 2.3.4",
            22: "OpenSSH 4.7p1",
            80: "Apache 2.2.8",
            445: "Samba 3.0.20",
        },
        "cve_results": {
            21: {
                "service": "vsftpd 2.3.4",
                "cves": [{
                    "id": "CVE-2011-2523",
                    "cvss": 9.8,
                    "severity": "CRITICAL",
                    "description": "vsftpd 2.3.4 downloaded between 20110630 "
                                   "and 20110703 contains a backdoor which "
                                   "opens a shell on port 6200/tcp."
                }],
                "total_found": 1,
                "high_critical": 1,
            },
        },
        "validation_results": {
            "CVE-2011-2523": {
                "cve": "CVE-2011-2523",
                "service": "vsftpd 2.3.4",
                "port": 21,
                "status": "CONFIRMED",
                "details": "vsftpd 2.3.4 backdoor is active. "
                           "Port 6200 opened after trigger."
            }
        },
    }

    result = generate_report(sample_data, ".")
    print(f"\nReports generated: {result}")
