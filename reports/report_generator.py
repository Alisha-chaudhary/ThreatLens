import os
from datetime import datetime

def generate_report(
    target     : str,
    osint      : dict,
    scan       : dict,
    misconfig  : dict,
    headers    : dict,
    dns_whois  : dict,
    fingerprint: dict,
    cve_results: dict,
    risk       : dict
    ) -> None:
    
    """
    Generates a professional HTML report from all scan results.
    Saves to output/report.html
    """
    os.makedirs("output", exist_ok=True) 
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_colour = {
        "Critical": "#c0392b",
        "High"    : "#e67e22",
        "Medium"  : "#f1c40f",
        "Low"     : "#27ae60",
        "Info"    : "#2980b9",
    }

    # ── Build findings rows ──────────────────────────────────────────────────
    findings_rows = ""
    for f in risk.get("findings", []):
        sev   = f.get("severity", "Info")
        color = severity_colour.get(sev, "#888")
        findings_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td>{f.get('title', '')}</td>
            <td>{f.get('source', '')}</td>
            <td>{f.get('recommendation', '')}</td>
        </tr>"""

    # ── Build OSINT section ──────────────────────────────────────────────────
    emails_list     = "".join(
        f"<li>{e}</li>" for e in osint.get("emails", [])
    ) or "<li>None found</li>"

    subdomains_list = "".join(
        f"<li>{s}</li>" for s in osint.get("subdomains", [])
    ) or "<li>None found</li>"

    # ── Build open ports table ───────────────────────────────────────────────
    ports_rows = ""
    for p in scan.get("open_ports", []):
        ports_rows += f"""
        <tr>
            <td>{p['port']}</td>
            <td>{p['protocol']}</td>
            <td>{p['service']}</td>
            <td>{p.get('version', '') or p.get('product', '') or '—'}</td>
        </tr>"""

    # ── Score colour ─────────────────────────────────────────────────────────
    score       = risk.get("score", 0)
    score_color = severity_colour.get(risk.get("overall_severity", "Low"), "#888")
    counts      = risk.get("severity_counts", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatLens Report — {target}</title>
    <style>
        body        {{ font-family: Arial, sans-serif; background: #0f0f0f;
                       color: #e0e0e0; margin: 0; padding: 0; }}
        .container  {{ max-width: 960px; margin: auto; padding: 40px 20px; }}
        h1          {{ color: #00ff88; letter-spacing: 2px; }}
        h2          {{ color: #00ccff; border-bottom: 1px solid #333;
                       padding-bottom: 6px; margin-top: 40px; }}
        .meta       {{ color: #888; font-size: 0.9em; margin-bottom: 30px; }}
        .score-box  {{ display: inline-block; padding: 16px 32px;
                       border-radius: 8px; font-size: 2.5em; font-weight: bold;
                       background: #1a1a1a; border: 2px solid {score_color};
                       color: {score_color}; }}
        .severity-summary {{ display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }}
        .sev-pill   {{ padding: 8px 18px; border-radius: 20px;
                       font-weight: bold; font-size: 0.9em; }}
        table       {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th          {{ background: #1a1a1a; color: #00ccff;
                       padding: 10px; text-align: left; }}
        td          {{ padding: 10px; border-bottom: 1px solid #1e1e1e;
                       vertical-align: top; }}
        tr:hover td {{ background: #151515; }}
        .badge      {{ padding: 3px 10px; border-radius: 12px;
                       color: #fff; font-size: 0.8em; font-weight: bold; }}
        ul          {{ padding-left: 20px; line-height: 1.8; }}
        .footer     {{ color: #555; font-size: 0.8em;
                       text-align: center; margin-top: 60px; }}
    </style>
</head>
<body>
<div class="container">

    <h1>&#x1F4CB; ThreatLens Security Report</h1>
    <div class="meta">
        Target: <strong>{target}</strong> &nbsp;|&nbsp;
        Generated: {timestamp}
    </div>

    <h2>Overall Risk Score</h2>
    <div class="score-box">{score} / 100</div>
    <p style="color:{score_color}; font-size:1.2em; margin-top:10px;">
        <strong>{risk.get('overall_severity','—')}</strong>
    </p>

    <div class="severity-summary">
        <span class="sev-pill" style="background:#c0392b">
            Critical: {counts.get('Critical',0)}
        </span>
        <span class="sev-pill" style="background:#e67e22">
            High: {counts.get('High',0)}
        </span>
        <span class="sev-pill" style="background:#b7950b; color:#000">
            Medium: {counts.get('Medium',0)}
        </span>
        <span class="sev-pill" style="background:#27ae60">
            Low: {counts.get('Low',0)}
        </span>
    </div>

    <h2>Findings & Recommendations</h2>
    <table>
        <tr>
            <th>Severity</th><th>Issue</th>
            <th>Source</th><th>Recommendation</th>
        </tr>
        {findings_rows if findings_rows else
         '<tr><td colspan="4">No findings detected.</td></tr>'}
    </table>

    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th><th>Protocol</th>
            <th>Service</th><th>Version</th>
        </tr>
        {ports_rows if ports_rows else
         '<tr><td colspan="4">No open ports detected.</td></tr>'}
    </table>

    <h2>OSINT Findings</h2>
    <p><strong>Emails found ({osint.get('email_count',0)}):</strong></p>
    <ul>{emails_list}</ul>
    <p><strong>Subdomains found ({osint.get('subdomain_count',0)}):</strong></p>
    <ul>{subdomains_list}</ul>

    <h2>DNS & Email Security</h2>
    <table>
        <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
        <tr>
            <td>SPF</td>
            <td>{'✔ Present' if dns_whois.get('spf',{}).get('present')
                 else '✘ Missing'}</td>
            <td>{dns_whois.get('spf',{}).get('record','—')}</td>
        </tr>
        <tr>
            <td>DMARC</td>
            <td>{'✔ Present' if dns_whois.get('dmarc',{}).get('present')
                 else '✘ Missing'}</td>
            <td>{dns_whois.get('dmarc',{}).get('record','—')}</td>
        </tr>
        <tr>
            <td>DKIM</td>
            <td>{'✔ Found' if dns_whois.get('dkim',{}).get('present')
                 else '✘ Not found'}</td>
            <td>{dns_whois.get('dkim',{}).get('selector','—')}</td>
        </tr>
        <tr>
            <td>Domain age</td>
            <td>{dns_whois.get('whois',{}).get('age_days','—')} days</td>
            <td>Registrar:
                {dns_whois.get('whois',{}).get('registrar','—')}</td>
        </tr>
    </table>

    <h2>Technology Fingerprint</h2>
    <table>
        <tr><th>Name</th><th>Type</th><th>Severity</th><th>Note</th></tr>
        {''.join(
            f"<tr><td>{d['name']}</td><td>{d['type']}</td>"
            f"<td><span class='badge' style='background:"
            f"{severity_colour.get(d['severity'],'#888')}'>"
            f"{d['severity']}</span></td>"
            f"<td>{d['note']}</td></tr>"
            for d in fingerprint.get('detected', [])
        ) or '<tr><td colspan="4">No technologies detected.</td></tr>'}
    </table>
    <p><strong>Server:</strong>
       {fingerprint.get('server', {}).get('name', '—')}
       {fingerprint.get('server', {}).get('version') or ''}
    </p>

    <h2>CVE Findings
        ({cve_results.get('cve_count', 0)} total)</h2>
    <table>
        <tr>
            <th>CVE ID</th><th>Severity</th>
            <th>CVSS</th><th>Affected</th><th>Details</th>
        </tr>
        {''.join(
            f"<tr>"
            f"<td><a href='{c['url']}' style='color:#00ccff'>"
            f"{c['cve_id']}</a></td>"
            f"<td><span class='badge' style='background:"
            f"{severity_colour.get(c['severity'],'#888')}'>"
            f"{c['severity']}</span></td>"
            f"<td>{c['cvss_score']}</td>"
            f"<td>{c['keyword']}</td>"
            f"<td>{c['description'][:100]}...</td>"
            f"</tr>"
            for c in cve_results.get('cves', [])
        ) or '<tr><td colspan="5">No CVEs found.</td></tr>'}
    </table>

    <h2>Security Headers — Grade: {headers.get('grade', 'N/A')}</h2>
    <table>
        <tr>
            <th>Type</th><th>Header</th>
            <th>Severity</th><th>Recommendation</th>
        </tr>
        {''.join(
            f"<tr><td>{i['type']}</td>"
            f"<td>{i['header']}</td>"
            f"<td><span class='badge' style='background:"
            f"{severity_colour.get(i['severity'],'#888')}'>"
            f"{i['severity']}</span></td>"
            f"<td>{i['recommendation']}</td></tr>"
            for i in headers.get('issues', [])
        ) or '<tr><td colspan="4">No header issues detected.</td></tr>'}
    </table>

    <h2>SSL / TLS Issues</h2>
    <table>
        <tr><th>Severity</th><th>Issue</th></tr>
        {''.join(
            f"<tr><td><span class='badge' style='background:"
            f"{severity_colour.get(i['severity'],'#888')}'>"
            f"{i['severity']}</span></td>"
            f"<td>{i['description']}</td></tr>"
            for i in misconfig.get('issues', [])
        ) or '<tr><td colspan="2">No SSL issues detected.</td></tr>'}
    </table>

    <div class="footer">Generated by ThreatLens &mdash; For authorised use only</div>
</div>
</body>
</html>"""

    with open("output/report.html", "w") as f:
        f.write(html)
