import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib           import colors
from reportlab.lib.styles    import ParagraphStyle
from reportlab.lib.units     import cm
from reportlab.platypus      import (
    SimpleDocTemplate, Paragraph,
    Spacer, Table, TableStyle, HRFlowable
)

C_BG       = colors.HexColor("#0f0f0f")
C_PRIMARY  = colors.HexColor("#00ff88")
C_ACCENT   = colors.HexColor("#00ccff")
C_TEXT     = colors.HexColor("#e0e0e0")
C_DIM      = colors.HexColor("#888888")
C_ROW_ALT  = colors.HexColor("#1a1a1a")
C_HDR_BG   = colors.HexColor("#1e1e1e")

SEV_COLOURS = {
    "Critical": colors.HexColor("#c0392b"),
    "High"    : colors.HexColor("#e67e22"),
    "Medium"  : colors.HexColor("#f1c40f"),
    "Low"     : colors.HexColor("#27ae60"),
    "Info"    : colors.HexColor("#2980b9"),
}


def _styles():
    return {
        "title": ParagraphStyle(
            "title", fontName="Helvetica-Bold",
            fontSize=22, textColor=C_PRIMARY, spaceAfter=4
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName="Helvetica",
            fontSize=10, textColor=C_DIM, spaceAfter=16
        ),
        "h2": ParagraphStyle(
            "h2", fontName="Helvetica-Bold",
            fontSize=13, textColor=C_ACCENT,
            spaceBefore=20, spaceAfter=6
        ),
        "body": ParagraphStyle(
            "body", fontName="Helvetica",
            fontSize=9, textColor=C_TEXT,
            spaceAfter=4, leading=14
        ),
        "small": ParagraphStyle(
            "small", fontName="Helvetica",
            fontSize=8, textColor=C_DIM
        ),
    }

def _hex(colour):
    r, g, b = int(colour.red * 255), int(colour.green * 255), int(colour.blue * 255)
    return f"{r:02x}{g:02x}{b:02x}"


def _score_table(score, severity, counts):
    sev_col = SEV_COLOURS.get(severity, C_TEXT)
    data = [
        ["RISK SCORE", "SEVERITY", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        [
            f"{score} / 100", severity,
            str(counts.get("Critical", 0)),
            str(counts.get("High",     0)),
            str(counts.get("Medium",   0)),
            str(counts.get("Low",      0)),
        ]
    ]
    t = Table(data,
              colWidths=[3*cm, 3*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",      (0,0), (-1,0),  C_HDR_BG),
        ("TEXTCOLOR",       (0,0), (-1,0),  C_ACCENT),
        ("FONTNAME",        (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",        (0,0), (-1,0),  8),
        ("ALIGN",           (0,0), (-1,-1), "CENTER"),
        ("VALIGN",          (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS",  (0,1), (-1,-1), [C_ROW_ALT]),
        ("TEXTCOLOR",       (0,1), (0,1),   sev_col),
        ("FONTNAME",        (0,1), (1,1),   "Helvetica-Bold"),
        ("FONTSIZE",        (0,1), (0,1),   16),
        ("FONTSIZE",        (1,1), (1,1),   11),
        ("TEXTCOLOR",       (1,1), (1,1),   sev_col),
        ("TEXTCOLOR",       (2,1), (2,1),   SEV_COLOURS["Critical"]),
        ("TEXTCOLOR",       (3,1), (3,1),   SEV_COLOURS["High"]),
        ("TEXTCOLOR",       (4,1), (4,1),   SEV_COLOURS["Medium"]),
        ("TEXTCOLOR",       (5,1), (5,1),   SEV_COLOURS["Low"]),
        ("FONTNAME",        (2,1), (-1,1),  "Helvetica-Bold"),
        ("FONTSIZE",        (2,1), (-1,1),  13),
        ("TOPPADDING",      (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",   (0,0), (-1,-1), 8),
        ("GRID",            (0,0), (-1,-1), 0.3,
         colors.HexColor("#333333")),
    ]))
    return t


def _findings_table(findings, styles):
    rows = [["SEV", "ISSUE", "SOURCE", "RECOMMENDATION"]]
    for f in findings:
        sev = f.get("severity", "Info")
        col = _hex(SEV_COLOURS.get(sev, C_TEXT))
        rows.append([
            Paragraph(
                f'<font color="#{col}"><b>{sev}</b></font>',
                styles["small"]),
            Paragraph(f.get("title", ""),           styles["small"]),
            Paragraph(f.get("source", ""),          styles["small"]),
            Paragraph(f.get("recommendation", ""),  styles["small"]),
        ])
    if len(rows) == 1:
        rows.append(["—", "No findings detected", "—", "—"])

    t = Table(rows, colWidths=[1.8*cm, 6*cm, 2.5*cm, 6.2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0),  C_HDR_BG),
        ("TEXTCOLOR",      (0,0), (-1,0),  C_ACCENT),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,0),  8),
        ("ALIGN",          (0,0), (-1,0),  "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_ROW_ALT]),
        ("TEXTCOLOR",      (0,1), (-1,-1), C_TEXT),
        ("FONTSIZE",       (0,1), (-1,-1), 8),
        ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",     (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 6),
        ("LEFTPADDING",    (0,0), (-1,-1), 6),
        ("GRID",           (0,0), (-1,-1), 0.3,
         colors.HexColor("#2a2a2a")),
    ]))
    return t


def _ports_table(open_ports):
    rows = [["PORT", "PROTOCOL", "SERVICE", "VERSION"]]
    for p in open_ports:
        rows.append([
            str(p.get("port",     "")),
            p.get("protocol",     ""),
            p.get("service",      ""),
            p.get("version",  "") or p.get("product", "") or "—",
        ])
    if len(rows) == 1:
        rows.append(["—", "—", "No open ports detected", "—"])

    t = Table(rows, colWidths=[2*cm, 3*cm, 4*cm, 7.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0),  C_HDR_BG),
        ("TEXTCOLOR",      (0,0), (-1,0),  C_ACCENT),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_ROW_ALT]),
        ("TEXTCOLOR",      (0,1), (-1,-1), C_TEXT),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("GRID",           (0,0), (-1,-1), 0.3,
         colors.HexColor("#2a2a2a")),
    ]))
    return t


def generate_pdf(target, osint, scan, misconfig, headers, dns_whois, fingerprint, cve_results, risk):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    styles    = _styles()
    score     = risk.get("score", 0)
    severity  = risk.get("overall_severity", "Low")
    counts    = risk.get("severity_counts", {})

    doc = SimpleDocTemplate(
        "output/report.pdf",
        pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm,  bottomMargin=1.8*cm,
    )
    story = []

    story.append(Paragraph("ThreatLens Security Report", styles["title"]))
    story.append(Paragraph(
        f"Target: <b>{target}</b> &nbsp;|&nbsp; Generated: {timestamp}",
        styles["subtitle"]
    ))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#333333")
    ))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Overall Risk Score", styles["h2"]))
    story.append(_score_table(score, severity, counts))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("Findings & Recommendations", styles["h2"]))
    story.append(_findings_table(risk.get("findings", []), styles))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("Open Ports", styles["h2"]))
    story.append(_ports_table(scan.get("open_ports", [])))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("OSINT Findings", styles["h2"]))
    emails     = osint.get("emails",     []) or ["None found"]
    subdomains = osint.get("subdomains", []) or ["None found"]
    story.append(Paragraph(
        f"Emails ({osint.get('email_count',0)}): "
        + ", ".join(emails), styles["body"]
    ))
    story.append(Paragraph(
        f"Subdomains ({osint.get('subdomain_count',0)}): "
        + ", ".join(subdomains), styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))
    
    # ── DNS & Email Security ──────────────────────────────────────────────
    story.append(Paragraph("DNS & Email Security", styles["h2"]))

    spf_ok   = dns_whois.get("spf",   {}).get("present", False)
    dmarc_ok = dns_whois.get("dmarc", {}).get("present", False)
    dkim_ok  = dns_whois.get("dkim",  {}).get("present", False)
    age_days = dns_whois.get("whois", {}).get("age_days", "—")
    registrar= dns_whois.get("whois", {}).get("registrar","—")

    dns_data = [
        ["CHECK",        "STATUS",                        "DETAIL"],
        ["SPF",
         "Present" if spf_ok   else "MISSING",
         dns_whois.get("spf",  {}).get("record", "—") or "—"],
        ["DMARC",
         "Present" if dmarc_ok else "MISSING",
         dns_whois.get("dmarc",{}).get("record", "—") or "—"],
        ["DKIM",
         "Found"   if dkim_ok  else "Not found",
         dns_whois.get("dkim", {}).get("selector","—") or "—"],
        ["Domain age",
         f"{age_days} days",
         f"Registrar: {registrar}"],
    ]

    dns_table = Table(dns_data,
                      colWidths=[3*cm, 3.5*cm, 10*cm])
    dns_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_HDR_BG),
        ("TEXTCOLOR",     (0,0), (-1,0),  C_ACCENT),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_BG, C_ROW_ALT]),
        ("TEXTCOLOR",     (0,1), (-1,-1), C_TEXT),
        ("GRID",          (0,0), (-1,-1), 0.3,
         colors.HexColor("#2a2a2a")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(dns_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Tech fingerprint ──────────────────────────────────────────────────
    story.append(Paragraph("Technology Fingerprint", styles["h2"]))

    detected = fingerprint.get("detected", [])
    server   = fingerprint.get("server",   {})

    if detected:
        tech_data = [["NAME", "TYPE", "SEVERITY", "NOTE"]]
        for d in detected:
            tech_data.append([
                d.get("name",     ""),
                d.get("type",     ""),
                d.get("severity", ""),
                d.get("note",     ""),
            ])
        tech_table = Table(tech_data,
                           colWidths=[3*cm, 3*cm, 3*cm, 7.5*cm])
        tech_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_HDR_BG),
            ("TEXTCOLOR",     (0,0), (-1,0),  C_ACCENT),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_BG, C_ROW_ALT]),
            ("TEXTCOLOR",     (0,1), (-1,-1), C_TEXT),
            ("GRID",          (0,0), (-1,-1), 0.3,
             colors.HexColor("#2a2a2a")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(tech_table)
    else:
        story.append(
            Paragraph("No technologies detected.", styles["body"])
        )

    if server.get("raw"):
        story.append(Paragraph(
            f"Server: {server.get('name','')} "
            f"{server.get('version','') or ''}  "
            f"— {server.get('note','')}",
            styles["body"]
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── CVE findings ──────────────────────────────────────────────────────
    cve_count = cve_results.get("cve_count", 0)
    story.append(Paragraph(
        f"CVE Findings ({cve_count} total)",
        styles["h2"]
    ))

    cves = cve_results.get("cves", [])
    if cves:
        cve_data = [["CVE ID", "SEV", "CVSS", "AFFECTED", "DESCRIPTION"]]
        for c in cves:
            cve_data.append([
                c.get("cve_id",      ""),
                c.get("severity",    ""),
                str(c.get("cvss_score", "")),
                c.get("keyword",     ""),
                c.get("description", "")[:80] + "...",
            ])

        cve_table = Table(cve_data,
                          colWidths=[2.5*cm, 2*cm, 1.5*cm, 3.5*cm, 7*cm])
        cve_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  C_HDR_BG),
            ("TEXTCOLOR",     (0,0), (-1,0),  C_ACCENT),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_BG, C_ROW_ALT]),
            ("TEXTCOLOR",     (0,1), (-1,-1), C_TEXT),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("GRID",          (0,0), (-1,-1), 0.3,
             colors.HexColor("#2a2a2a")),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ]))
        story.append(cve_table)
    else:
        story.append(
            Paragraph("No CVEs found.", styles["body"])
        )
    story.append(Spacer(1, 0.4*cm))

    # ── Header grades ─────────────────────────────────────────────────────
    grade = headers.get("grade", "N/A")
    story.append(Paragraph(
        f"Security Headers — Grade: {grade}", styles["h2"]
    ))
    header_issues = headers.get("issues", [])
    if header_issues:
        for issue in header_issues:
            sev = issue.get("severity", "Info")
            col = _hex(SEV_COLOURS.get(sev, C_TEXT))
            story.append(Paragraph(
                f'<font color="#{col}"><b>[{issue["type"]}]</b></font> '
                f'{issue["header"]} — {issue["description"]}',
                styles["body"]
            ))
            story.append(Paragraph(
                f'Fix: {issue["recommendation"]}',
                styles["small"]
            ))
    else:
        story.append(
            Paragraph("No header issues detected.", styles["body"])
        )
    story.append(Spacer(1, 0.4*cm))


    story.append(Paragraph("SSL / TLS Issues", styles["h2"]))
    ssl_issues = misconfig.get("issues", [])
    if ssl_issues:
        for issue in ssl_issues:
            sev = issue.get("severity", "Info")
            col = _hex(SEV_COLOURS.get(sev, C_TEXT))
            story.append(Paragraph(
                f'<font color="#{col}"><b>[{sev}]</b></font> '
                f'{issue.get("description","")}',
                styles["body"]
            ))
    else:
        story.append(
            Paragraph("No SSL issues detected.", styles["body"])
        )

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#333333")
    ))
    story.append(Paragraph(
        "Generated by ThreatLens — For authorised use only. "
        "Do not distribute without permission.",
        styles["small"]
    ))

    doc.build(story)
    print("    [+] PDF saved → output/report.pdf")
