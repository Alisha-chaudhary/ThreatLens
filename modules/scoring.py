def calculate_risk(
    scan     : dict,
    misconfig: dict,
    correlated: list
) -> dict:
    """
    Assigns a numeric score and severity to every finding.
    Returns an overall risk score out of 100.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 40,
        "High"    : 25,
        "Medium"  : 15,
        "Low"     :  5,
        "Info"    :  0,
    }

    scored_findings = []
    total_score     = 0

    # ── Score individual port findings ───────────────────────────────────────
    RISKY_PORTS = {
        21  : ("FTP open — unencrypted file transfer",     "High",     25),
        22  : ("SSH exposed to internet",                  "Medium",   15),
        23  : ("Telnet open — critically insecure",        "Critical", 40),
        25  : ("SMTP open — potential mail relay abuse",   "Medium",   15),
        80  : ("HTTP open — unencrypted web traffic",      "Low",       5),
        110 : ("POP3 open — email retrieval exposed",      "Medium",   15),
        143 : ("IMAP open — email access exposed",         "Medium",   15),
        445 : ("SMB open — common ransomware vector",      "Critical", 40),
        3306: ("MySQL exposed to internet",                "High",     25),
        3389: ("RDP exposed — common attack vector",       "High",     25),
        5432: ("PostgreSQL exposed to internet",           "High",     25),
        5900: ("VNC exposed — remote desktop risk",        "High",     25),
        6379: ("Redis exposed — often unauthenticated",    "Critical", 40),
        27017:("MongoDB exposed — often unauthenticated",  "Critical", 40),
    }

    for port_info in scan.get("open_ports", []):
        port = port_info["port"]
        if port in RISKY_PORTS:
            description, severity, weight = RISKY_PORTS[port]
            scored_findings.append({
                "source"        : "nmap",
                "port"          : port,
                "severity"      : severity,
                "title"         : description,
                "score_added"   : weight,
                "recommendation": f"Review whether port {port} should be "
                                  f"publicly accessible. Apply firewall rules.",
            })
            total_score += weight

    # ── Score SSL/TLS issues ─────────────────────────────────────────────────
    for issue in misconfig.get("issues", []):
        weight = SEVERITY_WEIGHTS.get(issue["severity"], 0)
        scored_findings.append({
            "source"        : "testssl",
            "severity"      : issue["severity"],
            "title"         : issue["description"],
            "score_added"   : weight,
            "recommendation": "Review SSL/TLS configuration on your web server.",
        })
        total_score += weight

    # ── Score correlated findings ────────────────────────────────────────────
    for finding in correlated:
        weight = SEVERITY_WEIGHTS.get(finding["severity"], 0)
        scored_findings.append({
            "source"        : finding["source"],
            "severity"      : finding["severity"],
            "title"         : finding["title"],
            "detail"        : finding.get("detail", ""),
            "score_added"   : weight,
            "recommendation": finding["recommendation"],
        })
        total_score += weight

    # ── Cap score and determine overall severity band ────────────────────────
    final_score = min(total_score, 100)

    if final_score >= 75:
        overall = "Critical"
    elif final_score >= 50:
        overall = "High"
    elif final_score >= 25:
        overall = "Medium"
    else:
        overall = "Low"

    # ── Count findings by severity ───────────────────────────────────────────
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in scored_findings:
        sev = f.get("severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "score"           : final_score,
        "overall_severity": overall,
        "severity_counts" : severity_counts,
        "finding_count"   : len(scored_findings),
        "findings"        : scored_findings,
    }
