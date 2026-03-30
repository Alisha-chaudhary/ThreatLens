def correlate_findings(scan: dict, osint: dict, misconfig: dict, headers: dict, dns_whois: dict, fingerprint: dict, cve_results: dict) -> list:
    """
    Looks across all three scan results together.
    Finds combined risk patterns that no single tool would catch alone.
    Returns a list of correlated findings.
    """
    findings = []

    open_ports   = scan.get("open_ports", [])
    port_numbers = [p["port"] for p in open_ports]
    ssl_issues   = misconfig.get("issues", [])
    header_issues  = headers.get("issues",  [])
    header_grade   = headers.get("grade",   "N/A")
    dns_issues     = dns_whois.get("issues", [])
    domain_age     = dns_whois.get("whois",  {}).get("age_days", 999)
    spf_present    = dns_whois.get("spf",    {}).get("present", True)
    dmarc_present  = dns_whois.get("dmarc",  {}).get("present", True)
    detected_tech  = fingerprint.get("detected", [])
    server_info    = fingerprint.get("server",   {})
    cms_names      = [d["name"] for d in detected_tech if d["type"] == "CMS"]
    critical_cves  = [c for c in cve_results.get("cves", [])
                  if c.get("severity") in ["Critical", "High"]]
    ssl_keywords = [i["keyword"].lower() for i in ssl_issues]
    emails       = osint.get("emails", [])
    subdomains   = osint.get("subdomains", [])

    # ── Pattern 1: Exposed admin ports ──────────────────────────────────────
    ADMIN_PORTS = {
        22  : "SSH",
        23  : "Telnet",
        3389: "RDP",
        5900: "VNC",
        5432: "PostgreSQL",
        3306: "MySQL",
        6379: "Redis",
        27017: "MongoDB",
    }
    for port, service in ADMIN_PORTS.items():
        if port in port_numbers:
            findings.append({
                "type"          : "exposed_admin_port",
                "severity"      : "High" if port != 23 else "Critical",
                "title"         : f"{service} port {port} is publicly exposed",
                "detail"        : f"Administrative service {service} is reachable "
                                  f"from the internet on port {port}.",
                "recommendation": f"Restrict port {port} to known IP ranges using "
                                  f"a firewall. Never expose {service} publicly.",
                "source"        : "nmap",
            })

    # ── Pattern 2: Weak SSL + open HTTPS port = active risk ─────────────────
    has_https = any(p["port"] == 443 for p in open_ports)
    weak_ssl  = any(k in ssl_keywords for k in ["tlsv1.0", "tlsv1.1", "sslv3"])

    if has_https and weak_ssl:
        findings.append({
            "type"          : "weak_ssl_active",
            "severity"      : "High",
            "title"         : "Weak TLS version active on live HTTPS service",
            "detail"        : "Port 443 is open and testssl detected a weak protocol. "
                              "An attacker can downgrade the connection.",
            "recommendation": "Disable TLSv1.0 and TLSv1.1 in your web server config. "
                              "Enforce TLS 1.2 minimum, prefer TLS 1.3.",
            "source"        : "nmap + testssl",
        })

    # ── Pattern 3: Email exposure + subdomains = phishing surface ───────────
    if emails and subdomains:
        findings.append({
            "type"          : "phishing_surface",
            "severity"      : "Medium",
            "title"         : "Email addresses exposed alongside subdomains",
            "detail"        : f"{len(emails)} email(s) and {len(subdomains)} subdomain(s) "
                              f"found publicly. Attackers can use these to craft "
                              f"targeted phishing emails impersonating your subdomains.",
            "recommendation": "Audit which emails are publicly indexed. Consider "
                              "DMARC, DKIM, and SPF records to prevent spoofing.",
            "source"        : "theHarvester",
        })

    # ── Pattern 4: Unencrypted services alongside sensitive ports ───────────
    UNENCRYPTED = {21: "FTP", 23: "Telnet", 80: "HTTP"}
    SENSITIVE   = {22, 3306, 5432, 3389}

    exposed_unencrypted = [
        svc for port, svc in UNENCRYPTED.items() if port in port_numbers
    ]
    exposed_sensitive = [
        p for p in port_numbers if p in SENSITIVE
    ]

    if exposed_unencrypted and exposed_sensitive:
        findings.append({
            "type"          : "unencrypted_with_sensitive",
            "severity"      : "High",
            "title"         : "Unencrypted services running alongside sensitive ports",
            "detail"        : f"Unencrypted services ({', '.join(exposed_unencrypted)}) "
                              f"are active on the same host as sensitive ports "
                              f"({', '.join(str(p) for p in exposed_sensitive)}). "
                              f"Credentials sent over unencrypted channels can be "
                              f"captured and reused on sensitive services.",
            "recommendation": "Disable FTP/Telnet/HTTP. Use SFTP, SSH, HTTPS instead.",
            "source"        : "nmap",
        })

    # ── Pattern 5: Expired or self-signed cert on live server ───────────────
    cert_issues = [
        k for k in ["expired", "self signed"] if k in ssl_keywords
    ]
    if cert_issues and has_https:
        findings.append({
            "type"          : "cert_trust_issue",
            "severity"      : "Medium",
            "title"         : "Certificate trust issue on live HTTPS service",
            "detail"        : f"testssl detected: {', '.join(cert_issues)}. "
                              f"Browsers will warn users and attackers can exploit "
                              f"the lack of certificate validation.",
            "recommendation": "Install a valid certificate from a trusted CA. "
                              "Use Let's Encrypt for free trusted certificates.",
            "source"        : "testssl",
        })

    # ── Pattern 6: Poor header grade + open HTTP port ────────────────────────────
    
    has_http       = any(p["port"] == 80 for p in open_ports)
    poor_grade     = header_grade in ["D", "F"]

    if has_http and poor_grade:
        findings.append({
            "type"          : "weak_headers_on_http",
            "severity"      : "High",
            "title"         : f"Poor security headers (grade {header_grade}) "
                              f"on live HTTP service",
            "detail"        : "Port 80 is open and security headers are poorly "
                              "configured. Attackers can exploit missing CSP "
                              "and HSTS to perform XSS and downgrade attacks.",
            "recommendation": "Implement all missing security headers and "
                              "redirect HTTP to HTTPS.",
            "source"        : "header_checker",
        })


    # ── Pattern 7: Young domain + email exposure = high phishing risk ────────────
    if domain_age < 180 and emails:
        findings.append({
             "type"          : "young_domain_email_exposure",
             "severity"      : "Critical",
             "title"         : f"Young domain ({domain_age} days) "
                               f"with exposed email addresses",
             "detail"        : "A recently registered domain with publicly "
                               "exposed emails is a strong phishing indicator. "
                               "Attackers register lookalike domains and harvest "
                               "real email addresses to target.",
             "recommendation": "Verify domain ownership and legitimacy. "
                               "Implement DMARC reject policy immediately.",
             "source"        : "whois + osint",
    })

    # ── Pattern 8: No SPF + No DMARC + MX present = email spoofing trivial ───────
    if not spf_present and not dmarc_present:
        findings.append({
             "type"          : "email_spoofing_trivial",
             "severity"      : "Critical",
             "title"         : "Email spoofing is trivial — no SPF or DMARC",
             "detail"        : "Neither SPF nor DMARC are configured. Anyone "
                               "can send email impersonating this domain with "
                               "zero technical barriers.",
             "recommendation": "Add SPF record immediately. Then add DMARC "
                               "with p=reject policy.",
             "source"        : "dns",
    })
    
    # ── Pattern 9: Outdated CMS + open ports = wider attack surface ──────────────
    if cms_names and scan.get("port_count", 0) > 3:
        findings.append({
            "type"          : "cms_large_attack_surface",
            "severity"      : "High",
            "title"         : f"{', '.join(cms_names)} detected with "
                              f"{scan.get('port_count',0)} open ports",
            "detail"        : "A CMS with many open ports increases the "
                              "attack surface significantly. Each open port "
                              "is a potential entry point for attackers "
                              "targeting CMS vulnerabilities.",
            "recommendation": "Close unnecessary ports. Keep CMS and all "
                              "plugins/themes fully updated.",
            "source"        : "fingerprint + nmap",
    })

    # ── Pattern 10: Server version exposed + CVE-able service ────────────────────
    server_raw = server_info.get("raw", "")
    if server_raw and weak_ssl:
        findings.append({
            "type"          : "version_exposed_weak_ssl",
            "severity"      : "High",
            "title"         : f"Server version exposed ({server_raw}) "
                              f"with weak SSL",
            "detail"        : "Server software version is publicly visible "
                              "in headers and weak SSL is active. Attackers "
                              "can look up exact CVEs for this version.",
            "recommendation": "Suppress the Server header and upgrade TLS "
                              "to 1.3.",
            "source"        : "fingerprint + testssl",
    })

    # ── Pattern 11: Critical CVE + exposed service port ──────────────────────────
    if critical_cves and scan.get("port_count", 0) > 0:
        top_cve = critical_cves[0]
        findings.append({
            "type"          : "critical_cve_exposed_service",
            "severity"      : "Critical",
            "title"         : f"Critical CVE ({top_cve['cve_id']}) "
                              f"on exposed service",
            "detail"        : f"{top_cve['cve_id']} affects "
                              f"{top_cve['keyword']}. Service is reachable "
                              f"from the internet. Exploitation may be "
                              f"possible without authentication.",
            "recommendation": f"Immediately patch or isolate the affected "
                              f"service. Review: {top_cve['url']}",
            "source"        : "nvd + nmap",
    })

    return findings
