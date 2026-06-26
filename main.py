# Import core modules and project components responsible for 
# input validation, parallel scanning, CVE enrichment, threat correlation, risk scoring, report generation, and terminal output.

import json, os
from utils.validation         import validate_input, sanitise_target
from modules.parallel_runner  import run_all_scans
from modules.cve_lookup       import run_cve_lookup
from modules.correlation      import correlate_findings
from modules.scoring          import calculate_risk
from reports.report_generator import generate_report
from reports.pdf_generator    import generate_pdf
from reports.terminal_output  import print_banner, print_scan_start, print_summary


# It takes user input, validates it, and sanitises it before use.
# The two-step approach: validate first, then sanitise is defensive programming.
# If validation fails, the tool exits cleanly rather than crashing downstream.
def main():
    print_banner()
    raw_input   = input("Enter target (domain/IP): ")
    target_type = validate_input(raw_input)

    if not target_type:
        print("[!] Invalid input. Enter a valid domain or IP.")
        exit(1)

    target = sanitise_target(raw_input)
    print_scan_start(target, target_type)


"""
Core reconnaissance phase.

Executes all reconnaissance modules in parallel to reduce overall scan
time, including port scanning, OSINT gathering, HTTP header analysis,
misconfiguration checks, DNS/WHOIS lookups, and service fingerprinting.

The results are returned as a single dictionary and unpacked into
individual variables for easier access.

A CVE lookup is performed only after the scan completes successfully,
as it requires service and version information to identify known vulnerabilities.
If either step fails, the lookup is skipped and an empty result is returned, 
preventing unnecessary errors and ensuring graceful fault tolerance.
"""
    # ── Step 2: Parallel scanning ────────────────────────────────────────────
    
    results = run_all_scans(target)
    scan        = results.get("scan",        {})
    osint       = results.get("osint",       {})
    misconfig   = results.get("misconfig",   {})
    headers     = results.get("headers",     {})
    dns_whois   = results.get("dns_whois",   {})
    fingerprint = results.get("fingerprint", {})
    
    # CVE lookup runs after scans —> needs nmap + fingerprint data
    if scan.get("status") == "success" and fingerprint.get("status") == "success":
        cve_results = run_cve_lookup(scan, fingerprint)
    else:
        print("[!] Skipping CVE lookup as scan or fingerprint did not complete")
        cve_results = {"cve_count": 0, "cves": []}


    """
    Correlate results from all scanning modules to identify meaningful
    security findings. Related evidence from multiple sources is combined
    into unified issues, reducing isolated results and providing a more
    accurate assessment of the target.
    """
    # ── Step 3a: Correlation ─────────────────────────────────────────────────
    print("\n[*] CORRELATING FINDINGS ...")
    correlated = correlate_findings(scan, osint, misconfig, headers, dns_whois, fingerprint, cve_results)
    print(f"    [+] {len(correlated)} correlated pattern(s) found")

    """
    Calculate an overall risk score (0–100) and assign a severity level
    using a weighted evaluation of vulnerabilities, exposed services,
    misconfigurations, and correlated findings.
    The resulting score provides a concise, actionable summary of the target's security risk.
    """
    # ── Step 3b: Risk scoring ────────────────────────────────────────────────
    print("[*] Calculating risk score...")
    risk = calculate_risk(scan, misconfig, correlated)
    print(f"    [+] Score: {risk['score']}/100 — {risk['overall_severity']}")


    """
    Generate scan outputs in multiple formats.
    
    - JSON: Complete machine-readable results for automation and integration.
    - HTML/PDF: Detailed reports for analysis, documentation, and sharing.
    - Terminal Summary: Highlights key findings for immediate review.
    """
    # ── Step 3c: Save JSON + generate report ────────────────────────────────
    os.makedirs("output", exist_ok=True)

    with open("output/raw_results.json", "w") as f:
        json.dump({
            "target"     : target,
            "osint"      : osint,
            "scan"       : scan,
            "misconfig"  : misconfig,
            "headers"    : headers,
            "dns_whois"  : dns_whois,
            "fingerprint": fingerprint,
            "cve_results": cve_results,
            "correlated" : correlated,   
            "risk"       : risk,
        }, f, indent=2, default=str)

    generate_report(target, osint, scan, misconfig, headers, dns_whois, fingerprint, cve_results, risk)
    generate_pdf(target, osint, scan, misconfig, headers, dns_whois, fingerprint, cve_results, risk)    
    print_summary(target, risk, osint, scan)             

    
if __name__ == "__main__":
    main()
