import json, os
from utils.validation         import validate_input, sanitise_target
from modules.parallel_runner  import run_all_scans
from modules.cve_lookup       import run_cve_lookup
from modules.correlation      import correlate_findings
from modules.scoring          import calculate_risk
from reports.report_generator import generate_report
from reports.pdf_generator    import generate_pdf
from reports.terminal_output  import print_banner, print_scan_start, print_summary

def main():
    print_banner()
    raw_input   = input("Enter target (domain/IP): ")
    target_type = validate_input(raw_input)

    if not target_type:
        print("[!] Invalid input. Enter a valid domain or IP.")
        exit(1)

    target = sanitise_target(raw_input)
    print_scan_start(target, target_type)

    # ── Step 2: Parallel scanning ────────────────────────────────────────────
    results = run_all_scans(target)
    scan        = results.get("scan",      {})
    osint       = results.get("osint",     {})
    misconfig   = results.get("misconfig", {})
    headers     = results.get("headers",   {})
    dns_whois   = results.get("dns_whois", {})
    fingerprint = results.get("fingerprint", {})
    
    # CVE lookup runs after scans — needs nmap + fingerprint data
    if scan.get("status") == "success" and fingerprint.get("status") == "success":
        cve_results = run_cve_lookup(scan, fingerprint)
    else:
        print("[!] Skipping CVE lookup — scan or fingerprint did not complete")
        cve_results = {"cve_count": 0, "cves": []}



    # ── Step 3a: Correlation ─────────────────────────────────────────────────
    print("\n[*] Correlating findings...")
    correlated = correlate_findings(scan, osint, misconfig, headers, dns_whois, fingerprint, cve_results)
    print(f"    [+] {len(correlated)} correlated pattern(s) found")

    # ── Step 3b: Risk scoring ────────────────────────────────────────────────
    print("[*] Calculating risk score...")
    risk = calculate_risk(scan, misconfig, correlated)
    print(f"    [+] Score: {risk['score']}/100 — {risk['overall_severity']}")

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
