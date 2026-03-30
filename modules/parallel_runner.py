from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.scanner  import run_nmap_scan
from modules.osint    import run_osint
from modules.misconfig import run_ssl_check
from modules.headers   import run_header_check
from modules.dns_whois import run_dns_whois_check
from modules.fingerprint import run_fingerprint


def run_all_scans(target: str) -> dict:
    """
    Runs nmap, OSINT, and SSL checks in parallel.
    Returns all results as a single dictionary.
    """
    results = {}

    # Define which functions to run and what to name their results
    tasks = {
        "scan"       : run_nmap_scan,
        "osint"      : run_osint,
        "misconfig"  : run_ssl_check,
        "headers"    : run_header_check,
        "dns_whois"  : run_dns_whois_check,
        "fingerprint": run_fingerprint,
      }

    print("Scanning...")

    with ThreadPoolExecutor(max_workers=6) as executor:

        # Submit all six tasks to the thread pool
        future_to_name = {
            executor.submit(func, target): name
            for name, func in tasks.items()
        }

        # Collect results as each one finishes
        for future in as_completed(future_to_name):
            name = future_to_name[future]

            try:
                results[name] = future.result()
                status = results[name].get("status", "unknown")
                 # ── Print a clear message for each outcome ────────────────────────
                if status == "not_installed":
                    error_msg = results[name].get("error", "")
                    print(f"    [!] {name:12} → not installed — {error_msg}")
                elif status == "error":
                    error_msg = results[name].get("error", "")
                    print(f"    [!] {name:12} → error — {error_msg}")
                else:
                    note = results[name].get("note", "")
                    suffix = f" ({note})" if note else ""
                    print(f"    [+] {name:12} → {status}{suffix}")

            except Exception as e:
                print(f"    [!] {name:12} → crashed: {e}")
                results[name] = {"status": "error", "error": str(e)}
                
            
    print("[*] All scans complete.")
    return results
