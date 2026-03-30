import subprocess
import re
import os
def run_osint(target: str) -> dict:
    """
    Runs theHarvester for subdomain, email, and IP discovery.
    Falls back to an empty result on failure.
    """
    try:
        result = subprocess.run(
            ["theHarvester", "-d", target, "-b", "google,bing"],
            capture_output=True,
            text=True,
            timeout=180
        )
        raw = result.stdout or ""      #  assigned raw

        os.makedirs("output", exist_ok=True)
        with open("output/osint_raw.txt", "w") as f:
            f.write(raw)
        return _parse_harvester_output(raw, target)

    except FileNotFoundError:
        return _error_result("theHarvester", target, "theHarvester is not installed")
    except subprocess.TimeoutExpired:
        return _error_result("theHarvester", target, "OSINT scan timed out after 180s")


def _parse_harvester_output(raw: str, target: str) -> dict:
    """Extracts emails, subdomains, and IPs from theHarvester raw output."""
    if not raw:
        raw=" "

    emails = list(set(
        re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw)
    ))

    subdomains = list(set(
        re.findall(
            r"(?:[a-zA-Z0-9\-]+\.){1,}" + re.escape(target),
            raw
        )
    ))

    ips = list(set(
        re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    ))

    return {
        "tool"           : "theHarvester",
        "target"         : target,
        "status"         : "success",
        "emails"         : emails,
        "subdomains"     : subdomains,
        "ip_addresses"   : ips,
        "email_count"    : len(emails),
        "subdomain_count": len(subdomains),
    }


def _error_result(tool: str, target: str, message: str) -> dict:
    return {
        "tool"           : tool,
        "target"         : target,
        "status"         : "error",
        "error"          : message,
        "emails"         : [],
        "subdomains"     : [],
        "ip_addresses"   : [],
        "email_count"    : 0,
        "subdomain_count": 0,
    }
