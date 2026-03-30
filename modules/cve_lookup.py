import requests
import time

# NVD API base URL — free, no auth needed for basic queries
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def run_cve_lookup(scan: dict, fingerprint: dict) -> dict:
    """
    Takes version information from nmap and fingerprint modules.
    Queries the NVD (National Vulnerability Database) for known CVEs.
    Returns structured CVE findings.
    """
    targets = _extract_version_targets(scan, fingerprint)

    if not targets:
        return {
            "tool"       : "cve_lookup",
            "status"     : "success",
            "note"       : "No version information available to query",
            "cves"       : [],
            "cve_count"  : 0,
            "issues"     : [],
        }

    all_cves = []


    for i, t in enumerate(targets):
        cves = _query_nvd(t["keyword"], t["source"])
        all_cves.extend(cves)
        if i < len(targets) - 1:
            time.sleep(6)

    issues = _build_issues(all_cves)

    return {
        "tool"      : "cve_lookup",
        "status"    : "success",
        "targets"   : targets,
        "cves"      : all_cves,
        "cve_count" : len(all_cves),
        "issues"    : issues,
    }


# ── Extract version strings to search ────────────────────────────────────────
def _extract_version_targets(scan: dict, fingerprint: dict) -> list:
    """
    Pulls software name + version strings from nmap and
    fingerprint results to use as NVD search keywords.
    """
    targets = []
    seen    = set()

    # from nmap open ports
    for port in scan.get("open_ports", []):
        product = port.get("product", "")
        version = port.get("version", "")
        service = port.get("service", "")

        if product and version:
            keyword = f"{product} {version}"
        elif product:
            keyword = product
        elif service and version:
            keyword = f"{service} {version}"
        else:
            continue

        keyword = keyword.strip()
        if keyword and keyword not in seen:
            seen.add(keyword)
            targets.append({
                "keyword": keyword,
                "source" : f"nmap port {port.get('port','')}",
                "port"   : port.get("port", ""),
            })

    # from fingerprint server info
    server = fingerprint.get("server", {})
    if server.get("name") and server.get("version"):
        keyword = f"{server['name']} {server['version']}"
        if keyword not in seen:
            seen.add(keyword)
            targets.append({
                "keyword": keyword,
                "source" : "server header",
                "port"   : None,
            })

    # from detected CMS/frameworks
    for tech in fingerprint.get("detected", []):
        name = tech.get("name", "")
        if name and name not in seen:
            seen.add(name)
            targets.append({
                "keyword": name,
                "source" : f"fingerprint ({tech.get('type','')})",
                "port"   : None,
            })

    return targets


# ── Query NVD API ─────────────────────────────────────────────────────────────
def _query_nvd(keyword: str, source: str) -> list:
    """
    Queries NVD for CVEs matching the keyword.
    Returns a list of CVE dicts.
    """
    try:
        response = requests.get(
            NVD_API,
            params={
                "keywordSearch" : keyword,
                "resultsPerPage": 5,        # top 5 per software
                "startIndex"    : 0,
            },
            timeout=15,
            headers={"User-Agent": "ThreatLens-Scanner/1.0"}
        )

        if response.status_code != 200:
            return []

        data        = response.json()
        cve_items   = data.get("vulnerabilities", [])
        results     = []

        for item in cve_items:
            cve      = item.get("cve", {})
            cve_id   = cve.get("id", "")
            desc     = _get_description(cve)
            severity, score = _get_severity(cve)

            results.append({
                "cve_id"     : cve_id,
                "keyword"    : keyword,
                "source"     : source,
                "description": desc,
                "severity"   : severity,
                "cvss_score" : score,
                "url"        : f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return results

    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []


# ── Parse description from NVD response ──────────────────────────────────────
def _get_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            text = d.get("value", "")
            # truncate long descriptions
            return text[:200] + "..." if len(text) > 200 else text
    return "No description available"


# ── Parse CVSS severity score ─────────────────────────────────────────────────
def _get_severity(cve: dict) -> tuple:
    """
    Extracts CVSS score and maps it to our severity labels.
    Tries CVSS v3.1 first then v3.0 then v2.
    """
    metrics = cve.get("metrics", {})

    # try v3.1
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(key, [])
        if entries:
            data  = entries[0].get("cvssData", {})
            score = data.get("baseScore", 0)
            return _score_to_severity(score), score

    return "Unknown", 0


def _score_to_severity(score: float) -> str:
    """Maps CVSS numeric score to severity label."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "Info"


# ── Build issues list from CVEs ───────────────────────────────────────────────
def _build_issues(cves: list) -> list:
    """
    Converts raw CVE list into structured issues.
    Only includes High and Critical CVEs as actionable issues.
    """
    issues = []
    seen   = set()

    for cve in cves:
        cve_id   = cve.get("cve_id", "")
        severity = cve.get("severity", "Info")

        # deduplicate
        if cve_id in seen:
            continue
        seen.add(cve_id)

        if severity in ["Critical", "High"]:
            issues.append({
                "severity"      : severity,
                "title"         : f"{cve_id} affects {cve['keyword']}",
                "description"   : cve.get("description", ""),
                "cvss_score"    : cve.get("cvss_score", 0),
                "recommendation": f"Review {cve_id} at {cve['url']} "
                                  f"and apply available patches.",
                "source"        : f"nvd + {cve.get('source','')}",
                "url"           : cve.get("url", ""),
            })

    return issues
