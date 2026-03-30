import requests
import re

# ── Fingerprint signatures ────────────────────────────────────────────────────
# Each entry defines what to look for and where

CMS_SIGNATURES = [
    # WordPress
    {
        "name"    : "WordPress",
        "type"    : "CMS",
        "checks"  : [
            {"where": "body",   "pattern": r"wp-content|wp-includes"},
            {"where": "body",   "pattern": r'content="WordPress'},
            {"where": "header", "key": "x-powered-by", "pattern": r"WordPress"},
        ],
        "severity": "Low",
        "note"    : "Ensure WordPress core, themes and plugins are updated.",
    },
    # Joomla
    {
        "name"    : "Joomla",
        "type"    : "CMS",
        "checks"  : [
            {"where": "body",   "pattern": r"/components/com_"},
            {"where": "body",   "pattern": r"Joomla!"},
        ],
        "severity": "Low",
        "note"    : "Ensure Joomla core and extensions are updated.",
    },
    # Drupal
    {
        "name"    : "Drupal",
        "type"    : "CMS",
        "checks"  : [
            {"where": "body",   "pattern": r"Drupal|drupal"},
            {"where": "header", "key": "x-generator", "pattern": r"Drupal"},
            {"where": "header", "key": "x-drupal-cache", "pattern": r".*"},
        ],
        "severity": "Low",
        "note"    : "Ensure Drupal core and modules are updated.",
    },
    # Magento
    {
        "name"    : "Magento",
        "type"    : "CMS",
        "checks"  : [
            {"where": "body",   "pattern": r"Mage\.cookies|magento"},
            {"where": "cookie", "pattern": r"frontend"},
        ],
        "severity": "Medium",
        "note"    : "Magento stores payment data. Ensure PCI compliance.",
    },
    # Shopify
    {
        "name"    : "Shopify",
        "type"    : "Platform",
        "checks"  : [
            {"where": "body",   "pattern": r"cdn\.shopify\.com"},
            {"where": "header", "key": "x-shopify-stage", "pattern": r".*"},
        ],
        "severity": "Info",
        "note"    : "Shopify-hosted store detected.",
    },
]

FRAMEWORK_SIGNATURES = [
    # PHP
    {
        "name"    : "PHP",
        "type"    : "Language",
        "checks"  : [
            {"where": "header", "key": "x-powered-by", "pattern": r"PHP/[\d.]+"},
            {"where": "header", "key": "set-cookie",   "pattern": r"PHPSESSID"},
        ],
        "severity": "Low",
        "note"    : "PHP version exposed. Update to latest stable release.",
    },
    # ASP.NET
    {
        "name"    : "ASP.NET",
        "type"    : "Framework",
        "checks"  : [
            {"where": "header", "key": "x-powered-by",    "pattern": r"ASP\.NET"},
            {"where": "header", "key": "x-aspnet-version","pattern": r"[\d.]+"},
            {"where": "header", "key": "set-cookie",      "pattern": r"ASP\.NET_SessionId"},
        ],
        "severity": "Medium",
        "note"    : "ASP.NET version exposed. Suppress version headers.",
    },
    # Django
    {
        "name"    : "Django",
        "type"    : "Framework",
        "checks"  : [
            {"where": "header", "key": "set-cookie", "pattern": r"csrftoken|sessionid"},
            {"where": "body",   "pattern": r"csrfmiddlewaretoken"},
        ],
        "severity": "Info",
        "note"    : "Django framework detected.",
    },
    # Laravel
    {
        "name"    : "Laravel",
        "type"    : "Framework",
        "checks"  : [
            {"where": "header", "key": "set-cookie", "pattern": r"laravel_session"},
            {"where": "body",   "pattern": r"laravel"},
        ],
        "severity": "Info",
        "note"    : "Laravel framework detected.",
    },
    # React / Next.js
    {
        "name"    : "React/Next.js",
        "type"    : "Frontend",
        "checks"  : [
            {"where": "body",  "pattern": r"__NEXT_DATA__|next/static"},
            {"where": "body",  "pattern": r"react-dom"},
        ],
        "severity": "Info",
        "note"    : "React/Next.js frontend detected.",
    },
]

SERVER_SIGNATURES = [
    {
        "name"   : "Apache",
        "pattern": r"Apache/([\d.]+)",
        "note"   : "Ensure Apache is updated to latest stable version.",
    },
    {
        "name"   : "Nginx",
        "pattern": r"nginx/([\d.]+)",
        "note"   : "Ensure Nginx is updated to latest stable version.",
    },
    {
        "name"   : "IIS",
        "pattern": r"Microsoft-IIS/([\d.]+)",
        "note"   : "Ensure IIS and Windows Server are fully patched.",
    },
    {
        "name"   : "LiteSpeed",
        "pattern": r"LiteSpeed",
        "note"   : "LiteSpeed web server detected.",
    },
    {
        "name"   : "Cloudflare",
        "pattern": r"cloudflare",
        "note"   : "Cloudflare CDN/WAF detected — direct IP may differ.",
    },
]


def run_fingerprint(target: str) -> dict:
    """
    Fetches the target and fingerprints CMS, frameworks,
    server software and version information.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "ThreatLens-Scanner/1.0"}
            )
            return _analyse(response, target, url)

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            return _error_result(target, "Connection timed out")

    return _error_result(target, "Could not connect on HTTPS or HTTP")


def _analyse(response, target: str, url: str) -> dict:
    """
    Runs all signature checks against the response.
    """
    body        = response.text.lower()
    headers     = {k.lower(): v for k, v in response.headers.items()}
    cookies     = response.cookies.keys()

    detected    = []
    issues      = []

    # ── CMS detection ─────────────────────────────────────────────────────────
    for sig in CMS_SIGNATURES:
        if _matches(sig["checks"], body, headers, cookies):
            detected.append({
                "name"    : sig["name"],
                "type"    : sig["type"],
                "severity": sig["severity"],
                "note"    : sig["note"],
            })
            if sig["severity"] not in ["Info"]:
                issues.append({
                    "severity"      : sig["severity"],
                    "title"         : f"{sig['name']} CMS detected",
                    "description"   : f"{sig['name']} identified via "
                                      f"fingerprinting techniques.",
                    "recommendation": sig["note"],
                    "source"        : "fingerprint",
                })

    # ── Framework detection ───────────────────────────────────────────────────
    for sig in FRAMEWORK_SIGNATURES:
        if _matches(sig["checks"], body, headers, cookies):
            detected.append({
                "name"    : sig["name"],
                "type"    : sig["type"],
                "severity": sig["severity"],
                "note"    : sig["note"],
            })
            if sig["severity"] not in ["Info"]:
                issues.append({
                    "severity"      : sig["severity"],
                    "title"         : f"{sig['name']} detected and "
                                      f"exposing version info",
                    "description"   : f"{sig['name']} identified. "
                                      f"Version information may be exposed.",
                    "recommendation": sig["note"],
                    "source"        : "fingerprint",
                })

    # ── Server detection ──────────────────────────────────────────────────────
    server_header = headers.get("server", "")
    server_info   = _detect_server(server_header)

    return {
        "tool"       : "fingerprint",
        "target"     : target,
        "url"        : url,
        "status"     : "success",
        "detected"   : detected,
        "server"     : server_info,
        "issues"     : issues,
        "issue_count": len(issues),
    }


def _matches(checks: list, body: str,
             headers: dict, cookies) -> bool:
    """
    Returns True if ANY check in the list matches.
    """
    for check in checks:
        where   = check["where"]
        pattern = check.get("pattern", ".*")

        if where == "body":
            if re.search(pattern, body, re.IGNORECASE):
                return True

        elif where == "header":
            key   = check.get("key", "")
            value = headers.get(key, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                return True

        elif where == "cookie":
            for cookie in cookies:
                if re.search(pattern, cookie, re.IGNORECASE):
                    return True
    return False


def _detect_server(server_header: str) -> dict:
    """
    Extracts server name and version from the Server header.
    """
    if not server_header:
        return {"name": "Hidden", "version": None, "raw": None}

    for sig in SERVER_SIGNATURES:
        match = re.search(sig["pattern"], server_header, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else None
            return {
                "name"   : sig["name"],
                "version": version,
                "raw"    : server_header,
                "note"   : sig["note"],
            }

    return {
        "name"   : "Unknown",
        "version": None,
        "raw"    : server_header,
    }


def _error_result(target: str, message: str) -> dict:
    return {
        "tool"       : "fingerprint",
        "target"     : target,
        "status"     : "error",
        "error"      : message,
        "detected"   : [],
        "server"     : {},
        "issues"     : [],
        "issue_count": 0,
    }

