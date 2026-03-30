import requests

# ── Headers we check and why ──────────────────────────────────────────────────
HEADER_CHECKS = [
    {
        "header"        : "Strict-Transport-Security",
        "short"         : "HSTS",
        "severity"      : "High",
        "description"   : "HSTS header missing — browser not forced to use HTTPS",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; "
                          "includeSubDomains",
    },
    {
        "header"        : "Content-Security-Policy",
        "short"         : "CSP",
        "severity"      : "High",
        "description"   : "Content-Security-Policy missing — XSS attacks possible",
        "recommendation": "Define a strict CSP policy. Start with: "
                          "Content-Security-Policy: default-src 'self'",
    },
    {
        "header"        : "X-Frame-Options",
        "short"         : "X-Frame",
        "severity"      : "Medium",
        "description"   : "X-Frame-Options missing — clickjacking attacks possible",
        "recommendation": "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    },
    {
        "header"        : "X-Content-Type-Options",
        "short"         : "X-Content-Type",
        "severity"      : "Medium",
        "description"   : "X-Content-Type-Options missing — MIME sniffing possible",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header"        : "Referrer-Policy",
        "short"         : "Referrer-Policy",
        "severity"      : "Low",
        "description"   : "Referrer-Policy missing — referrer data leaks possible",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header"        : "Permissions-Policy",
        "short"         : "Permissions-Policy",
        "severity"      : "Low",
        "description"   : "Permissions-Policy missing — browser features unrestricted",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=()",
    },
    {
        "header"        : "X-XSS-Protection",
        "short"         : "XSS-Protection",
        "severity"      : "Low",
        "description"   : "X-XSS-Protection missing — older browsers unprotected",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
]

# ── Headers that should NOT be present (information leakage) ─────────────────
LEAKY_HEADERS = [
    {
        "header"        : "Server",
        "severity"      : "Low",
        "description"   : "Server header exposes web server software and version",
        "recommendation": "Configure your web server to suppress the Server header.",
    },
    {
        "header"        : "X-Powered-By",
        "severity"      : "Low",
        "description"   : "X-Powered-By exposes backend technology (PHP, ASP etc.)",
        "recommendation": "Remove X-Powered-By header from server configuration.",
    },
    {
        "header"        : "X-AspNet-Version",
        "severity"      : "Medium",
        "description"   : "X-AspNet-Version exposes exact .NET framework version",
        "recommendation": "Disable in web.config: "
                          "<httpRuntime enableVersionHeader='false'/>",
    },
]


def run_header_check(target: str) -> dict:
    """
    Fetches HTTP headers from the target and checks for
    missing security headers and leaky information headers.
    """
    # build URL — try HTTPS first, fall back to HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,          # don't fail on bad certs
                headers={"User-Agent": "ThreatLens-Scanner/1.0"}
            )
            return _analyse_headers(response.headers, target, url)

        except requests.exceptions.SSLError:
            continue                   # try http if https cert fails
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            return _error_result(target, "Connection timed out after 10s")

    return _error_result(target, "Could not connect on HTTPS or HTTP")


def _analyse_headers(headers: dict, target: str, url: str) -> dict:
    """
    Checks response headers against our two lists.
    Returns structured findings.
    """
    issues       = []
    headers_seen = {k.lower(): v for k, v in headers.items()}

    # ── Check for missing security headers ───────────────────────────────────
    for check in HEADER_CHECKS:
        if check["header"].lower() not in headers_seen:
            issues.append({
                "type"          : "missing_header",
                "header"        : check["header"],
                "short"         : check["short"],
                "severity"      : check["severity"],
                "description"   : check["description"],
                "recommendation": check["recommendation"],
            })

    # ── Check for leaky headers that should be removed ───────────────────────
    for leak in LEAKY_HEADERS:
        if leak["header"].lower() in headers_seen:
            value = headers_seen[leak["header"].lower()]
            issues.append({
                "type"          : "leaky_header",
                "header"        : leak["header"],
                "short"         : leak["header"],
                "severity"      : leak["severity"],
                "description"   : f"{leak['description']} (value: {value})",
                "recommendation": leak["recommendation"],
            })

    # ── Grade the headers A+ to F ────────────────────────────────────────────
    grade = _grade_headers(issues)

    return {
        "tool"        : "header_checker",
        "target"      : target,
        "url"         : url,
        "status"      : "success",
        "grade"       : grade,
        "issues"      : issues,
        "issue_count" : len(issues),
        "headers_seen": dict(headers),
    }


def _grade_headers(issues: list) -> str:
    """
    Grades the security header implementation A+ to F.
    Based on severity and count of missing headers.
    """
    critical_count = sum(1 for i in issues if i["severity"] == "Critical")
    high_count     = sum(1 for i in issues if i["severity"] == "High")
    medium_count   = sum(1 for i in issues if i["severity"] == "Medium")

    if critical_count > 0:
        return "F"
    elif high_count >= 2:
        return "D"
    elif high_count == 1:
        return "C"
    elif medium_count >= 2:
        return "B"
    elif medium_count == 1:
        return "B+"
    else:
        return "A+"


def _error_result(target: str, message: str) -> dict:
    return {
        "tool"        : "header_checker",
        "target"      : target,
        "status"      : "error",
        "error"       : message,
        "grade"       : "N/A",
        "issues"      : [],
        "issue_count" : 0,
        "headers_seen": {},
    }
