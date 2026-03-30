import subprocess
import re
import os


TESTSSL_SEARCH_PATHS = [
    os.environ.get("TESTSSL_PATH", ""),          # env var takes priority
    "/home/alissa/testssl.sh/testssl.sh",        # your local path
    "/opt/testssl/testssl.sh",                   # common install location
    "/usr/local/bin/testssl.sh",                 # system-wide install
    "testssl.sh",                                # if it's in PATH
]

def _find_testssl() -> str | None:
    """
    Searches known locations for testssl.sh.
    Returns the first valid path found, or None if not found.
    """
    for path in TESTSSL_SEARCH_PATHS:
        if path and os.path.isfile(path):
            return path
    # also check if it's callable from PATH directly
    try:
        subprocess.run(
            ["testssl.sh", "--version"],
            capture_output=True, timeout=5
        )
        return "testssl.sh"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def run_ssl_check(target: str) -> dict:
    """
    Runs testssl.sh to detect weak SSL/TLS configs.
    Returns structured findings, or a clear status if tool is missing.
    """

    testssl_path =_find_testssl()
    # ── Tool not installed — return a clean not_installed status ─────────────
    if testssl_path is None:
        return {
            "tool"       : "testssl",
            "target"     : target,
            "status"     : "not_installed",
            "error"      : "testssl.sh not found. Install it or set TESTSSL_PATH.",
            "issues"     : [],
            "issue_count": 0,
        }   

    try:
        
        result = subprocess.run(
            [testssl_path, "--quiet", "--color", "0", target],
            capture_output=True,
            text=True,
            timeout=180
        )
        # testssl writes errors to stderr — check for them
        if result.returncode != 0 and not result.stdout.strip():
            return _error_result(
                "testssl", target,
                f"testssl exited with code {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )
        return _parse_testssl_output(result.stdout, target)

    except FileNotFoundError:
        return _error_result("testssl", target, "testssl.sh is not installed")
    except subprocess.TimeoutExpired:
        return _error_result("testssl", target, "SSL check timed out after 180s")
    except Exception as e:
        return _error_result("testssl", target, f"Unexpected error: {str(e)}")

def _parse_testssl_output(raw: str, target: str) -> dict:
    """Scans testssl output for known weak patterns and flags them."""
    issues = []

    checks = [
        ("TLSv1.0",         "Weak protocol TLSv1.0 supported",          "High"),
        ("TLSv1.1",         "Weak protocol TLSv1.1 supported",          "High"),
        ("SSLv3",           "Critically weak SSLv3 enabled",            "Critical"),
        ("RC4",             "Broken cipher RC4 in use",                 "High"),
        ("MD5",             "Weak MD5 signature algorithm detected",    "Medium"),
        ("SWEET32",         "SWEET32 birthday attack vulnerability",    "Medium"),
        ("POODLE",          "POODLE attack vulnerability detected",     "High"),
        ("HEARTBLEED",      "Heartbleed vulnerability detected",        "Critical"),
        ("expired",         "SSL certificate is expired",               "Critical"),
        ("self signed",     "Self-signed certificate in use",           "Medium"),
        ("HSTS",            "Missing HSTS header",                      "Low"),
    ]

    for keyword, description, severity in checks:
        if keyword.lower() in raw.lower():
            issues.append({
                "keyword"    : keyword,
                "description": description,
                "severity"   : severity,
            })
     # ── Ran successfully but found nothing ───────────────────────────────────
    note = "" if not issues else None

    return {
        "tool"       : "testssl",
        "target"     : target,
        "status"     : "success",
        "note"       : note,
        "issues"     : issues,
        "issue_count": len(issues),
    }


def _error_result(tool: str, target: str, message: str) -> dict:
    return {
        "tool"       : tool,
        "target"     : target,
        "status"     : "error",
        "error"      : message,
        "issues"     : [],
        "issue_count": 0,
    }
