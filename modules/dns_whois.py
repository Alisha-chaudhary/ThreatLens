import dns.resolver
import whois
from datetime import datetime


def run_dns_whois_check(target: str) -> dict:
    """
    Runs WHOIS lookup and DNS checks for SPF, DMARC, DKIM.
    Returns structured findings.
    """
    results = {}

    results["whois"]  = _run_whois(target)
    results["spf"]    = _check_spf(target)
    results["dmarc"]  = _check_dmarc(target)
    results["dkim"]   = _check_dkim(target)
    results["mx"]     = _check_mx(target)

    issues  = _analyse(results, target)

    return {
        "tool"       : "dns_whois",
        "target"     : target,
        "status"     : "success",
        "whois"      : results["whois"],
        "spf"        : results["spf"],
        "dmarc"      : results["dmarc"],
        "dkim"       : results["dkim"],
        "mx"         : results["mx"],
        "issues"     : issues,
        "issue_count": len(issues),
    }


# ── WHOIS ─────────────────────────────────────────────────────────────────────
def _run_whois(target: str) -> dict:
    try:
        w = whois.whois(target)

        # domain age calculation
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = None
        if creation:
            age_days = (datetime.now() - creation).days

        return {
            "status"      : "success",
            "registrar"   : w.registrar      or "Unknown",
            "creation_date": str(creation)   or "Unknown",
            "expiry_date" : str(w.expiration_date) or "Unknown",
            "age_days"    : age_days,
            "country"     : w.country        or "Unknown",
            "name_servers": w.name_servers   or [],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── SPF ───────────────────────────────────────────────────────────────────────
def _check_spf(target: str) -> dict:
    """
    SPF record tells receiving mail servers which IPs are
    allowed to send email for this domain.
    """
    try:
        answers = dns.resolver.resolve(target, "TXT")
        for record in answers:
            text = record.to_text().strip('"')
            if text.startswith("v=spf1"):
                return {
                    "status" : "found",
                    "record" : text,
                    "present": True,
                }
        return {
            "status" : "missing",
            "record" : None,
            "present": False,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "present": False}


# ── DMARC ─────────────────────────────────────────────────────────────────────
def _check_dmarc(target: str) -> dict:
    """
    DMARC tells receiving servers what to do when SPF/DKIM fail.
    Checked at _dmarc.domain.com
    """
    try:
        answers = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
        for record in answers:
            text = record.to_text().strip('"')
            if "v=DMARC1" in text:
                # check policy strength
                policy = "none"
                if "p=reject" in text:
                    policy = "reject"
                elif "p=quarantine" in text:
                    policy = "quarantine"
                return {
                    "status" : "found",
                    "record" : text,
                    "policy" : policy,
                    "present": True,
                }
        return {
            "status" : "missing",
            "record" : None,
            "present": False,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "present": False}


# ── DKIM ──────────────────────────────────────────────────────────────────────
def _check_dkim(target: str) -> dict:
    """
    DKIM adds a cryptographic signature to emails.
    We check common selectors since the selector name varies.
    """
    COMMON_SELECTORS = [
        "default", "google", "mail", "email",
        "dkim", "k1", "selector1", "selector2"
    ]
    for selector in COMMON_SELECTORS:
        try:
            dns.resolver.resolve(
                f"{selector}._domainkey.{target}", "TXT"
            )
            return {
                "status"  : "found",
                "selector": selector,
                "present" : True,
            }
        except Exception:
            continue

    return {
        "status" : "not_found",
        "present": False,
        "note"   : "No common DKIM selectors found. "
                   "Custom selector may still exist.",
    }


# ── MX Records ────────────────────────────────────────────────────────────────
def _check_mx(target: str) -> dict:
    """Checks if domain has mail exchange records configured."""
    try:
        answers = dns.resolver.resolve(target, "MX")
        records = [str(r.exchange) for r in answers]
        return {
            "status" : "found",
            "records": records,
            "present": True,
        }
    except Exception as e:
        return {
            "status" : "error",
            "error"  : str(e),
            "present": False,
        }


# ── Analysis — convert raw results into issues ────────────────────────────────
def _analyse(results: dict, target: str) -> list:
    issues = []

    # WHOIS — young domain = higher phishing risk
    whois_data = results.get("whois", {})
    age_days   = whois_data.get("age_days")
    if age_days is not None and age_days < 180:
        issues.append({
            "severity"      : "High",
            "title"         : f"Domain is only {age_days} days old",
            "description"   : "Very young domains are commonly used for "
                              "phishing and fraud campaigns.",
            "recommendation": "Treat emails from this domain with high "
                              "suspicion. Verify legitimacy independently.",
            "source"        : "whois",
        })

    # SPF missing
    if not results["spf"].get("present"):
        issues.append({
            "severity"      : "High",
            "title"         : "SPF record missing",
            "description"   : "Without SPF, anyone can send email "
                              "pretending to be from this domain.",
            "recommendation": "Add a TXT record: "
                              "v=spf1 include:_spf.yourmailprovider.com ~all",
            "source"        : "dns",
        })

    # DMARC missing
    if not results["dmarc"].get("present"):
        issues.append({
            "severity"      : "High",
            "title"         : "DMARC record missing",
            "description"   : "Without DMARC, spoofed emails from this "
                              "domain will be delivered to recipients.",
            "recommendation": "Add a TXT record at _dmarc.yourdomain.com: "
                              "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
            "source"        : "dns",
        })

    # DMARC weak policy
    elif results["dmarc"].get("policy") == "none":
        issues.append({
            "severity"      : "Medium",
            "title"         : "DMARC policy set to 'none' — not enforced",
            "description"   : "DMARC exists but p=none means spoofed emails "
                              "are still delivered, just reported.",
            "recommendation": "Upgrade DMARC policy to p=quarantine "
                              "or p=reject.",
            "source"        : "dns",
        })

    # DKIM missing
    if not results["dkim"].get("present"):
        issues.append({
            "severity"      : "Medium",
            "title"         : "DKIM record not found",
            "description"   : "No DKIM signature detected on common selectors. "
                              "Emails cannot be cryptographically verified.",
            "recommendation": "Enable DKIM signing in your mail provider "
                              "and publish the public key as a DNS TXT record.",
            "source"        : "dns",
        })

    # MX present but no email protection
    has_mx  = results["mx"].get("present", False)
    has_spf = results["spf"].get("present", False)
    if has_mx and not has_spf:
        issues.append({
            "severity"      : "Critical",
            "title"         : "Domain accepts email but has no SPF protection",
            "description"   : "MX records exist meaning this domain receives "
                              "email, but SPF is missing. High spoofing risk.",
            "recommendation": "Immediately add SPF record to prevent "
                              "email spoofing.",
            "source"        : "dns",
        })

    return issues
