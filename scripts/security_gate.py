#!/usr/bin/env python3
"""
security_gate.py - deterministic security policy enforcement.

Reads the vulnerability intelligence report and decides whether
the current findings satisfy the configured security policy.

The gate intentionally performs no network calls.

Policy:
    - CRITICAL findings above MAX_CRITICAL -> FAIL
    - HIGH findings above MAX_HIGH -> FAIL
    - Any KEV-listed finding when FAIL_ON_KEV=true -> FAIL
    - Intelligence lookup failures -> FAIL
"""

import argparse
import json
import os
import sys


def load_report(path: str) -> list[dict]:
    """Load the enriched vulnerability report."""

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            "Risk report must contain a JSON list of findings."
        )

    return data


def print_summary(findings: list[dict]) -> dict[str, int]:
    """Print a human-readable finding summary."""

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    kev_count = 0
    partial_count = 0

    print(
        f"\n{'Package':<20} "
        f"{'CVE':<18} "
        f"{'CVSS':<6} "
        f"{'EPSS':<8} "
        f"{'KEV':<5} "
        f"{'Intel':<10} "
        f"{'Tier'}"
    )

    print("-" * 90)

    for finding in findings:
        tier = finding.get("risk_tier", "UNKNOWN")

        counts[tier] = counts.get(tier, 0) + 1

        if finding.get("kev_listed"):
            kev_count += 1

        if finding.get("intelligence_status") == "partial":
            partial_count += 1

        cve = (
            finding.get("cve_id")
            or finding.get("advisory_id", "?")
        )

        cvss = finding.get("cvss_score")
        epss = finding.get("epss_score")

        cvss_display = (
            f"{cvss:.1f}"
            if cvss is not None
            else "-"
        )

        epss_display = (
            f"{epss:.3f}"
            if epss is not None
            else "-"
        )

        kev_display = (
            "YES"
            if finding.get("kev_listed")
            else "-"
        )

        intelligence_display = (
            finding.get("intelligence_status", "unknown")
        )

        print(
            f"{finding.get('package', '?'):<20} "
            f"{cve:<18} "
            f"{cvss_display:<6} "
            f"{epss_display:<8} "
            f"{kev_display:<5} "
            f"{intelligence_display:<10} "
            f"{tier}"
        )

    print("-" * 90)

    print(
        f"Totals - "
        f"CRITICAL: {counts['CRITICAL']}  "
        f"HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  "
        f"LOW: {counts['LOW']}  "
        f"UNKNOWN: {counts['UNKNOWN']}  "
        f"(KEV-listed: {kev_count})"
    )

    print(
        f"Intelligence status: "
        f"{partial_count} finding(s) with partial enrichment\n"
    )

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the ThreatLens security policy."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="enriched risk report",
    )

    args = parser.parse_args()

    max_high = int(
        os.environ.get("MAX_HIGH", "3")
    )

    max_critical = int(
        os.environ.get("MAX_CRITICAL", "0")
    )

    fail_on_kev = (
        os.environ
        .get("FAIL_ON_KEV", "true")
        .lower()
        == "true"
    )

    findings = load_report(args.input)

    if not findings:
        print("No findings to evaluate. PASS.")
        return 0

    counts = print_summary(findings)

    kev_present = any(
        finding.get("kev_listed")
        for finding in findings
    )

    partial_intelligence = any(
        finding.get("intelligence_status") == "partial"
        for finding in findings
    )

    reasons: list[str] = []

    if counts["CRITICAL"] > max_critical:
        reasons.append(
            f"{counts['CRITICAL']} CRITICAL finding(s) "
            f"exceed the limit of {max_critical}"
        )

    if counts["HIGH"] > max_high:
        reasons.append(
            f"{counts['HIGH']} HIGH finding(s) "
            f"exceed the limit of {max_high}"
        )

    if fail_on_kev and kev_present:
        reasons.append(
            "one or more findings are on the CISA KEV catalog"
        )

    if partial_intelligence:
        reasons.append(
            "one or more findings could not be fully enriched "
            "with vulnerability intelligence"
        )

    if reasons:
        print("Security gate: FAIL")

        for reason in reasons:
            print(f"  - {reason}")

        return 1

    print("Security gate: PASS")

    return 0


if __name__ == "__main__":
    sys.exit(main())
