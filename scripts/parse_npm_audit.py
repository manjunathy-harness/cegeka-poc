#!/usr/bin/env python3

"""
parse_npm_audit.py

Reads an npm audit --json report and converts vulnerabilities into
flat records that can be consumed by a Harness Repeat strategy.

Output:

RELEASE_NAME=<release name>
VULN_COUNT=<number of vulnerabilities>
VULN_ITEMS=<record1@@@record2@@@record3>

Each record contains 6 fields separated by "~":

ADVISORY_ID~SEVERITY~PACKAGE~VULNERABLE_RANGE~CVSS_SCORE~TITLE

Example:

GHSA-XXXX~HIGH~axios~<1.8.2~7.5~Axios vulnerability
"""

import argparse
import json
import os
import re
import sys


# ---------------------------------------------------------
# Safe separators
# ---------------------------------------------------------
FIELD_SEP = "~"
RECORD_SEP = "@@@"

# Remove characters that can break our delimiter scheme.
SANITIZE_RE = re.compile(r"[~@#<>+\r\n\t]")


# ---------------------------------------------------------
# Sanitize text
# ---------------------------------------------------------
def sanitize(value, max_len=180):
    if value is None:
        value = ""

    value = str(value)

    value = SANITIZE_RE.sub(" ", value)

    value = re.sub(r"\s+", " ", value).strip()

    if len(value) > max_len:
        value = value[: max_len - 3] + "..."

    return value


# ---------------------------------------------------------
# Extract advisory ID
# ---------------------------------------------------------
def advisory_id_from(via_entry):
    url = via_entry.get("url", "") or ""

    match = re.search(
        r"(GHSA-[a-z0-9-]+)",
        url,
        re.IGNORECASE
    )

    if match:
        return match.group(1).upper()

    source = via_entry.get("source")

    if source:
        return f"NPM-ADVISORY-{source}"

    return "UNKNOWN-ADVISORY"


# ---------------------------------------------------------
# Convert severity to normalized value
# ---------------------------------------------------------
def normalize_severity(raw_severity, cvss_score=None):
    """
    Resolve severity using:

    1. npm advisory severity
    2. package severity
    3. CVSS score fallback
    4. UNKNOWN
    """

    severity = str(raw_severity or "").strip().upper()

    valid = {
        "CRITICAL",
        "HIGH",
        "MODERATE",
        "MEDIUM",
        "LOW",
        "INFO",
    }

    if severity in valid:
        return severity

    # -----------------------------------------------------
    # Fallback to CVSS
    # -----------------------------------------------------
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        score = None

    if score is not None:
        if score >= 9.0:
            return "CRITICAL"

        if score >= 7.0:
            return "HIGH"

        if score >= 4.0:
            return "MODERATE"

        return "LOW"

    return "UNKNOWN"


# ---------------------------------------------------------
# Extract vulnerability records
# ---------------------------------------------------------
def extract_records(audit_report):
    vulnerabilities = (
        audit_report.get("vulnerabilities", {})
        or {}
    )

    seen = set()

    for package_name, pkg_info in vulnerabilities.items():

        if not isinstance(pkg_info, dict):
            continue

        via_list = (
            pkg_info.get("via", [])
            or []
        )

        for via_entry in via_list:

            # npm audit `via` can contain strings
            # representing transitive package references.
            if not isinstance(via_entry, dict):
                continue

            advisory_id = advisory_id_from(
                via_entry
            )

            dedupe_key = (
                advisory_id,
                package_name
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            # -------------------------------------------------
            # CVSS
            # -------------------------------------------------
            cvss = via_entry.get("cvss") or {}

            cvss_score = cvss.get("score")

            if cvss_score in (None, ""):
                cvss_score = "n/a"

            # -------------------------------------------------
            # Severity
            # -------------------------------------------------
            raw_severity = (
                via_entry.get("severity")
                or pkg_info.get("severity")
                or ""
            )

            severity = normalize_severity(
                raw_severity,
                cvss_score
            )

            # -------------------------------------------------
            # Package
            # -------------------------------------------------
            package = (
                package_name
                or pkg_info.get("name")
                or "unknown"
            )

            # -------------------------------------------------
            # Vulnerable range
            # -------------------------------------------------
            vulnerable_range = (
                via_entry.get("range")
                or pkg_info.get("range")
                or "unknown"
            )

            # -------------------------------------------------
            # Title
            # -------------------------------------------------
            title = (
                via_entry.get("title")
                or via_entry.get("name")
                or f"Vulnerability in {package}"
            )

            # -------------------------------------------------
            # URL
            # -------------------------------------------------
            url = via_entry.get("url", "") or ""

            yield {
                "advisory_id": advisory_id,
                "severity": severity,
                "package": package,
                "range": vulnerable_range,
                "cvss_score": cvss_score,
                "title": title,
                "url": url,
            }


# ---------------------------------------------------------
# Severity ranking
# ---------------------------------------------------------
def severity_rank(severity):
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MODERATE": 2,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }

    return order.get(
        str(severity).upper(),
        5
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "report_path",
        help="Path to npm audit JSON file"
    )

    parser.add_argument(
        "release_name",
        nargs="?",
        default=os.environ.get(
            "RELEASE_NAME",
            "unspecified-release"
        ),
        help="Release name"
    )

    parser.add_argument(
        "--min-severity",
        choices=[
            "low",
            "moderate",
            "medium",
            "high",
            "critical",
        ],
        default=None,
        help="Minimum severity to include"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of vulnerabilities"
    )

    args = parser.parse_args()

    # -----------------------------------------------------
    # Read audit report
    # -----------------------------------------------------
    with open(
        args.report_path,
        "r",
        encoding="utf-8"
    ) as f:
        audit_report = json.load(f)

    # -----------------------------------------------------
    # Extract records
    # -----------------------------------------------------
    records = list(
        extract_records(audit_report)
    )

    # -----------------------------------------------------
    # Sort highest severity first
    # -----------------------------------------------------
    records.sort(
        key=lambda r: (
            severity_rank(r["severity"]),
            r["package"],
            r["advisory_id"],
        )
    )

    # -----------------------------------------------------
    # Minimum severity filter
    # -----------------------------------------------------
    if args.min_severity:

        minimum_rank = severity_rank(
            args.min_severity.upper()
        )

        records = [
            record
            for record in records
            if severity_rank(
                record["severity"]
            ) <= minimum_rank
        ]

    # -----------------------------------------------------
    # Limit number of vulnerabilities
    # -----------------------------------------------------
    if args.limit:
        records = records[:args.limit]

    # -----------------------------------------------------
    # Flatten records
    # -----------------------------------------------------
    flattened_records = []

    for record in records:

        fields = [
            sanitize(
                record["advisory_id"],
                60
            ),

            sanitize(
                record["severity"],
                20
            ),

            sanitize(
                record["package"],
                80
            ),

            sanitize(
                record["range"],
                60
            ),

            sanitize(
                record["cvss_score"],
                20
            ),

            sanitize(
                record["title"],
                180
            ),
        ]

        flattened_records.append(
            FIELD_SEP.join(fields)
        )

    vuln_items = RECORD_SEP.join(
        flattened_records
    )

    # -----------------------------------------------------
    # Harness output variables
    # -----------------------------------------------------
    print(
        f"RELEASE_NAME={args.release_name}"
    )

    print(
        f"VULN_COUNT={len(records)}"
    )

    print(
        f"VULN_ITEMS={vuln_items}"
    )

    # -----------------------------------------------------
    # Human-readable log
    # -----------------------------------------------------
    print(
        "",
        file=sys.stderr
    )

    print(
        "============================================================",
        file=sys.stderr
    )

    print(
        f"Found {len(records)} vulnerabilities "
        f"for release '{args.release_name}'",
        file=sys.stderr
    )

    print(
        "============================================================",
        file=sys.stderr
    )

    for record in records:

        print(
            f"[{record['severity']}] "
            f"{record['advisory_id']} - "
            f"{record['package']} - "
            f"CVSS: {record['cvss_score']} - "
            f"{record['title']}",
            file=sys.stderr
        )


if __name__ == "__main__":
    main()
