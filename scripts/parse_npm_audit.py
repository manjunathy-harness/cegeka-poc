#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys

FIELD_SEP = "##"
RECORD_SEP = "@@@"

# Remove characters that can interfere with our delimiters.
_SANITIZE_RE = re.compile(r"[#@<>+\r\n\t]")


def sanitize(value, max_len=180):
    if value is None:
        value = ""

    value = str(value)

    value = _SANITIZE_RE.sub(" ", value)

    value = re.sub(r"\s+", " ", value).strip()

    if len(value) > max_len:
        value = value[: max_len - 3] + "..."

    return value


def advisory_id_from(via_entry):
    url = via_entry.get("url", "") or ""

    match = re.search(
        r"(GHSA-[a-z0-9-]+)",
        url,
        re.IGNORECASE,
    )

    if match:
        return match.group(1).upper()

    source = via_entry.get("source")

    if source:
        return f"NPM-ADVISORY-{source}"

    return "UNKNOWN-ADVISORY"


def normalize_severity(raw_severity, cvss_score):
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


def extract_records(audit_report):
    vulnerabilities = audit_report.get("vulnerabilities", {}) or {}

    seen = set()

    for package_name, pkg_info in vulnerabilities.items():

        if not isinstance(pkg_info, dict):
            continue

        via_list = pkg_info.get("via", []) or []

        for via_entry in via_list:

            if not isinstance(via_entry, dict):
                continue

            advisory_id = advisory_id_from(via_entry)

            dedupe_key = (
                advisory_id,
                package_name,
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            cvss = via_entry.get("cvss") or {}

            cvss_score = cvss.get("score")

            if cvss_score in (None, ""):
                cvss_score = "n/a"

            raw_severity = (
                via_entry.get("severity")
                or pkg_info.get("severity")
                or ""
            )

            severity = normalize_severity(
                raw_severity,
                cvss_score,
            )

            package = (
                package_name
                or pkg_info.get("name")
                or "unknown"
            )

            vulnerable_range = (
                via_entry.get("range")
                or pkg_info.get("range")
                or "unknown"
            )

            title = (
                via_entry.get("title")
                or f"Vulnerability in {package}"
            )

            yield {
                "advisory_id": advisory_id,
                "severity": severity,
                "package": package,
                "range": vulnerable_range,
                "cvss_score": cvss_score,
                "title": title,
            }


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
        5,
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "report_path"
    )

    parser.add_argument(
        "release_name",
        nargs="?",
        default=os.environ.get(
            "RELEASE_NAME",
            "unspecified-release",
        ),
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
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    args = parser.parse_args()

    with open(
        args.report_path,
        "r",
        encoding="utf-8",
    ) as f:
        audit_report = json.load(f)

    records = list(
        extract_records(audit_report)
    )

    records.sort(
        key=lambda r: (
            severity_rank(r["severity"]),
            r["package"],
            r["advisory_id"],
        )
    )

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

    if args.limit:
        records = records[:args.limit]

    # ---------------------------------------------------------
    # Flatten each vulnerability into:
    #
    # ADVISORY##SEVERITY##PACKAGE##RANGE##CVSS##TITLE
    # ---------------------------------------------------------

    flattened = []

    for record in records:

        fields = [
            sanitize(
                record["advisory_id"],
                60,
            ),
            sanitize(
                record["severity"],
                20,
            ),
            sanitize(
                record["package"],
                80,
            ),
            sanitize(
                record["range"],
                60,
            ),
            sanitize(
                record["cvss_score"],
                20,
            ),
            sanitize(
                record["title"],
                120,
            ),
        ]

        flattened.append(
            FIELD_SEP.join(fields)
        )

    # ---------------------------------------------------------
    # Split vulnerabilities into small chunks.
    #
    # 10 records per output variable.
    #
    # This prevents one large output variable from becoming
    # problematic when passed into the Jira Repeat strategy.
    # ---------------------------------------------------------

    chunk_size = 10

    chunks = [
        flattened[i:i + chunk_size]
        for i in range(
            0,
            len(flattened),
            chunk_size,
        )
    ]

    # Always create five variables so the Harness YAML can
    # reference the same variables every time.
    while len(chunks) < 5:
        chunks.append([])

    # ---------------------------------------------------------
    # Harness outputs
    # ---------------------------------------------------------

    print(
        f"RELEASE_NAME={args.release_name}"
    )

    print(
        f"VULN_COUNT={len(records)}"
    )

    for index in range(5):

        chunk = chunks[index]

        value = RECORD_SEP.join(chunk)

        print(
            f"VULN_ITEMS_{index + 1}={value}"
        )

    # ---------------------------------------------------------
    # Human-readable log
    # ---------------------------------------------------------

    print(
        "",
        file=sys.stderr,
    )

    print(
        "============================================================",
        file=sys.stderr,
    )

    print(
        f"Found {len(records)} vulnerabilities "
        f"for release '{args.release_name}'",
        file=sys.stderr,
    )

    print(
        "============================================================",
        file=sys.stderr,
    )

    for record in records:

        print(
            f"[{record['severity']}] "
            f"{record['advisory_id']} - "
            f"{record['package']} - "
            f"CVSS: {record['cvss_score']} - "
            f"{record['title']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
