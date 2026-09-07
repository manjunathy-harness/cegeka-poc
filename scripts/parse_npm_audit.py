#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys

FIELD_SEP = "|||"
RECORD_SEP = "@@@"

_SANITIZE_RE = re.compile(r"[|@<>+\r\n\t]")


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
        re.IGNORECASE
    )

    if match:
        return match.group(1).upper()

    source = via_entry.get("source")

    if source:
        return f"NPM-ADVISORY-{source}"

    return "UNKNOWN-ADVISORY"


def extract_records(audit_report):
    vulnerabilities = audit_report.get("vulnerabilities", {}) or {}

    seen_advisory_ids = set()

    for package_name, pkg_info in vulnerabilities.items():

        via_list = pkg_info.get("via", []) or []

        for via_entry in via_list:

            if not isinstance(via_entry, dict):
                continue

            advisory_id = advisory_id_from(via_entry)

            dedupe_key = (advisory_id, package_name)

            if dedupe_key in seen_advisory_ids:
                continue

            seen_advisory_ids.add(dedupe_key)

            cvss = via_entry.get("cvss") or {}

            severity = (
                via_entry.get("severity")
                or pkg_info.get("severity")
                or "unknown"
            )

            yield {
                "advisory_id": advisory_id,
                "severity": str(severity).upper(),
                "package": package_name,
                "range": (
                    via_entry.get("range")
                    or pkg_info.get("range")
                    or "unknown"
                ),
                "cvss_score": cvss.get("score", "n/a"),
                "title": via_entry.get(
                    "title",
                    f"Vulnerability in {package_name}"
                ),
                "url": via_entry.get("url", ""),
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
        severity.upper(),
        5
    )


def main():

    parser = argparse.ArgumentParser(
        description="Parse npm audit JSON report"
    )

    parser.add_argument(
        "report_path"
    )

    parser.add_argument(
        "release_name",
        nargs="?",
        default=os.environ.get(
            "RELEASE_NAME",
            "unspecified-release"
        )
    )

    parser.add_argument(
        "--min-severity",
        choices=[
            "low",
            "moderate",
            "medium",
            "high",
            "critical"
        ],
        default=None
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None
    )

    args = parser.parse_args()

    with open(args.report_path, "r") as f:
        audit_report = json.load(f)

    records = list(
        extract_records(audit_report)
    )

    records.sort(
        key=lambda r: (
            severity_rank(r["severity"]),
            r["package"]
        )
    )

    if args.min_severity:

        max_rank = severity_rank(
            args.min_severity.upper()
        )

        records = [
            r
            for r in records
            if severity_rank(
                r["severity"]
            ) <= max_rank
        ]

    if args.limit:
        records = records[:args.limit]

    flattened = []

    for r in records:

        fields = [
            sanitize(
                r["advisory_id"],
                40
            ),
            sanitize(
                r["severity"],
                20
            ),
            sanitize(
                r["package"],
                60
            ),
            sanitize(
                r["range"],
                40
            ),
            sanitize(
                r["cvss_score"],
                10
            ),
            sanitize(
                r["title"],
                140
            ),
        ]

        flattened.append(
            FIELD_SEP.join(fields)
        )

    vuln_items = RECORD_SEP.join(
        flattened
    )

    print(
        f"RELEASE_NAME={args.release_name}"
    )

    print(
        f"VULN_COUNT={len(records)}"
    )

    print(
        f"VULN_ITEMS={vuln_items}"
    )

    print(
        f"\n--- {len(records)} distinct vulnerabilities found for release '{args.release_name}' ---",
        file=sys.stderr
    )

    for r in records:

        print(
            f"[{r['severity']}] "
            f"{r['advisory_id']} - "
            f"{r['package']} "
            f"({r['range']}) - "
            f"{r['title']}",
            file=sys.stderr
        )


if __name__ == "__main__":
    main()
