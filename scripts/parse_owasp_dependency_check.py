#!/usr/bin/env python3
"""
parse_owasp_dependency_check.py  (BONUS / OPTIONAL - not wired into the demo pipeline by default)

The main demo pipeline drives the Jira automation off `npm audit --json`
(see parse_npm_audit.py) because that file is 100% guaranteed to exist at a
known path with a known schema, which matters for a live demo.

The real OWASP Dependency-Check CLI (the same scanner Harness STO's OWASP
step wraps) can also emit a JSON report if you pass `--format JSON` in the
step's "Additional CLI flags" field. If you confirm where your Harness
account writes that file (check the OWASP step's logs/artifacts after a run
- the exact shared path can vary by STO version/image), you can point this
script at it instead and get the exact same RELEASE_NAME / VULN_COUNT /
VULN_ITEMS output contract that the pipeline's Jira automation stage
expects - so swapping this in later requires no changes to the pipeline
YAML, only to which parser script the "Parse_Vulnerabilities" step calls.

OWASP Dependency-Check JSON report shape (dependency-check-report.json):
  {
    "dependencies": [
      {
        "fileName": "...",
        "packages": [{"id": "pkg:npm/lodash@4.17.15", ...}],
        "vulnerabilities": [
          {
            "name": "CVE-2020-8203",
            "severity": "High",
            "cvssv3": {"baseScore": 7.4},
            "description": "..."
          },
          ...
        ]
      },
      ...
    ]
  }

Usage:
  python3 parse_owasp_dependency_check.py <path-to-dependency-check-report.json> [release_name]
"""
import argparse
import json
import os
import re
import sys

FIELD_SEP = "##"
RECORD_SEP = "@@@"
_SANITIZE_RE = re.compile(r"[#@\r\n\t]")


def sanitize(value, max_len=180):
    if value is None:
        value = ""
    value = str(value)
    value = _SANITIZE_RE.sub(" ", value)
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > max_len:
        value = value[: max_len - 3] + "..."
    return value


def severity_rank(severity):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    return order.get((severity or "UNKNOWN").upper(), 5)


def component_name(dependency):
    packages = dependency.get("packages") or []
    if packages and packages[0].get("id"):
        return packages[0]["id"]
    return dependency.get("fileName", "unknown-component")


def extract_records(report):
    for dependency in report.get("dependencies", []) or []:
        component = component_name(dependency)
        for vuln in dependency.get("vulnerabilities", []) or []:
            cvssv3 = vuln.get("cvssv3") or {}
            cvssv2 = vuln.get("cvssv2") or {}
            score = cvssv3.get("baseScore", cvssv2.get("score", "n/a"))
            yield {
                "advisory_id": vuln.get("name", "UNKNOWN-CVE"),
                "severity": (vuln.get("severity") or "unknown").upper(),
                "package": component,
                "range": "",  # dependency-check doesn't report a semver range the way npm audit does
                "cvss_score": score,
                "title": vuln.get("description", f"Vulnerability in {component}"),
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_path")
    parser.add_argument("release_name", nargs="?", default=os.environ.get("RELEASE_NAME", "unspecified-release"))
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    with open(args.report_path, "r") as f:
        report = json.load(f)

    records = list(extract_records(report))
    records.sort(key=lambda r: (severity_rank(r["severity"]), r["package"]))

    if args.min_severity:
        max_rank = severity_rank(args.min_severity)
        records = [r for r in records if severity_rank(r["severity"]) <= max_rank]
    if args.limit:
        records = records[: args.limit]

    flattened = [
        FIELD_SEP.join(
            [
                sanitize(r["advisory_id"], 40),
                sanitize(r["severity"], 20),
                sanitize(r["package"], 80),
                sanitize(r["range"], 40),
                sanitize(r["cvss_score"], 10),
                sanitize(r["title"], 140),
            ]
        )
        for r in records
    ]

    print(f"RELEASE_NAME={args.release_name}")
    print(f"VULN_COUNT={len(records)}")
    print(f"VULN_ITEMS={RECORD_SEP.join(flattened)}")

    print(f"\n--- {len(records)} distinct vulnerabilities found for release '{args.release_name}' ---", file=sys.stderr)
    for r in records:
        print(f"[{r['severity']}] {r['advisory_id']} - {r['package']} - {r['title']}", file=sys.stderr)


if __name__ == "__main__":
    main()
