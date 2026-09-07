#!/usr/bin/env python3
"""
parse_npm_audit.py

Reads an `npm audit --json` report and flattens every distinct vulnerability
(advisory) it found into a single delimited string that a Harness "Repeat"
looping strategy can iterate over directly - no custom Jira API calls needed,
just Harness's built-in Jira Create step.

Why flatten into delimited strings instead of leaving it as JSON?
Harness pipeline expressions can do `<+ someVar.split("delimiter") >` and
`<+ someVar.split("delimiter")[0] >` (this is officially documented Harness
expression syntax), but they cannot walk arbitrary nested JSON out of the
box. Flattening here, once, in a script we control, means the pipeline YAML
only ever has to do simple string splitting.

Output: prints KEY=VALUE lines to stdout:
  RELEASE_NAME=<release name>
  VULN_COUNT=<number of distinct advisories found>
  VULN_ITEMS=<all advisories, joined by RECORD_SEP>

Each item in VULN_ITEMS has 6 fields joined by FIELD_SEP, in this order:
  ADVISORY_ID | SEVERITY | PACKAGE | VULNERABLE_RANGE | CVSS_SCORE | TITLE

The Harness pipeline step that runs this script must `export` these three
values as environment variables so they can be declared as the Run step's
outputVariables (RELEASE_NAME, VULN_COUNT, VULN_ITEMS) - see harness-pipeline.yaml.

Usage:
  python3 parse_npm_audit.py <path-to-npm-audit.json> [release_name]

  release_name defaults to the RELEASE_NAME environment variable, then to
  "unspecified-release" if that isn't set either.
"""
import argparse
import json
import os
import re
import sys

FIELD_SEP = "##"
RECORD_SEP = "@@@"

# Anything that could break our delimiter scheme or the shell/YAML around it
# gets stripped out of free-text fields (title/description).
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
    match = re.search(r"(GHSA-[a-z0-9-]+)", url, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    source = via_entry.get("source")
    if source:
        return f"NPM-ADVISORY-{source}"
    return "UNKNOWN-ADVISORY"


def extract_records(audit_report):
    """Yields one record dict per distinct advisory found in the report."""
    vulnerabilities = audit_report.get("vulnerabilities", {}) or {}
    seen_advisory_ids = set()

    for package_name, pkg_info in vulnerabilities.items():
        via_list = pkg_info.get("via", []) or []
        for via_entry in via_list:
            # `via` mixes dicts (real advisories) with plain strings
            # (just a transitive package name reference) - skip the strings.
            if not isinstance(via_entry, dict):
                continue

            advisory_id = advisory_id_from(via_entry)
            dedupe_key = (advisory_id, package_name)
            if dedupe_key in seen_advisory_ids:
                continue
            seen_advisory_ids.add(dedupe_key)

            cvss = via_entry.get("cvss") or {}
            yield {
                "advisory_id": advisory_id,
                "severity": (via_entry.get("severity") or pkg_info.get("severity") or "unknown").upper(),
                "package": package_name,
                "range": via_entry.get("range", pkg_info.get("range", "")),
                "cvss_score": cvss.get("score", "n/a"),
                "title": via_entry.get("title", f"Vulnerability in {package_name}"),
                "url": via_entry.get("url", ""),
            }


def severity_rank(severity):
    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    return order.get(severity.upper(), 5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_path", help="Path to the npm audit --json output file")
    parser.add_argument(
        "release_name",
        nargs="?",
        default=os.environ.get("RELEASE_NAME", "unspecified-release"),
        help="Release name to stamp on the parent ticket (default: $RELEASE_NAME env var)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "moderate", "medium", "high", "critical"],
        default=None,
        help="Only include vulnerabilities at or above this severity. "
        "Recommended for LIVE DEMOS - a real npm audit report can easily contain "
        "30-50+ advisories, and filing that many Jira sub-tasks on stage is slow "
        "and can trip Jira API rate limits. Try --min-severity high for a demo.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only include the top N vulnerabilities (highest severity first) after filtering. "
        "Also useful for keeping a live demo fast, e.g. --limit 5.",
    )
    args = parser.parse_args()

    with open(args.report_path, "r") as f:
        audit_report = json.load(f)

    records = list(extract_records(audit_report))
    records.sort(key=lambda r: (severity_rank(r["severity"]), r["package"]))

    if args.min_severity:
        max_rank = severity_rank(args.min_severity.upper())
        records = [r for r in records if severity_rank(r["severity"]) <= max_rank]

    if args.limit:
        records = records[: args.limit]

    release_name = args.release_name

    flattened = []
    for r in records:
        fields = [
            sanitize(r["advisory_id"], 40),
            sanitize(r["severity"], 20),
            sanitize(r["package"], 60),
            sanitize(r["range"], 40),
            sanitize(r["cvss_score"], 10),
            sanitize(r["title"], 140),
        ]
        flattened.append(FIELD_SEP.join(fields))

    vuln_items = RECORD_SEP.join(flattened)

    # KEY=VALUE lines - the calling shell step greps these out and `export`s
    # them so Harness can capture them as declared outputVariables.
    print(f"RELEASE_NAME={release_name}")
    print(f"VULN_COUNT={len(records)}")
    print(f"VULN_ITEMS={vuln_items}")

    # Also dump a human-readable summary to stderr for the live demo /
    # pipeline logs, so you have something to narrate on screen.
    print(f"\n--- {len(records)} distinct vulnerabilities found for release '{release_name}' ---", file=sys.stderr)
    for r in records:
        print(f"[{r['severity']}] {r['advisory_id']} - {r['package']} ({r['range']}) - {r['title']}", file=sys.stderr)


if __name__ == "__main__":
    main()
