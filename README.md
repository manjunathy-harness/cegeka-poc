# Harness CI/CD + STO (OWASP) + Jira automation demo

This package gives you a working Harness pipeline plus a small vulnerable
sample app, built to demo one specific flow: **when a security scan finds
new vulnerabilities, automatically file one parent Jira ticket named after
the release, with one child sub-task per vulnerability.**

## What's in here

```
sample-app/                          - throwaway Node.js app with old, known-vulnerable
                                        dependencies (lodash, minimist, axios, express),
                                        so a scan always has real CVEs to find
scripts/parse_npm_audit.py           - turns `npm audit --json` into the flattened
                                        string format the pipeline loops over
scripts/parse_owasp_dependency_check.py - same, but for the real OWASP Dependency-Check
                                        JSON report (optional upgrade path, see below)
harness-pipeline.yaml                - the full pipeline: build -> STO OWASP scan ->
                                        Jira automation
```

## The design, in one paragraph

The pipeline has two stages. **Build_And_Scan** builds the sample app, runs
Harness STO's native OWASP Dependency-Check step (so you get the real STO
scan, dashboard, and baseline tracking), and separately runs `npm audit
--json` + a parser script that flattens every distinct vulnerability into
one delimited string. **Jira_Automation** then uses Harness's built-in
**Jira Create** step twice: once to file the parent "release" ticket, and
once more wrapped in a **Repeat looping strategy** that iterates over the
flattened vulnerability list, creating one child sub-task per vulnerability
and linking each one back to the parent via Jira's `Parent` field. No
custom script calls the Jira API directly - ticket creation is 100% the
native Harness Jira step, exactly as you asked for.

## Why the Jira automation reads from `npm audit`, not the OWASP scan's own report file

This is worth explaining before your demo, because someone will ask.

Harness STO's OWASP Dependency-Check step writes its scan results into
Harness's own STO backend (visible in the STO UI/dashboard) - that part is
solid and is what's actually running in the pipeline for governance
purposes. But the *exact file path* where the underlying scanner also drops
its raw `dependency-check-report.json` inside the step's container can
differ by STO version/scanner image, and I can't verify that path against
your specific account from here. Getting it wrong would silently break the
Jira automation with no useful error.

`npm audit --json`, by contrast, is a stable, fully-documented, zero-config
command that's part of npm itself - no path-guessing required. So for the
part of this demo that absolutely has to work live (the Jira automation),
the pipeline parses that instead.

**Once you've run the pipeline once and confirmed where the real OWASP
report lands in your account** (check the OWASP step's logs/artifacts after
a run), switching the automation to use the real scan data is a one-line
change: point the `Parse_Vulnerabilities` step at
`scripts/parse_owasp_dependency_check.py <path-to-report> <release>`
instead of `parse_npm_audit.py`. Both scripts emit the exact same
`RELEASE_NAME` / `VULN_COUNT` / `VULN_ITEMS` output contract, so nothing
else in the pipeline needs to change.

## Before you run this

Replace these placeholders in `harness-pipeline.yaml`:

| Placeholder | What it is |
|---|---|
| `YOUR_HARNESS_PROJECT_ID` / `YOUR_HARNESS_ORG_ID` | Your Harness project/org |
| `YOUR_CODE_REPO_CONNECTOR` | A Harness connector to the repo containing `sample-app/` (push these files into a repo first) |
| `YOUR_JIRA_CONNECTOR` | A [Jira connector](https://developer.harness.io/docs/platform/connectors/ticketing-systems/connect-to-jira) |

You'll also be prompted at runtime for `release_name` and `jira_project_key`
(pipeline variables), since those are marked as runtime input.

**Three things to double-check in your account before the demo**, since
Harness's step schema can vary slightly by version and I couldn't fully
verify them against your specific account/plan from here:

1. **The OWASP Dependency-Check step's exact fields.** The YAML uses
   `type: Owasp` with `mode`, `config`, `target`, `advanced`, `privileged` -
   this mirrors Harness's own published pattern for other STO scanner steps
   (e.g. Aqua Trivy). The safest move: in Pipeline Studio, drag an **OWASP
   Dependency-Check** step onto the `Build_And_Scan` stage once, configure
   it in the visual editor, switch to YAML view, and reconcile any field
   differences against what's here.
2. **`Jira Create` in a Custom stage.** The `Jira_Automation` stage is typed
   `Custom` so it needs no dummy service/environment. Harness's docs
   explicitly confirm Jira Create works in CD and Approval stages; most
   current accounts also support it in Custom stages, but if it's missing
   from the step palette there, change `type: Custom` to `type: Approval`
   for that stage - same no-service/environment behavior, and it's
   explicitly documented to support Jira Create.
3. **Your Jira project's issue types.** `jira_child_issue_type` defaults to
   `Sub-task`, which requires `jira_parent_issue_type` (defaults to `Task`)
   to be a type Jira allows sub-tasks under. If your project uses different
   names, set the two pipeline variables accordingly at runtime.

## For a live demo: keep the vulnerability count small

A real `npm audit` on the sample app's pinned dependencies turns up **~45
distinct advisories** (I ran it while building this - lodash, minimist,
axios, and express all have a long history of CVEs). Filing 45 Jira
sub-tasks on stage is slow and can trip Jira API rate limits, so the
pipeline variable `min_severity_for_demo` (defaults to `high`) filters the
parser down to just High/Critical findings. Tighten it further with the
parser's `--limit N` flag (edit the `Parse_Vulnerabilities` step's command)
if you want an even smaller, snappier set for the live run - e.g. `--limit 3`
to guarantee exactly 3 child tickets.

## Demo script (suggested narration)

1. **"Here's a normal CI/CD pipeline"** - show the `Build_And_Scan` stage:
   clone, install, and the OWASP Dependency-Check step running as part of
   the build, no different from any other Harness pipeline.
2. **"This is the STO scan"** - after a run, open the **STO
   Vulnerabilities** tab for the step and show the findings in Harness's own
   security dashboard.
3. **"Now watch what happens automatically"** - switch to the
   `Jira_Automation` stage's execution. Point out the parent `Create_Parent_
   Release_Ticket` step running once, then the `Create_Child_Vulnerability_
   Ticket` step repeating - once per vulnerability - via the Repeat looping
   strategy (call out the iteration count in the step's execution list).
4. **"Here's the result in Jira"** - open the parent ticket and show the
   linked sub-tasks, each one titled with the CVE/advisory ID, severity, and
   affected package.
5. **"And it's all built-in Harness steps"** - no custom script talks to the
   Jira API; it's the native Jira Create step, looped.

## How the looping mechanism works (if asked)

Harness's `Run` steps can only export flat string output variables, not
JSON objects, so `Parse_Vulnerabilities` flattens every vulnerability into
one string using two delimiters: `##` between fields (advisory ID,
severity, package, range, CVSS score, title) and `@@@` between
vulnerabilities. The child Jira step then uses Harness's officially
documented `Repeat` looping strategy:

```yaml
strategy:
  repeat:
    items: <+ <+VULN_ITEMS_VARIABLE>.split("@@@") >
```

...and inside the loop, `<+repeat.item>` holds one vulnerability's
delimited string per iteration, with individual fields pulled out via
Harness's documented `.split(...)[index]` expression syntax (the same
pattern Harness's own docs use for extracting a value like `<+pipeline.
variables.abc.split(':')[1]>`). The parent ticket's key is then referenced
by the child step's `Parent` field as
`<+pipeline.stages.Jira_Automation.spec.execution.steps.Create_Parent_
Release_Ticket.issue.key>`, which is Harness's documented way to reference
a Jira Create step's resulting issue key in a later step.

## If you want the full STO suite later, not just OWASP

Nothing about the Jira automation stage is OWASP-specific - it only reads
whatever `Parse_Vulnerabilities` outputs. If you later add more STO
scanners (SAST, secret detection, etc.) to `Build_And_Scan`, you can extend
that step (or add more parser calls) to fold their findings into the same
`VULN_ITEMS` list, and the exact same parent/child Jira automation will
pick them up with no changes.
# cegeka-poc
