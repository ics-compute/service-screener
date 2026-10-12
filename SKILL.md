---
name: aws-svc-screener
description: "Run the AWS Service Screener v2 tool (this skill folder is the tool's git repo) to audit an AWS account against the Well-Architected pillars (Security, Reliability, Operational Excellence, Performance Efficiency, Cost Optimization) and summarize the findings. Use whenever the user asks to run service screener, ssc, ssv2, scan an AWS account/environment, audit AWS best practices, check Well-Architected compliance, generate a Service Screener report, or review/interpret an existing api-full.json / api-raw.json / index.html report produced by this tool. Also trigger on requests to find security or cost findings across an AWS account, or to summarize/prioritize AWS misconfigurations. Not for the ICS Technical Document generator (ics-ps-technical-docs-generator), which documents an as-built environment rather than auditing it against best practices."
---

# AWS Service Screener (aws-svc-screener)

Runs AWS Service Screener v2 — the open-source tool this skill folder *is*: the skill folder is a
git clone of `https://github.com/ics-compute/service-screener.git`, with `SKILL.md` at its root
(no separate tool copy, no extra clone needed; update it with `git pull` from the skill root) —
against a real AWS account/profile, then reads back and summarizes its findings. Kiro's job is to
build the right CLI invocation, run it, and turn the raw JSON output into a findings summary a
human can act on. The tool itself does all the scanning; nothing here reimplements it.

All paths below are relative to the skill root: `.kiro/skills/aws-svc-screener/` for a workspace
install, `~/.kiro/skills/aws-svc-screener/` for a global install. Every command must run with the
skill root as the current working directory, because `main.py` resolves everything (`services/`,
`adminlte/`, `output.zip`, caches) from the cwd.

```
main.py                             entry point — python main.py --regions ... --services ...
.venv/                              per-machine venv created by scripts/setup.sh|.ps1 (Step 1)
adminlte/aws/<acct>/                per-account output: index.html, api-raw.json, api-full.json,
                                     all.csv, workItem.xlsx, waf-pillars.xlsx, one .html per
                                     scanned service
utils/RemediationCatalog.py         remediation text keyed by reporter rule — use when a finding
                                     needs a "how do I fix this" answer beyond the report's own text
utils/ExcelBuilder.py               builds workItem.xlsx and waf-pillars.xlsx from scan results
crossAccounts.sample.json           template for multi-account scans
usecases/mcp/                       standalone MCP server for querying cached results (optional,
                                     heavier setup — prefer running main.py directly unless the user
                                     already has this MCP server configured)
scripts/setup.sh, scripts/setup.ps1 one-time dependency setup — run before Step 2 if .venv
                                     doesn't exist yet
```

## Step 0 — Confirm credentials and scope before running anything

This tool makes real read API calls (and briefly creates/deletes an empty CloudFormation marker
stack `ssv2-xxxxxxxxxxxx` for audit-trail purposes) against a live AWS account. Before running:

- Confirm which AWS profile/credentials to use (`aws sts get-caller-identity --profile <p>` is a
  cheap way to confirm the account/identity before scanning it). Never guess an account.
- Confirm region(s) and, if the user cares about scan time, which services. Default services list
  (used when `--services` is omitted) covers 43 core services — `--services ALL` runs the full
  45-service set including the newer additions (accessanalyzer, appsync, athena, cloudformation,
  emr, inspector, securityhub, etc. — see `info.json` for the full per-service rule counts).
- This needs read-only permissions across whatever services are scanned, plus
  `cloudformation:CreateStack`/`DeleteStack` for the marker stack, plus `AWSCloudShellFullAccess`
  if the user runs it from CloudShell instead of locally. Cross-account scans additionally need
  `iam:SetSecurityTokenServicePreferences` and a deployed assume-role (see Step 3).
- The generated report **must stay local and must never be hosted somewhere internet-accessible**
  — it contains real resource IDs and configuration detail for the account. Don't upload it
  anywhere the user hasn't explicitly asked for.

If credentials for the target account aren't available in this environment, say so and ask the
user to run the scan themselves, or provide a profile/credentials that resolve to the right
account. Don't fabricate findings.

## Step 1 — Check prerequisites once per environment (Linux/macOS and Windows)

Check whether setup already ran: does `.venv` exist in the skill root? If yes, skip straight to
Step 2 (just activate it there). If not, run the bundled setup script from the skill root — it's
the preferred path over manual steps because it handles two real gotchas the manual instructions
don't:

- Modern Debian/Ubuntu/Fedora Python installs are "externally managed" (PEP 668) and refuse a
  plain `pip install` outright, so dependencies must go into a venv, not system Python.
- `requirements.txt` ends with `-e .` (editable install of the tool itself), which pip resolves
  relative to the *current working directory*, not the requirements file's location — it silently
  tries to install the wrong thing if invoked from outside the skill root.

```bash
# Linux / macOS (use ~/.kiro/skills/aws-svc-screener for a global install)
cd .kiro/skills/aws-svc-screener
bash scripts/setup.sh
```

```powershell
# Windows (PowerShell) (use ~\.kiro\skills\aws-svc-screener for a global install)
cd .kiro\skills\aws-svc-screener
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

This creates `.venv` in the skill root and installs `requirements.txt` into it. It takes no
arguments and is idempotent — safe to re-run, it reuses an existing venv rather than recreating
it. The tool is already in the skill folder, so the only thing this step needs to fetch is Python
packages — there's no separate tool repo to clone first.

The Lambda deprecated-runtime check is currently skipped in this layout ("Skipped runtime version
check…" in the scan output is expected) — it's a known limitation, not a setup failure.

Only needed once for the beta Cloudscape UI (`--beta 1`); skip if the user just wants the default
AdminLTE report. Run from the skill root, each line separately rather than chaining with `&&`/`;`
so it works the same in PowerShell, `cmd`, and POSIX shells:

```
cd cloudscape-ui
npm ci
npm run build
cd ..
```

(Node `^20.19.0` or `>=22.12.0` on any OS.) Without this build, `--beta 1` still runs but silently
falls back to the legacy AdminLTE report as `index.html` — mention that if the user asked for the
new UI and the build hasn't been done.

If for some reason the script can't be used, the manual equivalent (from the skill root) is:
`python3 -m venv .venv`, then `.venv/bin/python -m pip install --upgrade pip`, then
`.venv/bin/python -m pip install -r requirements.txt` (on Windows: `python -m venv .venv`, then
`.venv\Scripts\python -m pip install --upgrade pip` and
`.venv\Scripts\python -m pip install -r requirements.txt`).

**Updating:** run `git pull` from the skill root. Re-run the setup script if `requirements.txt`
changed, and rebuild `cloudscape-ui` (steps above) if the user relies on `--beta 1`.

## Step 2 — Build and run the command

Activate the venv first, then run from the skill root:

```bash
# Linux / macOS
cd .kiro/skills/aws-svc-screener   # or ~/.kiro/skills/aws-svc-screener
source .venv/bin/activate
python main.py --regions <region1,region2|ALL> --services <svc1,svc2|ALL> [--profile <name>]
```

```powershell
# Windows (PowerShell)
cd .kiro\skills\aws-svc-screener   # or ~\.kiro\skills\aws-svc-screener
.venv\Scripts\Activate.ps1
python main.py --regions <region1,region2|ALL> --services <svc1,svc2|ALL> [--profile <name>]
```

Other flags to reach for based on what the user asks:

| Need | Flag |
|---|---|
| Specific AWS CLI profile | `--profile <name>` |
| Every supported service | `--services ALL` (or omit for the default subset) |
| Filter resources by tag | `--tags env=prod%department=hr,coe` (`%` separates tag conditions, `,` separates OR'd values) |
| New Cloudscape UI + content enrichment | `--beta 1` (enrichment makes outbound HTTPS calls to fetch public AWS guidance — flag this to the user since it leaves the account's read-only boundary) |
| Suppress known/accepted findings | `--suppress_file ./suppressions.json` (see `docs/Suppressions.md`; on Windows a relative path like `.\suppressions.json` also works) |
| Faster scan, skip TA/COH/aggregation | `--disable-custom-pages 1` |
| Disable concurrency (debugging) | `--sequential 1` |
| Well-Architected Tool workload sync | `--others "{\"WA\": {\"region\": \"...\", \"reportName\": \"...\", \"newMileStone\": 1}}"` |
| Partner migration evaluation tag | `--others "{\"mpe\": {\"id\": \"...\"}}"` |

`--others` takes a JSON string. On Linux/macOS wrap it in single quotes as shown in the README
(`--others '{"WA": {...}}'`); `cmd.exe` and PowerShell don't treat single quotes as a string
delimiter the same way, so on Windows wrap it in double quotes and escape the inner double quotes
with a backslash, as shown above — or build the JSON with a file and point at it if the escaping
gets unwieldy.

Run it with `execute_bash` (or the background-process tool if the user wants to keep working while
it scans — a full multi-region `ALL` services scan can take several minutes). Watch stdout: it also
writes a timestamped copy to `logs/`.

### A note on how the user asks for this

The user does not need to know `main.py`'s flag names. It's fine (preferred, even) for them to
describe the scan in plain language — e.g. "scan ap-southeast-1 and us-east-1 with profile prod,
just s3 and ec2, and put the report in ~/reports" — and for Kiro to translate that into the actual
`--regions`, `--profile`, `--services` flags above. Always state the exact command about to run
before executing it, so the user can confirm region/account/services before any AWS API calls
happen (see Step 0).

If the user (or a saved prompt) does use flag syntax, `--output <path>` is **not** a real
`main.py` argument — don't pass it through to the tool or it will fail with an unrecognized-
argument error. Treat it as a skill-level instruction: run the normal command without `--output`,
then once the scan finishes, copy `output.zip` (and/or the specific account folder under
`adminlte/aws/<account_id>/`) to the requested destination — `cp`/`mv` on Linux/macOS,
`Copy-Item`/`Move-Item` on Windows PowerShell. Create the destination directory if it doesn't
exist, and confirm before overwriting an existing file there.

## Step 3 — Cross-account scans (only if asked)

Cross-account scanning needs setup the user must do in the AWS console first — don't attempt to
skip this:

1. They deploy `usecases/crossAccounts/crossAccountRoleCF.yml` as a StackSet across target
   accounts (creates `ServiceScreenerAssumeRole` by default).
2. They (or you, given the account list) create `crossAccounts.json` in the skill root from
   `crossAccounts.sample.json` — a `general` block (this account's `ExternalId`/`RoleName`, and
   whether to include this account itself) plus an `accountLists` map keyed by account ID.
3. Run with `--crossAccounts 1` added to the normal command. The report groups findings per
   account, selectable from a dropdown in the HTML.

## Step 4 — Read back and summarize the findings

Per-account output lands in `adminlte/aws/<account_id>/` (forward slashes shown here resolve fine
on Windows too; use whatever path separator the file-reading tool expects):

- `api-full.json` — the structured file to parse programmatically. It only contains findings that
  failed or warned (no PASS records), with per-service stats, framework mappings, suppression
  metadata, and (for beta) `customPage_findings`/`customPage_modernize`/`customPage_ta`/`customPage_coh`.
- `api-raw.json` — rawer per-check results, less convenient to summarize than `api-full.json`.
- `all.csv` / `workItem.xlsx` — flat spreadsheet of findings, handy if the user wants something to
  filter/sort outside a browser.
- `waf-pillars.xlsx` — findings grouped one worksheet per Well-Architected pillar (Security,
  Reliability, Performance Efficiency, Cost Optimization, Operational Excellence); non-pillar `T`
  findings are excluded. Columns: `Service, Region, Check, ResourceID, Severity, Status,
  Description, Impact, Remediation, Effort`. `Description` is the finding's `shortDesc` plus the
  consequence from the reporter description; `Impact` lists the affected pillars plus tags like
  Data loss, Compliance, Downtime, Performance, Additional cost, Requires testing (prefixed
  "Possible" when the reporter says it's conditional); `Remediation` is the catalog's
  finding-specific guidance followed by a resolved/templated CLI command where one exists;
  `Effort` is Low/Medium/High (raised automatically when downtime/slowness/full-testing flags are
  set) and has a dropdown so the user can adjust it by hand. Each sheet has a frozen header row and
  autofilter, so this is the best file to hand the user when they want findings filterable by
  Severity, Impact, or Effort rather than just browsing the HTML.
- `index.html` (`index-legacy.html` too, in beta mode) — the interactive report. Point the user at
  this for browsing; don't try to "read" it yourself, parse the JSON instead.

When asked to summarize, don't just dump the JSON. Read `api-full.json`, then report:

- Counts by severity/status across the scanned services, and which services carried the most
  findings.
- The highest-risk items first (security/reliability findings before minor cost nits, unless the
  user asked specifically about cost).
- For "how do I fix this," cross-reference `utils/RemediationCatalog.py` and the finding's own
  `shortDesc`/description — don't invent remediation steps the tool doesn't already document.
- Anything in `meta`/warnings indicating a service was skipped due to `AccessDenied` — a silently
  empty section is worse than a flagged gap, always call it out.

If the user already has the `usecases/mcp` MCP server configured for this repo, its `get_findings`
/`get_summary`/`get_wa_score` tools are a shortcut for querying a completed scan's cache instead of
parsing `api-full.json` by hand — use it if available, otherwise the direct JSON read above works
without any extra setup.
