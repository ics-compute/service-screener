# Service Screener

An open source guidance tool for AWS environments. Click [here](https://d3si63niga8mq9.cloudfront.net/961319563195/index.html) for a sample report.

> **Important:** The generated report must be hosted locally and **MUST NOT** be internet accessible.

## Overview

Service Screener runs automated checks on AWS environments and provides recommendations based on AWS and community best practices. Use it to improve Security, Reliability, Operational Excellence, Performance Efficiency, and Cost Optimisation at the service level — complementing the [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/).

It makes read-only API calls (`describe`, `get`, `list`) plus briefly creates and auto-deletes an empty CloudFormation marker stack (`ssv2-xxxxxxxxxxxx`) for audit purposes.

---

## Getting Started

There are two ways to use Service Screener depending on your workflow.

---

### Method 1 — Kiro AI Skill (recommended for AI-assisted workflows)

Use this if you work inside [Kiro IDE](https://kiro.dev). The skill lets you describe scans in plain language — Kiro handles the command, runs the scan, and summarises the findings for you.

**Skill layout**

This repo *is* the skill: `SKILL.md` sits at the repo root, so a plain `git clone` into the skills folder is the whole install. The venv lives inside the clone. Nothing needs to live at your workspace root.

```
.kiro/skills/aws-svc-screener/    # git clone of this repo
├── SKILL.md                      # skill definition
├── main.py
├── requirements.txt
├── scripts/
│   ├── setup.sh                  # one-time setup (Linux / macOS)
│   └── setup.ps1                 # one-time setup (Windows)
├── .venv/                        # created during install (gitignored)
└── ...
```

Install it per workspace at `<workspace>/.kiro/skills/aws-svc-screener/`, or for every project at `~/.kiro/skills/aws-svc-screener/`.

**Install (Linux / macOS)**

```bash
# from your workspace root (use ~/.kiro/skills/aws-svc-screener for a global install)
git clone https://github.com/ics-compute/service-screener.git .kiro/skills/aws-svc-screener
cd .kiro/skills/aws-svc-screener
bash scripts/setup.sh
```

`setup.sh` creates `.venv/` in the skill root and installs `requirements.txt` into it. It's idempotent, so re-running it is safe. Or do it manually:

```bash
# run from the skill root, because requirements.txt ends with "-e ." which resolves against cwd
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

**Install (Windows PowerShell)**

```powershell
# from your workspace root (use ~\.kiro\skills\aws-svc-screener for a global install)
git clone https://github.com/ics-compute/service-screener.git .kiro\skills\aws-svc-screener
cd .kiro\skills\aws-svc-screener
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

Or manually, from the skill root:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
```

**Optional — Cloudscape UI** (only needed for `--beta 1` reports; Node `^20.19.0` or `>=22.12.0`):

```bash
cd .kiro/skills/aws-svc-screener/cloudscape-ui && npm ci && npm run build && cd -
```

**Activate**

Start a new Kiro chat session (or reload the window). Kiro picks up `.kiro/skills/aws-svc-screener/SKILL.md` and registers the skill; no other configuration is needed. It then shows up as `/aws-svc-screener` when you type `/` in chat, and activates automatically when a request matches its description.

**Update**

```bash
cd .kiro/skills/aws-svc-screener
git pull
```

Re-run `bash scripts/setup.sh` (or `scripts\setup.ps1`) if `requirements.txt` changed, and rebuild `cloudscape-ui` if you use `--beta 1`. Local scan output (`.venv/`, `adminlte/aws/<account_id>/`, `output.zip`, `logs/`, `__fork/`, `crossAccounts.json`) is untracked and gitignored, so it doesn't block `git pull` and isn't touched by it.

**Migrating from the old vendored layout**

If `.kiro/skills/aws-svc-screener/` already exists as a plain copy with an `ics-ssc/` subfolder, move it *outside* `.kiro/skills/` first (so Kiro doesn't also load the old `SKILL.md`), then clone and set up as above:

```bash
mv .kiro/skills/aws-svc-screener ./aws-svc-screener.old
# clone + bash scripts/setup.sh as above, then copy back any reports and config you want to keep:
#   aws-svc-screener.old/ics-ssc/adminlte/aws/<account_id>/  ->  .kiro/skills/aws-svc-screener/adminlte/aws/
#   aws-svc-screener.old/ics-ssc/crossAccounts.json          ->  .kiro/skills/aws-svc-screener/
rm -rf ./aws-svc-screener.old
```

**Known limitation**

The Lambda deprecated-runtime check is currently skipped in this layout (the botocore path in `constants.py` assumes a different venv location), so "Skipped runtime version check…" in the scan output is expected.

**Use**

Just describe the scan in Kiro — no flags needed:

```
/aws-svc-screener scan ap-southeast-1 with profile myprofile
/aws-svc-screener check s3, ec2 and iam in us-east-1 using profile prod, beta UI
/aws-svc-screener run a full scan of every region using profile prod
```

Kiro confirms the account and region before running anything, shows you the exact command, runs it, and summarises the findings.

---

### Method 2 — CLI with alias (shell / CloudShell)

Use this for direct terminal usage, CI/CD pipelines, or AWS CloudShell.

**Install**

```bash
# Clone and set up
git clone https://github.com/ics-compute/service-screener.git ics-ssc
cd ics-ssc

# Create a venv (required on modern Debian/Ubuntu/Fedora — PEP 668)
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# (Optional) Build the Cloudscape UI for --beta 1 reports
# Requires Node ^20.19.0 or >=22.12.0
cd cloudscape-ui && npm ci && npm run build && cd ..
```

**Alias the command** so you don't have to type the full path each time:

```bash
alias screener='python3 $(pwd)/main.py'
```

To make the alias permanent, add it to your `~/.bashrc` or `~/.zshrc`:

```bash
echo "alias screener='python3 /path/to/ics-ssc/main.py'" >> ~/.bashrc
source ~/.bashrc
```

**Use**

```bash
# Singapore region, all services, new Cloudscape UI
screener --regions ap-southeast-1 --beta 1

# Singapore region, S3 only
screener --regions ap-southeast-1 --services s3

# Multiple regions
screener --regions ap-southeast-1,us-east-1

# All regions and services
screener --regions ALL --profile myprofile

# Tag-based filtering
screener --regions ap-southeast-1 --tags env=prod%department=hr,coe

# Without the alias, from inside ics-ssc/
source .venv/bin/activate
python3 main.py --regions ap-southeast-1 --profile myprofile
```

---

## Prerequisites

1. Review the [DISCLAIMER](./docs/DISCLAIMER.md) before proceeding.
2. An existing AWS account.
3. An IAM user/role with sufficient read permissions ([ReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html)) plus:
   - `cloudformation:CreateStack` / `cloudformation:DeleteStack` (for the audit marker stack)
   - `AWSCloudShellFullAccess` (if running from CloudShell)
4. For cross-account scans: `iam:SetSecurityTokenServicePreferences` plus a deployed assume-role.

### Why CloudFormation permissions are required

Service Screener creates a temporary, empty CloudFormation stack per run (`ssv2-xxxxxxxxxxxx`) for audit and compliance purposes. It contains no resources, incurs no cost, and is automatically deleted when the scan completes. The stack remains visible under "Deleted" stacks for audit trail purposes.

---

## 🎉 Beta Features (v2.5.0-beta)

Enable with `--beta 1`:

- **AWS Cloudscape Design System UI** — Modern React-based interface (self-contained ~2.7 MB HTML file)
- **GuardDuty** enhanced reporting with interactive charts
- **Cross-service findings** aggregation with advanced filtering
- **Interactive modernisation recommendations** (Sankey diagrams)
- **Trusted Advisor** integration with pillar-based organisation
- **Framework compliance** reporting with visualisations
- **API Buttons** — interactive API call functionality in service pages

Standard features (always enabled): concurrent mode, enhanced TA data, full service coverage.

> Without `--beta 1`, `index.html` is the legacy AdminLTE report. In beta mode, AdminLTE is retained as `index-legacy.html` as a fallback.

---

## Usage Examples

All examples below use the `screener` alias (Method 2) or are equivalent to what Kiro runs under the hood (Method 1).

**Recommended: Singapore region, all services, Cloudscape UI**
```bash
screener --regions ap-southeast-1 --beta 1
```

**Legacy AdminLTE UI**
```bash
screener --regions ap-southeast-1
```

**Multiple regions, specific services**
```bash
screener --regions ap-southeast-1,us-east-1 --services rds,iam
```

**All regions**
```bash
screener --regions ALL --profile myprofile
```

**Tag filtering** (env=prod AND (department=hr OR department=coe))
```bash
screener --regions ap-southeast-1 --tags env=prod%department=hr,coe
```

**With suppression file**
```bash
screener --regions us-east-1 --services s3 --suppress_file ./suppressions.json
```

**Fast scan** — skip TA/COH/aggregation (~2–3 min faster)
```bash
screener --regions ap-southeast-1 --services ec2,iam,s3 --disable-custom-pages 1
```

**Well-Architected Tool integration**
```bash
screener --regions ap-southeast-1 --beta 1 --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report", "newMileStone": 1}}'
```

**Migration Evaluation ID (AWS Partners)**
```bash
screener --regions ap-southeast-1 --others '{"mpe": {"id": "aaaa-1111-cccc"}}'
```

---

## Where the output goes

| File | Location | What it is |
|---|---|---|
| `output.zip` | `output.zip` | Full report archive; overwritten on every run |
| `index.html` | `adminlte/aws/<account_id>/index.html` | Interactive HTML report |
| `api-full.json` | same folder | Structured findings (FAIL/WARN only) — machine-readable |
| `api-raw.json` | same folder | Raw per-check results |
| `waf-pillars.xlsx` | same folder | Findings per Well-Architected pillar, filterable by Severity/Impact/Effort |
| `workItem.xlsx`, `all.csv` | same folder | Flat worklist / CSV export |

Paths are relative to the tool root. For the Kiro skill install (Method 1) that's `.kiro/skills/aws-svc-screener/` itself; for Method 2 it's the cloned `ics-ssc/` folder.

To download from CloudShell: Actions → *Download file*, then open `index.html` locally.

---

## Suppression File

```json
{
  "metadata": { "version": "1.0", "description": "Your suppression description" },
  "suppressions": [
    { "service": "s3", "rule": "BucketReplication" },
    { "service": "s3", "rule": "BucketVersioning", "resource_id": ["Bucket::my-bucket-name"] }
  ]
}
```

See the [suppressions documentation](./docs/Suppressions.md) for details.

---

## Cross-Account Scans

1. Deploy `usecases/crossAccounts/crossAccountRoleCF.yml` as a StackSet across target accounts.
2. Create `crossAccounts.json` from `crossAccounts.sample.json`.
3. Run with `--crossAccounts 1`.

---

## Service Screener v2 migration notes

`ics-ssc` includes the full v2 feature set. Notable additions:

- **45 services** covered (26 new: Access Analyzer, ACM, AppSync, Athena, Backup, Bedrock, CloudFormation, CodeBuild, Cognito, Config, ECR, ECS, EMR, EventBridge, Firehose, Glue, Inspector, Kinesis, Route 53, SageMaker, Secrets Manager, Security Hub, SNS, SSM, Step Functions, WAFv2).
- **`api-full.json`** with per-service stats, framework data, suppression metadata, remediation resolution.
- **`waf-pillars.xlsx`** with Well-Architected pillar sheets and `RemediationCatalog.py` guidance for 1,039 rules.
- **Cloudscape UI** (`cloudscape-ui/`) — React single-file report; build once with `npm ci && npm run build`.
- **MCP server** at `usecases/mcp/` for querying cached scan results from any MCP-aware client.
- **`--disable-custom-pages 1`** skips TA/COH/aggregation for faster scans.
- **`--sequential 1`** disables concurrency (useful for debugging).
- Node `^20.19.0` or `>=22.12.0` required for the Cloudscape build; `package-lock.json` is authoritative — use `npm ci`.

---

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md) for our code of conduct and development process.

## Development Guide

See the [Development Guide](./docs/DevelopmentGuide.md).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications).

## License

Apache-2.0. See [LICENSE](./LICENSE).
