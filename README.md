# Service Screener

An open source guidance tool for the AWS environment. Click [here](https://d3si63niga8mq9.cloudfront.net/961319563195/index.html) for sample report.

***Important note***: *The generated report has to be hosted locally and MUST NOT be internet accessible*

This version of Service Screener may not compatible with the Greater China region. Our community folks have made it work [here](https://github.com/lijh-aws-tools/service-screener-cn).

## 🎉 NEW: Enhanced Beta Features (v2.5.0-beta)

**Enable beta features with `--beta 1`!**

### Latest Beta Features:
- **🆕 AWS Cloudscape Design System UI**: Modern React-based interface
  - Self-contained single HTML file (~2.7MB with embedded React and data)
  - Enhanced GuardDuty reporting with interactive charts
  - Cross-service findings aggregation with advanced filtering
  - Interactive modernization recommendations (Sankey diagrams)
  - Trusted Advisor integration with pillar-based organization
  - Framework compliance reporting with visualizations
  - Built on AWS Cloudscape Design System (designed for accessibility)
  - Mobile responsive design

- **🔧 API Buttons**: Interactive API call functionality in service pages

### Standard Features (Always Enabled):
- **⚡ Concurrent Mode**: Parallel check execution for better performance (use `--sequential` to disable)
- **📊 Enhanced TA Data**: Advanced Trusted Advisor data generation
- **🔍 Comprehensive Scanning**: All AWS services with Well-Architected best practices

Enable beta features with: `--beta 1` (legacy AdminLTE remains default for backward compatibility)

## Overview
Service Screener is a tool that runs automated checks on AWS environments and provides recommendations based on AWS and community best practices.

AWS customers can use this tool on their own environments and use the recommendations to improve the Security, Reliability, Operational Excellence, Performance Efficiency and Cost Optimisation at the service level.

This tool aims to complement the [AWS Well Architected Tool](https://aws.amazon.com/well-architected-tool/).

## How does it work?
Service Screener uses [AWS CloudShell](https://aws.amazon.com/cloudshell/), a free service that provides a browser-based shell to run scripts using the AWS CLI. It runs multiple `describe` and `get` API calls to determine the configuration of your environment.

## How much does it cost?
Running this tool is free as it is covered under the AWS Free Tier. If you have exceeded the free tier limits, each run will cost less than $0.01.

## Prerequisites
1. Please review the [DISCLAIMER](./docs/DISCLAIMER.md) before proceeding.
2. You must have an existing AWS Account.
3. You must have an IAM User with sufficient read permissions. Here is a sample [policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html). Additionally, the IAM User must also have the following permissions:
   - AWSCloudShellFullAccess
   - cloudformation:CreateStack
   - cloudformation:DeleteStack

4. (Optional) If you need to run cross-account operations, additional permissions are required:
   - iam:SetSecurityTokenServicePreferences

### Why CloudFormation Permissions Are Required

Service Screener creates a temporary, empty CloudFormation stack during each run for audit and compliance purposes. This stack:

- **Contains no actual resources** - It's an empty "marker" stack that incurs no cost
- **Provides audit trail** - Creates a record in CloudFormation history of when Service Screener was executed
- **Enables compliance tracking** - Allows organizations to track security assessment activities
- **Supports partner integrations** - Enables tracking for AWS Partner evaluations (MPE)

The stack is automatically created at the start of each run with a unique name (format: `ssv2-xxxxxxxxxxxx`) and is automatically deleted when the assessment completes. The stack remains visible in CloudFormation history (when viewing "Deleted" stacks) for audit purposes. This approach leverages AWS's built-in audit capabilities without requiring additional logging infrastructure.

## Installing service-screener V2
1. [Log in to your AWS account](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#start-session) using the IAM User with sufficient permissions described above.
2. Launch [AWS CloudShell](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#launch-region-shell) in any region.
3. In the AWS CloudShell terminal, run this script to update python version to 3.13:
  ``` bash
   sudo yum install python3.13 -y
   ```
4. In the same CloudShell terminal, run this script to install the dependencies:
   ``` bash
   cd /tmp
   git clone https://github.com/ics-compute/service-screener.git ics-ssc
   cd ics-ssc
   python3 -m venv .
   source bin/activate
   python3 -m pip install --upgrade pip
   pip install -r requirements.txt
   
   # alias the screener
   alias screener='python3 $(pwd)/main.py'

   # or
   python3 main.py --regions <e.g. ap-southeast-1> --profile <profile-name>

   # Build Cloudscape UI (required for --beta 1 mode; package-lock.json is authoritative)
   cd cloudscape-ui
   npm ci
   npm run build
   cd ..
   ```

   **Note:** AWS CloudShell comes with Node.js pre-installed. The Cloudscape UI build takes approximately 30-60 seconds.

   **Important:** If you skip the Cloudscape UI build step, the `--beta 1` flag will still work but will only generate the legacy AdminLTE UI. To use the new Cloudscape UI features, you must complete the build step above.

## Using Service Screener
When running Service Screener, you will need to specify the regions and services you would like it to run on. For the full list of services currently supported, please see "SERVICES_IDENTIFIER_MAPPING" in [Config.py](./utils/Config.py).

We recommend running it in all regions where you have workloads deployed in. Adjust the commands below to suit your needs then copy and paste it into CloudShell to run Service Screener.

**Example 1: (Recommended) Run in the Singapore region, check all services with NEW Cloudscape UI enabled**
``` bash
screener --regions ap-southeast-1 --beta 1
```

**Example 1a: Run in the Singapore region, check all services with legacy AdminLTE UI**
``` bash
screener --regions ap-southeast-1
```

**Example 2: Run in the Singapore region, check only Amazon S3**
``` bash
screener --regions ap-southeast-1 --services s3
```

**Example 3: Run in the Singapore & North Virginia regions, check all services**
``` bash
screener --regions ap-southeast-1,us-east-1
```

**Example 4: Run in the Singapore & North Virginia regions, check RDS and IAM**
``` bash
screener --regions ap-southeast-1,us-east-1 --services rds,iam
```

**Example 5: Run in the Singapore region, filter resources based on tags (e.g: Name=env Values=prod and Name=department Values=hr,coe)**
``` bash
screener --regions ap-southeast-1 --tags env=prod%department=hr,coe
```

**Example 6: Run in all regions and all services**
``` bash
screener --regions ALL
```

**Example 7: Run with suppression file to ignore specific findings**
``` bash
screener --regions us-east-1 --services s3 --suppress_file ./suppressions.json
```

## Performance Options

### Disable Custom Pages
For faster scans focused on core AWS service analysis, you can disable custom pages processing:

``` bash
screener --regions ap-southeast-1 --services ec2,s3,rds --disable-custom-pages 1
```

This skips processing of:
- **Cost Optimization Hub (COH)** - AWS cost optimization recommendations
- **Trusted Advisor (TA)** - TA check results and pillar organization
- **Findings aggregation** - Cross-service findings analysis
- **Modernize recommendations** - Modernization pathway analysis

**Performance benefits:**
- **Time savings:** ~2-3 minutes per scan
- **Faster execution:** Focuses only on core service security checks
- **Reduced API calls:** Skips COH, TA, and aggregation APIs

**Use cases:**
- CI/CD pipeline integration where speed is critical
- Quick security validation checks
- Development and testing environments
- Core service analysis without additional insights

**Example: Fast security scan**
``` bash
screener --regions us-east-1 --services ec2,iam,s3 --disable-custom-pages 1 --beta 1
```

## Other parameters

### Suppression File
To suppress specific findings, create a JSON file with the suppressions and use the `--suppress-file` parameter:

```json
{
 "metadata": {
   "version": "1.0",
   "description": "Your suppression description"
 },
 "suppressions": [
   {
     "service": "s3",
     "rule": "BucketReplication"
   },
   {
     "service": "s3",
     "rule": "BucketVersioning",
     "resource_id": ["Bucket::my-bucket-name"]
   }
 ]
}
```

For more details, see the [suppressions documentation](./docs/Suppressions.md).

### Migration Evaluation ID
For AWS Partners conducting migration evaluations:
```json
{
    "mpe": {
        "id": "aaaa-1111-cccc"
    }
}
```

Usage:

``` bash
screener --regions ap-southeast-1 --others '{"mpe": {"id": "aaaa-1111-cccc"}}'
```

### Well-Architected Tool Integration
To create a workload and milestone in the Well-Architected Tool:
``` json
{
    "WA": {
        "region": "ap-southeast-1",
        "reportName": "SS_Report",
        "newMileStone": 1
    }
}
```

Parameters:

- `region`: The region where the Well-Architected workload will be created
- `reportName`: Name of the workload (use existing name to update)
- `newMileStone`:
   - Set to 1 to create a new milestone each time (Recommended)
   - Set to 0 to create a milestone only if none exists

Usage:

``` bash
screener --regions ap-southeast-1 --beta 1 --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report", "newMileStone": 1}}'
```

### Combining Parameters
You can combine both MPE and WA parameters:

``` json
{
    "WA": {
        "region": "ap-southeast-1",
        "reportName": "SS_Report",
        "newMileStone": 1
    },
    "mpe": {
        "id": "aaaa-1111-cccc"
    }
}
```

Usage:

``` bash
screener --regions ap-southeast-1 --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report", "newMileStone": 1}, "mpe": {"id": "aaaa-1111-cccc"}}'
```

## Downloading the report
The output is generated as a ~/service-screener-v2/output.zip file.
You can [download the file](https://docs.aws.amazon.com/cloudshell/latest/userguide/working-with-cloudshell.html#files-storage) in the CloudShell console by clicking the *Download file* button under the *Actions* menu on the top right of the CloudShell console.

Once downloaded, unzip the file and open 'index.html' in your browser. You should see a page like [this](https://dev.d11el1twchxpia.amplifyapp.com/961319563195/index.html).

The new Cloudscape UI (enabled with `--beta 1`) includes:
- **GuardDuty Special Handling** - Dedicated charts, settings, and grouped findings
- **Cross-Service Findings** - Aggregated findings across all services with advanced filtering
- **Modernization Recommendations** - Interactive Sankey diagrams showing modernization pathways
- **Trusted Advisor Integration** - TA check results with pillar-based organization

Ensure that you can see the service(s) run on listed on the left pane.
You can navigate to the service(s) listed to see detailed findings on each service.


## Using the report
The report provides you an easy-to-navigate dashboard of the various best-practice checks that were run.

Use the left navigation bar to explore the checks for each service. Expand each check to read the description, find out which resources were highlighted, and get recommendations on how to remediate the findings.

Besides the HTML report, you can also find two JSON files that record the findings in each AWS account's folder:

- `api-raw.json`: Contains the raw findings
- `api-full.json`: Contains the full results in JSON format

## Contributing to service-screener
We encourage public contributions! Please review [CONTRIBUTING](./CONTRIBUTING.md) for details on our code of conduct and development process.

## Development Guide
A comprehensive development guide is available at [Development Guide](./docs/DevelopmentGuide.md).

## Contact
Please review [CONTRIBUTING](./CONTRIBUTING.md) to raise any issues.

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This project is licensed under the Apache-2.0 License.

## Service Screener v2 migration

This `ics-ssc` repository now includes the applicable Service Screener v2 feature set while retaining the legacy root utilities (`CreateService.py`, `RuleCount.py`, `DocLinkValidity.py`, `organizationAccountsInit.py`, `unzip_botocore_lambda_runtime.py`) and legacy AdminLTE assets as compatibility paths.

### What was introduced

- **Expanded scanner coverage and rule metadata:** the default scan now covers 45 services. The 26 added service bundles are Access Analyzer, ACM, AppSync, Athena, Backup, Bedrock, CloudFormation, CodeBuild, Cognito, Config, ECR, ECS, EMR, EventBridge, Firehose, Glue, Inspector, Kinesis, Route 53, SageMaker, Secrets Manager, Security Hub, SNS, SSM, Step Functions, and WAFv2. Each bundle includes its service class, drivers, reporter rules, and simulation materials; existing services received the corresponding v2 rule and driver updates.
- **Richer report contract and remediation:** `utils/OutputGenerator.py` now produces the legacy report plus `api-full.json` with per-service statistics, framework data, suppression metadata, structured GuardDuty findings, and per-resource remediation resolution (`__remediationByResource`). Reporter rule records carry remediation, risk, and documentation metadata where available.
- **WAF pillars workbook:** `waf-pillars.xlsx` contains only the five Well-Architected pillars; non-pillar `T` findings are excluded. `utils/RemediationCatalog.py` provides concise, finding-specific manual remediation guidance for all 1,039 reporter rules, while only existing reviewed commands are shown as executable. The **Notes** column is short plain text: the finding's `shortDesc` plus a specific hint when the catalog or the description has one, a `Why:` line taken from the reporter description when it adds information, a `Fix impact:` line built from the reporter's downtime/performance/cost/testing flags when any are set, and the resolved CLI command (with its `remediation_risk`) when a reviewed template exists. Every pillar sheet has a frozen header row with an autofilter, so rows can be filtered by Severity.
- **Structured custom-page data:** findings, modernization, Trusted Advisor, and Cost Optimization Hub (COH) data are exposed as `customPage_findings`, `customPage_modernize`, `customPage_ta`, and `customPage_coh`. TA/COH collection is coordinated once per scan and cached under `.cache/`; use `--disable-custom-pages 1` when the additional data is not required.
- **Cloudscape UI:** `cloudscape-ui/` supplies the locked React/Cloudscape single-file report build, including dashboards, risk and service details, GuardDuty views, frameworks, custom pages, suppressions, remediation presentation, and accessibility/error handling. The legacy AdminLTE report is always generated first.
- **Framework and quality additions:** refreshed framework mappings plus AAIL (Agentic AI Lens) and IRDAI directories are included. `scripts/validate_frameworks.py` and `.github/workflows/validate-frameworks.yml` prevent framework maps from silently referring to nonexistent checks; reporter validation was also updated.
- **Content enrichment and MCP:** beta reports can enrich the offline report with AWS best-practice content. `usecases/mcp/` adds the standalone stdio MCP server for rules, findings, scan management, and Well-Architected-pillar queries; install its separate `mcp_server/requirements.txt` in the MCP environment.
- **Operational controls:** scans run concurrently by default. `--sequential 1` disables both service- and evaluator-level concurrency; runs write timestamped logs under `logs/` and record checks taking at least three seconds in the account report's `slow_checks.log`. `--services ALL` selects the complete default service set.

### Prerequisites and network behavior

- Use the existing Python environment and `pip install -r requirements.txt`. The legacy `boto3[crt]` extra is intentionally retained alongside the v2 Python dependencies.
- To build Cloudscape, use **Node `^20.19.0` or `>=22.12.0`**; `cloudscape-ui/.nvmrc` pins `22.12.0`. The committed `cloudscape-ui/package-lock.json` is authoritative, so use `npm ci` rather than an unconstrained install.
- IAM must allow the selected services' read/list/describe/get APIs and `sts:GetCallerIdentity`. The normal marker-stack behavior additionally needs CloudFormation create/delete permissions; cross-account scans need the relevant assume-role permissions and `iam:SetSecurityTokenServicePreferences`. Optional TA and COH pages need access to their corresponding AWS advisory and cost-optimization APIs. Least-privilege policies should be scoped to the services and regions being scanned.
- `--beta 1` enables Cloudscape and content enrichment. Content enrichment makes outbound HTTPS requests to retrieve public AWS guidance; allow outbound HTTPS if it is desired. If enrichment is unavailable or fails, empty enrichment data is embedded and scanning/report generation continues. Keep generated reports local and never expose them on the internet.

### Commands and fallback behavior

```bash
# One-time, deterministic Cloudscape build (requires the Node version above)
cd cloudscape-ui
npm ci
npm run build
cd ..

# Legacy AdminLTE report (default), all v2 services in one region
python3 main.py --regions ap-southeast-1 --services ALL

# Beta Cloudscape report with embedded report data and content enrichment
python3 main.py --regions ap-southeast-1 --services ALL --beta 1

# Compatibility/performance controls
python3 main.py --regions ap-southeast-1 --sequential 1
python3 main.py --regions ap-southeast-1 --disable-custom-pages 1

# Offline metadata validation
python3 scripts/validate_reporter.py
python3 scripts/validate_frameworks.py
```

Without `--beta 1`, `index.html` remains the AdminLTE report. In beta mode AdminLTE is retained as `index-legacy.html`; if Cloudscape cannot build or its data cannot be embedded, Service Screener restores that AdminLTE report as `index.html` and completes with the legacy output instead of failing the scan.
