# reporter.json

Each service has a `services/{service}/{service}.reporter.json` file that defines metadata for every check the service's driver code can produce. The driver only ever writes a check name and a pass/fail result (see [How results map to this file](#how-results-map-to-this-file)); everything else shown in a report — description, severity, category, impact tags — comes from this file, keyed by that same check name.

This file is validated in CI by `scripts/validate_reporter.py` (`.github/workflows/validate-reporter.yml`) and consumed at report-build time by `services/Reporter.py` and `services/PageBuilder.py`.

## Syntax

```json
{
	"<CHECK_NAME>": {
		"category": "<ENUM>",       // REQUIRED, one or more of: O, S, R, P, C, T
		"^description": "<string>", // REQUIRED
		"shortDesc": "<string>",    // REQUIRED in practice — see note below
		"criticality": "<ENUM>",    // REQUIRED, single value: I, L, M, H
		"downtime": <int>,          // OPTIONAL, one of: -1, 0, 1
		"slowness": <int>,          // OPTIONAL, one of: -1, 0, 1
		"additionalCost": <int>,    // OPTIONAL, one of: -1, 0, 1
		"needFullTest": <int>,      // OPTIONAL, one of: -1, 0, 1
		"ref": [                    // OPTIONAL
			"[<text_to_display>]<url>",
			"[<text_to_display>]<url>"
		]
	}
}
```

Note on `shortDesc`: the field-level syntax historically marked this OPTIONAL, but `scripts/validate_reporter.py` lists it as a required field and every check in every `*.reporter.json` in this repo has it. Treat it as required when adding new checks.

## How results map to this file

A driver (e.g. `services/rds/drivers/RdsCommon.py`) sets `self.results['<CHECK_NAME>'] = [status, detail]`, where `status` is `-1` (fail), `0` (skip/not applicable), or `1` (pass). `services/Reporter.py` only surfaces checks with `status == -1` into the report, then looks up `<CHECK_NAME>` in this file to pull `category`, `criticality`, `^description`, `shortDesc`, and `ref`. If a driver returns a check name that has no entry here, `Reporter.py` prints a `[Fatal]`/warning and the finding is dropped from the summary — so every check name a driver can emit must have a matching entry in this file.

## Parameter Details

### CHECK_NAME
`Required: Yes`
`Type: string`

The object key. Must exactly match the check name a driver writes into `self.results` — this is a plain string key, not a value inside the object.

### category
`Required: Yes`
`Type: ENUM (combination)`

Indicates which [AWS Well-Architected Framework pillar(s)](https://aws.amazon.com/architecture/well-architected/) this check relates to. Value is a string of one or more of these letters, with **no repeats**:

- `O`: Operational Excellence
- `S`: Security
- `R`: Reliability
- `P`: Performance Efficiency
- `C`: Cost Optimization
- `T`: Custom/template page — excluded from pillar scoring (see below)

The **first character** is the main pillar; it drives severity roll-ups and dashboard scoring in `Reporter.py`. Any characters after the first are secondary pillars the check also touches.

Examples:
- `"category": "RS"` — Reliability (main) and Security (secondary).
- `"category": "CPO"` — Cost Optimization (main), Performance Efficiency and Operational Excellence (secondary).
- `"category": "S"` — Security only.

`T` is special: `Reporter.py` skips any check whose main category is `T` when building criticality/category dashboard aggregates and Well-Architected pillar mapping (`getSummary()` checks `if mainCategory == 'T': continue`). Use `T` only for informational/custom-page content that isn't a security or operational finding — e.g. usage stats or "consider migrating to X" advisory notes — not for real findings. Because of this, `T` should never be combined with other pillar letters; keep it as a standalone `"category": "T"`.

### ^description
`Required: Yes`
`Type: string`

Long-form description shown in the report's detail view. Explains what the check does, why it matters, and (via the `{$COUNT}` keyword below) how many resources are affected.

Example: `"^description": "You have {$COUNT} production instances which are not configured to be tolerant to issues in an Availability Zone."`

**Supported keyword:**

| Keyword | Replaced with |
|---|---|
| `{$COUNT}` | The number of resources that failed this check, wrapped in `<strong><u>...</u></strong>` at render time |

`{$COUNT}` is substituted by `Reporter.py` (`getSummary()`) at report-build time — do not hardcode a count.

### shortDesc
`Type: string`

Short label used in report tables and card headers where the full `^description` would be too long.

Example: `"shortDesc": "Enable MultiAZ"`

### criticality
`Required: Yes`
`Type: ENUM (single value)`

Severity of the finding. Exactly one of:

- `I`: Informational
- `L`: Low
- `M`: Medium
- `H`: High

Example: `"criticality": "H"`

### downtime
`Type: int`
`Default if omitted: falsy / not shown`

Whether remediating this finding requires downtime. One of:

- `0`: No downtime required
- `1`: Downtime required
- `-1`: It depends (context-dependent — leave to the reader's judgment)

Example: `"downtime": -1`

### slowness
`Type: int`

Whether remediating this finding is likely to cause a temporary performance impact. Same value convention as `downtime`:

- `0`: No performance impact
- `1`: Performance will be impacted
- `-1`: It depends

Example: `"slowness": -1`

### additionalCost
`Type: int`

Whether remediating this finding will incur additional AWS cost. Same value convention as `downtime`:

- `0`: No additional cost
- `1`: Additional cost will be incurred
- `-1`: It depends

Example: `"additionalCost": -1`

### needFullTest
`Type: int`

Whether remediating this finding requires application-level regression testing (beyond the AWS-side change itself). Same value convention as `downtime`:

- `0`: No additional testing required
- `1`: Additional testing required
- `-1`: It depends

Example: `"needFullTest": -1`

**How `downtime`/`slowness`/`additionalCost`/`needFullTest` are used:** `PageBuilder.py` renders each of these as an impact tag on the report card (`generateSummaryCardTag`) whenever the value is truthy (i.e. `1` or `-1`, since Python treats non-zero ints as truthy) — a `-1` ("it depends") still shows the tag, just as `1` does. `PageBuilder.checkIsLowHangingFruit()` also treats a check as a "quick win" only when `downtime == 0 and additionalCost == 0 and needFullTest == 0` exactly, so set these precisely rather than defaulting to `-1` when unsure.

### ref
`Type: list of strings`

External resources (AWS docs, blog posts) related to the check. Each entry must follow the exact syntax `[<display text>]<url>` — `PageBuilder.py` parses this with a regex (`\[(.*)\]<(.*)>`) and silently drops (with a console warning) any entry that doesn't match, so malformed entries won't fail validation but will disappear from the rendered report.

Example:
```json
"ref": [
	"[Multi-AZ overview]<https://aws.amazon.com/rds/features/multi-az/>",
	"[AWS Blog]<https://aws.amazon.com/blogs/aws/>"
]
```

## Example

```json
{
	"MultiAZ": {
		"category": "RO",
		"^description": "High Availability: You have {$COUNT} production instances/clusters which are not configured to be tolerant to issues in an Availability Zone. Reconfigure production RDS instances to Multi-AZ. For Aurora clusters, have at least 2 instances (each in a different availability zone). Enabling multi-AZ for RDS cluster and adding another instance will lead to additional cost. Converting single-AZ instance to multi-AZ instance will avoid downtime but you can experience performance impact. You should perform this operation during off-peak hours. You can also create a multi-AZ read replica and then perform a failover.",
		"downtime": -1,
		"slowness": -1,
		"additionalCost": 1,
		"needFullTest": 0,
		"criticality": "H",
		"shortDesc": "Enable MultiAZ",
		"ref": [
			"[What Is MultiAZ]<https://aws.amazon.com/rds/features/multi-az/>",
			"[Guide]<https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html>"
		]
	},
	"EngineVersionMajor": {
		"category": "SP",
		"^description": "Version Currency: {$COUNT} of your instances/clusters are on an older engine version. Upgrade to the latest version to get access to new features. You should perform proper testing before upgrading the production environment. There are different options to perform a major version upgrade and your choice will depend on architecture, schema, and workload. If you choose to upgrade by setting up replication, you may incur additional cost for replication (e.g. when using DMS) and for the additional instance.",
		"downtime": 1,
		"slowness": 0,
		"additionalCost": 0,
		"needFullTest": 1,
		"criticality": "H",
		"shortDesc": "Major version available",
		"ref": [
			"[Amazon RDS versions]<https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_UpgradeDBInstance.Upgrading.html>"
		]
	},
	"UsageStat": {
		"category": "T",
		"^description": "Custom Page Usage",
		"downtime": 0,
		"slowness": 0,
		"additionalCost": 0,
		"criticality": "L",
		"shortDesc": "UsageStat",
		"ref": []
	}
}
```

## Template

A boilerplate copy lives at `utils/services-template/service.reporter.json` and is copied into new services by `scripts/CreateService.py`. Fill it in per check:

```json
{
	"CHECKNAME": {
		"category": "OSRPC",
		"^description": "Sample {$COUNT} description",
		"downtime": -1,
		"slowness": -1,
		"additionalCost": 1,
		"needFullTest": 0,
		"criticality": "H",
		"shortDesc": "Enable MultiAZ",
		"ref": [
			"[Display text]<https://docs.aws.amazon.com/>"
		]
	}
}
```

## Validating changes

Run `python scripts/validate_reporter.py [file ...]` (no args validates every `*.reporter.json` under the repo) before committing. It checks that `category`, `^description`, `shortDesc`, and `criticality` are present, that `category` only contains `S/R/O/P/C/T` with no duplicate letters, and that `criticality` is one of `I/L/M/H`. This same check runs in CI (`.github/workflows/validate-reporter.yml`) against any changed `*.reporter.json` file in a PR.
