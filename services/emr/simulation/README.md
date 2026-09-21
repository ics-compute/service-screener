# EMR Simulation Testing

Creates a real, minimal, intentionally-misconfigured EMR cluster and runs the
full create → scan → cleanup loop.

## Resources Created

| Resource | Configuration | Directly Validates |
|---|---|---|
| Cluster `ss-test-emr-*` | 1× m5.xlarge master, `emr-5.36.2` (major 5), no security config, no log URI, no Kerberos, no termination protection, no auto-scaling role, step concurrency 1, no tags | `emrOldRelease`, `emrNoSecurityConfiguration`, `emrLoggingDisabled`, `emrKerberosNotEnabled`, `emrTerminationProtectionDisabled`, `emrAutoScalingDisabled`, `emrStepConcurrencyLow`, `emrNoTags` |
| EMR default IAM roles | Created only if absent; removed by cleanup only if this run created them | *(supporting)* |

## Coverage

Verified against a live cluster in `ap-southeast-1` — **8 FAIL**, plus one extra
FAIL the fixture was not specifically built for:

| Check | Result on the live cluster |
|---|---|
| `emrOldRelease` | ✓ FAIL (emr-5.36.2 is major 5) |
| `emrNoSecurityConfiguration` | ✓ FAIL |
| `emrLoggingDisabled` | ✓ FAIL |
| `emrKerberosNotEnabled` | ✓ FAIL |
| `emrTerminationProtectionDisabled` | ✓ FAIL |
| `emrAutoScalingDisabled` | ✓ FAIL |
| `emrStepConcurrencyLow` | ✓ FAIL |
| `emrNoTags` | ✓ FAIL |
| `emrPubliclyAccessible` | ✓ FAIL — the default subnet assigned the master a public IP. Confirms the check reads the master's actual IP, not just SG rules. Pass `--subnet <private-subnet-id>` to avoid this. |
| `emrEncryptionAtRestDisabled` / `emrEncryptionInTransitDisabled` | INFO — correctly gated on a security configuration existing; with none attached, `emrNoSecurityConfiguration` is the single finding. |
| `emrIdleCluster` | PASS — fires only after 24h WAITING; the fixture lives ~20 min |
| `emrMasterInstanceOnDemand` | INFO — on-demand master exercises the PASS/INFO branch |

The two encryption checks' FAIL branch is verified separately, because forcing it
needs a security configuration whose `EnableAtRestEncryption` is false — a second
resource the minimal fixture omits. That path was exercised against synthetic
`describe_cluster` data (a config present but with encryption off), which also
confirmed the two-hop `describe_security_configuration` JSON-string parse and the
`TerminationProtected` field name.

## Cost and time

A single `m5.xlarge` master is roughly **$0.20/hour** including the EMR uplift.
The cluster must reach the **WAITING** state before the scanner can see it
(`list_clusters` filters on `RUNNING`/`WAITING`), and provisioning takes **8–15
minutes** — EMR launches an EC2 instance and bootstraps Hadoop on it. A full
create/scan/cleanup cycle is about 20 minutes and costs roughly **$0.07**. No
steps are run.

## Usage

```bash
cd services/emr/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

./create_test_resources.sh --region ap-southeast-1        # ~8-15 min to WAITING
cd ../../.. && python3 main.py --regions ap-southeast-1 --services emr --beta 1 --sequential 1
cd services/emr/simulation && ./cleanup_test_resources.sh --force   # terminate PROMPTLY
```

Pass `--subnet <private-subnet-id>` to keep the master off the public internet.

## Safety

- Cleanup terminates only the cluster ID recorded in the manifest.
- The EMR default IAM roles (`EMR_DefaultRole`, `EMR_EC2_DefaultRole`,
  `EMR_AutoScaling_DefaultRole`) are removed **only when this run created them** —
  recorded as `CREATED_DEFAULT_ROLES:yes` in the manifest. A pre-existing set is
  left untouched. All three are removed together; an earlier version missed the
  autoscaling role, which then leaked.
- **Terminate promptly** — the cluster bills while it runs.
