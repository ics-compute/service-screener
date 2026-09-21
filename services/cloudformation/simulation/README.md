# CloudFormation Simulation Testing

Creates one minimal, intentionally-unprotected stack whose only resource is a
free SSM parameter.

## Resources Created

| Resource | Configuration | Directly Validates |
|---|---|---|
| Stack `ss-test-cfn-*` | No termination protection, no stack policy, no rollback configuration, no notification ARNs, no tags; drift never checked | `cfnTerminationProtectionDisabled`, `cfnStackPolicyMissing`, `cfnNoRollbackConfiguration`, `cfnNoNotifications`, `cfnNoTags`, `cfnDriftNeverChecked` |

## Coverage

Verified against a test account in `ap-southeast-1` — 6 FAIL on the
fixture, and the account's **429 real stacks** exercise every remaining branch
(including one genuinely `DRIFTED` stack and one in a failed state).

| Check | Simulated? |
|---|---|
| `cfnTerminationProtectionDisabled` | ✓ FAIL |
| `cfnStackPolicyMissing` | ✓ FAIL |
| `cfnNoRollbackConfiguration` | ✓ FAIL |
| `cfnNoNotifications` | ✓ FAIL |
| `cfnNoTags` | ✓ FAIL |
| `cfnDriftNeverChecked` | ✓ FAIL |
| `cfnDriftDetected` | ✗ forcing `DRIFTED` means mutating a stack-managed resource behind CloudFormation's back **and** running drift detection, which is a write. The account's own stacks include a DRIFTED one, which covers it. |
| `cfnRollbackFailed` | ✗ requires deliberately breaking a deployment; one real stack covers it |
| `cfnOldStackUnupdated` | ✗ needs a stack older than a year; 226 real stacks cover it |
| `cfnIAMCapabilityGranted` | ✗ INFO-only; would require an IAM resource in the fixture template, which it deliberately avoids |

## The read-only constraint that shaped this service

`cfnDriftDetected` reads `DriftInformation.StackDriftStatus` from the
`describe_stacks` response. It does **not** call `detect_stack_drift` — that
operation's only output is a `StackDriftDetectionId` because it *initiates* an
asynchronous, billed, rate-limited detection run that mutates stack state. A
scanner calling it per stack per region would be performing writes against
production infrastructure.

## Usage

```bash
cd services/cloudformation/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
cd ../../.. && python3 main.py --regions ap-southeast-1 --services cloudformation --beta 1 --sequential 1
cd services/cloudformation/simulation && ./cleanup_test_resources.sh --force
```

## Cost

Zero. The stack's only resource is a standard-tier SSM parameter, which is free.
Cleanup waits for `stack-delete-complete` so nothing is left behind.
