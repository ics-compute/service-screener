# EventBridge Simulation Testing

Scripts to create an intentionally-misconfigured custom event bus, rules, a
connection and an API destination so the `eb*` service-screener checks can be
validated end-to-end.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| Custom bus `ss-test-eb-bus-*` | No `KmsKeyIdentifier`, no tags, resource policy with `Principal: "*"` and no `Condition` | `ebBusNoEncryption`, `ebBusNoTags`, `ebBusPublicPolicy` |
| Rule `ss-test-eb-rule-orphan-*` | `State=DISABLED`, no targets, no description | `ebRuleDisabled`, `ebRuleNoTargets`, `ebRuleNoDescription` |
| Rule `ss-test-eb-rule-target-*` + SQS queue | Enabled with a described SQS target that has **no** `DeadLetterConfig` and **no** `RetryPolicy` | `ebRuleNoDeadLetterQueue`, `ebRuleNoRetryPolicy` |
| Connection `ss-test-eb-conn-*` + API destination `ss-test-eb-dest-*` | `API_KEY` auth, `https://` endpoint | `ebConnectionNoAuth` and `ebApiDestinationHttpEndpoint` — **PASS branch only** (see below) |
| *(nothing)* | The region has no archive and no schema discoverer | `ebArchiveNotConfigured`, `ebSchemaDiscoveryDisabled` — these fire on absence, so no fixture is needed |

## Coverage

Verified against a test account in `ap-southeast-1`:

| Check | Simulated? |
|---|---|
| `ebBusNoEncryption` | ✓ FAIL |
| `ebBusNoTags` | ✓ FAIL |
| `ebBusPublicPolicy` | ✓ FAIL — the script warns and the check reports PASS if an SCP rejects the wildcard policy |
| `ebRuleDisabled` | ✓ FAIL |
| `ebRuleNoTargets` | ✓ FAIL |
| `ebRuleNoDescription` | ✓ FAIL |
| `ebRuleNoDeadLetterQueue` | ✓ FAIL |
| `ebRuleNoRetryPolicy` | ✓ FAIL |
| `ebArchiveNotConfigured` | ✓ FAIL (absence) |
| `ebSchemaDiscoveryDisabled` | ✓ FAIL (absence) |
| `ebApiDestinationHttpEndpoint` | ⚠ PASS branch only. **The FAIL branch is unreachable through the API**: `CreateApiDestination` rejects an `http://` endpoint with `ValidationException: Endpoint 'http://...' is invalid, please provide a valid HTTPS endpoint URL`. EventBridge enforces HTTPS at the API layer, so a plaintext destination cannot be created in a current account — the check only fires on a legacy destination predating that validation. The fixture uses `https://` to prove the check evaluates. |
| `ebConnectionNoAuth` | ⚠ PASS branch only. `CreateConnection` requires one of `BASIC`, `API_KEY` or `OAUTH_CLIENT_CREDENTIALS`; there is no `NONE` authorization type, so an unauthenticated connection cannot be created. |
| `ebRuleTargetCrossAccountNoCondition` | ✗ needs a rule target in a second AWS account. Exercised by the real `default` bus instead, which has two rules forwarding to account `222385417670` and correctly reports FAIL. |
| `ebGlobalEndpointNoReplication` | ✗ needs two same-named buses in two regions plus a Route 53 health check and an IAM role — disproportionate to one L-severity check. |

## Usage

```bash
cd services/eventbridge/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

./create_test_resources.sh --region ap-southeast-1
sleep 30

cd ../../..
python3 main.py --regions ap-southeast-1 --services eventbridge --beta 1 --sequential 1

cd services/eventbridge/simulation
./cleanup_test_resources.sh --force
```

## Cost

Effectively zero. EventBridge charges per million custom events published and
these fixtures publish none; the SQS queue and the custom bus are free at rest.
The fixtures are still worth cleaning up so they do not clutter later scans.

## Safety

- The API key value is the literal string `not-a-real-key`.
- The cleanup script only deletes names it reads from the manifest written at
  creation time, so it cannot touch a resource it did not create.
- Deletion order matters and the script handles it: API destination → connection
  → rule targets → rules → bus → queue. EventBridge refuses to delete a rule
  that still has targets, or a bus that still has rules.
- Nothing here changes an account-level or region-level setting. In particular
  no archive and no schema discoverer is created, because both are
  region-scoped and would alter the result of a later scan for other users of
  the account.
