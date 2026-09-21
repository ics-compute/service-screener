# Secrets Manager Simulation Testing

Scripts to create intentionally-misconfigured Secrets Manager secrets so the
`sm*` service-screener checks can be validated end-to-end.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| `ss-test-sm-plain-*` | No `--kms-key-id` (AWS-managed `aws/secretsmanager` key), no rotation, no description, no tags, no replication | `smNotEncryptedWithCMK`, `smRotationNotEnabled`, `smNoDescription`, `smNoTags`, `smReplicationNotConfigured` |
| `ss-test-sm-policy-*` | Resource policy with `Principal: "*"` and no `Condition` | `smResourcePolicyPublicAccess` |
| `ss-test-sm-pending-*` | `delete-secret` with a 30-day recovery window, so `DeletedDate` is set | `smPendingDeletion` |

## Coverage

| Check | Simulated? |
|---|---|
| `smNotEncryptedWithCMK` | ✓ FAIL |
| `smRotationNotEnabled` | ✓ FAIL |
| `smNoDescription` | ✓ FAIL |
| `smNoTags` | ✓ FAIL |
| `smReplicationNotConfigured` | ✓ FAIL |
| `smResourcePolicyPublicAccess` | ✓ FAIL — unless an SCP or the account's block-public-policy setting rejects the wildcard principal, in which case the script warns and the check reports INFO |
| `smResourcePolicyCrossAccount` | ✗ needs a **named** principal in a second account. The check skips wildcard principals by design (they belong to `smResourcePolicyPublicAccess`), and `PutResourcePolicy` rejects a fabricated account ID with `MalformedPolicyDocumentException: unsupported principal` because it validates that the principal resolves. Naming a real third-party account would grant it genuine read access to a secret, so this needs a second account under the same ownership. |
| `smPendingDeletion` | ✓ FAIL |
| `smRotationOverdue` | ✗ needs `RotationEnabled=true`, which Secrets Manager only accepts with a working rotation Lambda |
| `smRotationLambdaMissing` | ✗ same reason |
| `smAutoRotationScheduleInvalid` | ✗ same reason |
| `smNotUsedRecently` | ✗ fires at `LastAccessedDate` > 90 days; a new secret cannot be that old |
| `smLastChangedOld` | ✗ fires at `LastChangedDate` > 365 days; same reason |
| `smVersionsExcessive` | ✗ needs > 10 non-current versions, and Secrets Manager expires non-current versions on its own schedule, so the outcome is not deterministic |
| `smNoVersionStages` | ✗ a secret with no `AWSCURRENT` stage cannot be created through the API — it only arises from a failed rotation |

The six age- and rotation-dependent checks are exercised by the real secrets in
an existing account rather than by fixtures. In the test account
(`ap-southeast-1`) the six pre-existing secrets produce FAILs for
`smLastChangedOld`, `smNotUsedRecently`, `smRotationNotEnabled` and
`smNotEncryptedWithCMK`.

## Usage

```bash
cd services/secretsmanager/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

./create_test_resources.sh --region ap-southeast-1
sleep 30

cd ../../..
python3 main.py --regions ap-southeast-1 --services secretsmanager --beta 1 --sequential 1

cd services/secretsmanager/simulation
./cleanup_test_resources.sh --force
```

## Cost

Secrets Manager bills **$0.40 per secret per month**, prorated, plus $0.05 per
10,000 API calls. Three secrets left for an hour cost well under a cent, but
they bill indefinitely if cleanup is skipped — the cleanup script is not
optional.

`cleanup_test_resources.sh` uses `--force-delete-without-recovery` so the names
are immediately reusable; a plain `delete-secret` would leave them in
`PendingDeletion` for up to 30 days and block recreating them.

Deletion is **asynchronous**: `delete-secret` returns a `DeletionDate` straight
away, but the secret keeps appearing in `list-secrets --include-planned-deletion`
with a `DeletedDate` for a minute or two afterwards. That is expected — allow
roughly 90 seconds before concluding that cleanup failed.

## Safety

- Every secret value is the literal string `not-a-real-password`. No real
  credential is ever written.
- The cleanup script only deletes ARNs it reads from the manifest file written
  at creation time, so it cannot delete a secret it did not create.
- Nothing here changes an account-level or region-level setting.
