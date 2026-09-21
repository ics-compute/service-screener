# Systems Manager Simulation Testing

Scripts to create intentionally-misconfigured SSM Parameter Store parameters so
the `ssmParameter*` checks can be validated end-to-end. The Session Manager,
Default Host Management and managed-instance checks are validated against real
account state instead — see below for why.

## Resources Created

All under the `/ss-test/` path prefix:

| Resource | Configuration | Directly Validates |
|---|---|---|
| `/ss-test/ssm/database-password-*` | `Type=String` with `password` in the name, no description, no tags | `ssmParameterNotEncrypted`, `ssmParameterNoDescription`, `ssmParameterNoTags` |
| `/ss-test/ssm/secure-default-key-*` | `Type=SecureString` with no `--key-id`, so it uses the AWS-managed `alias/aws/ssm` | `ssmParameterNoEncryptionCMK` |

The two fixtures are complementary: the plaintext one FAILs
`ssmParameterNotEncrypted` and reports INFO for `ssmParameterNoEncryptionCMK`
(no KMS key applies to a `String`), while the SecureString one does the reverse.
Together they cover both branches.

## Coverage

Verified against a test account in `ap-southeast-1`:

| Check | Simulated? |
|---|---|
| `ssmParameterNotEncrypted` | ✓ FAIL |
| `ssmParameterNoEncryptionCMK` | ✓ FAIL |
| `ssmParameterNoDescription` | ✓ FAIL |
| `ssmParameterNoTags` | ✓ FAIL |
| `ssmParameterOldVersion` | ✗ needs `Version > 20` **and** `LastModifiedDate > 365 days`. The 21 puts are cheap but the age cannot be faked, so it would still PASS. |
| `ssmSessionManagerNoEncryption` | ✗ region-wide setting — FAILs on real account state |
| `ssmSessionManagerNoCloudWatchLogs` | ✗ region-wide setting — FAILs on real account state |
| `ssmSessionManagerNoS3Logs` | ✗ region-wide setting — FAILs on real account state |
| `ssmSessionManagerRunAsDisabled` | ✗ region-wide setting — FAILs on real account state |
| `ssmDefaultHostManagementDisabled` | ✗ region-wide setting — PASSes on real account state (`Status=Customized`) |
| `ssmManagedInstanceNotPatched` | ✗ needs a real EC2 instance — PASSes on the account's existing instance |
| `ssmManagedInstanceOldAgent` | ✗ needs a real EC2 instance — PASSes (agent is latest) |
| `ssmManagedInstanceNotOnline` | ✗ needs a real EC2 instance — PASSes (`PingStatus=Online`) |
| `ssmInventoryNotConfigured` | ✗ needs a real EC2 instance — PASSes (1 inventory entry) |

All 14 checks evaluate on a real scan. `create_test_resources.sh` prints a
read-only report of the region-wide settings so you can see what each of those
checks will return before running the scanner.

## Why the region-wide settings are not modified

The four Session Manager checks read the `SSM-SessionManagerRunShell` document
and `ssmDefaultHostManagementDisabled` reads a service setting. Both are
**shared by every user of the region**. Changing them would alter how every
Session Manager session in the account behaves — and switching session logging
off to force a FAIL destroys an audit trail, which is exactly the outcome the
check exists to prevent. They are left alone deliberately.

The managed-instance checks need an EC2 instance with the SSM Agent registered.
Launching one costs money and takes minutes to register, and forcing a FAIL
would mean deliberately leaving an instance unpatched or knocking its agent
offline.

> **Note on the Default Host Management setting ID.** The correct ID is
> `/ssm/managed-instance/default-ec2-instance-management-role`. The ID given in
> the original spec —
> `/ssm/managed-instance/default-instance-management-configuration/ec2-instance-management`
> — does not exist; `GetServiceSetting` rejects it with
> `ServiceSettingNotFound`. Its `SettingValue` is the **name of an IAM role**,
> not `true`/`false`, so the authoritative signal is `Status`: `Customized`
> means DHMC is configured, `Default` means it is not.

## Usage

```bash
cd services/ssm/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

./create_test_resources.sh --region ap-southeast-1

cd ../../..
python3 main.py --regions ap-southeast-1 --services ssm --beta 1 --sequential 1

cd services/ssm/simulation
./cleanup_test_resources.sh --force
```

No `sleep` is needed — Parameter Store is immediately consistent for
`describe-parameters`.

## Cost

Standard-tier parameters are free (advanced tier would be $0.05 each per month;
these are standard). The KMS calls for the SecureString parameter cost
$0.03 per 10,000 requests. Effectively zero.

## Safety

- Parameter values are the literal strings `not-a-real-password` and
  `not-a-real-secret`. No real credential is ever written. The checks never read
  parameter values — `ssmParameterNotEncrypted` matches on the parameter *name* —
  so a realistic value would serve no purpose.
- The cleanup script only deletes names it reads from the manifest written at
  creation time, so it cannot delete a parameter it did not create.
- No region-wide or account-level setting is modified, so there is nothing to
  restore if cleanup is interrupted.
