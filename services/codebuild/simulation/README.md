# CodeBuild Simulation Testing

Scripts to create intentionally-misconfigured CodeBuild projects and a report
group so the `cb*` checks can be validated end-to-end.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| IAM role `ss-test-cb-role-*` | Minimal CodeBuild trust policy (no permissions attached) | *(supporting resource)* |
| S3 bucket `ss-test-cb-<acct>-*` | Holds artifacts, S3 build logs, report exports | *(supporting resource)* |
| Project `ss-test-cb-insecure-*` | PLAINTEXT credential env vars, `privilegedMode=true`, `encryptionDisabled` artifacts, no CMK, `insecureSsl=true`, no concurrent-build limit, no tags, retired `standard:5.0` image, all logging off | `cbPlaintextCredentialsInEnvVars`, `cbPrivilegedMode`, `cbNoArtifactEncryption`, `cbEncryptionDefaultKey`, `cbInsecureSSL`, `cbConcurrentBuildLimitNotSet`, `cbNoTags`, `cbImageOutdated`, `cbLogsDisabled` |
| Project `ss-test-cb-s3logs-*` | S3 build logs enabled with `encryptionDisabled=true` | `cbS3LogsNotEncrypted` |
| Report group `ss-test-cb-reports-*` | S3 export with `encryptionDisabled=true` | `cbReportGroupExportNotEncrypted` |

## Coverage

Verified against a test account in `ap-southeast-1`:

| Check | Simulated? |
|---|---|
| `cbPlaintextCredentialsInEnvVars` | ✓ FAIL (CRITICAL class) |
| `cbPrivilegedMode` | ✓ FAIL |
| `cbNoArtifactEncryption` | ✓ FAIL |
| `cbEncryptionDefaultKey` | ✓ FAIL |
| `cbInsecureSSL` | ✓ FAIL |
| `cbConcurrentBuildLimitNotSet` | ✓ FAIL |
| `cbNoTags` | ✓ FAIL |
| `cbImageOutdated` | ✓ FAIL |
| `cbLogsDisabled` | ✓ FAIL |
| `cbS3LogsNotEncrypted` | ✓ FAIL |
| `cbReportGroupExportNotEncrypted` | ✓ FAIL |
| `cbSourceUrlCredentials` | ✗ would require writing a `user:password@host` URL into a project — the check matches the URL pattern; unit-test the regex instead |
| `cbProjectVisibilityPublic` | ✗ `update-project-visibility PUBLIC_READ` makes build logs world-readable; not something a fixture should do even briefly |
| `cbNoVpcConfig` | ✗ INFO-only by design; the insecure project exercises the INFO branch |
| `cbSourceCredentialsInsecure` | ✗ INFO-only by design; same |

11 of 15 checks FAIL on the fixtures; the other 4 are either unsafe to simulate
or INFO-only. No builds are ever started, so **no build minutes are consumed**.

## Two bugs these fixtures caught

Worth recording, because they are the kind of thing static review misses:

1. **`cbEncryptionDefaultKey`** — CodeBuild does *not* leave `encryptionKey` null
   when none is given; it populates the field with `arn:aws:kms:...:alias/aws/s3`.
   The check was rewritten to detect that default key rather than an absent one.
2. **`cbImageOutdated`** — the image identifier is `aws/codebuild/standard:5.0`,
   not the `ubuntu:standard:5.0` short form the check first looked for.

## Usage

```bash
cd services/codebuild/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

./create_test_resources.sh --region ap-southeast-1

cd ../../..
python3 main.py --regions ap-southeast-1 --services codebuild --beta 1 --sequential 1

cd services/codebuild/simulation
./cleanup_test_resources.sh --force
```

## Cost

Effectively zero. No builds are started, so no build minutes accrue. The S3
bucket holds nothing until a build runs. The IAM role and empty projects are
free at rest.

## Safety

- Every credential value written is the literal string `not-a-real-secret`. The
  two credential checks match on the variable **name** and source **URL pattern**,
  never the value — verified: `not-a-real-secret` appears in no scan output.
- The cleanup script only deletes names it read from the manifest, in dependency
  order (report group → projects → bucket → role), so it cannot touch a resource
  it did not create.
- No builds are started and no account-level setting is modified.
