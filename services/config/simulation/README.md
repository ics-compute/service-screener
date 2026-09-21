# AWS Config Simulation Testing

**This service has no fixtures, by design.** `create_test_resources.sh` is a
read-only posture report and `cleanup_test_resources.sh` is a no-op.

## Why there is nothing to create

Every `config*` check reads account-level, region-wide state:

| API | Scope |
|---|---|
| `describe_configuration_recorders` | One recorder per account per region |
| `describe_delivery_channels` | One delivery channel per account per region |
| `describe_config_rules` | Shared compliance rules |
| `describe_retention_configurations` | One retention configuration per account |
| `describe_configuration_aggregators` | Org-wide aggregation |

There is no per-resource object to stand up. Forcing any of these checks to FAIL
would mean stopping the configuration recorder, deleting the delivery channel or
removing the retention configuration — which destroys the account's real
compliance audit trail and creates a genuine compliance gap for as long as the
fixture exists. In a Control Tower or SCP-governed account those calls also fail
outright or raise drift alarms.

Unlike a per-resource service, the subject of these checks **always already
exists**, so scanning the real account is a complete test rather than a partial
one.

## Coverage from real account state

Verified against a test account in `ap-southeast-1`:

| Check | Result | Why |
|---|---|---|
| `configRecorderNotEnabled` | PASS | Recorder `default` is recording |
| `configRecorderLastStatusFailed` | PASS | `lastStatus=SUCCESS` |
| `configDeliveryChannelMissing` | PASS | Channel `default` delivers to S3 |
| `configNoRules` | PASS | 364 active rules |
| `configAggregatorMissing` | PASS | One Control Tower aggregator |
| `configDeliveryChannelS3NotEncrypted` | **FAIL** | No `s3KmsKeyArn` |
| `configDeliveryChannelSNSMissing` | **FAIL** | No `snsTopicARN` |
| `configRulesNonCompliant` | **FAIL** | 95 of 364 rules NON_COMPLIANT |
| `configNoRemediationActions` | **FAIL** | None of the 95 have remediation configured |
| `configNoRetentionPolicy` | **FAIL** | No retention configuration |
| `configRecorderNotAllResources` | **FAIL** | Recorder excludes key resource types |
| `configRecorderExcludesGlobalResources` | **FAIL** | Exclusion list excludes global types |

All 12 checks evaluate, 7 FAIL and 5 PASS — both branches of the driver are
exercised without creating anything.

## Usage

```bash
cd services/config/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

# Read-only posture report: predicts which checks will FAIL
./create_test_resources.sh --region ap-southeast-1

cd ../../..
python3 main.py --regions ap-southeast-1 --services config --beta 1 --sequential 1
```

## Exercising the FAIL branches that the account already satisfies

Only in a **dedicated throwaway account** with nothing depending on AWS Config:

```bash
aws configservice stop-configuration-recorder \
    --configuration-recorder-name default --region ap-southeast-1
# scan -> configRecorderNotEnabled FAILs
aws configservice start-configuration-recorder \
    --configuration-recorder-name default --region ap-southeast-1
```

Do not do this in an account anything relies on: while the recorder is stopped,
no configuration items are captured and that window is permanently absent from
the configuration history.

## Cost

Zero. Nothing is created, and the read-only APIs used are not billed.
