#!/bin/bash

################################################################################
# Systems Manager Service Screener - Test Resource Creation Script
#
# Creates intentionally-misconfigured SSM Parameter Store parameters.
#
#   Parameter #1 (plaintext credential):
#     - Type=String, name contains 'password'  -> ssmParameterNotEncrypted
#     - no Description                         -> ssmParameterNoDescription
#     - no Tags                                -> ssmParameterNoTags
#
#   Parameter #2 (SecureString on the AWS-managed key):
#     - Type=SecureString, no --key-id         -> ssmParameterNoEncryptionCMK
#
# Checks NOT simulated here, and why:
#
#   The Session Manager and Default Host Management checks
#   (ssmSessionManagerNoEncryption, ssmSessionManagerNoCloudWatchLogs,
#    ssmSessionManagerNoS3Logs, ssmSessionManagerRunAsDisabled,
#    ssmDefaultHostManagementDisabled)
#     -- are REGION-WIDE ACCOUNT SETTINGS, not per-resource state. They live in
#        the SSM-SessionManagerRunShell document and a service setting, both
#        shared by every user of the region. Changing them would alter how every
#        Session Manager session in the account behaves -- including disabling
#        session logging, which destroys an audit trail. Deliberately untouched.
#        They are validated against real account state instead.
#
#   The managed-instance checks
#   (ssmManagedInstanceNotPatched, ssmManagedInstanceOldAgent,
#    ssmManagedInstanceNotOnline, ssmInventoryNotConfigured)
#     -- need a real EC2 instance with the SSM Agent registered. Launching one
#        costs money, takes minutes to register, and forcing FAIL would mean
#        deliberately leaving an instance unpatched or knocking its agent
#        offline. Validated against the account's existing managed instances.
#
#   ssmParameterOldVersion
#     -- needs Version > 20 AND LastModifiedDate > 365 days. The 21 puts are
#        cheap, but the age requirement cannot be faked, so it would still
#        report PASS. Not attempted.
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

export AWS_PAGER=""

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

# The name deliberately contains 'password' -- that substring is what
# SsmParameter.SENSITIVE_NAME_FRAGMENTS matches on. The VALUE is a harmless
# placeholder; the check never reads parameter values.
PARAM_PLAIN="/${PREFIX}/ssm/database-password-${TIMESTAMP}"
PARAM_SECURE="/${PREFIX}/ssm/secure-default-key-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Systems Manager Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Plaintext String parameter with a credential-shaped name
################################################################################

echo -e "${GREEN}=== Step 1: Plaintext parameter with a credential-shaped name ===${NC}"

# --type String (not SecureString) with no --description and no --tags.
aws ssm put-parameter \
    --name "$PARAM_PLAIN" \
    --value "not-a-real-password" \
    --type String \
    --region "$REGION" > /dev/null 2>&1 || {
        echo -e "${RED}✗ put-parameter failed${NC}"; exit 1;
    }
log "PARAMETER:${PARAM_PLAIN}"
echo -e "${GREEN}✓ ${PARAM_PLAIN}${NC}"
echo -e "  ${CYAN}-> ssmParameterNotEncrypted, ssmParameterNoDescription,${NC}"
echo -e "  ${CYAN}   ssmParameterNoTags${NC}"

################################################################################
# Step 2: SecureString parameter on the AWS-managed default key
################################################################################

echo -e "\n${GREEN}=== Step 2: SecureString on the AWS-managed key ===${NC}"

# No --key-id, so SSM encrypts with alias/aws/ssm, the AWS-managed key.
aws ssm put-parameter \
    --name "$PARAM_SECURE" \
    --value "not-a-real-secret" \
    --type SecureString \
    --region "$REGION" > /dev/null 2>&1 || {
        echo -e "${RED}✗ put-parameter failed${NC}"; exit 1;
    }
log "PARAMETER:${PARAM_SECURE}"
echo -e "${GREEN}✓ ${PARAM_SECURE}${NC}"
echo -e "  ${CYAN}-> ssmParameterNoEncryptionCMK${NC}"

################################################################################
# Report the region-wide settings this script deliberately does NOT change
################################################################################

echo -e "\n${GREEN}=== Region-wide settings (read-only — NOT modified) ===${NC}"

aws ssm get-document --name SSM-SessionManagerRunShell --region "$REGION" \
    --output json 2>/dev/null | python3 -c "
import json,sys
try:
    inputs = json.loads(json.load(sys.stdin).get('Content') or '{}').get('inputs', {})
except Exception:
    print('  SSM-SessionManagerRunShell not found -> all 4 session checks FAIL')
else:
    def verdict(v): return 'PASS' if v else 'FAIL'
    print('  kmsKeyId=%r -> ssmSessionManagerNoEncryption will %s'
          % (inputs.get('kmsKeyId', ''), verdict(inputs.get('kmsKeyId'))))
    print('  cloudWatchLogGroupName=%r -> ssmSessionManagerNoCloudWatchLogs will %s'
          % (inputs.get('cloudWatchLogGroupName', ''),
             verdict(inputs.get('cloudWatchLogGroupName'))))
    print('  s3BucketName=%r -> ssmSessionManagerNoS3Logs will %s'
          % (inputs.get('s3BucketName', ''), verdict(inputs.get('s3BucketName'))))
    print('  runAsEnabled=%r -> ssmSessionManagerRunAsDisabled will %s'
          % (inputs.get('runAsEnabled'), verdict(inputs.get('runAsEnabled') is True)))
" 2>/dev/null || echo "  (could not read Session Manager preferences)"

DHMC_STATUS=$(aws ssm get-service-setting \
    --setting-id /ssm/managed-instance/default-ec2-instance-management-role \
    --region "$REGION" --query 'ServiceSetting.Status' --output text 2>/dev/null || echo "unreadable")
echo "  DHMC status=${DHMC_STATUS} -> ssmDefaultHostManagementDisabled will $([ "$DHMC_STATUS" = "Customized" ] && echo PASS || echo FAIL)"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo ""
echo "Next:"
echo "  cd ../../.. && python3 main.py --regions $REGION --services ssm --beta 1 --sequential 1"
echo ""
echo -e "${YELLOW}Remember to run ./cleanup_test_resources.sh when finished.${NC}"
