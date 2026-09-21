#!/bin/bash
################################################################################
# CloudFormation Service Screener - Test Resource Creation Script
#
# Creates one minimal, intentionally-unprotected stack.
#
#   Stack #1 (an SSM parameter -- the cheapest possible real resource):
#     - EnableTerminationProtection false  -> cfnTerminationProtectionDisabled
#     - no stack policy                    -> cfnStackPolicyMissing
#     - no RollbackConfiguration           -> cfnNoRollbackConfiguration
#     - no NotificationARNs                -> cfnNoNotifications
#     - no tags                            -> cfnNoTags
#     - drift never checked                -> cfnDriftNeverChecked
#
# READ-ONLY NOTE for the scanner (not this script): the cfnDriftDetected check
# reads DriftInformation from describe_stacks. It does NOT call
# detect_stack_drift, which is a WRITE operation that starts a billed async
# detection run. This fixture therefore exercises the NOT_CHECKED branch.
#
# Checks NOT simulated:
#   cfnDriftDetected      -- forcing DRIFTED means manually mutating a
#     stack-managed resource behind CloudFormation's back, then running drift
#     detection (a write). The account's own stacks already include a DRIFTED one.
#   cfnRollbackFailed     -- requires deliberately breaking a deployment.
#   cfnOldStackUnupdated  -- needs a stack older than a year.
#   cfnIAMCapabilityGranted -- INFO only; would need an IAM resource in the
#     template, which this fixture deliberately avoids creating.
#
# Usage: ./create_test_resources.sh [--region REGION] [--help]
################################################################################
set -u
REGION="${AWS_REGION:-ap-southeast-1}"; PREFIX="ss-test"; TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) echo -e "${RED}Unknown: $1${NC}"; exit 1 ;; esac; done
export AWS_PAGER=""
STACK="${PREFIX}-cfn-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"; > "$OUTPUT_FILE"
echo -e "${GREEN}=== CloudFormation Test Resource Creation ===${NC}"
echo "Region: $REGION"; echo ""

# An SSM String parameter is free and creates nothing billable.
cat > "/tmp/${PREFIX}-cfn-template.json" <<'EOF'
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "ss-test simulation stack - safe to delete",
  "Resources": {
    "TestParameter": {
      "Type": "AWS::SSM::Parameter",
      "Properties": {
        "Type": "String",
        "Value": "ss-test-simulation",
        "Description": "Created by service-screener simulation"
      }
    }
  }
}
EOF

# No --enable-termination-protection, no --stack-policy-body, no
# --rollback-configuration, no --notification-arns, no --tags: all deliberate.
if aws cloudformation create-stack --stack-name "$STACK" \
    --template-body "file:///tmp/${PREFIX}-cfn-template.json" \
    --region "$REGION" > /dev/null 2>&1; then
    echo "STACK:${STACK}" >> "$OUTPUT_FILE"
    echo -n "  waiting for CREATE_COMPLETE"
    aws cloudformation wait stack-create-complete --stack-name "$STACK" \
        --region "$REGION" 2>/dev/null && echo " done" || echo " (timed out; check console)"
    echo -e "${GREEN}✓ ${STACK}${NC}"
    echo -e "  ${CYAN}-> cfnTerminationProtectionDisabled, cfnStackPolicyMissing,${NC}"
    echo -e "  ${CYAN}   cfnNoRollbackConfiguration, cfnNoNotifications, cfnNoTags,${NC}"
    echo -e "  ${CYAN}   cfnDriftNeverChecked${NC}"
else
    echo -e "${RED}✗ create-stack failed${NC}"
fi
rm -f "/tmp/${PREFIX}-cfn-template.json"
echo ""; echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "  cd ../../.. && python3 main.py --regions $REGION --services cloudformation --beta 1 --sequential 1"
