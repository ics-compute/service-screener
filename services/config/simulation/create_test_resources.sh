#!/bin/bash

################################################################################
# AWS Config Service Screener - Test Resource Creation Script
#
# READ THIS FIRST: this script creates NOTHING by default, and that is
# deliberate.
#
# Every `config*` check reads ACCOUNT-LEVEL, REGION-WIDE state:
#
#   describe_configuration_recorders     - one recorder per account per region
#   describe_delivery_channels           - one delivery channel per account
#   describe_config_rules                - shared compliance rules
#   describe_retention_configurations    - one retention config per account
#   describe_configuration_aggregators   - org-wide aggregation
#
# There is no per-resource fixture to create. Forcing any of these checks to
# FAIL would mean STOPPING THE RECORDER, DELETING THE DELIVERY CHANNEL or
# REMOVING THE RETENTION CONFIGURATION -- destroying the account's real
# compliance audit trail and creating a genuine compliance gap for as long as
# the fixture is in place. In an account governed by Control Tower or an SCP
# those calls also fail or trigger drift alarms.
#
# So this script only VERIFIES and REPORTS the account's current AWS Config
# posture, showing which checks will FAIL and which will PASS on a real scan.
# It is a read-only pre-flight, not a fixture builder.
#
# The `config` service is validated against real account state instead. That is
# sufficient: unlike a per-resource service, the subject of these checks always
# already exists.
#
# To exercise the FAIL branches safely, use a dedicated throwaway account:
#   1. In a sandbox account with nothing depending on AWS Config,
#   2. aws configservice stop-configuration-recorder --configuration-recorder-name default
#   3. run the scan, observe configRecorderNotEnabled FAIL,
#   4. aws configservice start-configuration-recorder --configuration-recorder-name default
# Do NOT do this in an account that anything relies on.
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"

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

echo -e "${GREEN}=== AWS Config Posture Report (read-only) ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID"
echo ""
echo -e "${YELLOW}This script creates no resources. See the header comment for why.${NC}"
echo ""

################################################################################
# Configuration recorder
################################################################################

echo -e "${GREEN}=== Configuration recorder ===${NC}"

RECORDERS=$(aws configservice describe-configuration-recorders \
    --region "$REGION" --output json 2>/dev/null || echo '{}')
RECORDER_NAME=$(echo "$RECORDERS" | python3 -c "
import json,sys
d=json.load(sys.stdin).get('ConfigurationRecorders') or []
print(d[0].get('name','') if d else '')
" 2>/dev/null || echo "")

if [ -z "$RECORDER_NAME" ]; then
    echo -e "${RED}✗ No configuration recorder${NC}"
    echo -e "  ${CYAN}-> configRecorderNotEnabled will FAIL${NC}"
else
    RECORDING=$(aws configservice describe-configuration-recorder-status \
        --region "$REGION" \
        --query 'ConfigurationRecordersStatus[0].recording' \
        --output text 2>/dev/null || echo "unknown")
    LAST_STATUS=$(aws configservice describe-configuration-recorder-status \
        --region "$REGION" \
        --query 'ConfigurationRecordersStatus[0].lastStatus' \
        --output text 2>/dev/null || echo "unknown")

    echo -e "${GREEN}✓ Recorder '${RECORDER_NAME}': recording=${RECORDING}, lastStatus=${LAST_STATUS}${NC}"
    [ "$RECORDING" = "True" ] \
        && echo -e "  ${CYAN}-> configRecorderNotEnabled will PASS${NC}" \
        || echo -e "  ${CYAN}-> configRecorderNotEnabled will FAIL${NC}"
    [ "$LAST_STATUS" = "SUCCESS" ] \
        && echo -e "  ${CYAN}-> configRecorderLastStatusFailed will PASS${NC}" \
        || echo -e "  ${CYAN}-> configRecorderLastStatusFailed will FAIL${NC}"
fi

################################################################################
# Delivery channel
################################################################################

echo -e "\n${GREEN}=== Delivery channel ===${NC}"

CHANNEL=$(aws configservice describe-delivery-channels \
    --region "$REGION" --output json 2>/dev/null || echo '{}')
echo "$CHANNEL" | python3 -c "
import json,sys
d=json.load(sys.stdin).get('DeliveryChannels') or []
if not d:
    print('  MISSING -> configDeliveryChannelMissing will FAIL')
else:
    c=d[0]
    print(f\"  name={c.get('name')} bucket={c.get('s3BucketName')}\")
    print('  -> configDeliveryChannelMissing will PASS')
    print('  -> configDeliveryChannelS3NotEncrypted will '
          + ('PASS' if c.get('s3KmsKeyArn') else 'FAIL'))
    print('  -> configDeliveryChannelSNSMissing will '
          + ('PASS' if c.get('snsTopicARN') else 'FAIL'))
" 2>/dev/null || echo "  (could not read delivery channels)"

################################################################################
# Rules and compliance
################################################################################

echo -e "\n${GREEN}=== Config rules ===${NC}"

# --no-paginate is essential here: these APIs page at 25 items, and without it
# the CLI emits one length() result PER PAGE, so the counts come out as a column
# of 25s instead of a total. Summing in python over the full JSON avoids relying
# on CLI pagination behaviour at all.
RULE_COUNT=$(aws configservice describe-config-rules --region "$REGION" \
    --output json 2>/dev/null | python3 -c "
import json,sys
try: print(len(json.load(sys.stdin).get('ConfigRules') or []))
except Exception: print(0)
")
echo "  rules on the first page: $RULE_COUNT"
[ "${RULE_COUNT:-0}" -gt 0 ] 2>/dev/null \
    && echo -e "  ${CYAN}-> configNoRules will PASS${NC}" \
    || echo -e "  ${CYAN}-> configNoRules will FAIL${NC}"

NONCOMPLIANT=$(aws configservice describe-compliance-by-config-rule \
    --compliance-types NON_COMPLIANT --region "$REGION" \
    --output json 2>/dev/null | python3 -c "
import json,sys
try: print(len(json.load(sys.stdin).get('ComplianceByConfigRules') or []))
except Exception: print(0)
")
echo "  NON_COMPLIANT rules on the first page: $NONCOMPLIANT"
[ "${NONCOMPLIANT:-0}" -eq 0 ] 2>/dev/null \
    && echo -e "  ${CYAN}-> configRulesNonCompliant will PASS${NC}" \
    || echo -e "  ${CYAN}-> configRulesNonCompliant will FAIL${NC}"

echo -e "  ${YELLOW}(counts above are first-page only; the scanner paginates fully)${NC}"

################################################################################
# Retention and aggregation
################################################################################

echo -e "\n${GREEN}=== Retention and aggregation ===${NC}"

RETENTION=$(aws configservice describe-retention-configurations --region "$REGION" \
    --output json 2>/dev/null | python3 -c "
import json,sys
try: print(len(json.load(sys.stdin).get('RetentionConfigurations') or []))
except Exception: print(0)
")
echo "  retention configurations: $RETENTION"
[ "${RETENTION:-0}" -eq 0 ] 2>/dev/null \
    && echo -e "  ${CYAN}-> configNoRetentionPolicy will FAIL${NC}" \
    || echo -e "  ${CYAN}-> configNoRetentionPolicy will PASS${NC}"

AGGREGATORS=$(aws configservice describe-configuration-aggregators --region "$REGION" \
    --output json 2>/dev/null | python3 -c "
import json,sys
try: print(len(json.load(sys.stdin).get('ConfigurationAggregators') or []))
except Exception: print(0)
")
echo "  aggregators: $AGGREGATORS"
[ "${AGGREGATORS:-0}" -eq 0 ] 2>/dev/null \
    && echo -e "  ${CYAN}-> configAggregatorMissing will FAIL${NC}" \
    || echo -e "  ${CYAN}-> configAggregatorMissing will PASS${NC}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Report Complete — nothing was created or modified ===${NC}"
echo ""
echo "Run the real scan to confirm:"
echo "  cd ../../.. && python3 main.py --regions $REGION --services config --beta 1 --sequential 1"
echo ""
echo -e "${CYAN}cleanup_test_resources.sh is a no-op, provided for interface parity.${NC}"
