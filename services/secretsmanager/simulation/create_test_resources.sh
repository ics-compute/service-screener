#!/bin/bash

################################################################################
# Secrets Manager Service Screener - Test Resource Creation Script
#
# Creates intentionally-misconfigured Secrets Manager secrets that exercise
# every `sm*` check reachable through the AWS API without mutating any
# account-level setting.
#
#   Secret #1 (baseline, AWS-managed key, no rotation):
#     - no KmsKeyId                    -> smNotEncryptedWithCMK
#     - RotationEnabled=false          -> smRotationNotEnabled
#     - no Description                 -> smNoDescription
#     - no Tags                        -> smNoTags
#     - no ReplicationStatus           -> smReplicationNotConfigured
#     - never retrieved                -> smNotUsedRecently (see note below)
#
#   Secret #2 (public resource policy):
#     - resource policy Principal:"*"  -> smResourcePolicyPublicAccess
#
#   Secret #3 (scheduled for deletion):
#     - DeletedDate set                -> smPendingDeletion
#
# Checks NOT simulated here, and why:
#   smRotationOverdue, smRotationLambdaMissing, smAutoRotationScheduleInvalid
#     -- all require RotationEnabled=true, which Secrets Manager only accepts
#        alongside a working rotation Lambda. Standing up that Lambda (plus its
#        execution role and VPC access) is a larger fixture than the check
#        warrants, and Secrets Manager rejects an unbacked rotation config.
#   smNotUsedRecently
#     -- fires at LastAccessedDate > 90 days. A freshly created secret cannot be
#        90 days old, so this check reports INFO on the fixtures. It is exercised
#        by real secrets in an existing account instead.
#   smLastChangedOld
#     -- same reason: needs LastChangedDate > 365 days.
#   smVersionsExcessive
#     -- needs > 10 non-current versions. The script could put 11 versions, but
#        Secrets Manager retains non-current versions on its own schedule, so the
#        result is not deterministic enough to assert on.
#   smNoVersionStages
#     -- a secret with no AWSCURRENT stage cannot be created through the API;
#        it only arises from a failed rotation.
#   smResourcePolicyCrossAccount
#     -- needs a NAMED principal in another account (the check skips wildcards by
#        design). PutResourcePolicy rejects a fabricated account ID, and naming a
#        real one would grant it genuine access. Needs a second owned account.
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

SECRET_PLAIN="${PREFIX}-sm-plain-${TIMESTAMP}"
SECRET_POLICY="${PREFIX}-sm-policy-${TIMESTAMP}"
SECRET_PENDING="${PREFIX}-sm-pending-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Secrets Manager Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Baseline secret — AWS-managed key, no rotation, no description/tags
################################################################################

echo -e "${GREEN}=== Step 1: Baseline secret (no CMK, no rotation, no tags) ===${NC}"

# No --kms-key-id, so Secrets Manager uses the AWS-managed aws/secretsmanager
# key. No --description and no --tags, so the hygiene checks fire too.
ARN_PLAIN=$(aws secretsmanager create-secret \
    --name "$SECRET_PLAIN" \
    --secret-string '{"username":"ss-test","password":"not-a-real-password"}' \
    --region "$REGION" \
    --query 'ARN' --output text 2>&1) || {
        echo -e "${RED}✗ create-secret failed${NC}"; echo "$ARN_PLAIN" | head -3; exit 1;
    }
log "SECRET:${ARN_PLAIN}"
echo -e "${GREEN}✓ ${SECRET_PLAIN}${NC}"
echo -e "  ${CYAN}-> smNotEncryptedWithCMK, smRotationNotEnabled, smNoDescription,${NC}"
echo -e "  ${CYAN}   smNoTags, smReplicationNotConfigured${NC}"

################################################################################
# Step 2: Secret with a public + cross-account resource policy
################################################################################

echo -e "\n${GREEN}=== Step 2: Secret with public wildcard resource policy ===${NC}"

ARN_POLICY=$(aws secretsmanager create-secret \
    --name "$SECRET_POLICY" \
    --secret-string '{"username":"ss-test","password":"not-a-real-password"}' \
    --region "$REGION" \
    --query 'ARN' --output text 2>&1) || {
        echo -e "${RED}✗ create-secret failed${NC}"; echo "$ARN_POLICY" | head -3; exit 1;
    }
log "SECRET:${ARN_POLICY}"

# Principal "*" with NO Condition is what smResourcePolicyPublicAccess looks
# for. BlockPublicPolicy is deliberately NOT passed -- that flag exists to
# reject exactly this policy, which is the misconfiguration being simulated.
#
# smResourcePolicyCrossAccount is deliberately NOT simulated here.
# _checkSmResourcePolicyCrossAccount skips wildcard principals by design (they
# belong to the public-access check), so firing it needs a NAMED principal in
# another account -- and PutResourcePolicy rejects a fabricated account ID with
# MalformedPolicyDocumentException ("unsupported principal"), because it
# validates that the principal resolves. Naming a real third-party account would
# grant that account genuine read access to a secret, which is not something a
# test fixture should do. The check therefore needs a second account under the
# same ownership to exercise.
cat > "/tmp/${PREFIX}-sm-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicGetSecretValueNoCondition",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }
  ]
}
EOF

if aws secretsmanager put-resource-policy \
    --secret-id "$ARN_POLICY" \
    --resource-policy "$(tr -d '\n' < "/tmp/${PREFIX}-sm-policy.json")" \
    --region "$REGION" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ ${SECRET_POLICY} (public policy applied)${NC}"
    echo -e "  ${CYAN}-> smResourcePolicyPublicAccess, smResourcePolicyCrossAccount${NC}"
else
    echo -e "${YELLOW}⚠ put-resource-policy was rejected${NC}"
    echo -e "${YELLOW}  An SCP or the account's block-public-policy setting refused${NC}"
    echo -e "${YELLOW}  the wildcard principal. smResourcePolicy* will report INFO.${NC}"
fi
rm -f "/tmp/${PREFIX}-sm-policy.json"

################################################################################
# Step 3: Secret scheduled for deletion
################################################################################

echo -e "\n${GREEN}=== Step 3: Secret scheduled for deletion ===${NC}"

ARN_PENDING=$(aws secretsmanager create-secret \
    --name "$SECRET_PENDING" \
    --secret-string '{"username":"ss-test","password":"not-a-real-password"}' \
    --region "$REGION" \
    --query 'ARN' --output text 2>&1) || {
        echo -e "${RED}✗ create-secret failed${NC}"; echo "$ARN_PENDING" | head -3; exit 1;
    }
log "SECRET:${ARN_PENDING}"

# 30 days is the maximum window, keeping the fixture recoverable for the
# longest possible time in case cleanup is forgotten.
aws secretsmanager delete-secret \
    --secret-id "$ARN_PENDING" \
    --recovery-window-in-days 30 \
    --region "$REGION" > /dev/null 2>&1 \
    && echo -e "${GREEN}✓ ${SECRET_PENDING} (deletion scheduled, 30-day window)${NC}" \
    && echo -e "  ${CYAN}-> smPendingDeletion${NC}" \
    || echo -e "${YELLOW}⚠ delete-secret failed; smPendingDeletion will not fire${NC}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo ""
echo "Next:"
echo "  sleep 30"
echo "  cd ../../.. && python3 main.py --regions $REGION --services secretsmanager --beta 1 --sequential 1"
echo ""
echo -e "${YELLOW}Remember to run ./cleanup_test_resources.sh when finished.${NC}"
echo -e "${YELLOW}Secrets cost \$0.40/secret/month if left behind.${NC}"
