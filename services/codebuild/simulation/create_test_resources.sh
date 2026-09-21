#!/bin/bash

################################################################################
# CodeBuild Service Screener - Test Resource Creation Script
#
# Creates intentionally-misconfigured CodeBuild projects plus a report group.
#
#   Project #1 (insecure baseline):
#     - PLAINTEXT env vars named AWS_SECRET_ACCESS_KEY / DB_PASSWORD
#                                          -> cbPlaintextCredentialsInEnvVars
#     - environment.privilegedMode = true  -> cbPrivilegedMode
#     - artifacts.encryptionDisabled       -> cbNoArtifactEncryption
#     - no encryptionKey                   -> cbEncryptionDefaultKey
#     - source.insecureSsl = true          -> cbInsecureSSL
#     - no concurrentBuildLimit            -> cbConcurrentBuildLimitNotSet
#     - no tags                            -> cbNoTags
#     - retired image ubuntu:standard:5.0  -> cbImageOutdated
#     - logging fully disabled             -> cbLogsDisabled
#
#   Project #2 (S3 logs, unencrypted):
#     - s3Logs ENABLED, encryptionDisabled -> cbS3LogsNotEncrypted
#
#   Report group #1:
#     - S3 export, encryptionDisabled      -> cbReportGroupExportNotEncrypted
#
# NOTE ON SECRET VALUES: every "credential" written here is the literal string
# not-a-real-secret. The checks match on the variable NAME, never the value, so a
# realistic value would serve no purpose and would create an actual secret in the
# account.
#
# Checks NOT simulated, and why:
#   cbSourceUrlCredentials
#     -- would require putting a real-looking user:password@host URL into a
#        project definition. CodeBuild validates the source on create for most
#        provider types, and writing a credential-shaped string into an account is
#        exactly what the check exists to discourage. Verify by unit-testing the
#        URL_CREDENTIAL_PATTERN regex instead.
#   cbProjectVisibilityPublic
#     -- update_project_visibility makes build logs WORLD-READABLE. Not something
#        a test fixture should ever do, even briefly.
#   cbNoVpcConfig / cbSourceCredentialsInsecure
#     -- both are INFO-only by design; project #1 exercises the INFO branch.
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

PROJECT_INSECURE="${PREFIX}-cb-insecure-${TIMESTAMP}"
PROJECT_S3LOGS="${PREFIX}-cb-s3logs-${TIMESTAMP}"
REPORT_GROUP="${PREFIX}-cb-reports-${TIMESTAMP}"
ROLE_NAME="${PREFIX}-cb-role-${TIMESTAMP}"
BUCKET="${PREFIX}-cb-${ACCOUNT_ID}-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== CodeBuild Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Service role (CodeBuild refuses to create a project without one)
################################################################################

echo -e "${GREEN}=== Step 1: Minimal CodeBuild service role ===${NC}"

cat > "/tmp/${PREFIX}-cb-trust.json" <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "codebuild.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

ROLE_ARN=$(aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file:///tmp/${PREFIX}-cb-trust.json" \
    --description "ss-test CodeBuild simulation role - safe to delete" \
    --query 'Role.Arn' --output text 2>&1) || {
        echo -e "${RED}✗ create-role failed${NC}"; echo "$ROLE_ARN" | head -3; exit 1;
    }
log "ROLE:${ROLE_NAME}"
rm -f "/tmp/${PREFIX}-cb-trust.json"
echo -e "${GREEN}✓ ${ROLE_NAME}${NC}"

# IAM role propagation to CodeBuild is not immediate.
echo -n "  waiting for role propagation"
for _ in $(seq 1 10); do echo -n "."; sleep 3; done
echo ""

################################################################################
# Step 2: S3 bucket for artifacts, S3 build logs and report exports
################################################################################

echo -e "\n${GREEN}=== Step 2: S3 bucket for artifacts and logs ===${NC}"

if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" > /dev/null 2>&1
else
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
        --create-bucket-configuration "LocationConstraint=$REGION" > /dev/null 2>&1
fi
if [ $? -eq 0 ]; then
    log "BUCKET:${BUCKET}"
    echo -e "${GREEN}✓ s3://${BUCKET}${NC}"
else
    echo -e "${YELLOW}⚠ bucket create failed; S3-log and report checks will report INFO${NC}"
    BUCKET=""
fi

################################################################################
# Step 3: Insecure project — hits 9 checks at once
################################################################################

echo -e "\n${GREEN}=== Step 3: Insecure project ===${NC}"

# ubuntu:standard:5.0 is a retired image -> cbImageOutdated.
# privilegedMode + encryptionDisabled + PLAINTEXT credential-named env vars.
# NO_SOURCE avoids needing a real repository; insecureSsl is set anyway so the
# field is present for the check to read.
cat > "/tmp/${PREFIX}-cb-src.json" <<EOF
{
  "type": "NO_SOURCE",
  "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ss-test\n",
  "insecureSsl": true
}
EOF

cat > "/tmp/${PREFIX}-cb-env.json" <<'EOF'
{
  "type": "LINUX_CONTAINER",
  "image": "aws/codebuild/standard:5.0",
  "computeType": "BUILD_GENERAL1_SMALL",
  "privilegedMode": true,
  "environmentVariables": [
    {"name": "AWS_SECRET_ACCESS_KEY", "value": "not-a-real-secret", "type": "PLAINTEXT"},
    {"name": "DB_PASSWORD", "value": "not-a-real-secret", "type": "PLAINTEXT"},
    {"name": "HARMLESS_SETTING", "value": "true", "type": "PLAINTEXT"}
  ]
}
EOF

ARTIFACTS='{"type":"NO_ARTIFACTS"}'
if [ -n "$BUCKET" ]; then
    ARTIFACTS="{\"type\":\"S3\",\"location\":\"${BUCKET}\",\"path\":\"artifacts\",\"encryptionDisabled\":true,\"packaging\":\"ZIP\",\"name\":\"out.zip\"}"
fi

if aws codebuild create-project \
    --name "$PROJECT_INSECURE" \
    --source "file:///tmp/${PREFIX}-cb-src.json" \
    --artifacts "$ARTIFACTS" \
    --environment "file:///tmp/${PREFIX}-cb-env.json" \
    --service-role "$ROLE_ARN" \
    --logs-config '{"cloudWatchLogs":{"status":"DISABLED"},"s3Logs":{"status":"DISABLED"}}' \
    --region "$REGION" > /dev/null 2>&1; then
    log "PROJECT:${PROJECT_INSECURE}"
    echo -e "${GREEN}✓ ${PROJECT_INSECURE}${NC}"
    echo -e "  ${CYAN}-> cbPlaintextCredentialsInEnvVars, cbPrivilegedMode,${NC}"
    echo -e "  ${CYAN}   cbNoArtifactEncryption, cbEncryptionDefaultKey, cbInsecureSSL,${NC}"
    echo -e "  ${CYAN}   cbLogsDisabled, cbImageOutdated, cbConcurrentBuildLimitNotSet,${NC}"
    echo -e "  ${CYAN}   cbNoTags${NC}"
else
    echo -e "${RED}✗ create-project failed${NC}"
    aws codebuild create-project --name "$PROJECT_INSECURE" \
        --source "file:///tmp/${PREFIX}-cb-src.json" --artifacts "$ARTIFACTS" \
        --environment "file:///tmp/${PREFIX}-cb-env.json" \
        --service-role "$ROLE_ARN" --region "$REGION" 2>&1 | head -3
fi

################################################################################
# Step 4: Project with unencrypted S3 build logs
################################################################################

if [ -n "$BUCKET" ]; then
    echo -e "\n${GREEN}=== Step 4: Project with unencrypted S3 build logs ===${NC}"
    if aws codebuild create-project \
        --name "$PROJECT_S3LOGS" \
        --source "file:///tmp/${PREFIX}-cb-src.json" \
        --artifacts '{"type":"NO_ARTIFACTS"}' \
        --environment "file:///tmp/${PREFIX}-cb-env.json" \
        --service-role "$ROLE_ARN" \
        --logs-config "{\"cloudWatchLogs\":{\"status\":\"ENABLED\"},\"s3Logs\":{\"status\":\"ENABLED\",\"location\":\"${BUCKET}/buildlogs\",\"encryptionDisabled\":true}}" \
        --region "$REGION" > /dev/null 2>&1; then
        log "PROJECT:${PROJECT_S3LOGS}"
        echo -e "${GREEN}✓ ${PROJECT_S3LOGS}${NC}"
        echo -e "  ${CYAN}-> cbS3LogsNotEncrypted${NC}"
    else
        echo -e "${YELLOW}⚠ second project create failed${NC}"
    fi
fi

rm -f "/tmp/${PREFIX}-cb-src.json" "/tmp/${PREFIX}-cb-env.json"

################################################################################
# Step 5: Report group exporting to S3 without encryption
################################################################################

if [ -n "$BUCKET" ]; then
    echo -e "\n${GREEN}=== Step 5: Report group with unencrypted S3 export ===${NC}"
    if aws codebuild create-report-group \
        --name "$REPORT_GROUP" \
        --type TEST \
        --export-config "{\"exportConfigType\":\"S3\",\"s3Destination\":{\"bucket\":\"${BUCKET}\",\"path\":\"reports\",\"packaging\":\"NONE\",\"encryptionDisabled\":true}}" \
        --region "$REGION" > /dev/null 2>&1; then
        log "REPORTGROUP:${REPORT_GROUP}"
        echo -e "${GREEN}✓ ${REPORT_GROUP}${NC}"
        echo -e "  ${CYAN}-> cbReportGroupExportNotEncrypted${NC}"
    else
        echo -e "${YELLOW}⚠ create-report-group failed${NC}"
    fi
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo ""
echo "Next:"
echo "  cd ../../.. && python3 main.py --regions $REGION --services codebuild --beta 1 --sequential 1"
echo ""
echo -e "${YELLOW}Remember to run ./cleanup_test_resources.sh when finished.${NC}"
echo -e "${YELLOW}No builds are ever started, so no build minutes are consumed.${NC}"
