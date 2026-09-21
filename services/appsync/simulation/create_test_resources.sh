#!/bin/bash
################################################################################
# AppSync Service Screener - Test Resource Creation Script
#
# Creates an intentionally-misconfigured AppSync GraphQL API.
#
#   API #1 (insecure baseline):
#     - authenticationType API_KEY only     -> appsyncNoAuthentication
#     - introspectionConfig ENABLED (default)-> appsyncIntrospectionEnabled
#     - no wafWebAclArn, visibility GLOBAL  -> appsyncWafNotAssociated
#     - no queryDepthLimit                  -> appsyncNoQueryDepthLimit
#     - no resolverCountLimit               -> appsyncNoResolverCountLimit
#     - no logConfig                        -> appsyncFieldLevelLogging,
#                                              appsyncCloudWatchLogsNotEnabled
#     - xrayEnabled false                   -> appsyncXrayTracingDisabled
#     - no tags                             -> appsyncNoTags
#     - API key with max (365d) expiry      -> appsyncApiKeyNoExpiry (boundary)
#
# Checks NOT simulated:
#   appsyncApiKeyExpiringSoon -- AppSync enforces a MINIMUM key lifetime of 1 day
#     and the check window is 7 days, so a key cannot be created already inside
#     the window. Would need a 7-day wait.
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
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }
API_NAME="${PREFIX}-appsync-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"; > "$OUTPUT_FILE"
log() { echo "$1" >> "$OUTPUT_FILE"; }
echo -e "${GREEN}=== AppSync Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID"; echo ""

# API_KEY auth with no logging, no WAF, no limits, no tags.
API_ID=$(aws appsync create-graphql-api \
    --name "$API_NAME" \
    --authentication-type API_KEY \
    --region "$REGION" \
    --query 'graphqlApi.apiId' --output text 2>&1) || {
        echo -e "${RED}✗ create-graphql-api failed${NC}"; echo "$API_ID" | head -3; exit 1; }
log "API:${API_ID}"
echo -e "${GREEN}✓ ${API_NAME} (${API_ID})${NC}"
echo -e "  ${CYAN}-> appsyncNoAuthentication, appsyncIntrospectionEnabled,${NC}"
echo -e "  ${CYAN}   appsyncWafNotAssociated, appsyncNoQueryDepthLimit,${NC}"
echo -e "  ${CYAN}   appsyncNoResolverCountLimit, appsyncFieldLevelLogging,${NC}"
echo -e "  ${CYAN}   appsyncCloudWatchLogsNotEnabled, appsyncXrayTracingDisabled,${NC}"
echo -e "  ${CYAN}   appsyncNoTags${NC}"

# Max-life API key (AppSync caps at 365 days) -> exercises appsyncApiKeyNoExpiry
# at its boundary.
EXPIRES=$(python3 -c "import time; print(int(time.time())+364*86400)")
aws appsync create-api-key --api-id "$API_ID" --expires "$EXPIRES" \
    --description "ss-test key" --region "$REGION" > /dev/null 2>&1 \
    && echo -e "${GREEN}✓ API key created (364d)${NC}" \
    || echo -e "${YELLOW}⚠ create-api-key failed${NC}"

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo "  cd ../../.. && python3 main.py --regions $REGION --services appsync --beta 1 --sequential 1"
echo -e "${YELLOW}Remember ./cleanup_test_resources.sh — an idle AppSync API is free but clutters scans.${NC}"
