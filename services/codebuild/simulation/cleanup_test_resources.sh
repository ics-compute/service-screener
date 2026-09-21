#!/bin/bash

################################################################################
# CodeBuild Service Screener - Test Resource Cleanup Script
#
# Deletes the resources recorded in a create_test_resources.sh manifest, in
# dependency order: report groups -> projects -> S3 bucket -> IAM role.
#
# Only ever deletes names read from the manifest, so it cannot touch a resource
# it did not create.
#
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then RESOURCE_FILE="$1"; shift
            else echo -e "${RED}Unknown: $1${NC}"; exit 1; fi
            ;;
    esac
done

export AWS_PAGER=""

if [ -z "$RESOURCE_FILE" ]; then
    RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
    [ -z "$RESOURCE_FILE" ] && { echo -e "${RED}No manifest found${NC}"; exit 1; }
    echo -e "${YELLOW}Auto-detected: $RESOURCE_FILE${NC}"
fi

[ ! -f "$RESOURCE_FILE" ] && { echo -e "${RED}Not found: $RESOURCE_FILE${NC}"; exit 1; }

echo -e "${GREEN}=== CodeBuild Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo ""
for r in "${RESOURCES[@]}"; do echo "  - $r"; done
echo ""

if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " C
    [ "$C" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

by_type() {
    local t="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${t}:* ]] && echo "${r#${t}:}"
    done
}

DELETED=0; FAILED=0
ok()   { echo -e "${GREEN}✓ $1${NC}"; DELETED=$((DELETED+1)); }
skip() { echo -e "${YELLOW}⚠ $1${NC}"; FAILED=$((FAILED+1)); }

# Report groups (--delete-reports removes retained report history too)
for g in $(by_type REPORTGROUP); do
    ARN=$(aws codebuild batch-get-report-groups --report-group-arns \
        "$(aws codebuild list-report-groups --region "$REGION" \
            --query "reportGroups[?contains(@,'${g}')]|[0]" --output text 2>/dev/null)" \
        --region "$REGION" --query 'reportGroups[0].arn' --output text 2>/dev/null || echo "")
    if [ -z "$ARN" ] || [ "$ARN" = "None" ]; then
        ARN=$(aws codebuild list-report-groups --region "$REGION" \
            --query "reportGroups[?contains(@,'${g}')]|[0]" --output text 2>/dev/null || echo "")
    fi
    if [ -n "$ARN" ] && [ "$ARN" != "None" ]; then
        aws codebuild delete-report-group --arn "$ARN" --delete-reports \
            --region "$REGION" > /dev/null 2>&1 && ok "Deleted report group $g" \
            || skip "Could not delete report group $g"
    else
        skip "Report group $g not found (already gone?)"
    fi
done

# Projects
for p in $(by_type PROJECT); do
    aws codebuild delete-project --name "$p" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted project $p" \
        || skip "Could not delete project $p"
done

# S3 bucket (empty then remove)
for b in $(by_type BUCKET); do
    aws s3 rm "s3://${b}" --recursive --region "$REGION" > /dev/null 2>&1
    aws s3api delete-bucket --bucket "$b" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted bucket $b" \
        || skip "Could not delete bucket $b"
done

# IAM role (no attached policies were added, so a plain delete suffices)
for role in $(by_type ROLE); do
    aws iam delete-role --role-name "$role" > /dev/null 2>&1 \
        && ok "Deleted role $role" || skip "Could not delete role $role"
done

echo ""
echo -e "${GREEN}=== Cleanup Complete: ${DELETED} deleted, ${FAILED} skipped ===${NC}"
if [ "$FAILED" -eq 0 ] && [ "$DELETED" -gt 0 ]; then
    mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"
    echo "Manifest renamed to ${RESOURCE_FILE}.done"
fi

echo ""
echo -e "${CYAN}Verify nothing is left behind:${NC}"
echo "  aws codebuild list-projects --region $REGION --query \"projects[?starts_with(@,'ss-test-')]\""
