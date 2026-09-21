#!/bin/bash

################################################################################
# Secrets Manager Service Screener - Test Resource Cleanup Script
#
# Deletes the secrets recorded in a create_test_resources.sh manifest.
#
# Uses --force-delete-without-recovery so the names are immediately reusable;
# a normal delete leaves the secret in PendingDeletion for up to 30 days and
# blocks recreating it under the same name.
#
# Only ever deletes ARNs read from the manifest file, so it cannot touch a
# secret it did not create.
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

echo -e "${GREEN}=== Secrets Manager Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo ""
echo "Resources:"
for r in "${RESOURCES[@]}"; do echo "  - $r"; done
echo ""

if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " C
    [ "$C" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

DELETED=0
FAILED=0

for r in "${RESOURCES[@]}"; do
    [[ "$r" != SECRET:* ]] && continue
    ARN="${r#SECRET:}"
    NAME=$(basename "$ARN")

    # A secret already in PendingDeletion (fixture #3) still accepts
    # force-delete-without-recovery, so no special case is needed.
    if aws secretsmanager delete-secret \
        --secret-id "$ARN" \
        --force-delete-without-recovery \
        --region "$REGION" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Deleted ${NAME}${NC}"
        DELETED=$((DELETED + 1))
    else
        echo -e "${YELLOW}⚠ Could not delete ${NAME} (already gone?)${NC}"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo -e "${GREEN}=== Cleanup Complete: ${DELETED} deleted, ${FAILED} skipped ===${NC}"

if [ "$FAILED" -eq 0 ] && [ "$DELETED" -gt 0 ]; then
    mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"
    echo "Manifest renamed to ${RESOURCE_FILE}.done"
fi

echo ""
echo -e "${CYAN}Verify nothing is left behind:${NC}"
echo "  aws secretsmanager list-secrets --include-planned-deletion \\"
echo "      --region $REGION --query \"SecretList[?starts_with(Name,'ss-test-')].Name\""
