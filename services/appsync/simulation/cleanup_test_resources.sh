#!/bin/bash
################################################################################
# AppSync Service Screener - Test Resource Cleanup Script
# Deletes only the API IDs recorded in a create_test_resources.sh manifest.
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################
set -u
REGION="${AWS_REGION:-ap-southeast-1}"; FORCE=false; RESOURCE_FILE=""
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;; --force) FORCE=true; shift ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) if [ -z "$RESOURCE_FILE" ]; then RESOURCE_FILE="$1"; shift; else shift; fi ;;
esac; done
export AWS_PAGER=""
[ -z "$RESOURCE_FILE" ] && RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
[ -z "$RESOURCE_FILE" ] || [ ! -f "$RESOURCE_FILE" ] && { echo -e "${RED}No manifest${NC}"; exit 1; }
echo -e "${GREEN}=== AppSync Cleanup ===${NC} ($RESOURCE_FILE)"
if [ "$FORCE" = false ]; then read -p "Continue? (yes/no): " C; [ "$C" != "yes" ] && exit 0; fi
D=0; F=0
while IFS= read -r line; do
    [[ "$line" != API:* ]] && continue
    ID="${line#API:}"
    if aws appsync delete-graphql-api --api-id "$ID" --region "$REGION" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Deleted API $ID${NC}"; D=$((D+1))
    else echo -e "${YELLOW}⚠ Could not delete $ID${NC}"; F=$((F+1)); fi
done < "$RESOURCE_FILE"
echo ""; echo -e "${GREEN}=== Cleanup Complete: ${D} deleted, ${F} skipped ===${NC}"
[ "$F" -eq 0 ] && [ "$D" -gt 0 ] && mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"
