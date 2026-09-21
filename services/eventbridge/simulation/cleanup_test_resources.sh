#!/bin/bash

################################################################################
# EventBridge Service Screener - Test Resource Cleanup Script
#
# Deletes the resources recorded in a create_test_resources.sh manifest, in
# dependency order:
#
#   API destination -> connection -> rule targets -> rules -> bus -> SQS queue
#
# EventBridge refuses to delete a rule that still has targets, and refuses to
# delete a bus that still has rules, so the order matters.
#
# Only ever deletes names read from the manifest file, so it cannot touch a
# resource it did not create.
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

echo -e "${GREEN}=== EventBridge Test Resource Cleanup ===${NC}"
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

by_type() {
    local t="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${t}:* ]] && echo "${r#${t}:}"
    done
}

DELETED=0
FAILED=0

ok()   { echo -e "${GREEN}✓ $1${NC}"; DELETED=$((DELETED + 1)); }
skip() { echo -e "${YELLOW}⚠ $1${NC}"; FAILED=$((FAILED + 1)); }

################################################################################
# Step 1: API destinations (must go before their connection)
################################################################################

for d in $(by_type DESTINATION); do
    aws events delete-api-destination --name "$d" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted API destination $d" \
        || skip "Could not delete API destination $d"
done

################################################################################
# Step 2: Connections
################################################################################

for c in $(by_type CONNECTION); do
    aws events delete-connection --name "$c" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted connection $c" \
        || skip "Could not delete connection $c"
done

################################################################################
# Step 3: Rule targets, then rules (a rule with targets cannot be deleted)
################################################################################

for entry in $(by_type RULE); do
    BUS="${entry%%/*}"
    RULE="${entry#*/}"

    TARGET_IDS=$(aws events list-targets-by-rule \
        --rule "$RULE" --event-bus-name "$BUS" --region "$REGION" \
        --query 'Targets[].Id' --output text 2>/dev/null || echo "")

    if [ -n "$TARGET_IDS" ] && [ "$TARGET_IDS" != "None" ]; then
        # shellcheck disable=SC2086
        aws events remove-targets \
            --rule "$RULE" --event-bus-name "$BUS" --ids $TARGET_IDS \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "  ${CYAN}removed targets from ${RULE}${NC}"
    fi

    aws events delete-rule --name "$RULE" --event-bus-name "$BUS" \
        --region "$REGION" > /dev/null 2>&1 && ok "Deleted rule $RULE" \
        || skip "Could not delete rule $RULE"
done

################################################################################
# Step 4: Event buses
################################################################################

for b in $(by_type BUS); do
    aws events delete-event-bus --name "$b" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted event bus $b" \
        || skip "Could not delete event bus $b"
done

################################################################################
# Step 5: SQS target queues
################################################################################

for q in $(by_type QUEUE); do
    aws sqs delete-queue --queue-url "$q" --region "$REGION" \
        > /dev/null 2>&1 && ok "Deleted queue $(basename "$q")" \
        || skip "Could not delete queue $(basename "$q")"
done

echo ""
echo -e "${GREEN}=== Cleanup Complete: ${DELETED} deleted, ${FAILED} skipped ===${NC}"

if [ "$FAILED" -eq 0 ] && [ "$DELETED" -gt 0 ]; then
    mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"
    echo "Manifest renamed to ${RESOURCE_FILE}.done"
fi

echo ""
echo -e "${CYAN}Verify nothing is left behind:${NC}"
echo "  aws events list-event-buses --region $REGION \\"
echo "      --query \"EventBuses[?starts_with(Name,'ss-test-')].Name\""
echo "  aws events list-connections --region $REGION \\"
echo "      --query \"Connections[?starts_with(Name,'ss-test-')].Name\""
echo ""
echo -e "${YELLOW}Note: an SQS queue name cannot be reused for 60 seconds after${NC}"
echo -e "${YELLOW}deletion. Re-running create immediately is still fine — the name${NC}"
echo -e "${YELLOW}is timestamped.${NC}"
