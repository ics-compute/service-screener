#!/bin/bash

################################################################################
# Amazon EMR Service Screener - Test Resource Cleanup Script
#
# Terminates the cluster recorded in a manifest, and removes the EMR default IAM
# roles ONLY if the create script recorded that it created them (a pre-existing
# set is left untouched).
#
# Order: terminate cluster -> wait for TERMINATED -> delete instance profile and
# roles if we created them.
#
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

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

echo -e "${GREEN}=== EMR Test Resource Cleanup ===${NC} ($RESOURCE_FILE)"
grep -E "^(CLUSTER|CREATED_DEFAULT_ROLES):" "$RESOURCE_FILE" | sed 's/^/  - /'
echo ""
if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " C; [ "$C" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

D=0; F=0

# --- Terminate the cluster (must complete before roles can be removed) --------
CLUSTER=$(grep "^CLUSTER:" "$RESOURCE_FILE" | head -1 | cut -d: -f2)
if [ -n "${CLUSTER:-}" ]; then
    aws emr terminate-clusters --cluster-ids "$CLUSTER" --region "$REGION" >/dev/null 2>&1
    echo -n "  terminating $CLUSTER"
    for _ in $(seq 1 40); do
        ST=$(aws emr describe-cluster --cluster-id "$CLUSTER" --region "$REGION" \
            --query 'Cluster.Status.State' --output text 2>/dev/null || echo "?")
        [ "$ST" = "TERMINATED" ] && { echo -e "\r${GREEN}✓ Terminated $CLUSTER${NC}       "; D=$((D+1)); break; }
        [ "$ST" = "TERMINATED_WITH_ERRORS" ] && { echo -e "\r${YELLOW}⚠ $CLUSTER TERMINATED_WITH_ERRORS${NC}"; D=$((D+1)); break; }
        echo -n " [$ST]"; sleep 20
    done
fi

# --- Remove default roles ONLY if this run created them -----------------------
if grep -q "^CREATED_DEFAULT_ROLES:yes" "$RESOURCE_FILE"; then
    echo -e "  ${CYAN}removing EMR default roles (this run created them)${NC}"
    aws iam remove-role-from-instance-profile --instance-profile-name EMR_EC2_DefaultRole \
        --role-name EMR_EC2_DefaultRole >/dev/null 2>&1
    aws iam delete-instance-profile --instance-profile-name EMR_EC2_DefaultRole >/dev/null 2>&1 \
        && echo -e "${GREEN}✓ Deleted instance profile EMR_EC2_DefaultRole${NC}" || F=$((F+1))
    ## create-default-roles makes THREE roles: EMR_DefaultRole,
    ## EMR_EC2_DefaultRole and EMR_AutoScaling_DefaultRole. Delete all three, or
    ## the autoscaling role leaks (it has no instance profile).
    for role in EMR_EC2_DefaultRole EMR_DefaultRole EMR_AutoScaling_DefaultRole; do
        # Detach any managed policies AWS attached, then delete the role.
        for arn in $(aws iam list-attached-role-policies --role-name "$role" \
                --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
            aws iam detach-role-policy --role-name "$role" --policy-arn "$arn" >/dev/null 2>&1
        done
        aws iam delete-role --role-name "$role" >/dev/null 2>&1 \
            && { echo -e "${GREEN}✓ Deleted role $role${NC}"; D=$((D+1)); } \
            || { echo -e "${YELLOW}⚠ Could not delete role $role${NC}"; F=$((F+1)); }
    done
else
    echo -e "  ${CYAN}EMR default roles pre-existed this run — left in place${NC}"
fi

echo ""
echo -e "${GREEN}=== Cleanup Complete: ${D} deleted, ${F} skipped ===${NC}"
[ "$F" -eq 0 ] && [ "$D" -gt 0 ] && mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"
echo ""
echo -e "${CYAN}Confirm no cluster remains:${NC}"
echo "  aws emr list-clusters --active --region $REGION --query \"Clusters[?starts_with(Name,'ss-test-')].Name\""
