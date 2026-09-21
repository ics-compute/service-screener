#!/bin/bash

################################################################################
# Amazon EMR Service Screener - Test Resource Creation Script
#
# Creates a real, minimal, intentionally-misconfigured EMR cluster.
#
#   Cluster (1x m5.xlarge master, on-demand, no core nodes):
#     - ReleaseLabel emr-5.36.2 (major 5)  -> emrOldRelease (fires when major < 6)
#     - no SecurityConfiguration           -> emrNoSecurityConfiguration
#                                             (encryption checks report INFO)
#     - no LogUri                          -> emrLoggingDisabled
#     - no Kerberos                        -> emrKerberosNotEnabled
#     - TerminationProtected false         -> emrTerminationProtectionDisabled
#     - no AutoScalingRole, no fleets      -> emrAutoScalingDisabled
#     - StepConcurrencyLevel 1 (default)   -> emrStepConcurrencyLow
#     - no tags                            -> emrNoTags
#
# COST + TIME: the cluster must reach the WAITING state before the scanner
# (which filters on ClusterStates=[RUNNING,WAITING]) can see it. Provisioning
# takes 8-15 minutes -- EMR launches an EC2 instance and bootstraps Hadoop on it,
# so budget generously. A single m5.xlarge master is roughly $0.20/hour including
# the EMR uplift, so a ~20-minute create/scan/cleanup cycle costs about $0.07.
# NO steps are run.
#
# This script creates the EMR default IAM roles (EMR_DefaultRole,
# EMR_EC2_DefaultRole and their instance profile) if they do not already exist,
# and records in the manifest whether IT created them. cleanup removes them ONLY
# when this script created them, so a pre-existing set is never deleted.
#
# Checks NOT forced here, and why:
#   emrEncryptionAtRestDisabled / emrEncryptionInTransitDisabled -- need a
#     security configuration to exist first; with none attached they correctly
#     report INFO. The encryption-off branch is covered by the synthetic test
#     described in README.md.
#   emrPubliclyAccessible -- launching into a private subnet keeps the master off
#     the internet (the safe default); forcing a public IP would make the fixture
#     itself a live exposure while it runs.
#   emrIdleCluster -- fires after 24h WAITING; the fixture is torn down first.
#   emrMasterInstanceOnDemand -- INFO only; the on-demand master exercises PASS.
#   emrBlockPublicAccessDisabled -- account-level; scanned against real state.
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--subnet SUBNET_ID] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUBNET=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --subnet) SUBNET="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

export AWS_PAGER=""

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"
log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== EMR Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Default IAM roles (only if absent — record whether WE created them)
################################################################################

echo -e "${GREEN}=== Step 1: EMR default IAM roles ===${NC}"

if aws iam get-role --role-name EMR_DefaultRole >/dev/null 2>&1; then
    echo -e "${CYAN}  EMR default roles already exist — leaving them in place${NC}"
else
    if aws emr create-default-roles --region "$REGION" >/dev/null 2>&1; then
        log "CREATED_DEFAULT_ROLES:yes"
        echo -e "${GREEN}✓ Created EMR_DefaultRole, EMR_EC2_DefaultRole + instance profile${NC}"
        echo -n "  waiting for IAM propagation"
        for _ in $(seq 1 10); do echo -n "."; sleep 3; done; echo ""
    else
        echo -e "${RED}✗ create-default-roles failed — cannot launch a cluster${NC}"
        exit 1
    fi
fi

################################################################################
# Step 2: Resolve a subnet (EMR requires one)
################################################################################

if [ -z "$SUBNET" ]; then
    SUBNET=$(aws ec2 describe-subnets --region "$REGION" \
        --filters Name=default-for-az,Values=true \
        --query 'Subnets[0].SubnetId' --output text 2>/dev/null)
fi
if [ -z "$SUBNET" ] || [ "$SUBNET" = "None" ]; then
    echo -e "${RED}✗ No subnet found. Pass --subnet <id> (a private subnet is best).${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Using subnet ${SUBNET}${NC}"

################################################################################
# Step 3: Launch a minimal, misconfigured cluster
################################################################################

echo -e "\n${GREEN}=== Step 3: Launch cluster (emr-6.0.0, no security config) ===${NC}"

# emr-5.36.2 is the latest 5.x release -- major version 5, so it fires
# emrOldRelease (which fails on major < 6) while still launching reliably.
# m5.xlarge is a current-generation type; the older m4 family fails to launch
# with an internal error against recent EMR releases in some regions.
CLUSTER_ID=$(aws emr create-cluster \
    --name "${PREFIX}-emr-${TIMESTAMP}" \
    --release-label emr-5.36.2 \
    --applications Name=Hadoop \
    --instance-groups InstanceGroupType=MASTER,InstanceCount=1,InstanceType=m5.xlarge \
    --ec2-attributes "SubnetId=${SUBNET},InstanceProfile=EMR_EC2_DefaultRole" \
    --service-role EMR_DefaultRole \
    --no-termination-protected \
    --region "$REGION" \
    --query 'ClusterId' --output text 2>&1) || {
        echo -e "${RED}✗ create-cluster failed${NC}"; echo "$CLUSTER_ID" | head -4; exit 1;
    }
log "CLUSTER:${CLUSTER_ID}"
echo -e "${GREEN}✓ Launched ${CLUSTER_ID}${NC}"

echo -n "  waiting for WAITING state (scanner only sees RUNNING/WAITING; ~5-8 min)"
for _ in $(seq 1 40); do
    STATE=$(aws emr describe-cluster --cluster-id "$CLUSTER_ID" --region "$REGION" \
        --query 'Cluster.Status.State' --output text 2>/dev/null || echo "?")
    if [ "$STATE" = "WAITING" ]; then echo -e "\n${GREEN}✓ Cluster is WAITING${NC}"; break; fi
    if [[ "$STATE" == TERMINAT* ]]; then
        echo -e "\n${RED}✗ Cluster entered ${STATE} — check the console; run cleanup${NC}"; break
    fi
    echo -n " [$STATE]"
    sleep 20
done

echo -e "  ${CYAN}-> emrOldRelease, emrNoSecurityConfiguration, emrLoggingDisabled,${NC}"
echo -e "  ${CYAN}   emrKerberosNotEnabled, emrTerminationProtectionDisabled,${NC}"
echo -e "  ${CYAN}   emrAutoScalingDisabled, emrStepConcurrencyLow, emrNoTags${NC}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo ""
echo "Next:"
echo "  cd ../../.. && python3 main.py --regions $REGION --services emr --beta 1 --sequential 1"
echo ""
echo -e "${YELLOW}RUN CLEANUP PROMPTLY — the cluster bills ~\$0.13/hour while it runs.${NC}"
