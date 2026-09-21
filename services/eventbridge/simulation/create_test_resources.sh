#!/bin/bash

################################################################################
# EventBridge Service Screener - Test Resource Creation Script
#
# Creates an intentionally-misconfigured custom event bus plus rules, a
# connection and an API destination, exercising every `eb*` check that can be
# forced through the AWS API without mutating account-level state.
#
#   Custom bus (no KMS key, no tags, public policy):
#     - no KmsKeyIdentifier            -> ebBusNoEncryption
#     - no tags                        -> ebBusNoTags
#     - policy Principal:"*" no Cond   -> ebBusPublicPolicy
#
#   Rule #1 (disabled, no targets, no description):
#     - State=DISABLED                 -> ebRuleDisabled
#     - no targets                     -> ebRuleNoTargets
#     - no Description                 -> ebRuleNoDescription
#
#   Rule #2 (enabled, SQS target with no DLQ and no retry policy):
#     - target without DeadLetterConfig-> ebRuleNoDeadLetterQueue
#     - target without RetryPolicy     -> ebRuleNoRetryPolicy
#
#   Connection + API destination (https, so the check PASSES):
#     - InvocationEndpoint https://    -> ebApiDestinationHttpEndpoint PASSES
#
#   Region-level (satisfied by absence, no resource needed):
#     - no archive                     -> ebArchiveNotConfigured
#     - no schema discoverer           -> ebSchemaDiscoveryDisabled
#
# Checks NOT simulated here, and why:
#   ebApiDestinationHttpEndpoint
#     -- CANNOT be made to FAIL. CreateApiDestination rejects an http:// endpoint
#        outright: "Parameter InvocationEndpoint is not valid. Reason: Endpoint
#        'http://...' is invalid, please provide a valid HTTPS endpoint URL."
#        EventBridge enforces HTTPS at the API layer, so a plaintext destination
#        cannot exist in a current account. The fixture therefore creates an
#        https:// destination to prove the check evaluates and PASSES; the FAIL
#        branch is only reachable on a legacy destination created before AWS
#        added that validation.
#   ebConnectionNoAuth
#     -- EventBridge has no 'NONE' AuthorizationType: CreateConnection requires
#        one of BASIC, API_KEY or OAUTH_CLIENT_CREDENTIALS. An unauthenticated
#        connection cannot be created through the API, so the check can only fire
#        on a connection in an anomalous state.
#   ebGlobalEndpointNoReplication
#     -- a global endpoint needs two buses of the same name in two regions plus a
#        Route 53 health check, and creating one with replication disabled also
#        requires an IAM role. Out of proportion to a single L-severity check.
#   ebRuleTargetCrossAccountNoCondition
#     -- needs a target in a second AWS account.
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

BUS_NAME="${PREFIX}-eb-bus-${TIMESTAMP}"
RULE_ORPHAN="${PREFIX}-eb-rule-orphan-${TIMESTAMP}"
RULE_TARGET="${PREFIX}-eb-rule-target-${TIMESTAMP}"
QUEUE_NAME="${PREFIX}-eb-target-queue-${TIMESTAMP}"
CONNECTION_NAME="${PREFIX}-eb-conn-${TIMESTAMP}"
DESTINATION_NAME="${PREFIX}-eb-dest-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== EventBridge Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Custom event bus with no KMS key and no tags
################################################################################

echo -e "${GREEN}=== Step 1: Custom event bus (no CMK, no tags) ===${NC}"

BUS_ARN=$(aws events create-event-bus \
    --name "$BUS_NAME" \
    --region "$REGION" \
    --query 'EventBusArn' --output text 2>&1) || {
        echo -e "${RED}✗ create-event-bus failed${NC}"; echo "$BUS_ARN" | head -3; exit 1;
    }
log "BUS:${BUS_NAME}"
echo -e "${GREEN}✓ ${BUS_NAME}${NC}"
echo -e "  ${CYAN}-> ebBusNoEncryption, ebBusNoTags${NC}"

################################################################################
# Step 2: Public wildcard resource policy on the bus
################################################################################

echo -e "\n${GREEN}=== Step 2: Public bus policy (Principal:*, no Condition) ===${NC}"

cat > "/tmp/${PREFIX}-eb-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicPutEventsNoCondition",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "events:PutEvents",
      "Resource": "${BUS_ARN}"
    }
  ]
}
EOF

if aws events put-permission \
    --event-bus-name "$BUS_NAME" \
    --policy "$(tr -d '\n' < "/tmp/${PREFIX}-eb-policy.json")" \
    --region "$REGION" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Public policy applied${NC}"
    echo -e "  ${CYAN}-> ebBusPublicPolicy${NC}"
else
    echo -e "${YELLOW}⚠ put-permission rejected (likely an SCP)${NC}"
    echo -e "${YELLOW}  ebBusPublicPolicy will report PASS instead of FAIL.${NC}"
fi
rm -f "/tmp/${PREFIX}-eb-policy.json"

################################################################################
# Step 3: Disabled rule with no targets and no description
################################################################################

echo -e "\n${GREEN}=== Step 3: Disabled rule, no targets, no description ===${NC}"

# --state DISABLED plus no --description, and no put-targets call afterwards.
aws events put-rule \
    --name "$RULE_ORPHAN" \
    --event-bus-name "$BUS_NAME" \
    --event-pattern '{"source":["ss.test.orphan"]}' \
    --state DISABLED \
    --region "$REGION" > /dev/null 2>&1 || {
        echo -e "${RED}✗ put-rule failed${NC}"; exit 1;
    }
log "RULE:${BUS_NAME}/${RULE_ORPHAN}"
echo -e "${GREEN}✓ ${RULE_ORPHAN}${NC}"
echo -e "  ${CYAN}-> ebRuleDisabled, ebRuleNoTargets, ebRuleNoDescription${NC}"

################################################################################
# Step 4: SQS queue as a rule target with no DLQ and no retry policy
################################################################################

echo -e "\n${GREEN}=== Step 4: Rule with an SQS target lacking DLQ + retry policy ===${NC}"

QUEUE_URL=$(aws sqs create-queue \
    --queue-name "$QUEUE_NAME" \
    --region "$REGION" \
    --query 'QueueUrl' --output text 2>&1) || {
        echo -e "${RED}✗ create-queue failed${NC}"; echo "$QUEUE_URL" | head -3; exit 1;
    }
log "QUEUE:${QUEUE_URL}"

QUEUE_ARN=$(aws sqs get-queue-attributes \
    --queue-url "$QUEUE_URL" \
    --attribute-names QueueArn \
    --region "$REGION" \
    --query 'Attributes.QueueArn' --output text)

aws events put-rule \
    --name "$RULE_TARGET" \
    --event-bus-name "$BUS_NAME" \
    --event-pattern '{"source":["ss.test.target"]}' \
    --state ENABLED \
    --description "ss-test rule with a target that has no DLQ or retry policy" \
    --region "$REGION" > /dev/null 2>&1 || {
        echo -e "${RED}✗ put-rule failed${NC}"; exit 1;
    }
log "RULE:${BUS_NAME}/${RULE_TARGET}"

# Deliberately no DeadLetterConfig and no RetryPolicy in the target definition.
aws events put-targets \
    --rule "$RULE_TARGET" \
    --event-bus-name "$BUS_NAME" \
    --targets "Id=ss-test-sqs-target,Arn=${QUEUE_ARN}" \
    --region "$REGION" > /dev/null 2>&1 || {
        echo -e "${YELLOW}⚠ put-targets failed${NC}";
    }

echo -e "${GREEN}✓ ${RULE_TARGET} -> ${QUEUE_NAME}${NC}"
echo -e "  ${CYAN}-> ebRuleNoDeadLetterQueue, ebRuleNoRetryPolicy${NC}"

################################################################################
# Step 5: Connection + API destination over plaintext HTTP
################################################################################

echo -e "\n${GREEN}=== Step 5: Connection + API destination (https) ===${NC}"

# API_KEY is the least-privileged authorization type that CreateConnection
# accepts -- there is no way to create an unauthenticated connection, which is
# why ebConnectionNoAuth is not simulated. The key value is a dummy.
CONNECTION_ARN=$(aws events create-connection \
    --name "$CONNECTION_NAME" \
    --authorization-type API_KEY \
    --auth-parameters 'ApiKeyAuthParameters={ApiKeyName=x-ss-test,ApiKeyValue=not-a-real-key}' \
    --region "$REGION" \
    --query 'ConnectionArn' --output text 2>&1) || {
        echo -e "${YELLOW}⚠ create-connection failed; skipping API destination${NC}"
        CONNECTION_ARN=""
    }

if [ -n "$CONNECTION_ARN" ]; then
    log "CONNECTION:${CONNECTION_NAME}"

    # A connection takes a few seconds to leave the CREATING state, and
    # create-api-destination rejects a connection that is not yet AUTHORIZED.
    echo -n "  waiting for connection to become authorized"
    for _ in $(seq 1 20); do
        STATE=$(aws events describe-connection --name "$CONNECTION_NAME" \
            --region "$REGION" --query 'ConnectionState' --output text 2>/dev/null || echo "")
        [ "$STATE" = "AUTHORIZED" ] && break
        echo -n "."
        sleep 3
    done
    echo ""

    # https:// -- an http:// endpoint is rejected by the API (see the header
    # comment), so this fixture exercises the check's PASS branch rather than
    # its FAIL branch.
    if aws events create-api-destination \
        --name "$DESTINATION_NAME" \
        --connection-arn "$CONNECTION_ARN" \
        --invocation-endpoint "https://example.com/ss-test-eventbridge" \
        --http-method POST \
        --region "$REGION" > /dev/null 2>&1; then
        log "DESTINATION:${DESTINATION_NAME}"
        echo -e "${GREEN}✓ ${DESTINATION_NAME} -> https://example.com/ss-test-eventbridge${NC}"
        echo -e "  ${CYAN}-> ebApiDestinationHttpEndpoint (PASS branch),${NC}"
        echo -e "  ${CYAN}   ebConnectionNoAuth (PASS branch)${NC}"
    else
        echo -e "${YELLOW}⚠ create-api-destination failed (connection state: ${STATE:-unknown})${NC}"
        echo -e "${YELLOW}  ebApiDestinationHttpEndpoint will report INFO.${NC}"
    fi
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "Manifest: $OUTPUT_FILE"
echo ""
echo -e "${CYAN}Note: ebArchiveNotConfigured and ebSchemaDiscoveryDisabled fire on${NC}"
echo -e "${CYAN}the ABSENCE of an archive/discoverer, so they need no fixture.${NC}"
echo ""
echo "Next:"
echo "  sleep 30"
echo "  cd ../../.. && python3 main.py --regions $REGION --services eventbridge --beta 1 --sequential 1"
echo ""
echo -e "${YELLOW}Remember to run ./cleanup_test_resources.sh when finished.${NC}"
