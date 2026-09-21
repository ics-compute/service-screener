#!/bin/bash

################################################################################
# AWS Config Service Screener - Test Resource Cleanup Script
#
# Intentionally a no-op.
#
# create_test_resources.sh for this service creates nothing: every `config*`
# check reads account-level, region-wide AWS Config state (the configuration
# recorder, the delivery channel, the shared rule set), so there is no
# per-resource fixture to build and therefore nothing to clean up.
#
# This script exists so the service matches the layout of the other 35 services
# and so a caller looping over `services/*/simulation/cleanup_test_resources.sh`
# does not fail on a missing file.
#
# Usage: ./cleanup_test_resources.sh [--region REGION] [--force] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        shift ;;
    esac
done

echo -e "${GREEN}=== AWS Config Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo ""
echo -e "${YELLOW}Nothing to clean up: the config simulation creates no resources.${NC}"
echo -e "${CYAN}See create_test_resources.sh for why AWS Config has no fixtures.${NC}"
echo ""
echo -e "${GREEN}=== Cleanup Complete: 0 deleted, 0 skipped ===${NC}"

exit 0
