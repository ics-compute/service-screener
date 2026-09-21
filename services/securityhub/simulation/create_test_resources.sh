#!/bin/bash
################################################################################
# AWS Security Hub Service Screener - Read-Only Posture Report
#
# Creates NOTHING. Every shub* check reads account/region-level Security Hub
# state. Enabling Security Hub or a standard is an account-level action with
# recurring per-check cost, and disabling one removes a live control, so this
# script only reports what each check will return. See services/config/simulation.
#
# Usage: ./create_test_resources.sh [--region REGION] [--help]
################################################################################
set -u
REGION="${AWS_REGION:-ap-southeast-1}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) shift ;; esac; done
export AWS_PAGER=""
echo -e "${GREEN}=== Security Hub Posture Report (read-only) ===${NC}"
echo "Region: $REGION"
echo -e "${YELLOW}This script creates nothing. See the header for why.${NC}"; echo ""
HUB=$(aws securityhub describe-hub --region "$REGION" --output json 2>&1)
if echo "$HUB" | grep -q "HubArn"; then
    echo "$HUB" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('  Security Hub ENABLED -> shubNotEnabled will PASS')
print('  AutoEnableControls=%s -> shubAutoEnableControlsDisabled will %s' % (d.get('AutoEnableControls'),'PASS' if d.get('AutoEnableControls') else 'FAIL'))
g=d.get('ControlFindingGenerator')
print('  ControlFindingGenerator=%s -> shubLegacyControlFindingGenerator will %s' % (g,'PASS' if g=='SECURITY_CONTROL' else 'FAIL'))
"
else
    echo "  Security Hub NOT enabled -> shubNotEnabled will FAIL (all others INFO)"
fi
echo ""
echo -e "${GREEN}=== Report Complete — nothing created ===${NC}"
echo "  cd ../../.. && python3 main.py --regions $REGION --services securityhub --beta 1 --sequential 1"
