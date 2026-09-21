#!/bin/bash
################################################################################
# Amazon Inspector Service Screener - Read-Only Posture Report
#
# Creates NOTHING. Every inspector* check reads account/region-level Inspector
# state via batch_get_account_status, list_coverage_statistics and
# list_finding_aggregations (each a single call, no finding enumeration).
# Enabling Inspector is an account-level action that bills per resource scanned,
# so this script only reports what each check will return.
# NOTE: the boto3 client is 'inspector2'; the AWS CLI command is 'inspector2'.
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
echo -e "${GREEN}=== Amazon Inspector Posture Report (read-only) ===${NC}"
echo "Region: $REGION"
echo -e "${YELLOW}This script creates nothing. See the header for why.${NC}"; echo ""
aws inspector2 batch-get-account-status --region "$REGION" --output json 2>/dev/null | python3 -c "
import json,sys
try: a=json.load(sys.stdin).get('accounts',[])[0]
except Exception: print('  Inspector NOT enabled -> inspectorNotEnabled will FAIL'); sys.exit()
st=a.get('state',{}).get('status')
print('  account status=%s -> inspectorNotEnabled will %s' % (st,'PASS' if st=='ENABLED' else 'FAIL'))
for rt,v in (a.get('resourceState') or {}).items():
    print('    %s scanning=%s' % (rt, v.get('status')))
" 2>/dev/null || echo "  (could not read Inspector status)"
aws inspector2 list-finding-aggregations --aggregation-type ACCOUNT --region "$REGION" --output json 2>/dev/null | python3 -c "
import json,sys
try: acc=json.load(sys.stdin).get('responses',[])[0].get('accountAggregation',{})
except Exception: sys.exit()
sc=acc.get('severityCounts',{})
print('  critical=%s -> inspectorCriticalFindings will %s' % (sc.get('critical'),'FAIL' if sc.get('critical') else 'PASS'))
print('  exploitAvailable=%s -> inspectorExploitableFindings will %s' % (acc.get('exploitAvailableCount'),'FAIL' if acc.get('exploitAvailableCount') else 'PASS'))
" 2>/dev/null
echo ""
echo -e "${GREEN}=== Report Complete — nothing created ===${NC}"
echo "  cd ../../.. && python3 main.py --regions $REGION --services inspector --beta 1 --sequential 1"
