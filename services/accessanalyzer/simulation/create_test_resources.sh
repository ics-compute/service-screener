#!/bin/bash

################################################################################
# IAM Access Analyzer Service Screener - Read-Only Posture Report
#
# Creates NOTHING. Every aa* check reads account/region-level Access Analyzer
# state (which analyzers exist, their findings, their archive rules), so there is
# no per-resource fixture to build.
#
# Creating an analyzer is cheap, but the finding-based checks depend on real
# cross-account access relationships that cannot be manufactured, and an
# unused-access analyzer bills per role analysed. So this script reports what
# each check will return rather than mutating the account. Follows the
# services/config/simulation precedent.
#
# Usage: ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u
REGION="${AWS_REGION:-ap-southeast-1}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) shift ;; esac; done
export AWS_PAGER=""

echo -e "${GREEN}=== IAM Access Analyzer Posture Report (read-only) ===${NC}"
echo "Region: $REGION"
echo -e "${YELLOW}This script creates nothing. See the header for why.${NC}"
echo ""

aws accessanalyzer list-analyzers --region "$REGION" --output json 2>/dev/null | python3 -c "
import json,sys
try: a=json.load(sys.stdin).get('analyzers',[])
except Exception: a=[]
types=[x.get('type') for x in a]
ext=[t for t in types if t in ('ACCOUNT','ORGANIZATION')]
unused=[t for t in types if 'UNUSED_ACCESS' in t]
internal=[t for t in types if 'INTERNAL_ACCESS' in t]
inactive=[x.get('name') for x in a if x.get('status')!='ACTIVE']
print(f'  analyzers: {len(a)}  types: {sorted(set(types)) or \"none\"}')
print('  -> aaNoAnalyzerConfigured will ' + ('PASS' if a else 'FAIL'))
print('  -> aaNoAccountAnalyzer will ' + ('PASS' if ext else 'FAIL'))
print('  -> aaUnusedAccessAnalyzerMissing will ' + ('PASS' if unused else 'FAIL'))
print('  -> aaNoInternalAccessAnalyzer will ' + ('PASS' if internal else 'INFO'))
print('  -> aaAnalyzerNotActive will ' + ('FAIL' if inactive else 'PASS'))
" 2>/dev/null || echo "  (could not read analyzers)"

echo ""
echo -e "${GREEN}=== Report Complete — nothing created ===${NC}"
echo "Confirm with the real scan:"
echo "  cd ../../.. && python3 main.py --regions $REGION --services accessanalyzer --beta 1 --sequential 1"
