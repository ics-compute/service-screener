#!/bin/bash
################################################################################
# Amazon GuardDuty Service Screener - Read-Only Posture Report
#
# Creates NOTHING, deliberately. The gd* checks read whether GuardDuty and its
# protection FEATURES (Runtime Monitoring, S3 Protection, Malware Protection,
# RDS/Lambda/EKS protection, ...) are enabled on the account's detector.
#
# To force a FAIL you would disable a feature; to force a PASS, enable one. Both
# are ACCOUNT-LEVEL changes to the account's live threat-detection posture --
# disabling Runtime Monitoring genuinely stops GuardDuty detecting container
# runtime threats for as long as the fixture exists, and enabling a paid feature
# starts billing. So there is nothing safe to create or toggle as a fixture; the
# checks are validated against the real detector instead.
#
# This report prints what each feature check will return, mirroring the
# read-only pattern used for config, securityhub, inspector and accessanalyzer.
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
echo -e "${GREEN}=== Amazon GuardDuty Posture Report (read-only) ===${NC}"
echo "Region: $REGION"
echo -e "${YELLOW}This script creates nothing. See the header for why.${NC}"; echo ""
DID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text 2>/dev/null)
if [ -z "$DID" ] || [ "$DID" = "None" ]; then
    echo "  No detector -> GuardDuty is not enabled in this region."
    echo "  (iam.enableGuardDuty covers the not-enabled case.)"
else
    echo "  detector: $DID"
    aws guardduty get-detector --detector-id "$DID" --region "$REGION" --output json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
feat={f['Name']:f['Status'] for f in d.get('Features',[])}
def ac(fn,cn):
    for f in d.get('Features',[]):
        if f['Name']==fn:
            for c in f.get('AdditionalConfiguration',[]) or []:
                if c['Name']==cn: return c['Status']
    return None
rows=[
 ('S3ProtectionDisabled','S3_DATA_EVENTS'),('EksAuditLogsDisabled','EKS_AUDIT_LOGS'),
 ('MalwareProtectionDisabled','EBS_MALWARE_PROTECTION'),('RdsProtectionDisabled','RDS_LOGIN_EVENTS'),
 ('LambdaProtectionDisabled','LAMBDA_NETWORK_LOGS'),('RuntimeMonitoringDisabled','RUNTIME_MONITORING'),
 ('AiProtectionDisabled','AI_PROTECTION'),
]
for check,fn in rows:
    st=feat.get(fn)
    verdict='PASS' if st=='ENABLED' else ('INFO(not reported)' if st is None else 'FAIL')
    print(f'  {fn:24} {st or \"-\":9} -> {check} will {verdict}')
print(f'  EKS_ADDON_MANAGEMENT (under RUNTIME_MONITORING): {ac(\"RUNTIME_MONITORING\",\"EKS_ADDON_MANAGEMENT\")}')
print(f'  ECS_FARGATE_AGENT_MANAGEMENT: {ac(\"RUNTIME_MONITORING\",\"ECS_FARGATE_AGENT_MANAGEMENT\")}')
print(f'  EC2_AGENT_MANAGEMENT: {ac(\"RUNTIME_MONITORING\",\"EC2_AGENT_MANAGEMENT\")}')
" 2>/dev/null || echo "  (could not read detector features)"
fi
echo ""; echo -e "${GREEN}=== Report Complete — nothing created ===${NC}"
echo "  cd ../../.. && python3 main.py --regions $REGION --services guardduty --beta 1 --sequential 1"
