from services.Evaluator import Evaluator


class InspectorCommon(Evaluator):
    """
    Account/region-scoped Amazon Inspector checks (10).

    Input:
      detail -- from services/inspector/Inspector.py.getResources:
        '_accountStatus', '_coverageByStatus', '_severityCounts',
        '_exploitAvailable', '_fixAvailable', '_totalFindings'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    When Inspector is not enabled, only inspectorNotEnabled produces a finding
    and the per-scanner checks report INFO.
    """

    ## Coverage-gap threshold: fail if more than this fraction of resources are
    ## not actively scanned.
    COVERAGE_GAP_FRACTION = 0.10

    def __init__(self, detail, insClient):
        super().__init__()
        self.detail = detail
        self.insClient = insClient
        self._resourceName = 'Account'

        self.status = detail.get('_accountStatus') or {}
        self.state = (self.status.get('state') or {})
        self.resourceState = (self.status.get('resourceState') or {})
        self.coverage = detail.get('_coverageByStatus') or {}
        self.severity = detail.get('_severityCounts') or {}
        self.exploit = detail.get('_exploitAvailable')
        self.fix = detail.get('_fixAvailable')
        self.total = detail.get('_totalFindings')

        self.enabled = self.state.get('status') == 'ENABLED'

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('accountStatus', self.state.get('status', 'N/A'))
        for rt in ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository'):
            self.addII(f'{rt}Scanning',
                       (self.resourceState.get(rt) or {}).get('status', 'N/A'))
        self.addII('criticalFindings', str(self.severity.get('critical', 'N/A')))
        self.addII('exploitAvailable', str(self.exploit if self.exploit is not None else 'N/A'))

    def _na(self, key):
        self.results[key] = [
            0, "Inspector is not enabled in this region — see inspectorNotEnabled"
        ]

    def _resourceStatus(self, rt):
        return (self.resourceState.get(rt) or {}).get('status')

    # 1. Inspector not enabled
    def _checkInspectorNotEnabled(self):
        if self.enabled:
            self.results['inspectorNotEnabled'] = [
                1, "Amazon Inspector is enabled in this region"
            ]
        else:
            self.results['inspectorNotEnabled'] = [
                -1,
                "Amazon Inspector is not enabled — EC2 instances, container "
                "images and Lambda functions are not being continuously scanned "
                "for known CVEs"
            ]

    def _resourceCheck(self, key, rt, label, fail_status):
        if not self.enabled:
            return self._na(key)
        status = self._resourceStatus(rt)
        if status is None:
            self.results[key] = [
                0, f"{label} scanning status is not reported in this region"
            ]
        elif status == 'ENABLED':
            self.results[key] = [1, f"{label} scanning is enabled"]
        else:
            self.results[key] = [fail_status,
                                 f"{label} scanning is {status} — this resource "
                                 "type is not being scanned for vulnerabilities"]

    # 2-6. Per-resource-type scanning
    def _checkInspectorEc2ScanningDisabled(self):
        self._resourceCheck('inspectorEc2ScanningDisabled', 'ec2',
                           'EC2', -1)

    def _checkInspectorEcrScanningDisabled(self):
        self._resourceCheck('inspectorEcrScanningDisabled', 'ecr',
                           'ECR container image', -1)

    def _checkInspectorLambdaScanningDisabled(self):
        self._resourceCheck('inspectorLambdaScanningDisabled', 'lambda',
                           'Lambda standard', -1)

    def _checkInspectorLambdaCodeScanningDisabled(self):
        self._resourceCheck('inspectorLambdaCodeScanningDisabled', 'lambdaCode',
                           'Lambda code', 0)

    def _checkInspectorCodeRepositoryScanningDisabled(self):
        ## codeRepository is present in the live API response but not in the
        ## original spec. INFO when absent (not all regions/tiers offer it).
        if not self.enabled:
            return self._na('inspectorCodeRepositoryScanningDisabled')
        status = self._resourceStatus('codeRepository')
        if status is None:
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                0, "Code repository scanning is not reported in this region"
            ]
        elif status == 'ENABLED':
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                1, "Code repository scanning is enabled"
            ]
        else:
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                -1,
                f"Code repository scanning is {status} — connected source "
                "repositories are not being scanned for exposed secrets and "
                "vulnerable dependencies"
            ]

    # 7. Coverage gap
    def _checkInspectorCoverageGap(self):
        if not self.enabled:
            return self._na('inspectorCoverageGap')
        total = self.coverage.get('_total') or 0
        if total == 0:
            self.results['inspectorCoverageGap'] = [
                0, "No resources reported by Inspector coverage"
            ]
            return
        inactive = self.coverage.get('INACTIVE', 0)
        fraction = inactive / total
        if fraction > self.COVERAGE_GAP_FRACTION:
            self.results['inspectorCoverageGap'] = [
                -1,
                "{} of {} resources ({:.0%}) have INACTIVE scan coverage — those "
                "resources are enrolled but not actually being scanned, so their "
                "vulnerabilities are unknown".format(inactive, total, fraction)
            ]
        else:
            self.results['inspectorCoverageGap'] = [
                1,
                "{} of {} resources actively scanned".format(
                    total - inactive, total)
            ]

    # 8. Critical findings
    def _checkInspectorCriticalFindings(self):
        if not self.enabled:
            return self._na('inspectorCriticalFindings')
        critical = self.severity.get('critical')
        if critical is None:
            self.results['inspectorCriticalFindings'] = [
                0, "Finding counts are not reported"
            ]
        elif critical > 0:
            self.results['inspectorCriticalFindings'] = [
                -1,
                f"{critical} CRITICAL Inspector finding(s) — critical CVEs on "
                "internet-adjacent or data-handling resources are the highest "
                "priority for patching"
            ]
        else:
            self.results['inspectorCriticalFindings'] = [
                1, "No CRITICAL Inspector findings"
            ]

    # 9. Exploitable findings
    def _checkInspectorExploitableFindings(self):
        if not self.enabled:
            return self._na('inspectorExploitableFindings')
        if self.exploit is None:
            self.results['inspectorExploitableFindings'] = [
                0, "Exploit-availability counts are not reported"
            ]
        elif self.exploit > 0:
            self.results['inspectorExploitableFindings'] = [
                -1,
                f"{self.exploit} finding(s) have a KNOWN EXPLOIT available — a "
                "vulnerability with a published exploit and a fix that has not "
                "been applied is the single highest-priority patching class"
            ]
        else:
            self.results['inspectorExploitableFindings'] = [
                1, "No findings with a known available exploit"
            ]

    # 10. Fixable findings not patched
    def _checkInspectorFixAvailableNotApplied(self):
        if not self.enabled:
            return self._na('inspectorFixAvailableNotApplied')
        if self.fix is None or not self.total:
            self.results['inspectorFixAvailableNotApplied'] = [
                0, "Fix-availability counts are not reported"
            ]
            return
        ## A high proportion of findings having an available-but-unapplied fix
        ## indicates patching is not keeping up. Report the raw numbers.
        if self.fix > 0:
            self.results['inspectorFixAvailableNotApplied'] = [
                -1,
                "{} of {} finding(s) have a fix available that has not been "
                "applied — these are patchable today; the vulnerability persists "
                "only because the update has not been rolled out".format(
                    self.fix, self.total)
            ]
        else:
            self.results['inspectorFixAvailableNotApplied'] = [
                1, "No findings with an unapplied available fix"
            ]
