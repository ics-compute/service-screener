from services.Evaluator import Evaluator


class AccessanalyzerCommon(Evaluator):
    """
    Account/region-scoped IAM Access Analyzer checks (8).

    Input:
      detail -- from services/accessanalyzer/Accessanalyzer.py.getResources:
        '_region', '_analyzers', '_activeExternalFindings', '_findingsCapped',
        '_archiveRuleCount'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ANALYZER_EXTERNAL = ('ACCOUNT', 'ORGANIZATION')
    ANALYZER_UNUSED = ('ACCOUNT_UNUSED_ACCESS', 'ORGANIZATION_UNUSED_ACCESS')
    ANALYZER_INTERNAL = ('ACCOUNT_INTERNAL_ACCESS', 'ORGANIZATION_INTERNAL_ACCESS')

    def __init__(self, detail, aaClient):
        super().__init__()
        self.detail = detail
        self.aaClient = aaClient
        self._resourceName = 'Account'

        self.analyzers = detail.get('_analyzers') or []
        self.activeFindings = detail.get('_activeExternalFindings')
        self.findingsCapped = bool(detail.get('_findingsCapped'))
        self.archiveRuleCount = detail.get('_archiveRuleCount') or 0

        self.types = [a.get('type') for a in self.analyzers]
        self.active = [a for a in self.analyzers if a.get('status') == 'ACTIVE']

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('analyzerCount', str(len(self.analyzers)))
        self.addII('activeAnalyzerCount', str(len(self.active)))
        self.addII('analyzerTypes', ', '.join(sorted(set(self.types))) or 'none')

    def _hasType(self, types):
        return any(t in types for t in self.types)

    def _hasActiveType(self, types):
        return any(a.get('type') in types for a in self.active)

    # 1. No analyzer at all
    def _checkAaNoAnalyzerConfigured(self):
        if self.analyzers:
            self.results['aaNoAnalyzerConfigured'] = [
                1, f"{len(self.analyzers)} Access Analyzer analyzer(s) configured"
            ]
        else:
            self.results['aaNoAnalyzerConfigured'] = [
                -1,
                "No IAM Access Analyzer analyzer exists in this region — nothing "
                "is continuously evaluating resource policies for access granted "
                "outside the account"
            ]

    # 2. No external-access analyzer
    def _checkAaNoAccountAnalyzer(self):
        if not self.analyzers:
            self.results['aaNoAccountAnalyzer'] = [
                0, "No analyzer at all — see aaNoAnalyzerConfigured"
            ]
            return
        if self._hasType(self.ANALYZER_EXTERNAL):
            self.results['aaNoAccountAnalyzer'] = [
                1, "An account or organization external-access analyzer exists"
            ]
        else:
            self.results['aaNoAccountAnalyzer'] = [
                -1,
                "No external-access analyzer (type ACCOUNT or ORGANIZATION) — "
                "external access to S3 buckets, IAM roles, KMS keys and the like "
                "is not being detected"
            ]

    # 3. No unused-access analyzer
    def _checkAaUnusedAccessAnalyzerMissing(self):
        if self._hasType(self.ANALYZER_UNUSED):
            self.results['aaUnusedAccessAnalyzerMissing'] = [
                1, "An unused-access analyzer exists"
            ]
        else:
            self.results['aaUnusedAccessAnalyzerMissing'] = [
                -1,
                "No unused-access analyzer (type ACCOUNT_UNUSED_ACCESS) — unused "
                "IAM roles, access keys and permissions are not being surfaced "
                "for least-privilege review"
            ]

    # 4. No internal-access analyzer (newer type)
    def _checkAaNoInternalAccessAnalyzer(self):
        if self._hasType(self.ANALYZER_INTERNAL):
            self.results['aaNoInternalAccessAnalyzer'] = [
                1, "An internal-access analyzer exists"
            ]
        else:
            self.results['aaNoInternalAccessAnalyzer'] = [
                0,
                "No internal-access analyzer (type ACCOUNT_INTERNAL_ACCESS) — "
                "this newer analyzer surfaces which principals inside the account "
                "can reach critical resources; consider enabling it"
            ]

    # 5. An analyzer exists but is not ACTIVE
    def _checkAaAnalyzerNotActive(self):
        if not self.analyzers:
            self.results['aaAnalyzerNotActive'] = [
                0, "No analyzer at all — see aaNoAnalyzerConfigured"
            ]
            return
        inactive = [
            a.get('name', 'unknown') for a in self.analyzers
            if a.get('status') != 'ACTIVE'
        ]
        if inactive:
            self.results['aaAnalyzerNotActive'] = [
                -1,
                "{} analyzer(s) are not in the ACTIVE state ({}) — an analyzer "
                "that is not active produces no findings".format(
                    len(inactive), ', '.join(inactive[:5]))
            ]
        else:
            self.results['aaAnalyzerNotActive'] = [
                1, f"All {len(self.analyzers)} analyzer(s) are ACTIVE"
            ]

    # 6. Unresolved external-access findings
    def _checkAaUnresolvedExternalAccess(self):
        if not self._hasActiveType(self.ANALYZER_EXTERNAL):
            self.results['aaUnresolvedExternalAccess'] = [
                0, "No active external-access analyzer to report findings"
            ]
            return
        if self.activeFindings is None:
            self.results['aaUnresolvedExternalAccess'] = [
                0, "Access Analyzer findings could not be read"
            ]
            return
        if self.activeFindings == 0:
            self.results['aaUnresolvedExternalAccess'] = [
                1, "No active external-access findings"
            ]
            return

        atLeast = "at least " if self.findingsCapped else ""
        self.results['aaUnresolvedExternalAccess'] = [
            -1,
            f"{atLeast}{self.activeFindings} active external-access finding(s) — "
            "each is a resource granting access outside the account that has not "
            "been reviewed and archived or remediated"
        ]

    # 7. No archive rules (known-good findings not auto-archived)
    def _checkAaNoArchiveRules(self):
        if not self._hasActiveType(self.ANALYZER_EXTERNAL):
            self.results['aaNoArchiveRules'] = [
                0, "No active external-access analyzer"
            ]
            return
        if self.archiveRuleCount > 0:
            self.results['aaNoArchiveRules'] = [
                1, f"{self.archiveRuleCount} archive rule(s) configured"
            ]
        else:
            self.results['aaNoArchiveRules'] = [
                -1,
                "No archive rules — every intended cross-account grant reappears "
                "as an active finding on each scan, so real findings are harder "
                "to see among the known-good ones"
            ]

    # 8. No organization analyzer when in an org
    def _checkAaNoOrganizationAnalyzer(self):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        ## Only meaningful inside an AWS Organization. We do not have a cheap
        ## org-membership signal here, so report INFO rather than FAIL when no
        ## ORGANIZATION analyzer exists — a standalone account correctly has none.
        orgTypes = ('ORGANIZATION', 'ORGANIZATION_UNUSED_ACCESS',
                    'ORGANIZATION_INTERNAL_ACCESS')
        if any(t in orgTypes for t in self.types):
            self.results['aaNoOrganizationAnalyzer'] = [
                1, "An organization-level analyzer exists"
            ]
        else:
            self.results['aaNoOrganizationAnalyzer'] = [
                0,
                "No organization-level analyzer. If this account is the "
                "delegated administrator for an AWS Organization, an ORGANIZATION "
                "analyzer gives a single cross-account view; a standalone account "
                "does not need one"
            ]
