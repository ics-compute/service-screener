from services.Evaluator import Evaluator


class SecurityhubCommon(Evaluator):
    """
    Account/region-scoped Security Hub checks (8).

    Input:
      detail -- from services/securityhub/Securityhub.py.getResources.
      cisArnFragment -- substring identifying a CIS standard ARN.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    When Security Hub is not enabled, only shubNotEnabled produces a finding;
    every other check reports INFO, because "is auto-enable on" is meaningless
    when the hub does not exist.
    """

    ## Below this many third-party integrations we flag shubIntegrationsMissing.
    MIN_INTEGRATIONS = 3

    def __init__(self, detail, shClient, cisArnFragment):
        super().__init__()
        self.detail = detail
        self.shClient = shClient
        self.cisArnFragment = cisArnFragment
        self._resourceName = 'Account'

        self.enabled = bool(detail.get('_enabled'))
        self.hub = detail.get('_hub') or {}
        self.standards = detail.get('_standards') or []
        self.aggregators = detail.get('_aggregators') or []
        self.products = detail.get('_products') or []
        self.unprocessed = detail.get('_unprocessedFindings')
        self.findingsCapped = bool(detail.get('_findingsCapped'))

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('enabled', str(self.enabled))
        self.addII('autoEnableControls',
                   str(self.hub.get('AutoEnableControls', 'N/A')))
        self.addII('controlFindingGenerator',
                   self.hub.get('ControlFindingGenerator', 'N/A'))
        self.addII('enabledStandardsCount', str(len(self.standards)))
        self.addII('integrationCount', str(len(self.products)))

    def _na(self, key):
        """Report INFO because Security Hub is not enabled here."""
        self.results[key] = [
            0, "Security Hub is not enabled in this region — see shubNotEnabled"
        ]

    # 1. Hub not enabled
    def _checkShubNotEnabled(self):
        if self.enabled:
            self.results['shubNotEnabled'] = [
                1, "Security Hub is enabled in this region"
            ]
        else:
            self.results['shubNotEnabled'] = [
                -1,
                "Security Hub is not enabled in this region — the account has no "
                "aggregated view of control failures across services, and none "
                "of the CIS/FSBP standard checks are running"
            ]

    # 2. No standards enabled
    def _checkShubNoStandardsEnabled(self):
        if not self.enabled:
            return self._na('shubNoStandardsEnabled')
        if self.standards:
            self.results['shubNoStandardsEnabled'] = [
                1, f"{len(self.standards)} security standard(s) enabled"
            ]
        else:
            self.results['shubNoStandardsEnabled'] = [
                -1,
                "Security Hub is enabled but no security standard is turned on — "
                "the hub is collecting nothing, so it reports no control findings"
            ]

    # 3. CIS standard not enabled
    def _checkShubCISStandardDisabled(self):
        if not self.enabled:
            return self._na('shubCISStandardDisabled')
        hasCis = any(self.cisArnFragment in (s.get('StandardsArn') or '')
                     for s in self.standards)
        if hasCis:
            self.results['shubCISStandardDisabled'] = [
                1, "A CIS AWS Foundations Benchmark standard is enabled"
            ]
        else:
            self.results['shubCISStandardDisabled'] = [
                -1,
                "No CIS AWS Foundations Benchmark standard is enabled — the most "
                "widely required baseline for AWS audits is not being evaluated"
            ]

    # 4. Auto-enable controls off
    def _checkShubAutoEnableControlsDisabled(self):
        if not self.enabled:
            return self._na('shubAutoEnableControlsDisabled')
        if self.hub.get('AutoEnableControls') is True:
            self.results['shubAutoEnableControlsDisabled'] = [
                1, "New controls are auto-enabled as AWS releases them"
            ]
        else:
            self.results['shubAutoEnableControlsDisabled'] = [
                -1,
                "AutoEnableControls is off — controls AWS adds for newly released "
                "services are not evaluated until someone enables them by hand, so "
                "coverage silently falls behind the services in use"
            ]

    # 5. Legacy control-finding generator
    def _checkShubLegacyControlFindingGenerator(self):
        if not self.enabled:
            return self._na('shubLegacyControlFindingGenerator')
        gen = self.hub.get('ControlFindingGenerator')
        if gen == 'SECURITY_CONTROL':
            self.results['shubLegacyControlFindingGenerator'] = [
                1, "Consolidated control findings (SECURITY_CONTROL) is enabled"
            ]
        else:
            self.results['shubLegacyControlFindingGenerator'] = [
                -1,
                f"ControlFindingGenerator is {gen or 'STANDARD_CONTROL'} (legacy) "
                "— the same control generates a separate finding under every "
                "standard it belongs to, multiplying finding volume and cost. "
                "Switch to consolidated control findings"
            ]

    # 6. No cross-region finding aggregator
    def _checkShubFindingAggregatorMissing(self):
        if not self.enabled:
            return self._na('shubFindingAggregatorMissing')
        if self.aggregators:
            self.results['shubFindingAggregatorMissing'] = [
                1, "A finding aggregator provides a cross-region view"
            ]
        else:
            self.results['shubFindingAggregatorMissing'] = [
                -1,
                "No finding aggregator — findings are siloed per region, so there "
                "is no single place to see the account's posture and a region "
                "nobody watches goes unmonitored"
            ]

    # 7. Too few integrations
    def _checkShubIntegrationsMissing(self):
        if not self.enabled:
            return self._na('shubIntegrationsMissing')
        if len(self.products) >= self.MIN_INTEGRATIONS:
            self.results['shubIntegrationsMissing'] = [
                1, f"{len(self.products)} product integration(s) importing findings"
            ]
        else:
            self.results['shubIntegrationsMissing'] = [
                -1,
                f"Only {len(self.products)} product integration(s) enabled — "
                "Security Hub is most useful as the single pane that aggregates "
                "GuardDuty, Inspector, Macie and partner findings; too few "
                "integrations means it is not seeing much"
            ]

    # 8. Backlog of unprocessed findings
    def _checkShubUnprocessedFindings(self):
        if not self.enabled:
            return self._na('shubUnprocessedFindings')
        if self.unprocessed is None:
            self.results['shubUnprocessedFindings'] = [
                0, "Finding count could not be read"
            ]
            return
        ## Threshold is 100 NEW findings; the page cap is high enough to
        ## distinguish "under 100" from "well over".
        if self.unprocessed <= 100 and not self.findingsCapped:
            self.results['shubUnprocessedFindings'] = [
                1, f"{self.unprocessed} finding(s) in the NEW workflow state"
            ]
        else:
            atLeast = "at least " if self.findingsCapped else ""
            self.results['shubUnprocessedFindings'] = [
                -1,
                f"{atLeast}{self.unprocessed} finding(s) are still in the NEW "
                "workflow state — a backlog this size means findings are not "
                "being triaged, so a real one is unlikely to be noticed among them"
            ]
