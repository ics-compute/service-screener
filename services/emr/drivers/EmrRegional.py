from services.Evaluator import Evaluator


class EmrRegional(Evaluator):
    """
    Account/region-scoped Amazon EMR check (1).

      emrBlockPublicAccessDisabled  -- FSBP EMR.2

    Security Hub's resource type for EMR.2 is AWS::::Account, so it is evaluated
    ONCE per region rather than once per cluster. Putting it on the cluster driver
    would report the same account-level setting N times.

    It is also evaluated when the region has NO clusters: the setting governs
    every cluster launched in future, so its absence is worth reporting before
    someone launches one.

    Input:
      detail -- '_region', '_blockPublicAccess', '_clusterCount'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## Port 22 is the documented default exception AWS ships, and is generally
    ## acceptable because SSH is still gated by the security group itself.
    ACCEPTABLE_PERMITTED_PORTS = frozenset([22])

    def __init__(self, detail, emrClient):
        super().__init__()
        self.detail = detail
        self.emrClient = emrClient
        self._resourceName = 'Account'

        self.config = detail.get('_blockPublicAccess')
        self.clusterCount = detail.get('_clusterCount', 0)

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('activeClusterCount', str(self.clusterCount))
        if isinstance(self.config, dict):
            self.addII('blockPublicSecurityGroupRules',
                       str(self.config.get('BlockPublicSecurityGroupRules',
                                           'N/A')))
            ranges = self.config.get(
                'PermittedPublicSecurityGroupRuleRanges') or []
            self.addII('permittedPublicPortRanges',
                       ', '.join(
                           f"{r.get('MinRange')}-{r.get('MaxRange')}"
                           for r in ranges) or 'none')
        else:
            self.addII('blockPublicSecurityGroupRules', 'unreadable')

    def _checkEmrBlockPublicAccessDisabled(self):
        if not isinstance(self.config, dict):
            self.results['emrBlockPublicAccessDisabled'] = [
                0,
                "The EMR block-public-access configuration could not be read in "
                "this region"
            ]
            return

        if self.config.get('BlockPublicSecurityGroupRules') is not True:
            self.results['emrBlockPublicAccessDisabled'] = [
                -1,
                "EMR block public access is DISABLED in this region — a cluster "
                "can be launched with a security group open to 0.0.0.0/0 on any "
                "port, and EMR will not refuse it. This is an account-level "
                "guardrail that applies to every future cluster"
            ]
            return

        ## Enabled, but wide exception ranges undermine it.
        ranges = self.config.get('PermittedPublicSecurityGroupRuleRanges') or []
        wide = []
        for entry in ranges:
            lo, hi = entry.get('MinRange'), entry.get('MaxRange')
            if lo is None or hi is None:
                continue
            ## A single acceptable port (22) is the AWS default; anything broader
            ## re-opens what the guardrail is meant to close.
            if lo == hi and lo in self.ACCEPTABLE_PERMITTED_PORTS:
                continue
            wide.append(f"{lo}-{hi}")

        if wide:
            self.results['emrBlockPublicAccessDisabled'] = [
                -1,
                "EMR block public access is enabled but permits public ingress on "
                "port range(s) " + ', '.join(wide)
                + " — those ports may still be exposed to 0.0.0.0/0, which "
                "narrows the guardrail to whatever is left"
            ]
        else:
            self.results['emrBlockPublicAccessDisabled'] = [
                1,
                "EMR block public access is enabled"
                + (" (permitting only port 22)" if ranges else "")
            ]
