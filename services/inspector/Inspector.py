import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.inspector.drivers.InspectorCommon import InspectorCommon


class Inspector(Service):
    """
    Amazon Inspector (Inspector2) service scanner.

    The boto3 client is 'inspector2', not 'inspector' (that is the retired
    Inspector Classic). The scanner's service module is named 'inspector' for
    the CLI, and the class is Inspector; the client name is set explicitly below.

    Account/region-scoped -> single 'Inspector::Account' descriptor per region.

    Hydration calls (all read-only, all ONE call each — no finding enumeration):
      - batch_get_account_status        (per-resource-type scanning state)
      - list_coverage_statistics        (coverage gaps, by SCAN_STATUS_CODE)
      - list_finding_aggregations       (exact severity/exploit/fix counts)

    Deliberately NOT called: list_findings. It paginates over every finding
    (verified: 1,248 in the test account). list_finding_aggregations returns the
    exact counts this scanner needs in a single call.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        ## Explicit client name: the module is 'inspector' but the API is
        ## 'inspector2'.
        self.insClient = ssBoto.client('inspector2', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        detail = {
            '_region': self.region,
            '_accountId': self._currentAccount(),
            '_accountStatus': None,
            '_coverageByStatus': {},
            '_severityCounts': {},
            '_exploitAvailable': None,
            '_fixAvailable': None,
        }

        try:
            detail['_accountStatus'] = self._batchGetAccountStatus()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Inspector not available in region {self.region}: {e}")
            return None

        detail['_coverageByStatus'] = self._coverageByStatus()
        agg = self._findingAggregation()
        detail['_severityCounts'] = agg.get('severity', {})
        detail['_exploitAvailable'] = agg.get('exploit')
        detail['_fixAvailable'] = agg.get('fix')
        detail['_totalFindings'] = agg.get('total')

        _pi('Inspector', f"Inspector posture in {self.region}")
        return detail

    def _batchGetAccountStatus(self):
        try:
            resp = self.insClient.batch_get_account_status()
            accounts = resp.get('accounts', []) or []
            return accounts[0] if accounts else None
        except botocore.exceptions.ClientError as e:
            self._logClientError('batch_get_account_status', e)
            return None

    def _coverageByStatus(self):
        """{scanStatusCode: count} from list_coverage_statistics — one call, no
        per-resource enumeration."""
        try:
            resp = self.insClient.list_coverage_statistics(
                groupBy='SCAN_STATUS_CODE')
            out = {}
            for group in resp.get('countsByGroup', []) or []:
                out[group.get('groupKey')] = group.get('count', 0)
            out['_total'] = resp.get('totalCounts', 0)
            return out
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_coverage_statistics', e)
            return {}

    def _findingAggregation(self):
        """Exact severity/exploit/fix counts from list_finding_aggregations."""
        try:
            resp = self.insClient.list_finding_aggregations(
                aggregationType='ACCOUNT')
            responses = resp.get('responses', []) or []
            if not responses:
                return {}
            acct = (responses[0] or {}).get('accountAggregation') or {}
            return {
                'severity': acct.get('severityCounts') or {},
                'exploit': acct.get('exploitAvailableCount'),
                'fix': acct.get('fixAvailableCount'),
                'total': (acct.get('severityCounts') or {}).get('all'),
            }
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_finding_aggregations', e)
            return {}

    def _currentAccount(self):
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        detail = self.getResources()
        if detail is None:
            return objs
        try:
            obj = InspectorCommon(detail, self.insClient)
            obj.run(self.__class__)
            objs['Inspector::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Inspector posture in {self.region}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Inspector {where}: {code} - {msg}")
