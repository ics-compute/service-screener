import botocore

from services.Evaluator import Evaluator

class ApiGatewayDomainName(Evaluator):
    ## Custom domain names are account/region scoped, not per-API, so they get
    ## their own evaluator rather than hanging off ApiGatewayRest.

    ## Only TLS_1_0 is below the TLSv1.2 minimum. The newer
    ## SecurityPolicy_TLS13_* policies all negotiate 1.2 or above, so deny the
    ## one bad value instead of allowing a list that goes stale as AWS adds
    ## policies.
    INSECURE_SECURITY_POLICIES = ['TLS_1_0']

    def __init__(self, domainName, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.domainName = domainName

        self._resourceName = domainName['domainName']

        return

    def _checkMinTLSVersion(self):
        securityPolicy = self.domainName.get('securityPolicy')
        if securityPolicy is None:
            return

        if securityPolicy in self.INSECURE_SECURITY_POLICIES:
            self.results['MinTLSVersion'] = [-1, securityPolicy]

        return
