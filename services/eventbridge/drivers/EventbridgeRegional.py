from services.Evaluator import Evaluator


class EventbridgeRegional(Evaluator):
    """
    Region-scoped EventBridge checks (5 of the 14).

      ebArchiveNotConfigured
      ebSchemaDiscoveryDisabled
      ebConnectionNoAuth
      ebApiDestinationHttpEndpoint
      ebGlobalEndpointNoReplication

    These subjects are per-region collections rather than per-bus or per-rule:
    archives, schema discoverers, connections, API destinations and global
    endpoints all live at the region level. Following the precedent of
    services/ec2/drivers/Ec2Regional.py.

    Input:
      detail -- dict from Eventbridge._getRegionalDetail. Keys: '_region',
        '_accountId', '_archives', '_connections', '_apiDestinations',
        '_endpoints', '_discoverers', '_discovererLookupFailed'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    MAX_NAMES_IN_MESSAGE = 5

    ## Connection AuthorizationType values that constitute real authentication.
    ## The EventBridge API has no 'NONE' value — a connection always carries one
    ## of these — so an unrecognised or absent value is the anomaly.
    AUTHENTICATED_TYPES = frozenset(['BASIC', 'OAUTH_CLIENT_CREDENTIALS', 'API_KEY'])

    def __init__(self, detail, ebClient):
        super().__init__()
        self.detail = detail
        self.ebClient = ebClient

        ## Region-scoped subject; there is no per-resource name.
        self._resourceName = 'Account'

        self.archives = detail.get('_archives') or []
        self.connections = detail.get('_connections') or []
        self.apiDestinations = detail.get('_apiDestinations') or []
        self.endpoints = detail.get('_endpoints') or []
        self.discoverers = detail.get('_discoverers') or []
        self.discovererLookupFailed = bool(detail.get('_discovererLookupFailed'))

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('archiveCount', str(len(self.archives)))
        self.addII('connectionCount', str(len(self.connections)))
        self.addII('apiDestinationCount', str(len(self.apiDestinations)))
        self.addII('globalEndpointCount', str(len(self.endpoints)))
        self.addII('schemaDiscovererCount', str(len(self.discoverers)))

    # ------------------------------------------------------------------ #
    # 1. No event archive
    # ------------------------------------------------------------------ #
    def _checkEbArchiveNotConfigured(self):
        """
        Without an archive there is no replay capability: an event lost to a bug
        in a downstream consumer cannot be re-delivered once it has been
        processed.
        """
        if not self.archives:
            self.results['ebArchiveNotConfigured'] = [
                -1,
                "No EventBridge archive exists in this region — delivered events "
                "are not retained, so none can be replayed after a downstream "
                "failure"
            ]
            return

        ## An archive in a non-ENABLED state retains nothing.
        enabled = [a for a in self.archives if a.get('State') == 'ENABLED']
        if not enabled:
            states = sorted({a.get('State', 'UNKNOWN') for a in self.archives})
            self.results['ebArchiveNotConfigured'] = [
                -1,
                f"{len(self.archives)} archive(s) exist but none are ENABLED "
                f"(state(s): {', '.join(states)}) — no events are being retained"
            ]
            return

        names = [a.get('ArchiveName', '?') for a in enabled]
        self.results['ebArchiveNotConfigured'] = [
            1,
            f"{len(enabled)} enabled archive(s): " + self._joinNames(names)
        ]

    # ------------------------------------------------------------------ #
    # 2. Schema discovery not enabled
    # ------------------------------------------------------------------ #
    def _checkEbSchemaDiscoveryDisabled(self):
        """
        Schema discovery is provided by the separate 'schemas' service, which is
        absent in some regions and needs its own IAM permission. A failed lookup
        must report INFO, not FAIL — otherwise every region without the endpoint
        raises a finding the customer cannot act on.
        """
        if self.discovererLookupFailed:
            self.results['ebSchemaDiscoveryDisabled'] = [
                0,
                "EventBridge Schema Registry could not be queried in this region "
                "(endpoint unavailable or schemas:ListDiscoverers denied)"
            ]
            return

        if not self.discoverers:
            self.results['ebSchemaDiscoveryDisabled'] = [
                -1,
                "No schema discoverer is configured — event schemas are not "
                "catalogued, so consumers have no generated contract to bind to"
            ]
            return

        started = [d for d in self.discoverers if d.get('State') == 'STARTED']
        if not started:
            self.results['ebSchemaDiscoveryDisabled'] = [
                -1,
                f"{len(self.discoverers)} schema discoverer(s) exist but none are "
                "in the STARTED state — no schemas are being discovered"
            ]
            return

        self.results['ebSchemaDiscoveryDisabled'] = [
            1, f"{len(started)} schema discoverer(s) are running"
        ]

    # ------------------------------------------------------------------ #
    # 3. Connection with no authorization
    # ------------------------------------------------------------------ #
    def _checkEbConnectionNoAuth(self):
        if not self.connections:
            self.results['ebConnectionNoAuth'] = [
                0, "No EventBridge connection exists in this region"
            ]
            return

        unauthenticated = [
            c.get('Name', '?') for c in self.connections
            if c.get('AuthorizationType') not in self.AUTHENTICATED_TYPES
        ]

        if unauthenticated:
            self.results['ebConnectionNoAuth'] = [
                -1,
                "{} of {} connection(s) do not use a recognised authorization "
                "type (BASIC, API_KEY or OAUTH_CLIENT_CREDENTIALS): {}".format(
                    len(unauthenticated), len(self.connections),
                    self._joinNames(unauthenticated))
            ]
        else:
            self.results['ebConnectionNoAuth'] = [
                1,
                f"All {len(self.connections)} connection(s) use an authenticated "
                "authorization type"
            ]

    # ------------------------------------------------------------------ #
    # 4. API destination over plaintext HTTP
    # ------------------------------------------------------------------ #
    def _checkEbApiDestinationHttpEndpoint(self):
        if not self.apiDestinations:
            self.results['ebApiDestinationHttpEndpoint'] = [
                0, "No EventBridge API destination exists in this region"
            ]
            return

        insecure = []
        for destination in self.apiDestinations:
            endpoint = destination.get('InvocationEndpoint') or ''
            if endpoint.lower().startswith('http://'):
                insecure.append(destination.get('Name', '?'))

        if insecure:
            self.results['ebApiDestinationHttpEndpoint'] = [
                -1,
                "{} of {} API destination(s) invoke a plaintext http:// endpoint, "
                "so event payloads and any credentials in them cross the network "
                "unencrypted: {}".format(len(insecure), len(self.apiDestinations),
                                         self._joinNames(insecure))
            ]
        else:
            self.results['ebApiDestinationHttpEndpoint'] = [
                1,
                f"All {len(self.apiDestinations)} API destination(s) use https://"
            ]

    # ------------------------------------------------------------------ #
    # 5. Global endpoint without event replication
    # ------------------------------------------------------------------ #
    def _checkEbGlobalEndpointNoReplication(self):
        if not self.endpoints:
            self.results['ebGlobalEndpointNoReplication'] = [
                0, "No EventBridge global endpoint exists in this region"
            ]
            return

        notReplicating = []
        for endpoint in self.endpoints:
            state = (endpoint.get('ReplicationConfig') or {}).get('State')
            if state != 'ENABLED':
                notReplicating.append(endpoint.get('Name', '?'))

        if notReplicating:
            self.results['ebGlobalEndpointNoReplication'] = [
                -1,
                "{} of {} global endpoint(s) have event replication disabled — "
                "events published before a regional failover are not mirrored to "
                "the secondary region: {}".format(
                    len(notReplicating), len(self.endpoints),
                    self._joinNames(notReplicating))
            ]
        else:
            self.results['ebGlobalEndpointNoReplication'] = [
                1,
                f"All {len(self.endpoints)} global endpoint(s) have replication "
                "ENABLED"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
