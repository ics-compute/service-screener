from datetime import datetime, timezone

from services.Evaluator import Evaluator


class AppsyncApi(Evaluator):
    """
    Per-API AWS AppSync checks (11).

    Input:
      api -- a list_graphql_apis entry plus '_tags' (normalised to Key/Value),
             '_region' and '_apiKeys', from services/appsync/Appsync.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    Dropped from the original spec after review:
      appsyncCachingDisabled -- cachingConfig is not a member of GraphqlApi
        (caching requires a separate get_api_cache call), and AWS RETIRED the
        AppSync cache-encryption controls (AppSync.1, AppSync.6) on 2026-03-09
        because caches are now encrypted by default. Little left to check.
    """

    ## Authentication types that verify caller identity per request. API_KEY is
    ## deliberately absent: a static key shared by every client is not
    ## authentication in the sense a GraphQL endpoint needs.
    STRONG_AUTH_TYPES = frozenset([
        'AWS_IAM', 'AMAZON_COGNITO_USER_POOLS', 'OPENID_CONNECT', 'AWS_LAMBDA',
    ])

    ## An API key valid for longer than this is effectively permanent.
    LONG_EXPIRY_DAYS = 365

    ## Warn when a key expires within this window, so rotation can be planned
    ## before the API starts rejecting clients.
    EXPIRING_SOON_DAYS = 7

    ## How many names to list explicitly in a message before truncating.
    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, api, asClient):
        super().__init__()
        self.api = api
        self.asClient = asClient

        self.name = api.get('name') or api.get('apiId', 'unknown')
        self._resourceName = self.name

        self.authType = api.get('authenticationType')
        self.additionalAuth = api.get('additionalAuthenticationProviders') or []
        self.logConfig = api.get('logConfig') or {}
        self.tags = api.get('_tags') or []
        self.apiKeys = api.get('_apiKeys') or []
        self.visibility = api.get('visibility')

        self.addII('apiName', self.name)
        self.addII('apiId', api.get('apiId', 'N/A'))
        self.addII('region', api.get('_region', 'N/A'))
        self.addII('authenticationType', self.authType or 'N/A')
        self.addII('additionalAuthCount', str(len(self.additionalAuth)))
        self.addII('visibility', self.visibility or 'N/A')
        self.addII('wafWebAclArn', api.get('wafWebAclArn') or 'None')
        self.addII('xrayEnabled', str(api.get('xrayEnabled', False)))
        self.addII('introspectionConfig',
                   api.get('introspectionConfig') or 'N/A')
        self.addII('apiKeyCount', str(len(self.apiKeys)))
        self.addII('tagCount', str(len(self.tags)))

    def _allAuthTypes(self):
        types = [self.authType] if self.authType else []
        types += [p.get('authenticationType') for p in self.additionalAuth
                  if isinstance(p, dict)]
        return [t for t in types if t]

    # ------------------------------------------------------------------ #
    # 1. API key is the only authentication
    # ------------------------------------------------------------------ #
    def _checkAppsyncNoAuthentication(self):
        """
        FSBP AppSync.5. An API key is a static shared secret with no notion of
        who is calling; it cannot be scoped per user, revoked per client, or
        audited to a principal. Passing means at least one strong mechanism is
        configured, even if a key also exists for a public/read tier.
        """
        types = self._allAuthTypes()
        if not types:
            self.results['appsyncNoAuthentication'] = [
                0, f"API '{self.name}' reports no authentication type"
            ]
            return

        strong = [t for t in types if t in self.STRONG_AUTH_TYPES]
        if strong:
            self.results['appsyncNoAuthentication'] = [
                1,
                f"API '{self.name}' uses " + self._joinNames(sorted(set(strong)))
            ]
        else:
            self.results['appsyncNoAuthentication'] = [
                -1,
                f"API '{self.name}' authenticates only with "
                + self._joinNames(sorted(set(types)))
                + " — a static API key identifies no caller, cannot be scoped per "
                "user and cannot be revoked for one client without breaking all "
                "of them"
            ]

    # ------------------------------------------------------------------ #
    # 2. API key expiring soon
    # ------------------------------------------------------------------ #
    def _checkAppsyncApiKeyExpiringSoon(self):
        if not self.apiKeys:
            self.results['appsyncApiKeyExpiringSoon'] = [
                0, f"API '{self.name}' has no API keys"
            ]
            return

        soon = []
        for key in self.apiKeys:
            days = self._daysUntil(key.get('expires'))
            if days is not None and 0 <= days <= self.EXPIRING_SOON_DAYS:
                soon.append(f"{key.get('id', '?')[:8]}… ({days}d)")

        if soon:
            self.results['appsyncApiKeyExpiringSoon'] = [
                -1,
                f"{len(soon)} API key(s) on '{self.name}' expire within "
                f"{self.EXPIRING_SOON_DAYS} days: " + self._joinNames(soon)
                + " — every client using them will start receiving "
                "authentication errors at that point"
            ]
        else:
            self.results['appsyncApiKeyExpiringSoon'] = [
                1,
                f"No API key on '{self.name}' expires within "
                f"{self.EXPIRING_SOON_DAYS} days"
            ]

    # ------------------------------------------------------------------ #
    # 3. API key with an effectively unlimited lifetime
    # ------------------------------------------------------------------ #
    def _checkAppsyncApiKeyNoExpiry(self):
        if not self.apiKeys:
            self.results['appsyncApiKeyNoExpiry'] = [
                0, f"API '{self.name}' has no API keys"
            ]
            return

        longLived = []
        for key in self.apiKeys:
            days = self._daysUntil(key.get('expires'))
            if days is None or days > self.LONG_EXPIRY_DAYS:
                longLived.append(key.get('id', '?')[:8] + '…')

        if longLived:
            self.results['appsyncApiKeyNoExpiry'] = [
                -1,
                f"{len(longLived)} API key(s) on '{self.name}' are valid for more "
                f"than {self.LONG_EXPIRY_DAYS} days: "
                + self._joinNames(longLived)
                + " — a long-lived static key that leaks stays valid for as long "
                "as it takes someone to notice"
            ]
        else:
            self.results['appsyncApiKeyNoExpiry'] = [
                1,
                f"All API keys on '{self.name}' expire within "
                f"{self.LONG_EXPIRY_DAYS} days"
            ]

    # ------------------------------------------------------------------ #
    # 4. Field-level logging off
    # ------------------------------------------------------------------ #
    def _checkAppsyncFieldLevelLogging(self):
        """FSBP AppSync.2 — fails on fieldLogLevel NONE or absent logConfig."""
        level = self.logConfig.get('fieldLogLevel')
        if level and level != 'NONE':
            self.results['appsyncFieldLevelLogging'] = [
                1, f"API '{self.name}' logs fields at level {level}"
            ]
        else:
            self.results['appsyncFieldLevelLogging'] = [
                -1,
                f"API '{self.name}' has fieldLogLevel="
                f"{level or 'not configured'} — resolver-level errors are not "
                "logged, so a failing or abused field cannot be identified from "
                "the logs"
            ]

    # ------------------------------------------------------------------ #
    # 5. No CloudWatch Logs role
    # ------------------------------------------------------------------ #
    def _checkAppsyncCloudWatchLogsNotEnabled(self):
        if self.logConfig.get('cloudWatchLogsRoleArn'):
            self.results['appsyncCloudWatchLogsNotEnabled'] = [
                1, f"API '{self.name}' delivers logs to CloudWatch Logs"
            ]
        else:
            self.results['appsyncCloudWatchLogsNotEnabled'] = [
                -1,
                f"API '{self.name}' has no cloudWatchLogsRoleArn — nothing is "
                "written to CloudWatch Logs at all, so there is no request record "
                "for either debugging or abuse investigation"
            ]

    # ------------------------------------------------------------------ #
    # 6. Introspection enabled
    # ------------------------------------------------------------------ #
    def _checkAppsyncIntrospectionEnabled(self):
        """
        GraphQL introspection publishes the entire schema — every type, field and
        mutation, including ones intended to be internal. On a production API it
        hands an attacker a complete map of the attack surface.
        """
        if self.api.get('introspectionConfig') == 'DISABLED':
            self.results['appsyncIntrospectionEnabled'] = [
                1, f"API '{self.name}' has introspection disabled"
            ]
        else:
            self.results['appsyncIntrospectionEnabled'] = [
                -1,
                f"API '{self.name}' has introspection ENABLED — any client can "
                "download the full schema, including internal types and "
                "mutations, which is a complete map of the API's attack surface"
            ]

    # ------------------------------------------------------------------ #
    # 7. No WAF association
    # ------------------------------------------------------------------ #
    def _checkAppsyncWafNotAssociated(self):
        """
        Only meaningful for a GLOBAL (internet-facing) API. A PRIVATE API is
        reachable only from within a VPC, so a WAF is not the relevant control.
        """
        if self.visibility and self.visibility != 'GLOBAL':
            self.results['appsyncWafNotAssociated'] = [
                0,
                f"API '{self.name}' has visibility {self.visibility} — not "
                "internet-facing, so a WAF is not the relevant control"
            ]
            return

        if self.api.get('wafWebAclArn'):
            self.results['appsyncWafNotAssociated'] = [
                1, f"API '{self.name}' is protected by a WAFv2 WebACL"
            ]
        else:
            self.results['appsyncWafNotAssociated'] = [
                -1,
                f"API '{self.name}' is internet-facing with no WAFv2 WebACL — "
                "there is no rate limiting, no managed rule protection and no "
                "bot control in front of a public GraphQL endpoint"
            ]

    # ------------------------------------------------------------------ #
    # 8. No query depth limit
    # ------------------------------------------------------------------ #
    def _checkAppsyncNoQueryDepthLimit(self):
        """
        GraphQL lets a client nest a query arbitrarily deep. Without a depth
        limit, one crafted query can fan out into an enormous number of resolver
        invocations — a denial-of-service that needs no volume at all.
        """
        limit = self.api.get('queryDepthLimit')
        if limit:
            self.results['appsyncNoQueryDepthLimit'] = [
                1, f"API '{self.name}' limits query depth to {limit}"
            ]
        else:
            self.results['appsyncNoQueryDepthLimit'] = [
                -1,
                f"API '{self.name}' has no queryDepthLimit — a single deeply "
                "nested query can expand into a very large number of resolver "
                "calls, so one request is enough to exhaust capacity"
            ]

    # ------------------------------------------------------------------ #
    # 9. No resolver count limit
    # ------------------------------------------------------------------ #
    def _checkAppsyncNoResolverCountLimit(self):
        limit = self.api.get('resolverCountLimit')
        if limit:
            self.results['appsyncNoResolverCountLimit'] = [
                1, f"API '{self.name}' limits resolvers per query to {limit}"
            ]
        else:
            self.results['appsyncNoResolverCountLimit'] = [
                -1,
                f"API '{self.name}' has no resolverCountLimit — a single query "
                "may trigger an unbounded number of resolver invocations, each "
                "billed and each consuming downstream capacity"
            ]

    # ------------------------------------------------------------------ #
    # 10. X-Ray tracing disabled
    # ------------------------------------------------------------------ #
    def _checkAppsyncXrayTracingDisabled(self):
        if self.api.get('xrayEnabled') is True:
            self.results['appsyncXrayTracingDisabled'] = [
                1, f"API '{self.name}' has X-Ray tracing enabled"
            ]
        else:
            self.results['appsyncXrayTracingDisabled'] = [
                -1,
                f"API '{self.name}' has X-Ray tracing disabled — a slow GraphQL "
                "response cannot be attributed to a specific resolver or "
                "downstream dependency"
            ]

    # ------------------------------------------------------------------ #
    # 11. No tags
    # ------------------------------------------------------------------ #
    def _checkAppsyncNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['appsyncNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['appsyncNoTags'] = [
                -1,
                f"API '{self.name}' has no tags — it cannot be attributed to an "
                "owning team or environment"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _daysUntil(self, expires):
        """
        AppSync returns `expires` as a Unix epoch SECOND count (an integer), not
        a datetime. Returns None when absent or unparseable.
        """
        if not expires:
            return None
        try:
            when = datetime.fromtimestamp(int(expires), tz=timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            return None
        return (when - datetime.now(timezone.utc)).days

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
