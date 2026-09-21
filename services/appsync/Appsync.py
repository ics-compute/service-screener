import botocore

from utils.Tools import _pi
from services.Service import Service

from services.appsync.drivers.AppsyncApi import AppsyncApi


class Appsync(Service):
    """
    AWS AppSync service scanner.

    Discovery: list_graphql_apis (paginated). The list response already contains
    every field the checks read, so get_graphql_api per API is not needed --
    verified against the botocore model: logConfig, authenticationType,
    additionalAuthenticationProviders, introspectionConfig, queryDepthLimit,
    resolverCountLimit, wafWebAclArn, xrayEnabled, visibility and tags are all
    present on the list entry.

    Hydration calls (all read-only):
      - list_graphql_apis
      - list_api_keys      (per API, for key expiry checks)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.asClient = ssBoto.client('appsync', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        apis = []
        try:
            paginator = self.asClient.get_paginator('list_graphql_apis')
            for page in paginator.paginate():
                for api in page.get('graphqlApis', []) or []:
                    if not api.get('apiId'):
                        continue

                    ## AppSync returns tags as a {key: value} MAP, not a list of
                    ## Key/Value dicts. Normalise for the shared tag filter.
                    tags = self._normaliseTags(api.get('tags') or {})
                    if self.tags and not self.resourceHasTags(tags):
                        continue

                    api['_tags'] = tags
                    api['_region'] = self.region
                    api['_apiKeys'] = self._listApiKeys(api['apiId'],
                                                        api.get('name', ''))
                    _pi('Appsync', f"GraphQL API: {api.get('name', api['apiId'])}")
                    apis.append(api)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_graphql_apis', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"AppSync not available in region {self.region}: {e}")
        except botocore.exceptions.OperationNotPageableError:
            try:
                resp = self.asClient.list_graphql_apis()
                for api in resp.get('graphqlApis', []) or []:
                    if api.get('apiId'):
                        api['_tags'] = self._normaliseTags(api.get('tags') or {})
                        api['_region'] = self.region
                        api['_apiKeys'] = self._listApiKeys(
                            api['apiId'], api.get('name', ''))
                        apis.append(api)
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_graphql_apis', e)
        return apis

    def _listApiKeys(self, apiId, name):
        try:
            resp = self.asClient.list_api_keys(apiId=apiId)
            return resp.get('apiKeys', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('NotFoundException',):
                return []
            self._logClientError(f'list_api_keys({name or apiId})', e)
            return []

    def _normaliseTags(self, tags):
        """AppSync tags are a {key: value} map; convert to Key/Value dicts."""
        if isinstance(tags, dict):
            return [{'Key': k, 'Value': v} for k, v in tags.items()]
        return []

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for api in self.getResources():
            name = api.get('name') or api.get('apiId', 'unknown')
            try:
                _pi('Appsync', f"Analyzing API: {name}")
                obj = AppsyncApi(api, self.asClient)
                obj.run(self.__class__)
                objs[f"AppSync API::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing AppSync API {name}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Appsync {where}: {code} - {msg}")
