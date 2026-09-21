# AppSync Simulation Testing

Creates one intentionally-misconfigured GraphQL API.

## Resources Created

| Resource | Configuration | Directly Validates |
|---|---|---|
| GraphQL API `ss-test-appsync-*` | `authenticationType=API_KEY` only, introspection enabled (default), no WAF, no query-depth or resolver-count limit, no log config, X-Ray off, no tags | 9 checks — see below |
| API key (364-day expiry) | Longest lifetime AppSync permits | `appsyncApiKeyNoExpiry` boundary |

## Coverage

Verified against a test account in `ap-southeast-1` — **9 of 11 FAIL**:

| Check | Simulated? |
|---|---|
| `appsyncNoAuthentication` | ✓ FAIL (API_KEY only) |
| `appsyncIntrospectionEnabled` | ✓ FAIL |
| `appsyncWafNotAssociated` | ✓ FAIL |
| `appsyncNoQueryDepthLimit` | ✓ FAIL |
| `appsyncNoResolverCountLimit` | ✓ FAIL |
| `appsyncFieldLevelLogging` | ✓ FAIL |
| `appsyncCloudWatchLogsNotEnabled` | ✓ FAIL |
| `appsyncXrayTracingDisabled` | ✓ FAIL |
| `appsyncNoTags` | ✓ FAIL |
| `appsyncApiKeyNoExpiry` | ✗ PASS at 364 days — the threshold is >365 and AppSync **caps key lifetime at 365 days**, so the FAIL branch is only reachable for a key with no expiry at all, which the current API does not allow |
| `appsyncApiKeyExpiringSoon` | ✗ AppSync enforces a 1-day minimum key lifetime and the check window is 7 days, so a new key cannot start inside the window — would need a 7-day wait |

## Usage

```bash
cd services/appsync/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
cd ../../.. && python3 main.py --regions ap-southeast-1 --services appsync --beta 1 --sequential 1
cd services/appsync/simulation && ./cleanup_test_resources.sh --force
```

## Cost

Zero at rest. AppSync bills per query and per real-time message; the fixture API
is never queried. Note the API has **no schema**, which is fine — every check
reads API configuration, not the schema.

## Safety

Cleanup deletes only the API IDs recorded in the manifest.
