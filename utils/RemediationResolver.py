import re

## Resolves the placeholders in reporter.json `remediation` commands against the
## identifier strings the Reporter already tracks per finding.
##
## Placeholders are documented in docs/RemediationEnrichmentInstructions.md:
##   {ResourceArn} {ResourceId} {ResourceName} {Region} {AccountId}
##
## The identifiers come from each service's advise(), so their shape is per
## service rather than uniform. Every shape observed in a real full-account scan:
##
##   Bucket::my-bucket                    prefix::name        (most common)
##   Ecs::Cluster::default                prefix::type::name
##   Route53::HostedZone=example.com      prefix::key=value
##   ACM::arn:aws:acm:...:certificate/x   prefix::arn
##   61900f07-b52b-4a4f-...               bare (kms key ids)
##
## Anything unresolvable is deliberately LEFT AS THE LITERAL PLACEHOLDER rather
## than blanked or guessed: a visible `{ResourceArn}` tells the operator "fill
## this in", whereas a silently-empty flag would produce a command that looks
## runnable but is wrong. See resolve() for the full contract.

PLACEHOLDER_RE = re.compile(r'\{(ResourceArn|ResourceId|ResourceName|Region|AccountId)\}')

## Identifiers whose trailing segment is a label for an account/region-wide
## finding, not a resource. Substituting these would produce a command aimed at
## a resource literally named "General" or "Account".
AGGREGATE_SEGMENTS = frozenset(['general', 'account'])

## Services whose ARN is `arn:{partition}:{service}:{region}:{account}:{name}`,
## i.e. the resource part is the bare name with no type prefix. Only these can
## have an ARN derived from a name; anything else (a type/name or type:name
## layout) would need per-resource knowledge the scanner does not record, so it
## stays unresolved rather than being guessed.
##
## Keyed by the reporter service directory name.
FLAT_ARN_SERVICES = {
    'sns': 'sns',
    'sqs': 'sqs',
}

## Services whose ARN carries a `{type}/{name}` resource part that is fixed for
## every resource the scanner reports, so it is safely derivable.
TYPED_ARN_SERVICES = {
    'stepfunctions': ('states', 'stateMachine'),
}


def arnResourceName(arn):
    """
    Pull the resource name out of an ARN.

    The resource part is everything after the fifth colon, and it may be
    `name`, `type/name` or `type:name` depending on the service - so an SNS
    topic arn ends `:mytopic` while an ACM one ends `/54b2f94a`. Splitting on
    only one of the two separators silently returns the whole resource part.
    """
    parts = arn.split(':', 5)
    if len(parts) < 6:
        return None

    resource = parts[5]
    for separator in ('/', ':'):
        if separator in resource:
            resource = resource.rsplit(separator, 1)[-1]

    return resource or None


def splitIdentifier(identifier):
    """
    Split a Reporter identifier into (name, arn).

    Returns (None, None) when the identifier names no single resource - either
    it is an aggregate label such as `Cloudtrail::General`, or it is empty.
    """
    if not identifier or not isinstance(identifier, str):
        return None, None

    ## Full ARN, with or without a display prefix.
    if identifier.startswith('arn:'):
        return arnResourceName(identifier), identifier

    if '::arn:' in identifier:
        arn = identifier.split('::', 1)[1]
        return arnResourceName(arn), arn

    ## Take the last :: segment, so `Ecs::Cluster::default` yields `default`.
    tail = identifier.rsplit('::', 1)[-1] if '::' in identifier else identifier

    ## `HostedZone=example.com` -> `example.com`
    if '=' in tail:
        tail = tail.split('=', 1)[1]

    if not tail or tail.lower() in AGGREGATE_SEGMENTS:
        return None, None

    return tail, None


def buildArn(service, name, region, accountId, partition='aws'):
    """
    Derive an ARN from a resource name, for the services where the ARN layout is
    fixed and therefore safe to construct. Returns None otherwise.
    """
    if not name or not region or not accountId:
        return None

    if service in FLAT_ARN_SERVICES:
        return 'arn:{}:{}:{}:{}:{}'.format(
            partition, FLAT_ARN_SERVICES[service], region, accountId, name)

    if service in TYPED_ARN_SERVICES:
        awsService, resourceType = TYPED_ARN_SERVICES[service]
        return 'arn:{}:{}:{}:{}:{}/{}'.format(
            partition, awsService, region, accountId, resourceType, name)

    return None


def buildQueueUrl(name, region, accountId):
    """
    SQS commands take --queue-url, not a name or an ARN, and the URL is fully
    determined by region/account/name.
    """
    if not name or not region or not accountId:
        return None

    return 'https://sqs.{}.amazonaws.com/{}/{}'.format(region, accountId, name)


def resolve(command, identifier, region=None, accountId=None, service=None):
    """
    Substitute placeholders in a remediation command for one affected resource.

    Unresolvable placeholders are left verbatim. That is deliberate: the
    reporter data declares which identifier belongs in each slot, and where the
    scanner cannot supply it, a visible {ResourceArn} tells the operator to fill
    it in - whereas substituting a bare name into --topic-arn would produce a
    command that looks runnable and fails.

    `service` is the reporter service directory name. When given, ARNs and SQS
    queue URLs are derived for the services whose layout is fixed.

    Returns (resolvedCommand, unresolvedPlaceholders).
    """
    if not command:
        return '', []

    name, arn = splitIdentifier(identifier)

    if arn is None and service:
        arn = buildArn(service, name, region, accountId)

    ## SQS is the one service whose commands take neither a name nor an ARN.
    resourceId = name
    if service == 'sqs':
        resourceId = buildQueueUrl(name, region, accountId) or name

    values = {
        'ResourceName': name,
        'ResourceId': resourceId,
        'ResourceArn': arn,
        'Region': region,
        'AccountId': accountId,
    }

    unresolved = []

    def sub(match):
        key = match.group(1)
        value = values.get(key)
        if value:
            return value
        unresolved.append(key)
        return match.group(0)

    return PLACEHOLDER_RE.sub(sub, command), unresolved


def placeholdersIn(command):
    """List the distinct placeholders a command uses, in first-appearance order."""
    if not command:
        return []

    seen = []
    for name in PLACEHOLDER_RE.findall(command):
        if name not in seen:
            seen.append(name)

    return seen
