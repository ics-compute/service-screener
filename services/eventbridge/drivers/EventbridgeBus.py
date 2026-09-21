import json

from services.Evaluator import Evaluator


class EventbridgeBus(Evaluator):
    """
    Per-event-bus EventBridge checks (4 of the 14).

      ebBusNoEncryption
      ebBusPublicPolicy
      ebBusNoTags
      ebRuleTargetCrossAccountNoCondition

    The cross-account check lives here rather than in EventbridgeRule because
    the condition it looks for is written on the BUS policy, not the rule, and
    judging it needs every rule's targets at once.

    Input:
      bus -- dict from services/eventbridge/Eventbridge.py._describeBus. Keys:
        '_name', '_arn', '_tags', '_isDefault', '_currentAccount', '_region',
        '_rules', plus the describe_event_bus response ('KmsKeyIdentifier',
        'Policy', ...).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    ## Condition keys that adequately constrain a cross-account or wildcard
    ## principal. aws:PrincipalOrgID is the canonical one; the others bound the
    ## caller to a known account, org path or source.
    SCOPING_CONDITION_KEYS = frozenset([
        'aws:principalorgid',
        'aws:principalorgpaths',
        'aws:sourcearn',
        'aws:sourceaccount',
        'aws:sourceowner',
        'aws:principalaccount',
        'aws:principalarn',
    ])

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, bus, ebClient):
        super().__init__()
        self.bus = bus
        self.ebClient = ebClient

        self.name = bus.get('_name', 'unknown')
        self._resourceName = self.name

        self.arn = bus.get('_arn', '')
        self.tags = bus.get('_tags') or []
        self.isDefault = bool(bus.get('_isDefault'))
        self.currentAccount = bus.get('_currentAccount')
        self.rules = bus.get('_rules') or []
        self.kmsKeyIdentifier = bus.get('KmsKeyIdentifier')
        self.policyDoc = self._parsePolicy(bus.get('Policy'))

        self.addII('busName', self.name)
        self.addII('region', bus.get('_region', 'N/A'))
        self.addII('isDefaultBus', str(self.isDefault))
        self.addII('kmsKeyIdentifier', self.kmsKeyIdentifier or 'None (AWS-owned)')
        self.addII('hasResourcePolicy', str(self.policyDoc is not None))
        self.addII('ruleCount', str(len(self.rules)))
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # 1. Bus not encrypted with a customer managed KMS key
    # ------------------------------------------------------------------ #
    def _checkEbBusNoEncryption(self):
        """
        An event bus with no KmsKeyIdentifier is still encrypted, but with an
        AWS-owned key the customer cannot audit, rotate or revoke. Reported as
        a finding on every bus including default, because the default bus does
        support a CMK.
        """
        if self.kmsKeyIdentifier:
            self.results['ebBusNoEncryption'] = [
                1, f"Bus '{self.name}' is encrypted with {self.kmsKeyIdentifier}"
            ]
        else:
            self.results['ebBusNoEncryption'] = [
                -1,
                f"Bus '{self.name}' has no KmsKeyIdentifier — events at rest are "
                "encrypted with an AWS-owned key that cannot be audited or rotated "
                "by the account"
            ]

    # ------------------------------------------------------------------ #
    # 2. Bus resource policy allows a wildcard principal
    # ------------------------------------------------------------------ #
    def _checkEbBusPublicPolicy(self):
        if self.policyDoc is None:
            ## No resource policy means no cross-account access is granted at
            ## all, which is the safe state rather than a finding.
            self.results['ebBusPublicPolicy'] = [
                1, f"Bus '{self.name}' has no resource policy — no external access"
            ]
            return

        offending = []
        for stmt in self._statements(self.policyDoc):
            if stmt.get('Effect') != 'Allow':
                continue
            if not self._hasWildcardPrincipal(stmt.get('Principal')):
                continue
            ## A wildcard principal that is scoped by a condition (org ID,
            ## source ARN) is the documented pattern for org-wide buses and is
            ## not public.
            if self._hasScopingCondition(stmt.get('Condition')):
                continue
            offending.append(stmt.get('Sid') or '(unnamed statement)')

        if offending:
            self.results['ebBusPublicPolicy'] = [
                -1,
                f"Bus '{self.name}' policy allows Principal '*' with no scoping "
                "condition in statement(s): " + self._joinNames(offending)
                + " — any AWS account can put events onto this bus"
            ]
        else:
            self.results['ebBusPublicPolicy'] = [
                1,
                f"Bus '{self.name}' policy grants no unconditional wildcard access"
            ]

    # ------------------------------------------------------------------ #
    # 3. Bus has no tags
    # ------------------------------------------------------------------ #
    def _checkEbBusNoTags(self):
        if self.isDefault:
            ## The default bus is created by AWS and cannot be tagged in some
            ## regions; flagging it produces noise the customer cannot action.
            self.results['ebBusNoTags'] = [
                0, "Default event bus — tagging not evaluated"
            ]
            return

        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['ebBusNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['ebBusNoTags'] = [
                -1,
                f"Bus '{self.name}' has no tags — it cannot be attributed to an "
                "owner, environment or cost centre"
            ]

    # ------------------------------------------------------------------ #
    # 4. Cross-account rule target with no scoping condition on the bus policy
    # ------------------------------------------------------------------ #
    def _checkEbRuleTargetCrossAccountNoCondition(self):
        """
        A rule that forwards events to a resource in another account is only
        safe when the bus policy constrains who may interact with it. Without
        the account ID from STS there is nothing to compare target ARNs
        against, so the check reports INFO rather than guessing.
        """
        if not self.currentAccount:
            self.results['ebRuleTargetCrossAccountNoCondition'] = [
                0, "Current account ID unavailable — cross-account targets not evaluated"
            ]
            return

        if not self.rules:
            self.results['ebRuleTargetCrossAccountNoCondition'] = [
                0, f"Bus '{self.name}' has no rules"
            ]
            return

        crossAccount = []
        for rule in self.rules:
            ruleName = rule.get('Name', 'unknown')
            for target in rule.get('_targets') or []:
                account = self._accountFromArn(target.get('Arn'))
                if account and account != self.currentAccount:
                    crossAccount.append(f"{ruleName} -> {account}")

        if not crossAccount:
            self.results['ebRuleTargetCrossAccountNoCondition'] = [
                1, f"No rule on bus '{self.name}' targets another account"
            ]
            return

        ## Cross-account targets exist. They are acceptable when the bus policy
        ## scopes access; a bus with no policy at all leaves the trust
        ## relationship undocumented in the resource itself.
        if self.policyDoc is not None and self._anyStatementScoped(self.policyDoc):
            self.results['ebRuleTargetCrossAccountNoCondition'] = [
                1,
                f"{len(crossAccount)} cross-account target(s) on bus "
                f"'{self.name}', and the bus policy scopes access with an "
                "explicit condition"
            ]
            return

        self.results['ebRuleTargetCrossAccountNoCondition'] = [
            -1,
            f"{len(crossAccount)} rule target(s) on bus '{self.name}' cross an "
            "account boundary with no scoping condition on the bus policy: "
            + self._joinNames(crossAccount)
        ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _parsePolicy(self, policy):
        """describe_event_bus returns Policy as a JSON string, or omits it."""
        if not policy:
            return None
        if isinstance(policy, dict):
            return policy
        try:
            return json.loads(policy)
        except (ValueError, TypeError):
            return None

    def _statements(self, policyDoc):
        statements = policyDoc.get('Statement')
        if isinstance(statements, dict):
            return [statements]
        if isinstance(statements, list):
            return [s for s in statements if isinstance(s, dict)]
        return []

    def _hasWildcardPrincipal(self, principal):
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for value in principal.values():
                if value == '*':
                    return True
                if isinstance(value, list) and '*' in value:
                    return True
        return False

    def _hasScopingCondition(self, condition):
        if not isinstance(condition, dict):
            return False
        for operatorBlock in condition.values():
            if not isinstance(operatorBlock, dict):
                continue
            for key in operatorBlock:
                if str(key).lower() in self.SCOPING_CONDITION_KEYS:
                    return True
        return False

    def _anyStatementScoped(self, policyDoc):
        for stmt in self._statements(policyDoc):
            if stmt.get('Effect') != 'Allow':
                continue
            if self._hasScopingCondition(stmt.get('Condition')):
                return True
        return False

    def _accountFromArn(self, arn):
        """
        Return the account field of an ARN, or None when it is absent. Some
        service principals emit ARNs with an empty account segment (for example
        arn:aws:autoscaling:region:::), which must not be read as cross-account.
        """
        if not arn or not isinstance(arn, str):
            return None
        parts = arn.split(':')
        if len(parts) < 5:
            return None
        account = parts[4].strip()
        return account or None

    def _joinNames(self, names):
        shown = ', '.join(names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
