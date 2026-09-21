from services.Evaluator import Evaluator


class EventbridgeRule(Evaluator):
    """
    Per-rule EventBridge checks (5 of the 14).

      ebRuleDisabled
      ebRuleNoTargets
      ebRuleNoDeadLetterQueue
      ebRuleNoRetryPolicy
      ebRuleNoDescription

    AWS-managed rules (ManagedBy set, e.g. autoscaling.amazonaws.com) are
    created and owned by another AWS service. The customer cannot edit their
    targets, DLQ, retry policy or description, so those checks report INFO
    rather than an unactionable FAIL. State is still evaluated, because a
    managed rule being disabled is a real signal.

    Input:
      rule -- dict from Eventbridge._listRules: a list_rules entry plus
              '_busName' and '_targets'.
      bus  -- the parent bus descriptor, for context in messages.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    MAX_NAMES_IN_MESSAGE = 5

    ## Target types that cannot accept a DeadLetterConfig or RetryPolicy. Events
    ## delivered to these are handled synchronously by EventBridge or forwarded
    ## to another bus that carries its own failure handling, so demanding a DLQ
    ## on them would be a false positive.
    ##
    ## Derived from the ARN service segment (parts[2]).
    NO_DLQ_SUPPORT_SERVICES = frozenset([
        'events',       # bus-to-bus forwarding
        'autoscaling',  # managed service principal targets
    ])

    def __init__(self, rule, bus, ebClient):
        super().__init__()
        self.rule = rule
        self.bus = bus
        self.ebClient = ebClient

        self.name = rule.get('Name', 'unknown')
        self.busName = rule.get('_busName', bus.get('_name', 'unknown'))
        ## Bus-qualified so two same-named rules on different buses stay distinct.
        self._resourceName = f"{self.busName}/{self.name}"

        self.state = rule.get('State')
        self.description = rule.get('Description')
        self.managedBy = rule.get('ManagedBy')
        self.targets = rule.get('_targets') or []

        self.addII('ruleName', self.name)
        self.addII('busName', self.busName)
        self.addII('state', self.state or 'N/A')
        self.addII('managedBy', self.managedBy or 'customer')
        self.addII('targetCount', str(len(self.targets)))
        self.addII('scheduleExpression', rule.get('ScheduleExpression') or 'N/A')
        self.addII('hasEventPattern', str(bool(rule.get('EventPattern'))))

    # ------------------------------------------------------------------ #
    # 1. Rule is disabled
    # ------------------------------------------------------------------ #
    def _checkEbRuleDisabled(self):
        """
        Evaluated for managed rules too: a disabled managed rule means the
        owning AWS service is silently not receiving its events.
        """
        if self.state == 'ENABLED':
            self.results['ebRuleDisabled'] = [
                1, f"Rule '{self.name}' is ENABLED"
            ]
        elif self.state == 'DISABLED':
            owner = f" (managed by {self.managedBy})" if self.managedBy else ""
            self.results['ebRuleDisabled'] = [
                -1,
                f"Rule '{self.name}' is DISABLED{owner} — it matches no events, "
                "so whatever it was created to trigger never runs"
            ]
        else:
            self.results['ebRuleDisabled'] = [
                0, f"Rule '{self.name}' reports an unrecognised state: {self.state}"
            ]

    # ------------------------------------------------------------------ #
    # 2. Rule has no targets
    # ------------------------------------------------------------------ #
    def _checkEbRuleNoTargets(self):
        if self.targets:
            self.results['ebRuleNoTargets'] = [
                1, f"Rule '{self.name}' has {len(self.targets)} target(s)"
            ]
        else:
            self.results['ebRuleNoTargets'] = [
                -1,
                f"Rule '{self.name}' has no targets — matching events are "
                "evaluated and then discarded, so the rule does nothing"
            ]

    # ------------------------------------------------------------------ #
    # 3. Targets have no dead letter queue
    # ------------------------------------------------------------------ #
    def _checkEbRuleNoDeadLetterQueue(self):
        if self.managedBy:
            self.results['ebRuleNoDeadLetterQueue'] = [
                0,
                f"Rule '{self.name}' is managed by {self.managedBy} — its target "
                "configuration is not customer editable"
            ]
            return

        if not self.targets:
            self.results['ebRuleNoDeadLetterQueue'] = [
                0, f"Rule '{self.name}' has no targets — see ebRuleNoTargets"
            ]
            return

        eligible, missing = [], []
        for target in self.targets:
            if not self._supportsFailureHandling(target):
                continue
            eligible.append(target)
            if not (target.get('DeadLetterConfig') or {}).get('Arn'):
                missing.append(target.get('Id', '?'))

        if not eligible:
            self.results['ebRuleNoDeadLetterQueue'] = [
                0,
                f"Rule '{self.name}' has no target that supports a dead letter "
                "queue"
            ]
            return

        if missing:
            self.results['ebRuleNoDeadLetterQueue'] = [
                -1,
                "{} of {} target(s) on rule '{}' have no DeadLetterConfig — an "
                "event that cannot be delivered after all retries is lost with "
                "no record: {}".format(len(missing), len(eligible), self.name,
                                       self._joinNames(missing))
            ]
        else:
            self.results['ebRuleNoDeadLetterQueue'] = [
                1,
                f"All {len(eligible)} eligible target(s) on rule '{self.name}' "
                "have a dead letter queue"
            ]

    # ------------------------------------------------------------------ #
    # 4. Targets rely on the default retry policy
    # ------------------------------------------------------------------ #
    def _checkEbRuleNoRetryPolicy(self):
        """
        With no RetryPolicy, EventBridge applies its default of up to 185
        attempts over 24 hours. That is rarely what a caller wants: a failing
        target keeps being retried for a full day. An explicit policy is the
        signal that the retry behaviour was actually considered.
        """
        if self.managedBy:
            self.results['ebRuleNoRetryPolicy'] = [
                0,
                f"Rule '{self.name}' is managed by {self.managedBy} — its target "
                "configuration is not customer editable"
            ]
            return

        if not self.targets:
            self.results['ebRuleNoRetryPolicy'] = [
                0, f"Rule '{self.name}' has no targets — see ebRuleNoTargets"
            ]
            return

        eligible, missing = [], []
        for target in self.targets:
            if not self._supportsFailureHandling(target):
                continue
            eligible.append(target)
            retry = target.get('RetryPolicy') or {}
            ## Either field being set proves the policy was configured
            ## deliberately rather than inherited.
            if retry.get('MaximumRetryAttempts') is None and \
                    retry.get('MaximumEventAgeInSeconds') is None:
                missing.append(target.get('Id', '?'))

        if not eligible:
            self.results['ebRuleNoRetryPolicy'] = [
                0,
                f"Rule '{self.name}' has no target that supports a retry policy"
            ]
            return

        if missing:
            self.results['ebRuleNoRetryPolicy'] = [
                -1,
                "{} of {} target(s) on rule '{}' have no explicit RetryPolicy — "
                "EventBridge falls back to its default of up to 185 attempts "
                "over 24 hours: {}".format(len(missing), len(eligible), self.name,
                                           self._joinNames(missing))
            ]
        else:
            self.results['ebRuleNoRetryPolicy'] = [
                1,
                f"All {len(eligible)} eligible target(s) on rule '{self.name}' "
                "set an explicit retry policy"
            ]

    # ------------------------------------------------------------------ #
    # 5. Rule has no description
    # ------------------------------------------------------------------ #
    def _checkEbRuleNoDescription(self):
        if self.managedBy:
            self.results['ebRuleNoDescription'] = [
                0,
                f"Rule '{self.name}' is managed by {self.managedBy} — its "
                "description is not customer editable"
            ]
            return

        if self.description and self.description.strip():
            self.results['ebRuleNoDescription'] = [
                1,
                f"Rule '{self.name}' has a description "
                f"({len(self.description)} chars)"
            ]
        else:
            self.results['ebRuleNoDescription'] = [
                -1,
                f"Rule '{self.name}' has no description — its event pattern is "
                "the only record of what it is for"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _supportsFailureHandling(self, target):
        """
        Whether a DeadLetterConfig / RetryPolicy is meaningful for this target.
        Bus-to-bus and managed service principal targets do not support them.
        """
        arn = target.get('Arn')
        if not arn or not isinstance(arn, str):
            return False
        parts = arn.split(':')
        if len(parts) < 3:
            return False
        return parts[2] not in self.NO_DLQ_SUPPORT_SERVICES

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
