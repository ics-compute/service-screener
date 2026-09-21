from services.Evaluator import Evaluator


class ConfigCommon(Evaluator):
    """
    All 12 AWS Config checks.

    AWS Config has no per-resource fan-out: at most one customer-managed
    configuration recorder and one delivery channel exist per account per region.
    So this driver evaluates a single account/region-scoped subject, following the
    precedent set by services/cloudtrail/drivers/CloudtrailAccount.py.

    Input:
      detail -- dict produced by services/config/Config.py.getResources(). Keys:
        '_region', '_accountId', '_recorders', '_recorderStatus',
        '_deliveryChannels', '_configRules', '_compliance',
        '_retentionConfigurations', '_aggregators', '_nonCompliantRules',
        '_remediationConfigurations', '_keyResourceTypes'
      configClient -- boto3 config client (kept for future extension).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    ## recordingStrategy.useOnly values, per the AWS Config API.
    STRATEGY_ALL = 'ALL_SUPPORTED_RESOURCE_TYPES'
    STRATEGY_INCLUSION = 'INCLUSION_BY_RESOURCE_TYPES'
    STRATEGY_EXCLUSION = 'EXCLUSION_BY_RESOURCE_TYPES'

    ## Resource types that only exist globally. AWS Config records them in the
    ## recorder's home region only.
    GLOBAL_RESOURCE_TYPES = frozenset([
        'AWS::IAM::User',
        'AWS::IAM::Group',
        'AWS::IAM::Role',
        'AWS::IAM::Policy',
    ])

    ## How many names to name explicitly in a finding message before truncating.
    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, detail, configClient):
        super().__init__()
        self.detail = detail
        self.configClient = configClient

        ## Account/region-scoped subject; there is no per-resource name to use.
        self._resourceName = 'Account'

        self.recorders = detail.get('_recorders') or []
        self.recorderStatus = detail.get('_recorderStatus') or []
        self.deliveryChannels = detail.get('_deliveryChannels') or []
        self.configRules = detail.get('_configRules') or []
        self.compliance = detail.get('_compliance') or []
        self.retentionConfigurations = detail.get('_retentionConfigurations') or []
        self.aggregators = detail.get('_aggregators') or []
        self.nonCompliantRules = detail.get('_nonCompliantRules') or []
        self.remediationConfigurations = detail.get('_remediationConfigurations') or []
        self.keyResourceTypes = detail.get('_keyResourceTypes') or []

        ## The customer-managed recorder, if any. AWS permits only one per
        ## account per region, so index 0 is the whole story.
        self.recorder = self.recorders[0] if self.recorders else None
        self.recordingGroup = (self.recorder or {}).get('recordingGroup') or {}
        self.status = self.recorderStatus[0] if self.recorderStatus else None
        self.channel = self.deliveryChannels[0] if self.deliveryChannels else None

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('recorderName', (self.recorder or {}).get('name', 'None'))
        self.addII('recording', str((self.status or {}).get('recording', 'N/A')))
        self.addII('lastStatus', (self.status or {}).get('lastStatus', 'N/A'))
        self.addII('recordingStrategy', self._recordingStrategy() or 'N/A')
        self.addII('deliveryChannelName', (self.channel or {}).get('name', 'None'))
        self.addII('deliveryChannelS3Bucket',
                   (self.channel or {}).get('s3BucketName', 'None'))
        self.addII('configRuleCount', str(len(self.configRules)))
        self.addII('nonCompliantRuleCount', str(len(self.nonCompliantRules)))
        self.addII('aggregatorCount', str(len(self.aggregators)))
        self.addII('retentionConfigurationCount',
                   str(len(self.retentionConfigurations)))

    # ------------------------------------------------------------------ #
    # 1. Configuration recorder not enabled
    # ------------------------------------------------------------------ #
    def _checkConfigRecorderNotEnabled(self):
        if not self.recorders:
            self.results['configRecorderNotEnabled'] = [
                -1, "No AWS Config configuration recorder exists in this region"
            ]
            return

        name = self.recorder.get('name', 'unknown')
        if self.status is None:
            ## A recorder exists but the status API returned nothing — treat as
            ## not recording, because nothing proves that it is.
            self.results['configRecorderNotEnabled'] = [
                -1, f"Recorder '{name}' exists but no recorder status is reported"
            ]
            return

        if self.status.get('recording') is True:
            self.results['configRecorderNotEnabled'] = [
                1, f"Recorder '{name}' is recording"
            ]
        else:
            self.results['configRecorderNotEnabled'] = [
                -1, f"Recorder '{name}' exists but recording is stopped"
            ]

    # ------------------------------------------------------------------ #
    # 2. Recorder does not cover key resource types
    # ------------------------------------------------------------------ #
    def _checkConfigRecorderNotAllResources(self):
        """
        allSupported=True is the ideal. When it is False the recorder either
        lists an explicit inclusion set or an exclusion set, so compute what is
        EFFECTIVELY covered rather than reading allSupported alone — an
        exclusion-strategy recorder reports allSupported=False and an empty
        resourceTypes list while still recording almost everything.
        """
        if not self.recorders:
            self.results['configRecorderNotAllResources'] = [
                0, "No configuration recorder — see configRecorderNotEnabled"
            ]
            return

        strategy = self._recordingStrategy()

        if self.recordingGroup.get('allSupported') is True or \
                strategy == self.STRATEGY_ALL:
            self.results['configRecorderNotAllResources'] = [
                1, "Recorder records all supported resource types"
            ]
            return

        if strategy == self.STRATEGY_EXCLUSION:
            excluded = set(
                (self.recordingGroup.get('exclusionByResourceTypes') or {})
                .get('resourceTypes') or []
            )
            missing = [t for t in self.keyResourceTypes if t in excluded]
            if not missing:
                self.results['configRecorderNotAllResources'] = [
                    1,
                    "Exclusion strategy in use but no key resource type is excluded"
                    + (f" ({len(excluded)} type(s) excluded)" if excluded else "")
                ]
                return
            self.results['configRecorderNotAllResources'] = [
                -1,
                "Recorder excludes key resource type(s): "
                + self._joinNames(missing)
            ]
            return

        ## Inclusion strategy (or a legacy recorder with an explicit list).
        included = set(self.recordingGroup.get('resourceTypes') or [])
        missing = [t for t in self.keyResourceTypes if t not in included]
        if not missing:
            self.results['configRecorderNotAllResources'] = [
                1, "Recorder's inclusion list covers all key resource types"
            ]
            return

        self.results['configRecorderNotAllResources'] = [
            -1,
            f"allSupported=False and the inclusion list ({len(included)} type(s)) "
            f"omits key resource type(s): " + self._joinNames(missing)
        ]

    # ------------------------------------------------------------------ #
    # 3. Delivery channel missing
    # ------------------------------------------------------------------ #
    def _checkConfigDeliveryChannelMissing(self):
        if not self.deliveryChannels:
            self.results['configDeliveryChannelMissing'] = [
                -1,
                "No AWS Config delivery channel — configuration snapshots and "
                "history are not delivered to S3"
            ]
        else:
            self.results['configDeliveryChannelMissing'] = [
                1,
                "Delivery channel '{}' delivers to s3://{}".format(
                    self.channel.get('name', 'unknown'),
                    self.channel.get('s3BucketName', 'unknown'))
            ]

    # ------------------------------------------------------------------ #
    # 4. Delivery channel S3 objects not encrypted with a KMS key
    # ------------------------------------------------------------------ #
    def _checkConfigDeliveryChannelS3NotEncrypted(self):
        if not self.deliveryChannels:
            self.results['configDeliveryChannelS3NotEncrypted'] = [
                0, "No delivery channel — see configDeliveryChannelMissing"
            ]
            return

        kmsArn = self.channel.get('s3KmsKeyArn')
        if kmsArn:
            self.results['configDeliveryChannelS3NotEncrypted'] = [
                1, f"Delivery channel encrypts objects with {kmsArn}"
            ]
        else:
            self.results['configDeliveryChannelS3NotEncrypted'] = [
                -1,
                "Delivery channel '{}' has no s3KmsKeyArn — Config does not "
                "SSE-KMS encrypt the objects it writes".format(
                    self.channel.get('name', 'unknown'))
            ]

    # ------------------------------------------------------------------ #
    # 5. Delivery channel has no SNS topic
    # ------------------------------------------------------------------ #
    def _checkConfigDeliveryChannelSNSMissing(self):
        if not self.deliveryChannels:
            self.results['configDeliveryChannelSNSMissing'] = [
                0, "No delivery channel — see configDeliveryChannelMissing"
            ]
            return

        topic = self.channel.get('snsTopicARN')
        if topic:
            self.results['configDeliveryChannelSNSMissing'] = [
                1, f"Delivery channel notifies {topic}"
            ]
        else:
            self.results['configDeliveryChannelSNSMissing'] = [
                -1,
                "Delivery channel '{}' has no snsTopicARN — no notification is "
                "emitted on configuration or compliance change".format(
                    self.channel.get('name', 'unknown'))
            ]

    # ------------------------------------------------------------------ #
    # 6. Recorder last status is FAILURE
    # ------------------------------------------------------------------ #
    def _checkConfigRecorderLastStatusFailed(self):
        if self.status is None:
            self.results['configRecorderLastStatusFailed'] = [
                0, "No recorder status reported — see configRecorderNotEnabled"
            ]
            return

        lastStatus = self.status.get('lastStatus')
        if lastStatus == 'FAILURE':
            reason = self.status.get('lastErrorMessage') \
                or self.status.get('lastErrorCode') or 'no error detail reported'
            self.results['configRecorderLastStatusFailed'] = [
                -1,
                "Recorder '{}' lastStatus=FAILURE: {}".format(
                    self.status.get('name', 'unknown'), reason)
            ]
        elif lastStatus:
            self.results['configRecorderLastStatusFailed'] = [
                1, f"Recorder lastStatus={lastStatus}"
            ]
        else:
            self.results['configRecorderLastStatusFailed'] = [
                0, "Recorder has never reported a lastStatus"
            ]

    # ------------------------------------------------------------------ #
    # 7. No Config rules at all
    # ------------------------------------------------------------------ #
    def _checkConfigNoRules(self):
        if not self.configRules:
            self.results['configNoRules'] = [
                -1,
                "No AWS Config rules exist — recorded configuration is never "
                "evaluated against any compliance requirement"
            ]
        else:
            active = [
                r for r in self.configRules
                if r.get('ConfigRuleState', 'ACTIVE') == 'ACTIVE'
            ]
            if not active:
                self.results['configNoRules'] = [
                    -1,
                    f"{len(self.configRules)} Config rule(s) exist but none are "
                    "in the ACTIVE state"
                ]
            else:
                self.results['configNoRules'] = [
                    1, f"{len(active)} active Config rule(s)"
                ]

    # ------------------------------------------------------------------ #
    # 8. Rules reporting NON_COMPLIANT
    # ------------------------------------------------------------------ #
    def _checkConfigRulesNonCompliant(self):
        if not self.configRules:
            self.results['configRulesNonCompliant'] = [
                0, "No Config rules — see configNoRules"
            ]
            return

        if not self.compliance:
            self.results['configRulesNonCompliant'] = [
                0, "No compliance results reported yet for the existing rules"
            ]
            return

        if self.nonCompliantRules:
            self.results['configRulesNonCompliant'] = [
                -1,
                "{} of {} evaluated rule(s) are NON_COMPLIANT: {}".format(
                    len(self.nonCompliantRules), len(self.compliance),
                    self._joinNames(self.nonCompliantRules))
            ]
        else:
            self.results['configRulesNonCompliant'] = [
                1, f"No NON_COMPLIANT rule among {len(self.compliance)} evaluated"
            ]

    # ------------------------------------------------------------------ #
    # 9. No retention configuration
    # ------------------------------------------------------------------ #
    def _checkConfigNoRetentionPolicy(self):
        if not self.retentionConfigurations:
            self.results['configNoRetentionPolicy'] = [
                -1,
                "No retention configuration — configuration item history falls "
                "back to the AWS default and the retention period is not "
                "explicitly governed"
            ]
        else:
            entry = self.retentionConfigurations[0]
            self.results['configNoRetentionPolicy'] = [
                1,
                "Retention configuration '{}' keeps history for {} day(s)".format(
                    entry.get('Name', 'default'),
                    entry.get('RetentionPeriodInDays', 'unknown'))
            ]

    # ------------------------------------------------------------------ #
    # 10. No configuration aggregator
    # ------------------------------------------------------------------ #
    def _checkConfigAggregatorMissing(self):
        if not self.aggregators:
            self.results['configAggregatorMissing'] = [
                -1,
                "No configuration aggregator — there is no single pane of glass "
                "across regions or accounts for Config data"
            ]
        else:
            names = [
                a.get('ConfigurationAggregatorName', 'unknown')
                for a in self.aggregators
            ]
            self.results['configAggregatorMissing'] = [
                1,
                f"{len(self.aggregators)} aggregator(s): " + self._joinNames(names)
            ]

    # ------------------------------------------------------------------ #
    # 11. Non-compliant rules have no automatic remediation
    # ------------------------------------------------------------------ #
    def _checkConfigNoRemediationActions(self):
        if not self.nonCompliantRules:
            ## Nothing is failing, so a missing remediation action is not a
            ## finding — the check is scoped to non-compliant rules.
            self.results['configNoRemediationActions'] = [
                0, "No NON_COMPLIANT rule — remediation actions not applicable"
            ]
            return

        remediated = set(
            r.get('ConfigRuleName')
            for r in self.remediationConfigurations
            if r.get('ConfigRuleName')
        )
        missing = [r for r in self.nonCompliantRules if r not in remediated]

        if not missing:
            self.results['configNoRemediationActions'] = [
                1,
                f"All {len(self.nonCompliantRules)} NON_COMPLIANT rule(s) have a "
                "remediation configuration"
            ]
            return

        self.results['configNoRemediationActions'] = [
            -1,
            "{} of {} NON_COMPLIANT rule(s) have no remediation configuration: "
            "{}".format(len(missing), len(self.nonCompliantRules),
                        self._joinNames(missing))
        ]

    # ------------------------------------------------------------------ #
    # 12. Global (IAM) resource types not recorded
    # ------------------------------------------------------------------ #
    def _checkConfigRecorderExcludesGlobalResources(self):
        """
        includeGlobalResourceTypes is deprecated by AWS in favour of
        recordingStrategy, and it is REQUIRED to be false when the exclusion
        strategy is used — so reading that flag alone would raise a false
        positive on every exclusion-strategy recorder. Determine instead whether
        the global IAM resource types are effectively recorded.
        """
        if not self.recorders:
            self.results['configRecorderExcludesGlobalResources'] = [
                0, "No configuration recorder — see configRecorderNotEnabled"
            ]
            return

        strategy = self._recordingStrategy()
        includeGlobal = self.recordingGroup.get('includeGlobalResourceTypes')

        if strategy == self.STRATEGY_EXCLUSION:
            excluded = set(
                (self.recordingGroup.get('exclusionByResourceTypes') or {})
                .get('resourceTypes') or []
            )
            excludedGlobal = sorted(self.GLOBAL_RESOURCE_TYPES & excluded)
            if excludedGlobal:
                self.results['configRecorderExcludesGlobalResources'] = [
                    -1,
                    "Recorder's exclusion list excludes global resource type(s): "
                    + self._joinNames(excludedGlobal)
                ]
            else:
                self.results['configRecorderExcludesGlobalResources'] = [
                    1,
                    "Exclusion strategy in use and no global resource type is "
                    "excluded"
                ]
            return

        if strategy == self.STRATEGY_INCLUSION or \
                (self.recordingGroup.get('allSupported') is not True
                 and self.recordingGroup.get('resourceTypes')):
            included = set(self.recordingGroup.get('resourceTypes') or [])
            missingGlobal = sorted(self.GLOBAL_RESOURCE_TYPES - included)
            if missingGlobal:
                self.results['configRecorderExcludesGlobalResources'] = [
                    -1,
                    "Recorder's inclusion list omits global resource type(s): "
                    + self._joinNames(missingGlobal)
                ]
            else:
                self.results['configRecorderExcludesGlobalResources'] = [
                    1, "Recorder's inclusion list covers the global resource types"
                ]
            return

        ## allSupported / ALL_SUPPORTED_RESOURCE_TYPES: the deprecated flag is
        ## the only signal available and it is authoritative in this mode.
        if includeGlobal is True:
            self.results['configRecorderExcludesGlobalResources'] = [
                1, "Recorder records global resource types"
            ]
        else:
            self.results['configRecorderExcludesGlobalResources'] = [
                -1,
                "Recorder has includeGlobalResourceTypes=False — IAM users, "
                "groups, roles and policies are not recorded"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _recordingStrategy(self):
        return (self.recordingGroup.get('recordingStrategy') or {}).get('useOnly')

    def _joinNames(self, names):
        shown = ', '.join(names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
