from services.Evaluator import Evaluator


class SsmManagedInstance(Evaluator):
    """
    Per-managed-instance SSM checks (4 of the 14).

      ssmManagedInstanceNotPatched
      ssmManagedInstanceOldAgent
      ssmManagedInstanceNotOnline
      ssmInventoryNotConfigured

    Input:
      inst -- dict from services/ssm/Ssm.py._describeInstances: a
        describe_instance_information entry plus '_patchState',
        '_inventoryEntryCount' and '_region'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    def __init__(self, inst, ssmClient):
        super().__init__()
        self.inst = inst
        self.ssmClient = ssmClient

        self.instanceId = inst.get('InstanceId', 'unknown')
        self._resourceName = self.instanceId

        self.pingStatus = inst.get('PingStatus')
        self.agentVersion = inst.get('AgentVersion')
        self.isLatestVersion = inst.get('IsLatestVersion')
        self.patchState = inst.get('_patchState')
        self.inventoryEntryCount = inst.get('_inventoryEntryCount')

        self.addII('instanceId', self.instanceId)
        self.addII('region', inst.get('_region', 'N/A'))
        self.addII('pingStatus', self.pingStatus or 'N/A')
        self.addII('agentVersion', self.agentVersion or 'N/A')
        self.addII('platformType', inst.get('PlatformType') or 'N/A')
        self.addII('platformName', inst.get('PlatformName') or 'N/A')
        self.addII('platformVersion', str(inst.get('PlatformVersion') or 'N/A'))
        self.addII('resourceType', inst.get('ResourceType') or 'N/A')
        self.addII('hasPatchState', str(self.patchState is not None))

    # ------------------------------------------------------------------ #
    # 1. Missing critical or security patches
    # ------------------------------------------------------------------ #
    def _checkSsmManagedInstanceNotPatched(self):
        """
        Patch Manager reports both a raw MissingCount and the compliance-graded
        CriticalNonCompliantCount / SecurityNonCompliantCount. The graded counts
        are what matter: MissingCount alone includes patches the instance's
        baseline deliberately does not approve yet.
        """
        if self.patchState is None:
            self.results['ssmManagedInstanceNotPatched'] = [
                0,
                f"Instance {self.instanceId} reports no patch state — Patch "
                "Manager has never scanned it, so its patch posture is unknown"
            ]
            return

        critical = self.patchState.get('CriticalNonCompliantCount') or 0
        security = self.patchState.get('SecurityNonCompliantCount') or 0
        missing = self.patchState.get('MissingCount') or 0
        group = self.patchState.get('PatchGroup', 'unknown')

        if critical or security:
            self.results['ssmManagedInstanceNotPatched'] = [
                -1,
                "Instance {} is non-compliant with patch group '{}': {} critical "
                "and {} security patch(es) are missing"
                .format(self.instanceId, group, critical, security)
            ]
            return

        if missing:
            ## Missing but not graded critical/security: real, but a much weaker
            ## signal, so it is reported as INFO rather than a finding.
            self.results['ssmManagedInstanceNotPatched'] = [
                0,
                "Instance {} has {} missing patch(es) in group '{}', none graded "
                "critical or security".format(self.instanceId, missing, group)
            ]
            return

        self.results['ssmManagedInstanceNotPatched'] = [
            1,
            f"Instance {self.instanceId} is patch compliant in group '{group}'"
        ]

    # ------------------------------------------------------------------ #
    # 2. Outdated SSM Agent
    # ------------------------------------------------------------------ #
    def _checkSsmManagedInstanceOldAgent(self):
        """
        Uses the API's own IsLatestVersion flag rather than comparing version
        strings or dates against a hardcoded 'current' release. A pinned
        constant would start producing false positives the moment AWS ships a
        new agent, and the spec's 'older than 6 months' framing has no
        corresponding field to read.
        """
        if self.isLatestVersion is True:
            self.results['ssmManagedInstanceOldAgent'] = [
                1,
                f"Instance {self.instanceId} runs the latest SSM Agent "
                f"({self.agentVersion or 'version not reported'})"
            ]
            return

        if self.isLatestVersion is False:
            self.results['ssmManagedInstanceOldAgent'] = [
                -1,
                "Instance {} runs SSM Agent {}, which is not the latest release — "
                "it misses fixes for known agent defects and may not support "
                "newer Systems Manager features"
                .format(self.instanceId, self.agentVersion or 'unknown')
            ]
            return

        self.results['ssmManagedInstanceOldAgent'] = [
            0,
            f"Instance {self.instanceId} does not report whether its SSM Agent "
            "is the latest version"
        ]

    # ------------------------------------------------------------------ #
    # 3. Instance not online
    # ------------------------------------------------------------------ #
    def _checkSsmManagedInstanceNotOnline(self):
        if self.pingStatus == 'Online':
            self.results['ssmManagedInstanceNotOnline'] = [
                1, f"Instance {self.instanceId} is Online"
            ]
            return

        if not self.pingStatus:
            self.results['ssmManagedInstanceNotOnline'] = [
                0, f"Instance {self.instanceId} reports no ping status"
            ]
            return

        self.results['ssmManagedInstanceNotOnline'] = [
            -1,
            "Instance {} has PingStatus {} — Systems Manager cannot reach it, so "
            "it receives no patches, no inventory collection and no Run Command "
            "or Session Manager access".format(self.instanceId, self.pingStatus)
        ]

    # ------------------------------------------------------------------ #
    # 4. No inventory collected
    # ------------------------------------------------------------------ #
    def _checkSsmInventoryNotConfigured(self):
        if self.inventoryEntryCount is None:
            ## Either the lookup failed, or the instance was beyond the sampling
            ## limit in Ssm.INVENTORY_SAMPLE_LIMIT. Neither is evidence of
            ## missing inventory.
            self.results['ssmInventoryNotConfigured'] = [
                0,
                f"Inventory was not queried for instance {self.instanceId} "
                "(beyond the sampling limit, or the lookup was denied)"
            ]
            return

        if self.inventoryEntryCount > 0:
            self.results['ssmInventoryNotConfigured'] = [
                1,
                f"Instance {self.instanceId} reports "
                f"{self.inventoryEntryCount} AWS:InstanceInformation inventory "
                "entry(ies)"
            ]
        else:
            self.results['ssmInventoryNotConfigured'] = [
                -1,
                "Instance {} has no AWS:InstanceInformation inventory entry — no "
                "Inventory association is collecting from it, so its installed "
                "software and configuration are not recorded for audit or "
                "vulnerability triage".format(self.instanceId)
            ]
