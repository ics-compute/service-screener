import re
from datetime import datetime, timezone

from services.Evaluator import Evaluator


class EmrCluster(Evaluator):
    """
    Per-cluster Amazon EMR checks (12).

    Input:
      cluster -- a describe_cluster Cluster dict plus '_region', '_tags',
                 '_securityConfig' (PARSED from the JSON string) and
                 '_masterPublicIps', from services/emr/Emr.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    Review-mandated corrections applied:
      - the termination-protection field is TerminationProtected, NOT
        TerminationProtection (the spec's name would always pass);
      - the encryption checks report INFO when no security configuration exists,
        so they do not double-report with emrNoSecurityConfiguration;
      - emrNoBootstrapActions was DROPPED (absence is not a defect);
      - emrMasterInstanceOnDemand demoted to INFO (a spot master is a deliberate
        cost trade-off in dev/test).
    """

    ## Minimum EMR major release considered current enough to be receiving
    ## security patches. Parsed out of a label like 'emr-6.15.0'.
    MIN_RELEASE_MAJOR = 6
    RELEASE_PATTERN = re.compile(r'emr-(\d+)\.')

    ## A WAITING cluster with no work for longer than this is idle spend.
    IDLE_HOURS = 24

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, cluster, emrClient):
        super().__init__()
        self.cluster = cluster
        self.emrClient = emrClient

        self.name = cluster.get('Name') or cluster.get('Id', 'unknown')
        self._resourceName = self.name

        self.securityConfigName = cluster.get('SecurityConfiguration')
        self.securityConfig = cluster.get('_securityConfig')
        self.masterPublicIps = cluster.get('_masterPublicIps')
        self.tags = cluster.get('_tags') or []
        self.status = cluster.get('Status') or {}
        self.ec2Attributes = cluster.get('Ec2InstanceAttributes') or {}

        self.addII('clusterName', self.name)
        self.addII('clusterId', cluster.get('Id', 'N/A'))
        self.addII('region', cluster.get('_region', 'N/A'))
        self.addII('state', (self.status.get('State') or 'N/A'))
        self.addII('releaseLabel', cluster.get('ReleaseLabel', 'N/A'))
        self.addII('securityConfiguration', self.securityConfigName or 'None')
        self.addII('terminationProtected',
                   str(cluster.get('TerminationProtected', 'N/A')))
        self.addII('logUri', cluster.get('LogUri') or 'None')
        self.addII('stepConcurrencyLevel',
                   str(cluster.get('StepConcurrencyLevel', 'N/A')))
        self.addII('autoScalingRole', cluster.get('AutoScalingRole') or 'None')
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # Security configuration
    # ------------------------------------------------------------------ #
    def _encryptionConfig(self):
        if not isinstance(self.securityConfig, dict):
            return None
        return self.securityConfig.get('EncryptionConfiguration')

    def _checkEmrNoSecurityConfiguration(self):
        """
        The single FAIL for a cluster with no security configuration. The two
        encryption checks below report INFO in that case so one missing config
        does not produce three near-identical findings.
        """
        if self.securityConfigName:
            self.results['emrNoSecurityConfiguration'] = [
                1,
                f"Cluster '{self.name}' uses security configuration "
                f"'{self.securityConfigName}'"
            ]
        else:
            self.results['emrNoSecurityConfiguration'] = [
                -1,
                f"Cluster '{self.name}' has no security configuration attached — "
                "encryption at rest and in transit, Kerberos authentication and "
                "IAM role mapping for EMRFS are all unconfigured, because a "
                "security configuration is the only place they can be set"
            ]

    def _checkEmrEncryptionAtRestDisabled(self):
        if not self.securityConfigName:
            self.results['emrEncryptionAtRestDisabled'] = [
                0,
                "No security configuration — see emrNoSecurityConfiguration"
            ]
            return
        enc = self._encryptionConfig()
        if enc is None:
            self.results['emrEncryptionAtRestDisabled'] = [
                0,
                f"Security configuration '{self.securityConfigName}' could not be "
                "read or defines no EncryptionConfiguration"
            ]
            return

        if enc.get('EnableAtRestEncryption') is True:
            self.results['emrEncryptionAtRestDisabled'] = [
                1, f"Cluster '{self.name}' encrypts data at rest"
            ]
        else:
            self.results['emrEncryptionAtRestDisabled'] = [
                -1,
                f"Cluster '{self.name}' has at-rest encryption disabled — data on "
                "local EBS volumes, in the EMRFS S3 layer and in HDFS is written "
                "in clear text, and EMR clusters routinely process the largest "
                "datasets in the account"
            ]

    def _checkEmrEncryptionInTransitDisabled(self):
        if not self.securityConfigName:
            self.results['emrEncryptionInTransitDisabled'] = [
                0,
                "No security configuration — see emrNoSecurityConfiguration"
            ]
            return
        enc = self._encryptionConfig()
        if enc is None:
            self.results['emrEncryptionInTransitDisabled'] = [
                0,
                f"Security configuration '{self.securityConfigName}' could not be "
                "read or defines no EncryptionConfiguration"
            ]
            return

        if enc.get('EnableInTransitEncryption') is True:
            self.results['emrEncryptionInTransitDisabled'] = [
                1, f"Cluster '{self.name}' encrypts data in transit"
            ]
        else:
            self.results['emrEncryptionInTransitDisabled'] = [
                -1,
                f"Cluster '{self.name}' has in-transit encryption disabled — "
                "traffic between nodes, including shuffle data that contains the "
                "actual dataset being processed, crosses the network unencrypted"
            ]

    def _checkEmrKerberosNotEnabled(self):
        kerberos = self.cluster.get('KerberosAttributes')
        if kerberos:
            self.results['emrKerberosNotEnabled'] = [
                1, f"Cluster '{self.name}' has Kerberos configured"
            ]
        else:
            self.results['emrKerberosNotEnabled'] = [
                -1,
                f"Cluster '{self.name}' has no Kerberos configuration — the Hadoop "
                "services authenticate no one, so any principal that can reach a "
                "node's service ports has the access that service grants"
            ]

    # ------------------------------------------------------------------ #
    # Network exposure
    # ------------------------------------------------------------------ #
    def _checkEmrPubliclyAccessible(self):
        """
        Reports whether the MASTER node actually has a public IP, which is
        directly readable from list_instances. This is deliberately NOT a
        security-group rule evaluation: the SG rules are already covered by
        ec2.SGSensitivePortOpenToAll, and duplicating that here would report the
        same misconfiguration twice in two services.
        """
        if self.masterPublicIps is None:
            self.results['emrPubliclyAccessible'] = [
                0,
                f"Master node addresses for '{self.name}' could not be read"
            ]
            return

        if self.masterPublicIps:
            self.results['emrPubliclyAccessible'] = [
                -1,
                "Cluster '{}' has {} master node(s) with a public IP address ({}) "
                "— the cluster's management interfaces are reachable from the "
                "internet, subject only to security group rules".format(
                    self.name, len(self.masterPublicIps),
                    self._joinNames(self.masterPublicIps))
            ]
        else:
            self.results['emrPubliclyAccessible'] = [
                1, f"No master node of '{self.name}' has a public IP address"
            ]

    # ------------------------------------------------------------------ #
    # Operational
    # ------------------------------------------------------------------ #
    def _checkEmrLoggingDisabled(self):
        if self.cluster.get('LogUri'):
            self.results['emrLoggingDisabled'] = [
                1, f"Cluster '{self.name}' archives logs to "
                   f"{self.cluster['LogUri']}"
            ]
        else:
            self.results['emrLoggingDisabled'] = [
                -1,
                f"Cluster '{self.name}' has no LogUri — step, instance and Hadoop "
                "component logs live only on the cluster nodes, so they vanish "
                "when it terminates and cannot be used to investigate a failed or "
                "compromised job"
            ]

    def _checkEmrTerminationProtectionDisabled(self):
        ## The field is TerminationProtected. The spec said
        ## 'TerminationProtection', which does not exist and would always pass.
        if self.cluster.get('TerminationProtected') is True:
            self.results['emrTerminationProtectionDisabled'] = [
                1, f"Cluster '{self.name}' has termination protection enabled"
            ]
        else:
            self.results['emrTerminationProtectionDisabled'] = [
                -1,
                f"Cluster '{self.name}' has termination protection disabled — an "
                "accidental API call or console action can terminate it, "
                "destroying HDFS data and any in-flight job"
            ]

    def _checkEmrOldRelease(self):
        label = self.cluster.get('ReleaseLabel') or ''
        match = self.RELEASE_PATTERN.match(label)
        if not match:
            self.results['emrOldRelease'] = [
                0,
                f"Cluster '{self.name}' release label '{label or 'unknown'}' could "
                "not be parsed"
            ]
            return

        major = int(match.group(1))
        if major >= self.MIN_RELEASE_MAJOR:
            self.results['emrOldRelease'] = [
                1, f"Cluster '{self.name}' runs {label}"
            ]
        else:
            self.results['emrOldRelease'] = [
                -1,
                f"Cluster '{self.name}' runs {label} — EMR releases before "
                f"{self.MIN_RELEASE_MAJOR}.x no longer receive security patches "
                "for the bundled Hadoop, Spark and JVM components"
            ]

    def _checkEmrAutoScalingDisabled(self):
        if self.cluster.get('AutoScalingRole'):
            self.results['emrAutoScalingDisabled'] = [
                1, f"Cluster '{self.name}' has an auto-scaling role configured"
            ]
        elif self.cluster.get('InstanceCollectionType') == 'INSTANCE_FLEET':
            ## Instance fleets scale through a different mechanism that does not
            ## need AutoScalingRole.
            self.results['emrAutoScalingDisabled'] = [
                0,
                f"Cluster '{self.name}' uses instance fleets, which manage "
                "capacity without an auto-scaling role"
            ]
        else:
            self.results['emrAutoScalingDisabled'] = [
                -1,
                f"Cluster '{self.name}' has no AutoScalingRole — capacity is "
                "fixed, so the cluster is either over-provisioned when idle or "
                "too small under load"
            ]

    def _checkEmrStepConcurrencyLow(self):
        level = self.cluster.get('StepConcurrencyLevel')
        if level and level > 1:
            self.results['emrStepConcurrencyLow'] = [
                1, f"Cluster '{self.name}' runs up to {level} concurrent steps"
            ]
        else:
            self.results['emrStepConcurrencyLow'] = [
                -1,
                f"Cluster '{self.name}' has StepConcurrencyLevel=1 (the default) — "
                "steps run strictly one at a time, so the cluster sits partly idle "
                "whenever a step does not saturate it"
            ]

    def _checkEmrMasterInstanceOnDemand(self):
        """
        INFO, not FAIL. A spot master is a deliberate cost trade-off in dev and
        test environments; failing it would penalise an intentional choice. The
        risk (losing the master terminates the cluster) is worth surfacing.
        """
        market = None
        for group in (self.cluster.get('InstanceGroups') or []):
            if group.get('InstanceGroupType') == 'MASTER':
                market = group.get('Market')
                break

        if market == 'SPOT':
            self.results['emrMasterInstanceOnDemand'] = [
                0,
                f"Cluster '{self.name}' runs its master node on SPOT capacity — an "
                "interruption terminates the whole cluster. Acceptable for dev and "
                "test; review for production"
            ]
        elif market:
            self.results['emrMasterInstanceOnDemand'] = [
                1, f"Cluster '{self.name}' master node uses {market} capacity"
            ]
        else:
            self.results['emrMasterInstanceOnDemand'] = [
                0, f"Cluster '{self.name}' master capacity type is not reported"
            ]

    def _checkEmrIdleCluster(self):
        state = self.status.get('State')
        if state != 'WAITING':
            self.results['emrIdleCluster'] = [
                0, f"Cluster '{self.name}' is {state}, not WAITING"
            ]
            return

        timeline = self.status.get('Timeline') or {}
        ready = timeline.get('ReadyDateTime')
        hours = self._hoursSince(ready)
        if hours is None:
            self.results['emrIdleCluster'] = [
                0, f"Cluster '{self.name}' ready time is not reported"
            ]
        elif hours > self.IDLE_HOURS:
            self.results['emrIdleCluster'] = [
                -1,
                f"Cluster '{self.name}' has been WAITING for {hours} hours — a "
                "WAITING cluster is fully provisioned and fully billed while "
                "running no steps"
            ]
        else:
            self.results['emrIdleCluster'] = [
                1, f"Cluster '{self.name}' has been WAITING for {hours} hours"
            ]

    def _checkEmrNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['emrNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['emrNoTags'] = [
                -1,
                f"Cluster '{self.name}' has no tags — EMR is among the most "
                "expensive services per hour, so an untagged cluster makes a large "
                "cost impossible to attribute"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _hoursSince(self, value):
        if not isinstance(value, datetime):
            return None
        when = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - when).total_seconds() // 3600)

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
