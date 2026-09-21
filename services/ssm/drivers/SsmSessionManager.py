from services.Evaluator import Evaluator


class SsmSessionManager(Evaluator):
    """
    Region-scoped Session Manager and Default Host Management checks (5 of 14).

      ssmSessionManagerNoEncryption
      ssmSessionManagerNoCloudWatchLogs
      ssmSessionManagerNoS3Logs
      ssmSessionManagerRunAsDisabled
      ssmDefaultHostManagementDisabled

    Session Manager preferences are a single per-region document, not a
    per-instance setting, so they are evaluated once for the region — following
    the precedent of services/ec2/drivers/Ec2Regional.py.

    Input:
      detail -- dict from services/ssm/Ssm.py._getSessionManagerDetail. Keys:
        '_region', '_accountId', '_sessionPreferences' (the inputs block of
        SSM-SessionManagerRunShell), '_sessionPreferencesFound',
        '_dhmcSetting' (a GetServiceSetting ServiceSetting dict, or None).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    ## GetServiceSetting Status values. 'Default' means the setting has never
    ## been changed from the AWS default, 'Customized' means the account set it.
    STATUS_DEFAULT = 'Default'
    STATUS_CUSTOMIZED = 'Customized'

    def __init__(self, detail, ssmClient):
        super().__init__()
        self.detail = detail
        self.ssmClient = ssmClient

        ## Region-scoped subject; there is no per-resource name.
        self._resourceName = 'Account'

        self.prefs = detail.get('_sessionPreferences') or {}
        self.prefsFound = bool(detail.get('_sessionPreferencesFound'))
        self.dhmc = detail.get('_dhmcSetting')

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('sessionPreferencesDocumentFound', str(self.prefsFound))
        self.addII('kmsKeyId', self.prefs.get('kmsKeyId') or 'None')
        self.addII('cloudWatchLogGroupName',
                   self.prefs.get('cloudWatchLogGroupName') or 'None')
        self.addII('s3BucketName', self.prefs.get('s3BucketName') or 'None')
        self.addII('runAsEnabled', str(self.prefs.get('runAsEnabled', 'N/A')))
        self.addII('idleSessionTimeout',
                   str(self.prefs.get('idleSessionTimeout') or 'N/A'))
        self.addII('dhmcStatus',
                   (self.dhmc or {}).get('Status', 'N/A'))

    # ------------------------------------------------------------------ #
    # 1. Session data not encrypted with a KMS key
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoEncryption(self):
        if not self.prefsFound:
            self.results['ssmSessionManagerNoEncryption'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "Session Manager preferences have never been configured, so "
                "session data is not encrypted with a customer managed KMS key"
            ]
            return

        kmsKeyId = self.prefs.get('kmsKeyId')
        if kmsKeyId:
            self.results['ssmSessionManagerNoEncryption'] = [
                1, f"Session data is KMS encrypted with {kmsKeyId}"
            ]
        else:
            self.results['ssmSessionManagerNoEncryption'] = [
                -1,
                "Session Manager has no kmsKeyId configured — session data is "
                "protected only by TLS in transit, with no additional KMS "
                "encryption of the session content itself"
            ]

    # ------------------------------------------------------------------ #
    # 2. Session activity not logged to CloudWatch Logs
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoCloudWatchLogs(self):
        """
        cloudWatchStreamingEnabled alone is not sufficient: without a log group
        name there is nowhere to stream to. Both are required for the session
        transcript to actually land in CloudWatch.
        """
        if not self.prefsFound:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "no session activity is logged to CloudWatch Logs"
            ]
            return

        logGroup = self.prefs.get('cloudWatchLogGroupName')
        streaming = self.prefs.get('cloudWatchStreamingEnabled')

        if logGroup and streaming is not False:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                1, f"Session activity streams to CloudWatch log group {logGroup}"
            ]
            return

        if logGroup and streaming is False:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                -1,
                f"CloudWatch log group '{logGroup}' is configured but "
                "cloudWatchStreamingEnabled is false — no session transcript is "
                "written"
            ]
            return

        self.results['ssmSessionManagerNoCloudWatchLogs'] = [
            -1,
            "Session Manager has no cloudWatchLogGroupName — shell sessions on "
            "managed instances leave no transcript in CloudWatch Logs, so there "
            "is no record of what commands an operator ran"
        ]

    # ------------------------------------------------------------------ #
    # 3. Session output not archived to S3
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoS3Logs(self):
        if not self.prefsFound:
            self.results['ssmSessionManagerNoS3Logs'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "no session output is archived to S3"
            ]
            return

        bucket = self.prefs.get('s3BucketName')
        if bucket:
            self.results['ssmSessionManagerNoS3Logs'] = [
                1, f"Session output is archived to s3://{bucket}"
            ]
        else:
            self.results['ssmSessionManagerNoS3Logs'] = [
                -1,
                "Session Manager has no s3BucketName — session output is not "
                "archived to S3, so there is no durable long-term copy of the "
                "transcript independent of the CloudWatch log retention period"
            ]

    # ------------------------------------------------------------------ #
    # 4. Run As not enabled
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerRunAsDisabled(self):
        """
        With Run As disabled every session runs as ssm-user, so all operators
        share one OS identity and on-host logs cannot attribute an action to a
        person. Enabling it makes the session assume a per-user OS account.
        """
        if not self.prefsFound:
            self.results['ssmSessionManagerRunAsDisabled'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "Run As is not enabled, so every session runs as the shared "
                "ssm-user account"
            ]
            return

        runAs = self.prefs.get('runAsEnabled')
        if runAs is True:
            defaultUser = self.prefs.get('runAsDefaultUser')
            suffix = f", default user '{defaultUser}'" if defaultUser else ""
            self.results['ssmSessionManagerRunAsDisabled'] = [
                1, f"Run As is enabled{suffix}"
            ]
        else:
            self.results['ssmSessionManagerRunAsDisabled'] = [
                -1,
                "Session Manager has runAsEnabled=false — every session runs as "
                "the shared ssm-user account, so on-host audit logs cannot "
                "attribute a command to the individual who ran it"
            ]

    # ------------------------------------------------------------------ #
    # 5. Default Host Management Configuration not enabled
    # ------------------------------------------------------------------ #
    def _checkSsmDefaultHostManagementDisabled(self):
        """
        DHMC lets Systems Manager manage every EC2 instance in the region through
        an IAM role, without attaching an instance profile to each one.

        The setting is read from
        '/ssm/managed-instance/default-ec2-instance-management-role'. Its
        SettingValue is the NAME OF THE IAM ROLE, not a boolean — so the
        authoritative signal is Status: 'Customized' means DHMC was configured,
        'Default' means it never was.
        """
        if self.dhmc is None:
            self.results['ssmDefaultHostManagementDisabled'] = [
                0,
                "The Default Host Management Configuration service setting could "
                "not be read in this region (not exposed, or "
                "ssm:GetServiceSetting denied)"
            ]
            return

        status = self.dhmc.get('Status')
        value = self.dhmc.get('SettingValue')

        if status == self.STATUS_CUSTOMIZED and value:
            self.results['ssmDefaultHostManagementDisabled'] = [
                1,
                "Default Host Management Configuration is enabled with IAM role "
                f"'{value}'"
            ]
            return

        if status == self.STATUS_DEFAULT:
            self.results['ssmDefaultHostManagementDisabled'] = [
                -1,
                "Default Host Management Configuration is not enabled — every EC2 "
                "instance needs its own instance profile to become managed, so "
                "any instance launched without one silently misses patching, "
                "inventory and Session Manager access"
            ]
            return

        ## Customized but with no role name, or an unrecognised status.
        self.results['ssmDefaultHostManagementDisabled'] = [
            -1,
            "Default Host Management Configuration reports status "
            f"'{status or 'unknown'}' with setting value "
            f"'{value or 'empty'}' — it is not usably configured"
        ]
