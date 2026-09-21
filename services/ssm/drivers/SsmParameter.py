from datetime import datetime, timezone

from services.Evaluator import Evaluator


class SsmParameter(Evaluator):
    """
    Per-parameter SSM Parameter Store checks (5 of the 14).

      ssmParameterNotEncrypted
      ssmParameterNoEncryptionCMK
      ssmParameterOldVersion
      ssmParameterNoDescription
      ssmParameterNoTags

    Input:
      param -- dict from services/ssm/Ssm.py._describeParameters: a
        describe_parameters entry plus '_name', '_tags', '_region'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    ## Name fragments suggesting the value is a credential. Matched
    ## case-insensitively against the full parameter path.
    ##
    ## 'key' is deliberately absent even though the spec lists it: it matches
    ## far too much innocuous configuration ('sort_key', 'partition_key',
    ## 'keystone_url') to be a usable signal. The narrower fragments below cover
    ## the real credential cases without the noise.
    SENSITIVE_NAME_FRAGMENTS = (
        'secret', 'password', 'passwd', 'token', 'credential', 'privatekey',
        'private_key', 'private-key', 'apikey', 'api_key', 'api-key',
        'accesskey', 'access_key', 'access-key',
    )

    ## KMS key aliases that denote the AWS-managed default key for SSM.
    DEFAULT_SSM_KEY_ALIASES = ('alias/aws/ssm',)

    ## An SSM parameter has no explicit deprecation signal, so 'stale' is
    ## approximated as: heavily revised AND untouched for a long time.
    OLD_VERSION_THRESHOLD = 20
    OLD_VERSION_AGE_DAYS = 365

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, param, ssmClient):
        super().__init__()
        self.param = param
        self.ssmClient = ssmClient

        self.name = param.get('_name', param.get('Name', 'unknown'))
        self._resourceName = self.name

        self.type = param.get('Type')
        self.keyId = param.get('KeyId')
        self.version = param.get('Version')
        self.description = param.get('Description')
        self.tags = param.get('_tags') or []
        self.lastModified = param.get('LastModifiedDate')

        self.addII('parameterName', self.name)
        self.addII('region', param.get('_region', 'N/A'))
        self.addII('type', self.type or 'N/A')
        self.addII('kmsKeyId', self.keyId or 'None')
        self.addII('version', str(self.version) if self.version else 'N/A')
        self.addII('tier', param.get('Tier') or 'N/A')
        self.addII('tagCount', str(len(self.tags)))
        self.addII('lastModified', self._formatDate(self.lastModified))

    # ------------------------------------------------------------------ #
    # 1. Credential-looking parameter stored as plaintext
    # ------------------------------------------------------------------ #
    def _checkSsmParameterNotEncrypted(self):
        """
        Only parameters whose NAME suggests a credential are flagged. The value
        is never read — doing so would pull secrets into the scanner's memory
        and its output — so the name is the only evidence available.
        """
        if self.type == 'SecureString':
            self.results['ssmParameterNotEncrypted'] = [
                1, f"Parameter '{self.name}' is a SecureString"
            ]
            return

        matched = self._matchedSensitiveFragments()
        if not matched:
            self.results['ssmParameterNotEncrypted'] = [
                0,
                f"Parameter '{self.name}' is type {self.type or 'unknown'} and its "
                "name does not suggest it holds a credential"
            ]
            return

        self.results['ssmParameterNotEncrypted'] = [
            -1,
            "Parameter '{}' is type {} (not SecureString) but its name contains "
            "{} — anyone with ssm:GetParameter reads the value in plaintext, and "
            "it appears unencrypted in CloudTrail and CloudFormation output"
            .format(self.name, self.type or 'unknown', self._joinNames(matched))
        ]

    # ------------------------------------------------------------------ #
    # 2. SecureString using the AWS-managed default key
    # ------------------------------------------------------------------ #
    def _checkSsmParameterNoEncryptionCMK(self):
        if self.type != 'SecureString':
            self.results['ssmParameterNoEncryptionCMK'] = [
                0,
                f"Parameter '{self.name}' is not a SecureString — no KMS key applies"
            ]
            return

        if not self.keyId:
            ## A SecureString always has a key; an absent KeyId means the
            ## default was used and the API simply did not echo it back.
            self.results['ssmParameterNoEncryptionCMK'] = [
                -1,
                f"Parameter '{self.name}' is a SecureString with no KeyId "
                "reported — it is encrypted with the AWS-managed key alias/aws/ssm"
            ]
            return

        if self._isDefaultSsmKey(self.keyId):
            self.results['ssmParameterNoEncryptionCMK'] = [
                -1,
                f"Parameter '{self.name}' is encrypted with the AWS-managed key "
                f"{self.keyId} — its key policy cannot be restricted, so every "
                "principal holding ssm:GetParameter can decrypt the value, and "
                "the key cannot be rotated or revoked by the account"
            ]
        else:
            self.results['ssmParameterNoEncryptionCMK'] = [
                1,
                f"Parameter '{self.name}' is encrypted with the customer managed "
                f"key {self.keyId}"
            ]

    # ------------------------------------------------------------------ #
    # 3. Heavily revised parameter that has since gone stale
    # ------------------------------------------------------------------ #
    def _checkSsmParameterOldVersion(self):
        ageDays = self._ageInDays(self.lastModified)
        version = self.version if isinstance(self.version, int) else None

        if version is None or ageDays is None:
            self.results['ssmParameterOldVersion'] = [
                0,
                f"Parameter '{self.name}' does not report both a version and a "
                "last-modified date"
            ]
            return

        if version > self.OLD_VERSION_THRESHOLD and ageDays > self.OLD_VERSION_AGE_DAYS:
            self.results['ssmParameterOldVersion'] = [
                -1,
                "Parameter '{}' is at version {} but has not changed in {} day(s) "
                "— it accumulated {} revisions and then stopped being maintained, "
                "which suggests it is stale or abandoned"
                .format(self.name, version, ageDays, version)
            ]
        else:
            self.results['ssmParameterOldVersion'] = [
                1,
                f"Parameter '{self.name}' is at version {version}, last modified "
                f"{ageDays} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 4. No description
    # ------------------------------------------------------------------ #
    def _checkSsmParameterNoDescription(self):
        if self.description and self.description.strip():
            self.results['ssmParameterNoDescription'] = [
                1,
                f"Parameter '{self.name}' has a description "
                f"({len(self.description)} chars)"
            ]
        else:
            self.results['ssmParameterNoDescription'] = [
                -1,
                f"Parameter '{self.name}' has no description — its name is the "
                "only clue to what consumes it, so nobody can safely change or "
                "delete it"
            ]

    # ------------------------------------------------------------------ #
    # 5. No tags
    # ------------------------------------------------------------------ #
    def _checkSsmParameterNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['ssmParameterNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['ssmParameterNoTags'] = [
                -1,
                f"Parameter '{self.name}' has no tags — it cannot be attributed "
                "to an owner or environment, and tag-based IAM conditions cannot "
                "restrict who reads it"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _matchedSensitiveFragments(self):
        lowered = self.name.lower()
        return [f for f in self.SENSITIVE_NAME_FRAGMENTS if f in lowered]

    def _isDefaultSsmKey(self, keyId):
        lowered = str(keyId).lower()
        for alias in self.DEFAULT_SSM_KEY_ALIASES:
            ## Matches both the bare alias and its full ARN form.
            if lowered == alias or lowered.endswith('/' + alias.split('/', 1)[1]):
                return True
        return False

    def _ageInDays(self, value):
        if not isinstance(value, datetime):
            return None
        now = datetime.now(timezone.utc)
        ## Boto3 returns tz-aware datetimes, but guard against a naive one.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (now - value).days

    def _formatDate(self, value):
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        return 'N/A'

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
