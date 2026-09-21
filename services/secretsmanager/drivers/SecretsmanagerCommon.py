import datetime
import json

from services.Evaluator import Evaluator


class SecretsmanagerCommon(Evaluator):
    """
    All 15 AWS Secrets Manager checks.

    Input:
      secret -- dict produced by Secretsmanager.py._describeSecret. It is the raw
        describe_secret response body (ARN, Name, Description, KmsKeyId,
        RotationEnabled, RotationLambdaARN, RotationRules, LastRotatedDate,
        LastChangedDate, LastAccessedDate, DeletedDate, NextRotationDate, Tags,
        VersionIdsToStages, OwningService, CreatedDate, PrimaryRegion,
        ReplicationStatus) plus the scanner-added keys:
          '_arn', '_name', '_tags', '_resourcePolicy' (JSON string or None),
          '_currentAccount', '_region'.
      smClient -- boto3 secretsmanager client (kept for future extension).
    """

    # KmsKeyId is omitted by the API when the AWS-managed key is in use, but the
    # console writes the alias explicitly, so both shapes must be detected.
    AWS_MANAGED_KMS_ALIAS = 'aws/secretsmanager'

    CURRENT_STAGE = 'AWSCURRENT'
    PREVIOUS_STAGE = 'AWSPREVIOUS'

    UNUSED_DAYS = 90
    STALE_CHANGE_DAYS = 365
    MAX_NONCURRENT_VERSIONS = 10

    # Conditions that legitimately scope an otherwise-open statement.
    SCOPING_CONDITION_KEYS = {
        'aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOwner',
        'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths',
        'aws:PrincipalAccount', 'aws:PrincipalArn',
        'secretsmanager:ResourceTag',
    }

    # For the cross-account check, only org-scoping / explicit-principal
    # conditions count as adequate scoping.
    CROSS_ACCOUNT_CONDITION_KEYS = {
        'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths',
        'aws:PrincipalArn', 'aws:SourceArn', 'aws:SourceVpce', 'aws:SourceVpc',
    }

    def __init__(self, secret, smClient):
        super().__init__()
        self.secret = secret
        self.smClient = smClient

        self._resourceName = secret.get('_name', 'unknown')
        self.versionStages = secret.get('VersionIdsToStages') or {}
        self.rotationRules = secret.get('RotationRules') or {}
        self._policy = self._parsePolicy(secret.get('_resourcePolicy'))

        self.addII('secretArn', secret.get('_arn', 'N/A'))
        self.addII('name', self._resourceName)
        self.addII('kmsKeyId', secret.get('KmsKeyId') or 'aws/secretsmanager (default)')
        self.addII('rotationEnabled', str(secret.get('RotationEnabled', False)))
        self.addII('lastRotatedDate', self._fmtDate(secret.get('LastRotatedDate')))
        self.addII('lastAccessedDate', self._fmtDate(secret.get('LastAccessedDate')))
        self.addII('lastChangedDate', self._fmtDate(secret.get('LastChangedDate')))
        self.addII('owningService', secret.get('OwningService') or 'None')
        self.addII('versionCount', str(len(self.versionStages)))

    # ------------------------------------------------------------------ #
    # 1. Automatic rotation not enabled
    # ------------------------------------------------------------------ #
    def _checkSmRotationNotEnabled(self):
        if self._rotationEnabled():
            self.results['smRotationNotEnabled'] = [
                1, "RotationEnabled=True"
            ]
            return

        owning = self.secret.get('OwningService')
        if owning:
            # Service-linked secrets (e.g. rds!..., opsworks) are rotated by the
            # owning service, not by a user-configured rotation.
            self.results['smRotationNotEnabled'] = [
                0, f"Managed by OwningService={owning}; rotation is service-controlled"
            ]
            return

        self.results['smRotationNotEnabled'] = [
            -1, "RotationEnabled is false/unset — the secret never rotates automatically"
        ]

    # ------------------------------------------------------------------ #
    # 2. Rotation overdue relative to its own schedule
    # ------------------------------------------------------------------ #
    def _checkSmRotationOverdue(self):
        if not self._rotationEnabled():
            self.results['smRotationOverdue'] = [
                0, "Rotation not enabled — see smRotationNotEnabled"
            ]
            return

        interval = self.rotationRules.get('AutomaticallyAfterDays')
        try:
            interval = int(interval) if interval is not None else None
        except (TypeError, ValueError):
            interval = None

        if not interval:
            self.results['smRotationOverdue'] = [
                0,
                "RotationRules has no AutomaticallyAfterDays — cannot compute an "
                "expected rotation interval"
            ]
            return

        lastRotated = self._toUtc(self.secret.get('LastRotatedDate'))
        if lastRotated is None:
            self.results['smRotationOverdue'] = [
                -1,
                f"Rotation is enabled (every {interval} day(s)) but LastRotatedDate "
                "is unset — the secret has never rotated"
            ]
            return

        age = (self._now() - lastRotated).days
        if age > interval:
            self.results['smRotationOverdue'] = [
                -1,
                f"Last rotated {age} day(s) ago, which exceeds the configured "
                f"{interval}-day rotation interval"
            ]
        else:
            self.results['smRotationOverdue'] = [
                1, f"Last rotated {age} day(s) ago (interval {interval} day(s))"
            ]

    # ------------------------------------------------------------------ #
    # 3. Not encrypted with a customer-managed KMS key
    # ------------------------------------------------------------------ #
    def _checkSmNotEncryptedWithCMK(self):
        kmsKeyId = self.secret.get('KmsKeyId')
        if not kmsKeyId:
            self.results['smNotEncryptedWithCMK'] = [
                -1,
                "KmsKeyId is not set — encrypted with the AWS-managed key "
                "aws/secretsmanager"
            ]
            return

        if self.AWS_MANAGED_KMS_ALIAS in kmsKeyId:
            self.results['smNotEncryptedWithCMK'] = [
                -1, f"Encrypted with the AWS-managed key ({kmsKeyId})"
            ]
        else:
            self.results['smNotEncryptedWithCMK'] = [
                1, f"Encrypted with customer-managed key: {kmsKeyId}"
            ]

    # ------------------------------------------------------------------ #
    # 4. Not retrieved recently
    # ------------------------------------------------------------------ #
    def _checkSmNotUsedRecently(self):
        lastAccessed = self._toUtc(self.secret.get('LastAccessedDate'))
        if lastAccessed is None:
            # LastAccessedDate is omitted until the secret is first retrieved in
            # the region. A brand-new secret has simply not been wired up yet, so
            # only flag it once it is older than the same threshold.
            created = self._toUtc(self.secret.get('CreatedDate'))
            if created is None:
                self.results['smNotUsedRecently'] = [
                    0, "LastAccessedDate and CreatedDate both unavailable"
                ]
                return
            createdAge = (self._now() - created).days
            if createdAge > self.UNUSED_DAYS:
                self.results['smNotUsedRecently'] = [
                    -1,
                    f"Never retrieved in this region and created {createdAge} day(s) ago"
                ]
            else:
                self.results['smNotUsedRecently'] = [
                    0,
                    f"Never retrieved yet, but only {createdAge} day(s) old — "
                    f"below the {self.UNUSED_DAYS}-day threshold"
                ]
            return

        age = (self._now() - lastAccessed).days
        if age > self.UNUSED_DAYS:
            self.results['smNotUsedRecently'] = [
                -1, f"Last retrieved {age} day(s) ago (> {self.UNUSED_DAYS} days)"
            ]
        else:
            self.results['smNotUsedRecently'] = [
                1, f"Last retrieved {age} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 5. Resource policy grants public (wildcard-principal) access
    # ------------------------------------------------------------------ #
    def _checkSmResourcePolicyPublicAccess(self):
        if self._policy is None:
            self.results['smResourcePolicyPublicAccess'] = [
                0, "No resource policy attached"
            ]
            return

        offending = []
        for i, stmt in enumerate(self._policyStatements()):
            if stmt.get('Effect') != 'Allow':
                continue
            if not self._principalIsWildcard(stmt.get('Principal')):
                continue
            if self._conditionHasAnyKey(stmt.get('Condition'),
                                        self.SCOPING_CONDITION_KEYS):
                continue
            offending.append(stmt.get('Sid', f"stmt{i}"))

        if offending:
            self.results['smResourcePolicyPublicAccess'] = [
                -1,
                "Resource policy allows Principal:* without a scoping Condition: "
                + ", ".join(offending[:5])
            ]
        else:
            self.results['smResourcePolicyPublicAccess'] = [
                1, "No open wildcard-principal Allow statements"
            ]

    # ------------------------------------------------------------------ #
    # 6. Cross-account access without an org/ARN scoping condition
    # ------------------------------------------------------------------ #
    def _checkSmResourcePolicyCrossAccount(self):
        if self._policy is None:
            self.results['smResourcePolicyCrossAccount'] = [
                0, "No resource policy attached"
            ]
            return

        owner = (self.secret.get('_currentAccount')
                 or self._ownerAccountFromArn(self.secret.get('_arn', '')))
        if not owner:
            self.results['smResourcePolicyCrossAccount'] = [
                0, "Could not derive the owning account"
            ]
            return

        offending = []
        for i, stmt in enumerate(self._policyStatements()):
            if stmt.get('Effect') != 'Allow':
                continue
            # Wildcard principals are reported by smResourcePolicyPublicAccess.
            if self._principalIsWildcard(stmt.get('Principal')):
                continue

            external = self._externalAccountsInPrincipal(stmt.get('Principal'), owner)
            if not external:
                continue

            if self._conditionHasAnyKey(stmt.get('Condition'),
                                        self.CROSS_ACCOUNT_CONDITION_KEYS):
                continue

            sid = stmt.get('Sid', f"stmt{i}")
            offending.append(f"{sid}({','.join(sorted(external)[:3])})")

        if offending:
            self.results['smResourcePolicyCrossAccount'] = [
                -1,
                "Cross-account Allow without an org/ARN scoping Condition: "
                + "; ".join(offending[:5])
            ]
        else:
            self.results['smResourcePolicyCrossAccount'] = [
                1, "No unscoped cross-account access"
            ]

    # ------------------------------------------------------------------ #
    # 7. No cross-region replication
    # ------------------------------------------------------------------ #
    def _checkSmReplicationNotConfigured(self):
        replicas = self.secret.get('ReplicationStatus') or []
        if replicas:
            regions = [r.get('Region', '?') for r in replicas if isinstance(r, dict)]
            self.results['smReplicationNotConfigured'] = [
                1, f"Replicated to {len(replicas)} region(s): {', '.join(regions[:5])}"
            ]
            return

        if self.secret.get('OwningService'):
            self.results['smReplicationNotConfigured'] = [
                0,
                f"Managed by OwningService={self.secret.get('OwningService')}; "
                "replication is controlled by the owning service"
            ]
            return

        self.results['smReplicationNotConfigured'] = [
            -1,
            "ReplicationStatus is empty — the secret exists in a single region "
            "with no replica for regional failover"
        ]

    # ------------------------------------------------------------------ #
    # 8. Scheduled for deletion
    # ------------------------------------------------------------------ #
    def _checkSmPendingDeletion(self):
        deleted = self._toUtc(self.secret.get('DeletedDate'))
        if deleted is None:
            self.results['smPendingDeletion'] = [1, "Not scheduled for deletion"]
            return

        # DeletedDate is the date the deletion was REQUESTED, not the date the
        # secret disappears — verified against the API: a secret deleted with
        # --recovery-window-in-days 7 reports DeletedDate = now, while the
        # DeleteSecret response reports DeletionDate = now + 7d. DescribeSecret
        # does not return the actual purge date, so it is not reported here.
        days = (self._now() - deleted).days
        self.results['smPendingDeletion'] = [
            -1,
            f"Marked for deletion on {self._fmtDate(deleted)} ({days} day(s) ago); "
            "the secret value is unreadable and will be purged when the recovery "
            "window closes"
        ]

    # ------------------------------------------------------------------ #
    # 9. No description
    # ------------------------------------------------------------------ #
    def _checkSmNoDescription(self):
        desc = self.secret.get('Description')
        if desc and str(desc).strip():
            self.results['smNoDescription'] = [
                1, f"Description set ({len(str(desc))} chars)"
            ]
        else:
            self.results['smNoDescription'] = [-1, "Description is empty or unset"]

    # ------------------------------------------------------------------ #
    # 10. No tags
    # ------------------------------------------------------------------ #
    def _checkSmNoTags(self):
        tags = self.secret.get('_tags') or self.secret.get('Tags') or []
        if not tags:
            self.results['smNoTags'] = [-1, "No tags applied"]
            return
        keys = [t.get('Key') for t in tags if isinstance(t, dict) and t.get('Key')]
        self.results['smNoTags'] = [
            1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
        ]

    # ------------------------------------------------------------------ #
    # 11. Excessive non-current versions
    # ------------------------------------------------------------------ #
    def _checkSmVersionsExcessive(self):
        if not self.versionStages:
            self.results['smVersionsExcessive'] = [
                0, "VersionIdsToStages unavailable for this secret"
            ]
            return

        nonCurrent = 0
        for _versionId, stages in self.versionStages.items():
            stageList = stages if isinstance(stages, list) else [stages]
            if self.CURRENT_STAGE not in stageList:
                nonCurrent += 1

        if nonCurrent > self.MAX_NONCURRENT_VERSIONS:
            self.results['smVersionsExcessive'] = [
                -1,
                f"{nonCurrent} non-current version(s) retained "
                f"(> {self.MAX_NONCURRENT_VERSIONS})"
            ]
        else:
            self.results['smVersionsExcessive'] = [
                1, f"{nonCurrent} non-current version(s) retained"
            ]

    # ------------------------------------------------------------------ #
    # 12. No AWSCURRENT version stage
    # ------------------------------------------------------------------ #
    def _checkSmNoVersionStages(self):
        if self.secret.get('DeletedDate'):
            self.results['smNoVersionStages'] = [
                0,
                "Secret is scheduled for deletion — version stages are not "
                "retrievable; see smPendingDeletion"
            ]
            return

        if not self.versionStages:
            self.results['smNoVersionStages'] = [
                -1,
                "describe_secret returned no VersionIdsToStages — the secret has "
                "no retrievable version"
            ]
            return

        for _versionId, stages in self.versionStages.items():
            stageList = stages if isinstance(stages, list) else [stages]
            if self.CURRENT_STAGE in stageList:
                self.results['smNoVersionStages'] = [
                    1, f"{self.CURRENT_STAGE} stage present"
                ]
                return

        self.results['smNoVersionStages'] = [
            -1,
            f"{len(self.versionStages)} version(s) exist but none carries the "
            f"{self.CURRENT_STAGE} stage — GetSecretValue will fail"
        ]

    # ------------------------------------------------------------------ #
    # 13. Rotation enabled but no rotation function
    # ------------------------------------------------------------------ #
    def _checkSmRotationLambdaMissing(self):
        if not self._rotationEnabled():
            self.results['smRotationLambdaMissing'] = [
                0, "Rotation not enabled — see smRotationNotEnabled"
            ]
            return

        lambdaArn = self.secret.get('RotationLambdaARN')
        if lambdaArn:
            self.results['smRotationLambdaMissing'] = [
                1, f"RotationLambdaARN set: {lambdaArn.split(':')[-1]}"
            ]
            return

        # Managed rotation (AWS-managed DB secrets) and managed external secret
        # rotation legitimately have no user Lambda.
        if self.secret.get('ExternalSecretRotationRoleArn'):
            self.results['smRotationLambdaMissing'] = [
                0, "Managed external secret rotation is in use (no user Lambda needed)"
            ]
            return
        if self.secret.get('OwningService'):
            self.results['smRotationLambdaMissing'] = [
                0,
                f"Managed rotation via OwningService="
                f"{self.secret.get('OwningService')} (no user Lambda needed)"
            ]
            return

        self.results['smRotationLambdaMissing'] = [
            -1,
            "RotationEnabled=True but RotationLambdaARN is empty — rotation "
            "cannot execute"
        ]

    # ------------------------------------------------------------------ #
    # 14. Secret value not changed in over a year and no rotation
    # ------------------------------------------------------------------ #
    def _checkSmLastChangedOld(self):
        if self._rotationEnabled():
            self.results['smLastChangedOld'] = [
                0, "Rotation is enabled — staleness is managed by rotation"
            ]
            return

        lastChanged = self._toUtc(self.secret.get('LastChangedDate'))
        if lastChanged is None:
            self.results['smLastChangedOld'] = [
                0, "LastChangedDate unavailable"
            ]
            return

        age = (self._now() - lastChanged).days
        if age > self.STALE_CHANGE_DAYS:
            self.results['smLastChangedOld'] = [
                -1,
                f"Last modified {age} day(s) ago with no rotation configured "
                f"(> {self.STALE_CHANGE_DAYS} days)"
            ]
        else:
            self.results['smLastChangedOld'] = [
                1, f"Last modified {age} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 15. Rotation rules present but no ScheduleExpression
    # ------------------------------------------------------------------ #
    def _checkSmAutoRotationScheduleInvalid(self):
        if not self.rotationRules:
            self.results['smAutoRotationScheduleInvalid'] = [
                0, "No RotationRules configured"
            ]
            return

        schedule = self.rotationRules.get('ScheduleExpression')
        if schedule and str(schedule).strip():
            self.results['smAutoRotationScheduleInvalid'] = [
                1, f"ScheduleExpression={schedule}"
            ]
            return

        after = self.rotationRules.get('AutomaticallyAfterDays')
        self.results['smAutoRotationScheduleInvalid'] = [
            -1,
            "RotationRules has no ScheduleExpression "
            f"(AutomaticallyAfterDays={after}) — the rotation window cannot be "
            "controlled and the schedule is implicit"
        ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _rotationEnabled(self):
        return str(self.secret.get('RotationEnabled', False)).lower() == 'true'

    @staticmethod
    def _now():
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def _toUtc(val):
        """Normalise a boto3 timestamp (datetime or ISO string) to tz-aware UTC."""
        if val is None:
            return None
        if isinstance(val, datetime.datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=datetime.timezone.utc)
            return val
        if isinstance(val, str):
            try:
                parsed = datetime.datetime.fromisoformat(val.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        return None

    @classmethod
    def _fmtDate(cls, val):
        dt = cls._toUtc(val)
        if dt is None:
            return 'None'
        return dt.strftime('%Y-%m-%d')

    @staticmethod
    def _parsePolicy(raw):
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def _policyStatements(self):
        if self._policy is None:
            return []
        stmts = self._policy.get('Statement', [])
        if isinstance(stmts, dict):
            return [stmts]
        return stmts if isinstance(stmts, list) else []

    @staticmethod
    def _principalIsWildcard(principal):
        if principal is None:
            return False
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == '*':
                    return True
                if isinstance(v, list) and '*' in v:
                    return True
        return False

    @staticmethod
    def _conditionHasAnyKey(condition, keys):
        if not condition or not isinstance(condition, dict):
            return False
        for opBlock in condition.values():
            if not isinstance(opBlock, dict):
                continue
            for key in opBlock.keys():
                if key in keys:
                    return True
                # secretsmanager:ResourceTag/<name> style keys
                if '/' in key and key.split('/', 1)[0] in keys:
                    return True
        return False

    @staticmethod
    def _ownerAccountFromArn(arn):
        # arn:aws:secretsmanager:region:account:secret:name-suffix
        parts = arn.split(':') if arn else []
        if len(parts) >= 5 and parts[4].isdigit():
            return parts[4]
        return None

    @staticmethod
    def _accountFromPrincipalValue(v):
        """Return the 12-digit account ID a principal value references, or None."""
        if not isinstance(v, str) or v == '*':
            return None
        if v.isdigit() and len(v) == 12:
            return v
        if ':iam::' in v:
            tail = v.split(':iam::', 1)[1]
            acct = tail.split(':', 1)[0]
            if acct.isdigit() and len(acct) == 12:
                return acct
        if ':sts::' in v:
            tail = v.split(':sts::', 1)[1]
            acct = tail.split(':', 1)[0]
            if acct.isdigit() and len(acct) == 12:
                return acct
        return None

    @classmethod
    def _externalAccountsInPrincipal(cls, principal, owner):
        accts = set()
        if principal is None or principal == '*':
            return accts
        if isinstance(principal, str):
            a = cls._accountFromPrincipalValue(principal)
            if a and a != owner:
                accts.add(a)
            return accts
        if isinstance(principal, dict):
            for v in principal.values():
                items = v if isinstance(v, list) else [v]
                for item in items:
                    a = cls._accountFromPrincipalValue(item)
                    if a and a != owner:
                        accts.add(a)
        return accts
