"""Short remediation guidance for Service Screener findings.

The guidance feeds the ``Description``, ``Impact``, ``Remediation`` and
``Effort`` columns of ``waf-pillars.xlsx``. It never invents AWS CLI commands:
runnable commands come only from a reviewed ``remediation`` template in the
reporter definition, resolved per resource by ``utils/RemediationResolver.py``.

Every finding gets a ``summary`` (its ``shortDesc``). A short ``instruction``
is added only when it is specific enough to help:

* an exact, hand-written entry keyed by ``service.check``; or
* a family hint matched against the check name and ``shortDesc``. For very
  short summaries the first sentence of the description is tried as well.

A hint that mostly repeats the summary is dropped, and when nothing specific
applies the instruction is empty: a generic sentence adds length, not meaning.
The ``Remediation`` cell is the instruction, or the summary when there is
none; the ``Description`` cell is the summary plus the "why it matters"
sentences from the reporter description.

``impact`` is a list of tags: the Well-Architected pillars the reporter assigns
to the check (main pillar first), keyword-derived extras (data loss,
compliance) and the reporter's downtime / slowness / additionalCost /
needFullTest flags. ``effort`` (Low, Medium or High) starts from a base for
the kind of change (an explicit exact entry, else ``remediation_risk``, else
the matched family) and is raised by the same reporter flags.
"""

import re
from typing import Any, Mapping


def _db_param(name, value):
    return (
        f'Set {name} to {value} in the DB or cluster parameter group; '
        'reboot if the parameter is static.'
    )


class RemediationCatalog:
    """Resolve a finding into a short summary and, where possible, a concrete hint."""

    _EXACT_GUIDANCE = {
        # CloudWatch Logs
        'cloudwatch.SetRetentionDays':
            'Set the log group retention to the logging policy (365 days where CIS applies).',
        'cloudwatch.CISRetentionAtLeast1Yr':
            'Set the log group retention to at least 365 days.',

        # EC2 / Auto Scaling
        'ec2.EC2IMDSv2':
            'Set metadata option HttpTokens=required; confirm installed agents and SDKs support IMDSv2 first.',
        'ec2.EC2Active':
            'Terminate stopped instances that are no longer needed; snapshot volumes first if the data matters.',
        'ec2.ELBListenerInsecure':
            'Move the listener to HTTPS/TLS with an ACM certificate, then redirect or remove the insecure listener.',
        'ec2.ASGELBHealthCheckEnabled':
            'Set the Auto Scaling group health check type to ELB with a suitable grace period.',

        'ec2.EC2DiskMonitor': (
            'Install the CloudWatch agent (for example via SSM) to publish disk metrics, then alarm on low free space.',
            'Without agent metrics a full disk is invisible to CloudWatch until the instance or its application fails.',
            'medium',
        ),
        'ec2.EC2MemoryMonitor': (
            'Install the CloudWatch agent (for example via SSM) to publish memory metrics, then alarm on high usage.',
            'Without agent metrics memory exhaustion is invisible to CloudWatch until the instance swaps or crashes.',
            'medium',
        ),
        'ec2.EC2LowUtilization': (
            'Downsize the instance to the type Compute Optimizer recommends after checking peak usage.', '', 'low'),
        'ec2.EC2AMD': (
            'Change the instance type to the AMD equivalent (for example m5 to m5a) after testing.', '', 'low'),
        'ec2.EC2Graviton': (
            'Change the instance type to the Graviton equivalent (for example m5 to m6g) after rebuilding the workload for arm64.',
            '', 'medium'),
        'ec2.ComputeOptimizerEnabled': (
            'Opt in to Compute Optimizer for the account or organization.', '', 'low'),
        'ec2.ELBConnectionDraining': (
            'Enable connection draining on the Classic Load Balancer with a timeout that covers the longest request.', '', 'low'),
        'ec2.ASGELBHealthCheckValidation': (
            'Attach the Auto Scaling group to its load balancer or target group, or switch the health check type to EC2.', '', 'low'),
        'ec2.ASGInstancesRemoved': (
            'Set the desired capacity above zero, or delete the Auto Scaling group if it is no longer used.', '', 'low'),
        'ec2.ASGTargetGroupELBExist': (
            'Attach the target group to a load balancer, or detach it from the Auto Scaling group.', '', 'low'),
        'ec2.ASGClassicLBExist': (
            'Detach the deleted Classic Load Balancer from the Auto Scaling group and attach a current one.', '', 'low'),
        'ec2.ASGAMIExist': (
            'Point the launch template or configuration at an existing AMI, then refresh the instances.', '', 'medium'),
        'ec2.ASGIMDSv2': (
            'Set HttpTokens=required in the launch template metadata options and roll the instances.', '', 'medium'),

        'ec2.ELBCrossZone': (
            'Enable cross-zone load balancing on the load balancer.',
            'Without it each AZ receives an equal share of traffic regardless of how many targets it has, so the AZ with fewer targets is overloaded.',
        ),
        'ec2.SGDefaultInUsed':
            'Move the attached resources to a purpose-built security group and leave the default group unused.',
        'ec2.SGDefaultDisallowTraffic':
            'Remove every inbound and outbound rule from the default security group.',
        'ec2.SGAllPortOpen':
            'Replace the all-ports rule with the specific ports and protocols the workload needs.',
        'ec2.SGAllPortOpenToAll':
            'Replace the all-ports 0.0.0.0/0 rule with specific ports and approved source CIDRs.',
        'ec2.SGAllTCPOpen':
            'Replace the all-TCP rule with the specific ports the workload needs.',

        # IAM
        'iam.passwordLastChange90':
            'Have the user change the password, or set a maximum password age in the account password policy.',
        'iam.passwordLastChange365':
            'Have the user change the password, or set a maximum password age in the account password policy.',
        'iam.userNoActivity90days':
            'Disable console access and access keys for the user, then delete it once confirmed unused.',

        # Lambda
        'lambda.lambdaTracingDisabled':
            'Enable X-Ray active tracing on the function.',

        # RDS general
        'rds.FreeStorage20pct':
            'Increase allocated storage or enable storage autoscaling on the instance.',
        'rds.DefaultMasterAdmin': (
            'Restore a snapshot into a new instance with a non-default master username, then cut over.', '', 'high'),
        'rds.EngineVersionMinor': (
            'Apply the minor engine version upgrade in a maintenance window (or enable auto minor version upgrade) after testing.',
            '', 'low'),
        'rds.CACertExpiringIn365days':
            'Modify the instance to the current RDS CA and update client trust stores before the old CA expires.',
        'rds.MSSQLorPG__TransportEncrpytionDisabled':
            'Set rds.force_ssl=1 in the parameter group and use SSL in client connection strings.',

        # RDS MySQL / Aurora MySQL parameters
        'rds.MYSQL__parammAutoCommit':
            _db_param('autocommit', 'ON') + ' Test application transaction handling first.',
        'rds.MYSQL__parammInnodbStatsPersistent':
            _db_param('innodb_stats_persistent', 'ON'),
        'rds.MYSQLA__paramAuroraLabMode':
            'Review aurora_lab_mode in the cluster parameter group; lab-mode features are not meant for production.',
        'rds.MYSQLA__paramQueryCacheType':
            _db_param('query_cache_type', '1') + ' Keep it off if the workload does not reuse queries.',
        'rds.MYSQL__paramQueryCacheType':
            _db_param('query_cache_type', '0') + ' Test the workload impact first.',
        'rds.MYSQL__param_syncBinLog':
            _db_param('sync_binlog', '1') + ' Test the performance and RPO impact first.',
        'rds.MYSQL__param_innodbFlushTrxCommit':
            _db_param('innodb_flush_log_at_trx_commit', '1') + ' Test the performance impact first.',
        'rds.MYSQL__innodb_change_buffering':
            _db_param('innodb_change_buffering', 'NONE'),
        'rds.MYSQL__innodb_open_files':
            _db_param('innodb_open_files', 'at least 65'),

        # RDS PostgreSQL / Aurora PostgreSQL parameters
        'rds.PG__param_idleTransTimeout':
            _db_param('idle_in_transaction_session_timeout', 'a non-zero value (ms)'),
        'rds.PG__param_statementTimeout':
            _db_param('statement_timeout', 'a non-zero value (ms) above the longest expected query'),
        'rds.PG__param_logTempFiles':
            _db_param('log_temp_files', 'a non-zero value (kB)'),
        'rds.PG__param_tempFileLimit':
            _db_param('temp_file_limit', 'a non-zero value (kB)'),
        'rds.PG__param_rdsAutoVacuumLevel':
            _db_param('rds.force_autovacuum_logging_level', "'warning'"),
        'rds.PG__param_autoVacDuration':
            _db_param('log_autovacuum_min_duration', 'a non-zero value (ms)'),
        'rds.PG__param_trackIoTime':
            _db_param('track_io_timing', '1'),
        'rds.PG__param_logStatement':
            _db_param('log_statement', "'ddl' or 'none'") + ' Logging all statements wastes storage and IOPS.',
        'rds.PG__param_trackActivities':
            _db_param('track_activities', '1'),
        'rds.PG__param_trackCounts':
            _db_param('track_counts', '1'),
        'rds.PG__param_synchronousCommit':
            _db_param('synchronous_commit', '1') + ' Test the performance impact first.',
        'rds.PG__param_autovacuum':
            _db_param('autovacuum', '1'),
        'rds.PG__param_enable_indexonlyscan':
            _db_param('enable_indexonlyscan', '1'),
        'rds.PG__param_enable_indexscan':
            _db_param('enable_indexscan', '1'),

        # RDS SQL Server parameters
        'rds.MSSQL__ParamMaxMemoryTooLow':
            _db_param('max server memory (MB)', 'the value recommended for the instance class'),
        'rds.MSSQL__ParamMaxMemoryTooHigh':
            _db_param('max server memory (MB)', 'the value recommended for the instance class'),
        'rds.MSSQL__ParamCostThresholdTooLow':
            _db_param('cost threshold for parallelism', '50 as a starting point'),
        'rds.MSSQL__ParamMaxDegreeParallism':
            _db_param('max degree of parallelism', 'a value tuned for the workload'),

        # S3
        's3.AccessControlList':
            'Set Object Ownership to "Bucket owner enforced" so ACLs are ignored; check no client relies on ACL grants first.',

        # Findings whose shortDesc is a noun phrase, so without an entry the
        # Remediation cell would only repeat the finding name.
        'cloudtrail.HasCoverGlobalServices': (
            'Enable "Include global service events" on at least one multi-region trail.', '', 'low'),
        'cloudtrail.HasManagementEventsCaptured': (
            'Enable management events (read and write) on at least one multi-region trail.', '', 'low'),
        'cloudtrail.HasDataEventsCaptured': (
            'Add data event selectors (S3 objects, Lambda invocations) to a trail for the workloads that need them.', '', 'low'),
        'cloudwatch.trailWithCWLogsWithoutMetrics': (
            'Create the CIS metric filters and alarms on the CloudTrail log group (root usage, IAM changes, console sign-in failures and the rest).',
            '', 'medium'),
        'cognito.cognitoTokenValidityTooLong': (
            'Set access and ID token validity to 60 minutes or less and refresh token validity to 30 days or less on each app client.',
            '', 'low'),
        'dynamodb.disabledTTL': (
            'Enable TTL with an expiry attribute so expired items are removed at no write cost.', '', 'low'),
        'dynamodb.systemErrors': (
            'Review the SystemErrors metric and add SDK retries with exponential backoff; open a support case if errors persist.',
            '', 'medium'),
        'dynamodb.conditionalCheckFailedRequests': (
            'Review the application logic behind the failed conditional writes; expected optimistic-locking conflicts can be ignored.',
            '', 'medium'),
        'dynamodb.userErrors': (
            'Fix the client requests behind the UserErrors metric (invalid parameters, missing tables, throttled requests).',
            '', 'medium'),
        'dynamodb.trailDeleteBackup': (
            'Confirm the backup deletions were intentional and restrict backup deletion to approved roles.', '', 'low'),
        'dynamodb.trailDeleteTable': (
            'Confirm the table deletions were intentional and enable deletion protection on the remaining production tables.',
            '', 'low'),
        'eks.eksNoManagedNodeGroups': (
            'Create a managed node group (or Fargate profile) and move workloads off self-managed nodes.', '', 'high'),
        'eks.eksNoManagedStorageDrivers': (
            'Install the EBS CSI add-on (and EFS CSI if needed) through EKS add-ons.', '', 'low'),
        'guardduty.FailMeetingCompliances': (
            'Triage and resolve the GuardDuty findings that have breached the SLA, then archive them.', '', 'medium'),
    }

    # (family, match patterns, exclude pattern, hint). Ordered specific to
    # general: the first family whose pattern matches wins. Patterns are
    # regular expressions applied to lower-case text.
    _FAMILIES = (
        ('waf_association',
         (r'without ?(a )?(wafv2 )?web ?acl', r'associat\w*.*web ?acl', r'web ?acl.*associat',
          r'web ?acl ?(id|arn)\b', r'waf not associated', r'web application firewall',
          r'\bwaf\b.*(enable|associat|use)', r'(enable|use|associat\w*).*\bwaf\b'),
         None,
         'Attach the approved Web ACL and confirm legitimate traffic still passes.'),
        ('waf_visibility',
         (r'web ?acl.*(logging|metrics|sampled|visibility|redact)',
          r'(logging|metrics|sampled|visibility|redact).*web ?acl',
          r'wafv2.*(logging|metrics|sampled|visibility|redact)'),
         None,
         'Update the Web ACL logging and visibility settings, then confirm logs and metrics arrive.'),
        ('waf_protection',
         (r'managed ?rule', r'rule ?groups?', r'rate.?based', r'sqli', r'sql ?injection', r'\bxss\b',
          r'bot ?control', r'known ?bad', r'anonymous ?ip', r'account ?takeover', r'\batp\b', r'scope.?down'),
         r'cognito|notify|excessive|trim|excluded|version|pinned|empty',
         'Add the rule in Count mode, review matched requests, then switch it to Block.'),
        ('alerting',
         (r'\balarms?\b', r'\bnotifications?\b', r'event ?subscriptions?', r'\bsns ?topic\b', r'\balert\w*'),
         r'metric ?math|composite|insufficient|dashboard',
         'Point the alarm or notification at an SNS topic with a live subscriber and send a test notification.'),
        ('tagging',
         (r'\btags?\b', r'\btagging\b', r'\btagged\b', r'cost.?(center|centre|allocation)'),
         r'immutab|tag ?mutability|propagat|sensitive|classification',
         'Add owner, environment, and cost-allocation tags.'),
        ('versioning',
         (r'\bversioning\b',),
         None,
         'Enable versioning so overwritten or deleted items can be recovered.'),
        ('deletion_protection',
         (r'delet\w* ?protection', r'termination ?protection'),
         None,
         'Enable deletion protection; turn it off only for an intended delete.'),
        ('backup_and_recovery',
         (r'\bbackups?\b', r'\bsnapshots?\b', r'recovery ?points?', r'point.in.time', r'\bpitr\b'),
         r'too ?many|excessive|unused|old |public|encrypt|shared|scan|vault|air.?gapped|lifecycle|opt.?in|strategy|deleted'
         r'|archiv|tier|analyz|agent|pending|deletion',
         'Enable automated backups with the required retention and test a restore.'),
        ('retention',
         (r'\bretention\b', r'\blifecycle\b', r'\bretain\w*'),
         r'lifecycle ?config|notebook|expired|persist|investigate',
         'Set the retention or lifecycle period required by policy.'),
        ('certificate_expiry',
         (r'cert\w*.*(expir|renew)', r'(expir|renew).*cert\w*'),
         None,
         'Renew or reissue the certificate and confirm every listener or distribution uses the new one.'),
        ('certificate_validation',
         (r'cert\w*.*validat', r'validat\w*.*cert\w*'),
         None,
         'Complete the DNS or email validation so ACM can issue the certificate.'),
        ('certificate_and_tls',
         (r'\bcertificates?\b', r'\bcerts?\b', r'\btls\b', r'\bssl\b', r'\bhttps\b', r'\bacm\b', r'\bsni\b', r'\bmtls\b'),
         r'not ?(in ?use|associated)|unused',
         'Use a supported TLS policy with a valid, correctly attached certificate.'),
        ('availability_and_failover',
         (r'multi.?az', r'single.?az', r'\bfailover\b', r'\breplicas?\b', r'\breplication\b',
          r'availability ?zones?', r'disaster ?recovery', r'origin ?group'),
         r'healthy ?percent|minimum|bucket|event replication',
         'Add the standby, replica, or failover configuration, then test failover in a maintenance window.'),
        ('key_rotation',
         (r'\bkey ?rotation\b', r'rotat\w*.*\bkms\b', r'\bkms\b.*rotat\w*'),
         r'access ?key',
         'Enable automatic key rotation on the KMS key.'),
        ('encryption',
         (r'encrypt\w*', r'\bkms\b', r'\bcmks?\b', r'at ?rest', r'in ?transit', r'secure ?string', r'\bsse\b'),
         r'key ?polic|cross.?account|grantor|pending ?deletion|unused|orphan|\bgrants?\b|duplicate|enforc|sse-c',
         'Enable encryption with an approved KMS key, then confirm clients still connect.'),
        ('public_access',
         (r'\bpublic(ly)? ?(access\w*|exposure|endpoint|ips?|read|write|snapshots?|amis?|buckets?)',
          r'internet.?facing', r'open to the internet', r'0\.0\.0\.0/0', r'wildcard ?principal',
          r'anonymous ?access', r'\bpublic\b.*\b(restrict|disable|block)', r'(restrict|disable|block)\w*.*\bpublic\b'),
         r'document|approval',
         'Remove public access; allow only approved principals and CIDR ranges.'),
        ('mfa',
         (r'\bmfa\b', r'multi.?factor'),
         r'delete',
         'Enroll the MFA device, then verify sign-in still works.'),
        ('password_policy',
         (r'password ?polic', r'password.*(weak|length|complex|reuse|expir)'),
         None,
         'Strengthen the password policy (length, complexity, reuse, expiry).'),
        ('secret_rotation',
         (r'auto.?rotation', r'rotation ?(not |never )?(enabled|overdue|schedule|lambda|disabled|configured|missing)',
          r'\brotate\b.*\b(secrets?|passwords?|credentials?|access ?keys?)\b',
          r'\b(secrets?|passwords?|credentials?|access ?keys?)\b.*\brotat', r'no ?rotat'),
         None,
         'Rotate the credential (automatically where the service supports it), then verify consumers pick up the new value.'),
        ('authentication',
         (r'\bauthenticat\w*', r'\bauthoriz(ation|ers?)\b', r'\bunauthenticated\b', r'identity ?provider',
          r'\bidp\b', r'\bsso\b', r'\bfederat\w*', r'\biam ?auth', r'\boauth'),
         None,
         'Require an approved authentication method and test client sign-in.'),
        ('secrets_and_credentials',
         (r'\bsecrets?\b', r'access ?keys?', r'api ?keys?', r'\bcredentials?\b', r'\bpasswords?\b',
          r'plain.?text', r'hard.?coded'),
         r'description|purpose|version|replicat|staging|\bno ?secret\b|expir|\broot\b|remove|delete|compromised'
         r'|individual|identit|temporary|validity|resolves|valuefrom|reference|deletion|pending',
         'Move the credential into Secrets Manager and remove it from code, configs, and environment variables.'),
        ('least_privilege',
         (r'least.?privilege', r'full ?(admin|access)', r'administrator', r'over.?privileg\w*', r'\bwildcard\b',
          r'\bpermissions?\b', r'sensitive .*actions?', r'restrict\w* .*(polic|actions?|access)',
          r'limit (access|permissions?)'),
         r'inactive|unused|use managed polic|user ?group|password ?polic|individual|identit',
         'Scope the policy to least privilege and re-test the affected identities.'),
        ('network_controls',
         (r'security ?groups?', r'\bsgs?\b', r'\bingress\b', r'\begress\b', r'network ?acl', r'\bnacl\b',
          r'\bfirewall\b', r'\bports?\b', r'\bcidrs?\b', r'ip ?(range|address)', r'\ballow(ed)? ?(ip|traffic|source)'),
         r'import|export|report|support|unused',
         'Limit network access to approved sources, ports, and protocols.'),
        ('failure_handling',
         (r'dead.?letter', r'\bdlq\b', r'\bretr(y|ies)\b', r'circuit.?breaker', r'catch ?handler',
          r'error ?handling', r'max ?receive ?count'),
         None,
         'Configure the failure-handling setting and test it with a forced failure.'),
        ('threat_detection',
         (r'guard ?duty', r'\binspector\b', r'security ?hub', r'\bmacie\b', r'access ?analyzer', r'\bdetective\b'),
         r'findings?|remediat|resolve|standard|control|aggregat|integrat',
         'Enable the service in every active region and route findings to the security team.'),
        ('log_delivery',
         (r'\b(enable|send|stream|archive|deliver|publish|export|turn on|configure|set ?up)\b.*\b(logs?|logging|trail|audit)\b',
          r'\b(logs?|logging)\b.*\b(disabled|missing|not (enabled|configured))', r'flow ?logs?', r'access ?log',
          r'\bcloud ?trail\b.*\b(cloud ?watch|s3|log)'),
         r'insights|retention|metric|dashboard|analysis|validation|encrypt|group ?does ?not ?exist|log ?statement|error',
         'Enable logging, then confirm a test event appears at the log destination.'),
        ('upgrade_and_patch',
         (r'\bversions?\b', r'\bupgrade\w*', r'\bpatch\w*', r'\bdeprecat\w*', r'end.of.(support|life)', r'\beol\b',
          r'\boutdated\b', r'\bolder\b', r'\blatest\b', r'\bgeneration\b', r'\bruntime\b', r'\bunsupported\b'),
         r'versioning|api ?version|schema|revis|version ?stages?|versions ?excessive|policy ?version|label|delivery|error|pinned|unpin'
         r'|excessive|obsolete|agentcore|vault|empty|failed',
         'Test the upgrade first, then apply it in a maintenance window.'),
        ('autoscaling',
         (r'auto.?scal\w*', r'\bscaling\b'),
         r'storage ?autoscal',
         'Configure scaling policies with tested minimum and maximum bounds.'),
        ('capacity_and_quota',
         (r'\bquotas?\b', r'\blimits?\b', r'\bcapacity\b', r'\bthrottl\w*', r'\bthroughput\b', r'\bconcurren\w*',
          r'free ?storage', r'\bstorage\b.*\b(full|free|low|space)\b'),
         r'temp_file_limit|rate.?limit|no ?limit|unlimited|monitor|task.level|cpu and memory|resource ?limits|limit\w* (the )?(access|permission)'
         r'|depth|complexity|configure|usage ?plan',
         'Review current usage, then adjust capacity or request a quota increase.'),
        ('unused_cleanup',
         (r'\bunused\b', r'\binactive\b', r'\bidle\b', r'not ?(in ?use|used|attached)', r'\bunattached\b',
          r'\borphan\w*', r'\bstale\b', r'\bempty\b', r'no longer'),
         r'timeout|session|revis|version|re-?ingest|sync|roll|drift|refresh|rotat|re-?scan|rebuild|investigate|vault',
         'Confirm nothing depends on the resource, then remove it; snapshot or export first if the data matters.'),
        ('cost_optimization',
         (r'\bcosts?\b', r'right.?siz\w*', r'under.?utili\w*', r'savings ?plans?', r'\breserved\b',
          r'over.?siz\w*', r'\bcheaper\b', r'\bsavings?\b', r'\bdownsiz\w*'),
         r'report|explorer|budget',
         'Validate the saving against usage data before changing the resource.'),
    )

    # Impact tags. Pillars come from the reporter ``category`` string (main
    # pillar first); the flags are the reporter's own remediation attributes,
    # shown with the same meaning as the "impact tags" in the Cloudscape UI.
    _PILLAR_IMPACT = {
        'S': 'Security',
        'R': 'Availability',
        'P': 'Performance',
        'C': 'Additional cost',
        'O': 'Operations',
    }
    # flag -> (tag when 1, tag when -1 "depends")
    _FLAG_IMPACT = (
        ('downtime', 'Downtime', 'Possible downtime'),
        ('slowness', 'Performance', 'Possible performance impact'),
        ('additionalCost', 'Additional cost', 'Possible additional cost'),
        ('needFullTest', 'Requires testing', 'May require testing'),
    )
    # (tag, patterns, exclude pattern, also scan the description). Data-loss
    # patterns run on the check name and summary only, because descriptions
    # mention backups and snapshots in passing; compliance names (CIS, PCI,
    # Security Hub controls) are reliable wherever they appear.
    _IMPACT_EXTRAS = (
        ('Data loss',
         (r'\bbackups?\b', r'\bsnapshots?\b', r'\bversioning\b', r'delet\w* ?protection',
          r'termination ?protection', r'point.in.time', r'\bpitr\b', r'recovery ?points?',
          r'\bmfa ?delete\b', r'object ?lock', r'vault ?lock', r'\bdurab'),
         r'too ?many|excessive|unused|old |public|encrypt|shared|scan|cost|archive|copy',
         False),
        ('Compliance',
         (r'\bcis\b', r'\bcomplian', r'\baudit', r'\bpci\b', r'\bhipaa\b', r'\bgdpr\b',
          r'\bsoc ?2\b', r'security ?hub control', r'config rule', r'\bcloud ?trail\b'),
         None,
         True),
    )

    # Effort. Base score by the kind of change, then the reporter flags add to
    # it: a change that needs downtime or a full test is more work to schedule
    # and verify. Score < 0.5 is Low, < 2 is Medium, otherwise High.
    _EFFORT_BASE = {'low': 0.0, 'medium': 1.0, 'high': 2.0}
    _EFFORT_UNKNOWN = 0.5
    _FAMILY_EFFORT = {
        'tagging': 'low', 'versioning': 'low', 'deletion_protection': 'low', 'retention': 'low',
        'key_rotation': 'low', 'alerting': 'low', 'log_delivery': 'low', 'threat_detection': 'low',
        'mfa': 'low', 'password_policy': 'low', 'backup_and_recovery': 'low', 'waf_visibility': 'low',
        'certificate_validation': 'low', 'certificate_expiry': 'low', 'unused_cleanup': 'low',
        'capacity_and_quota': 'low',
        'waf_association': 'medium', 'waf_protection': 'medium', 'certificate_and_tls': 'medium',
        'encryption': 'medium', 'public_access': 'medium', 'secret_rotation': 'medium',
        'secrets_and_credentials': 'medium', 'least_privilege': 'medium', 'network_controls': 'medium',
        'failure_handling': 'medium', 'autoscaling': 'medium', 'cost_optimization': 'medium',
        'upgrade_and_patch': 'medium',
        'availability_and_failover': 'high', 'authentication': 'high',
    }
    # flag -> (score when 1, score when -1 "depends")
    _FLAG_EFFORT = (
        ('downtime', 1.0, 0.5),
        ('needFullTest', 0.5, 0.25),
        ('slowness', 0.5, 0.25),
    )

    # Summaries this short are tried against the first sentence of the
    # description as well, because the summary alone carries too few words.
    _SHORT_SUMMARY_WORDS = 4

    # Description sentences that open like this are instructions, not context.
    _ACTION_LEAD_RE = re.compile(
        r'^(you should|we recommend|it is recommended|please|make sure|ensure|consider|'
        r'enable|disable|configure|set|use|remove|add|create|rotate|review|restrict|apply|attach|'
        r'delete|upgrade|update|migrate|require|limit|increase|reduce|avoid|block|turn|move|define|'
        r'specify|implement|check|tag|encrypt|associate|install|run|switch|replace|renew|enforce|'
        r'reconfigure|verify|investigate|resize|terminate|deploy|publish|send|store|separate|'
        r'document|rename|activate|allow|follow|plan|adjust|scope|distribute|protect|grant|'
        r'optimize|monitor|opt|place|recreate|request|prune|fix|keep|redact|close|perform|setup|'
        r'restore|tune|prefer|stop|constrain|change|choose|select|assign|register|provision|'
        r'schedule|test|validate|confirm|clean|audit|evaluate|leverage|utilize|adopt|complete|'
        r'decrease|downsize|archive|export|subscribe|wire|write|transition|resolve|reconcile|'
        r'record|roll|source|drop|generate|strengthen|shorten|re-?enable|re-?ingest|re-?scan|'
        r'rebuild|remediate|prioriti[sz]e|triage|auto-?verify|detach|revoke|isolate|harden|'
        r'consolidate|redirect|refresh|do not|never)\b',
        re.IGNORECASE,
    )
    _CONTEXT_MAX_CHARS = 220
    _CONTEXT_MAX_SENTENCES = 2
    # Pointer sentences that carry no explanation of their own.
    _NOISE_RE = re.compile(
        r'^(for more (information|details)|refer to|see |learn more|read more|more details|'
        r'more information|please refer|please see|for details|for further)',
        re.IGNORECASE,
    )

    _STOPWORDS = frozenset((
        'the', 'a', 'an', 'and', 'or', 'to', 'of', 'on', 'in', 'for', 'with', 'then', 'it', 'its',
        'every', 'all', 'so', 'that', 'this', 'is', 'are', 'be', 'via', 'by', 'from', 'at', 'into',
        'as', 'your', 'you', 'use', 'set', 'has', 'have', 'not', 'no', 'per', 'if', 'only', 'any',
    ))

    @classmethod
    def get_guidance(
        cls,
        service: str,
        check: str,
        detail: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return the workbook text for one finding.

        ``summary`` is the shortDesc; ``instruction`` and ``context`` may be
        empty; ``family`` names the matching rule. ``context`` is the "why it
        matters" text: hand-written for exact entries, otherwise the first
        description sentences that neither repeat the summary nor read as an
        instruction.

        The column values are ``description`` (summary plus context),
        ``remediation`` (the instruction, or the summary when there is none;
        the caller appends the CLI line), ``impact`` (list of tags) and
        ``effort`` (``Low``, ``Medium`` or ``High``).
        """
        summary = cls._clean(detail.get('shortDesc'))
        if not summary:
            summary = cls._humanize_check(check)

        instruction, context, exact_effort = cls._exact_entry(f'{service}.{check}')
        family = 'exact' if instruction else None
        # Where the instruction came from: 'exact', 'family' (a generic hint)
        # or 'description' (a sentence of the reporter description).
        source = 'exact' if instruction else None

        primary = f'{cls._humanize_check(check)} {summary}'.lower()
        text_family, hint = cls._match_family(primary)
        if not instruction:
            family, instruction = text_family, hint
            source = 'family' if instruction else None

        if not instruction and len(summary.split()) <= cls._SHORT_SUMMARY_WORDS:
            first_sentence = cls._first_sentence(detail.get('^description'))
            if first_sentence:
                family, instruction = cls._match_family(first_sentence.lower())
                source = 'family' if instruction else None

        if instruction and source == 'family' and cls._is_redundant(summary, instruction):
            instruction = ''
            source = None

        why = []
        known = f'{summary} {instruction}'
        for sentence in cls._description_sentences(detail.get('^description')):
            if cls._NOISE_RE.match(sentence) or cls._is_redundant(known, sentence):
                continue
            if cls._ACTION_LEAD_RE.match(sentence):
                if not instruction:
                    instruction = sentence
                    source = 'description'
                    family = family or 'description'
                    known = f'{summary} {instruction}'
                continue
            why.append(sentence)
        if not context:
            context = cls._join_context(why)
        if not context and not instruction:
            # Nothing specific survived; the finding statement itself is still
            # better than a bare noun-phrase summary.
            context = cls._join_context(cls._description_sentences(detail.get('^description'))[:1])

        # An imperative summary ("Enable MultiAZ") is itself the action, so it
        # leads the Remediation cell and only the consequence stays in the
        # Description; a generic family hint follows it as the second sentence.
        # A noun-phrase summary ("EC2 Disk Monitoring") stays in Description.
        imperative = bool(cls._ACTION_LEAD_RE.match(summary))
        if source == 'family' and imperative:
            remediation = ' '.join((cls._as_sentence(summary), cls._as_sentence(instruction)))
            description = context or cls._as_sentence(summary)
        elif instruction:
            remediation = cls._as_sentence(instruction)
            description = ' '.join(filter(None, (cls._as_sentence(summary), context)))
        else:
            remediation = cls._as_sentence(summary)
            description = context or remediation

        effort_family = family if family in cls._FAMILY_EFFORT else text_family

        return {
            'summary': summary,
            'instruction': instruction or '',
            'context': context or '',
            'family': family or 'none',
            'description': description,
            'remediation': remediation,
            'impact': cls._impact(check, summary, detail),
            'effort': cls._effort(detail, effort_family, exact_effort),
        }

    @classmethod
    def _exact_entry(cls, key):
        """Return (instruction, context, effort) for an exact entry, empty strings when absent."""
        entry = cls._EXACT_GUIDANCE.get(key)
        if entry is None:
            return '', '', ''
        if isinstance(entry, str):
            return entry, '', ''
        parts = tuple(entry) + ('', '')
        return parts[0] or '', parts[1] or '', parts[2] or ''

    @classmethod
    def _impact(cls, check, summary, detail):
        """Ordered, de-duplicated impact tags for one finding."""
        tags = [cls._PILLAR_IMPACT[p] for p in cls._pillars(detail) if p in cls._PILLAR_IMPACT]

        title = f'{cls._humanize_check(check)} {summary}'.lower()
        description = cls._clean(detail.get('^description')).lower()
        for tag, patterns, exclude, scan_description in cls._IMPACT_EXTRAS:
            if exclude and re.search(exclude, title):
                continue
            text = f'{title} {description}' if scan_description else title
            if any(re.search(pattern, text) for pattern in patterns):
                tags.append(tag)

        for key, yes, maybe in cls._FLAG_IMPACT:
            value = cls._flag(detail, key)
            if value == 1:
                tags.append(yes)
            elif value == -1 and yes not in tags:
                tags.append(maybe)

        ordered = []
        for tag in tags:
            if tag not in ordered:
                ordered.append(tag)
        return ordered

    @classmethod
    def _effort(cls, detail, family, exact_effort):
        """Low, Medium or High: base for the kind of change plus the reporter flags."""
        risk = str(detail.get('remediation_risk') or '').lower()
        if exact_effort in cls._EFFORT_BASE:
            score = cls._EFFORT_BASE[exact_effort]
        elif risk in cls._EFFORT_BASE:
            score = cls._EFFORT_BASE[risk]
        elif family in cls._FAMILY_EFFORT:
            score = cls._EFFORT_BASE[cls._FAMILY_EFFORT[family]]
        else:
            score = cls._EFFORT_UNKNOWN

        for key, yes, maybe in cls._FLAG_EFFORT:
            value = cls._flag(detail, key)
            if value == 1:
                score += yes
            elif value == -1:
                score += maybe

        if score < 0.5:
            return 'Low'
        if score < 2.0:
            return 'Medium'
        return 'High'

    @staticmethod
    def _pillars(detail):
        """Pillar letters, main pillar first, from raw reporter data or a Reporter card summary."""
        category = detail.get('category')
        if category:
            return list(str(category))
        return list(str(detail.get('__categoryMain') or '')) + list(str(detail.get('__categorySub') or ''))

    @staticmethod
    def _flag(detail, key):
        try:
            return int(detail.get(key) or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _as_sentence(text):
        text = ' '.join(str(text or '').split()).rstrip('.')
        if not text:
            return ''
        return text[0].upper() + text[1:] + '.'

    @classmethod
    def _match_family(cls, text):
        for family, patterns, exclude, instruction in cls._FAMILIES:
            if exclude and re.search(exclude, text):
                continue
            if any(re.search(pattern, text) for pattern in patterns):
                return family, instruction
        return None, None

    @classmethod
    def _is_redundant(cls, summary, instruction):
        """True when at least half of the hint's content words already appear in the summary."""
        hint_stems = cls._stems(instruction)
        if not hint_stems:
            return True
        overlap = hint_stems & cls._stems(summary)
        return len(overlap) / len(hint_stems) >= 0.5

    @classmethod
    def _stems(cls, text):
        words = re.findall(r'[a-z0-9]+', str(text).lower())
        return {
            word.rstrip('s')[:4]
            for word in words
            if len(word) >= 3 and word not in cls._STOPWORDS
        }

    @classmethod
    def _description_sentences(cls, description: Any):
        raw = re.sub(r'<strong><u>(\d+)</u></strong>', r'\1', str(description or ''))
        text = cls._clean(raw).replace('{$COUNT}', 'N')
        text = re.sub(r'([.!?])(?=[A-Z][a-z])', r'\1 ', text)                       # "buckets.This" -> "buckets. This"
        text = re.sub(r'^\[[^\]]*\]\s*:?\s*', '', text)                          # "[Category] "
        text = re.sub(r'^[A-Z][A-Za-z0-9 /&()-]{2,45}:\s+(?=[A-Z0-9])', '', text)  # "Title: "
        parts = re.split(r'(?<=[.!?])\s+(?=[A-Z0-9(])', text)
        return [part.strip() for part in parts if len(part.strip()) >= 12]

    @classmethod
    def _join_context(cls, sentences):
        out, total = [], 0
        for sentence in sentences:
            if not sentence.endswith(('.', '!', '?')):
                sentence += '.'
            if not out and len(sentence) > cls._CONTEXT_MAX_CHARS:
                return cls._truncate(sentence, cls._CONTEXT_MAX_CHARS)
            if len(out) >= cls._CONTEXT_MAX_SENTENCES or total + len(sentence) + 1 > cls._CONTEXT_MAX_CHARS:
                break
            out.append(sentence)
            total += len(sentence) + 1
        return ' '.join(out)

    @staticmethod
    def _truncate(text, limit):
        head = text[:limit - 1]
        cuts = [m.start() for m in re.finditer(r'[,;:]\s|\s[—–-]\s', head)]
        cut = max((c for c in cuts if c >= limit // 2), default=-1)
        if cut == -1:
            cut = head.rfind(' ')
        return head[:cut].rstrip(' ,;:') + '…'

    @staticmethod
    def _clean(value: Any) -> str:
        text = re.sub(r'<[^>]+>', ' ', str(value or ''))
        return re.sub(r'\s+', ' ', text).strip()

    @classmethod
    def _first_sentence(cls, description: Any) -> str:
        text = cls._clean(description).replace('{$COUNT}', 'N')
        text = re.sub(r'^\[[^\]]*\]\s*:?\s*', '', text)   # drop "[Category]" prefix
        match = re.match(r'(.+?[.!?])(\s|$)', text)
        return match.group(1) if match else text

    @classmethod
    def _humanize_check(cls, check: str) -> str:
        words = check.replace('__', ' ').replace('_', ' ')
        words = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', words)
        words = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', words)
        return cls._clean(words) or 'Review the reported configuration'
