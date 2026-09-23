"""Short remediation guidance for Service Screener findings.

The guidance feeds the ``Notes`` column of ``waf-pillars.xlsx``. It never
invents AWS CLI commands: runnable commands come only from a reviewed
``remediation`` template in the reporter definition, resolved per resource by
``utils/RemediationResolver.py``.

Every finding gets a ``summary`` (its ``shortDesc``). A short ``instruction``
is added only when it is specific enough to help:

* an exact, hand-written entry keyed by ``service.check``; or
* a family hint matched against the check name and ``shortDesc``. For very
  short summaries the first sentence of the description is tried as well.

A hint that mostly repeats the summary is dropped, and when nothing specific
applies the instruction is empty: a generic sentence adds length, not meaning.
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
        ),
        'ec2.EC2MemoryMonitor': (
            'Install the CloudWatch agent (for example via SSM) to publish memory metrics, then alarm on high usage.',
            'Without agent metrics memory exhaustion is invisible to CloudWatch until the instance swaps or crashes.',
        ),

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
        'rds.DefaultMasterAdmin':
            'Restore a snapshot into a new instance with a non-default master username, then cut over.',
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
         'Point it at an SNS topic with a live subscriber and send a test notification.'),
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
         'Blocks accidental deletes; turn it off only for an intended delete.'),
        ('backup_and_recovery',
         (r'\bbackups?\b', r'\bsnapshots?\b', r'\brestore\b', r'recovery ?points?', r'point.in.time', r'\bpitr\b'),
         r'too ?many|excessive|unused|old |public|encrypt|shared|scan|vault|air.?gapped|lifecycle|opt.?in|strategy|deleted',
         'Enable automated backups with the required retention and test a restore.'),
        ('retention',
         (r'\bretention\b', r'\blifecycle\b', r'\bretain\w*'),
         r'lifecycle ?config|notebook',
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
         'Test failover afterwards in a maintenance window.'),
        ('key_rotation',
         (r'\bkey ?rotation\b', r'rotat\w*.*\bkms\b', r'\bkms\b.*rotat\w*'),
         r'access ?key',
         'Enable automatic key rotation on the KMS key.'),
        ('encryption',
         (r'encrypt\w*', r'\bkms\b', r'\bcmks?\b', r'at ?rest', r'in ?transit', r'secure ?string', r'\bsse\b'),
         r'key ?polic|cross.?account|grantor|pending ?deletion|unused|orphan',
         'Use an approved KMS key, then confirm clients still connect.'),
        ('public_access',
         (r'\bpublic(ly)? ?(access\w*|exposure|endpoint|ips?|read|write|snapshots?|amis?|buckets?)',
          r'internet.?facing', r'open to the internet', r'0\.0\.0\.0/0', r'wildcard ?principal',
          r'anonymous ?access', r'\bpublic\b.*\b(restrict|disable|block)', r'(restrict|disable|block)\w*.*\bpublic\b'),
         None,
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
         'Verify the next rotation succeeds and consumers pick up the new value.'),
        ('authentication',
         (r'\bauthenticat\w*', r'\bauthoriz(ation|ers?)\b', r'\bunauthenticated\b', r'identity ?provider',
          r'\bidp\b', r'\bsso\b', r'\bfederat\w*', r'\biam ?auth', r'\boauth'),
         None,
         'Require an approved authentication method and test client sign-in.'),
        ('secrets_and_credentials',
         (r'\bsecrets?\b', r'access ?keys?', r'api ?keys?', r'\bcredentials?\b', r'\bpasswords?\b',
          r'plain.?text', r'hard.?coded'),
         r'description|purpose|version|replicat|staging|\bno ?secret\b|expir|\broot\b|remove|delete|compromised'
         r'|individual|identit|temporary|validity|resolves|valuefrom|reference',
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
         'Enable it in every active region and route findings to the security team.'),
        ('log_delivery',
         (r'\b(enable|send|stream|archive|deliver|publish|export|turn on|configure|set ?up)\b.*\b(logs?|logging|trail|audit)\b',
          r'\b(logs?|logging)\b.*\b(disabled|missing|not (enabled|configured))', r'flow ?logs?', r'access ?log',
          r'\bcloud ?trail\b.*\b(cloud ?watch|s3|log)'),
         r'insights|retention|metric|dashboard|analysis|validation|encrypt|group ?does ?not ?exist|log ?statement|error',
         'After enabling, confirm a test event appears at the log destination.'),
        ('upgrade_and_patch',
         (r'\bversions?\b', r'\bupgrade\w*', r'\bpatch\w*', r'\bdeprecat\w*', r'end.of.(support|life)', r'\beol\b',
          r'\boutdated\b', r'\bolder\b', r'\blatest\b', r'\bgeneration\b', r'\bruntime\b', r'\bunsupported\b'),
         r'versioning|api ?version|schema|revis|version ?stages?|versions ?excessive|policy ?version|label|delivery|error|pinned|unpin',
         'Test the upgrade first, then apply it in a maintenance window.'),
        ('autoscaling',
         (r'auto.?scal\w*', r'\bscaling\b'),
         r'storage ?autoscal',
         'Configure scaling policies with tested minimum and maximum bounds.'),
        ('capacity_and_quota',
         (r'\bquotas?\b', r'\blimits?\b', r'\bcapacity\b', r'\bthrottl\w*', r'\bthroughput\b', r'\bconcurren\w*',
          r'free ?storage', r'\bstorage\b.*\b(full|free|low|space)\b'),
         r'temp_file_limit|rate.?limit|no ?limit|unlimited|monitor|task.level|cpu and memory|resource ?limits|limit\w* (the )?(access|permission)',
         'Review current usage, then adjust capacity or request a quota increase.'),
        ('unused_cleanup',
         (r'\bunused\b', r'\binactive\b', r'\bidle\b', r'not ?(in ?use|used|attached)', r'\bunattached\b',
          r'\borphan\w*', r'\bstale\b', r'\bempty\b', r'no longer'),
         r'timeout|session|revis|version',
         'Confirm nothing depends on it, then remove it; snapshot or export first if the data matters.'),
        ('cost_optimization',
         (r'\bcosts?\b', r'right.?siz\w*', r'under.?utili\w*', r'savings ?plans?', r'\breserved\b',
          r'over.?siz\w*', r'\bcheaper\b', r'\bsavings?\b', r'\bdownsiz\w*'),
         r'report|explorer|budget',
         'Validate the saving against usage data before changing the resource.'),
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
        r'schedule|test|validate|confirm|clean|audit|evaluate|leverage|utilize|adopt|complete)\b',
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
    ) -> Mapping[str, str]:
        """Return ``summary``, ``instruction``, ``context`` (both may be empty) and ``family``.

        ``context`` is the "why it matters" text: hand-written for exact
        entries, otherwise the first description sentences that neither
        repeat the summary nor read as an instruction.
        """
        summary = cls._clean(detail.get('shortDesc'))
        if not summary:
            summary = cls._humanize_check(check)

        exact = cls._EXACT_GUIDANCE.get(f'{service}.{check}')
        instruction, context = exact if isinstance(exact, tuple) else (exact, '')
        family = 'exact' if instruction else None

        if not instruction:
            primary = f'{cls._humanize_check(check)} {summary}'.lower()
            family, instruction = cls._match_family(primary)

        if not instruction and len(summary.split()) <= cls._SHORT_SUMMARY_WORDS:
            first_sentence = cls._first_sentence(detail.get('^description'))
            if first_sentence:
                family, instruction = cls._match_family(first_sentence.lower())

        if instruction and family != 'exact' and cls._is_redundant(summary, instruction):
            instruction = ''

        why = []
        known = f'{summary} {instruction}'
        for sentence in cls._description_sentences(detail.get('^description')):
            if cls._NOISE_RE.match(sentence) or cls._is_redundant(known, sentence):
                continue
            if cls._ACTION_LEAD_RE.match(sentence):
                if not instruction:
                    instruction = sentence
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

        return {
            'summary': summary,
            'instruction': instruction or '',
            'context': context or '',
            'family': family or 'none',
        }

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
