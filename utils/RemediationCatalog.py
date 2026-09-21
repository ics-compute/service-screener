"""Safe, concise remediation guidance for Service Screener findings.

This module intentionally produces operator guidance rather than inventing AWS CLI
commands. A runnable command is emitted only when the source reporter definition
contains a reviewed remediation template and RemediationResolver can resolve it.
"""

import re
from typing import Any, Mapping


class RemediationCatalog:
    """Resolve a finding into concise, service-aware manual remediation guidance."""

    _EXACT_GUIDANCE = {
        'cloudwatch.SetRetentionDays': (
            'Set the log group retention period to meet the logging policy; use at '
            'least 365 days when the CIS retention requirement applies.'
        ),
        'cloudwatch.CISRetentionAtLeast1Yr': (
            'Set the log group retention period to at least 365 days.'
        ),
    }

    _FAMILIES = (
        (
            'waf_association',
            ('notassociated', 'withoutwebacl', 'web acl association'),
            'Associate the approved Web ACL with the protected resource and validate legitimate traffic.',
        ),
        (
            'waf_visibility',
            ('wafv2logging', 'web acl logging', 'visibilityconfig', 'sampledrequests', 'metricsenabled'),
            'Enable the required Web ACL logging, metrics, or sampled requests and validate the log destination permissions.',
        ),
        (
            'waf_protection',
            ('ratebased', 'sqli', 'xss', 'managedrule', 'knownbad', 'botcontrol', 'fraud', 'core rule'),
            'Add or tune the recommended Web ACL protection in Count mode, review matches, then enforce it through change control.',
        ),
        (
            'encryption',
            ('encrypt', 'encryption', 'kms key', 'at rest', 'in transit'),
            'Enable the required encryption using an approved key or transport setting, then verify access still works.',
        ),
        (
            'public_network_access',
            ('public access', 'publicly accessible', 'public exposure', 'internet-facing', 'open to the internet'),
            'Restrict public exposure to approved identities and networks, then test the required application paths.',
        ),
        (
            'network_controls',
            ('security group', 'ingress', 'egress', 'vpc', 'subnet', 'network acl', 'firewall'),
            'Restrict network access to approved sources, destinations, ports, and protocols; validate dependent workloads.',
        ),
        (
            'identity_and_access',
            ('mfa', 'multi-factor', 'password', 'credential', 'root user', 'iam policy', 'least privilege', 'permission', 'identity provider', 'federat'),
            'Apply the required authentication or least-privilege control, then confirm intended user and workload access.',
        ),
        (
            'secrets',
            ('secret', 'access key', 'api key', 'token rotation'),
            'Rotate or secure the credential through the approved secret-management process and update dependent workloads safely.',
        ),
        (
            'logging_and_monitoring',
            ('cloudtrail', 'logging', 'log group', 'log delivery', 'audit log', 'monitoring', 'alarm', 'metric', 'dashboard', 'notification'),
            'Configure the required logging, monitoring, or alerting control and verify that an expected test event is recorded or notified.',
        ),
        (
            'retention',
            ('retention', 'expire', 'lifecycle'),
            'Set the retention or lifecycle policy to the approved duration and verify it applies to the affected resource.',
        ),
        (
            'backup_and_recovery',
            ('backup', 'snapshot', 'restore', 'recovery point'),
            'Configure automated backups and retention to meet the recovery objective, then test a restore procedure.',
        ),
        (
            'availability_and_failover',
            ('multi-az', 'multi az', 'failover', 'replica', 'replication', 'availability zone', 'disaster recovery'),
            'Enable the required resilience configuration and validate failover or recovery using an approved test plan.',
        ),
        (
            'upgrade_and_patch',
            ('version', 'upgrade', 'patch', 'deprecated', 'end of support', 'generation'),
            'Plan, test, and deploy a supported version or configuration upgrade during an approved maintenance window.',
        ),
        (
            'capacity_and_quota',
            ('quota', 'limit', 'capacity', 'scaling', 'throttl', 'utilization'),
            'Review current demand and quotas, then adjust capacity or request the required quota through change control.',
        ),
        (
            'tagging',
            ('tag', 'cost allocation'),
            'Apply the required ownership, environment, and cost-allocation tags, then verify tag-policy compliance.',
        ),
        (
            'certificate_and_tls',
            ('certificate', 'tls', 'ssl', 'https'),
            'Require a supported TLS configuration and renew, replace, or correctly attach the approved certificate.',
        ),
        (
            'cost_optimization',
            ('cost', 'rightsiz', 'unused', 'idle', 'underutil', 'savings plan', 'reserved instance'),
            'Review utilization and dependencies, then resize, retire, or purchase capacity only after the impact is approved.',
        ),
        (
            'configuration_defaults',
            ('default', 'baseline', 'configuration', 'setting'),
            'Update the resource configuration to the approved baseline and validate the change in a non-production path where possible.',
        ),
    )

    @classmethod
    def get_guidance(
        cls,
        service: str,
        check: str,
        detail: Mapping[str, Any],
    ) -> Mapping[str, str]:
        """Return a concise finding summary and safe manual remediation action."""
        summary = cls._normalize(detail.get('shortDesc'))
        if not summary:
            summary = cls._humanize_check(check)

        finding_key = f'{service}.{check}'
        instruction = cls._EXACT_GUIDANCE.get(finding_key)
        family = 'exact' if instruction else 'fallback'

        if not instruction:
            searchable = ' '.join((
                service,
                check,
                summary,
                cls._normalize(detail.get('^description')),
            )).lower()
            for family_name, terms, family_instruction in cls._FAMILIES:
                if any(term in searchable for term in terms):
                    instruction = family_instruction
                    family = family_name
                    break

        if not instruction:
            instruction = (
                f'Update the resource configuration to satisfy "{summary}" using '
                'the approved console or infrastructure-as-code workflow.'
            )

        return {
            'summary': summary,
            'instruction': instruction,
            'family': family,
        }

    @staticmethod
    def _normalize(value: Any) -> str:
        return re.sub(r'\s+', ' ', str(value or '')).strip()

    @classmethod
    def _humanize_check(cls, check: str) -> str:
        words = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', check.replace('_', ' '))
        return cls._normalize(words) or 'Review the reported configuration'
