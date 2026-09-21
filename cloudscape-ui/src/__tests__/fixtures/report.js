/**
 * Synthetic report fixture shaped like api-full.json.
 *
 * Hand-built rather than captured from a real scan so it carries no account
 * data, and so each aggregation edge case is deliberate:
 *
 *  * two regions where the SECONDARY one (us-east-1) carries more
 *    high-severity findings than the primary -- the "forgotten region" case
 *  * a global service (iam) whose findings sit under the GLOBAL key
 *  * two checks sharing one remediation command, which must collapse to a
 *    single recommended action
 *  * a framework with a large not-available count, so coverage reporting is
 *    exercised
 *  * criticality values limited to H/M/L/I, matching the real reporter
 */

const check = ({
  severity,
  shortDesc,
  category = 'S',
  resources,
  remediation = null,
  remediationRisk = null
}) => ({
  '^description': `<b>${shortDesc}</b> long form description`,
  shortDesc,
  criticality: severity,
  downtime: 0,
  slowness: 0,
  additionalCost: 0,
  needFullTest: 0,
  remediation,
  remediation_risk: remediationRisk,
  remediation_doc: 'https://docs.aws.amazon.com/',
  __categoryMain: category,
  __links: [],
  __affectedResources: resources
});

const range = (prefix, n) => Array.from({ length: n }, (_, i) => `${prefix}-${i}`);

export const REPORT = {
  __metadata: {
    accountId: '000000000000',
    regions: ['ap-southeast-1', 'us-east-1'],
    suppressions: { serviceLevelSuppressions: [], resourceSuppressions: [] }
  },

  ec2: {
    stats: { resources: 40, rules: 120, exceptions: 0, timespent: 5, suppressed: 0 },
    detail: {},
    summary: {
      // us-east-1 deliberately far worse than the primary region.
      openSecurityGroup: check({
        severity: 'H',
        shortDesc: 'Restrict open security groups',
        resources: {
          'us-east-1': range('sg', 20),
          'ap-southeast-1': range('sg-primary', 2)
        }
      }),
      unencryptedVolume: check({
        severity: 'M',
        shortDesc: 'Encrypt EBS volumes',
        category: 'S',
        resources: { 'us-east-1': range('vol', 6) }
      }),
      oldAmi: check({
        severity: 'L',
        shortDesc: 'Update to a newer AMI',
        category: 'O',
        resources: { 'ap-southeast-1': range('i', 4) }
      })
    }
  },

  s3: {
    stats: { resources: 12, rules: 40, exceptions: 0, timespent: 2, suppressed: 0 },
    detail: {},
    summary: {
      bucketVersioning: check({
        severity: 'M',
        shortDesc: 'Enable bucket versioning',
        category: 'R',
        resources: { 'ap-southeast-1': range('bucket', 3) }
      })
    }
  },

  iam: {
    stats: { resources: 8, rules: 30, exceptions: 0, timespent: 1, suppressed: 0 },
    detail: {},
    summary: {
      rootMfaActive: check({
        severity: 'H',
        shortDesc: 'Enable MFA on root user',
        resources: { GLOBAL: ['User::<b>root</b>'] }
      }),
      // These two share one command: fixing either fixes both, so the
      // recommended-actions list must show one row, one resource.
      passwordPolicyLength: check({
        severity: 'M',
        shortDesc: 'Set a stronger password policy',
        resources: { GLOBAL: ['AccountPasswordPolicy'] },
        remediation: 'aws iam update-account-password-policy --minimum-password-length 14',
        remediationRisk: 'medium'
      }),
      passwordPolicyWeak: check({
        severity: 'M',
        shortDesc: 'Set a stronger password policy',
        resources: { GLOBAL: ['AccountPasswordPolicy'] },
        remediation: 'aws iam update-account-password-policy --minimum-password-length 14',
        remediationRisk: 'medium'
      })
    }
  },

  framework_CIS: {
    metadata: { originator: 'CIS', fullname: 'CIS AWS Foundations Benchmark' },
    summary: { mcn: [1, 30, 6], stats: {} },
    details: {}
  },
  // Large not-available count: scores 90% on assessed controls but covers only
  // 20 of 120, which the UI has to disclose rather than report as broad health.
  framework_NIST: {
    metadata: { originator: 'NIST', fullname: 'NIST Cybersecurity Framework' },
    summary: { mcn: [100, 18, 2], stats: {} },
    details: {}
  },

  customPage_coh: {
    executive_summary: {
      total_recommendations: 4,
      total_monthly_savings: 25.5,
      total_annual_savings: 306,
      high_priority_count: 2,
      medium_priority_count: 2,
      low_priority_count: 0,
      top_categories: [],
      implementation_roadmap: [
        {
          phase: 'Phase 1: Quick Wins',
          timeframe: '0-30 days',
          count: 2,
          total_savings: 15.5,
          description: 'High impact, low effort'
        }
      ],
      data_freshness: '2026-01-01T00:00:00'
    },
    recommendations: [{ id: 'r1', monthly_savings: 15.5 }],
    error_messages: [],
    data_collection_time: '2026-01-01T00:00:00'
  }
};

/** A report where Cost Optimization Hub produced nothing. */
export const REPORT_WITHOUT_COH = {
  ...REPORT,
  customPage_coh: {
    executive_summary: {},
    recommendations: [],
    error_messages: ['No Cost Optimization Hub data available'],
    data_collection_time: null
  }
};

/** A report whose only findings come from a global service. */
export const REPORT_GLOBAL_ONLY = {
  __metadata: { accountId: '000000000000', regions: ['ap-southeast-1'] },
  iam: REPORT.iam
};

/** Build a report spanning `count` services, for pagination checks. */
export const manyServices = (count) => {
  const out = { __metadata: { accountId: '000000000000', regions: ['ap-southeast-1'] } };

  for (let i = 0; i < count; i += 1) {
    out[`service${String(i).padStart(2, '0')}`] = {
      stats: { resources: 5, rules: 10, exceptions: 0, timespent: 1, suppressed: 0 },
      detail: {},
      summary: {
        someCheck: check({
          severity: i % 3 === 0 ? 'H' : 'L',
          shortDesc: `Finding in service ${i}`,
          resources: { 'ap-southeast-1': range('r', (i % 4) + 1) }
        })
      }
    };
  }

  return out;
};
