import { describe, it, expect } from 'vitest';

import {
  getCostHighlights,
  getFrameworkLowlights,
  getQuickWins,
  getRankedFindings,
  getRegionRisk,
  getRiskPosture,
  getServicePillarMatrix,
  getTopFindings,
  sortByImpact
} from '../utils/dataLoader';
import { REPORT, REPORT_WITHOUT_COH, REPORT_GLOBAL_ONLY } from './fixtures/report';

describe('getRiskPosture', () => {
  it('counts affected resources by severity, not rules', () => {
    const posture = getRiskPosture(REPORT);

    // ec2 openSecurityGroup 22 + iam rootMfa 1
    expect(posture.high).toBe(23);
    // ec2 unencryptedVolume 6 + s3 versioning 3 + two password checks 1 each
    expect(posture.medium).toBe(11);
    expect(posture.low).toBe(4);
    expect(posture.totalFindings).toBe(38);
  });

  it('reports remediable checks and how many are low risk', () => {
    const posture = getRiskPosture(REPORT);

    expect(posture.remediableChecks).toBe(2);
    expect(posture.lowRiskRemediableChecks).toBe(0);
  });

  it('sums scanned resources from the per-service stats', () => {
    expect(getRiskPosture(REPORT).totalResources).toBe(60);
  });
});

describe('sortByImpact', () => {
  it('ranks on severity weight times resource count', () => {
    const ranked = sortByImpact(getRankedFindings(REPORT));

    // 20 high-severity resources outrank everything else.
    expect(ranked[0].checkName).toBe('openSecurityGroup');
    expect(ranked[0].impactScore).toBe(66); // 3 * 22
  });

  it('breaks ties deterministically so redraws do not reshuffle', () => {
    const first = sortByImpact(getRankedFindings(REPORT)).map(f => f.checkName);
    const second = sortByImpact(getRankedFindings(REPORT)).map(f => f.checkName);

    expect(first).toEqual(second);
  });
});

describe('getTopFindings', () => {
  it('collapses checks that share a description into one row', () => {
    const merged = getTopFindings(REPORT)
      .filter(f => f.shortDesc === 'Set a stronger password policy');

    expect(merged).toHaveLength(1);
    expect(merged[0].mergedChecks).toEqual(['passwordPolicyLength', 'passwordPolicyWeak']);
  });

  it('counts a resource once when merged checks share it', () => {
    const [merged] = getTopFindings(REPORT)
      .filter(f => f.shortDesc === 'Set a stronger password policy');

    expect(merged.resourceCount).toBe(1);
  });

  it('keeps the highest severity of a merged group', () => {
    const mixed = JSON.parse(JSON.stringify(REPORT));
    // Same description, differing severity: the merged row must not downgrade.
    mixed.iam.summary.passwordPolicyWeak.criticality = 'H';

    const [merged] = getTopFindings(mixed)
      .filter(f => f.shortDesc === 'Set a stronger password policy');

    expect(merged.severity).toBe('H');
  });

  it('still ranks by impact after merging', () => {
    expect(getTopFindings(REPORT)[0].checkName).toBe('openSecurityGroup');
  });
});

describe('getQuickWins', () => {
  it('collapses checks that share one remediation command', () => {
    const { items } = getQuickWins(REPORT);

    expect(items).toHaveLength(1);
    expect(items[0].mergedChecks).toEqual(['passwordPolicyLength', 'passwordPolicyWeak']);
  });

  it('counts the shared resource once rather than twice', () => {
    const { items } = getQuickWins(REPORT);

    // Both checks flag the single account password policy.
    expect(items[0].resourceCount).toBe(1);
  });

  it('falls back to higher-risk fixes when none are low risk', () => {
    const result = getQuickWins(REPORT);

    expect(result.riskLevel).toBe('other');
    expect(result.fallback).toBe(true);
  });

  it('prefers low-risk fixes when they exist', () => {
    const withLowRisk = JSON.parse(JSON.stringify(REPORT));
    withLowRisk.s3.summary.bucketVersioning.remediation = 'aws s3api put-bucket-versioning';
    withLowRisk.s3.summary.bucketVersioning.remediation_risk = 'low';

    const result = getQuickWins(withLowRisk);

    expect(result.riskLevel).toBe('low');
    expect(result.fallback).toBe(false);
    expect(result.items.every(item => item.remediationRisk === 'low')).toBe(true);
  });
});

describe('getRegionRisk', () => {
  it('ranks a secondary region above the primary when it carries more risk', () => {
    const { regions } = getRegionRisk(REPORT);

    expect(regions[0].region).toBe('us-east-1');
    expect(regions[0].high).toBe(20);
    expect(regions[1].region).toBe('ap-southeast-1');
  });

  it('reports GLOBAL separately so it cannot outrank real regions', () => {
    const { regions, global } = getRegionRisk(REPORT);

    expect(regions.map(r => r.region)).not.toContain('GLOBAL');
    expect(global.total).toBe(3);
  });

  it('exposes the scanned region list for coverage disclosure', () => {
    expect(getRegionRisk(REPORT).scannedRegions).toEqual(['ap-southeast-1', 'us-east-1']);
  });

  it('counts distinct services per region', () => {
    const { regions } = getRegionRisk(REPORT);
    const primary = regions.find(r => r.region === 'ap-southeast-1');

    expect(primary.serviceCount).toBe(2); // ec2 and s3
  });

  it('reports no regional findings for a global-only scan', () => {
    const result = getRegionRisk(REPORT_GLOBAL_ONLY);

    expect(result.hasRegionalFindings).toBe(false);
    expect(result.regions).toEqual([]);
  });
});

describe('getServicePillarMatrix', () => {
  it('crosses service against pillar', () => {
    const { rows } = getServicePillarMatrix(REPORT);
    const ec2 = rows.find(r => r.service === 'ec2');

    expect(ec2.cells.S.count).toBe(28); // 22 security group + 6 volumes
    expect(ec2.cells.O.count).toBe(4);
  });

  it('orders rows by weighted risk', () => {
    const { rows } = getServicePillarMatrix(REPORT);

    expect(rows[0].service).toBe('ec2');
  });
});

describe('getFrameworkLowlights', () => {
  it('scores on assessed controls and reports coverage alongside', () => {
    const { worst } = getFrameworkLowlights(REPORT);
    const nist = worst.find(f => f.name === 'NIST');

    expect(nist.pct).toBe(90);      // 18 of 20 assessed
    expect(nist.assessed).toBe(20);
    expect(nist.total).toBe(120);   // 100 not available
  });

  it('sorts lowest-scoring first', () => {
    const { worst } = getFrameworkLowlights(REPORT);

    expect(worst[0].name).toBe('CIS'); // 30/36 = 83%
  });
});

describe('getCostHighlights', () => {
  it('surfaces the headline savings and first roadmap phase', () => {
    const cost = getCostHighlights(REPORT);

    expect(cost.monthlySavings).toBe(25.5);
    expect(cost.annualSavings).toBe(306);
    expect(cost.phaseOne.count).toBe(2);
  });

  it('returns null when Cost Optimization Hub produced nothing', () => {
    // Guards the $0 regression: an unavailable COH must hide the section, not
    // render zeroes as though the account had nothing to save.
    expect(getCostHighlights(REPORT_WITHOUT_COH)).toBeNull();
  });

  it('returns null when the report has no COH key at all', () => {
    expect(getCostHighlights({ __metadata: {} })).toBeNull();
  });
});
