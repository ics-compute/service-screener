// Data loading utilities for Service Screener

/**
 * Load report data from window.__REPORT_DATA__ or fetch from JSON file
 * This data is embedded in the HTML file during build or loaded dynamically
 * @returns {Promise<Object|null>} Report data or null if not available
 */
export const loadReportData = async () => {
  try {
    // First try to load from window.__REPORT_DATA__ (embedded data)
    if (typeof window !== 'undefined' && window.__REPORT_DATA__) {
      console.log('Report data loaded from window.__REPORT_DATA__');
      return window.__REPORT_DATA__;
    }

    // If not embedded, wait for it to be loaded (development mode)
    console.log('Waiting for report data to be loaded...');
    return new Promise((resolve, reject) => {
      // Check if data is available now
      if (window.__REPORT_DATA__) {
        resolve(window.__REPORT_DATA__);
        return;
      }

      // Wait for the reportDataReady event
      const timeout = setTimeout(() => {
        reject(new Error('Timeout waiting for report data'));
      }, 10000); // 10 second timeout

      window.addEventListener('reportDataReady', () => {
        clearTimeout(timeout);
        if (window.__REPORT_DATA__) {
          console.log('Report data loaded successfully');
          resolve(window.__REPORT_DATA__);
        } else {
          reject(new Error('Report data not available after event'));
        }
      }, { once: true });
    });
  } catch (error) {
    console.error('Error loading report data:', error);
    return null;
  }
};

/**
 * Discover available accounts from various sources
 * @returns {Array} Array of account objects with id and label
 */
export const discoverAccounts = () => {
  // In a real multi-account scenario, this would scan the directory structure
  // For now, return empty array as single-account is the default use case
  return [];
};

/**
 * Switch to a different account by navigating to its folder
 * @param {string} newAccountId - Target account ID
 */
export const switchAccount = (newAccountId) => {
  const currentPath = window.location.pathname;
  const currentHash = window.location.hash;

  // Pattern to match /aws/{12-digit-account}/
  const accountMatch = currentPath.match(/\/aws\/(\d{12})\//);

  if (accountMatch) {
    const currentAccountId = accountMatch[1];
    if (currentAccountId !== newAccountId) {
      // Replace account ID in path while preserving the rest
      const newPath = currentPath.replace(/\/aws\/\d{12}\//, `/aws/${newAccountId}/`);
      // Preserve hash for current page context
      window.location.href = newPath + currentHash;
    }
  } else {
    // Fallback: try to construct path to new account
    const pathParts = currentPath.split('/');
    const awsIndex = pathParts.findIndex(part => part === 'aws');

    if (awsIndex !== -1 && pathParts[awsIndex + 1]) {
      // Replace the account ID part
      pathParts[awsIndex + 1] = newAccountId;
      const newPath = pathParts.join('/');
      window.location.href = newPath + currentHash;
    } else {
      // Last resort: navigate to new account's index
      const protocol = window.location.protocol;
      const host = window.location.host;
      const basePath = currentPath.split('/').slice(0, -2).join('/'); // Remove filename and current account
      window.location.href = `${protocol}//${host}${basePath}/aws/${newAccountId}/index.html`;
    }
  }
};

/**
 * Extract account ID from report data or URL
 * @param {Object} data - Report data
 * @returns {string} Account ID or 'Unknown'
 */
export const getAccountId = (data) => {
  // First try to get from URL path (for multi-account scenarios)
  const currentPath = window.location.pathname;
  const accountMatch = currentPath.match(/\/aws\/(\d{12})\//);
  if (accountMatch) {
    return accountMatch[1];
  }

  // Account ID might be in metadata
  if (data && data.__metadata && data.__metadata.accountId) {
    return data.__metadata.accountId;
  }

  // Try to extract account ID from resource names
  // Look for patterns like "956288449190" in resource names
  for (const serviceName in data) {
    if (serviceName.startsWith('__') || serviceName.startsWith('framework_') || serviceName.startsWith('customPage_')) {
      continue;
    }

    const service = data[serviceName];
    if (service && service.detail) {
      for (const region in service.detail) {
        for (const resourceId in service.detail[region]) {
          // Extract account ID from resource names like "Bucket::aws-athena-query-results-ap-southeast-1-956288449190"
          const match = resourceId.match(/(\d{12})/);
          if (match) {
            return match[1];
          }
        }
      }
    }
  }

  return 'Unknown';
};

/**
 * Get list of all services from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of service names
 */
export const getServices = (data) => {
  if (!data) return [];

  // Filter out metadata, framework, and customPage keys
  return Object.keys(data).filter(key =>
    !key.startsWith('__') &&
    !key.startsWith('framework_') &&
    !key.startsWith('customPage_') &&
    typeof data[key] === 'object' &&
    data[key] !== null
  );
};

/**
 * Get list of all frameworks from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of framework names
 */
export const getFrameworks = (data) => {
  if (!data) return [];

  return Object.keys(data).filter(key => key.startsWith('framework_'));
};

/**
 * Get list of all custom pages from report data
 * @param {Object} data - Report data
 * @returns {Array<string>} Array of custom page names
 */
export const getCustomPages = (data) => {
  if (!data) return [];

  return Object.keys(data)
    .filter(key => key.startsWith('customPage_'))
    .map(key => key.replace('customPage_', ''));
};

/**
 * Get service data by service name
 * @param {Object} data - Report data
 * @param {string} serviceName - Service name
 * @returns {Object|null} Service data or null
 */
export const getServiceData = (data, serviceName) => {
  if (!data || !serviceName) return null;

  const serviceKey = serviceName.toLowerCase();
  return data[serviceKey] || null;
};

/**
 * Get framework data by framework name
 * @param {Object} data - Report data
 * @param {string} frameworkName - Framework name
 * @returns {Object|null} Framework data or null
 */
export const getFrameworkData = (data, frameworkName) => {
  if (!data || !frameworkName) return null;

  // Try exact match first
  const frameworkKey = frameworkName.startsWith('framework_')
    ? frameworkName
    : `framework_${frameworkName}`;

  if (data[frameworkKey]) {
    return data[frameworkKey];
  }

  // Try case-insensitive match
  const frameworkKeyUpper = frameworkName.startsWith('framework_')
    ? frameworkName.toUpperCase()
    : `framework_${frameworkName.toUpperCase()}`;

  if (data[frameworkKeyUpper]) {
    return data[frameworkKeyUpper];
  }

  // Try finding by case-insensitive search through all keys
  const lowerFrameworkName = frameworkName.toLowerCase().replace('framework_', '');
  const matchingKey = Object.keys(data).find(key => {
    if (!key.startsWith('framework_')) return false;
    const keyFrameworkName = key.replace('framework_', '').toLowerCase();
    return keyFrameworkName === lowerFrameworkName;
  });

  return matchingKey ? data[matchingKey] : null;
};

/**
 * Get all findings for a service
 * @param {Object} serviceData - Service data object
 * @returns {Array<Object>} Array of findings with metadata
 */
export const getServiceFindings = (serviceData) => {
  if (!serviceData || !serviceData.summary) return [];

  return Object.entries(serviceData.summary).map(([ruleName, finding]) => ({
    ruleName,
    ...finding
  }));
};

/**
 * Calculate dashboard statistics from report data
 * @param {Object} data - Report data
 * @returns {Object} Statistics object
 */
export const calculateDashboardStats = (data) => {
  const services = getServices(data);

  let totalFindings = 0;
  let highPriority = 0;
  let mediumPriority = 0;
  let lowPriority = 0;

  services.forEach(service => {
    const serviceData = data[service];
    if (serviceData && serviceData.summary) {
      Object.values(serviceData.summary).forEach(finding => {
        // Count affected resources instead of rules
        let resourceCount = 0;
        if (finding.__affectedResources) {
          // Sum up resources across all regions
          Object.values(finding.__affectedResources).forEach(resources => {
            if (Array.isArray(resources)) {
              resourceCount += resources.length;
            }
          });
        }

        // If no affected resources, count as 1 (the rule itself)
        if (resourceCount === 0) {
          resourceCount = 1;
        }

        totalFindings += resourceCount;

        switch (finding.criticality) {
          case 'H':
            highPriority += resourceCount;
            break;
          case 'M':
            mediumPriority += resourceCount;
            break;
          case 'L':
            lowPriority += resourceCount;
            break;
        }
      });
    }
  });

  return {
    totalServices: services.length,
    totalFindings,
    highPriority,
    mediumPriority,
    lowPriority
  };
};

/**
 * Get service statistics for dashboard cards
 * @param {Object} data - Report data
 * @returns {Array<Object>} Array of service statistics
 */
export const getServiceStats = (data) => {
  const services = getServices(data);

  return services.map(service => {
    const serviceData = data[service];
    const findings = getServiceFindings(serviceData);

    let totalResources = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    const categories = new Set();

    findings.forEach(finding => {
      // Count affected resources instead of rules
      let resourceCount = 0;
      if (finding.__affectedResources) {
        // Sum up resources across all regions
        Object.values(finding.__affectedResources).forEach(resources => {
          if (Array.isArray(resources)) {
            resourceCount += resources.length;
          }
        });
      }

      // If no affected resources, count as 1 (the rule itself)
      if (resourceCount === 0) {
        resourceCount = 1;
      }

      totalResources += resourceCount;

      switch (finding.criticality) {
        case 'H':
          high += resourceCount;
          break;
        case 'M':
          medium += resourceCount;
          break;
        case 'L':
          low += resourceCount;
          break;
      }

      if (finding.__categoryMain) {
        categories.add(finding.__categoryMain);
      }
    });

    return {
      serviceName: service,
      totalFindings: totalResources,
      high,
      medium,
      low,
      categories: Array.from(categories)
    };
  });
};

/**
 * Check if suppressions are active in the report
 * @param {Object} data - Report data
 * @returns {boolean} True if suppressions are active
 */
export const hasSuppressions = (data) => {
  if (!data || !data.__metadata || !data.__metadata.suppressions) return false;

  const suppressions = data.__metadata.suppressions;

  // Handle array format
  if (Array.isArray(suppressions)) {
    return suppressions.length > 0;
  }

  // Handle object format with serviceLevelSuppressions and resourceSuppressions
  if (typeof suppressions === 'object') {
    const hasServiceLevel = suppressions.serviceLevelSuppressions &&
                           suppressions.serviceLevelSuppressions.length > 0;
    const hasResourceLevel = suppressions.resourceSuppressions &&
                            suppressions.resourceSuppressions.length > 0;
    return hasServiceLevel || hasResourceLevel;
  }

  return false;
};

/**
 * Get suppression data from report
 * @param {Object} data - Report data
 * @returns {Object} Suppression data
 */
export const getSuppressions = (data) => {
  if (!data || !data.__metadata || !data.__metadata.suppressions) {
    return { serviceLevelSuppressions: [], resourceSuppressions: [] };
  }

  return data.__metadata.suppressions;
};

// --- Executive risk summary aggregation -------------------------------------
//
// Everything below feeds the Risk Summary page. Two things to know about the
// shape of the data being aggregated:
//
//  * Only failures reach api-full.json. Reporter._process() keeps a check only
//    when its status is -1, so there are no PASS records to count and a
//    pass/fail health ratio cannot be computed on the client. Severity-weighted
//    finding counts are used instead.
//  * `criticality` is only ever H, M, L or I -- there is no CRITICAL tier.

const SEVERITY_WEIGHT = { H: 3, M: 2, L: 1, I: 0 };

// Rank order for breaking impact-score ties, so a redraw cannot reshuffle rows
// that scored the same.
const SEVERITY_RANK = { H: 3, M: 2, L: 1, I: 0 };

/**
 * Count the resources one check affects, across every region.
 * Falls back to 1 so a check that reports no resource list still ranks.
 * @param {Object} finding - Reporter summary entry
 * @returns {number} Affected resource count
 */
const countFindingResources = (finding) => {
  const affected = finding.__affectedResources;
  if (!affected) return 1;

  const total = Object.values(affected).reduce(
    (sum, resources) => sum + (Array.isArray(resources) ? resources.length : 0),
    0
  );

  return total || 1;
};

/**
 * List region-qualified resource identifiers for a finding, for de-duplicating
 * resources across checks that get merged into one action.
 * @param {Object} affected - __affectedResources map
 * @returns {Array<string>} Region::identifier keys
 */
const collectResourceKeys = (affected) => {
  if (!affected) return [];

  const keys = [];
  Object.entries(affected).forEach(([region, resources]) => {
    if (Array.isArray(resources)) {
      resources.forEach(identifier => keys.push(`${region}::${identifier}`));
    }
  });

  return keys;
};

/**
 * Flatten every check of every service into one list of ranked findings.
 * @param {Object} data - Report data
 * @returns {Array<Object>} Findings with service, severity, resourceCount and impactScore
 */
export const getRankedFindings = (data) => {
  const findings = [];

  getServices(data).forEach(service => {
    const summary = data[service]?.summary;
    if (!summary) return;

    Object.entries(summary).forEach(([checkName, finding]) => {
      const severity = finding.criticality || 'I';
      const resourceCount = countFindingResources(finding);

      findings.push({
        checkName,
        service,
        severity,
        resourceCount,
        category: finding.__categoryMain || 'Other',
        shortDesc: finding.shortDesc || checkName,
        remediation: finding.remediation || null,
        remediationRisk: finding.remediation_risk || null,
        remediationDoc: finding.remediation_doc || null,
        remediationByResource: finding.__remediationByResource || null,
        affectedResources: finding.__affectedResources || null,
        impactScore: (SEVERITY_WEIGHT[severity] ?? 0) * resourceCount
      });
    });
  });

  return findings;
};

/**
 * Collapse findings that describe the same work into one entry.
 *
 * Distinct checks can carry an identical shortDesc, and separately can share one
 * remediation command -- IAM's passwordPolicyLength and passwordPolicyWeak do
 * both. Presenting them as separate rows reads as a duplicate, so they are
 * merged on service plus whichever identity they share, with the resource count
 * taken as the number of DISTINCT resources so a single underlying resource is
 * not counted once per check.
 *
 * @param {Array<Object>} findings - Findings from getRankedFindings
 * @param {Function} identity - Maps a finding to its merge key
 * @returns {Array<Object>} Merged findings, each carrying mergedChecks
 */
const mergeFindings = (findings, identity) => {
  const merged = new Map();

  findings.forEach(finding => {
    const key = identity(finding);
    const existing = merged.get(key);

    if (!existing) {
      merged.set(key, {
        ...finding,
        mergedChecks: [finding.checkName],
        _resourceKeys: new Set(collectResourceKeys(finding.affectedResources))
      });
      return;
    }

    collectResourceKeys(finding.affectedResources).forEach(k => existing._resourceKeys.add(k));
    existing.mergedChecks.push(finding.checkName);

    // Keep the highest severity of the merged set, so a merge never understates risk.
    if ((SEVERITY_WEIGHT[finding.severity] ?? 0) > (SEVERITY_WEIGHT[existing.severity] ?? 0)) {
      existing.severity = finding.severity;
    }
  });

  return [...merged.values()].map(finding => {
    const resourceCount = finding._resourceKeys.size || finding.resourceCount;
    delete finding._resourceKeys;

    return {
      ...finding,
      resourceCount,
      impactScore: (SEVERITY_WEIGHT[finding.severity] ?? 0) * resourceCount
    };
  });
};

/**
 * Findings ranked for display, with same-work duplicates collapsed.
 *
 * Merges on service + description, since two checks sharing a description are
 * one line of work to the reader even when their rule names differ.
 *
 * @param {Object} data - Report data
 * @returns {Array<Object>} Merged findings, highest impact first
 */
export const getTopFindings = (data) => {
  const merged = mergeFindings(
    getRankedFindings(data),
    finding => `${finding.service}::${finding.shortDesc}`
  );

  return sortByImpact(merged);
};

/**
 * Sort findings by impact, breaking ties on severity then name for stability.
 * @param {Array<Object>} findings - Findings from getRankedFindings
 * @returns {Array<Object>} New sorted array, highest impact first
 */
export const sortByImpact = (findings) => {
  return [...findings].sort((a, b) => {
    if (b.impactScore !== a.impactScore) return b.impactScore - a.impactScore;

    const rankDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (rankDiff !== 0) return rankDiff;

    return a.checkName.localeCompare(b.checkName);
  });
};

/**
 * Account-wide totals for the risk posture strip.
 * Counts affected resources, not rules, to match the rest of the UI.
 * @param {Object} data - Report data
 * @returns {Object} Severity totals plus service, resource and remediable counts
 */
export const getRiskPosture = (data) => {
  const findings = getRankedFindings(data);
  const posture = {
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    totalFindings: 0,
    totalChecks: findings.length,
    totalServices: getServices(data).length,
    totalResources: 0,
    remediableChecks: 0,
    lowRiskRemediableChecks: 0
  };

  findings.forEach(finding => {
    posture.totalFindings += finding.resourceCount;

    switch (finding.severity) {
      case 'H': posture.high += finding.resourceCount; break;
      case 'M': posture.medium += finding.resourceCount; break;
      case 'L': posture.low += finding.resourceCount; break;
      default: posture.informational += finding.resourceCount; break;
    }

    if (finding.remediation) {
      posture.remediableChecks += 1;
      if (finding.remediationRisk === 'low') posture.lowRiskRemediableChecks += 1;
    }
  });

  // Scanned resource totals come from the per-service stat files, which count
  // resources inspected rather than resources that failed something.
  getServices(data).forEach(service => {
    posture.totalResources += data[service]?.stats?.resources || 0;
  });

  return posture;
};

/**
 * Findings that ship a runnable CLI command, ranked by impact.
 *
 * Prefers low-risk remediations and falls back to the remaining risk levels
 * when a scan has none -- most checks are not yet enriched with a low-risk
 * command, so a strict low-risk filter empties the section on real accounts.
 *
 * @param {Object} data - Report data
 * @param {number} limit - Maximum rows to return
 * @returns {Object} { items, riskLevel, fallback } where riskLevel is 'low' or 'other'
 */
export const getQuickWins = (data, limit = 10) => {
  const remediable = getRankedFindings(data).filter(finding => finding.remediation);

  const lowRisk = remediable.filter(finding => finding.remediationRisk === 'low');
  const usingLowRisk = lowRisk.length > 0;
  const pool = usingLowRisk ? lowRisk : remediable;

  // Merge on the command rather than the description: two checks that resolve
  // with the same command are one action to run, so they belong on one row.
  const items = mergeFindings(pool, finding => `${finding.service}::${finding.remediation}`);

  return {
    items: sortByImpact(items).slice(0, limit),
    riskLevel: usingLowRisk ? 'low' : 'other',
    fallback: !usingLowRisk && remediable.length > 0,
    totalAvailable: items.length
  };
};

/**
 * Per-region risk breakdown, ranked worst-first.
 *
 * The point of this view is the region a user does not think about: a scan
 * covering several regions can turn up more high-severity findings in an
 * incidental region than in the one the team works in daily, and no other page
 * separates findings by region.
 *
 * Scope limit, surfaced in the UI by `scannedRegions`: only regions passed to
 * --regions are ever called, so a region absent from the scan contributes
 * nothing here. This ranks what was looked at; it cannot reveal an unscanned
 * region.
 *
 * `GLOBAL` is reported separately from real regions -- it is where global
 * services such as IAM land, so folding it in would make it outrank every
 * region while telling the user nothing about geography.
 *
 * @param {Object} data - Report data
 * @returns {Object} { regions, global, scannedRegions, maxWeight, hasRegionalFindings }
 */
export const getRegionRisk = (data) => {
  const byRegion = {};

  getServices(data).forEach(service => {
    const summary = data[service]?.summary;
    if (!summary) return;

    Object.values(summary).forEach(finding => {
      const severity = finding.criticality || 'I';
      const weight = SEVERITY_WEIGHT[severity] ?? 0;

      Object.entries(finding.__affectedResources || {}).forEach(([region, resources]) => {
        const count = Array.isArray(resources) ? resources.length : 0;
        if (!count) return;

        if (!byRegion[region]) {
          byRegion[region] = {
            region,
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0,
            weight: 0,
            services: new Set()
          };
        }

        const entry = byRegion[region];
        entry.total += count;
        entry.weight += weight * count;
        entry.services.add(service);

        switch (severity) {
          case 'H': entry.high += count; break;
          case 'M': entry.medium += count; break;
          case 'L': entry.low += count; break;
          default: entry.informational += count; break;
        }
      });
    });
  });

  const finalise = (entry) => ({
    ...entry,
    serviceCount: entry.services.size,
    services: [...entry.services].sort()
  });

  const all = Object.values(byRegion).map(finalise);
  const regions = all
    .filter(entry => entry.region !== 'GLOBAL')
    .sort((a, b) => b.weight - a.weight || a.region.localeCompare(b.region));

  return {
    regions,
    global: all.find(entry => entry.region === 'GLOBAL') || null,
    scannedRegions: data?.__metadata?.regions || [],
    maxWeight: regions.reduce((max, entry) => Math.max(max, entry.weight), 0),
    hasRegionalFindings: regions.length > 0
  };
};

/**
 * Service x Well-Architected pillar matrix of severity-weighted findings.
 *
 * Neither existing view crosses these two axes: the dashboard's category cards
 * collapse services, and its service cards collapse pillars. `weight` drives
 * the heat gradient; `count` is the human-readable resource total.
 *
 * @param {Object} data - Report data
 * @returns {Object} { pillars, rows, maxWeight }
 */
export const getServicePillarMatrix = (data) => {
  const pillars = ['S', 'R', 'C', 'P', 'O'];
  const findings = getRankedFindings(data);
  const byService = {};
  let maxWeight = 0;

  findings.forEach(finding => {
    // 'T' is an internal category and is not shown anywhere in the UI.
    if (finding.category === 'T' || !pillars.includes(finding.category)) return;

    if (!byService[finding.service]) {
      byService[finding.service] = {
        service: finding.service,
        cells: {},
        totalCount: 0,
        totalWeight: 0
      };
    }

    const row = byService[finding.service];
    const cell = row.cells[finding.category] || { count: 0, weight: 0 };

    cell.count += finding.resourceCount;
    cell.weight += finding.impactScore;
    row.cells[finding.category] = cell;

    row.totalCount += finding.resourceCount;
    row.totalWeight += finding.impactScore;

    if (cell.weight > maxWeight) maxWeight = cell.weight;
  });

  const rows = Object.values(byService).sort((a, b) => b.totalWeight - a.totalWeight);

  return { pillars, rows, maxWeight };
};

/**
 * Lowest-scoring frameworks, for the compliance strip.
 *
 * Reuses the precomputed `summary.mcn` triple ([notAvailable, compliant,
 * needAttention]) that FrameworkOverview scores from, so the two pages cannot
 * disagree. `assessed` excludes not-available controls, which is why coverage
 * is reported alongside the percentage -- a high score over a small assessed
 * set is not the same as broad compliance.
 *
 * @param {Object} data - Report data
 * @param {number} limit - Maximum frameworks to return
 * @returns {Object} { worst, overallPct, frameworkCount }
 */
export const getFrameworkLowlights = (data, limit = 3) => {
  const scored = getFrameworks(data).map(key => {
    const name = key.replace('framework_', '');
    const mcn = data[key]?.summary?.mcn;

    if (!mcn) return null;

    const [notAvailable, compliant, needAttention] = mcn;
    const assessed = compliant + needAttention;
    const total = notAvailable + assessed;

    return {
      name,
      fullname: data[key]?.metadata?.fullname || name,
      compliant,
      needAttention,
      notAvailable,
      assessed,
      total,
      pct: assessed > 0 ? Math.round((compliant / assessed) * 100) : null
    };
  }).filter(Boolean);

  const totals = scored.reduce(
    (acc, f) => ({ compliant: acc.compliant + f.compliant, assessed: acc.assessed + f.assessed }),
    { compliant: 0, assessed: 0 }
  );

  const worst = scored
    .filter(f => f.pct !== null)
    .sort((a, b) => a.pct - b.pct || a.name.localeCompare(b.name))
    .slice(0, limit);

  return {
    worst,
    overallPct: totals.assessed > 0 ? Math.round((totals.compliant / totals.assessed) * 100) : null,
    frameworkCount: scored.length
  };
};

/**
 * Cost Optimization Hub headline figures for the teaser strip.
 *
 * Returns null when the account is not enrolled or collection failed, so the
 * caller hides the section rather than rendering a misleading $0.
 *
 * @param {Object} data - Report data
 * @returns {Object|null} Headline savings figures, or null when unavailable
 */
export const getCostHighlights = (data) => {
  const coh = data?.customPage_coh;
  const summary = coh?.executive_summary;

  if (!summary || !Object.keys(summary).length) return null;

  const monthly = summary.total_monthly_savings || 0;
  const recommendations = summary.total_recommendations || 0;

  if (!monthly && !recommendations) return null;

  const phaseOne = (summary.implementation_roadmap || [])[0] || null;

  return {
    monthlySavings: monthly,
    annualSavings: summary.total_annual_savings || monthly * 12,
    recommendations,
    highPriority: summary.high_priority_count || 0,
    phaseOne: phaseOne && {
      phase: phaseOne.phase,
      timeframe: phaseOne.timeframe,
      count: phaseOne.count,
      savings: phaseOne.total_savings
    }
  };
};

/**
 * Get category statistics with severity breakdown
 * @param {Object} data - Report data
 * @returns {Array<Object>} Array of category statistics
 */
export const getCategoryStats = (data) => {
  const services = getServices(data);
  const categoryMap = {};

  services.forEach(service => {
    const serviceData = data[service];
    if (serviceData && serviceData.summary) {
      Object.values(serviceData.summary).forEach(finding => {
        const category = finding.__categoryMain || 'Other';
        if (category === 'T') return;
        const severity = finding.criticality || 'I';

        // Count affected resources instead of rules
        let resourceCount = 0;
        if (finding.__affectedResources) {
          // Sum up resources across all regions
          Object.values(finding.__affectedResources).forEach(resources => {
            if (Array.isArray(resources)) {
              resourceCount += resources.length;
            }
          });
        }

        // If no affected resources, count as 1 (the rule itself)
        if (resourceCount === 0) {
          resourceCount = 1;
        }

        if (!categoryMap[category]) {
          categoryMap[category] = {
            category,
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0
          };
        }

        categoryMap[category].total += resourceCount;

        switch (severity) {
          case 'H':
            categoryMap[category].high += resourceCount;
            break;
          case 'M':
            categoryMap[category].medium += resourceCount;
            break;
          case 'L':
            categoryMap[category].low += resourceCount;
            break;
          case 'I':
            categoryMap[category].informational += resourceCount;
            break;
        }
      });
    }
  });

  // Convert to array, filter out 'T' category, and sort by total (descending)
  return Object.values(categoryMap)
    .sort((a, b) => b.total - a.total);
};
