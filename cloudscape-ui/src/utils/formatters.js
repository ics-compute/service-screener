// Formatting utilities for Service Screener data

import {
  CRITICALITY,
  CRITICALITY_COLORS,
  CATEGORY_MAIN,
  CATEGORY_COLORS,
  CATEGORY_STYLES,
  COMPLIANCE_STATUS,
  COMPLIANCE_COLORS,
  IMPACT_TAGS
} from './constants';

/**
 * Format criticality level to human-readable text
 * @param {string} criticality - H, M, L, or I
 * @returns {string} Human-readable criticality
 */
export const formatCriticality = (criticality) => {
  return CRITICALITY[criticality] || criticality;
};

/**
 * Get color for criticality badge
 * @param {string} criticality - H, M, L, or I
 * @returns {string} Cloudscape badge color
 */
export const getCriticalityColor = (criticality) => {
  return CRITICALITY_COLORS[criticality] || 'grey';
};

/**
 * Format category code to human-readable text
 * @param {string} category - R, S, O, P, or C
 * @returns {string} Human-readable category
 */
export const formatCategory = (category) => {
  return CATEGORY_MAIN[category] || category;
};

/**
 * Get color for category badge
 * @param {string} category - R, S, O, P, or C
 * @returns {string} Cloudscape badge color
 */
export const getCategoryColor = (category) => {
  return CATEGORY_COLORS[category] || 'grey';
};

/**
 * Get custom style for category badge
 * @param {string} category - R, S, O, P, or C
 * @returns {Object} Style object with backgroundColor and color
 */
export const getCategoryStyle = (category) => {
  return CATEGORY_STYLES[category] || { backgroundColor: '#545b64', color: 'white' };
};

/**
 * Filter out internal categories (T) from category list
 * @param {Array<string>} categories - Array of category codes
 * @returns {Array<string>} Filtered categories excluding T
 */
export const filterUserCategories = (categories) => {
  return categories.filter(category => category !== 'T');
};

/**
 * Format compliance status code to human-readable text
 * @param {number} status - 0, 1, or 2
 * @returns {string} Human-readable compliance status
 */
export const formatComplianceStatus = (status) => {
  return COMPLIANCE_STATUS[status] || 'Unknown';
};

/**
 * Get color for compliance status badge
 * @param {number} status - 0, 1, or 2
 * @returns {string} Cloudscape badge color
 */
export const getComplianceColor = (status) => {
  return COMPLIANCE_COLORS[status] || 'grey';
};

/**
 * Get impact tags from finding data
 * @param {Object} finding - Finding object
 * @returns {Array<string>} Array of impact tag labels
 */
export const getImpactTags = (finding) => {
  const tags = [];

  if (finding.downtime > 0) tags.push(IMPACT_TAGS.downtime);
  if (finding.slowness > 0) tags.push(IMPACT_TAGS.slowness);
  if (finding.additionalCost > 0) tags.push(IMPACT_TAGS.additionalCost);
  if (finding.needFullTest > 0) tags.push(IMPACT_TAGS.needFullTest);

  return tags;
};

/**
 * Count total resources affected by a finding
 * @param {Object} affectedResources - Object with regions as keys and resource arrays as values
 * @returns {number} Total count of affected resources
 */
export const countAffectedResources = (affectedResources) => {
  if (!affectedResources) return 0;

  return Object.values(affectedResources).reduce((total, resources) => {
    return total + (Array.isArray(resources) ? resources.length : 0);
  }, 0);
};

/**
 * Extract service name from service key
 * @param {string} serviceKey - Service key from data (e.g., "cloudfront", "ec2")
 * @returns {string} Formatted service name
 */
export const formatServiceName = (serviceKey) => {
  return serviceKey.toUpperCase();
};

/**
 * Get color for a remediation_risk value
 * @param {string} risk - low, medium, or high
 * @returns {string} Cloudscape badge color
 */
export const getRiskColor = (risk) => {
  switch (risk) {
    case 'low': return 'severity-low';
    case 'medium': return 'severity-medium';
    case 'high': return 'severity-high';
    default: return 'grey';
  }
};

const PLACEHOLDER_RE = /\{(ResourceArn|ResourceId|ResourceName|Region|AccountId)\}/g;

/**
 * List the distinct placeholders left in a command, in order of appearance.
 * Mirrors placeholdersIn() in utils/RemediationResolver.py.
 * @param {string} command - Remediation command
 * @returns {Array<string>} Placeholder names without braces
 */
export const placeholdersIn = (command) => {
  if (!command) return [];

  const names = (command.match(PLACEHOLDER_RE) || []).map(token => token.slice(1, -1));
  return [...new Set(names)];
};

/**
 * Get the resolved remediation command for one affected resource.
 *
 * Placeholder substitution happens in the Python backend
 * (utils/RemediationResolver.py) because the identifier format is per-service,
 * so this is a lookup rather than a string replace. Falls back to the raw
 * command with placeholders intact when the backend produced no entry -- e.g.
 * a report generated before __remediationByResource existed.
 *
 * @param {Object} finding - Finding object
 * @param {string} region - Region key
 * @param {string} identifier - Resource identifier as it appears in __affectedResources
 * @returns {Object|null} { command, unresolved } or null when the check has no remediation
 */
export const getRemediationForResource = (finding, region, identifier) => {
  if (!finding || !finding.remediation) return null;

  const resolved = finding.__remediationByResource?.[region]?.[identifier];
  if (resolved) return resolved;

  // Nothing pre-resolved for this resource. Report the command's own
  // placeholders as unresolved so the UI never presents a template as runnable.
  return {
    command: finding.remediation,
    unresolved: placeholdersIn(finding.remediation)
  };
};

/**
 * Look up a check's reporter entry from the flat findings-table row shape.
 *
 * The Findings page rows come from workItem.xlsx (one row per resource), which
 * carries no remediation columns. The reporter entry -- remediation included --
 * already lives in the report data under the service summary, so this rejoins
 * the two on service + check rather than widening the spreadsheet.
 *
 * @param {Object} data - Full report data (window.__REPORT_DATA__)
 * @param {Object} row - Findings-table row with `service` and `Check`
 * @returns {Object|null} The check's summary entry, or null when absent
 */
export const findCheckSummary = (data, row) => {
  if (!data || !row || !row.service || !row.Check) return null;

  const service = data[String(row.service).toLowerCase()];
  return service?.summary?.[row.Check] || null;
};

/**
 * Resolve the CLI command for one findings-table row
 * @param {Object} data - Full report data
 * @param {Object} row - Findings-table row with service, Check, Region, ResourceID
 * @returns {Object|null} { command, unresolved } or null when there is no CLI fix
 */
export const getRemediationForRow = (data, row) => {
  const check = findCheckSummary(data, row);
  if (!check) return null;

  return getRemediationForResource(check, row.Region, row.ResourceID);
};

/**
 * Count findings that ship a runnable CLI command
 * @param {Array<Object>} findings - Finding objects
 * @returns {number} Count of findings with a non-null remediation
 */
export const countRemediableFindings = (findings) => {
  if (!Array.isArray(findings)) return 0;

  return findings.filter(finding => finding && finding.remediation).length;
};

/**
 * Parse links from finding description
 * @param {Object} finding - Finding object with __links array
 * @returns {Array<Object>} Array of link objects with text and url
 */
export const parseLinks = (finding) => {
  if (!finding.__links || !Array.isArray(finding.__links)) {
    return [];
  }

  return finding.__links.map((link, index) => ({
    text: `Reference ${index + 1}`,
    url: link
  }));
};
