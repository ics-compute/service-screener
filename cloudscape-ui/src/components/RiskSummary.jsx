import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import {
  getCostHighlights,
  getFrameworkLowlights,
  getQuickWins,
  getRegionRisk,
  getRiskPosture,
  getServicePillarMatrix,
  getTopFindings
} from '../utils/dataLoader';
import {
  formatCategory,
  formatCriticality,
  formatServiceName,
  getCriticalityColor,
  getRemediationForResource,
  getRiskColor
} from '../utils/formatters';
import { decodeHtml } from '../utils/htmlDecoder';
import EmptyState from './EmptyState';

/**
 * Risk Summary - a single ranked "what to fix first" view.
 *
 * Every figure is aggregated client-side from the report data already in memory;
 * no new backend output is required. Two constraints from the data shape drive
 * the design:
 *
 *  * Only failures reach api-full.json, so there are no PASS counts and no
 *    pass/fail health ratio. The service matrix uses severity-weighted finding
 *    counts instead.
 *  * `criticality` holds only H/M/L/I, so there is no CRITICAL tier to show.
 *
 * Sections that restate another page (frameworks, cost) are deliberately
 * compact and link out rather than duplicating the detail.
 */

const TOP_N = 10;

// Heat gradient for the service x pillar matrix. Cell background scales with
// the severity-weighted finding count relative to the busiest cell, so the eye
// lands on the worst service/pillar intersection.
const heatStyle = (weight, maxWeight) => {
  if (!weight) {
    return { backgroundColor: 'transparent', color: '#5f6b7a' };
  }

  const intensity = maxWeight > 0 ? weight / maxWeight : 0;

  // Pale amber through to deep red. Text flips to white once the background is
  // dark enough that dark text would fail contrast.
  const background = `rgba(211, 50, 18, ${0.08 + intensity * 0.82})`;

  return {
    backgroundColor: background,
    color: intensity > 0.55 ? '#ffffff' : '#16191f',
    fontWeight: 600,
    textAlign: 'center',
    borderRadius: '4px',
    padding: '6px 8px'
  };
};

const StatBlock = ({ label, value, color, description }) => (
  <div>
    <Box variant="awsui-key-label">{label}</Box>
    <Box fontSize="display-l" fontWeight="bold" color={color}>
      {value}
    </Box>
    {description && (
      <Box variant="small" color="text-body-secondary">{description}</Box>
    )}
  </div>
);

/**
 * Render the CLI cell for one quick-win row.
 *
 * Commands are resolved per resource by the Python backend, so a check that
 * affects many resources has many commands and no single one belongs in a
 * table cell. Only an unambiguous single-resource command is offered as
 * copyable; anything else links to the service page where every command is
 * listed. This keeps the page from ever presenting a template as runnable.
 */
const CommandCell = ({ finding, onNavigate }) => {
  const regions = Object.keys(finding.affectedResources || {});
  const singleRegion = regions.length === 1 ? regions[0] : null;
  const identifiers = singleRegion ? finding.affectedResources[singleRegion] : [];

  if (singleRegion && identifiers.length === 1) {
    const resolved = getRemediationForResource(finding, singleRegion, identifiers[0]);

    if (resolved && !(resolved.unresolved || []).length) {
      return (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '4px' }}>
          <Box variant="code" fontSize="body-s">
            {resolved.command}
          </Box>
          <CopyToClipboard
            copyButtonAriaLabel={`Copy CLI command for ${finding.checkName}`}
            copySuccessText="Command copied"
            copyErrorText="Failed to copy command"
            textToCopy={resolved.command}
            variant="icon"
          />
        </div>
      );
    }
  }

  return (
    <SpaceBetween size="xxs">
      <Box variant="small" color="text-status-warning">
        {finding.resourceCount} resource-specific commands
      </Box>
      <Link onFollow={() => onNavigate(finding.service)} variant="secondary">
        View commands on {formatServiceName(finding.service)}
      </Link>
    </SpaceBetween>
  );
};

const RiskSummary = ({ data }) => {
  const navigate = useNavigate();

  const posture = useMemo(() => getRiskPosture(data), [data]);
  const topFindings = useMemo(() => getTopFindings(data).slice(0, TOP_N), [data]);
  const quickWins = useMemo(() => getQuickWins(data, TOP_N), [data]);
  const matrix = useMemo(() => getServicePillarMatrix(data), [data]);
  const regionRisk = useMemo(() => getRegionRisk(data), [data]);
  const frameworks = useMemo(() => getFrameworkLowlights(data), [data]);
  const cost = useMemo(() => getCostHighlights(data), [data]);

  const goToService = (service) => navigate(`/service/${service.toLowerCase()}`);

  if (posture.totalChecks === 0) {
    return (
      <Container header={<Header variant="h1">Risk Summary</Header>}>
        <EmptyState
          title="No findings"
          description="This report contains no findings to summarise."
          icon="status-positive"
        />
      </Container>
    );
  }

  return (
    <SpaceBetween size="l">
      <Header
        variant="h1"
        description="Ranked view of what to fix first, aggregated across every scanned service"
      >
        Risk Summary
      </Header>

      {/* Risk posture -- the one account-wide total the dashboard does not show */}
      <Container header={<Header variant="h2">Risk Posture</Header>}>
        <SpaceBetween size="m">
          <ColumnLayout columns={4} variant="text-grid">
            <StatBlock
              label="High"
              value={posture.high}
              color="text-status-error"
            />
            <StatBlock
              label="Medium"
              value={posture.medium}
              color="text-status-warning"
            />
            <StatBlock
              label="Low"
              value={posture.low}
              color="text-status-info"
            />
            <StatBlock
              label="Runnable fixes"
              value={posture.remediableChecks}
              color="text-status-success"
              description={
                posture.lowRiskRemediableChecks > 0
                  ? `${posture.lowRiskRemediableChecks} low-risk`
                  : 'none low-risk'
              }
            />
          </ColumnLayout>

          <Box variant="p" color="text-body-secondary">
            <strong>{posture.totalFindings}</strong> findings from{' '}
            <strong>{posture.totalChecks}</strong> failed checks across{' '}
            <strong>{posture.totalServices}</strong>{' '}
            {posture.totalServices === 1 ? 'service' : 'services'}
            {posture.totalResources > 0 && (
              <> and <strong>{posture.totalResources}</strong> scanned resources</>
            )}
            .
          </Box>

          {/* Call out the worst region up front: on a multi-region scan the
              region carrying the most weighted risk is often not the one the
              team watches. Only meaningful once more than one region has findings. */}
          {regionRisk.regions.length > 1 && (
            <Alert type="warning" header={`Highest-risk region: ${regionRisk.regions[0].region}`}>
              <strong>{regionRisk.regions[0].total}</strong> findings
              {regionRisk.regions[0].high > 0 && (
                <> including <strong>{regionRisk.regions[0].high}</strong> high severity</>
              )}
              {' '}across {regionRisk.regions[0].serviceCount}{' '}
              {regionRisk.regions[0].serviceCount === 1 ? 'service' : 'services'} — more
              weighted risk than any other region in this scan.
            </Alert>
          )}
        </SpaceBetween>
      </Container>

      {/* Regional risk -- surfaces the region nobody is watching */}
      <Container
        header={
          <Header
            variant="h2"
            description="Where the findings are. A region you rarely work in can carry more high-severity findings than your primary one."
          >
            Regions by Risk
          </Header>
        }
      >
        <SpaceBetween size="m">
          {regionRisk.hasRegionalFindings ? (
            <Table
              variant="embedded"
              columnDefinitions={[
                {
                  id: 'region',
                  header: 'Region',
                  cell: item => <Box fontWeight="bold">{item.region}</Box>
                },
                {
                  id: 'total',
                  header: 'Findings',
                  cell: item => (
                    <div style={heatStyle(item.weight, regionRisk.maxWeight)}>
                      {item.total}
                    </div>
                  ),
                  width: 130
                },
                {
                  id: 'high',
                  header: 'High',
                  cell: item => item.high > 0
                    ? <StatusIndicator type="error">{item.high}</StatusIndicator>
                    : <Box color="text-status-inactive">—</Box>,
                  width: 110
                },
                {
                  id: 'medium',
                  header: 'Medium',
                  cell: item => item.medium > 0
                    ? <StatusIndicator type="warning">{item.medium}</StatusIndicator>
                    : <Box color="text-status-inactive">—</Box>,
                  width: 120
                },
                {
                  id: 'low',
                  header: 'Low',
                  cell: item => item.low > 0
                    ? <StatusIndicator type="info">{item.low}</StatusIndicator>
                    : <Box color="text-status-inactive">—</Box>,
                  width: 110
                },
                {
                  id: 'services',
                  header: 'Services affected',
                  cell: item => item.serviceCount
                }
              ]}
              items={regionRisk.regions}
              wrapLines
            />
          ) : (
            <Box variant="p" color="text-body-secondary">
              No region-specific findings. Every finding in this report comes from a
              global service.
            </Box>
          )}

          {regionRisk.global && (
            <Box variant="small" color="text-body-secondary">
              A further <strong>{regionRisk.global.total}</strong> findings come from
              global services such as IAM and are not tied to a region.
            </Box>
          )}

          {/* The scanner only calls the regions passed to --regions, so an
              unlisted region contributes nothing above and must not be read as clean. */}
          <Alert type="info" header="Scan coverage">
            {regionRisk.scannedRegions.length > 0 ? (
              <>
                This scan covered{' '}
                <strong>{regionRisk.scannedRegions.join(', ')}</strong>. Regions outside
                that list were never called, so they contribute no findings here — an
                absent region is unassessed, not clean. Re-run with{' '}
                <Box variant="code">--regions ALL</Box> to cover every enabled region.
              </>
            ) : (
              <>
                Only regions included in the scan appear above. An absent region is
                unassessed, not clean.
              </>
            )}
          </Alert>
        </SpaceBetween>
      </Container>

      {/* Service x pillar matrix -- neither existing view crosses these axes */}
      <Container
        header={
          <Header
            variant="h2"
            description="Severity-weighted findings per service and Well-Architected pillar. Darker means higher weighted risk."
          >
            Service Risk Matrix
          </Header>
        }
      >
        {matrix.rows.length === 0 ? (
          <Box variant="p" color="text-body-secondary">
            No pillar-classified findings to plot.
          </Box>
        ) : (
          <Table
            variant="embedded"
            columnDefinitions={[
              {
                id: 'service',
                header: 'Service',
                cell: item => (
                  <Link onFollow={() => goToService(item.service)}>
                    {formatServiceName(item.service)}
                  </Link>
                )
              },
              ...matrix.pillars.map(pillar => ({
                id: pillar,
                header: formatCategory(pillar),
                cell: item => {
                  const cell = item.cells[pillar];
                  return (
                    <div style={heatStyle(cell?.weight || 0, matrix.maxWeight)}>
                      {cell ? cell.count : '—'}
                    </div>
                  );
                }
              })),
              {
                id: 'total',
                header: 'Total',
                cell: item => <Box fontWeight="bold">{item.totalCount}</Box>
              }
            ]}
            items={matrix.rows}
            wrapLines
          />
        )}
      </Container>

      {/* Top findings by impact -- severity weight x affected resources */}
      <Table
        variant="container"
        columnDefinitions={[
          {
            id: 'rank',
            header: '#',
            cell: (item) => topFindings.indexOf(item) + 1,
            width: 60
          },
          {
            id: 'action',
            header: 'Finding',
            cell: item => (
              <Link onFollow={() => goToService(item.service)}>
                {decodeHtml(item.shortDesc)}
              </Link>
            )
          },
          {
            id: 'service',
            header: 'Service',
            cell: item => formatServiceName(item.service),
            width: 120
          },
          {
            id: 'pillar',
            header: 'Pillar',
            cell: item => formatCategory(item.category),
            width: 140
          },
          {
            id: 'severity',
            header: 'Severity',
            cell: item => (
              <Badge color={getCriticalityColor(item.severity)}>
                {formatCriticality(item.severity)}
              </Badge>
            ),
            width: 120
          },
          {
            id: 'resources',
            header: 'Resources',
            cell: item => item.resourceCount,
            width: 110
          },
          {
            id: 'fix',
            header: 'CLI fix',
            cell: item => item.remediation
              ? <Badge color={getRiskColor(item.remediationRisk)}>
                  {item.remediationRisk || 'available'}
                </Badge>
              : <Box color="text-status-inactive">—</Box>,
            width: 110
          }
        ]}
        items={topFindings}
        header={
          <Header
            variant="h2"
            counter={`(${topFindings.length})`}
            description="Ranked by severity weight multiplied by affected resource count"
            actions={
              <Button onClick={() => navigate('/page/findings')}>
                All findings
              </Button>
            }
          >
            Top Findings by Impact
          </Header>
        }
        wrapLines
      />

      {/* Quick wins -- low-risk first, other risk levels as a fallback */}
      <Table
        variant="container"
        columnDefinitions={[
          {
            id: 'rank',
            header: '#',
            cell: (item) => quickWins.items.indexOf(item) + 1,
            width: 60
          },
          {
            id: 'action',
            header: 'Action',
            cell: item => (
              <Link onFollow={() => goToService(item.service)}>
                {decodeHtml(item.shortDesc)}
              </Link>
            )
          },
          {
            id: 'service',
            header: 'Service',
            cell: item => formatServiceName(item.service),
            width: 110
          },
          {
            id: 'resources',
            header: 'Resources',
            cell: item => item.resourceCount,
            width: 100
          },
          {
            id: 'risk',
            header: 'Risk',
            cell: item => (
              <Badge color={getRiskColor(item.remediationRisk)}>
                {item.remediationRisk || 'unrated'}
              </Badge>
            ),
            width: 110
          },
          {
            id: 'command',
            header: 'CLI command',
            cell: item => <CommandCell finding={item} onNavigate={goToService} />
          }
        ]}
        items={quickWins.items}
        header={
          <Header
            variant="h2"
            counter={`(${quickWins.items.length})`}
            description="Findings that ship a CLI remediation, ranked by impact"
          >
            Recommended Actions
          </Header>
        }
        empty={
          <EmptyState
            title="No runnable fixes"
            description="No finding in this report ships a CLI remediation command."
            icon="status-info"
          />
        }
        wrapLines
      />

      {quickWins.fallback && (
        <Alert type="warning" header="No low-risk remediations in this scan">
          Every runnable fix above carries a higher remediation risk. Review the
          impact of each command before running it.
        </Alert>
      )}

      {/* Compliance lowlights -- compresses the framework overview page */}
      {frameworks.worst.length > 0 && (
        <Container
          header={
            <Header
              variant="h2"
              description="Lowest-scoring frameworks. Percentages cover assessed controls only."
              actions={
                <Button onClick={() => navigate('/framework/overview')}>
                  All frameworks
                </Button>
              }
            >
              Compliance Attention
            </Header>
          }
        >
          <SpaceBetween size="m">
            <ColumnLayout columns={frameworks.worst.length} variant="text-grid">
              {frameworks.worst.map(framework => (
                <div key={framework.name}>
                  <Box variant="awsui-key-label">{framework.name}</Box>
                  <Box
                    fontSize="display-l"
                    fontWeight="bold"
                    color={framework.pct >= 80 ? 'text-status-success' : 'text-status-error'}
                  >
                    {framework.pct}%
                  </Box>
                  <Box variant="small" color="text-body-secondary">
                    {framework.needAttention} need attention ·{' '}
                    {framework.assessed} of {framework.total} controls assessed
                  </Box>
                </div>
              ))}
            </ColumnLayout>

            {frameworks.overallPct !== null && (
              <Box variant="small" color="text-body-secondary">
                Across all {frameworks.frameworkCount} frameworks:{' '}
                <strong>{frameworks.overallPct}%</strong> of assessed controls are
                compliant. Controls a scan cannot evaluate are excluded, so a high
                score over a small assessed set is not broad compliance.
              </Box>
            )}
          </SpaceBetween>
        </Container>
      )}

      {/* Cost teaser -- the only pillar with a dollar figure; hidden when COH is unavailable */}
      {cost && (
        <Container
          header={
            <Header
              variant="h2"
              description="From Cost Optimization Hub"
              actions={
                <Button onClick={() => navigate('/page/coh')}>
                  View recommendations
                </Button>
              }
            >
              Cost Savings Available
            </Header>
          }
        >
          <ColumnLayout columns={cost.phaseOne ? 4 : 3} variant="text-grid">
            <StatBlock
              label="Monthly savings"
              value={`$${cost.monthlySavings.toLocaleString()}`}
              color="text-status-success"
            />
            <StatBlock
              label="Annual savings"
              value={`$${Math.round(cost.annualSavings).toLocaleString()}`}
              color="text-status-success"
            />
            <StatBlock
              label="Recommendations"
              value={cost.recommendations}
              description={cost.highPriority > 0 ? `${cost.highPriority} high priority` : undefined}
            />
            {cost.phaseOne && (
              <StatBlock
                label={cost.phaseOne.timeframe}
                value={cost.phaseOne.count}
                description={`$${cost.phaseOne.savings.toLocaleString()} from quick wins`}
              />
            )}
          </ColumnLayout>
        </Container>
      )}
    </SpaceBetween>
  );
};

export default RiskSummary;
