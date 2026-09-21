import React from 'react';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

import { getRemediationForResource, getRiskColor } from '../utils/formatters';

/**
 * Renders the remediation block for one finding: the risk badge, one
 * copy-to-clipboard CLI command per affected resource, and the doc link.
 *
 * Commands arrive pre-resolved from the Python backend
 * (utils/RemediationResolver.py) since the resource identifier format varies by
 * service. Any placeholder the backend could not fill is reported in
 * `unresolved` and surfaced here as a warning, so a command that still needs
 * hand-editing never looks ready to run.
 */

const CODE_STYLE = {
  fontFamily: 'Monaco, Menlo, "Courier New", monospace',
  fontSize: '12px',
  backgroundColor: '#f4f4f4',
  color: '#16191f',
  padding: '8px 10px',
  borderRadius: '4px',
  border: '1px solid #d5dbdb',
  margin: 0,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  flex: 1
};

const CommandRow = ({ identifier, remediation, showIdentifier }) => (
  <div>
    {showIdentifier && (
      <Box variant="small" fontWeight="bold">{identifier}</Box>
    )}
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '4px' }}>
      <pre style={CODE_STYLE}>{remediation.command}</pre>
      <CopyToClipboard
        copyButtonAriaLabel={`Copy CLI command for ${identifier}`}
        copySuccessText="Command copied"
        copyErrorText="Failed to copy command"
        textToCopy={remediation.command}
        variant="icon"
      />
    </div>
    {remediation.unresolved && remediation.unresolved.length > 0 && (
      <Box variant="small" color="text-status-warning">
        Replace {remediation.unresolved.map(name => `{${name}}`).join(', ')} before running —
        the scan did not capture {remediation.unresolved.length > 1 ? 'these values' : 'this value'}.
      </Box>
    )}
  </div>
);

const RemediationSection = ({ finding }) => {
  if (!finding) return null;

  const hasCommand = Boolean(finding.remediation);

  // No CLI fix, but the docs still tell the operator what to do by hand.
  if (!hasCommand) {
    if (!finding.remediation_doc) return null;

    return (
      <div>
        <Box variant="awsui-key-label">Remediation</Box>
        <SpaceBetween size="xxs">
          <StatusIndicator type="info">Manual remediation required</StatusIndicator>
          <Link href={finding.remediation_doc} external externalIconAriaLabel="Opens in a new tab">
            AWS documentation
          </Link>
        </SpaceBetween>
      </div>
    );
  }

  // Flatten {region: {identifier: {...}}} into rows, preserving region grouping
  // only when there is more than one region to disambiguate.
  const affected = finding.__affectedResources || {};
  const regions = Object.keys(affected);

  const rows = [];
  regions.forEach(region => {
    const identifiers = Array.isArray(affected[region]) ? affected[region] : [];
    identifiers.forEach(identifier => {
      const remediation = getRemediationForResource(finding, region, identifier);
      if (remediation) rows.push({ region, identifier, remediation });
    });
  });

  // Distinct commands: when every resource yields the same command (no
  // placeholders), showing it once is clearer than repeating it N times.
  const distinctCommands = new Set(rows.map(row => row.remediation.command));
  const isPerResource = distinctCommands.size > 1;

  return (
    <div>
      <Box variant="awsui-key-label">Remediation</Box>
      <SpaceBetween size="xs">
        <SpaceBetween direction="horizontal" size="xs">
          <Badge color={getRiskColor(finding.remediation_risk)}>
            {(finding.remediation_risk || 'unknown').toUpperCase()} RISK
          </Badge>
          <Box variant="small">AWS CLI fix</Box>
        </SpaceBetween>

        {rows.length === 0 && (
          <CommandRow
            identifier="command"
            remediation={{ command: finding.remediation, unresolved: [] }}
            showIdentifier={false}
          />
        )}

        {rows.length > 0 && !isPerResource && (
          <CommandRow
            identifier={rows[0].identifier}
            remediation={rows[0].remediation}
            showIdentifier={false}
          />
        )}

        {isPerResource && (
          <ExpandableSection
            headerText={`Commands for ${rows.length} affected ${rows.length === 1 ? 'resource' : 'resources'}`}
            variant="footer"
          >
            <SpaceBetween size="xs">
              {rows.map(row => (
                <CommandRow
                  key={`${row.region}/${row.identifier}`}
                  identifier={regions.length > 1 ? `${row.region} — ${row.identifier}` : row.identifier}
                  remediation={row.remediation}
                  showIdentifier
                />
              ))}
            </SpaceBetween>
          </ExpandableSection>
        )}

        {finding.remediation_doc && (
          <Link href={finding.remediation_doc} external externalIconAriaLabel="Opens in a new tab">
            AWS documentation
          </Link>
        )}
      </SpaceBetween>
    </div>
  );
};

export default RemediationSection;
