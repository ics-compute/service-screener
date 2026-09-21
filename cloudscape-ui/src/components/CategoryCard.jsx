import React from 'react';
import Box from '@cloudscape-design/components/box';
import Container from '@cloudscape-design/components/container';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

import { formatCategory } from '../utils/formatters';

/**
 * CategoryCard - one Well-Architected pillar, with a clickable severity
 * breakdown that deep-links into the filtered findings table.
 *
 * Severity is rendered with StatusIndicator rather than emoji so the icons
 * follow the Cloudscape theme (including dark mode) instead of depending on
 * whichever emoji font the viewer's OS ships.
 */

// Cloudscape StatusIndicator types, ordered high to low.
const SEVERITY_ROWS = [
  { key: 'high', code: 'H', label: 'High', type: 'error' },
  { key: 'medium', code: 'M', label: 'Medium', type: 'warning' },
  { key: 'low', code: 'L', label: 'Low', type: 'info' },
  { key: 'informational', code: 'I', label: 'Info', type: 'pending' }
];

const TOTAL_COLOR = {
  S: 'text-status-error',
  C: 'text-status-info',
  P: 'text-status-success',
  R: 'text-status-error',
  O: 'text-status-warning'
};

const CategoryCard = ({ category, onClick }) => {
  const { category: categoryCode, total } = category;
  const categoryName = formatCategory(categoryCode);

  return (
    <Container
      variant="stacked"
      disableContentPaddings={false}
      header={
        <Box textAlign="center" padding={{ top: 'xs' }}>
          <Link
            onFollow={() => onClick(categoryCode)}
            fontSize="heading-s"
            variant="primary"
          >
            {categoryName}
          </Link>
        </Box>
      }
    >
      <SpaceBetween size="s">
        <Box textAlign="center">
          <Link onFollow={() => onClick(categoryCode)} variant="primary">
            <Box
              fontSize="display-l"
              fontWeight="bold"
              color={TOTAL_COLOR[categoryCode] || 'inherit'}
            >
              {total}
            </Box>
          </Link>
          <Box variant="small" color="text-body-secondary">
            {total === 1 ? 'finding' : 'findings'}
          </Box>
        </Box>

        {total > 0 ? (
          <SpaceBetween size="xxs">
            {SEVERITY_ROWS.filter(row => category[row.key] > 0).map(row => (
              <Link
                key={row.key}
                onFollow={() => onClick(categoryCode, row.code)}
                variant="secondary"
              >
                <StatusIndicator type={row.type}>
                  {category[row.key]} {row.label}
                </StatusIndicator>
              </Link>
            ))}
          </SpaceBetween>
        ) : (
          <Box textAlign="center">
            <StatusIndicator type="success">No findings</StatusIndicator>
          </Box>
        )}
      </SpaceBetween>
    </Container>
  );
};

export default CategoryCard;
