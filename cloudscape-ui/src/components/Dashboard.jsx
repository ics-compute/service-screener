import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import {
  calculateDashboardStats,
  getServiceStats,
  getCategoryStats
} from '../utils/dataLoader';
import {
  formatCategory,
  formatServiceName,
  getCategoryStyle,
  filterUserCategories
} from '../utils/formatters';
import EmptyState from './EmptyState';
import CategoryCard from './CategoryCard';
import ContentEnrichment from './ContentEnrichment';

const PILLAR_ORDER = ['S', 'R', 'C', 'P', 'O'];
const PAGE_SIZE = 12;

// Deep-link labels the findings table filters on.
const CATEGORY_NAMES = {
  S: 'Security',
  R: 'Reliability',
  C: 'Cost',
  P: 'Performance',
  O: 'Operation'
};

const SEVERITY_NAMES = { H: 'High', M: 'Medium', L: 'Low', I: 'Informational' };

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
 * Dashboard - the report landing page.
 *
 * Shows account-wide totals, a per-pillar breakdown, and every scanned service
 * ranked worst-first. Services are a sorted, filterable, paginated table rather
 * than a card grid: a full scan covers ~30 services, which as cards is several
 * screens of near-identical blocks in alphabetical order, burying the services
 * that actually need attention.
 */
const Dashboard = ({ data }) => {
  const navigate = useNavigate();
  const [filterText, setFilterText] = useState('');
  const [currentPageIndex, setCurrentPageIndex] = useState(1);

  const stats = useMemo(() => calculateDashboardStats(data), [data]);
  const serviceStats = useMemo(() => getServiceStats(data), [data]);
  const categoryStats = useMemo(() => getCategoryStats(data), [data]);

  // Worst-first, so the services needing attention are on the first page.
  const rankedServices = useMemo(() => {
    return [...serviceStats].sort((a, b) => {
      if (b.high !== a.high) return b.high - a.high;
      if (b.medium !== a.medium) return b.medium - a.medium;
      if (b.totalFindings !== a.totalFindings) return b.totalFindings - a.totalFindings;
      return a.serviceName.localeCompare(b.serviceName);
    });
  }, [serviceStats]);

  const filteredServices = useMemo(() => {
    if (!filterText.trim()) return rankedServices;

    const needle = filterText.trim().toLowerCase();
    return rankedServices.filter(service =>
      service.serviceName.toLowerCase().includes(needle)
    );
  }, [rankedServices, filterText]);

  const paginatedServices = useMemo(() => {
    const start = (currentPageIndex - 1) * PAGE_SIZE;
    return filteredServices.slice(start, start + PAGE_SIZE);
  }, [filteredServices, currentPageIndex]);

  // All five pillars always render, so a clean pillar reads as "clean" rather
  // than silently disappearing.
  const orderedCategories = useMemo(() => {
    return PILLAR_ORDER.map(code =>
      categoryStats.find(c => c.category === code) || {
        category: code,
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0
      }
    );
  }, [categoryStats]);

  const handleServiceClick = (serviceName) => {
    navigate(`/service/${serviceName.toLowerCase()}`);
  };

  const handleCategoryClick = (category, severity = null) => {
    const params = new URLSearchParams();
    params.append('type', CATEGORY_NAMES[category] || category);

    if (severity) {
      params.append('severity', SEVERITY_NAMES[severity] || severity);
    }

    navigate(`/page/findings?${params.toString()}`);
  };

  const columnDefinitions = [
    {
      id: 'service',
      header: 'Service',
      cell: item => (
        <Link onFollow={() => handleServiceClick(item.serviceName)}>
          {formatServiceName(item.serviceName)}
        </Link>
      ),
      sortingField: 'serviceName'
    },
    {
      id: 'total',
      header: 'Findings',
      cell: item => <Box fontWeight="bold">{item.totalFindings}</Box>,
      sortingField: 'totalFindings',
      width: 120
    },
    {
      id: 'high',
      header: 'High',
      cell: item => item.high > 0
        ? <StatusIndicator type="error">{item.high}</StatusIndicator>
        : <Box color="text-status-inactive">—</Box>,
      sortingField: 'high',
      width: 110
    },
    {
      id: 'medium',
      header: 'Medium',
      cell: item => item.medium > 0
        ? <StatusIndicator type="warning">{item.medium}</StatusIndicator>
        : <Box color="text-status-inactive">—</Box>,
      sortingField: 'medium',
      width: 120
    },
    {
      id: 'low',
      header: 'Low',
      cell: item => item.low > 0
        ? <StatusIndicator type="info">{item.low}</StatusIndicator>
        : <Box color="text-status-inactive">—</Box>,
      sortingField: 'low',
      width: 110
    },
    {
      id: 'categories',
      header: 'Pillars',
      cell: item => (
        <SpaceBetween size="xxs" direction="horizontal">
          {filterUserCategories(item.categories).map(category => (
            <span
              key={category}
              onClick={() => handleCategoryClick(category)}
              role="button"
              tabIndex={0}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  handleCategoryClick(category);
                }
              }}
              title={`View ${formatCategory(category)} findings`}
              style={{
                cursor: 'pointer',
                display: 'inline-block',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 500,
                ...getCategoryStyle(category)
              }}
            >
              {formatCategory(category)}
            </span>
          ))}
        </SpaceBetween>
      )
    }
  ];

  return (
    <SpaceBetween size="l">
      <Header variant="h1" description="AWS Well-Architected Assessment Report">
        Service Screener Dashboard
      </Header>

      {/* Account-wide totals */}
      <Container header={<Header variant="h2">Assessment Summary</Header>}>
        <SpaceBetween size="m">
          <ColumnLayout columns={4} variant="text-grid">
            <StatBlock
              label="Total findings"
              value={stats.totalFindings}
              description={`across ${stats.totalServices} ${stats.totalServices === 1 ? 'service' : 'services'}`}
            />
            <StatBlock label="High" value={stats.highPriority} color="text-status-error" />
            <StatBlock label="Medium" value={stats.mediumPriority} color="text-status-warning" />
            <StatBlock label="Low" value={stats.lowPriority} color="text-status-info" />
          </ColumnLayout>

          <Box>
            <Button variant="primary" onClick={() => navigate('/risk-summary')}>
              What should I fix first?
            </Button>
          </Box>
        </SpaceBetween>
      </Container>

      {/* Well-Architected pillars, all five at equal weight */}
      <Container
        header={
          <Header
            variant="h2"
            description="Select a pillar or severity to open the matching findings"
          >
            Findings by Pillar
          </Header>
        }
      >
        <ColumnLayout columns={5} variant="default" minColumnWidth={170}>
          {orderedCategories.map(category => (
            <CategoryCard
              key={category.category}
              category={category}
              onClick={handleCategoryClick}
            />
          ))}
        </ColumnLayout>
      </Container>

      <ContentEnrichment data={data} />

      {/* Services, ranked worst-first */}
      <Table
        variant="container"
        columnDefinitions={columnDefinitions}
        items={paginatedServices}
        header={
          <Header
            variant="h2"
            counter={`(${filteredServices.length})`}
            description="Ranked by high-severity findings first"
          >
            Services
          </Header>
        }
        filter={
          rankedServices.length > PAGE_SIZE ? (
            <TextFilter
              filteringText={filterText}
              filteringPlaceholder="Find a service"
              filteringAriaLabel="Filter services"
              onChange={({ detail }) => {
                setFilterText(detail.filteringText);
                setCurrentPageIndex(1);
              }}
              countText={`${filteredServices.length} ${filteredServices.length === 1 ? 'match' : 'matches'}`}
            />
          ) : undefined
        }
        pagination={
          filteredServices.length > PAGE_SIZE ? (
            <Pagination
              currentPageIndex={currentPageIndex}
              pagesCount={Math.ceil(filteredServices.length / PAGE_SIZE)}
              onChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
            />
          ) : undefined
        }
        empty={
          <EmptyState
            title={filterText ? 'No matching services' : 'No services found'}
            description={
              filterText
                ? 'No service name matches your filter.'
                : 'No service data available in this report.'
            }
            icon="search"
          />
        }
        wrapLines
      />
    </SpaceBetween>
  );
};

export default Dashboard;
