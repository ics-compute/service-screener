import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { HashRouter } from 'react-router-dom';

import RiskSummary from '../components/RiskSummary';
import { REPORT, REPORT_WITHOUT_COH, REPORT_GLOBAL_ONLY } from './fixtures/report';

const draw = (data) => render(<HashRouter><RiskSummary data={data} /></HashRouter>);

describe('RiskSummary', () => {
  it('renders every section for a full report', () => {
    const { container } = draw(REPORT);
    const text = container.textContent;

    [
      'Risk Posture',
      'Regions by Risk',
      'Service Risk Matrix',
      'Top Findings by Impact',
      'Recommended Actions',
      'Compliance Attention',
      'Cost Savings Available'
    ].forEach(section => expect(text).toContain(section));
  });

  it('flags the highest-risk region up front', () => {
    const { container } = draw(REPORT);

    expect(container.textContent).toContain('Highest-risk region: us-east-1');
  });

  it('discloses scan coverage so an unscanned region is not read as clean', () => {
    const { container } = draw(REPORT);

    expect(container.textContent).toContain('Scan coverage');
    expect(container.textContent).toContain('unassessed, not clean');
  });

  it('omits the region banner when there is nothing to compare', () => {
    const { container } = draw(REPORT_GLOBAL_ONLY);

    expect(container.textContent).not.toContain('Highest-risk region');
    expect(container.textContent).toContain('comes from a global service');
  });

  it('hides the cost section rather than showing $0 when COH is unavailable', () => {
    const { container } = draw(REPORT_WITHOUT_COH);

    expect(container.textContent).not.toContain('Cost Savings Available');
    expect(container.textContent).not.toContain('$0');
  });

  it('shows one row per table for checks that share a remediation command', () => {
    const { queryAllByText } = draw(REPORT);
    const hits = queryAllByText('Set a stronger password policy');

    // passwordPolicyLength and passwordPolicyWeak are one line of work, so each
    // table lists them once: once as a finding, once as the action that fixes it.
    // Two rows total is correct; four would be the duplicate bug.
    expect(hits).toHaveLength(2);

    const tables = new Set(hits.map(el => el.closest('table')));
    expect(tables.size).toBe(2);
  });

  it('warns when only higher-risk remediations are available', () => {
    const { container } = draw(REPORT);

    expect(container.textContent).toContain('No low-risk remediations in this scan');
  });

  it('reports framework coverage next to the score', () => {
    const { container } = draw(REPORT);

    // NIST scores 90% but only 20 of 120 controls were assessed.
    expect(container.textContent).toContain('20 of 120 controls assessed');
  });

  it('decodes HTML in finding labels instead of printing tags', () => {
    const { container } = draw(REPORT);

    expect(container.innerHTML).not.toContain('&lt;b&gt;');
  });

  it('handles a report with no findings', () => {
    const { container } = draw({ __metadata: {} });

    expect(container.textContent).toContain('No findings');
  });
});
