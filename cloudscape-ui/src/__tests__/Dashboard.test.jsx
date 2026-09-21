import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { HashRouter } from 'react-router-dom';

import Dashboard from '../components/Dashboard';
import { REPORT, manyServices } from './fixtures/report';

const draw = (data) => render(<HashRouter><Dashboard data={data} /></HashRouter>);

describe('Dashboard', () => {
  it('shows account-wide totals', () => {
    const { container } = draw(REPORT);
    const text = container.textContent;

    expect(text).toContain('Assessment Summary');
    expect(text).toContain('Total findings');
    expect(text).toContain('38');
  });

  it('renders all five Well-Architected pillars, including empty ones', () => {
    const { container } = draw(REPORT);

    ['Security', 'Reliability', 'Cost Ops', 'Performance', 'Ops Excellence']
      .forEach(pillar => expect(container.textContent).toContain(pillar));
  });

  it('marks a pillar with no findings as clean rather than hiding it', () => {
    const { container } = draw(REPORT);

    // The fixture has no Performance findings.
    expect(container.textContent).toContain('No findings');
  });

  it('uses status indicators rather than emoji for severity', () => {
    const { container } = draw(REPORT);

    ['🚫', '⚠️', '👁️', 'ℹ️'].forEach(glyph => {
      expect(container.textContent).not.toContain(glyph);
    });
  });

  it('ranks services by high severity rather than alphabetically', () => {
    const { container } = draw(REPORT);
    const order = [...container.querySelectorAll('tbody tr a')].map(a => a.textContent);

    // ec2 has the high-severity findings; alphabetically it would follow s3/iam
    // only by coincidence, so assert it leads.
    expect(order[0]).toBe('EC2');
  });

  it('paginates instead of rendering one card per service on a wide scan', () => {
    const { container } = draw(manyServices(30));
    const rows = container.querySelectorAll('tbody tr');

    expect(rows.length).toBeLessThanOrEqual(12);
    expect(container.textContent).toContain('(30)');
  });

  it('offers no filter or pagination on a small scan', () => {
    const { container } = draw(REPORT);

    expect(container.textContent).not.toContain('Find a service');
  });

  it('links to the risk summary for prioritisation', () => {
    const { container } = draw(REPORT);

    expect(container.textContent).toContain('What should I fix first?');
  });

  it('handles a report with no services', () => {
    const { container } = draw({ __metadata: {} });

    expect(container.textContent).toContain('No services found');
  });
});
