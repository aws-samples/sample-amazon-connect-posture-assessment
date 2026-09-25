import React from 'react';
import { BarChart, Box, ColumnLayout, Container, Header, PieChart } from '@cloudscape-design/components';
import { SEVERITIES, SEVERITY_COLOR, STATUS, capitalize } from './data';

const emptyState = (text) => (
  <Box textAlign="center" color="inherit" padding={{ vertical: 'xxl' }}>
    <b>{text}</b>
  </Box>
);
const empty = emptyState('No data');

export default function Charts({ data }) {
  const { summary, findings, pillars } = data;
  const statusCounts = {
    pass: summary.passed_checks,
    fail: summary.failed_checks,
    error: summary.error_checks,
    skipped: summary.skipped_checks,
    not_applicable: summary.not_applicable_checks,
  };
  const statusData = Object.entries(statusCounts)
    .filter(([, value]) => value > 0)
    .map(([key, value]) => ({ title: STATUS[key].label, value, color: STATUS[key].color }));
  const severityCounts = {
    critical: summary.critical_findings,
    high: summary.high_findings,
    medium: summary.medium_findings,
    low: summary.low_findings,
  };
  const pillarsWithFindings = pillars.filter((p) => findings.some((f) => f.pillar === p.id));
  const pillarSeries = [
    ['pass', 'Passed'],
    ['fail', 'Failed'],
    ['other', 'Other (error / skipped / N/A)'],
  ].map(([key, title]) => ({
    title,
    type: 'bar',
    color: key === 'other' ? STATUS.skipped.color : STATUS[key].color,
    data: pillarsWithFindings.map((p) => ({
      x: p.label,
      y: findings.filter(
        (f) => f.pillar === p.id && (key === 'other' ? f.status !== 'pass' && f.status !== 'fail' : f.status === key),
      ).length,
    })),
  }));

  return (
    <ColumnLayout columns={3}>
      <Container header={<Header variant="h2">Check status</Header>}>
        <PieChart
          data={statusData}
          variant="donut"
          innerMetricValue={String(summary.total_checks)}
          innerMetricDescription="checks"
          hideFilter
          size="medium"
          empty={empty}
          ariaLabel="Check status distribution"
        />
      </Container>
      <Container header={<Header variant="h2">Failed findings by severity</Header>}>
        {SEVERITIES.every((sev) => !severityCounts[sev]) ? (
          emptyState('No failed findings')
        ) : (
          <BarChart
            series={SEVERITIES.map((sev) => ({
              title: capitalize(sev),
              type: 'bar',
              color: SEVERITY_COLOR[sev],
              data: [{ x: capitalize(sev), y: severityCounts[sev] }],
            }))}
            xDomain={SEVERITIES.map(capitalize)}
            xScaleType="categorical"
            stackedBars
            hideFilter
            height={220}
            empty={empty}
            ariaLabel="Failed findings by severity"
          />
        )}
      </Container>
      <Container header={<Header variant="h2">Findings by pillar</Header>}>
        {pillarsWithFindings.length === 0 ? (
          emptyState('No findings')
        ) : (
          <BarChart
            series={pillarSeries}
            xScaleType="categorical"
            stackedBars
            horizontalBars
            hideFilter
            height={220}
            empty={empty}
            ariaLabel="Findings by pillar"
          />
        )}
      </Container>
    </ColumnLayout>
  );
}
