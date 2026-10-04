import React from 'react';
import { BarChart, Box, Button, ColumnLayout, Container, Header, PieChart, SpaceBetween } from '@cloudscape-design/components';
import { FILTER_QUERIES, SEVERITIES, SEVERITY_COLOR, STATUS, capitalize } from './data';

const emptyState = (text) => (
  <Box textAlign="center" color="inherit" padding={{ vertical: 'xxl' }}>
    <b>{text}</b>
  </Box>
);
const empty = emptyState('No data');

export default function Charts({ data, onShowFindings }) {
  const { findings, pillars, charts } = data;
  const statusKinds = ['scored_pass', 'scored_fail', 'unevaluated_control', 'not_applicable', 'manual_review', 'informational'];
  const statusData = charts.status_distribution.labels.map((title, index) => ({
    title,
    value: charts.status_distribution.data[index],
    color: charts.status_distribution.colors[index],
    filterKind: statusKinds[index],
  })).filter((item) => item.value > 0);
  const severityCounts = Object.fromEntries(
    charts.severity_distribution.labels.map((label, index) => [
      label.toLowerCase(),
      charts.severity_distribution.data[index],
    ]),
  );
  const pillarsWithFindings = pillars.filter((p) => findings.some((f) => f.pillar === p.id));
  const pillarSeriesDefinitions = [
    ['passed', 'Scored control passes', STATUS.pass.color],
    ['failed', 'Scored control failures', STATUS.fail.color],
    ['manual_review_candidates', 'Manual-review candidates', SEVERITY_COLOR.medium],
    ['informational_records', 'Informational records', STATUS.not_applicable.color],
    ['unevaluated_controls', 'Unevaluated controls', STATUS.skipped.color],
  ];
  const pillarSeries = pillarSeriesDefinitions.map(([key, title, color]) => ({
    key,
    title,
    type: 'bar',
    color,
    data: pillarsWithFindings.map((pillar) => ({
      x: pillar.label,
      y: charts.pillar_breakdown[pillar.id]?.[key] ?? 0,
    })),
  }));

  return (
    <ColumnLayout columns={3}>
      <Container header={<Header variant="h2">Assessment records</Header>}>
        <PieChart
          data={statusData}
          variant="donut"
          innerMetricValue={String(data.stats.total_records)}
          innerMetricDescription="records"
          hideFilter
          size="medium"
          detailPopoverContent={(segment) => [{ key: 'Records', value: segment.value }]}
          detailPopoverFooter={(segment) => (
            <Button variant="inline-link" onClick={() => onShowFindings(FILTER_QUERIES.statusDistribution(segment.filterKind))}>
              View {segment.title.toLowerCase()}
            </Button>
          )}
          empty={empty}
          ariaLabel="Check status distribution"
        />
      </Container>
      <Container header={<Header variant="h2">Failed controls by severity</Header>}>
        {SEVERITIES.every((sev) => !severityCounts[sev]) ? (
          emptyState('No failed controls')
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
            detailPopoverSeriesContent={({ series, x, y }) => ({
              key: series.title,
              value: (
                <SpaceBetween size="xxs">
                  <span>{y}</span>
                  <Button variant="inline-link" onClick={() => onShowFindings(FILTER_QUERIES.failedSeverity(String(x).toLowerCase()))}>
                    View {String(x).toLowerCase()} failed controls
                  </Button>
                </SpaceBetween>
              ),
            })}
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
            detailPopoverSeriesContent={({ series, x, y }) => ({
              key: series.title,
              value: (
                <SpaceBetween size="xxs">
                  <span>{y}</span>
                  <Button variant="inline-link" onClick={() => onShowFindings(FILTER_QUERIES.pillarStack(series.key, x))}>
                    View {String(x)} {series.title.toLowerCase()}
                  </Button>
                </SpaceBetween>
              ),
            })}
            height={220}
            empty={empty}
            ariaLabel="Findings by pillar"
          />
        )}
      </Container>
    </ColumnLayout>
  );
}
