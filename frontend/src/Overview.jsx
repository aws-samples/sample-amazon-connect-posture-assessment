import React from 'react';
import {
  Alert,
  Box,
  Button,
  Container,
  ExpandableSection,
  Header,
  KeyValuePairs,
  SpaceBetween,
  StatusIndicator,
} from '@cloudscape-design/components';
import { ALERT_TYPE, DISPOSITIONS, FILTER_QUERIES } from './data';

const Counter = ({ children, color }) => (
  <Box tagOverride="span" variant="awsui-value-large" color={color}>
    {children}
  </Box>
);

const MetricLink = ({ children, color, query, label, onShowFindings }) => (
  <button
    type="button"
    className="acr-metric-link"
    aria-label={`${label}: ${children}`}
    title={label}
    onClick={() => onShowFindings(query)}
  >
    <Counter color={color}>{children}</Counter>
  </button>
);

export function Insights({ data }) {
  return (
    <SpaceBetween size="s">
      {data.insights.map((insight) => (
        <Alert key={insight.message} type={ALERT_TYPE[insight.type] ?? 'info'}>
          {insight.message}
        </Alert>
      ))}
      {data.execution_errors.length > 0 && (
        <Alert type="warning" header={`${data.execution_errors.length} issue(s) occurred during the full assessment${data.scope_instance_id ? ' (all instances)' : ''}`}>
          <ExpandableSection headerText="Show details" variant="footer">
            <ul>
              {data.execution_errors.map((err, i) => (
                <li key={i}>{err}</li>
              ))}
            </ul>
          </ExpandableSection>
        </Alert>
      )}
    </SpaceBetween>
  );
}

export function ExecutiveSummary({ data, onShowFindings }) {
  const { stats } = data;
  return (
    <Container
      header={
        <Header variant="h2" description={`Assessed ${data.assessment.timestamp}`}>
          Executive summary
        </Header>
      }
    >
      <SpaceBetween size="l">
        <KeyValuePairs
          columns={4}
          items={[
            {
              label: 'Total records',
              value: <MetricLink query={FILTER_QUERIES.allRecords()} label="View all scoped records" onShowFindings={onShowFindings}>{stats.total_records}</MetricLink>,
            },
            {
              label: 'Control posture',
              value: (
                <SpaceBetween size="xxs">
                  <MetricLink query={FILTER_QUERIES.controlPosture()} label="View scored controls" onShowFindings={onShowFindings}>
                    {stats.scored_control_numerator}/{stats.scored_control_denominator}
                  </MetricLink>
                  <Box color="text-body-secondary" fontSize="body-s">{stats.pass_rate_display} pass rate</Box>
                </SpaceBetween>
              ),
            },
            {
              label: 'Failed controls',
              value: <MetricLink color="text-status-error" query={FILTER_QUERIES.failedControls()} label="View failed controls" onShowFindings={onShowFindings}>{stats.scored_control_failures}</MetricLink>,
            },
            {
              label: 'Unevaluated controls',
              value: <MetricLink query={FILTER_QUERIES.unevaluatedControls()} label="View unevaluated controls" onShowFindings={onShowFindings}>{stats.unevaluated_controls}</MetricLink>,
            },
            {
              label: 'Manual-review candidates',
              value: <MetricLink query={FILTER_QUERIES.manualReviewCandidates()} label="View manual-review candidates" onShowFindings={onShowFindings}>{stats.manual_review_candidates}</MetricLink>,
            },
            {
              label: 'Manual-review records',
              value: <MetricLink query={FILTER_QUERIES.manualReviewRecords()} label="View manual-review records" onShowFindings={onShowFindings}>{stats.manual_review_findings}</MetricLink>,
            },
            {
              label: 'Informational records',
              value: <MetricLink query={FILTER_QUERIES.informationalRecords()} label="View informational records" onShowFindings={onShowFindings}>{stats.informational_findings}</MetricLink>,
            },
            {
              label: 'Not applicable',
              value: <MetricLink query={FILTER_QUERIES.notApplicableRecords()} label="View not-applicable records" onShowFindings={onShowFindings}>{stats.not_applicable_records}</MetricLink>,
            },
            {
              label: 'Failed-control severity index',
              value: <MetricLink color={stats.risk_score >= 70 ? 'text-status-error' : undefined} query={FILTER_QUERIES.failedControls()} label="View failed controls" onShowFindings={onShowFindings}>{stats.risk_score}</MetricLink>,
            },
            {
              label: 'Connect instances',
              value: <MetricLink query={FILTER_QUERIES.allRecords()} label="View scoped findings" onShowFindings={onShowFindings}>{stats.instances_assessed}</MetricLink>,
            },
          ]}
        />
        <ExpandableSection headerText="How to read results: disposition guide" variant="container" defaultExpanded>
          <SpaceBetween size="s">
            <Alert type="info" header="Execution status, disposition, and scoring answer different questions">
              Status reports what the check observed or whether it ran. Disposition explains how to use the record. Score classification determines whether the record contributes to control posture. Only Control records classified as Scored pass or Scored failure enter the posture numerator or denominator.
            </Alert>
            <KeyValuePairs
              columns={3}
              items={Object.values(DISPOSITIONS).map((item) => ({
                label: item.label,
                value: item.description,
              }))}
            />
          </SpaceBetween>
        </ExpandableSection>
      </SpaceBetween>
    </Container>
  );
}

const PRIORITY_INDICATOR = { critical: 'error', high: 'warning', medium: 'info' };

export function Recommendations({ data, onShowFindings }) {
  if (!data.recommendations.length) return null;
  return (
    <Container header={<Header variant="h2" counter={`(${data.recommendations.length})`}>Priority recommendations</Header>}>
      <SpaceBetween size="l">
        {data.recommendations.map((rec) => (
          <SpaceBetween key={rec.title} size="xxs">
            <Box variant="h3">{rec.title}</Box>
            <Box>{rec.description}</Box>
            <SpaceBetween direction="horizontal" size="s" alignItems="center">
              <StatusIndicator type={PRIORITY_INDICATOR[rec.priority] ?? 'info'}>
                {rec.findings_count} finding{rec.findings_count === 1 ? '' : 's'}
              </StatusIndicator>
              <Button variant="inline-link" onClick={() => onShowFindings(rec.query ?? FILTER_QUERIES.failedSeverity(rec.priority))}>
                View findings
              </Button>
            </SpaceBetween>
          </SpaceBetween>
        ))}
      </SpaceBetween>
    </Container>
  );
}

export function AssessmentDetails({ data }) {
  const { assessment, metadata } = data;
  return (
    <Container header={<Header variant="h2">Assessment details</Header>}>
      <KeyValuePairs
        columns={4}
        items={[
          { label: 'Account', value: assessment.account_id },
          { label: 'Region', value: assessment.region },
          { label: 'Assessment ID', value: <Box variant="code">{assessment.id}</Box> },
          { label: 'Assessed at', value: assessment.timestamp },
          { label: 'Tool version', value: metadata.tool_version },
          { label: 'Execution time', value: metadata.execution_time },
          { label: 'Environment', value: metadata.execution_environment },
          { label: 'Report generated', value: data.generated_at },
        ]}
      />
    </Container>
  );
}
