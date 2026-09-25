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
import { ALERT_TYPE } from './data';

const Counter = ({ children, color }) => (
  <Box variant="awsui-value-large" color={color}>
    {children}
  </Box>
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
        <Alert type="warning" header={`${data.execution_errors.length} issue(s) occurred while running the assessment`}>
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

export function ExecutiveSummary({ data }) {
  const { summary, stats } = data;
  return (
    <Container
      header={
        <Header variant="h2" description={`Assessed ${data.assessment.timestamp}`}>
          Executive summary
        </Header>
      }
    >
      <KeyValuePairs
        columns={4}
        items={[
          { label: 'Total checks', value: <Counter>{summary.total_checks}</Counter> },
          { label: 'Passed', value: <Counter color="text-status-success">{summary.passed_checks}</Counter> },
          { label: 'Failed', value: <Counter color="text-status-error">{summary.failed_checks}</Counter> },
          {
            label: 'Pass rate',
            value: <Counter>{stats.pass_rate}%</Counter>,
            info: <Box color="text-body-secondary" fontSize="body-s">excl. skipped / N/A</Box>,
          },
          {
            label: 'Risk score',
            value: <Counter color={stats.risk_score >= 70 ? 'text-status-error' : undefined}>{stats.risk_score}</Counter>,
            info: <Box color="text-body-secondary" fontSize="body-s">0–100, severity-weighted</Box>,
          },
          { label: 'Registered checks', value: <Counter>{stats.registered_checks}</Counter> },
          { label: 'Journey findings', value: <Counter>{stats.journey_findings}</Counter> },
          { label: 'Connect instances', value: <Counter>{stats.instances_assessed}</Counter> },
        ]}
      />
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
              {(rec.priority === 'critical' || rec.priority === 'high') && (
                <Button variant="inline-link" onClick={() => onShowFindings(rec.priority)}>
                  View findings
                </Button>
              )}
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
