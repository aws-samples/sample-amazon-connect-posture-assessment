import React from 'react';
import CodeView from '@cloudscape-design/code-view/code-view';
import {
  Alert,
  Box,
  CopyToClipboard,
  ExpandableSection,
  Header,
  KeyValuePairs,
  Link,
  SpaceBetween,
  Table,
} from '@cloudscape-design/components';
import { SeverityBadge, Status } from './Findings';

// Finding markdown is rendered server-side by markdown-it with raw HTML
// disabled (ReportGenerator._render_markdown), so it is safe to inject.
export const Markdown = ({ html }) =>
  // nosemgrep: typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml
  html ? <div className="acr-markdown" dangerouslySetInnerHTML={{ __html: html }} /> : null;

const Copy = ({ text }) => (
  <CopyToClipboard variant="icon" textToCopy={text} copyButtonAriaLabel="Copy" copySuccessText="Copied" copyErrorText="Copy failed" />
);

function EvidenceCell({ cell }) {
  if (!cell) return null;
  if (cell.kind === 'null') return <Box color="text-status-inactive">—</Box>;
  if (cell.kind === 'arn') {
    return (
      <span title={cell.full}>
        <Box variant="code">{cell.text}</Box>
      </span>
    );
  }
  return <span title={cell.full}>{cell.text}</span>;
}

// Renders ReportGenerator._evidence_view output. Nesting depth is capped
// server-side, so this recursion is bounded.
function EvidenceBlock({ block }) {
  if (block.fallback !== undefined) return <CodeView content={block.fallback} />;
  return (
    <SpaceBetween size="m">
      {block.pairs.length > 0 && (
        <KeyValuePairs columns={2} items={block.pairs.map((p) => ({ label: p.label, value: <EvidenceCell cell={p.value} /> }))} />
      )}
      {block.tables.map((table) => (
        <Table
          key={table.title}
          variant="embedded"
          wrapLines
          header={
            <Header variant="h3" counter={`(${table.rows.length})`}>
              {table.title}
            </Header>
          }
          items={table.rows.map((cells, i) => ({ i, cells }))}
          trackBy="i"
          columnDefinitions={table.columns.map((column, c) => ({
            id: `c${c}`,
            header: column,
            cell: (row) => <EvidenceCell cell={row.cells[c]} />,
          }))}
        />
      ))}
      {block.lists.map((list) => (
        <SpaceBetween key={list.title} size="xxs">
          <Box variant="h4">
            {list.title}{' '}
            <Box variant="span" color="text-body-secondary">
              ({list.items.length})
            </Box>
          </Box>
          {list.items.length ? (
            <ul style={{ margin: 0, paddingInlineStart: 20 }}>
              {list.items.map((cell, i) => (
                <li key={i}>
                  <EvidenceCell cell={cell} />
                </li>
              ))}
            </ul>
          ) : (
            <Box color="text-status-inactive">None</Box>
          )}
        </SpaceBetween>
      ))}
      {block.sections.map((section) => (
        <ExpandableSection key={section.title} headerText={section.title} variant="inline" defaultExpanded>
          <EvidenceBlock block={section.block} />
        </ExpandableSection>
      ))}
    </SpaceBetween>
  );
}

function Remediation({ finding }) {
  const rem = finding.structured_remediation;
  if (!rem) {
    return finding.remediation_html ? <Markdown html={finding.remediation_html} /> : <Box color="text-status-inactive">No remediation guidance.</Box>;
  }
  return (
    <SpaceBetween size="m">
      <Box fontWeight="bold">{rem.summary}</Box>
      {rem.applies_if && <Alert type="info">Applies if relevant: {rem.applies_if}</Alert>}
      {rem.steps.map((step) => (
        <SpaceBetween key={step.order} size="xs">
          <Box variant="h4">Step {step.order}</Box>
          <Markdown html={step.instruction_html} />
          {step.console_path && <Box color="text-body-secondary">Console: {step.console_path}</Box>}
          {step.command && <CodeView content={step.command} actions={<Copy text={step.command} />} />}
        </SpaceBetween>
      ))}
      {rem.target_resources.length > 0 && (
        <KeyValuePairs items={[{ label: 'Targets', value: rem.target_resources.join(', ') }]} />
      )}
      {rem.references.length > 0 && (
        <SpaceBetween size="xxs">
          <Box variant="h4">References</Box>
          {rem.references.map((ref) => (
            <Link key={ref.url + ref.title} href={ref.url} external>
              {ref.title}
            </Link>
          ))}
        </SpaceBetween>
      )}
    </SpaceBetween>
  );
}

export default function FindingDetail({ finding }) {
  return (
    <SpaceBetween size="l">
      <KeyValuePairs
        columns={2}
        items={[
          { label: 'Severity', value: <SeverityBadge severity={finding.severity} /> },
          { label: 'Status', value: <Status status={finding.status} /> },
          { label: 'Pillar', value: finding.pillarLabel },
          { label: 'Check ID', value: <Box variant="code">{finding.check_id}</Box> },
          { label: 'Resource type', value: finding.resource_type },
          {
            label: 'Resource',
            value: (
              <CopyToClipboard
                variant="inline"
                textToCopy={finding.resource_id}
                textToDisplay={finding.resource_label}
                copySuccessText="Resource ID copied"
                copyErrorText="Copy failed"
              />
            ),
          },
          { label: 'Checked at', value: finding.timestamp },
        ]}
      />
      <Markdown html={finding.description_html} />
      <ExpandableSection headerText="Remediation" variant="container" defaultExpanded>
        <Remediation finding={finding} />
      </ExpandableSection>
      {finding.evidence && (
        <ExpandableSection headerText="Evidence" variant="container" defaultExpanded={finding.status !== 'pass'}>
          <SpaceBetween size="m">
            <EvidenceBlock block={finding.evidence} />
            <ExpandableSection headerText="Raw evidence (JSON)" variant="footer">
              <CodeView content={finding.evidence_json} lineNumbers actions={<Copy text={finding.evidence_json} />} />
            </ExpandableSection>
          </SpaceBetween>
        </ExpandableSection>
      )}
    </SpaceBetween>
  );
}
