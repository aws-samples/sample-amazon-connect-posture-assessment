import React, { useLayoutEffect, useRef } from 'react';
import DOMPurify from 'dompurify';
import CodeView from '@cloudscape-design/code-view/code-view';
import {
  Alert,
  Box,
  CopyToClipboard,
  ExpandableSection,
  KeyValuePairs,
  Link,
  SpaceBetween,
} from '@cloudscape-design/components';
import AdaptiveEvidence from './AdaptiveEvidence';
import { evidenceCellFullValue, safeHref } from './data';
import { DispositionBadge, SeverityBadge, Status } from './Findings';

// Finding markdown is rendered server-side by markdown-it with raw HTML, images
// and links disabled (ReportGenerator._get_markdown_parser). It is sanitized
// again here (defense in depth) before injection.
const SANITIZE_OPTIONS = {
  USE_PROFILES: { html: true },
  FORBID_TAGS: ['img', 'a', 'style', 'form', 'iframe', 'object', 'embed'],
  FORBID_ATTR: ['style', 'srcset'],
};

const FRAGMENT_OPTIONS = { ...SANITIZE_OPTIONS, RETURN_DOM_FRAGMENT: true };

export const sanitizeHtml = (html) => DOMPurify.sanitize(String(html), SANITIZE_OPTIONS);

// Returns a sanitized DocumentFragment; nodes are attached by reference, so the
// markup is never re-parsed from a string through a React HTML-injection prop.
export const sanitizeToFragment = (html) => DOMPurify.sanitize(String(html), FRAGMENT_OPTIONS);

export const Markdown = ({ html }) => {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (ref.current) ref.current.replaceChildren(html ? sanitizeToFragment(html) : '');
  }, [html]);
  return html ? <div className="acr-markdown" ref={ref} /> : null;
};

const Copy = ({ text }) => (
  <CopyToClipboard variant="icon" textToCopy={text} copyButtonAriaLabel="Copy" copySuccessText="Copied" copyErrorText="Copy failed" />
);

function EvidenceCell({ cell }) {
  if (!cell) return null;
  if (cell.kind === 'null') return <Box color="text-status-inactive">—</Box>;
  const value = evidenceCellFullValue(cell);
  if (cell.kind === 'arn') {
    return (
      <span title={value}>
        <Box variant="code">{value}</Box>
      </span>
    );
  }
  return <span title={value}>{value}</span>;
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
      {block.tables.map((table) => <AdaptiveEvidence key={table.title} table={table} />)}
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
          {rem.references.map((ref) => {
            const href = safeHref(ref.url);
            return href ? (
              <Link key={ref.url + ref.title} href={href} external>
                {ref.title}
              </Link>
            ) : (
              <Box key={ref.url + ref.title}>{ref.title}</Box>
            );
          })}
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
          { label: 'Execution status', value: <Status status={finding.status} /> },
          { label: 'Disposition', value: <DispositionBadge disposition={finding.disposition} /> },
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
      {finding.methodology && (
        <ExpandableSection headerText="Assessment methodology" variant="container" defaultExpanded>
          <KeyValuePairs
            columns={1}
            items={[
              { label: 'Why this is assessed', value: finding.methodology.reason },
              { label: 'Evidence source', value: finding.methodology.evidence_source },
              { label: 'What the evidence cannot prove', value: finding.methodology.proof_limitations },
              { label: 'What this means', value: finding.methodology.developer_admin_meaning },
              { label: 'Verification and closure', value: finding.methodology.verification_criteria },
              ...(finding.methodology.responsible_function
                ? [{ label: 'Responsible function', value: finding.methodology.responsible_function }]
                : []),
              ...(finding.methodology.primary_lens_reference
                ? [{ label: 'Primary lens reference', value: finding.methodology.primary_lens_reference }]
                : []),
            ]}
          />
        </ExpandableSection>
      )}
      <ExpandableSection headerText={finding.action_label} variant="container" defaultExpanded>
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
