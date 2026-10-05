import React, { useEffect, useMemo, useState } from 'react';
import { flushSync } from 'react-dom';
import { Header } from '@cloudscape-design/components';
import { capitalize, dispositionLabel, flattenEvidenceForPrint, printableFindings, printableRemediation, scoreClassificationLabel, statusLabel } from './data';
import { Markdown } from './FindingDetail';

function PrintRemediation({ remediation }) {
  if (remediation.kind === 'none') return <p>No remediation guidance.</p>;
  if (remediation.kind === 'flat') return <Markdown html={remediation.html} />;
  return (
    <div className="acr-print-remediation">
      <p><strong>{remediation.summary}</strong></p>
      {remediation.applies_if && <p><strong>Applies if relevant:</strong> {remediation.applies_if}</p>}
      <ol>
        {remediation.steps.map((step) => (
          <li key={step.order}>
            <Markdown html={step.instruction_html} />
            {step.console_path && <p><strong>Console:</strong> {step.console_path}</p>}
            {step.command && <pre><code>{step.command}</code></pre>}
          </li>
        ))}
      </ol>
      {remediation.target_resources.length > 0 && (
        <p><strong>Targets:</strong> {remediation.target_resources.join(', ')}</p>
      )}
      {remediation.references.length > 0 && (
        <div>
          <strong>References</strong>
          <ul>
            {remediation.references.map((reference) => (
              <li key={reference.url + reference.title}>
                {reference.title}{reference.url ? ` (${reference.url})` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// Stand-in for the interactive findings table when printing: that table shows one
// filtered page, so a PDF of it would silently drop most findings. The complete
// non-interactive record layout is rendered only while printing.
export default function PrintFindings({ data, pillarLabel }) {
  const [printing, setPrinting] = useState(false);
  useEffect(() => {
    // beforeprint fires for both the Export menu and the browser's own Print command;
    // flushSync commits the table before the browser snapshots the page.
    const before = () => flushSync(() => setPrinting(true));
    const after = () => setPrinting(false);
    window.addEventListener('beforeprint', before);
    window.addEventListener('afterprint', after);
    return () => {
      window.removeEventListener('beforeprint', before);
      window.removeEventListener('afterprint', after);
    };
  }, []);
  const findings = useMemo(() => (printing ? printableFindings(data.findings) : []), [printing, data]);
  if (!printing) return null;

  return (
    <div>
      <Header variant="h2" counter={`(${findings.length})`} description={data.scope_instance_id ? `Instance ${data.scope_instance_id}` : 'All instances'}>
        {data.scope_instance_id ? 'Scoped findings' : 'All findings'}
      </Header>
      <div className="acr-print-finding-list">
        {findings.map((f) => {
          const evidence = flattenEvidenceForPrint(f.evidence);
          const remediation = printableRemediation(f);
          return (
            <article className="acr-print-finding" key={f.key}>
              <h3>{f.check_name}</h3>
              <dl className="acr-print-record">
                <dt>Check ID</dt><dd><code>{f.check_id}</code></dd>
                <dt>Severity</dt><dd>{capitalize(f.severity)}</dd>
                <dt>Execution status</dt><dd>{statusLabel(f.status)}</dd>
                <dt>Disposition</dt><dd>{dispositionLabel(f.disposition)}</dd>
                <dt>Score classification</dt><dd>{scoreClassificationLabel(f.score_classification)}</dd>
                <dt>Pillar</dt><dd>{pillarLabel[f.pillar] ?? f.pillar}</dd>
                <dt>Resource</dt><dd>{f.resource_label || f.instance}</dd>
              </dl>
              <h4>Description</h4>
              <Markdown html={f.description_html} />
              {f.methodology && (
                <>
                  <h4>Methodology</h4>
                  <dl className="acr-print-record">
                    <dt>Why this is assessed</dt><dd>{f.methodology.reason}</dd>
                    <dt>Evidence source</dt><dd>{f.methodology.evidence_source}</dd>
                    <dt>What the evidence cannot prove</dt><dd>{f.methodology.proof_limitations}</dd>
                    <dt>What this means</dt><dd>{f.methodology.developer_admin_meaning}</dd>
                    <dt>Verification and closure</dt><dd>{f.methodology.verification_criteria}</dd>
                    {f.responsible_function && <><dt>Responsible function</dt><dd>{f.responsible_function}</dd></>}
                    {f.primary_lens_reference && <><dt>Primary lens reference</dt><dd>{f.primary_lens_reference}</dd></>}
                  </dl>
                </>
              )}
              <h4>{f.action_label}</h4>
              <PrintRemediation remediation={remediation} />
              {evidence.length > 0 && (
                <>
                  <h4>Evidence</h4>
                  <dl className="acr-print-record acr-print-evidence">
                    {evidence.map((item, index) => (
                      <React.Fragment key={`${item.label}-${index}`}>
                        <dt>{item.label}</dt><dd>{item.value}</dd>
                      </React.Fragment>
                    ))}
                  </dl>
                </>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
}
