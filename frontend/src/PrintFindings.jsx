import React, { useEffect, useMemo, useState } from 'react';
import { flushSync } from 'react-dom';
import { Header } from '@cloudscape-design/components';
import { capitalize, dispositionLabel, flattenEvidenceForPrint, printableFindings, scoreClassificationLabel, statusLabel } from './data';
import { Markdown } from './FindingDetail';

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
                  </dl>
                </>
              )}
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
