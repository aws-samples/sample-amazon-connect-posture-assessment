import React, { useEffect, useMemo, useState } from 'react';
import { flushSync } from 'react-dom';
import { Header } from '@cloudscape-design/components';
import { capitalize, printableFindings, statusLabel } from './data';
import { Markdown } from './FindingDetail';

// Stand-in for the interactive findings table when printing: that table shows one
// filtered page, so a PDF of it would silently drop most findings. Rendered only
// while printing so large reports don't carry a second copy of every finding.
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
      <Header variant="h2" counter={`(${findings.length})`}>
        All findings
      </Header>
      <table className="acr-print-findings">
        <thead>
          <tr>
            <th>Check</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Pillar</th>
            <th>Resource</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.key}>
              <td>
                {f.check_name}
                <br />
                <code>{f.check_id}</code>
              </td>
              <td>{capitalize(f.severity)}</td>
              <td>{statusLabel(f.status)}</td>
              <td>{pillarLabel[f.pillar] ?? f.pillar}</td>
              <td>{f.resource_label || f.instance}</td>
              <td>
                <Markdown html={f.description_html} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
