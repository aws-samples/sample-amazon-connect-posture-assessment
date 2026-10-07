import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Box, Cards, CopyToClipboard, Header, Table } from '@cloudscape-design/components';
import { evidenceCellFullValue, evidenceLayout } from './data';

function EvidenceValue({ cell, copy = true }) {
  const value = evidenceCellFullValue(cell);
  if (cell?.kind === 'null') return <Box color="text-status-inactive">—</Box>;
  return (
    <span className="acr-evidence-value" title={value}>
      {cell?.kind === 'arn' ? <Box variant="code">{value}</Box> : value}
      {copy && value && (
        <CopyToClipboard
          variant="icon"
          textToCopy={value}
          copyButtonAriaLabel="Copy full evidence value"
          copySuccessText="Copied"
          copyErrorText="Copy failed"
        />
      )}
    </span>
  );
}

export default function AdaptiveEvidence({ table }) {
  const ref = useRef(null);
  const [width, setWidth] = useState(0);
  const items = useMemo(
    () => table.rows.map((cells, index) => ({ id: String(index), recordNumber: index + 1, cells })),
    [table.rows],
  );

  useLayoutEffect(() => {
    if (!ref.current) return undefined;
    const update = () => setWidth(ref.current?.getBoundingClientRect().width ?? 0);
    update();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(update);
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  const layout = evidenceLayout(width, table.columns.length);
  return (
    <div ref={ref}>
      {layout === 'table' ? (
        <Table
          variant="embedded"
          wrapLines
          header={<Header variant="h3" counter={`(${items.length})`}>{table.title}</Header>}
          items={items}
          trackBy="id"
          columnDefinitions={table.columns.map((column, index) => ({
            id: `c${index}`,
            header: column,
            width: 160,
            cell: (row) => <EvidenceValue cell={row.cells[index]} />,
          }))}
        />
      ) : (
        <Cards
          items={items}
          trackBy="id"
          cardsPerRow={[{ cards: 1 }]}
          header={<Header variant="h3" counter={`(${items.length})`}>{table.title}</Header>}
          cardDefinition={{
            header: (item) => `Record ${item.recordNumber}`,
            sections: table.columns.map((column, index) => ({
              id: `c${index}`,
              header: column,
              content: (item) => <EvidenceValue cell={item.cells[index]} />,
            })),
          }}
        />
      )}
    </div>
  );
}
