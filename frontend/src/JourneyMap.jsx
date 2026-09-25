import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  colorBackgroundContainerContent,
  colorBackgroundLayoutMain,
  colorBorderDividerDefault,
  colorBorderStatusInfo,
  colorChartsPaletteCategorical1,
  colorChartsPaletteCategorical3,
  colorChartsPaletteCategorical4,
  colorChartsPaletteCategorical5,
  colorChartsStatusNeutral,
  colorTextAccent,
  colorTextBodyDefault,
  colorTextBodySecondary,
  colorTextStatusError,
  colorTextStatusWarning,
  fontFamilyBase,
} from '@cloudscape-design/design-tokens';
import {
  Alert,
  Badge,
  Box,
  Button,
  ButtonDropdown,
  ColumnLayout,
  Container,
  FormField,
  Header,
  KeyValuePairs,
  SegmentedControl,
  Select,
  SpaceBetween,
  StatusIndicator,
  Table,
  Toggle,
} from '@cloudscape-design/components';
import { downloadSvgAsPng, downloadText, safeFilenamePart } from './download';

export const CATEGORIES = {
  speaks: { label: 'Caller hears', color: colorChartsPaletteCategorical1 },
  chooses: { label: 'Caller chooses', color: colorChartsPaletteCategorical4 },
  waits: { label: 'Caller waits', color: colorChartsPaletteCategorical5 },
  processing: { label: 'System work', color: colorChartsPaletteCategorical3 },
  terminal: { label: 'Call ends', color: colorChartsStatusNeutral },
};
export const ROUTE = {
  normal: { type: 'success', label: 'Normal', color: colorTextBodySecondary },
  fallback: { type: 'warning', label: 'Fallback', color: colorTextStatusWarning },
  exception: { type: 'error', label: 'Exception', color: colorTextStatusError },
};

const MIN_ZOOM = 0.25;
const MAX_ZOOM = 2;

export function CategoryLabel({ category }) {
  const cat = CATEGORIES[category] ?? CATEGORIES.processing;
  return (
    <SpaceBetween direction="horizontal" size="xxs" alignItems="center">
      <span aria-hidden="true" style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 2, background: cat.color }} />
      <span>{cat.label}</span>
    </SpaceBetween>
  );
}

export const RouteStatus = ({ routeType }) => (
  <StatusIndicator type={ROUTE[routeType]?.type ?? 'info'}>{ROUTE[routeType]?.label ?? routeType}</StatusIndicator>
);

// Draws the layout computed by journey/renderer.py (_layout_payload): node
// positions, orthogonal connector paths and label anchors are all server-side,
// so this view matches the SVG and draw.io exports exactly.
function Diagram({ model, zoom, highlightPrimary, selectedKey, onSelect }) {
  const { nodes, edges, layout } = model;
  const { width, height } = layout.canvas;
  const nodeW = layout.node_size.width;
  const nodeH = layout.node_size.height;
  const dim = (primary) => (highlightPrimary && !primary ? 0.2 : 1);
  const edgeColor = (key, edge) => {
    if (selectedKey === key) return colorBorderStatusInfo;
    if (highlightPrimary && edge.is_primary) return colorTextAccent;
    return ROUTE[edge.route_type]?.color ?? colorTextBodySecondary;
  };

  return (
    <div style={{ position: 'relative', width: width * zoom, height: height * zoom }}>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          width,
          height,
          transform: `scale(${zoom})`,
          transformOrigin: '0 0',
          fontFamily: fontFamilyBase,
        }}
      >
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ position: 'absolute', inset: 0 }} aria-hidden="true">
          {Object.entries(layout.connectors).map(([key, connector]) => {
            const edge = edges[key];
            if (!edge) return null;
            const color = edgeColor(key, edge);
            const emphasized = selectedKey === key || (highlightPrimary && edge.is_primary);
            return (
              <g key={key} opacity={dim(edge.is_primary)} style={{ cursor: 'pointer' }} onClick={() => onSelect({ kind: 'edge', key })}>
                {connector.paths.map((d) => (
                  <React.Fragment key={d}>
                    <path d={d} fill="none" stroke="transparent" strokeWidth="12" />
                    <path
                      d={d}
                      fill="none"
                      stroke={color}
                      strokeWidth={emphasized ? 2.5 : 1.5}
                      strokeDasharray={edge.route_type === 'normal' ? undefined : '6 4'}
                      strokeLinejoin="round"
                    />
                  </React.Fragment>
                ))}
                <path d={connector.arrow} fill={color} />
              </g>
            );
          })}
        </svg>

        {Object.entries(nodes).map(([key, node]) => {
          const pos = layout.positions[key];
          if (!pos) return null;
          const cat = CATEGORIES[node.category] ?? CATEGORIES.processing;
          const selected = selectedKey === key;
          return (
            <button
              type="button"
              key={key}
              onClick={() => onSelect({ kind: 'node', key })}
              aria-label={`Inspect step: ${node.title}`}
              aria-pressed={selected}
              title={node.title}
              style={{
                position: 'absolute',
                left: pos.x,
                top: pos.y,
                width: nodeW,
                height: nodeH,
                boxSizing: 'border-box',
                textAlign: 'start',
                cursor: 'pointer',
                opacity: dim(node.is_primary),
                overflow: 'hidden',
                background: colorBackgroundContainerContent,
                borderRadius: 12,
                border: `${selected ? 2 : 1}px ${node.category === 'processing' ? 'dashed' : 'solid'} ${selected ? colorBorderStatusInfo : colorBorderDividerDefault}`,
                borderInlineStart: `4px solid ${cat.color}`,
                padding: '6px 10px',
                font: 'inherit',
                boxShadow: selected ? `0 0 0 2px ${colorBorderStatusInfo}` : 'none',
              }}
            >
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase', color: cat.color }}>
                {node.is_entry ? 'Entry · ' : ''}
                {cat.label}
                {node.is_group ? ` · ${node.actions.length} actions` : ''}
              </div>
              <div
                style={{
                  fontSize: 12,
                  lineHeight: '16px',
                  color: colorTextBodyDefault,
                  marginTop: 2,
                  display: '-webkit-box',
                  WebkitLineClamp: 3,
                  WebkitBoxOrient: 'vertical',
                  overflow: 'hidden',
                }}
              >
                {node.title}
              </div>
            </button>
          );
        })}

        {Object.entries(layout.labels).map(([key, label]) => {
          const edge = edges[key];
          if (!edge) return null;
          const selected = selectedKey === key;
          const routeColor = ROUTE[edge.route_type]?.color ?? colorTextBodySecondary;
          return (
            <button
              type="button"
              key={key}
              onClick={() => onSelect({ kind: 'edge', key })}
              aria-label={`Inspect route: ${edge.title}`}
              aria-pressed={selected}
              title={label.tooltip}
              style={{
                position: 'absolute',
                left: label.x,
                top: Math.max(0, label.y - 24),
                transform: 'translateX(-50%)',
                whiteSpace: 'nowrap',
                cursor: 'pointer',
                opacity: dim(edge.is_primary),
                font: 'inherit',
                fontSize: 11,
                lineHeight: '18px',
                padding: '0 8px',
                borderRadius: 10,
                background: selected ? colorBorderStatusInfo : colorBackgroundContainerContent,
                color: selected ? colorBackgroundContainerContent : routeColor,
                border: `1px solid ${selected ? colorBorderStatusInfo : routeColor}`,
              }}
            >
              {label.text}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function StepsTable({ model, selectedKey, onSelect }) {
  const { positions } = model.layout;
  const order = Object.keys(model.nodes)
    .filter((k) => positions[k])
    .sort((a, b) => positions[a].x - positions[b].x || positions[a].y - positions[b].y);
  const items = order.map((key) => ({ key, ...model.nodes[key] }));
  const routesOut = (key) => Object.values(model.edges).filter((e) => e.source === key).length;
  return (
    <Table
      variant="embedded"
      items={items}
      trackBy="key"
      selectionType="single"
      selectedItems={items.filter((n) => n.key === selectedKey)}
      onSelectionChange={({ detail }) => onSelect({ kind: 'node', key: detail.selectedItems[0].key })}
      onRowClick={({ detail }) => onSelect({ kind: 'node', key: detail.item.key })}
      ariaLabels={{ selectionGroupLabel: 'Journey steps', itemSelectionLabel: (_, n) => n.title }}
      wrapLines
      columnDefinitions={[
        { id: 'type', header: 'Type', cell: (n) => <CategoryLabel category={n.category} />, width: 150 },
        { id: 'title', header: 'Step', cell: (n) => n.title, isRowHeader: true },
        {
          id: 'primary',
          header: 'Primary path',
          cell: (n) => (n.is_primary ? <StatusIndicator type="success">Yes</StatusIndicator> : '—'),
          width: 130,
        },
        { id: 'actions', header: 'Actions', cell: (n) => n.actions.length, width: 90 },
        { id: 'routes', header: 'Routes out', cell: (n) => routesOut(n.key), width: 110 },
      ]}
    />
  );
}

function EmptyJourney({ status }) {
  return (
    <Container header={<Header variant="h2">Caller journey map</Header>}>
      <SpaceBetween size="s">
        <Box>
          {status?.message ?? 'No inbound phone number in this assessment terminates on a contact flow, so there is no journey to draw.'}
        </Box>
        {status?.hint && (
          <Alert type="info" header="What to try">
            {status.hint}
          </Alert>
        )}
        {status?.reason && (
          <Box color="text-body-secondary" fontSize="body-s">
            Diagnostic: <Box variant="code">{status.reason}</Box>
          </Box>
        )}
      </SpaceBetween>
    </Container>
  );
}

export default function JourneyMap({ journey, selection, onSelect, onClearSelection }) {
  const entries = journey.entries;
  const instances = useMemo(
    () => [...new Map(entries.map((e) => [e.instance_id, e.instance_display_name || e.instance_id])).entries()],
    [entries],
  );
  const [instanceId, setInstanceId] = useState(instances[0]?.[0]);
  const numbers = entries.filter((e) => e.instance_id === instanceId);
  const [entryIndex, setEntryIndex] = useState(0);
  const entry = numbers[entryIndex] ?? numbers[0];
  const [view, setView] = useState('diagram');
  const [zoom, setZoom] = useState(1);
  const [highlightPrimary, setHighlightPrimary] = useState(false);
  const [exportStatus, setExportStatus] = useState(null);
  const canvasRef = useRef(null);

  const model = entry?.diagram_model;
  const layout = model?.layout;
  const fit = () => {
    if (!canvasRef.current || !layout) return;
    const available = canvasRef.current.clientWidth - 8;
    setZoom(Math.min(1.5, Math.max(MIN_ZOOM, available / layout.canvas.width)));
  };
  // The canvas only mounts in diagram view, so refit when returning to it too.
  useLayoutEffect(fit, [entry, view]);

  if (!entries.length) return <EmptyJourney status={journey.status} />;

  const selectedKey = selection && selection.entry === entry ? selection.key : undefined;
  const select = (s) => onSelect({ ...s, entry });
  const formats = entry.exports?.formats ?? {};
  const filename = (ext) => `caller-journey-${safeFilenamePart(entry.flow_name)}-${safeFilenamePart(entry.flow_id)}.${ext}`;

  const runExport = async (format) => {
    try {
      if (format === 'png') {
        setExportStatus({ type: 'in-progress', text: 'Preparing PNG…' });
        await downloadSvgAsPng(formats.svg, filename('png'));
      } else {
        const f = formats[format];
        downloadText(filename(format === 'svg' ? 'svg' : 'drawio'), f.content, f.media_type);
      }
      setExportStatus({ type: 'success', text: `${format === 'drawio' ? 'draw.io' : format.toUpperCase()} download started.` });
    } catch (error) {
      setExportStatus({ type: 'error', text: error.message || 'Export failed.' });
    }
  };

  const numberLabel = (e) => e.phone_number || e.flow_name;

  return (
    <Container
      header={
        <Header
          variant="h2"
          description="How a caller moves through the contact flow behind each inbound number. Only numbers that terminate on a contact flow are listed. Select a step or route for details."
          actions={
            <ButtonDropdown
              items={[
                { id: 'svg', text: 'SVG image', disabled: !formats.svg },
                { id: 'png', text: 'PNG image', disabled: !formats.svg },
                { id: 'drawio', text: 'draw.io diagram', disabled: !formats.drawio },
              ]}
              onItemClick={({ detail }) => runExport(detail.id)}
            >
              Export diagram
            </ButtonDropdown>
          }
        >
          Caller journey map
        </Header>
      }
    >
      <SpaceBetween size="l">
        <ColumnLayout columns={2}>
          <FormField label="Connect instance">
            <Select
              selectedOption={{ value: instanceId, label: instances.find(([id]) => id === instanceId)?.[1] }}
              options={instances.map(([value, label]) => ({ value, label, description: value }))}
              onChange={({ detail }) => {
                setInstanceId(detail.selectedOption.value);
                setEntryIndex(0);
                setExportStatus(null);
                onClearSelection();
              }}
            />
          </FormField>
          <FormField label="DID / toll-free number">
            <Select
              selectedOption={{ value: String(entryIndex), label: numberLabel(entry), description: entry.phone_description || undefined }}
              options={numbers.map((e, i) => ({
                value: String(i),
                label: numberLabel(e),
                description: e.phone_description || undefined,
                labelTag: e.flow_name,
                tags: e.phone_type ? [e.phone_type.replace(/_/g, ' ')] : undefined,
              }))}
              onChange={({ detail }) => {
                setEntryIndex(Number(detail.selectedOption.value));
                setExportStatus(null);
                onClearSelection();
              }}
            />
          </FormField>
        </ColumnLayout>

        <KeyValuePairs
          columns={4}
          items={[
            { label: 'Contact flow', value: entry.flow_name, info: <Box variant="code" fontSize="body-s">{entry.flow_id}</Box> },
            { label: 'Number type', value: entry.phone_type ? <Badge color="grey">{entry.phone_type.replace(/_/g, ' ')}</Badge> : '—' },
            { label: 'Displayed steps', value: model.displayed_step_count ?? Object.keys(model.nodes).length },
            {
              label: 'Flow actions',
              value:
                model.original_action_count !== undefined
                  ? `${model.original_action_count} (${model.original_action_count - (model.displayed_step_count ?? 0)} grouped)`
                  : '—',
            },
          ]}
        />

        {exportStatus && (
          <StatusIndicator type={exportStatus.type}>{exportStatus.text}</StatusIndicator>
        )}

        {!layout ? (
          <Alert type="info">{model.notice || 'A diagram is not available for this flow.'}</Alert>
        ) : (
          <>
            <SpaceBetween direction="horizontal" size="m" alignItems="center">
              <SegmentedControl
                selectedId={view}
                onChange={({ detail }) => setView(detail.selectedId)}
                label="Journey view"
                options={[
                  { id: 'diagram', text: 'Diagram', iconName: 'share' },
                  { id: 'steps', text: 'Steps list', iconName: 'list-view' },
                ]}
              />
              {view === 'diagram' && (
                <>
                  <SpaceBetween direction="horizontal" size="xxs" alignItems="center">
                    <Button variant="icon" iconName="zoom-out" ariaLabel="Zoom out" disabled={zoom <= MIN_ZOOM} onClick={() => setZoom((z) => Math.max(MIN_ZOOM, z - 0.15))} />
                    <Box variant="span" color="text-body-secondary">
                      <span aria-live="polite">{Math.round(zoom * 100)}%</span>
                    </Box>
                    <Button variant="icon" iconName="zoom-in" ariaLabel="Zoom in" disabled={zoom >= MAX_ZOOM} onClick={() => setZoom((z) => Math.min(MAX_ZOOM, z + 0.15))} />
                    <Button variant="icon" iconName="zoom-to-fit" ariaLabel="Fit diagram to width" onClick={fit} />
                  </SpaceBetween>
                  <Toggle checked={highlightPrimary} onChange={({ detail }) => setHighlightPrimary(detail.checked)}>
                    Highlight primary path
                  </Toggle>
                </>
              )}
            </SpaceBetween>

            {view === 'diagram' ? (
              <SpaceBetween size="s">
                <div
                  ref={canvasRef}
                  style={{
                    overflow: 'auto',
                    maxHeight: 640,
                    borderRadius: 16,
                    padding: 4,
                    border: `1px solid ${colorBorderDividerDefault}`,
                    background: colorBackgroundLayoutMain,
                  }}
                >
                  <Diagram model={model} zoom={zoom} highlightPrimary={highlightPrimary} selectedKey={selectedKey} onSelect={select} />
                </div>
                <SpaceBetween direction="horizontal" size="l">
                  {Object.keys(CATEGORIES).map((c) => (
                    <Box key={c} fontSize="body-s">
                      <CategoryLabel category={c} />
                    </Box>
                  ))}
                  {Object.entries(ROUTE).map(([k, r]) => (
                    <Box key={k} fontSize="body-s">
                      <SpaceBetween direction="horizontal" size="xxs" alignItems="center">
                        <svg width="24" height="8" aria-hidden="true">
                          <line x1="0" y1="4" x2="24" y2="4" stroke={r.color} strokeWidth="2" strokeDasharray={k === 'normal' ? undefined : '5 3'} />
                        </svg>
                        <span>{r.label} route</span>
                      </SpaceBetween>
                    </Box>
                  ))}
                </SpaceBetween>
              </SpaceBetween>
            ) : (
              <StepsTable model={model} selectedKey={selectedKey} onSelect={select} />
            )}
          </>
        )}
      </SpaceBetween>
    </Container>
  );
}
