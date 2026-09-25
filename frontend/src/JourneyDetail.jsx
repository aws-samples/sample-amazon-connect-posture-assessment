import React from 'react';
import { Box, Button, Header, KeyValuePairs, SpaceBetween, StatusIndicator, Table } from '@cloudscape-design/components';
import { CategoryLabel, RouteStatus } from './JourneyMap';

const capitalize = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' ') : '');

function OutcomesTable({ title, outcomes, showActions }) {
  return (
    <Table
      variant="embedded"
      wrapLines
      header={
        <Header variant="h3" counter={`(${outcomes.length})`}>
          {title}
        </Header>
      }
      items={outcomes.map((o, i) => ({ i, ...o }))}
      trackBy="i"
      columnDefinitions={[
        {
          id: 'label',
          header: 'Outcome',
          isRowHeader: true,
          cell: (o) => (
            <SpaceBetween size="xxxs">
              <span>{o.label}</span>
              <Box color="text-body-secondary" fontSize="body-s">
                {capitalize(o.transition_type)}
                {showActions ? ` · ${o.source_action_label || o.source_action_id} → ${o.target_action_label || o.target_action_id}` : ''}
              </Box>
            </SpaceBetween>
          ),
        },
        ...(showActions ? [{ id: 'route', header: 'Route', cell: (o) => <RouteStatus routeType={o.route_type} />, width: 120 }] : []),
        { id: 'raw', header: 'Connect value', cell: (o) => <Box variant="code" fontSize="body-s">{o.raw_label}</Box>, minWidth: 160 },
        { id: 'meaning', header: 'Meaning', cell: (o) => o.meaning || '—' },
      ]}
    />
  );
}

export default function JourneyDetail({ entry, selection, onSelect }) {
  const model = entry.diagram_model;
  const nodeTitle = (key) => model.nodes[key]?.title ?? key;
  const NodeLink = ({ nodeKey }) => (
    <Button variant="inline-link" onClick={() => onSelect({ kind: 'node', key: nodeKey })}>
      {nodeTitle(nodeKey)}
    </Button>
  );

  if (selection.kind === 'edge') {
    const edge = model.edges[selection.key];
    if (!edge) return null;
    return (
      <SpaceBetween size="l">
        <KeyValuePairs
          columns={2}
          items={[
            { label: 'From', value: <NodeLink nodeKey={edge.source} /> },
            { label: 'To', value: <NodeLink nodeKey={edge.target} /> },
            { label: 'Route type', value: <RouteStatus routeType={edge.route_type} /> },
            { label: 'Primary path', value: edge.is_primary ? <StatusIndicator type="success">On primary path</StatusIndicator> : 'No' },
          ]}
        />
        {edge.summary && <Box>{edge.summary}</Box>}
        <OutcomesTable title="Amazon Connect outcomes on this route" outcomes={edge.outcomes} />
      </SpaceBetween>
    );
  }

  const node = model.nodes[selection.key];
  if (!node) return null;
  const incoming = Object.entries(model.edges).filter(([, e]) => e.target === selection.key);
  const outgoing = Object.entries(model.edges).filter(([, e]) => e.source === selection.key);
  const routeTable = (title, rows, direction) => (
    <Table
      variant="embedded"
      wrapLines
      header={
        <Header variant="h3" counter={`(${rows.length})`}>
          {title}
        </Header>
      }
      items={rows.map(([key, e]) => ({ key, ...e }))}
      trackBy="key"
      empty={<Box color="text-body-secondary">None</Box>}
      columnDefinitions={[
        {
          id: 'when',
          header: 'When',
          cell: (e) => (
            <Button variant="inline-link" onClick={() => onSelect({ kind: 'edge', key: e.key })}>
              {e.title}
            </Button>
          ),
        },
        { id: 'step', header: direction === 'out' ? 'Goes to' : 'Comes from', cell: (e) => <NodeLink nodeKey={direction === 'out' ? e.target : e.source} /> },
        { id: 'route', header: 'Route', cell: (e) => <RouteStatus routeType={e.route_type} />, width: 130 },
      ]}
    />
  );
  const ai = node.ai || {};
  const aiItems = [
    ['identity', 'AI agent'],
    ['technology', 'Technology'],
    ['subtype', 'Type'],
    ['alias', 'Alias'],
  ].filter(([k]) => ai[k]);

  return (
    <SpaceBetween size="l">
      <KeyValuePairs
        columns={2}
        items={[
          { label: 'Type', value: <CategoryLabel category={node.category} /> },
          { label: 'Entry point', value: node.is_entry ? 'Yes' : 'No' },
          { label: 'Primary path', value: node.is_primary ? <StatusIndicator type="success">On primary path</StatusIndicator> : 'No' },
          { label: 'Underlying actions', value: node.actions.length },
        ]}
      />
      {node.summary && <Box>{node.summary}</Box>}
      {node.scope?.length > 0 && (
        <SpaceBetween size="xxs">
          <Box variant="h3">{node.is_group ? 'What this group does' : 'What happens'}</Box>
          <ul style={{ margin: 0, paddingInlineStart: 20 }}>
            {node.scope.map((item) => (
              <li key={item}>
                <Box variant="p">{item}</Box>
              </li>
            ))}
          </ul>
        </SpaceBetween>
      )}
      {aiItems.length > 0 && <KeyValuePairs columns={2} items={aiItems.map(([k, label]) => ({ label, value: ai[k] }))} />}
      {routeTable('Routes out', outgoing, 'out')}
      {routeTable('Routes in', incoming, 'in')}
      {node.absorbed_outcomes?.length > 0 && (
        <OutcomesTable title="Routes handled inside this step" outcomes={node.absorbed_outcomes} showActions />
      )}
      <Table
        variant="embedded"
        wrapLines
        header={
          <Header variant="h3" counter={`(${node.actions.length})`}>
            Contact flow actions
          </Header>
        }
        items={node.actions}
        trackBy="id"
        columnDefinitions={[
          { id: 'id', header: 'Action ID', cell: (a) => <Box variant="code">{a.id}</Box>, width: 140 },
          { id: 'type', header: 'Type', cell: (a) => a.type },
          { id: 'detail', header: 'Detail', cell: (a) => a.detail },
        ]}
      />
    </SpaceBetween>
  );
}
