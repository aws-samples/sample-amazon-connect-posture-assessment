import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useCollection } from '@cloudscape-design/collection-hooks';
import {
  Badge,
  Box,
  Button,
  CollectionPreferences,
  Header,
  Pagination,
  PropertyFilter,
  SpaceBetween,
  StatusIndicator,
  Table,
  Tabs,
} from '@cloudscape-design/components';
import { SEVERITIES, SEVERITY_RANK, STATUS, capitalize, defaultFilterQuery, statusLabel } from './data';
import { downloadText, findingsCsv } from './download';

export const SeverityBadge = ({ severity }) => <Badge color={`severity-${severity}`}>{capitalize(severity)}</Badge>;
export const Status = ({ status }) => (
  <StatusIndicator type={STATUS[status]?.type ?? 'info'}>{statusLabel(status)}</StatusIndicator>
);

// Count stacked under the name keeps each tab narrow enough that all pillars fit without scrolling.
const TabLabel = ({ name, failed }) => (
  <span style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center' }}>
    <span>{name}</span>
    <Box variant="small" color={failed ? 'text-status-error' : 'text-body-secondary'}>
      {failed} failed
    </Box>
  </span>
);

const COLUMNS = [
  { id: 'check_name', header: 'Check', cell: (f) => f.check_name, sortingField: 'check_name', isRowHeader: true, width: 360 },
  {
    id: 'severity',
    header: 'Severity',
    cell: (f) => <SeverityBadge severity={f.severity} />,
    sortingComparator: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  },
  { id: 'status', header: 'Status', cell: (f) => <Status status={f.status} />, sortingField: 'status' },
  { id: 'pillar', header: 'Pillar', cell: (f) => f.pillarLabel, sortingField: 'pillarLabel' },
  { id: 'instance', header: 'Instance', cell: (f) => f.instance, sortingField: 'instance' },
  { id: 'resource_type', header: 'Resource type', cell: (f) => f.resource_type, sortingField: 'resource_type' },
  { id: 'check_id', header: 'Check ID', cell: (f) => <Box variant="code">{f.check_id}</Box>, sortingField: 'check_id' },
];

const FILTERING_PROPERTIES = [
  {
    key: 'severity',
    propertyLabel: 'Severity',
    groupValuesLabel: 'Severity values',
    operators: ['=', '!='].map((operator) => ({ operator, format: capitalize })),
  },
  {
    key: 'status',
    propertyLabel: 'Status',
    groupValuesLabel: 'Status values',
    operators: ['=', '!='].map((operator) => ({ operator, format: statusLabel })),
  },
  { key: 'pillarLabel', propertyLabel: 'Pillar', groupValuesLabel: 'Pillar values', operators: ['=', '!='] },
  { key: 'instance', propertyLabel: 'Instance', groupValuesLabel: 'Instance values', operators: ['=', '!='] },
  { key: 'resource_type', propertyLabel: 'Resource type', groupValuesLabel: 'Resource types', operators: ['=', '!='] },
  { key: 'check_id', propertyLabel: 'Check ID', groupValuesLabel: 'Check IDs', operators: ['=', ':', '!='] },
  { key: 'check_name', propertyLabel: 'Check name', groupValuesLabel: 'Check names', operators: [':', '!:'] },
  { key: 'description', propertyLabel: 'Description', groupValuesLabel: 'Descriptions', operators: [':', '!:'] },
];

const LABELED_OPTIONS = [
  ...Object.entries(STATUS).map(([value, s]) => ({ propertyKey: 'status', value, label: s.label })),
  ...SEVERITIES.map((value) => ({ propertyKey: 'severity', value, label: capitalize(value) })),
];

export default function FindingsTable({ data, selected, onSelect, filterRequest }) {
  const pillarLabel = useMemo(() => Object.fromEntries(data.pillars.map((p) => [p.id, p.label])), [data]);
  const allItems = useMemo(
    () => data.findings.map((f) => ({ ...f, pillarLabel: pillarLabel[f.pillar] ?? f.pillar })),
    [data, pillarLabel],
  );
  const [pillarTab, setPillarTab] = useState('all');
  const [preferences, setPreferences] = useState({
    pageSize: 25,
    wrapLines: false,
    stripedRows: false,
    contentDisplay: COLUMNS.map((c) => ({ id: c.id, visible: c.id !== 'resource_type' })),
  });
  const tabItems = pillarTab === 'all' ? allItems : allItems.filter((f) => f.pillar === pillarTab);
  const containerRef = useRef(null);

  const { items, actions, filteredItemsCount, collectionProps, propertyFilterProps, paginationProps } = useCollection(tabItems, {
    propertyFiltering: {
      filteringProperties: FILTERING_PROPERTIES,
      defaultQuery: defaultFilterQuery(data),
      empty: (
        <Box textAlign="center" color="inherit">
          <b>No findings</b>
        </Box>
      ),
      noMatch: (
        <Box textAlign="center" color="inherit">
          <SpaceBetween size="xs">
            <b>No matches</b>
            <Button onClick={() => actions.setPropertyFiltering({ operation: 'and', tokens: [] })}>Clear filter</Button>
          </SpaceBetween>
        </Box>
      ),
    },
    sorting: { defaultState: { sortingColumn: COLUMNS[1] } },
    pagination: { pageSize: preferences.pageSize },
    selection: {},
  });

  useEffect(() => {
    if (!filterRequest) return;
    setPillarTab('all');
    actions.setPropertyFiltering(filterRequest.query);
    containerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    // Only react to new requests, not to `actions` identity changes.
  }, [filterRequest]);

  const failedIn = (pillar) => allItems.filter((f) => f.pillar === pillar && f.status === 'fail').length;
  const filteringOptions = [
    ...propertyFilterProps.filteringOptions.filter((o) => o.propertyKey !== 'status' && o.propertyKey !== 'severity'),
    ...LABELED_OPTIONS,
  ];

  return (
    <div ref={containerRef}>
      <SpaceBetween size="s">
        <Tabs
          activeTabId={pillarTab}
          onChange={({ detail }) => setPillarTab(detail.activeTabId)}
          ariaLabel="Filter findings by pillar"
          tabs={[
            { id: 'all', label: <TabLabel name="All" failed={allItems.filter((f) => f.status === 'fail').length} /> },
            ...data.pillars
              .filter((p) => allItems.some((f) => f.pillar === p.id))
              .map((p) => ({ id: p.id, label: <TabLabel name={p.label} failed={failedIn(p.id)} /> })),
          ]}
        />
        <Table
          {...collectionProps}
          items={items}
          columnDefinitions={COLUMNS}
          columnDisplay={preferences.contentDisplay}
          selectionType="single"
          selectedItems={selected ? [selected] : []}
          onSelectionChange={({ detail }) => onSelect(detail.selectedItems[0])}
          onRowClick={({ detail }) => onSelect(detail.item)}
          trackBy="key"
          variant="container"
          stickyHeader
          resizableColumns
          wrapLines={preferences.wrapLines}
          stripedRows={preferences.stripedRows}
          ariaLabels={{ selectionGroupLabel: 'Findings', itemSelectionLabel: (_, f) => f.check_name }}
          header={
            <Header
              variant="h2"
              counter={`(${filteredItemsCount}/${tabItems.length})`}
              description="Select a finding to see its evidence and remediation."
              actions={
                <Button iconName="download" onClick={() => downloadText('assessment_findings_filtered.csv', findingsCsv(items), 'text/csv;charset=utf-8')}>
                  Export page (CSV)
                </Button>
              }
            >
              Findings
            </Header>
          }
          filter={
            <PropertyFilter
              {...propertyFilterProps}
              filteringOptions={filteringOptions}
              countText={`${filteredItemsCount} match${filteredItemsCount === 1 ? '' : 'es'}`}
              filteringPlaceholder="Filter findings by severity, status, pillar, instance or text"
              expandToViewport
            />
          }
          pagination={<Pagination {...paginationProps} />}
          preferences={
            <CollectionPreferences
              title="Preferences"
              confirmLabel="Confirm"
              cancelLabel="Cancel"
              preferences={preferences}
              onConfirm={({ detail }) => setPreferences(detail)}
              pageSizePreference={{
                title: 'Page size',
                options: [10, 25, 50, 100].map((value) => ({ value, label: `${value} findings` })),
              }}
              wrapLinesPreference={{}}
              stripedRowsPreference={{}}
              contentDisplayPreference={{
                title: 'Column preferences',
                options: COLUMNS.map((c) => ({ id: c.id, label: c.header, alwaysVisible: c.id === 'check_name' })),
              }}
            />
          }
        />
      </SpaceBetween>
    </div>
  );
}
