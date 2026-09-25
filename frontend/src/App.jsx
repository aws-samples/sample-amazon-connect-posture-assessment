import React, { useMemo, useState } from 'react';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import CodeView from '@cloudscape-design/code-view/code-view';
import {
  AppLayout,
  Box,
  ButtonDropdown,
  ContentLayout,
  CopyToClipboard,
  ExpandableSection,
  Header,
  SpaceBetween,
  SplitPanel,
  TopNavigation,
} from '@cloudscape-design/components';
import Charts from './Charts';
import FindingDetail from './FindingDetail';
import FindingsTable from './Findings';
import JourneyDetail from './JourneyDetail';
import JourneyMap from './JourneyMap';
import PrintFindings from './PrintFindings';
import { AssessmentDetails, ExecutiveSummary, Insights, Recommendations } from './Overview';
import { downloadText, findingsCsv } from './download';

const THEME_KEY = 'darkMode';

// Cloudscape has no sun/moon glyphs; strokes inherit currentColor like the built-in icons.
const SUN_ICON = (
  <svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" focusable="false" aria-hidden="true">
    <circle cx="8" cy="8" r="3" />
    <path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.05 3.05l1.06 1.06M11.89 11.89l1.06 1.06M3.05 12.95l1.06-1.06M11.89 4.11l1.06-1.06" />
  </svg>
);
const MOON_ICON = (
  <svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" focusable="false" aria-hidden="true">
    <path d="M13.5 9.5A5.5 5.5 0 1 1 6.5 2.5a4.5 4.5 0 0 0 7 7Z" />
  </svg>
);

function initialTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved !== null) return saved === 'true' ? 'dark' : 'light';
  } catch {
    // Storage can be unavailable for file:// pages; fall back to the OS setting.
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App({ data }) {
  const [theme, setTheme] = useState(() => {
    const t = initialTheme();
    applyMode(t === 'dark' ? Mode.Dark : Mode.Light);
    return t;
  });
  const [selection, setSelection] = useState(undefined);
  const [splitOpen, setSplitOpen] = useState(true);
  const [splitSize, setSplitSize] = useState(620);
  const [filterRequest, setFilterRequest] = useState(undefined);

  const pillarLabel = useMemo(() => Object.fromEntries(data.pillars.map((p) => [p.id, p.label])), [data]);

  const changeTheme = (t) => {
    setTheme(t);
    applyMode(t === 'dark' ? Mode.Dark : Mode.Light);
    try {
      window.localStorage.setItem(THEME_KEY, String(t === 'dark'));
    } catch {
      // Preference just won't persist.
    }
  };
  const select = (s) => {
    setSelection(s);
    setSplitOpen(true);
  };
  const showFindings = (severity) =>
    setFilterRequest({
      query: {
        operation: 'and',
        tokens: [
          { propertyKey: 'status', operator: '=', value: 'fail' },
          { propertyKey: 'severity', operator: '=', value: severity },
        ],
      },
    });
  const exportReport = (id) => {
    if (id === 'csv') downloadText('assessment_findings.csv', findingsCsv(data.findings), 'text/csv;charset=utf-8');
    if (id === 'json') {
      const { service_icon: _icon, ...exportable } = data;
      downloadText('assessment_findings.json', JSON.stringify(exportable, null, 2), 'application/json');
    }
    if (id === 'pdf') window.print();
  };

  let splitHeader = '';
  let splitBody = null;
  if (selection?.kind === 'finding') {
    splitHeader = selection.finding.check_name;
    splitBody = <FindingDetail finding={selection.finding} />;
  } else if (selection) {
    const model = selection.entry.diagram_model;
    splitHeader = selection.kind === 'node' ? model.nodes[selection.key]?.title : `Route: ${model.edges[selection.key]?.title}`;
    splitBody = <JourneyDetail entry={selection.entry} selection={selection} onSelect={(s) => select({ ...s, entry: selection.entry })} />;
  }

  const { assessment } = data;
  return (
    <>
      <div id="top-nav" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
        <TopNavigation
          identity={{
            href: '#',
            title: 'Amazon Connect Assessment',
            logo: data.service_icon ? { src: data.service_icon, alt: 'Amazon Connect' } : undefined,
          }}
          utilities={[
            { type: 'button', text: `Account ${assessment.account_id}`, iconName: 'user-profile' },
            { type: 'button', text: assessment.region, iconName: 'globe' },
            {
              type: 'button',
              iconSvg: theme === 'dark' ? SUN_ICON : MOON_ICON,
              ariaLabel: theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
              title: theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
              onClick: () => changeTheme(theme === 'dark' ? 'light' : 'dark'),
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        navigationHide
        toolsHide
        contentType="dashboard"
        ariaLabels={{ splitPanelToggle: 'Details panel' }}
        splitPanelOpen={splitOpen && !!selection}
        onSplitPanelToggle={({ detail }) => setSplitOpen(detail.open)}
        splitPanelPreferences={{ position: 'side' }}
        splitPanelSize={splitSize}
        onSplitPanelResize={({ detail }) => setSplitSize(detail.size)}
        splitPanel={
          selection && (
            <SplitPanel header={splitHeader} hidePreferencesButton closeBehavior="hide">
              {splitBody}
            </SplitPanel>
          )
        }
        content={
          <ContentLayout
            header={
              <Header
                variant="h1"
                description={`Well-Architected posture assessment · Account ${assessment.account_id} · ${assessment.region} · Assessment ${assessment.id}`}
                actions={
                  <ButtonDropdown
                    variant="primary"
                    items={[
                      { id: 'json', text: 'Report data (JSON)' },
                      { id: 'csv', text: 'All findings (CSV)' },
                      { id: 'pdf', text: 'Print / save as PDF' },
                    ]}
                    onItemClick={({ detail }) => exportReport(detail.id)}
                  >
                    Export
                  </ButtonDropdown>
                }
              >
                {data.title}
              </Header>
            }
          >
            <SpaceBetween size="l">
              <Insights data={data} />
              <ExecutiveSummary data={data} />
              <Charts data={data} />
              <Recommendations data={data} onShowFindings={showFindings} />
              <JourneyMap
                journey={data.journey}
                selection={selection?.kind === 'finding' ? undefined : selection}
                onSelect={select}
                // Journey details belong to the previous entry; an open finding stays open.
                onClearSelection={() => setSelection((s) => (s?.kind === 'finding' ? s : undefined))}
              />
              <div className="acr-no-print">
                <FindingsTable
                  data={data}
                  selected={selection?.kind === 'finding' ? selection.finding : undefined}
                  onSelect={(f) => f && select({ kind: 'finding', finding: { ...f, pillarLabel: pillarLabel[f.pillar] ?? f.pillar } })}
                  filterRequest={filterRequest}
                />
              </div>
              <PrintFindings data={data} pillarLabel={pillarLabel} />
              <AssessmentDetails data={data} />
              {data.raw_data && (
                <ExpandableSection headerText="Raw assessment data" variant="container" headerDescription="The complete assessment result as JSON.">
                  <CodeView
                    content={data.raw_data}
                    lineNumbers
                    actions={
                      <CopyToClipboard variant="icon" textToCopy={data.raw_data} copyButtonAriaLabel="Copy raw assessment data" copySuccessText="Copied" copyErrorText="Copy failed" />
                    }
                  />
                </ExpandableSection>
              )}
              <Box textAlign="center" color="text-body-secondary" fontSize="body-s" padding={{ vertical: 'l' }}>
                Amazon Connect Assessment Tool · Generated {data.generated_at} · {data.findings.length} findings across{' '}
                {data.instances.length} Connect instance{data.instances.length === 1 ? '' : 's'}
              </Box>
            </SpaceBetween>
          </ContentLayout>
        }
      />
    </>
  );
}
