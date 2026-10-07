// Unit tests for the report UI's pure logic. Run with `npm test` (node:test, no extra deps).
// fixtures/report-data.json is generated from the real Python output; the Python test
// tests/test_report_ui_contract.py keeps it in sync with ReportGenerator._build_report_data().
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, describe, it } from 'node:test';

import { contractViolations, REQUIRED_FIELDS } from '../src/contract.js';
import {
  DISPOSITIONS,
  FILTER_QUERIES,
  defaultFilterQuery,
  evidenceCellFullValue,
  evidenceLayout,
  evidenceTableMinimumWidth,
  flattenEvidenceForPrint,
  journeyEntryOptions,
  loadReportData,
  makeFilterRequest,
  printableFindings,
  printableRemediation,
  safeHref,
  scopeReportData,
} from '../src/data.js';
import { downloadSvgAsPng, findingsCsv, pngOutputSize, safeFilenamePart } from '../src/download.js';

const FIXTURE_TEXT = readFileSync(new URL('./fixtures/report-data.json', import.meta.url), 'utf8');
const fixture = () => JSON.parse(FIXTURE_TEXT);

// Minimal stand-in for the page: loadReportData only needs getElementById().textContent.
function withIsland(textContent) {
  globalThis.document = {
    getElementById: (id) => (id === 'report-data' && textContent !== undefined ? { textContent } : null),
  };
}
afterEach(() => {
  delete globalThis.document;
});

describe('findingsCsv', () => {
  const row = (overrides) => ({
    check_id: 'SEC-001',
    check_name: 'Check',
    pillar: 'security',
    severity: 'high',
    status: 'fail',
    resource_type: 'ConnectInstance',
    resource_id: 'i-1',
    instance: 'cc',
    description: 'desc',
    ...overrides,
  });
  const lines = (csv) => csv.replace(/^\ufeff/, '').split('\r\n');

  it('writes a quoted header in a stable column order', () => {
    assert.equal(
      lines(findingsCsv([]))[0],
      '"Check ID","Check Name","Pillar","Severity","Execution Status","Disposition","Resource Type","Resource ID","Instance ID","Instance","Observed Result","Why This Is Assessed","Evidence Source","Proof Limitations","Developer/Admin Meaning","Action","Verification Criteria","Responsible Function","Primary Lens Reference"',
    );
  });

  it('quotes every cell and doubles embedded quotes', () => {
    const [, line] = lines(findingsCsv([row({ check_name: 'Say "hi", then leave' })]));
    assert.ok(line.includes('"Say ""hi"", then leave"'));
  });

  it('keeps embedded newlines inside the quoted cell', () => {
    const csv = findingsCsv([row({ description: 'line 1\nline 2' })]);
    assert.ok(csv.includes('"line 1\nline 2"'));
  });

  it('starts with a UTF-8 BOM and uses CRLF line endings', () => {
    const csv = findingsCsv([row({})]);
    assert.equal(csv.charCodeAt(0), 0xfeff);
    assert.equal(csv.split('\r\n').length, 2);
  });

  for (const lead of [' ', '  \t', '\n', '\u0000', '\u00a0', '\u200b', '\ufeff']) {
    for (const trigger of ['=', '+', '-', '@', '|']) {
      it(`prefixes ${JSON.stringify(lead + trigger)} (leading whitespace/control payload)`, () => {
        const [, line] = lines(findingsCsv([row({ check_name: `${lead}${trigger}cmd` })]));
        assert.ok(line.includes(`"'${lead}${trigger}cmd"`), line);
      });
    }
  }

  it('does not prefix benign cells that merely contain a trigger later', () => {
    const [, line] = lines(findingsCsv([row({ check_name: 'a=b | c' })]));
    assert.ok(line.includes('"a=b | c"'));
  });

  for (const lead of ['=', '+', '-', '@', '|', '\t', '\r']) {
    it(`prefixes formula-leading ${JSON.stringify(lead)} so spreadsheets treat it as text`, () => {
      const [, line] = lines(findingsCsv([row({ check_name: `${lead}HYPERLINK("x")` })]));
      assert.ok(line.includes(`"'${lead}HYPERLINK(""x"")"`), line);
    });
  }

  it('renders null and undefined as empty cells', () => {
    const [, line] = lines(findingsCsv([row({ instance: null, description: undefined })]));
    assert.equal(
      line,
      '"SEC-001","Check","security","high","fail","","ConnectInstance","i-1","","","","","","","","","","",""',
    );
  });

  it('exports every finding in the fixture', () => {
    const data = fixture();
    assert.equal(lines(findingsCsv(data.findings)).length, data.findings.length + 1);
  });
});

describe('safeFilenamePart', () => {
  it('strips accents and replaces unsafe characters', () => {
    assert.equal(safeFilenamePart('Café Menu / Main IVR'), 'Cafe-Menu-Main-IVR');
  });

  it('removes control characters and leading/trailing separators', () => {
    assert.equal(safeFilenamePart('..\u0000\u001fflow\u007f--'), 'flow');
  });

  it('falls back to "journey" for empty or reserved Windows names', () => {
    assert.equal(safeFilenamePart(''), 'journey');
    assert.equal(safeFilenamePart(null), 'journey');
    assert.equal(safeFilenamePart('///'), 'journey');
    assert.equal(safeFilenamePart('CON'), 'journey');
    assert.equal(safeFilenamePart('lpt1'), 'journey');
  });

  it('caps the length at 80 characters', () => {
    assert.equal(safeFilenamePart('a'.repeat(200)).length, 80);
  });
});

describe('pngOutputSize / downloadSvgAsPng', () => {
  it('keeps small diagrams at their native size', () => {
    assert.deepEqual(pngOutputSize(1200, 600), { width: 1200, height: 600 });
  });

  it('caps the longest side at 8192px', () => {
    assert.deepEqual(pngOutputSize(16384, 100), { width: 8192, height: 50 });
  });

  it('caps the total pixel count at 32 megapixels', () => {
    const { width, height } = pngOutputSize(8000, 8000);
    assert.ok(width * height <= 32000000);
    assert.equal(width, height);
  });

  it('rejects unusable dimensions', () => {
    for (const [w, h] of [[0, 10], [10, -1], [NaN, 10], ['abc', 10], [Infinity, 10]]) {
      assert.equal(pngOutputSize(w, h), null, `${w}x${h}`);
    }
  });

  it('reports invalid dimensions and missing SVG as errors instead of throwing', async () => {
    await assert.rejects(downloadSvgAsPng({ content: '<svg/>', width: 0, height: 10 }, 'x.png'), /dimensions are invalid/);
    await assert.rejects(downloadSvgAsPng(undefined, 'x.png'), /unavailable/);
    await assert.rejects(downloadSvgAsPng({ width: 10, height: 10 }, 'x.png'), /unavailable/);
  });
});

describe('loadReportData', () => {
  it('returns the parsed fixture', () => {
    withIsland(FIXTURE_TEXT);
    assert.equal(loadReportData().assessment.id, fixture().assessment.id);
  });

  it('names the data element when it is missing or empty', () => {
    withIsland(undefined);
    assert.throws(loadReportData, /<script id="report-data">\) is missing or empty/);
    withIsland('   ');
    assert.throws(loadReportData, /missing or empty/);
  });

  it('reports invalid JSON', () => {
    withIsland('{"schema_version": 1, oops');
    assert.throws(loadReportData, /report-data.*not valid JSON/);
  });

  it('rejects an unsupported schema version', () => {
    withIsland(JSON.stringify({ ...fixture(), schema_version: 2 }));
    assert.throws(loadReportData, /schema version 2; this report viewer supports version 1/);
  });

  it('lists missing required fields', () => {
    const data = fixture();
    delete data.pillars;
    withIsland(JSON.stringify(data));
    assert.throws(loadReportData, /missing required fields: data\.pillars/);
  });
});

describe('report data contract', () => {
  it('the Python-generated fixture provides every field the UI reads', () => {
    assert.deepEqual(contractViolations(fixture()), []);
  });

  it('detects missing nested fields with their path', () => {
    const data = fixture();
    delete data.findings[0].description_html;
    delete data.findings[0].methodology.reason;
    delete data.journey.entries[0].diagram_model.layout.connectors;
    assert.deepEqual(contractViolations(data), [
      'data.findings[0].description_html',
      'data.findings[0].methodology.reason',
      'data.journey.entries[0].diagram_model.layout.connectors',
    ]);
  });

  it('flags a list that became something else', () => {
    const data = fixture();
    data.findings = null;
    assert.deepEqual(contractViolations(data), ['data.findings (expected a list)']);
  });

  it('accepts a journey entry without a layout (oversized or empty flow)', () => {
    const data = fixture();
    data.journey.entries[0].diagram_model.layout = null;
    assert.deepEqual(contractViolations(data), []);
  });

  it('covers every top-level key the generator emits', () => {
    assert.deepEqual([...REQUIRED_FIELDS.report].sort(), Object.keys(fixture()).sort());
  });
});

describe('defaultFilterQuery', () => {
  it('filters to failed findings of the highest failed severity', () => {
    assert.deepEqual(defaultFilterQuery(fixture()), {
      operation: 'and',
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'fail' },
        { propertyKey: 'severity', operator: '=', value: 'critical' },
        { propertyKey: 'disposition', operator: '=', value: 'control' },
      ],
    });
  });

  it('adds no token for "all"', () => {
    assert.deepEqual(defaultFilterQuery({ filters: { default_status: 'all', default_severity: 'all' } }), {
      operation: 'and',
      tokens: [],
    });
  });

  it('applies the status token alone when no critical/high failures exist', () => {
    assert.deepEqual(defaultFilterQuery({ filters: { default_status: 'fail', default_severity: 'all' } }).tokens, [
      { propertyKey: 'status', operator: '=', value: 'fail' },
    ]);
  });
});

describe('printableFindings', () => {
  it('keeps every finding, failures and errors first, then by severity', () => {
    const f = (key, status, severity, check_name = key) => ({ key, status, severity, check_name });
    const findings = [
      f('a', 'pass', 'critical'),
      f('b', 'fail', 'low'),
      f('c', 'error', 'critical'),
      f('d', 'fail', 'critical', 'z'),
      f('e', 'fail', 'critical', 'y'),
      f('g', 'not_applicable', 'high'),
    ];
    const printed = printableFindings(findings);
    assert.deepEqual(printed.map((x) => x.key), ['e', 'd', 'b', 'c', 'a', 'g']);
    assert.equal(findings[0].key, 'a', 'input is not mutated');
  });

  it('includes all fixture findings regardless of the default table filter', () => {
    const data = JSON.parse(FIXTURE_TEXT);
    assert.equal(printableFindings(data.findings).length, data.findings.length);
  });
});

describe('printable remediation', () => {
  it('normalizes complete structured remediation in step order without the flat fallback', () => {
    const finding = {
      remediation_html: '<p>flat fallback</p>',
      structured_remediation: {
        summary: 'Summary',
        applies_if: 'Applicable',
        steps: [
          { order: 2, instruction_html: '<p>Second</p>', command: 'second', console_path: 'Console / Second' },
          { order: 1, instruction_html: '<p>First</p>', command: 'first', console_path: 'Console / First' },
        ],
        target_resources: ['queue-1'],
        references: [{ title: 'Guide', url: 'https://docs.aws.amazon.com/guide' }],
      },
    };

    const remediation = printableRemediation(finding);

    assert.equal(remediation.kind, 'structured');
    assert.equal(remediation.summary, 'Summary');
    assert.equal(remediation.applies_if, 'Applicable');
    assert.deepEqual(remediation.steps.map((step) => step.order), [1, 2]);
    assert.deepEqual(remediation.target_resources, ['queue-1']);
    assert.deepEqual(remediation.references, [{ title: 'Guide', url: 'https://docs.aws.amazon.com/guide' }]);
    assert.equal('html' in remediation, false);
  });

  it('uses flat remediation only when structured remediation is absent', () => {
    assert.deepEqual(
      printableRemediation({ remediation_html: '<p>Flat guidance</p>', structured_remediation: null }),
      { kind: 'flat', html: '<p>Flat guidance</p>' },
    );
    assert.deepEqual(printableRemediation({ remediation_html: '', structured_remediation: null }), { kind: 'none' });
  });

  it('renders every required print section once through the shared normalization path', () => {
    const source = readFileSync(new URL('../src/PrintFindings.jsx', import.meta.url), 'utf8');
    const occurrences = (needle) => source.split(needle).length - 1;

    assert.ok(source.includes('const remediation = printableRemediation(f);'));
    assert.ok(source.includes('<PrintRemediation remediation={remediation} />'));
    assert.equal(occurrences('f.action_label'), 1);
    assert.equal(occurrences('f.responsible_function'), 2);
    assert.equal(occurrences('<dt>Responsible function</dt>'), 1);
    assert.equal(occurrences('f.primary_lens_reference'), 2);
    assert.equal(occurrences('<dt>Primary lens reference</dt>'), 1);
    assert.ok(source.includes('flattenEvidenceForPrint(f.evidence)'));
    assert.ok(!source.includes('dangerouslySetInnerHTML'));
  });
});

describe('safeHref', () => {
  it('allows http, https, mailto and relative URLs', () => {
    for (const url of ['https://docs.aws.amazon.com/x', 'HTTP://a.b', 'mailto:a@b.c', '/docs/x', 'page.html']) {
      assert.equal(safeHref(url), url);
    }
  });

  it('rejects dangerous schemes, backslashes, control chars and scheme-relative URLs', () => {
    for (const url of ['javascript:alert(1)', ' JaVaScRiPt:alert(1)', 'data:text/html,x', 'vbscript:x', '//evil.test', 'https:\\\\evil', 'java\nscript:x', '', null, 5]) {
      assert.equal(safeHref(url), null, String(url));
    }
  });
});

describe('markdown rendering', () => {
  it('attaches sanitized DOM fragments instead of injecting HTML strings', () => {
    const source = readFileSync(new URL('../src/FindingDetail.jsx', import.meta.url), 'utf8');
    assert.ok(!source.includes('dangerouslySetInnerHTML'));
    assert.ok(source.includes('RETURN_DOM_FRAGMENT'));
    assert.ok(source.includes('replaceChildren'));
  });
  it('keeps backend-humanized evidence labels in React text properties', () => {
    const source = readFileSync(new URL('../src/FindingDetail.jsx', import.meta.url), 'utf8');
    assert.ok(source.includes('label: p.label'));
    assert.ok(source.includes('headerText={section.title}'));
    assert.ok(!source.includes('dangerouslySetInnerHTML'));
  });
});

describe('report instance scope', () => {
  function twoInstanceReport() {
    const data = fixture();
    const second = { ...data.instances[0], id: 'i-0002', alias: 'backup', display_name: "'backup' (i-0002)" };
    data.instances.push(second);
    const base = data.findings[1];
    data.findings.push(
      { ...base, key: '2', instance_id: 'i-0002', instance: 'backup', status: 'pass', score_classification: 'scored_pass', severity: 'low' },
      { ...base, key: '3', instance_id: 'i-0002', instance: 'backup', status: 'fail', disposition: 'manual_review', score_classification: 'non_scoring', severity: 'medium' },
      { ...base, key: '4', instance_id: 'i-0002', instance: 'backup', status: 'error', disposition: 'control', score_classification: 'unevaluated_control', severity: 'high' },
    );
    data.journey.entries.push({ ...data.journey.entries[0], instance_id: 'i-0002', instance_display_name: 'backup', phone_number: '+18005550200' });
    return data;
  }

  it('derives findings, journeys, aggregates, charts, insights and recommendations without mutation', () => {
    const data = twoInstanceReport();
    const before = structuredClone(data);
    const scoped = scopeReportData(data, 'i-0002');

    assert.deepEqual(scoped.findings.map((finding) => finding.key), ['2', '3', '4']);
    assert.deepEqual(scoped.instances.map((instance) => instance.id), ['i-0002']);
    assert.deepEqual(scoped.journey.entries.map((entry) => entry.instance_id), ['i-0002']);
    assert.deepEqual(scoped.stats.scored_control_numerator, 1);
    assert.deepEqual(scoped.stats.scored_control_denominator, 1);
    assert.deepEqual(scoped.stats.total_checks, 3);
    assert.deepEqual(scoped.stats.registered_checks, 3);
    assert.deepEqual(scoped.stats.journey_findings, 0);
    assert.deepEqual(scoped.stats.execution_time, data.stats.execution_time);
    assert.deepEqual(scoped.stats.execution_time_scope, 'assessment');
    assert.deepEqual(scoped.stats.manual_review_candidates, 1);
    assert.deepEqual(scoped.stats.unevaluated_controls, 1);
    assert.deepEqual(scoped.charts.status_distribution.data, [1, 0, 1, 0, 1, 0]);
    assert.match(scoped.insights.at(-1).message, /manual-review candidate/);
    assert.deepEqual(scoped.recommendations, []);
    assert.deepEqual(data, before, 'original report data is not mutated');
  });

  it('counts canonical Journey controls from scoped findings', () => {
    const data = twoInstanceReport();
    data.findings[2].check_id = 'sec-flow-auth-001';

    const scoped = scopeReportData(data, 'i-0002');

    assert.equal(scoped.stats.total_checks, 3);
    assert.equal(scoped.stats.journey_findings, 1);
    assert.equal(scoped.stats.registered_checks, 2);
  });

  it('includes unattributed findings only in All scope and exposes their policy', () => {
    const data = twoInstanceReport();
    const unattributed = { ...data.findings[0], key: 'unattributed', instance_id: null, instance: 'unknown' };
    data.findings.push(unattributed);

    const all = scopeReportData(data, 'all');
    const primary = scopeReportData(data, 'i-0001');
    const secondary = scopeReportData(data, 'i-0002');

    assert.equal(all.findings.filter((finding) => finding.key === 'unattributed').length, 1);
    assert.equal(primary.findings.some((finding) => finding.key === 'unattributed'), false);
    assert.equal(secondary.findings.some((finding) => finding.key === 'unattributed'), false);
    assert.equal(all.stats.total_checks, data.findings.length);
    assert.equal(primary.stats.total_checks, 2);
    assert.equal(secondary.stats.total_checks, 3);
    assert.equal(all.stats.unattributed_findings, 1);
    assert.equal(primary.stats.unattributed_findings, 0);
    assert.equal(primary.stats.assessment_unattributed_findings, 1);
    assert.equal(all.unattributed_findings_count, 1);
    assert.match(all.scope_notice, /included only in All instances/);
    assert.match(primary.scope_notice, /excluded from this instance scope/);
    assert.match(all.insights.at(-1).message, /included only in All instances/);
    assert.match(primary.insights.at(-1).message, /excluded from this instance scope/);
  });

  it('returns fresh derived collections for all instances and preserves totals', () => {
    const data = twoInstanceReport();
    const scoped = scopeReportData(data, 'all');
    assert.notEqual(scoped.findings, data.findings);
    assert.notEqual(scoped.charts, data.charts);
    assert.equal(scoped.findings.length, data.findings.length);
    assert.equal(scoped.stats.instances_assessed, 2);
  });
});

describe('finding drill-down queries', () => {
  it('uses exact failed-control semantics for medium severity', () => {
    assert.deepEqual(FILTER_QUERIES.failedSeverity('medium'), {
      operation: 'and',
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'fail' },
        { propertyKey: 'disposition', operator: '=', value: 'control' },
        { propertyKey: 'severity', operator: '=', value: 'medium' },
      ],
    });
  });

  it('maps status-distribution records with score classification and disposition semantics', () => {
    assert.deepEqual(FILTER_QUERIES.statusDistribution('scored_fail'), {
      operation: 'and',
      tokens: [{ propertyKey: 'score_classification', operator: '=', value: 'scored_fail' }],
    });
    assert.deepEqual(FILTER_QUERIES.statusDistribution('manual_review'), {
      operation: 'and',
      tokens: [
        { propertyKey: 'disposition', operator: '=', value: 'manual_review' },
        { propertyKey: 'score_classification', operator: '=', value: 'non_scoring' },
      ],
    });
  });

  it('matches the selected pillar stack and pillar label', () => {
    assert.deepEqual(FILTER_QUERIES.pillarStack('manual_review_candidates', 'Security'), {
      operation: 'and',
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'fail' },
        { propertyKey: 'disposition', operator: '=', value: 'manual_review' },
        { propertyKey: 'pillarLabel', operator: '=', value: 'Security' },
      ],
    });
  });

  it('gives repeated identical requests distinct identities', () => {
    const query = FILTER_QUERIES.failedControls();
    assert.notDeepEqual(makeFilterRequest(query, 1), makeFilterRequest(query, 2));
    assert.deepEqual(makeFilterRequest(query, 1).query, makeFilterRequest(query, 2).query);
  });
});

describe('disposition guidance', () => {
  it('defines visible guidance for every disposition and explains scoring', () => {
    assert.deepEqual(Object.keys(DISPOSITIONS), ['control', 'manual_review', 'informational']);
    for (const item of Object.values(DISPOSITIONS)) assert.match(item.description, /posture/);
  });
});

describe('adaptive evidence helpers', () => {
  it('uses tables only when every column can meet its minimum width', () => {
    assert.equal(evidenceTableMinimumWidth(4), 640);
    assert.equal(evidenceLayout(639, 4), 'cards');
    assert.equal(evidenceLayout(640, 4), 'table');
    assert.equal(evidenceLayout(1000, 8), 'cards');
  });

  it('always resolves the full cell value', () => {
    assert.equal(evidenceCellFullValue({ text: 'short…', full: 'short but complete' }), 'short but complete');
    assert.equal(evidenceCellFullValue({ text: 'direct' }), 'direct');
  });

  it('flattens every nested value into print records without clipping', () => {
    const long = 'x'.repeat(240);
    const block = {
      pairs: [{ label: 'Direct', value: { text: 'x…', full: long } }],
      tables: [{ title: 'Routes', columns: ['Name', 'Config'], rows: [[{ text: 'primary' }, { text: 'a=1', full: '{\n  "a": 1\n}' }]] }],
      lists: [{ title: 'Queues', items: [{ text: 'q-1' }, { text: 'q-2' }] }],
      sections: [{ title: 'Nested', block: { pairs: [{ label: 'Enabled', value: { text: 'true' } }], tables: [], lists: [], sections: [] } }],
    };
    const flattened = flattenEvidenceForPrint(block);
    assert.equal(flattened.length, 6);
    assert.equal(flattened[0].value, long);
    assert.deepEqual(flattened[2], { label: 'Routes / Record 1 / Config', value: '{\n  "a": 1\n}' });
    assert.deepEqual(flattened.at(-1), { label: 'Nested / Enabled', value: 'true' });
  });
});

describe('journey entry options', () => {
  const entry = (instance_id, instance_display_name, phone_number, flow_name) => ({
    instance_id,
    instance_display_name,
    phone_number,
    phone_description: 'Main line',
    phone_type: 'TOLL_FREE',
    flow_name,
  });

  it('identifies the instance when all-instance options span instances', () => {
    const options = journeyEntryOptions([
      entry('i-1', 'Primary', '+18005550100', 'Main IVR'),
      entry('i-2', 'Backup', '+18005550200', 'Overflow'),
    ]);
    assert.equal(options[0].labelTag, 'Primary');
    assert.deepEqual(options[0].tags, ['TOLL FREE', 'Main IVR']);
    assert.equal(options[1].labelTag, 'Backup');
  });

  it('uses the flow name when the report scope contains one instance', () => {
    const options = journeyEntryOptions([entry('i-1', 'Primary', '+18005550100', 'Main IVR')]);
    assert.equal(options[0].labelTag, 'Main IVR');
    assert.deepEqual(options[0].tags, ['TOLL FREE']);
  });
});

describe('executive summary metric drill-down', () => {
  it('uses the metric value as the accessible action without separate view text', () => {
    const source = readFileSync(new URL('../src/Overview.jsx', import.meta.url), 'utf8');
    assert.ok(source.includes('className="acr-metric-link"'));
    assert.ok(source.includes('aria-label={`${label}: ${children}`}'));
    assert.ok(!source.includes('info: action('));
  });
});

describe('bundle freshness check portability', () => {
  it('compares generated bytes without requiring Git in the build image', () => {
    // Arrange
    const source = readFileSync(new URL('../build.mjs', import.meta.url), 'utf8');

    // Act
    const invokesGit = source.includes("execFileSync('git'") || source.includes('node:child_process');

    // Assert
    assert.equal(invokesGit, false);
    assert.ok(source.includes('previousOutputs'));
    assert.ok(source.includes('.equals(output)'));
  });
});
