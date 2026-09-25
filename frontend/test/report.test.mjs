// Unit tests for the report UI's pure logic. Run with `npm test` (node:test, no extra deps).
// fixtures/report-data.json is generated from the real Python output; the Python test
// tests/test_report_ui_contract.py keeps it in sync with ReportGenerator._build_report_data().
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, describe, it } from 'node:test';

import { contractViolations, REQUIRED_FIELDS } from '../src/contract.js';
import { defaultFilterQuery, loadReportData, printableFindings } from '../src/data.js';
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
  const lines = (csv) => csv.split('\n');

  it('writes a quoted header in a stable column order', () => {
    assert.equal(
      lines(findingsCsv([]))[0],
      '"Check ID","Check Name","Pillar","Severity","Status","Resource Type","Resource ID","Instance","Description"',
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

  for (const lead of ['=', '+', '-', '@', '\t', '\r']) {
    it(`prefixes formula-leading ${JSON.stringify(lead)} so spreadsheets treat it as text`, () => {
      const [, line] = lines(findingsCsv([row({ check_name: `${lead}HYPERLINK("x")` })]));
      assert.ok(line.includes(`"'${lead}HYPERLINK(""x"")"`), line);
    });
  }

  it('renders null and undefined as empty cells', () => {
    const [, line] = lines(findingsCsv([row({ instance: null, description: undefined })]));
    assert.equal(line, '"SEC-001","Check","security","high","fail","ConnectInstance","i-1","",""');
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
    delete data.journey.entries[0].diagram_model.layout.connectors;
    assert.deepEqual(contractViolations(data), [
      'data.findings[0].description_html',
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
