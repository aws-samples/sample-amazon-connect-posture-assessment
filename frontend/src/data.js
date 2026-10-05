// Report data contract produced by ReportGenerator._build_report_data (Python).
import {
  colorChartsStatusCritical,
  colorChartsStatusHigh,
  colorChartsStatusInfo,
  colorChartsStatusLow,
  colorChartsStatusMedium,
  colorChartsStatusNeutral,
  colorChartsStatusPositive,
} from '@cloudscape-design/design-tokens';
import { contractViolations } from './contract.js';

export const SUPPORTED_SCHEMA_VERSION = 1;

// Fail loudly: every section reads this contract, so a silent `{}` would just
// blank the page. index.jsx turns the error into a visible Alert.
export function loadReportData() {
  const island = document.getElementById('report-data');
  if (!island || !island.textContent.trim()) {
    throw new Error('The report data element (<script id="report-data">) is missing or empty.');
  }
  let data;
  try {
    data = JSON.parse(island.textContent);
  } catch (error) {
    throw new Error(`The report data element (<script id="report-data">) is not valid JSON: ${error.message}`);
  }
  if (data?.schema_version !== SUPPORTED_SCHEMA_VERSION) {
    throw new Error(
      `The report data element (<script id="report-data">) has schema version ${data?.schema_version ?? 'none'}; ` +
        `this report viewer supports version ${SUPPORTED_SCHEMA_VERSION}.`,
    );
  }
  const missing = contractViolations(data);
  if (missing.length) {
    const shown = missing.slice(0, 5).join(', ') + (missing.length > 5 ? `, and ${missing.length - 5} more` : '');
    throw new Error(`The report data element (<script id="report-data">) is missing required fields: ${shown}.`);
  }
  return data;
}

// Initial findings-table filter: the backend's default status (failed) plus
// the highest severity that has failures ('all' adds no token).
export function defaultFilterQuery(data) {
  const tokens = [];
  const {
    default_status: status,
    default_severity: severity,
    default_disposition: disposition,
  } = data.filters;
  if (status && status !== 'all') tokens.push({ propertyKey: 'status', operator: '=', value: status });
  if (severity && severity !== 'all') tokens.push({ propertyKey: 'severity', operator: '=', value: severity });
  if (disposition && disposition !== 'all') tokens.push({ propertyKey: 'disposition', operator: '=', value: disposition });
  return { operation: 'and', tokens };
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const CANONICAL_JOURNEY_CHECK_IDS = new Set([
  'sec-flow-auth-001',
  'cost-containment-001',
  'journey-res-001',
  'journey-scope-001',
]);
const LEGACY_JOURNEY_CHECK_ALIASES = {
  'journey-sec-001': 'sec-flow-auth-001',
  'journey-cost-001': 'cost-containment-001',
};
export const SEVERITY_COLOR = {
  critical: colorChartsStatusCritical,
  high: colorChartsStatusHigh,
  medium: colorChartsStatusMedium,
  low: colorChartsStatusLow,
};

// StatusIndicator type + label per CheckStatus value.
export const STATUS = {
  fail: { type: 'error', label: 'Failed', color: colorChartsStatusHigh },
  pass: { type: 'success', label: 'Passed', color: colorChartsStatusPositive },
  error: { type: 'warning', label: 'Error', color: colorChartsStatusCritical },
  skipped: { type: 'stopped', label: 'Skipped', color: colorChartsStatusNeutral },
  not_applicable: { type: 'info', label: 'Not applicable', color: colorChartsStatusInfo },
};

export const DISPOSITIONS = {
  control: {
    label: 'Control',
    description: 'An automated control result. PASS and FAIL outcomes contribute to the scored control posture.',
  },
  manual_review: {
    label: 'Manual review',
    description: 'Evidence that requires a person to validate. These records never change the scored control posture.',
  },
  informational: {
    label: 'Informational',
    description: 'Context or an observation for awareness. These records never change the scored control posture.',
  },
};
export const SCORE_CLASSIFICATIONS = {
  scored_pass: { label: 'Scored pass' },
  scored_fail: { label: 'Scored failure' },
  unevaluated_control: { label: 'Unevaluated control' },
  not_applicable: { label: 'Not applicable' },
  non_scoring: { label: 'Non-scoring' },
};
export const dispositionLabel = (value) => DISPOSITIONS[value]?.label ?? capitalize(String(value).replace(/_/g, ' '));
export const scoreClassificationLabel = (value) => SCORE_CLASSIFICATIONS[value]?.label ?? capitalize(String(value).replace(/_/g, ' '));

// Insight / recommendation type -> Alert type.
export const ALERT_TYPE = { critical: 'error', warning: 'warning', success: 'success', info: 'info' };

export const capitalize = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');
export const statusLabel = (status) => STATUS[status]?.label ?? capitalize(String(status).replace(/_/g, ' '));

// Every finding, for the print/PDF view: failures and errors first, then by
// severity. The on-screen table is filtered and paginated, so it can't be printed.
const PRINT_STATUS_RANK = { fail: 0, error: 1 };
export function printableFindings(findings) {
  const rank = (f) => PRINT_STATUS_RANK[f.status] ?? 2;
  return [...findings].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      (SEVERITY_RANK[a.severity] ?? SEVERITIES.length) - (SEVERITY_RANK[b.severity] ?? SEVERITIES.length) ||
      String(a.check_name).localeCompare(String(b.check_name)),
  );
}

export function printableRemediation(finding) {
  const structured = finding.structured_remediation;
  if (!structured) {
    return finding.remediation_html
      ? { kind: 'flat', html: finding.remediation_html }
      : { kind: 'none' };
  }
  return {
    kind: 'structured',
    summary: structured.summary ?? '',
    applies_if: structured.applies_if ?? '',
    steps: [...(structured.steps ?? [])].sort((a, b) => Number(a.order) - Number(b.order)),
    target_resources: [...(structured.target_resources ?? [])],
    references: [...(structured.references ?? [])],
  };
}

function isJourneyFinding(finding) {
  const canonicalId = LEGACY_JOURNEY_CHECK_ALIASES[finding.check_id] ?? finding.check_id;
  return CANONICAL_JOURNEY_CHECK_IDS.has(canonicalId);
}

// Only http(s), mailto and relative URLs may become link targets.
export function safeHref(url) {
  if (typeof url !== 'string') return null;
  const value = url.trim();
  if (!value || /[\\\u0000-\u001f\u007f]/.test(value)) return null;
  if (value.startsWith('//')) return null;
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(value);
  if (scheme) return ['http', 'https', 'mailto'].includes(scheme[1].toLowerCase()) ? value : null;
  return value;
}

const query = (...tokens) => ({ operation: 'and', tokens });
const classificationQuery = (value) => query({ propertyKey: 'score_classification', operator: '=', value });

export const FILTER_QUERIES = {
  allRecords: () => query(),
  controlPosture: () => ({
    operation: 'or',
    tokens: [
      { propertyKey: 'score_classification', operator: '=', value: 'scored_pass' },
      { propertyKey: 'score_classification', operator: '=', value: 'scored_fail' },
    ],
  }),
  failedControls: () => classificationQuery('scored_fail'),
  unevaluatedControls: () => classificationQuery('unevaluated_control'),
  manualReviewCandidates: () => query(
    { propertyKey: 'status', operator: '=', value: 'fail' },
    { propertyKey: 'disposition', operator: '=', value: 'manual_review' },
  ),
  manualReviewRecords: () => query({ propertyKey: 'disposition', operator: '=', value: 'manual_review' }),
  informationalRecords: () => query({ propertyKey: 'disposition', operator: '=', value: 'informational' }),
  notApplicableRecords: () => classificationQuery('not_applicable'),
  failedSeverity: (severity) => query(
    { propertyKey: 'status', operator: '=', value: 'fail' },
    { propertyKey: 'disposition', operator: '=', value: 'control' },
    { propertyKey: 'severity', operator: '=', value: severity },
  ),
  statusDistribution: (kind) => ({
    scored_pass: classificationQuery('scored_pass'),
    scored_fail: classificationQuery('scored_fail'),
    unevaluated_control: classificationQuery('unevaluated_control'),
    not_applicable: classificationQuery('not_applicable'),
    manual_review: query(
      { propertyKey: 'disposition', operator: '=', value: 'manual_review' },
      { propertyKey: 'score_classification', operator: '=', value: 'non_scoring' },
    ),
    informational: query(
      { propertyKey: 'disposition', operator: '=', value: 'informational' },
      { propertyKey: 'score_classification', operator: '=', value: 'non_scoring' },
    ),
  }[kind]),
  pillarStack: (stack, pillarLabel) => {
    const stackTokens = {
      passed: [{ propertyKey: 'score_classification', operator: '=', value: 'scored_pass' }],
      failed: [{ propertyKey: 'score_classification', operator: '=', value: 'scored_fail' }],
      manual_review_candidates: [
        { propertyKey: 'status', operator: '=', value: 'fail' },
        { propertyKey: 'disposition', operator: '=', value: 'manual_review' },
      ],
      informational_records: [{ propertyKey: 'disposition', operator: '=', value: 'informational' }],
      unevaluated_controls: [{ propertyKey: 'score_classification', operator: '=', value: 'unevaluated_control' }],
    }[stack] ?? [];
    return query(...stackTokens, { propertyKey: 'pillarLabel', operator: '=', value: pillarLabel });
  },
};

export const makeFilterRequest = (queryValue, requestId) => ({ id: requestId, query: queryValue });

function summarize(findings) {
  const countClass = (value) => findings.filter((finding) => finding.score_classification === value).length;
  const scoredPasses = countClass('scored_pass');
  const scoredFailures = countClass('scored_fail');
  const denominator = scoredPasses + scoredFailures;
  const passRate = denominator ? (scoredPasses / denominator) * 100 : null;
  return {
    total_records: findings.length,
    control_findings: findings.filter((finding) => finding.disposition === 'control').length,
    manual_review_findings: findings.filter((finding) => finding.disposition === 'manual_review').length,
    manual_review_non_scoring_records: findings.filter(
      (finding) => finding.disposition === 'manual_review' && finding.score_classification === 'non_scoring',
    ).length,
    manual_review_candidates: findings.filter(
      (finding) => finding.disposition === 'manual_review' && finding.status === 'fail',
    ).length,
    informational_findings: findings.filter((finding) => finding.disposition === 'informational').length,
    informational_non_scoring_records: findings.filter(
      (finding) => finding.disposition === 'informational' && finding.score_classification === 'non_scoring',
    ).length,
    scored_control_passes: scoredPasses,
    scored_control_failures: scoredFailures,
    unevaluated_controls: countClass('unevaluated_control'),
    not_applicable_controls: findings.filter(
      (finding) => finding.disposition === 'control' && finding.status === 'not_applicable',
    ).length,
    not_applicable_records: countClass('not_applicable'),
    scored_control_numerator: scoredPasses,
    scored_control_denominator: denominator,
    scored_control_pass_rate: passRate,
  };
}

function riskScore(findings) {
  const weights = { critical: 10, high: 7, medium: 4, low: 1 };
  const failed = findings.filter((finding) => finding.score_classification === 'scored_fail');
  if (!failed.length) return 0;
  return Math.min(100, Math.trunc(failed.reduce((sum, finding) => sum + (weights[finding.severity] ?? 1), 0) / (failed.length * 10) * 100));
}

function scopedStats(data, findings, instances, assessmentUnattributedFindings) {
  const summary = summarize(findings);
  const journeyFindings = findings.filter(isJourneyFinding).length;
  const severity_breakdown = Object.fromEntries(
    SEVERITIES.map((severity) => [severity, findings.filter(
      (finding) => finding.score_classification === 'scored_fail' && finding.severity === severity,
    ).length]),
  );
  const pillar_issues = Object.fromEntries(data.pillars.map((pillar) => [
    pillar.id,
    findings.filter((finding) => finding.score_classification === 'scored_fail' && finding.pillar === pillar.id).length,
  ]));
  const passRate = summary.scored_control_pass_rate;
  return {
    ...summary,
    total_checks: findings.length,
    registered_checks: findings.length - journeyFindings,
    journey_findings: journeyFindings,
    unattributed_findings: findings.filter((finding) => !finding.instance_id).length,
    assessment_unattributed_findings: assessmentUnattributedFindings,
    pass_rate: passRate === null ? null : Math.round(passRate * 10) / 10,
    pass_rate_display: passRate === null ? 'Not scored' : `${passRate.toFixed(1)}%`,
    risk_score: riskScore(findings),
    status_breakdown: {
      passed: summary.scored_control_passes,
      failed: summary.scored_control_failures,
      error: findings.filter((finding) => finding.status === 'error').length,
      skipped: findings.filter((finding) => finding.status === 'skipped').length,
      unevaluated: summary.unevaluated_controls,
      not_applicable: findings.filter((finding) => finding.status === 'not_applicable').length,
      manual_review: summary.manual_review_findings,
      informational: summary.informational_findings,
    },
    severity_breakdown,
    pillar_issues,
    instances_assessed: instances.length,
    execution_time: data.stats.execution_time,
    execution_time_scope: 'assessment',
    has_critical_issues: severity_breakdown.critical > 0,
    has_high_issues: severity_breakdown.high > 0,
  };
}

function scopedCharts(data, findings) {
  const summary = summarize(findings);
  const status = data.charts.status_distribution;
  const failed = findings.filter((finding) => finding.score_classification === 'scored_fail');
  const pillar_breakdown = Object.fromEntries(data.pillars.map((pillar) => {
    const items = findings.filter((finding) => finding.pillar === pillar.id);
    const counts = summarize(items);
    return [pillar.id, {
      total_records: items.length,
      scored_control_numerator: counts.scored_control_numerator,
      scored_control_denominator: counts.scored_control_denominator,
      passed: counts.scored_control_passes,
      failed: counts.scored_control_failures,
      pass_rate: counts.scored_control_pass_rate === null ? null : Math.round(counts.scored_control_pass_rate * 10) / 10,
      manual_review_candidates: counts.manual_review_candidates,
      informational_records: counts.informational_findings,
      unevaluated_controls: counts.unevaluated_controls,
      not_applicable_records: counts.not_applicable_records,
      not_applicable_controls: counts.not_applicable_controls,
    }];
  }));
  return {
    status_distribution: {
      labels: [...status.labels],
      colors: [...status.colors],
      data: [
        summary.scored_control_passes,
        summary.scored_control_failures,
        summary.unevaluated_controls,
        summary.not_applicable_records,
        summary.manual_review_non_scoring_records,
        summary.informational_non_scoring_records,
      ],
    },
    severity_distribution: {
      labels: [...data.charts.severity_distribution.labels],
      colors: [...data.charts.severity_distribution.colors],
      data: SEVERITIES.map((severity) => failed.filter((finding) => finding.severity === severity).length),
    },
    pillar_breakdown,
  };
}

const pillarTitle = (id) => id.split('_').map(capitalize).join(' ');

function scopedExecutive(data, findings, assessmentUnattributedFindings, selectedInstanceId) {
  const failed = findings.filter((finding) => finding.score_classification === 'scored_fail');
  const critical = failed.filter((finding) => finding.severity === 'critical');
  const high = failed.filter((finding) => finding.severity === 'high');
  const summary = summarize(findings);
  const insights = [];
  if (critical.length) insights.push({ type: 'critical', message: `Found ${critical.length} critical failed controls requiring immediate attention.` });
  if (high.length) insights.push({ type: 'warning', message: `Identified ${high.length} high-severity failed controls that should be addressed soon.` });
  const passRate = summary.scored_control_pass_rate;
  if (passRate === null) insights.push({ type: 'info', message: 'Control posture is not scored because no controls returned PASS or FAIL.' });
  else if (passRate >= 90) insights.push({ type: 'success', message: `Scored control pass rate is ${passRate.toFixed(1)}%.` });
  else if (passRate >= 75) insights.push({ type: 'info', message: `Scored control pass rate is ${passRate.toFixed(1)}% with room for improvement.` });
  else insights.push({ type: 'warning', message: `Scored control pass rate is ${passRate.toFixed(1)}% and needs attention.` });
  if (summary.manual_review_candidates) {
    const count = summary.manual_review_candidates;
    insights.push({ type: 'info', message: `${count} manual-review candidate${count === 1 ? '' : 's'} require validation before closure.` });
  }
  if (assessmentUnattributedFindings) {
    const count = assessmentUnattributedFindings;
    const records = `finding${count === 1 ? '' : 's'}`;
    insights.push({
      type: 'info',
      message: selectedInstanceId
        ? `${count} unattributed ${records} are excluded from this instance scope and remain available in All instances.`
        : `${count} unattributed ${records} are included only in All instances because no instance could be determined.`,
    });
  }
  const recommendations = [];
  if (critical.length) recommendations.push({ priority: 'critical', title: 'Address Critical Failed Controls', description: `Review and remediate ${critical.length} critical failed controls.`, findings_count: critical.length, query: FILTER_QUERIES.failedSeverity('critical') });
  if (high.length) recommendations.push({ priority: 'high', title: 'Resolve High-Severity Failed Controls', description: `Address ${high.length} high-severity failed controls.`, findings_count: high.length, query: FILTER_QUERIES.failedSeverity('high') });
  for (const { id: pillar } of data.pillars) {
    const count = failed.filter((finding) => finding.pillar === pillar).length;
    if (count >= 3) {
      const title = pillarTitle(pillar);
      recommendations.push({ priority: 'medium', title: `Improve ${title}`, description: `Focus on ${count} failed controls in ${title.toLowerCase()}.`, findings_count: count, query: FILTER_QUERIES.pillarStack('failed', title) });
    }
  }
  return { insights, recommendations: recommendations.slice(0, 5) };
}

function scopedFilters(findings) {
  const failed = findings.filter((finding) => finding.score_classification === 'scored_fail');
  const severities = new Set(failed.map((finding) => finding.severity));
  return {
    default_status: failed.length ? 'fail' : 'all',
    default_severity: severities.has('critical') ? 'critical' : severities.has('high') ? 'high' : 'all',
    default_disposition: failed.length ? 'control' : 'all',
  };
}

export function scopeReportData(data, instanceId = 'all') {
  const selected = instanceId && instanceId !== 'all' ? instanceId : null;
  const unattributedFindings = data.findings.filter((finding) => !finding.instance_id);
  const findings = data.findings.filter((finding) => !selected || finding.instance_id === selected);
  const instances = data.instances.filter((instance) => !selected || instance.id === selected);
  const journeyEntries = data.journey.entries.filter((entry) => !selected || entry.instance_id === selected);
  const executive = scopedExecutive(data, findings, unattributedFindings.length, selected);
  return {
    ...data,
    scope_instance_id: selected,
    unattributed_findings_count: unattributedFindings.length,
    scope_notice: unattributedFindings.length
      ? selected
        ? `${unattributedFindings.length} unattributed findings excluded from this instance scope.`
        : `${unattributedFindings.length} unattributed findings included only in All instances.`
      : null,
    findings,
    instances,
    journey: { ...data.journey, entries: journeyEntries },
    stats: scopedStats(data, findings, instances, unattributedFindings.length),
    charts: scopedCharts(data, findings),
    insights: executive.insights,
    recommendations: executive.recommendations,
    filters: scopedFilters(findings),
  };
}

export function evidenceCellFullValue(cell) {
  return cell?.full ?? cell?.text ?? '';
}

export function evidenceTableMinimumWidth(columnCount) {
  return Math.max(320, columnCount * 160);
}

export function evidenceLayout(width, columnCount) {
  return Number.isFinite(width) && width >= evidenceTableMinimumWidth(columnCount) ? 'table' : 'cards';
}

export function flattenEvidenceForPrint(block, path = []) {
  if (!block) return [];
  if (block.fallback !== undefined) return [{ label: [...path, 'Raw evidence'].filter(Boolean).join(' / '), value: block.fallback }];
  const rows = (block.pairs ?? []).map((pair) => ({
    label: [...path, pair.label].join(' / '),
    value: evidenceCellFullValue(pair.value),
  }));
  for (const table of block.tables ?? []) {
    table.rows.forEach((cells, rowIndex) => {
      table.columns.forEach((column, columnIndex) => rows.push({
        label: [...path, table.title, `Record ${rowIndex + 1}`, column].join(' / '),
        value: evidenceCellFullValue(cells[columnIndex]),
      }));
    });
  }
  for (const list of block.lists ?? []) {
    list.items.forEach((cell, index) => rows.push({
      label: [...path, list.title, `Item ${index + 1}`].join(' / '),
      value: evidenceCellFullValue(cell),
    }));
  }
  for (const section of block.sections ?? []) rows.push(...flattenEvidenceForPrint(section.block, [...path, section.title]));
  return rows;
}

export function journeyEntryOptions(entries) {
  const multipleInstances = new Set(entries.map((entry) => entry.instance_id)).size > 1;
  return entries.map((entry, index) => ({
    value: String(index),
    label: entry.phone_number || entry.flow_name,
    description: entry.phone_description || undefined,
    labelTag: multipleInstances ? (entry.instance_display_name || entry.instance_id) : entry.flow_name,
    tags: [
      ...(entry.phone_type ? [entry.phone_type.replace(/_/g, ' ')] : []),
      ...(multipleInstances ? [entry.flow_name] : []),
    ],
  }));
}
