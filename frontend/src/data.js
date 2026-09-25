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
  const { default_status: status, default_severity: severity } = data.filters;
  if (status && status !== 'all') tokens.push({ propertyKey: 'status', operator: '=', value: status });
  if (severity && severity !== 'all') tokens.push({ propertyKey: 'severity', operator: '=', value: severity });
  return { operation: 'and', tokens };
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
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
