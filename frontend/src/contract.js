// The fields the report UI reads from ReportGenerator._build_report_data().
// loadReportData() rejects data missing any of them, and the Node tests check the
// committed fixture (generated from the real Python output) against this list.
// Values may be null where the UI handles it; only presence is required.

export const REQUIRED_FIELDS = {
  report: [
    'schema_version', 'title', 'generated_at', 'assessment', 'metadata', 'summary', 'stats',
    'insights', 'recommendations', 'filters', 'pillars', 'instances', 'findings', 'journey',
    'execution_errors', 'raw_data', 'service_icon',
  ],
  assessment: ['id', 'account_id', 'region', 'timestamp'],
  metadata: ['tool_version', 'execution_time', 'execution_environment'],
  summary: [
    'total_checks', 'passed_checks', 'failed_checks', 'error_checks', 'skipped_checks',
    'not_applicable_checks', 'critical_findings', 'high_findings', 'medium_findings', 'low_findings',
  ],
  stats: ['pass_rate', 'risk_score', 'registered_checks', 'journey_findings', 'instances_assessed'],
  filters: ['default_severity', 'default_status'],
  journey: ['entries', 'status'],
  pillar: ['id', 'label'],
  insight: ['type', 'message'],
  recommendation: ['priority', 'title', 'description', 'findings_count'],
  finding: [
    'key', 'check_id', 'check_name', 'pillar', 'severity', 'status', 'resource_id', 'resource_type',
    'resource_label', 'instance', 'timestamp', 'description', 'description_html', 'remediation_html',
    'structured_remediation', 'evidence', 'evidence_json',
  ],
  structured_remediation: ['summary', 'steps', 'target_resources', 'references', 'applies_if'],
  remediation_step: ['order', 'instruction_html', 'command', 'console_path'],
  journey_entry: [
    'instance_id', 'instance_display_name', 'phone_number', 'phone_type', 'phone_description',
    'flow_id', 'flow_name', 'diagram_model', 'exports',
  ],
  diagram_model: ['nodes', 'edges', 'layout'],
  layout: ['canvas', 'node_size', 'positions', 'connectors', 'labels'],
  journey_node: ['title', 'category', 'summary', 'scope', 'ai', 'is_group', 'is_entry', 'is_primary', 'actions'],
  journey_edge: ['title', 'source', 'target', 'route_type', 'summary', 'is_primary', 'outcomes'],
};

const has = (obj, key) => obj !== null && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);

// Returns human-readable paths of every missing field (empty when valid).
export function contractViolations(data) {
  const missing = [];
  const check = (obj, kind, path) => {
    if (obj === null || typeof obj !== 'object') {
      missing.push(`${path} (expected an object)`);
      return;
    }
    for (const key of REQUIRED_FIELDS[kind]) if (!has(obj, key)) missing.push(`${path}.${key}`);
  };
  const each = (list, kind, path, visit) => {
    if (!Array.isArray(list)) {
      missing.push(`${path} (expected a list)`);
      return;
    }
    list.forEach((item, i) => {
      check(item, kind, `${path}[${i}]`);
      if (visit) visit(item, `${path}[${i}]`);
    });
  };

  check(data, 'report', 'data');
  if (missing.length) return missing;
  for (const kind of ['assessment', 'metadata', 'summary', 'stats', 'filters', 'journey']) check(data[kind], kind, `data.${kind}`);
  each(data.pillars, 'pillar', 'data.pillars');
  each(data.insights, 'insight', 'data.insights');
  each(data.recommendations, 'recommendation', 'data.recommendations');
  each(data.findings, 'finding', 'data.findings', (f, path) => {
    if (f.structured_remediation) {
      check(f.structured_remediation, 'structured_remediation', `${path}.structured_remediation`);
      each(f.structured_remediation.steps, 'remediation_step', `${path}.structured_remediation.steps`);
    }
  });
  each(data.journey?.entries, 'journey_entry', 'data.journey.entries', (entry, path) => {
    const model = entry.diagram_model;
    check(model, 'diagram_model', `${path}.diagram_model`);
    if (!has(model, 'nodes')) return;
    if (model.layout) check(model.layout, 'layout', `${path}.diagram_model.layout`);
    for (const [key, node] of Object.entries(model.nodes ?? {})) check(node, 'journey_node', `${path}.diagram_model.nodes.${key}`);
    for (const [key, edge] of Object.entries(model.edges ?? {})) check(edge, 'journey_edge', `${path}.diagram_model.edges.${key}`);
  });
  return missing;
}
