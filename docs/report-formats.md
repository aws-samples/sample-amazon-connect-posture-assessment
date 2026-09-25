# Report Formats

The CLI writes reports to the configured `output.directory`, which defaults to
`./reports`. Report filenames are basenames only; directory separators in
`output.filename_template` are rejected.

## Table of Contents

- [HTML](#html)
- [JSON](#json)
- [CSV](#csv)
- [ASFF](#asff)
- [Timestamps](#timestamps)
- [Filename Templates](#filename-templates)

Generate one or more formats with:

```bash
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json csv asff
```

## HTML

HTML is a self-contained interactive report intended for browser viewing, built
with [Cloudscape Design System](https://cloudscape.design/) components. It
contains the executive summary, charts, priority recommendations, a findings
table (property filter, sorting, pagination, column preferences) whose rows open
evidence and remediation in a side panel, and the phone-number-driven Caller
Journey Map. The map renders available contact flows targeted by inbound phone
numbers; it is disabled by `--skip-flow-analysis`.

The file needs no network access: the UI bundle, fonts, and data are embedded.
The inlined UI bundle adds roughly 3 MB to every HTML report, independent of
the number of findings; use JSON or CSV when report size matters.
Assessment data travels in a `<script id="report-data" type="application/json">`
element (schema version 1), so it can also be extracted programmatically. The
report's **Export** menu downloads that data as JSON, all findings as CSV, or
prints to PDF. Printing (from the menu or the browser) replaces the filtered,
paginated findings table with a table of every finding.

## JSON

JSON is the complete machine-readable assessment result. Its top-level fields are:

| Field | Description |
|---|---|
| `assessment_id` | Unique assessment identifier. |
| `timestamp` | Assessment time in UTC, ISO 8601 with offset (for example `2026-01-15T10:00:00.123456+00:00`). See [Timestamps](#timestamps). |
| `account_id` | AWS account assessed. |
| `region` | AWS region assessed. |
| `summary` | Counts by status and severity, including `total_checks` (all finding results), `registered_checks` (checks from the registry), and `journey_findings` (Caller Journey results). |
| `instances` | Assessed Amazon Connect Customer instance metadata. |
| `findings` | Finding records, evidence, remediation, and timestamps. |
| `journey_map_entries` | HTML Journey Map entries, including phone number, flow, and diagram data. |
| `journey_map_status` | Empty-state or skip metadata when the Journey Map has no entries; otherwise `null`. |
| `metadata` | Tool version, execution time, account/region, environment, and Python version. |
| `execution_errors` | Errors recorded while continuing a fail-open assessment. |

The `findings` array includes `check_id`, `check_name`, `pillar`, `severity`,
`status`, `resource_id`, `resource_type`, `description`, `remediation`,
`structured_remediation`, `evidence`, and `timestamp`.

## CSV

CSV is a flat finding-oriented export for spreadsheets and SIEM ingestion. It
contains one row per finding and includes:

`Assessment ID`, `Timestamp`, `Account ID`, `Region`, `Instance ID`,
`Instance Alias`, `Check ID`, `Check Name`, `Pillar`, `Severity`, `Status`,
`Resource Type`, `Resource ID`, `Description`, `Remediation`,
`Remediation Targets`, and `Evidence`.

Journey-map entries and assessment summary counts are available in JSON, not CSV.

## ASFF

ASFF is a Security Hub import document. It writes a JSON object with a
`Findings` array containing findings that are actionable or unavailable for
evaluation. Passing, skipped, and not-applicable findings are omitted.

Import an ASFF report with:

```bash
aws securityhub batch-import-findings \
  --findings file://reports/connect_assessment_asff_*.json \
  --region us-east-1
```

ASFF output uses Security Hub-compatible resource type `Other` and preserves the
Connect-specific resource type in tags.

## Timestamps

| Where | Format | Example |
|---|---|---|
| JSON `timestamp` fields, CSV `Timestamp` column | ISO 8601 with `+00:00` offset | `2026-01-15T10:00:00.123456+00:00` |
| HTML report | `YYYY-MM-DD HH:MM:SS UTC` | `2026-01-15 10:00:00 UTC` |
| ASFF `CreatedAt` (finding time) and `UpdatedAt` (export time) | ISO 8601 with microseconds and `Z` suffix | `2026-01-15T10:00:00.123456Z` |
| Filename `{timestamp}` placeholder | `YYYYMMDD_HHMMSS` | `20260115_100000` |

All timestamps are recorded and written in UTC, whatever the timezone of the
machine running the assessment.

## Filename Templates

The configured template may use:

- `{timestamp}` (assessment time in UTC as `YYYYMMDD_HHMMSS`)
- `{account_id}`
- `{region}`
- `{assessment_id}`

For example:

```yaml
output:
  directory: ./reports
  format: [html, json]
  filename_template: connect_assessment_{timestamp}_{account_id}
```

The template controls the basename. Use `output.directory` or `--output-dir` to
choose where reports are written.
