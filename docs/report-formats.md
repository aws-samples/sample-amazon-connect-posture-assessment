# Report Formats

The CLI writes reports to `output.directory`, which defaults to `./reports`.
Filename templates are basenames; directory separators are rejected.

All formats use the same 64-control catalog and emit canonical IDs only.
Migration note: the legacy input aliases `journey-sec-001` and
`journey-cost-001` remain accepted for selection, but output uses
`sec-flow-auth-001` and `cost-containment-001`.

Generate one or more formats with:

```bash
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json csv asff
```

## Shared result model

`status` reports execution as `pass`, `fail`, `skipped`, `error`, or
`not_applicable`. `disposition` reports the methodological role as `control`,
`manual_review`, or `informational`. A failed manual-review record is a review
candidate, not proof of a failed control. An informational record is inventory
or planning context.

The posture score counts only `control` records with `pass` or `fail`. Its
numerator is passed controls. Its denominator is passed plus failed controls.
Skipped controls, errors, Not Applicable records, manual reviews, and
informational records do not enter the denominator.

## HTML

HTML is a self-contained interactive report for browser review. It uses the
React/Cloudscape application maintained in `frontend/` and embeds the committed
bundle, fonts, report-data JSON, and Journey Map into one offline file. It includes:

- the scored-control numerator, denominator, and pass rate;
- separate counts for failed controls, unevaluated controls, manual-review
  candidates, informational records, and Not Applicable records;
- a visible disposition guide explaining Control, Manual review, Informational,
  execution status, and score classification;
- a report-wide instance scope that updates summary metrics, charts,
  recommendations, findings, the Journey Map, and printed output;
- summary and chart drill-down actions that apply the exact matching findings
  filters;
- disposition badges and disposition filters;
- observed evidence and remediation or review action;
- adaptive evidence records that remain readable in narrow detail panels and
  preserve complete values in print;
- complete printed descriptions, methodology, remediation or review actions,
  and evidence for every finding in the selected report scope;
- methodology sections for why the control exists, evidence source, proof
  limitations, developer/admin meaning, and verification criteria;
- the phone-number-driven Caller Journey Map when flow analysis is enabled.

The JSON and CSV export actions remain explicitly labeled as full-assessment,
all-instance exports. Print and PDF output follow the selected report scope.

The report distinguishes measured control failures from review candidates and
inventory. It shows **Not scored** when the denominator is zero.

## JSON

JSON is the complete machine-readable result. Top-level fields are:

| Field | Description |
|---|---|
| `assessment_id` | Unique assessment identifier. |
| `timestamp` | Assessment timestamp as an ISO 8601 UTC value. Naive input datetimes are treated as UTC; timezone-aware values are converted to UTC. |
| `account_id` | AWS account assessed. |
| `region` | AWS region assessed. |
| `summary` | Status, disposition, and scored-control totals. |
| `instances` | Assessed Amazon Connect Customer instance metadata. |
| `findings` | Canonical control outcomes. |
| `journey_map_entries` | Phone-number and flow diagram data for the HTML map. |
| `journey_map_status` | Reason the Journey Map is empty, or `null`. |
| `metadata` | Tool version and execution metadata. |
| `execution_errors` | Errors retained while the assessment continued. |

Each finding timestamp follows the same UTC contract. CSV timestamps are UTC
ISO 8601 values, HTML displays finding timestamps with a `UTC` suffix, ASFF uses
UTC `Z` timestamps, and generated filename timestamps use UTC
`YYYYMMDD_HHMMSS`.

Each `findings` item includes:

- `check_id`, `check_name`, `pillar`, `severity`, `status`, and `disposition`;
- `instance_id`, `resource_id`, and `resource_type`;
- `description`, `remediation`, `structured_remediation`, and `evidence`;
- `score_classification` and `timestamp`;
- `methodology`, containing `reason`, `evidence_source`,
  `proof_limitations`, `developer_admin_meaning`, `verification_criteria`,
  `responsible_function`, and `primary_lens_reference`.

The additive `summary` fields include `total_records`, `control_findings`,
`manual_review_findings`, `informational_findings`,
`manual_review_candidates`, `scored_control_passes`,
`scored_control_failures`, `unevaluated_controls`,
`not_applicable_controls`, `scored_control_numerator`,
`scored_control_denominator`, and `scored_control_pass_rate`. The legacy
`total_checks`, `registered_checks`, and `journey_findings` fields remain for
backward compatibility; use the disposition-aware fields for posture reporting.

## CSV

CSV contains one row per canonical control outcome. The columns are:

`Assessment ID`, `Timestamp`, `Account ID`, `Region`, `Instance ID`,
`Instance Alias`, `Check ID`, `Check Name`, `Pillar`, `Severity`, `Status`,
`Resource Type`, `Resource ID`, `Description`, `Remediation`,
`Remediation Targets`, `Evidence`, `Disposition`, `Reason`, `Evidence Source`,
`Proof Limitations`, `Developer/Admin Meaning`, `Verification Criteria`,
`Responsible Function`, and `Primary Lens Reference`.

Journey-backed and BaseCheck outcomes use the same row shape. Journey-map
diagrams and assessment summary counts are available in JSON and HTML, not CSV.

## ASFF

ASFF is a Security Hub import document. It exports **failed `CONTROL` records only**. Passing controls, skipped controls, errors, Not Applicable records,
manual-review candidates, and informational inventory are omitted. This avoids
presenting non-scoring review candidates as Security Hub compliance failures.

Import an ASFF report with:

```bash
aws securityhub batch-import-findings \
  --findings file://reports/connect_assessment_asff_*.json \
  --region us-east-1
```

ASFF uses resource type `Other`, preserves the Connect-specific resource type in
tags, and includes disposition and bounded methodology fields in
`ProductFields`. Finding identity is stable for the same provider control ID and
resource ID, so re-importing an updated result updates the existing Security Hub
finding instead of creating a duplicate. The two renamed Journey controls retain
their historical provider IDs for this compatibility boundary; reports and
catalogs still use canonical IDs. Journey aggregation can change resource
identity from a phone number to an instance, so that migration is a new logical
finding rather than an identity collision.

## Custom report shell templates

Maintainer integrations that construct `ReportGenerator(template_dir=...)` must
provide an existing directory containing `assessment_report.html`. Custom shells
use the static placeholders `@@STYLE_SRC@@`, `@@SCRIPT_SRC@@`,
`@@REPORT_TITLE@@`, `@@APP_CSS@@`, `@@REPORT_DATA_JSON@@`, and `@@APP_JS@@`.
Construction fails fast for a missing directory or shell, missing required or
unsupported placeholders, or legacy Jinja syntax. The renderer does not silently
fall back to the packaged shell, and replacement values are applied once rather
than rescanned.

## Filename templates

The configured template may use `{timestamp}`, `{account_id}`, `{region}`, and
`{assessment_id}`. For example:

```yaml
output:
  directory: ./reports
  format: [html, json]
  filename_template: connect_assessment_{timestamp}_{account_id}
```

Use `output.directory` or `--output-dir` to choose the destination directory.
