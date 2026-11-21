# Report Formats

The CLI writes reports to `output.directory`, which defaults to `./reports`.
Filename templates are basenames; directory separators are rejected.

All formats use the same 64-control catalog and emit canonical IDs only
(except the ASFF finding `Id`, which keeps the historical provider IDs; see
[ASFF](#asff)). Migration note: the legacy input aliases `journey-sec-001` and
`journey-cost-001` remain accepted for selection, but output uses
`sec-flow-auth-001` and `cost-containment-001`.

Generate one or more formats with:

```bash
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json csv asff
```

Regardless of filename template, the ASFF file ends in `_asff.json` (a
trailing `.json` in the template is replaced) so it does not overwrite the
full-assessment JSON report from the same run.

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
- the Customer Journey Map, covering entry points on every channel, when flow analysis is enabled.

The JSON and CSV export actions remain explicitly labeled as full-assessment,
all-instance exports. Print and PDF output follow the selected report scope.
These in-browser exports use the report's own data shape and column set; use
`--output-format json csv` for the JSON and CSV contracts documented below.

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
| `posture_roadmap` | Per-pillar scored-control posture keyed by pillar: `pillar`, `total_records`, `scored_control_numerator`, `scored_control_denominator`, `pass_rate`, `maturity_level`, and `improvement_actions`. |
| `instances` | Assessed Amazon Connect Customer instance metadata. |
| `findings` | Canonical control outcomes. |
| `journey_map_entries` | Phone-number and flow diagram data for the HTML map. Entries contain the claimed phone number in full (not masked), along with its type, country code, and description. |
| `journey_map_status` | Object with `reason` (slug), `message`, and `hint` explaining why the Journey Map is empty; `null` when entries exist or the map was not computed. |
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
`not_applicable_controls`, `manual_review_non_scoring_records`,
`informational_non_scoring_records`, `not_applicable_records`,
`scored_control_numerator`, `scored_control_denominator`, and
`scored_control_pass_rate`. The legacy status and severity counters
(`total_checks`, `passed_checks`, `failed_checks`, `error_checks`,
`skipped_checks`, `not_applicable_checks`, `critical_findings`,
`high_findings`, `medium_findings`, `low_findings`, `registered_checks`, and
`journey_findings`) remain for backward compatibility; use the
disposition-aware fields for posture reporting.

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

The ASFF file contains a top-level `Findings` array. If it contains findings,
pass the actual generated filename as CLI input:

```bash
aws securityhub batch-import-findings \
  --cli-input-json file://reports/connect_assessment_20260101_120000_123456789012_asff.json \
  --region us-east-1
```

Replace the example timestamp and account ID with the generated filename.
`BatchImportFindings` accepts 1–100 findings per request; split a larger ASFF
file into batches before importing it. An ASFF file with no failed controls has
an empty `Findings` array and needs no import.

ASFF uses resource type `Other`, preserves the Connect-specific resource type in
tags, and includes disposition and bounded methodology fields in
`ProductFields`. Finding identity is stable for the same provider control ID and
resource ID, so re-importing an updated result updates the existing Security Hub
finding instead of creating a duplicate. The two renamed Journey controls retain
their historical provider IDs for this compatibility boundary; reports and
catalogs still use canonical IDs. Journey aggregation can change resource
identity from a phone number to an instance, so that migration is a new logical
finding rather than an identity collision.

## Diff output

`--diff BASELINE_JSON` compares the current run against a previous JSON report
and prints the result to the console. Failed `CONTROL` records and failed
manual-review candidates are compared separately, each as resolved, new, and
persistent. Informational records never participate in the diff. Records match
by canonical control ID (legacy aliases in the baseline are resolved) and
instance, falling back to resource ID for older reports without `instance_id`.
To produce the comparison, `--diff` always writes a current JSON report to the
output directory, even when `json` is not in `--output-format`.

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

Set the template with `output.filename_template` or `--output-filename`. It
may use `{timestamp}`, `{account_id}`, `{region}`, and `{assessment_id}`. For
example:

```yaml
output:
  directory: ./reports
  format: [html, json]
  filename_template: connect_assessment_{timestamp}_{account_id}
```

Use `output.directory` or `--output-dir` to choose the destination directory.
