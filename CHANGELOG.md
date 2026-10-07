# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Upgrade notes

- The unified catalog now emits 64 canonical control outcomes. The only legacy
  Journey input aliases are `journey-sec-001` to `sec-flow-auth-001` and
  `journey-cost-001` to `cost-containment-001`. `journey-res-001` and
  `journey-scope-001` remain canonical IDs. Reports and current examples emit
  canonical IDs only.
- Journey execution now aggregates one outcome per selected Journey control and
  Amazon Connect Customer instance instead of emitting failure-only records per
  phone number. Authentication and containment are manual-review records,
  structural dead ends remain a scored control, and dormant-flow scope is a
  manual-review record.
- Findings now separate execution status from `CONTROL`, `MANUAL_REVIEW`, and
  `INFORMATIONAL` disposition. Only passed and failed `CONTROL` records enter
  the posture numerator and denominator. Skipped, Error, Not Applicable,
  manual-review, and informational records are non-scoring.
- ASFF exports failed `CONTROL` records only. Passing, unevaluated, Not
  Applicable, manual-review, and informational records are omitted. ASFF
  identity remains stable for the same provider control ID and resource ID, so
  existing Security Hub findings remain update-compatible after the identity
  fix. The two renamed Journey controls preserve their historical provider IDs;
  Journey records whose resource identity changed from phone number to instance
  are intentionally new logical findings.
- Agentic CX error-routing now requires the exact authored
  `InputTimeLimitExceeded` and `NoMatchingError` route tokens.
  `NoMatchingCondition` is reported as the readable Other outcome and does not
  satisfy either required route. Escalation review checks for an authored exact
  `Escalation` condition token and does not claim a successful runtime handoff
  to an agent.
- CloudTrail coverage now requires an applicable, actively logging trail whose
  basic or advanced selectors prove coverage of Connect management write
  events. Indeterminate detail reads produce `Skipped` when no qualifying trail
  is known.
- Storage encryption now paginates all supported Connect storage resource
  types. Explicitly unencrypted storage still fails, incomplete evidence skips
  when no known defect exists, and AWS-managed encryption passes with guidance
  to apply organizational customer-managed-key requirements where needed.
- Identity semantics now treat non-SAML instance identity as inventory that
  requires review of the real sign-in path, MFA, lifecycle, and break-glass
  controls rather than a proven failure. Excessive-agency analysis evaluates
  selected high-risk actions in Lambda execution-role identity policies and
  states the policy boundaries it cannot prove.
- The packaged report shell migrated from Jinja expressions to a static,
  single-pass placeholder contract: `@@STYLE_SRC@@`, `@@SCRIPT_SRC@@`,
  `@@REPORT_TITLE@@`, `@@APP_CSS@@`, `@@REPORT_DATA_JSON@@`, and `@@APP_JS@@`.
  Custom `template_dir` users must migrate before upgrading. Missing custom
  directories or shells, missing or unsupported placeholders, and legacy Jinja
  syntax fail fast instead of silently falling back to the packaged shell.
- Report scope now recomputes summaries, charts, recommendations, Journey Map
  entries, and findings for the selected instance. Top-level JSON and CSV
  exports remain full-run exports. Print/save-as-PDF includes every finding in
  the selected report scope with complete descriptions, methodology,
  remediation or review actions, and evidence, independent of table filters and
  pagination.
- Journey analysis is bounded static enumeration: depth 50, 200 paths per phone
  number, and 5,000 paths per run. Cycle edges are pruned without reducing
  structural node reachability. Reached caps, dynamic targets, and unresolved
  cross-flow references retain partial evidence and mark analysis incomplete.
- Assessment and finding timestamps use UTC across JSON, CSV, HTML, ASFF,
  generated filenames, and S3 report prefixes.
- `--s3-output` is a consequential opt-in write that also hardens an existing
  selected bucket by applying Block Public Access and versioning and ensuring
  default encryption before upload.

### Migration integrity

- No aliases or historical IDs are inferred or fabricated. Only compatibility
  mappings proven by the prior output contract are retained.
- Known follow-up: `AGENTS.md` still describes the report shell as Jinja-based.
  It is intentionally unchanged in this update and should be corrected in a
  separately approved change.
