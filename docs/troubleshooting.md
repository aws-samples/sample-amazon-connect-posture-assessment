# Amazon Connect Customer Posture Assessment Tool — Troubleshooting Guide

## Table of Contents

- [Quick diagnostic](#quick-diagnostic)
- [Installation issues](#installation-issues)
- [AWS credential issues](#aws-credential-issues)
- [Assessment issues](#assessment-issues)
- [Report issues](#report-issues)
- [Getting more information](#getting-more-information)

---

## Quick diagnostic

Run diagnostics from the repository root with the workspace environment:

```bash
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Validate Python, dependencies, AWS credentials, and permissions
python scripts/validate_environment.py

# Check credentials and list missing permissions
python -m amazon_connect_assessment.cli --check-permissions --region us-east-1

# Validate without running checks
python -m amazon_connect_assessment.cli --dry-run --region us-east-1
```

---

## Installation issues

### `ModuleNotFoundError: No module named 'amazon_connect_assessment'`

The package isn't installed in the active Python environment.

```bash
# Create and activate the workspace environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the current checkout
python -m pip install -e .

# Confirm the module loaded by this interpreter
python -m amazon_connect_assessment.cli --version
python -c "import amazon_connect_assessment; print(amazon_connect_assessment.__file__)"
```

### `ModuleNotFoundError: No module named 'boto3'` (or another dependency)

Dependencies are not installed in the active workspace environment.

```bash
source .venv/bin/activate
python -m pip install -e .
```

### The global command runs old controls or report code

A global `pipx` or system installation can shadow the repository workspace.
Compare the executable and module locations:

```bash
command -v amazon-connect-assessment
python -c "import amazon_connect_assessment; print(amazon_connect_assessment.__file__)"
python -m amazon_connect_assessment.cli --list-checks
```

The module path should be inside the current repository checkout, and the
interpreter should be `.venv/bin/python` (`where python` on Windows). Activate
`.venv`, reinstall with `python -m pip install -e .`, and use the module command
for repository runs. Do not rely on a stale global executable.

---

## AWS credential issues

### `NoCredentialsError` or `Unable to locate credentials`

No credentials are configured.

```bash
# Check what credentials are active
aws sts get-caller-identity

# Configure if missing
aws configure
# or
aws configure --profile my-profile
```

### `ProfileNotFound: The config profile (name) could not be found`

The profile name doesn't exist in `~/.aws/config`.

```bash
# List available profiles
aws configure list-profiles

# Use one that exists, or configure a new one
aws configure --profile new-profile-name
```

### `TokenExpiredError` or `ExpiredTokenException`

Temporary credentials (SSO, assumed role, CloudShell session) have expired.

```bash
# Refresh SSO login
aws sso login --profile my-sso-profile

# Or re-export new temporary credentials
```

---

## Assessment issues

### "No Amazon Connect Customer instances found" / `InstanceSummaryList: []`

Credentials work but no instances are returned.

1. **Wrong region** — Amazon Connect Customer instances are region-specific. Confirm with the [AWS CLI `connect list-instances` command](https://docs.aws.amazon.com/cli/latest/reference/connect/list-instances.html):
   ```bash
   aws connect list-instances --region us-east-1
   ```
2. **Missing permission** — `connect:ListInstances` must be in the IAM policy.
3. **Wrong account** — the assumed role may be in a different account than where Connect is deployed.

### Checks return `Skipped` instead of Pass/Fail

The IAM role is missing the permission for that specific API. The finding description names it exactly. Grant the permission and re-run.

For the full read-only assessment permission set, see
`docs/iam-policy-template.json` or deploy
`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`. The opt-in
`--s3-output` path additionally requires the S3 write permissions listed in
the user guide; those are intentionally not included in the read-only policy.
The read-only artifacts are kept in sync with the canonical permission
catalog in `amazon_connect_assessment/iam_permissions.py` (the JSON file is
generated from it — see that module's docstring to add a permission).

### Assessment produces findings but the HTML report is empty

The report generator could not find the pre-built Cloudscape application bundle or its thin HTML shell. Ensure the package is installed correctly:

```bash
pip install -e .
# Confirm the committed runtime assets exist
ls amazon_connect_assessment/templates/html/assessment_report.html
ls amazon_connect_assessment/templates/app/report-app.{js,css}
```

If you changed `frontend/src/`, rebuild the committed bundle:

```bash
cd frontend
npm ci
npm test
npm run build
npm run check
```

### Assessment is very slow

Several options:

```bash
# Target one instance instead of all
python -m amazon_connect_assessment.cli --region us-east-1 --instance-id <id>

# Skip flow analysis, every flow-dependent control, and most flow-content API
# work. This excludes res-hardcoded-routing-001.
python -m amazon_connect_assessment.cli --region us-east-1 --skip-flow-analysis

# Increase parallelism (default is 2x CPU cores)
python -m amazon_connect_assessment.cli --region us-east-1 --max-workers 16 --batch-size 20

# Focus on one pillar
python -m amazon_connect_assessment.cli --region us-east-1 --pillars security
```

### `ThrottlingException` / rate limiting errors

The tool is hitting AWS API rate limits. Reduce parallelism:

```bash
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --max-workers 4 \
  --batch-size 5 \
  --retry-base-delay 2.0 \
  --retry-max-delay 120.0
```

---

## Report issues

### HTML report doesn't open / shows blank

The report is a self-contained HTML file — open it directly in a browser:

```bash
open reports/connect_assessment_*.html        # macOS
xdg-open reports/connect_assessment_*.html   # Linux
start reports\connect_assessment_*.html       # Windows
```

Don't double-click from a file manager on some systems — drag it into the browser instead.

### Charts do not render in the report

The report does not load Chart.js or any other CDN dependency. React,
Cloudscape, chart code, styles, and report data are embedded in the
self-contained HTML artifact.

Confirm the committed bundle exists and matches the maintained frontend source:

```bash
ls amazon_connect_assessment/templates/app/report-app.{js,css}
cd frontend
npm ci
npm test
npm run check
```

If `npm run check` reports a stale bundle, rebuild and verify it:

```bash
npm run build
npm run check
```

Then return to the repository root and regenerate the HTML report. Also inspect
the browser console for a visible report-data schema or bundle error.

### Report scope or drill-down shows unexpected findings

**Report scope** applies to the executive summary, metrics, charts,
recommendations, journey map, and findings table. Clicking a metric value or
chart segment replaces the findings property-filter query with the exact
classification, status, disposition, severity, and/or pillar filter for that
visual. Selecting another instance resets the query to that scope's default.

If the table appears empty, select the **All** pillar tab and clear the property
filter. Remember that top-level JSON and CSV exports remain full-run and are not
narrowed by report scope or table filters; only **Export page (CSV)** follows
the current table collection.

### Evidence cards or tables are clipped or do not switch layout

Evidence switches between a Cloudscape table and cards according to the detail
panel's available width. Widen or narrow the split panel rather than only the
browser window. Long values wrap and can be copied in either layout. If the
layout does not update, close and reopen the detail panel or reload the report.

### Printed/PDF findings differ from the on-screen table

This is expected. Browser print/save-as-PDF includes every finding with its
complete description, methodology, remediation or review action, and evidence
in the current **Report scope**, not only the current property filter, pillar
tab, sort order, or page. Choose the intended instance before printing. Use the
table's **Export page (CSV)** action when you need the current filtered page
instead.

### Custom report template fails before assessment

A custom `template_dir` is strict. It must exist, contain
`assessment_report.html`, and use every required static `@@NAME@@` placeholder
without unsupported placeholders or legacy Jinja syntax. The report generator
fails fast and does not fall back to the packaged shell. Migrate custom shells
to the placeholder list in [Report Formats](report-formats.md#custom-report-shell-templates).

### `--s3-output`: upload didn't complete

`--s3-output` is a consequential opt-in write. Before upload, it hardens an
existing selected bucket as well as a newly created bucket by applying Block
Public Access and versioning and ensuring default encryption. These changes do
not roll back automatically if the later upload fails. The assessment still
succeeds and local reports are written. Common causes:

- **Missing permissions** — the identity needs `s3:CreateBucket`, `s3:PutObject`, `s3:ListBucket`, and the bucket-hardening puts (`s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutBucketVersioning`) on `arn:aws:s3:::amazon-connect-assessment-report-*`. These are separate from the read-only assessment policy and must be granted explicitly when `--s3-output` is enabled.
- **Bucket name taken** — S3 bucket names are globally unique. If `amazon-connect-assessment-report-<account_id>` is already owned elsewhere, pass `--s3-bucket <your-unique-name>`.
- **Wrong region** — the bucket is created in the run region (`--region`). A pre-existing bucket in another region will report a region mismatch; use `--s3-bucket` to point at the right one.

---

## Getting more information

```bash
# Verbose output — shows each step
python -m amazon_connect_assessment.cli --region us-east-1 -v

# Debug output — shows every API call
python -m amazon_connect_assessment.cli --region us-east-1 -vv

# Save all output to a file
python -m amazon_connect_assessment.cli --region us-east-1 -vv --log-file debug.log 2>&1

# JSON log format (useful for piping to jq or a log aggregator)
python -m amazon_connect_assessment.cli --region us-east-1 --log-format json
```
