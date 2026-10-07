# Amazon Connect Customer Posture Assessment Tool — User Guide

[Back to the documentation index](README.md)

This guide covers installation, AWS access, assessment execution, report
operations, and CI/CD usage. For configuration keys, see
[configuration.md](configuration.md). For implemented checks, see
[check-catalog.md](check-catalog.md).

## Table of Contents

- [Installation](#installation)
  - [Repository workspace](#repository-workspace)
  - [AWS CloudShell](#aws-cloudshell)
  - [Contributor dependencies](#contributor-dependencies)
- [AWS Access](#aws-access)
- [Running Assessments](#running-assessments)
- [Report Operations](#report-operations)
- [CI/CD](#cicd)
- [Further Help](#further-help)

## Installation

Use a virtual environment in the repository workspace. A global `pipx` or
system installation can remain on `PATH` after the repository changes and run
older controls or report code. Use Python 3.12 or later for the environment;
replace `python3.12` below with a newer installed interpreter if needed.

### Repository workspace

```bash
git clone https://github.com/aws-samples/sample-amazon-connect-posture-assessment
cd sample-amazon-connect-posture-assessment
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e .
python -m amazon_connect_assessment.cli --version
```

Run the module from the repository root with the activated environment. The
editable install also creates an environment-local
`.venv/bin/amazon-connect-assessment` console entry point.

After pulling changes, keep the same environment current:

```bash
git pull
source .venv/bin/activate
python -m pip install -e .
```

### AWS CloudShell

CloudShell has Python and the AWS CLI available and uses the credentials of the
signed-in AWS Console session.

```bash
git clone https://github.com/aws-samples/sample-amazon-connect-posture-assessment
cd sample-amazon-connect-posture-assessment
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --output-dir ./reports
```

Download generated reports from the CloudShell **Actions → Download file**
menu. CloudShell sessions are ephemeral, so this path is best for one-off runs.

### Contributor dependencies

Contributors use the same workspace and invocation, with development and test
extras:

```bash
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev,test]"
python -m amazon_connect_assessment.cli --help
```

For installation failures, see [troubleshooting.md](troubleshooting.md).

## AWS Access

The assessment uses read-oriented `List`, `Get`, `Describe`, and `Head`
operations against the
[Amazon Connect Customer](https://docs.aws.amazon.com/connect/latest/adminguide/what-is-amazon-connect.html)
resources and supporting services it inspects. The consequential opt-in
`--s3-output` feature creates or hardens the selected report bucket and uploads
reports.

Confirm the active identity and region access:

```bash
aws sts get-caller-identity
aws connect list-instances --region us-east-1
```

AWS documents this command under the
[`connect list-instances` CLI reference](https://docs.aws.amazon.com/cli/latest/reference/connect/list-instances.html).

If access is denied, deploy the self-assessment policy:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToUserName=YOUR_USERNAME \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

To attach the policy to a role instead:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToRoleName=YOUR_ROLE_NAME \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

To create the policy without attaching it:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

aws cloudformation describe-stacks \
  --stack-name amazon-connect-assessment-permissions \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicyArn`].OutputValue' \
  --output text
```

The canonical read-permission source is
`amazon_connect_assessment/iam_permissions.py`. It generates
[iam-policy-template.json](iam-policy-template.json), and drift tests keep the
CloudFormation template action-equivalent. The template does not grant the
additional S3 write permissions required by `--s3-output`.

### Profiles, SSO, and environment variables

```bash
# Default profile
python -m amazon_connect_assessment.cli --region us-east-1 --output-dir ./reports

# Named profile
python -m amazon_connect_assessment.cli --profile my-profile --region us-east-1

# SSO profile
aws sso login --profile my-sso-profile
python -m amazon_connect_assessment.cli --profile my-sso-profile --region us-east-1
```

For CI/CD or temporary credentials:

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
export AWS_SESSION_TOKEN="..."   # temporary credentials only

python -m amazon_connect_assessment.cli --output-dir ./reports
```

Validate access before a long run:

```bash
python -m amazon_connect_assessment.cli --check-permissions --region us-east-1
python -m amazon_connect_assessment.cli --dry-run --region us-east-1
```

## Running Assessments

Basic assessment:

```bash
python -m amazon_connect_assessment.cli --region us-east-1 --output-dir ./reports
```

Common options:

```bash
# List controls selected by the effective configuration without calling AWS
# From the repository root, the bundled config selects 63 of 64 controls
python -m amazon_connect_assessment.cli --list-checks

# Select canonical controls (BaseCheck and Journey-backed IDs behave the same)
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --checks sec-cloudtrail-001 journey-res-001

# Assess one instance
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --instance-id <id> \
  --output-dir ./reports

# Select pillars and severities
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --pillars security resilience \
  --severity critical high

# Skip flow analysis and every flow-dependent control, including
# res-hardcoded-routing-001.
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --skip-flow-analysis

# Generate all report formats
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --output-format html json csv asff

# Tune journey-scoring bounds
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --config config/assessment_config.yaml
```

Use `python -m amazon_connect_assessment.cli --help` for the complete CLI reference,
including control selection, worker controls, retries, logging, checkpoints,
configuration inspection, and report options.

The catalog contains 64 canonical controls: 60 BaseCheck executors and 4
Journey-backed executors. `--pillars`, `--severity`, `--checks`,
`--exclude-checks`, config enablement, and `--skip-flow-analysis` form one
AND-filtered selection. Journey-backed controls appear in `--list-checks` with
their pillar, severity, and disposition.

For backward compatibility, `journey-sec-001` selects `sec-flow-auth-001` and
`journey-cost-001` selects `cost-containment-001`. Listings, current examples,
and reports emit only canonical IDs.

Journey analysis statically enumerates paths with maximum depth 50, 200 paths
per phone number, and 5,000 paths per instance. Cycle edges are pruned per path
without reducing structural node reachability. A reached cap, dynamic target,
or unresolved flow reference makes the result incomplete; the tool retains
partial evidence and does not claim that every runtime route was evaluated.

## Report Operations

### Open a report

```bash
open reports/connect_assessment_*.html        # macOS
xdg-open reports/connect_assessment_*.html    # Linux
```

The HTML report is self-contained and can be viewed offline. It separates
scored control outcomes from manual-review candidates and informational
inventory. `CheckStatus` explains whether execution passed, failed, was
skipped, errored, or was not applicable; disposition explains whether the
record contributes to posture scoring. Only passed and failed `CONTROL`
records enter the scored-control denominator.

Each finding includes methodology explaining why it is assessed, the evidence
source, proof limitations, developer/admin meaning, and verification criteria.
The Caller Journey Map renders contact flows targeted by inbound phone numbers.

### Scope and drill-downs

A report opens at **All instances**. Use **Report scope** to select one instance;
the executive summary, charts, recommendations, journey map, and findings are
recomputed for that scope. Scope covers only the AWS account and region used by
the assessment run.

Clickable metric values and chart segments open the findings table with exact
filters. Depending on the selected value, these filters use
`score_classification`, `status`, `disposition`, `severity`, and
`pillarLabel`. Changing report scope resets the findings query to the selected
scope's default filter. The table's **Export page (CSV)** action follows the
current scope, pillar, filter, sort order, and page.

Evidence automatically uses a Cloudscape table when the detail panel is wide
enough and responsive cards when it is narrow. Long values remain available
for copying. Print output expands complete descriptions, methodology,
remediation or review actions, and evidence rather than abbreviated display
values.

### Export scope

The top-level **Export** menu has intentionally different scope rules:

- **Full report data (JSON)** exports the complete embedded report across all
  instances, independent of the current scope and findings filter.
- **All findings, all instances (CSV)** exports every embedded finding,
  independent of the current scope and findings filter.
- **Print scoped report / save as PDF** prints every finding in the current
  instance scope, independent of the on-screen filter and pagination. At **All
  instances**, it prints all instances.

CLI-generated JSON and CSV files also contain the complete assessment run. If
the run used `--instance-id`, that complete run is already single-instance.
Assessment and finding timestamps are exported as UTC ISO 8601 values; HTML
labels them `UTC`, ASFF uses `Z`, and generated filename timestamps use UTC.
PDF is a browser print/save operation, not a CLI output format.

See [report-formats.md](report-formats.md) for the JSON, CSV, HTML, and ASFF
contracts. ASFF contains failed controls only.

### Agentic CX proof boundary

The three ACXD controls inspect reachable
`ConnectParticipantWithAgenticCX` actions in parsed customer-authored Connect
flows. They report Connect-side handoff inventory, required error routes, and
whether an authored condition contains the case-insensitive exact token
`Escalation` for manual review. That token does not prove a successful
escalated-to-agent runtime outcome. The controls do not call Agentic CX Designer
APIs or prove application internals, builds, deployments, alias resolution,
runtime containment, or guardrails. Context-variable values are not retained
in evidence.

### Publish reports to S3

```bash
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --output-format html json \
  --s3-output
```

The default bucket is
`amazon-connect-assessment-report-<account_id>`. Override it with
`--s3-bucket`. Before upload, the publisher applies Block Public Access and
versioning to a new or existing selected bucket and preserves existing default
encryption or adds SSE-S3 when none is configured. Enabling this option can
therefore modify an existing bucket, and those hardening changes do not roll
back automatically if upload later fails. Review the selected bucket and grant
write access deliberately.

Required additional permissions include:

- `s3:CreateBucket`
- `s3:PutObject`
- `s3:ListBucket`
- `s3:PutBucketPublicAccessBlock`
- `s3:PutEncryptionConfiguration`
- `s3:PutBucketVersioning`

Local reports remain available if an S3 upload fails.

### Compare assessment runs

Generate a JSON baseline, then compare a later run:

```bash
# Baseline
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --output-format html json \
  --output-dir ./reports

# Later run
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --output-format html \
  --diff reports/connect_assessment_<baseline>.json \
  --output-dir ./reports
```

The command reports resolved, new, and persistent findings.

## CI/CD

The CLI exits with code `0` on success and `1` on failure.

### GitHub Actions

```yaml
name: Amazon Connect Customer Posture Assessment Tool

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: pip install .
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AMAZON_CONNECT_ROLE_ARN }}
          aws-region: us-east-1
      - name: Run assessment
        run: |
          python -m amazon_connect_assessment.cli \
            --region us-east-1 \
            --output-format html json \
            --output-dir ./reports \
            --quiet
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: amazon-connect-report-${{ github.run_id }}
          path: reports/
          retention-days: 90
```

## Further Help

- [Configuration](configuration.md)
- [Check catalog](check-catalog.md)
- [Report formats](report-formats.md)
- [Performance guide](performance-optimization.md)
- [Troubleshooting](troubleshooting.md)
