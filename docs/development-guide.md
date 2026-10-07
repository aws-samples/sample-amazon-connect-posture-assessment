# Amazon Connect Customer Posture Assessment Tool — Development Guide

## Table of Contents

- [Setup](#setup)
- [Running tests](#running-tests)
- [Code quality](#code-quality)
- [Developer scripts](#developer-scripts)
- [Adding a new canonical control](#adding-a-new-canonical-control)
  - [Create the BaseCheck executor](#1-create-the-basecheck-executor)
  - [Add the atomic catalog record and register the executor](#2-add-the-atomic-catalog-record-and-register-the-executor)
  - [Write tests](#3-write-tests)
  - [Update documentation](#4-update-documentation)
- [Project architecture](#project-architecture)
  - [Data flow](#data-flow)
- [CI pipeline](#ci-pipeline)
- [Release process](#release-process)

---

## Setup

Use the repository workspace and its `.venv` so the Python module and generated
reports always come from the current checkout. Use Python 3.12 or later;
replace `python3.12` with a newer installed interpreter if needed:

```bash
git clone https://github.com/aws-samples/sample-amazon-connect-posture-assessment
cd sample-amazon-connect-posture-assessment
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev,test]"
python -m amazon_connect_assessment.cli --help
```

The editable install also creates the environment-local console entry point:

```bash
.venv/bin/amazon-connect-assessment --help
```

Prefer `python -m amazon_connect_assessment.cli` in development instructions.
It makes the interpreter and checkout explicit and avoids accidentally invoking
a stale globally installed executable.

The HTML report spans two ownership boundaries:

- Python in `report_generator.py` owns the report-data schema, embeds the
  `report-data` JSON island, and produces the self-contained HTML shell plus
  backend JSON and CSV exports.
- React/Cloudscape in `frontend/src/` owns rendering, report scope, metric and
  chart drill-downs, adaptive evidence cards/tables, browser CSV/JSON exports,
  and print/save-as-PDF behavior.

The committed frontend bundle lets Python users run without Node. The frontend
source is maintained in this repository. When `frontend/` changes, run:

```bash
cd frontend
npm ci
npm test
npm run build
npm run check
cd ..
```

`npm run check` verifies that the committed bundle under
`amazon_connect_assessment/templates/app/` matches the maintained frontend
source.

The packaged report shell uses a static, single-pass placeholder contract:
`@@STYLE_SRC@@`, `@@SCRIPT_SRC@@`, `@@REPORT_TITLE@@`, `@@APP_CSS@@`,
`@@REPORT_DATA_JSON@@`, and `@@APP_JS@@`. Replacement values are not rescanned,
and ordinary text values are HTML-escaped. If a caller supplies `template_dir`,
`ReportGenerator` fails immediately when the directory or
`assessment_report.html` is missing, when a required placeholder is absent,
when an unsupported placeholder is present, or when legacy Jinja syntax remains.
It never silently falls back to the packaged template. Custom templates must be
migrated to the static placeholders before use.

---

## Running tests

```bash
# Full suite with coverage
pytest

# Specific file
pytest tests/test_engine.py

# Specific test
pytest tests/test_engine.py::TestAssessmentEngine::test_run_assessment

# By marker
pytest -m unit
pytest -m property
pytest -m integration

# Without coverage (faster)
pytest --no-cov
```

Coverage gate is 65%. The htmlcov/ report is written after each run — open `htmlcov/index.html` to browse line-level coverage.

---

## Code quality

All of these run in CI on every push. Fix them locally before pushing:

```bash
# Format (replaces black + isort)
ruff format amazon_connect_assessment/ tests/

# Lint + import order (replaces flake8 + isort; --fix auto-fixes)
ruff check amazon_connect_assessment/ tests/

# Types
mypy amazon_connect_assessment/ --ignore-missing-imports
```

Or run all of the above at once via pre-commit (config in `.pre-commit-config.yaml`):

```bash
pre-commit install            # auto-run on git commit (where core.hooksPath allows)
pre-commit run --all-files    # or run on demand
```

If `core.hooksPath` is set globally (e.g. Amazon git-defender), `pre-commit install`
is skipped — run `pre-commit run` manually before committing.

---

## Developer scripts

Standalone utilities in `scripts/` (run directly, not part of the installed package):

```bash
# Benchmark sequential vs. parallel engine and demo parallel features
python scripts/performance_test.py

# Pre-flight environment check (Python version, deps, imports, AWS credentials)
python scripts/validate_environment.py

# Regenerate the deterministic report from all 64 canonical controls
python scripts/generate_sample_report.py

# Regenerate the local HTML copy of README.md (requires: pip install markdown;
# docs/README.html is generated and is not a source document)
python scripts/generate_readme_html.py
```

Regenerate the README screenshots after changing the sample report in `examples/`:

```bash
pip install -e ".[screenshots]"
playwright install chromium
python scripts/capture_screenshots.py
```

One render writes both `docs/images/sample-assessment-report-full.png` and the
cropped `docs/images/sample-assessment-report.png` used by the README. The
capture script comes from the AWS Samples Cloudscape report workflow.

---

## Adding a new canonical control

The unified catalog contains 64 canonical records. Each record owns one root
condition, disposition, methodology, and executor. Of the current records, 60
use a `BaseCheck` executor and 4 use the Journey executor. Add the catalog
record before registering a new executor; catalog hydration rejects missing,
duplicate, aliased, or mismatched IDs.

Use `CONTROL` only when available evidence supports a scored pass/fail decision.
Use `MANUAL_REVIEW` for candidates that require human validation and
`INFORMATIONAL` for inventory or context. Status remains separate from this
disposition.

Treat every finding description as the reader's explanation, not only as an
evidence count. State what was observed, why the condition is called out, and
why it matters to the developer or administrator. Distinguish evidence from
inference and include relevant proof limitations. Catalog methodology supports
this explanation but does not replace it.

For a BaseCheck-backed control, implement `execute()` as follows. Catalog
hydration attaches disposition and methodology to the executor before it runs.

### 1. Create the BaseCheck executor

```python
# amazon_connect_assessment/checks/my_checks.py
from .base import BaseCheck, CheckContext
from ..models import Finding, Pillar, Severity, CheckStatus


class MyNewCheck(BaseCheck):
    def __init__(self):
        super().__init__(
            check_id="my-check-001",
            name="My New Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description="What this check validates.",
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        client = context.aws_client_factory.get_connect_client()

        # ... your check logic ...

        if compliant:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
            )
        else:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="Specific description of what failed.",
                evidence={"key": "value"},
                remediation="Prescriptive steps to fix this.",
            )
```

For insufficient-permission scenarios, use the built-in helper instead of returning ERROR:

```python
except ClientError as e:
    if e.response["Error"]["Code"] == "AccessDeniedException":
        return self.skipped_for_access_denied(
            context, required_permission="connect:DescribeInstanceAttribute"
        )
    raise
```

### 2. Add the atomic catalog record and register the executor

Add an `AtomicControl` definition in
`amazon_connect_assessment/checks/control_registry.py`. Choose a unique
canonical ID and root-condition key, the disposition, complete methodology,
the exact executor class, and whether flow analysis is required. Never create a
second control for the same root condition.

Then register the executor through
`amazon_connect_assessment/checks/registration.py` and its domain registration
function:

```python
from .my_checks import register_my_checks


def register_all_checks(registry, pillars=None, skip_flow_analysis=False):
    # Existing registrations...
    register_my_checks(registry)
```

```python
def register_my_checks(registry):
    registry.register_check(MyNewCheck())
```

`AtomicControlRegistry.hydrate_base_checks()` verifies exact catalog coverage,
pillar, severity, and executor identity. `CheckRegistry.get_selected_controls()`
is the unified execution plan used by listing and filtering. Journey-backed
controls use the same catalog but are emitted by
`journey.journey_scorer.generate_journey_findings()`.

### 3. Write tests

```python
# tests/test_my_checks.py
from unittest.mock import Mock
from amazon_connect_assessment.checks.my_checks import MyNewCheck
from amazon_connect_assessment.models import CheckStatus


def test_passes_when_compliant(make_check_context):
    ctx = make_check_context()
    ctx.aws_client_factory.get_connect_client.return_value.describe_instance_attribute\
        .return_value = {"Attribute": {"Value": "true"}}

    result = MyNewCheck().execute(ctx)

    assert result.status == CheckStatus.PASS


def test_fails_when_not_compliant(make_check_context):
    ctx = make_check_context()
    ctx.aws_client_factory.get_connect_client.return_value.describe_instance_attribute\
        .return_value = {"Attribute": {"Value": "false"}}

    result = MyNewCheck().execute(ctx)

    assert result.status == CheckStatus.FAIL
    assert "specific description" in result.description.lower()
```

Use `make_check_context` from `conftest.py` — it builds a `CheckContext` with sensible defaults and accepts overrides.

For AWS API mocking, use `moto`:

```python
from moto import mock_aws
import boto3

@mock_aws
def test_with_real_connect_api():
    # set up moto resources
    conn = boto3.client("connect", region_name="us-east-1")
    # ... create moto resources ...
    # run check
```

### 4. Update documentation

Update the curated `docs/check-catalog.md` row and any affected user guidance.
`DocsGenerator` consumes `CheckRegistry.get_selected_controls()` and can create
derived catalogs containing Journey-backed controls, disposition, root
condition, and methodology. Do not use it to overwrite the curated catalog.

Update `tests/test_documentation_consistency.py` when an approved catalog change
alters the exact canonical IDs or totals. Regenerate the deterministic sample
through `python scripts/generate_sample_report.py`; do not hand-edit the HTML.

---

## Project architecture

```
amazon_connect_assessment/
├── cli.py                    # Entry point — argument parsing, component wiring
├── engine.py                 # Orchestrates discovery → analysis → checks → results
├── parallel_engine.py        # Parallel execution (default, extends engine.py)
├── aws_client_factory.py     # boto3 session management, credential handling
├── models.py                 # Dataclasses: Finding, ConnectInstance, AssessmentResult, etc.
├── score_policy.py           # Shared disposition-aware scored-control policy
├── report_generator.py       # JSON/CSV plus self-contained Cloudscape HTML data contract
├── network_resilience.py     # Retry logic, exponential backoff, rate limit detection
├── logging_config.py         # Structured logging setup
│
├── analyzers/                # Collect raw data from AWS APIs into ConnectInstance
│   ├── base.py               # BaseAnalyzer with safe_analyze()
│   ├── connect_instance_analyzer.py
│   ├── contact_flow_analyzer.py
│   ├── queue_analyzer.py
│   ├── security_profile_analyzer.py
│   └── integration_analyzer.py
│
├── checks/                   # Assessment logic — one file per domain
│   ├── base.py               # BaseCheck, CheckContext, create_finding(), skipped_for_access_denied()
│   ├── control_registry.py   # Immutable 64-control identity, disposition, and methodology catalog
│   ├── registry.py           # BaseCheck executors plus unified selected-control view
│   ├── registration.py       # register_all_checks() — central loader and AND-filtered selector
│   ├── mvp_checks.py         # 5 original MVP checks + register_priority_checks()
│   ├── security_checks.py / security_deep_checks.py / contact_flow_security_checks.py
│   ├── ai_agent_security_checks.py
│   ├── acxd_checks.py          # Connect-side Agentic CX handoff, error-route, and escalation evidence
│   ├── resilience_advanced_checks.py  # resilience_checks.py was removed — see its module docstring history
│   ├── cost_optimization_checks.py / cost_intelligence_checks.py / cost_containment_checks.py
│   ├── operational_excellence_checks.py
│   ├── performance_efficiency_checks.py
│   └── mvp_remediation_enricher.py  # Enriches MVP findings with structured remediation
│
├── parsers/                  # Contact flow graph analysis
│   ├── contact_flow_parser.py   # Parses flow JSON into FlowAction / FlowTransition
│   ├── flow_graph.py            # DFS, cycle detection, reachability
│   ├── flow_complexity.py       # Complexity scoring
│   └── flow_patterns.py        # Pattern detection (auth, personalization, transfer)
│
├── journey/                  # Caller Journey Mapping — discovery experience
│   ├── __init__.py           # run_journey_mapping() — pipeline orchestrator
│   ├── models.py             # PhoneNumberEntry, SuperGraph, JourneyPath, JourneyScore
│   ├── topology.py           # Phone number → flow resolution, tier classification
│   ├── super_graph.py        # Stitches flows at transfer edges into instance-wide graph
│   ├── path_enumerator.py    # Bounded iterative DFS, 5000 paths per instance
│   └── journey_scorer.py     # Security/CX/cost scoring per path + finding generation
│
├── report/
│   ├── asff_export.py        # AWS Security Finding Format for Security Hub
│   ├── findings_diff.py      # Cross-run comparison
│   ├── posture_roadmap.py    # Roadmap generation
│   └── s3_publisher.py       # Optional upload of reports to an S3 bucket (--s3-output)
│
└── templates/                # Built assets and thin self-contained report shell
    ├── html/assessment_report.html
    ├── app/report-app.js
    ├── app/report-app.css
    └── assets/amazon-connect.svg

frontend/                     # AWS Samples React/Cloudscape report source
├── src/                      # Cloudscape views and report-data contract
├── test/                     # Node contract and export tests
└── build.mjs                 # esbuild bundle → templates/app/

cloudformation/
└── AmazonConnectSelfAssessmentPolicy.yaml # Deploy to grant your account the required IAM permissions

tests/                        # pytest suite (moto for AWS mocking)
config/                       # assessment_config.yaml template
docs/                         # This file and companions
```

### Data flow

```
Repository .venv
    └── python -m amazon_connect_assessment.cli (or .venv console entry point)
            ↓
       CLI args + config file
            ↓
       AWSClientFactory (resolved credentials, region, resilient boto3 clients)
            ↓
       AssessmentEngine.run_assessment()
            ├── ListInstances in the current account and one selected region
            ├── optional --instance-id run filter; otherwise assess every discovered instance
            ├── analyzers populate flows, queues, users, integrations, and related data
            ├── selected BaseCheck controls emit one outcome per selected control/instance
            │     └── acxd_checks.py reuses parsed flow data for Connect-side ACXD evidence
            └── Journey executor emits one aggregate outcome per selected Journey control/instance
                  ├── phone numbers → flow topology → bounded paths
                  └── authentication, containment, scope, and dead-end evidence
            ↓
       AssessmentResult + disposition-aware score policy
            ├── JSON / CSV / ASFF exporters use the complete run result
            └── ReportGenerator builds the Python-owned report-data contract
                    ↓
               self-contained HTML embeds report-data + committed UI bundle
                    ↓
               React/Cloudscape viewer
                    ├── all-instance or one-instance report scope
                    ├── exact metric/chart → findings-table filter requests
                    ├── table/card evidence selected from container width
                    ├── full unscoped report JSON and all-instance findings CSV
                    └── print/save-as-PDF for every finding in the current instance scope
```

The report-wide instance selector recomputes summaries, charts,
recommendations, journey entries, and findings for the chosen instance. Metric
and chart interactions send these exact property-filter queries to the findings
table:

| Interaction | Findings query |
| --- | --- |
| Total records or Connect instances | Clear all property filters. |
| Control posture | `score_classification=scored_pass OR scored_fail`. |
| Failed controls or severity index | `score_classification=scored_fail`. |
| Unevaluated controls | `score_classification=unevaluated_control`. |
| Not applicable | `score_classification=not_applicable`. |
| Manual-review candidates | `status=fail AND disposition=manual_review`. |
| All manual-review records | `disposition=manual_review`. |
| Informational records | `disposition=informational`. |
| Status donut | The selected segment's score classification, or `disposition=manual_review/informational AND score_classification=non_scoring`. |
| Failed-severity bar | `status=fail AND disposition=control AND severity=<selected severity>`. |
| Pillar stack | The selected stack semantics above plus `pillarLabel=<selected pillar>`. |

Every drill-down uses the current instance-scoped dataset, switches the findings
table to the All pillar tab, replaces the table query, and scrolls the table
into view.

Evidence rendering is adaptive. Structured records use a Cloudscape table when
the container width is at least `max(320px, column_count × 160px)` and cards
when it is narrower. A resize observer updates the choice as the details panel
changes width. Print rendering uses complete, unabridged descriptions,
methodology, remediation or review actions, and evidence values.

Export scope is deliberate. Top-level HTML report JSON and CSV actions export
the complete embedded run, independent of the current instance selector and
findings filter. Print/save-as-PDF includes all findings in the current instance
scope, independent of the on-screen findings filter and pagination. Backend
JSON and CSV files likewise contain the complete CLI run result; an
`--instance-id` run is already single-instance before export.

---

## CI pipeline

GitHub Actions runs on every push and PR to `main`:

- **Test** — pytest on Python 3.12
- **Lint** — `ruff check` (lint + import order) and `ruff format --check`
- **Type check** — mypy
- **Security audit** — pip-audit on dependencies

See `.github/workflows/ci.yml` for the full definition.

---

## Release process

1. Update `__version__` in `amazon_connect_assessment/__init__.py` and `pyproject.toml`
2. Run the full test suite: `pytest`
3. Commit: `git commit -m "Release v0.x.0"`
4. Tag: `git tag v0.x.0 && git push origin v0.x.0`
