"""
Tests for the HTML report generator.

This module tests the ReportGenerator class functionality including
HTML generation, template rendering, and interactive features.
"""

import json
import os
import tempfile
from datetime import datetime
from unittest.mock import patch

import pytest

from amazon_connect_assessment.models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report_generator import ReportGenerator


def _report_data(html_content: str) -> dict:
    """Parse the JSON data island the Cloudscape report UI renders from."""
    start_tag = '<script id="report-data" type="application/json">'
    start = html_content.index(start_tag) + len(start_tag)
    end = html_content.index("</script>", start)
    return json.loads(html_content[start:end])


@pytest.fixture
def sample_assessment_result():
    """Create a sample assessment result for testing."""

    # Create sample Connect instance
    instance = ConnectInstance(
        instance_id="test-instance-123",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance-123",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        instance_alias="test-instance",
        status="ACTIVE",
    )

    # Create sample findings
    findings = [
        Finding(
            check_id="SEC-001",
            check_name="Test Security Check",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Test security finding description",
            remediation="Test remediation guidance",
            evidence={"test_key": "test_value"},
            timestamp=datetime.now(),
        ),
        Finding(
            check_id="RES-001",
            check_name="Test Resilience Check",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Test resilience finding description",
            remediation="Configuration is compliant",
            evidence={},
            timestamp=datetime.now(),
        ),
    ]

    # Create summary
    summary = AssessmentSummary(
        total_checks=2,
        passed_checks=1,
        failed_checks=1,
        error_checks=0,
        skipped_checks=0,
        critical_findings=1,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )

    # Create metadata
    metadata = AssessmentMetadata(
        tool_version="0.1.0",
        execution_time_seconds=30.5,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        execution_environment="Test Environment",
        python_version="3.12.7",
    )

    # Create assessment result
    return AssessmentResult(
        assessment_id="test-assessment-123",
        timestamp=datetime.now(),
        account_id="123456789012",
        region="us-east-1",
        instances=[instance],
        findings=findings,
        summary=summary,
        metadata=metadata,
        execution_errors=[],
    )


class TestReportGenerator:
    """Test ReportGenerator functionality."""

    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization."""
        generator = ReportGenerator()
        assert generator is not None
        assert generator.template_env is not None

    def test_filename_template_rejects_paths(self, sample_assessment_result):
        generator = ReportGenerator()

        with pytest.raises(ValueError, match="filename, not a path"):
            generator._generate_filename(
                "../../outside/report",
                sample_assessment_result,
                "json",
            )

    def test_generate_html_report_basic(self, sample_assessment_result):
        """Test basic HTML report generation."""
        generator = ReportGenerator()

        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=False
        )

        # Verify HTML content contains expected elements
        assert "<!DOCTYPE html>" in html_content
        assert "Amazon Connect Assessment Tool Report" in html_content
        data = _report_data(html_content)
        assert data["schema_version"] == 1
        assert data["assessment"]["id"] == sample_assessment_result.assessment_id
        assert data["assessment"]["account_id"] == sample_assessment_result.account_id
        assert {f["check_name"] for f in data["findings"]} == {
            "Test Security Check",
            "Test Resilience Check",
        }
        assert data["raw_data"] is None

    def test_html_report_is_self_contained(self, sample_assessment_result):
        """The report must work offline: no external stylesheet, script, or font fetches."""
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)

        assert "<link" not in html_content
        assert "<script src" not in html_content
        assert "cdn." not in html_content
        assert "fonts.googleapis.com" not in html_content

    def test_finding_view_carries_markdown_remediation_and_evidence(self, sample_assessment_result):
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        finding = next(
            f for f in _report_data(html_content)["findings"] if f["check_id"] == "SEC-001"
        )

        assert finding["severity"] == "critical"
        assert finding["status"] == "fail"
        assert finding["pillar"] == "security"
        assert finding["description_html"] == "<p>Test security finding description</p>\n"
        assert finding["remediation_html"] == "<p>Test remediation guidance</p>\n"
        assert finding["structured_remediation"] is None
        assert finding["evidence"]["pairs"] == [
            {"label": "Test key", "value": {"text": "test_value", "kind": "text"}}
        ]
        assert json.loads(finding["evidence_json"]) == {"test_key": "test_value"}

    def test_structured_remediation_is_serialized_with_safe_urls(self, sample_assessment_result):
        from amazon_connect_assessment.models import (
            Remediation,
            RemediationReference,
            RemediationStep,
        )

        sample_assessment_result.findings[0].structured_remediation = Remediation(
            summary="Enable encryption",
            steps=[
                RemediationStep(1, "Run **this**", command="aws kms create-key", console_path="KMS")
            ],
            target_resources=["bucket-a"],
            references=[
                RemediationReference("Docs", "https://docs.aws.amazon.com/connect/"),
                RemediationReference("Evil", "javascript:alert(1)"),
            ],
            applies_if="Recordings are enabled",
        )

        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        finding = next(
            f for f in _report_data(html_content)["findings"] if f["check_id"] == "SEC-001"
        )
        rem = finding["structured_remediation"]

        assert finding["remediation_html"] == ""
        assert rem["summary"] == "Enable encryption"
        assert rem["steps"][0]["instruction_html"] == "<p>Run <strong>this</strong></p>\n"
        assert rem["steps"][0]["command"] == "aws kms create-key"
        assert rem["steps"][0]["console_path"] == "KMS"
        assert rem["target_resources"] == ["bucket-a"]
        assert rem["applies_if"] == "Recordings are enabled"
        assert [r["url"] for r in rem["references"]] == [
            "https://docs.aws.amazon.com/connect/",
            "#",
        ]

    def test_findings_are_ordered_failed_first_by_severity_within_pillar(
        self, sample_assessment_result
    ):
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        findings = _report_data(html_content)["findings"]

        # Pillar enum order (resilience before security), then failed-first.
        assert [f["check_id"] for f in findings] == ["RES-001", "SEC-001"]
        assert [f["key"] for f in findings] == ["0", "1"]

    def test_default_filter_shows_failed_findings(self, sample_assessment_result):
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        filters = _report_data(html_content)["filters"]

        assert filters["default_status"] == "fail"
        assert filters["default_severity"] == "critical"

    def test_execution_errors_are_surfaced(self, sample_assessment_result):
        sample_assessment_result.execution_errors = ["Throttled calling ListQueues"]

        html_content = ReportGenerator().generate_html_report(sample_assessment_result)

        assert _report_data(html_content)["execution_errors"] == ["Throttled calling ListQueues"]

    def test_generate_json_report_includes_journey_map_data(
        self, sample_assessment_result, tmp_path
    ):
        sample_assessment_result.journey_map_entries = [
            {
                "instance_id": "test-instance-123",
                "phone_number": "+18005551234",
                "flow_id": "flow-1",
                "mermaid_diagram": "flowchart LR",
            }
        ]
        sample_assessment_result.journey_map_status = {
            "reason": "no_phone_numbers",
            "message": "No inbound phone numbers were found.",
            "hint": "Assign a phone number to a contact flow.",
        }

        path = ReportGenerator().generate_json_report(sample_assessment_result, str(tmp_path))

        with open(path, encoding="utf-8") as report_file:
            report_data = json.load(report_file)

        assert report_data["journey_map_entries"] == sample_assessment_result.journey_map_entries
        assert report_data["journey_map_status"] == sample_assessment_result.journey_map_status

    def test_html_report_resource_id_shows_instance_alias(self, sample_assessment_result):
        """
        Regression test: the "Resource ID" line in each finding card used
        to render only the raw instance UUID, with no way to tell which
        instance that was without cross-referencing the executive
        summary. It should now show the friendly alias alongside the
        UUID, matching ConnectInstance.display_name's format.
        """
        generator = ReportGenerator()
        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=False
        )
        instance = sample_assessment_result.instances[0]
        assert instance.instance_alias == "test-instance"
        finding = _report_data(html_content)["findings"][0]
        assert finding["resource_label"] == f"'{instance.instance_alias}' ({instance.instance_id})"
        assert finding["instance"] == instance.instance_alias

    def test_instance_label_filter_falls_back_to_bare_id(self):
        """No alias known for a UUID -> render the bare UUID, not 'None (uuid)'."""
        label = ReportGenerator._render_instance_label("unknown-uuid", {})
        assert label == "unknown-uuid"

    def test_instance_label_filter_uses_alias_when_present(self):
        label = ReportGenerator._render_instance_label("abc-123", {"abc-123": "prod-cc"})
        assert label == "'prod-cc' (abc-123)"

    def test_generate_html_report_with_raw_data(self, sample_assessment_result):
        """Test HTML report generation with raw data included."""
        generator = ReportGenerator()

        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=True
        )

        # Verify raw data is included as a JSON document
        raw = json.loads(_report_data(html_content)["raw_data"])
        assert raw["assessment_id"] == sample_assessment_result.assessment_id
        assert raw["findings"][0]["check_id"] == "SEC-001"

    def test_generate_csv_report_includes_instance_alias(self, sample_assessment_result):
        """
        Regression test: same alias-visibility gap as the HTML report
        applied to CSV export — the "Instance ID" column had the raw UUID
        with no alias anywhere in the row.
        """
        import csv

        generator = ReportGenerator()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = generator.generate_csv_report(sample_assessment_result, temp_dir)
            with open(output_path, newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))

        headers = rows[0]
        assert "Instance Alias" in headers
        alias_idx = headers.index("Instance Alias")
        instance_id_idx = headers.index("Instance ID")
        instance = sample_assessment_result.instances[0]
        for row in rows[1:]:
            assert row[instance_id_idx] == instance.instance_id
            assert row[alias_idx] == instance.instance_alias

    def test_generate_html_report_with_file_output(self, sample_assessment_result):
        """Test HTML report generation with file output."""
        generator = ReportGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test_report.html")

            html_content = generator.generate_html_report(
                assessment_result=sample_assessment_result,
                output_path=output_path,
                include_raw_data=False,
            )

            # Verify file was created
            assert os.path.exists(output_path)

            # Verify file content matches returned content
            with open(output_path, "r", encoding="utf-8") as f:
                file_content = f.read()

            assert file_content == html_content

    def test_summary_statistics_generation(self, sample_assessment_result):
        """Test summary statistics generation."""
        generator = ReportGenerator()

        stats = generator._generate_summary_statistics(sample_assessment_result)

        assert stats["total_checks"] == 2
        assert stats["registered_checks"] == 2
        assert stats["journey_findings"] == 0
        assert stats["pass_rate"] == 50.0  # 1 passed out of 2
        assert stats["status_breakdown"]["passed"] == 1
        assert stats["status_breakdown"]["failed"] == 1
        assert stats["severity_breakdown"]["critical"] == 1
        assert stats["has_critical_issues"] is True

    def test_risk_score_calculation(self, sample_assessment_result):
        """Test risk score calculation."""
        generator = ReportGenerator()

        # Test with critical finding
        risk_score = generator._calculate_risk_score(sample_assessment_result.findings)
        assert risk_score > 0  # Should have some risk due to critical finding

        # Test with no failed findings
        passed_findings = [
            f for f in sample_assessment_result.findings if f.status == CheckStatus.PASS
        ]
        risk_score_no_failures = generator._calculate_risk_score(passed_findings)
        assert risk_score_no_failures == 0

    def test_findings_organization_by_pillar(self, sample_assessment_result):
        """Test findings organization by pillar."""
        generator = ReportGenerator()

        organized = generator._organize_findings_by_pillar(sample_assessment_result.findings)

        assert "security" in organized
        assert "resilience" in organized
        assert len(organized["security"]) == 1
        assert len(organized["resilience"]) == 1
        assert organized["security"][0].check_name == "Test Security Check"
        assert organized["resilience"][0].check_name == "Test Resilience Check"

    def test_executive_summary_creation(self, sample_assessment_result):
        """Test executive summary creation."""
        generator = ReportGenerator()

        summary = generator._create_executive_summary(sample_assessment_result)

        assert "insights" in summary
        assert "recommendations" in summary
        assert "assessment_date" in summary
        assert "instances_count" in summary
        assert "total_findings" in summary

        # Should have insights about critical findings
        insights = summary["insights"]
        critical_insight = next((i for i in insights if i["type"] == "critical"), None)
        assert critical_insight is not None

    def test_default_filters(self, sample_assessment_result):
        """Default filter is failed findings at the highest failing severity."""
        generator = ReportGenerator()

        assert generator._default_filters(sample_assessment_result.findings) == {
            "default_severity": "critical",
            "default_status": "fail",
        }
        passing = [f for f in sample_assessment_result.findings if f.status == CheckStatus.PASS]
        assert generator._default_filters(passing) == {
            "default_severity": "all",
            "default_status": "all",
        }

    def test_journey_finding_instance_comes_from_evidence(self, sample_assessment_result):
        """Per-number journey findings group under their instance, not the phone number."""
        journey_finding = Finding(
            check_id="journey-sec-001",
            check_name="Journey Reaches Agent Queue Without Authentication",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            resource_id="+15555550100",
            resource_type="PhoneNumberJourney",
            description="d",
            remediation="r",
            evidence={"phone_number": "+1555***0100", "instance_id": "test-instance-123"},
            timestamp=datetime.now(),
        )
        sample_assessment_result.findings.append(journey_finding)
        generator = ReportGenerator()

        data = generator._build_report_data(sample_assessment_result, include_raw_data=False)
        view = next(f for f in data["findings"] if f["check_id"] == "journey-sec-001")
        assert view["instance"] == "test-instance"

        with tempfile.TemporaryDirectory() as tmp:
            path = generator.generate_csv_report(sample_assessment_result, tmp)
            with open(path, encoding="utf-8") as fh:
                row = next(line for line in fh if "journey-sec-001" in line)
        assert "test-instance-123,test-instance" in row

    def test_template_filters(self, sample_assessment_result):
        """Test custom template filters."""
        generator = ReportGenerator()

        # Test datetime formatting
        dt = datetime(2023, 1, 15, 10, 30, 45)
        formatted = generator._format_datetime(dt)
        assert "2023-01-15 10:30:45 UTC" in formatted

        # Test duration formatting
        assert generator._format_duration(30.5) == "30.5s"
        assert generator._format_duration(90) == "1.5m"
        assert generator._format_duration(3700) == "1.0h"


class TestMarkdownFilter:
    """
    Finding descriptions are authored in markdown. The template runs
    them through ``_render_markdown`` and marks the result safe — so
    that filter has to (a) produce readable HTML for the paragraph +
    list + code-block subset we use, and (b) never emit raw HTML from
    the source string, because untrusted flow content (queue names,
    prompt text) gets interpolated into these descriptions.
    """

    def test_paragraph_break_produces_paragraph_tags(self):
        out = ReportGenerator._render_markdown("First para.\n\nSecond para.")
        assert "<p>First para.</p>" in out
        assert "<p>Second para.</p>" in out

    def test_bullet_list_renders_ul(self):
        src = "Intro line.\n\n* item one\n* item two\n* item three\n"
        out = ReportGenerator._render_markdown(src)
        assert "<ul>" in out
        assert "<li>item one</li>" in out
        assert "<li>item three</li>" in out

    def test_numbered_list_renders_ol(self):
        src = "1. first\n2. second\n3. third\n"
        out = ReportGenerator._render_markdown(src)
        assert "<ol>" in out
        assert "<li>first</li>" in out

    def test_fenced_code_block_renders_pre_code(self):
        src = "Before.\n\n```\nsome preformatted text\n```\n"
        out = ReportGenerator._render_markdown(src)
        assert "<pre><code>" in out
        assert "some preformatted text" in out

    def test_inline_code_renders_code_tags(self):
        out = ReportGenerator._render_markdown("Set `$.Attributes.foo` to something.")
        assert "<code>$.Attributes.foo</code>" in out

    def test_bold_renders_strong(self):
        out = ReportGenerator._render_markdown("This is **important** text.")
        assert "<strong>important</strong>" in out

    def test_raw_html_in_source_is_escaped(self):
        # Untrusted flow content might contain angle brackets or a
        # <script> tag — markdown-it-py with html=False must render
        # those as text, never as active HTML.
        malicious = "Look at <script>alert(1)</script> and <img src=x onerror=alert(1)>."
        out = ReportGenerator._render_markdown(malicious)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out
        assert "onerror=" not in out or "&lt;img" in out  # tag is escaped

    @pytest.mark.parametrize(
        "source",
        [
            "[x](//evil.test)",
            "[x](ftp://example.com)",
            "[x](/relative/path)",
            "[x](javascript:alert(1))",
            "[x](JaVaScRiPt:alert(1))",
            "[x](data:text/html,hi)",
            "<ftp://example.com>",
            "[ref]\n\n[ref]: //evil.test",
        ],
    )
    def test_disallowed_link_targets_render_as_text(self, source):
        # Markdown HTML is injected as live markup, so only absolute
        # http(s)/mailto links may become anchors.
        out = ReportGenerator._render_markdown(source)
        assert "<a " not in out
        assert "href=" not in out

    @pytest.mark.parametrize(
        "source,href",
        [
            (
                "[docs](https://docs.aws.amazon.com/connect/)",
                "https://docs.aws.amazon.com/connect/",
            ),
            ("<https://example.com>", "https://example.com"),
            ("[mail](mailto:ops@example.com)", "mailto:ops@example.com"),
        ],
    )
    def test_allowed_links_open_in_new_tab(self, source, href):
        out = ReportGenerator._render_markdown(source)
        assert f'href="{href}"' in out
        assert 'target="_blank"' in out
        assert 'rel="noopener noreferrer"' in out

    def test_images_render_as_alt_text_without_fetching(self):
        # The report must stay offline and never load remote content.
        out = ReportGenerator._render_markdown("![diagram <b>x</b>](https://example.com/x.png)")
        assert "<img" not in out
        assert "example.com" not in out
        assert "diagram" in out

    def test_ssml_in_code_block_survives_intact(self):
        # A common pattern in the injection-check description shows an
        # SSML injection example inside a fenced code block. The angle
        # brackets should render as escaped text so the reader sees
        # them, and no HTML actually enters the page.
        src = "```\n<speak>Hello</speak>\n```\n"
        out = ReportGenerator._render_markdown(src)
        assert "&lt;speak&gt;" in out
        assert "<speak>" not in out

    def test_none_and_empty_pass_through(self):
        assert ReportGenerator._render_markdown(None) == ""
        assert ReportGenerator._render_markdown("") == ""

    def test_non_string_input_coerced_to_string(self):
        # Defensive: numeric or None-ish inputs shouldn't crash the
        # template render — a check that stashed an int in the wrong
        # field is a bug, but not a report-breaking one.
        out = ReportGenerator._render_markdown(42)
        assert "42" in out

    def test_parser_is_cached_across_calls(self):
        ReportGenerator._MARKDOWN_PARSER = None
        first = ReportGenerator._get_markdown_parser()
        second = ReportGenerator._get_markdown_parser()
        assert first is second


class TestEvidenceView:
    """
    Evidence dicts stashed on findings are structured by ``_evidence_view``
    for the report UI: scalars become key-value pairs, list-of-dicts keys
    become tables, list-of-scalars become lists, nested dicts become
    sections, and ARN / long values are abbreviated with the full value kept.
    """

    def test_scalar_keys_render_as_pairs(self):
        view = ReportGenerator._evidence_view({"hardcoded_count": 10, "flows_analyzed": 27})
        assert view["pairs"] == [
            {"label": "Hardcoded count", "value": {"text": "10", "kind": "number"}},
            {"label": "Flows analyzed", "value": {"text": "27", "kind": "number"}},
        ]
        assert view["tables"] == view["lists"] == view["sections"] == []

    def test_list_of_dicts_renders_as_table(self):
        view = ReportGenerator._evidence_view(
            {
                "hardcoded_details": [
                    {"flow": "IVR", "action_type": "TransferToFlow"},
                    {"flow": "Sales", "action_type": "TransferToFlow", "extra": 1},
                ]
            }
        )
        table = view["tables"][0]
        assert table["title"] == "Hardcoded details"
        # Column order = first row's keys, then keys later rows introduce.
        assert table["columns"] == ["Flow", "Action type", "Extra"]
        assert [row[0]["text"] for row in table["rows"]] == ["IVR", "Sales"]
        assert table["rows"][0][2] == {"text": "", "kind": "text"}

    def test_arn_values_are_abbreviated_with_full_value(self):
        arn = "arn:aws:connect:us-east-1:819205311151:instance/6b050445-2dee-4475-9f78-399ad0a69aac"
        cell = ReportGenerator._evidence_view({"instance": arn})["pairs"][0]["value"]
        assert cell["kind"] == "arn"
        assert cell["full"] == arn
        assert cell["text"].startswith("connect:")
        assert len(cell["text"]) < len(arn)

    def test_long_strings_are_abbreviated(self):
        cell = ReportGenerator._evidence_view({"prompt": "x" * 150})["pairs"][0]["value"]
        assert cell["text"] == "x" * 99 + "\u2026"
        assert cell["full"] == "x" * 150

    def test_none_and_empty_evidence_pass_through(self):
        assert ReportGenerator._evidence_view(None) is None
        assert ReportGenerator._evidence_view({}) is None

    def test_scalar_kinds(self):
        pairs = ReportGenerator._evidence_view(
            {"auth_enabled": True, "encrypted": False, "queue": None, "ids": [1, "a"]}
        )["pairs"]
        assert [p["value"] for p in pairs[:3]] == [
            {"text": "true", "kind": "bool"},
            {"text": "false", "kind": "bool"},
            {"text": "\u2014", "kind": "null"},
        ]

    def test_list_of_scalars_renders_as_list(self):
        view = ReportGenerator._evidence_view({"queues": ["general", "returns"], "empty": []})
        assert view["lists"] == [
            {
                "title": "Queues",
                "items": [
                    {"text": "general", "kind": "text"},
                    {"text": "returns", "kind": "text"},
                ],
            },
            {"title": "Empty", "items": []},
        ]

    def test_nested_dict_renders_as_section(self):
        view = ReportGenerator._evidence_view(
            {
                "flows_analyzed": 10,
                "analysis_limits": {"paths_per_flow": 100, "route_states": 20000},
            }
        )
        section = view["sections"][0]
        assert section["title"] == "Analysis limits"
        assert section["block"]["pairs"][0] == {
            "label": "Paths per flow",
            "value": {"text": "100", "kind": "number"},
        }

    def test_deep_nesting_falls_back_to_json(self):
        deep: dict = {"leaf": 1}
        for _ in range(10):
            deep = {"level": deep}
        view = ReportGenerator._evidence_view(deep)
        block = view
        for _ in range(ReportGenerator._EVIDENCE_MAX_DEPTH + 1):
            block = block["sections"][0]["block"]
        assert '"leaf": 1' in block["fallback"]

    def test_non_dict_evidence_falls_back_to_pretty_json(self):
        # A check may (mistakenly) stash a list at the top level;
        # the view should not crash, but produce readable JSON.
        view = ReportGenerator._evidence_view([1, 2, 3])
        assert json.loads(view["fallback"]) == [1, 2, 3]

    def test_html_in_values_reaches_the_ui_as_text(self):
        # Evidence is rendered as text by React, so markup stays inert
        # data — and the data island escapes it so it can't end the script.
        html_content_value = "<script>alert(1)</script>"
        view = ReportGenerator._evidence_view({"note": html_content_value})
        assert view["pairs"][0]["value"]["text"] == html_content_value
        island = ReportGenerator._json_for_script(view)
        assert "<script>" not in island
        assert json.loads(island)["pairs"][0]["value"]["text"] == html_content_value

    def test_report_ui_bundle_is_embedded(self, sample_assessment_result):
        generator = ReportGenerator()

        css = generator._load_app_asset("report-app.css")
        js = generator._load_app_asset("report-app.js")
        html_content = generator.generate_html_report(sample_assessment_result)

        # Cloudscape global styles + components are in the bundle.
        assert "Open Sans" in css
        assert "report-data" in js
        # A missing/corrupt data island surfaces an error instead of a blank page.
        assert "This report could not be displayed" in js
        assert "</script" not in js.lower()
        assert "</style" not in css.lower()
        assert js in html_content
        assert css in html_content

    def test_missing_bundle_raises_actionable_error(self, tmp_path):
        generator = ReportGenerator()
        generator._APP_DIR = tmp_path  # type: ignore[misc]

        with pytest.raises(FileNotFoundError, match="npm ci && npm run build"):
            generator._load_app_asset("report-app.js")

    def test_inlined_asset_cannot_close_its_element(self, tmp_path):
        generator = ReportGenerator()
        generator._APP_DIR = tmp_path  # type: ignore[misc]
        (tmp_path / "report-app.js").write_text('var s = "</ScRiPt><b>";', encoding="utf-8")
        (tmp_path / "report-app.css").write_text("a{content:'</STYLE>'}", encoding="utf-8")

        assert generator._load_app_asset("report-app.js") == 'var s = "<\\/ScRiPt><b>";'
        assert generator._load_app_asset("report-app.css") == "a{content:'<\\/STYLE>'}"

    def test_save_report_with_subdirectory(self, sample_assessment_result):
        """Test saving report with subdirectory creation."""
        generator = ReportGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create path with subdirectory
            output_path = os.path.join(temp_dir, "reports", "subdir", "test_report.html")

            generator.generate_html_report(
                assessment_result=sample_assessment_result,
                output_path=output_path,
                include_raw_data=False,
            )

            # Verify file and directories were created
            assert os.path.exists(output_path)
            assert os.path.isdir(os.path.join(temp_dir, "reports", "subdir"))

    def test_error_handling_invalid_output_path(self, sample_assessment_result):
        """Test error handling for invalid output path.

        Uses a mock for os.makedirs to force the failure deterministically —
        relying on a real filesystem path (e.g. "/invalid/...") is not
        portable: a process running as root (as CI containers typically do)
        can create that directory, so the test would pass locally but fail
        in CI (or vice versa).
        """
        generator = ReportGenerator()
        invalid_path = "/invalid/path/that/does/not/exist/report.html"

        with patch("os.makedirs", side_effect=OSError("Permission denied")):
            with pytest.raises(Exception):
                generator.generate_html_report(
                    assessment_result=sample_assessment_result,
                    output_path=invalid_path,
                    include_raw_data=False,
                )


class TestJourneyMapExportReportIntegration:
    @staticmethod
    def _entry(drawio_content: str = "<mxfile><diagram/></mxfile>"):
        return {
            "instance_id": "test-instance-123",
            "instance_display_name": "test-instance",
            "phone_number": "+18005551212",
            "phone_type": "TOLL_FREE",
            "phone_country_code": "US",
            "phone_description": "Main line",
            "flow_id": "flow-ivr",
            "flow_name": "Main IVR",
            "flow_type": "CONTACT_FLOW",
            "diagram_html": '<div class="jm-canvas" style="width:100px;height:100px;"></div>',
            "diagram_model": {"nodes": {}, "edges": {}, "primary_path": []},
            "exports": {
                "schema_version": 1,
                "formats": {
                    "svg": {
                        "content": '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
                        "media_type": "image/svg+xml;charset=utf-8",
                        "width": 100,
                        "height": 100,
                    },
                    "drawio": {
                        "content": drawio_content,
                        "media_type": "application/vnd.jgraph.mxfile;charset=utf-8",
                    },
                },
            },
        }

    def test_journey_map_json_mixed_case_script_end_tag_stays_inside_data_island(
        self, sample_assessment_result
    ):
        # Arrange
        hostile = "</ScRiPt><script>alert(1)</script>"
        sample_assessment_result.journey_map_entries = [self._entry(hostile)]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)
        island_start = html_content.index('<script id="report-data"')
        island_end = html_content.index("</script>", island_start)
        island = html_content[island_start:island_end]

        # Assert
        assert "<script" not in island[len("<script") :].lower()
        decoded = _report_data(html_content)
        assert decoded["journey"]["entries"][0]["exports"]["formats"]["drawio"]["content"] == (
            hostile
        )

    def test_journey_map_ships_full_inspector_model_but_not_legacy_markup(
        self, sample_assessment_result
    ):
        # Arrange
        entry = self._entry()
        entry["diagram_model"] = {
            "nodes": {
                "n0": {
                    "title": "System work · 2 internal actions",
                    "category": "processing",
                    "summary": "Groups internal actions.",
                    "scope": ["Looks up customer data with customer-lookup"],
                    "ai": {"technology": "Amazon Lex", "identity": "CustomerServiceBot"},
                    "is_group": True,
                    "is_entry": True,
                    "is_primary": True,
                    "actions": [
                        {"id": "lookup", "type": "InvokeLambdaFunction", "detail": "Looks up"}
                    ],
                    "absorbed_outcomes": [
                        {
                            "label": "Catch-all error route",
                            "raw_label": "NoMatchingError",
                            "route_type": "exception",
                            "transition_type": "error",
                            "meaning": "Catch-all.",
                            "source_action_id": "lookup",
                            "target_action_id": "attributes",
                        }
                    ],
                }
            },
            "edges": {},
            "primary_path": ["n0"],
            "layout": None,
        }
        sample_assessment_result.journey_map_entries = [entry]

        # Act
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        shipped = _report_data(html_content)["journey"]["entries"][0]

        # Assert — the inspector shows technical detail (actions, raw Connect
        # values, absorbed routes), so the whole model reaches the UI...
        node = shipped["diagram_model"]["nodes"]["n0"]
        assert node["actions"][0]["type"] == "InvokeLambdaFunction"
        assert node["absorbed_outcomes"][0]["raw_label"] == "NoMatchingError"
        assert node["ai"]["identity"] == "CustomerServiceBot"
        # ...while the legacy server-rendered diagram markup is not shipped twice.
        assert "diagram_html" not in shipped
        # And the UI bundle carries the inspector sections that render it.
        js = ReportGenerator()._load_app_asset("report-app.js")
        for text in (
            "Contact flow actions",
            "Routes handled inside this step",
            "Connect value",
            "Routes out",
        ):
            assert text in js

    def test_journey_map_empty_state_status_is_shipped(self, sample_assessment_result):
        sample_assessment_result.journey_map_status = {
            "reason": "no_phone_numbers",
            "message": "No inbound phone numbers were found.",
            "hint": "Claim a number.",
        }

        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        journey = _report_data(html_content)["journey"]

        assert journey["entries"] == []
        assert journey["status"]["reason"] == "no_phone_numbers"

    def test_journey_map_report_with_exports_renders_download_controls(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]

        # Act
        html_content = ReportGenerator().generate_html_report(sample_assessment_result)
        formats = _report_data(html_content)["journey"]["entries"][0]["exports"]["formats"]
        js = ReportGenerator()._load_app_asset("report-app.js")

        # Assert
        assert set(formats) == {"svg", "drawio"}
        for text in ("SVG image", "PNG image", "draw.io diagram", "caller-journey-"):
            assert text in js

    def test_journey_map_report_export_payload_is_data_not_live_markup(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)
        island_start = html_content.index('<script id="report-data"')
        island_end = html_content.index("</script>", island_start)
        island = html_content[island_start:island_end]

        # Assert
        assert "<mxfile" not in island
        assert "<svg xmlns" not in island
        assert "\\u003cmxfile" in island
        assert "\\u003csvg" in island
