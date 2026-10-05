"""
Tests for the HTML report generator.

This module tests the ReportGenerator class functionality including
HTML generation, template rendering, and interactive features.
"""

import csv
import json
import logging
import os
import sys
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
    FindingDisposition,
    FindingMethodology,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report_generator import ReportGenerator


def _cloudscape_data(html_content: str) -> dict:
    marker = '<script id="report-data" type="application/json">'
    start = html_content.index(marker) + len(marker)
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
        assert generator.template_path.is_file()

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
        assert "Amazon Connect Customer Posture Assessment Report" in html_content
        assert sample_assessment_result.assessment_id in html_content
        assert sample_assessment_result.account_id in html_content
        assert "Test Security Check" in html_content
        assert "Test Resilience Check" in html_content

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
        report_data = _cloudscape_data(html_content)
        assert report_data["findings"][0]["instance"] == "test-instance"
        assert report_data["findings"][0]["instance_id"] == instance.instance_id

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

        # Verify raw data is carried in the Cloudscape report contract.
        report_data = _cloudscape_data(html_content)
        assert report_data["raw_data"] is not None
        assert "assessment_id" in report_data["raw_data"]

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

    def test_charts_data_generation(self, sample_assessment_result):
        """Test charts data generation."""
        generator = ReportGenerator()

        charts_data = generator._generate_charts_data(sample_assessment_result)

        # Verify status distribution chart
        assert "status_distribution" in charts_data
        status_chart = charts_data["status_distribution"]
        assert "labels" in status_chart
        assert "data" in status_chart
        assert "colors" in status_chart

        # Verify severity distribution chart
        assert "severity_distribution" in charts_data
        severity_chart = charts_data["severity_distribution"]
        assert severity_chart["data"][0] == 1  # 1 critical finding

        # Verify pillar breakdown
        assert "pillar_breakdown" in charts_data
        pillar_data = charts_data["pillar_breakdown"]
        assert "security" in pillar_data
        assert "resilience" in pillar_data

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

    def test_filter_options_generation(self, sample_assessment_result):
        """Test filter options generation."""
        generator = ReportGenerator()

        # _get_filter_options takes instances too now so the report can
        # show the customer-chosen alias in the instance dropdown rather
        # than the raw UUID. Pass the fixture's instance list through.
        options = generator._get_filter_options(
            sample_assessment_result.findings,
            sample_assessment_result.instances,
        )

        assert "severities" in options
        assert "statuses" in options
        assert "pillars" in options
        assert "instances" in options

        assert "critical" in options["severities"]
        assert "high" in options["severities"]
        assert "pass" in options["statuses"]
        assert "fail" in options["statuses"]
        assert "security" in options["pillars"]
        assert "resilience" in options["pillars"]
        # Instance entries are {id, label} pairs — the UUID is the option
        # value (so filtering matches finding.resource_id), the label is
        # the friendly alias.
        for entry in options["instances"]:
            assert "id" in entry
            assert "label" in entry

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


class TestEvidenceView:
    def test_table_cells_preserve_complete_nested_values(self):
        nested_list = ["first", {"deep": ["value", {"leaf": "complete"}]}]
        nested_dict = {"routing": {"queue": "support"}, "limits": [1, 2, 3]}

        view = ReportGenerator._evidence_view(
            {
                "records": [
                    {"name": "primary", "nested_list": nested_list, "nested_dict": nested_dict}
                ]
            }
        )

        assert view is not None
        table = view["tables"][0]
        columns = table["columns"]
        row = table["rows"][0]
        list_cell = row[columns.index("Nested list")]
        dict_cell = row[columns.index("Nested dict")]
        assert json.loads(list_cell["full"]) == nested_list
        assert json.loads(dict_cell["full"]) == nested_dict

    def test_table_uses_union_of_columns_and_preserves_direct_long_value(self):
        long_value = "evidence-" + "x" * 200

        view = ReportGenerator._evidence_view(
            {"records": [{"first": long_value}, {"second": "complete second value"}]}
        )

        assert view is not None
        table = view["tables"][0]
        assert table["columns"] == ["First", "Second"]
        assert table["rows"][0][0]["full"] == long_value
        assert table["rows"][1][1]["text"] == "complete second value"

    def test_nested_section_fallback_preserves_full_json(self):
        evidence = {"level": {"level": {"level": {"level": {"level": {"leaf": [1, 2]}}}}}}

        view = ReportGenerator._evidence_view(evidence)

        assert view is not None
        block = view
        for _ in range(5):
            block = block["sections"][0]["block"]
        assert json.loads(block["fallback"]) == {"leaf": [1, 2]}


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


class TestMarkdownRendererUnavailable:
    """
    A stale environment missing markdown-it-py must not abort the report.

    By the time rendering starts the assessment has already made every AWS
    call it was going to make, so raising here would throw away the whole run
    over a text formatter. These tests pin the degraded behaviour: escaped
    plain text, one warning, and no exception.
    """

    @pytest.fixture(autouse=True)
    def _isolate_parser_cache(self):
        """Restore the class-level parser cache so other tests are unaffected."""
        saved = (ReportGenerator._MARKDOWN_PARSER, ReportGenerator._MARKDOWN_UNAVAILABLE)
        ReportGenerator._MARKDOWN_PARSER = None
        ReportGenerator._MARKDOWN_UNAVAILABLE = False
        yield
        ReportGenerator._MARKDOWN_PARSER, ReportGenerator._MARKDOWN_UNAVAILABLE = saved

    @staticmethod
    def _without_markdown_it():
        """Make ``from markdown_it import MarkdownIt`` raise ImportError."""
        return patch.dict(sys.modules, {"markdown_it": None})

    def test_parser_returns_none_instead_of_raising(self):
        with self._without_markdown_it():
            assert ReportGenerator._get_markdown_parser() is None

    def test_render_falls_back_to_paragraphs(self):
        with self._without_markdown_it():
            out = ReportGenerator._render_markdown("First para.\n\nSecond para.")
        assert out == "<p>First para.</p><p>Second para.</p>"

    def test_fallback_still_escapes_html(self):
        # The no-raw-HTML guarantee has to survive the degraded path, since
        # finding text can interpolate flow-authored strings.
        with self._without_markdown_it():
            out = ReportGenerator._render_markdown("<script>alert('xss')</script>")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_failed_import_is_not_retried(self, caplog):
        with caplog.at_level(logging.WARNING), self._without_markdown_it():
            ReportGenerator._render_markdown("one")
            ReportGenerator._render_markdown("two")
        warnings = [r for r in caplog.records if "markdown-it-py" in r.message]
        assert len(warnings) == 1

    def test_report_still_renders_without_markdown(self, sample_assessment_result):
        with self._without_markdown_it():
            html_out = ReportGenerator().generate_html_report(sample_assessment_result)
        assert "<html" in html_out.lower()


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
        serialized = generator._journey_map_entries_json(sample_assessment_result)
        decoded = json.loads(serialized)

        # Assert
        assert "</script" not in serialized.lower()
        assert "<script" not in serialized.lower()
        assert decoded[0]["exports"]["formats"]["drawio"]["content"] == hostile

    def test_journey_map_report_keeps_inspector_reader_focused_and_provenance_hidden(
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
                    "scope": [
                        "Looks up customer data with customer-lookup",
                        "Sets contact attributes",
                    ],
                    "ai": {
                        "technology": "Amazon Lex",
                        "identity": "CustomerServiceBot",
                        "subtype": "V2 bot",
                        "alias": "Production",
                    },
                    "is_group": True,
                    "is_entry": True,
                    "is_primary": True,
                    "actions": [
                        {"id": "lookup", "type": "InvokeLambdaFunction", "detail": "Looks up data"},
                        {
                            "id": "attributes",
                            "type": "SetContactAttributes",
                            "detail": "Sets attributes",
                        },
                    ],
                    "absorbed_outcomes": [
                        {
                            "label": "Catch-all error route",
                            "raw_label": "NoMatchingError",
                            "route_type": "exception",
                            "transition_type": "error",
                            "meaning": (
                                "A configured catch-all route used only if the action fails and "
                                "no specific error condition matches. This does not mean an error "
                                "was observed."
                            ),
                            "source_action_id": "lookup",
                            "source_action_type": "InvokeLambdaFunction",
                            "source_action_label": "Looks up data",
                            "target_action_id": "attributes",
                            "target_action_type": "SetContactAttributes",
                            "target_action_label": "Sets attributes",
                        }
                    ],
                }
            },
            "edges": {},
            "primary_path": ["n0"],
        }
        sample_assessment_result.journey_map_entries = [entry]
        generator = ReportGenerator()

        # Act
        serialized = generator._journey_map_entries_json(sample_assessment_result)
        decoded_route = json.loads(serialized)[0]["diagram_model"]["nodes"]["n0"][
            "absorbed_outcomes"
        ][0]
        html_content = generator.generate_html_report(sample_assessment_result)

        # Assert
        assert decoded_route["source_action_id"] == "lookup"
        assert decoded_route["source_action_label"] == "Looks up data"
        assert decoded_route["target_action_id"] == "attributes"
        assert decoded_route["target_action_label"] == "Sets attributes"
        report_data = _cloudscape_data(html_content)
        node = report_data["journey"]["entries"][0]["diagram_model"]["nodes"]["n0"]
        assert node["scope"] == [
            "Looks up customer data with customer-lookup",
            "Sets contact attributes",
        ]
        assert node["ai"]["identity"] == "CustomerServiceBot"
        assert node["is_group"] is True
        assert node["absorbed_outcomes"][0]["raw_label"] == "NoMatchingError"

    def test_journey_map_report_with_exports_renders_download_controls(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)

        # Assert
        report_data = _cloudscape_data(html_content)
        formats = report_data["journey"]["entries"][0]["exports"]["formats"]
        assert set(formats) == {"svg", "drawio"}
        assert formats["svg"]["content"].startswith("<svg")
        assert formats["drawio"]["content"].startswith("<mxfile")
        assert "Export diagram" in html_content

    def test_journey_map_report_export_payload_is_data_not_live_markup(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)
        report_data = _cloudscape_data(html_content)
        island_start = html_content.index('<script id="report-data"')
        island_end = html_content.index("</script>", island_start)
        island = html_content[island_start:island_end]

        # Assert
        formats = report_data["journey"]["entries"][0]["exports"]["formats"]
        assert formats["drawio"]["content"].startswith("<mxfile")
        assert formats["svg"]["content"].startswith("<svg")
        assert "<mxfile" not in island
        assert "<svg xmlns" not in island
        assert "\\u003cmxfile" in island
        assert "\\u003csvg" in island


def _disposition_matrix_result(sample_assessment_result, hostile_text="Methodology reason"):
    methodology = FindingMethodology(
        reason=hostile_text,
        evidence_source="Amazon Connect APIs",
        proof_limitations="Configuration does not prove operating practice",
        developer_admin_meaning="Review the configured behavior",
        verification_criteria="Confirm the approved setting and capture evidence",
        responsible_function="Security",
        primary_lens_reference="SEC-1",
    )
    instance_id = sample_assessment_result.instances[0].instance_id

    def finding(check_id, status, disposition, severity=Severity.HIGH, methodology_value=None):
        return Finding(
            check_id=check_id,
            check_name=f"Check {check_id}",
            pillar=Pillar.SECURITY,
            severity=severity,
            status=status,
            resource_id=f"resource-{check_id}",
            resource_type="ContactFlow",
            description=f"Observed {check_id}",
            remediation=f"Act on {check_id}",
            evidence={"check": check_id},
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            disposition=disposition,
            methodology=methodology_value,
            instance_id=instance_id,
        )

    sample_assessment_result.findings = [
        finding("control-pass", CheckStatus.PASS, FindingDisposition.CONTROL),
        finding(
            "control-fail",
            CheckStatus.FAIL,
            FindingDisposition.CONTROL,
            Severity.CRITICAL,
            methodology,
        ),
        finding("control-skipped", CheckStatus.SKIPPED, FindingDisposition.CONTROL),
        finding("control-error", CheckStatus.ERROR, FindingDisposition.CONTROL),
        finding("control-na", CheckStatus.NOT_APPLICABLE, FindingDisposition.CONTROL),
        finding(
            "manual-fail",
            CheckStatus.FAIL,
            FindingDisposition.MANUAL_REVIEW,
            Severity.CRITICAL,
            methodology,
        ),
        finding(
            "info-fail",
            CheckStatus.FAIL,
            FindingDisposition.INFORMATIONAL,
            Severity.CRITICAL,
            methodology,
        ),
    ]
    sample_assessment_result.summary = AssessmentSummary(
        total_checks=7,
        passed_checks=1,
        failed_checks=3,
        error_checks=1,
        skipped_checks=1,
        critical_findings=3,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
        not_applicable_checks=1,
    )
    return sample_assessment_result


def test_report_mixed_dispositions_returns_policy_consistent_statistics(sample_assessment_result):
    # Arrange
    result = _disposition_matrix_result(sample_assessment_result)
    generator = ReportGenerator()

    # Act
    stats = generator._generate_summary_statistics(result)
    executive = generator._create_executive_summary(result)

    # Assert
    assert stats["total_records"] == 7
    assert stats["scored_control_numerator"] == 1
    assert stats["scored_control_denominator"] == 2
    assert stats["scored_control_pass_rate"] == 50.0
    assert stats["scored_control_failures"] == 1
    assert stats["unevaluated_controls"] == 2
    assert stats["not_applicable_controls"] == 1
    assert stats["manual_review_findings"] == 1
    assert stats["manual_review_candidates"] == 1
    assert stats["informational_findings"] == 1
    assert stats["severity_breakdown"]["critical"] == 1
    assert executive["total_findings"] == 1
    assert executive["recommendations"][0]["findings_count"] == 1


def test_report_mixed_dispositions_produces_policy_consistent_chart_data(sample_assessment_result):
    # Arrange
    result = _disposition_matrix_result(sample_assessment_result)
    generator = ReportGenerator()

    # Act
    charts = generator._generate_charts_data(result)

    # Assert
    assert charts["status_distribution"]["data"] == [1, 1, 2, 1, 1, 1]
    assert charts["severity_distribution"]["data"] == [1, 0, 0, 0]
    security = charts["pillar_breakdown"]["security"]
    assert security["scored_control_numerator"] == 1
    assert security["scored_control_denominator"] == 2
    assert security["passed"] == 1
    assert security["failed"] == 1
    assert security["pass_rate"] == 50.0
    assert security["manual_review_candidates"] == 1


def test_report_zero_scored_controls_renders_not_scored_without_false_pass(
    sample_assessment_result,
):
    # Arrange
    result = _disposition_matrix_result(sample_assessment_result)
    result.findings = [
        finding
        for finding in result.findings
        if finding.status not in (CheckStatus.PASS, CheckStatus.FAIL)
    ]
    result.summary.total_checks = len(result.findings)
    generator = ReportGenerator()

    # Act
    stats = generator._generate_summary_statistics(result)
    charts = generator._generate_charts_data(result)
    html_content = generator.generate_html_report(result)

    # Assert
    assert stats["pass_rate"] is None
    assert stats["pass_rate_display"] == "Not scored"
    assert charts["pillar_breakdown"]["security"]["pass_rate"] is None
    report_data = _cloudscape_data(html_content)
    assert report_data["stats"]["pass_rate_display"] == "Not scored"
    assert report_data["stats"]["scored_control_numerator"] == 0
    assert report_data["stats"]["scored_control_denominator"] == 0
    assert all(insight["type"] != "success" for insight in report_data["insights"])


def test_report_json_csv_additive_contract_preserves_legacy_columns(
    sample_assessment_result, tmp_path
):
    # Arrange
    import csv

    result = _disposition_matrix_result(sample_assessment_result)
    generator = ReportGenerator()
    legacy_headers = [
        "Assessment ID",
        "Timestamp",
        "Account ID",
        "Region",
        "Instance ID",
        "Instance Alias",
        "Check ID",
        "Check Name",
        "Pillar",
        "Severity",
        "Status",
        "Resource Type",
        "Resource ID",
        "Description",
        "Remediation",
        "Remediation Targets",
        "Evidence",
    ]
    additive_headers = [
        "Disposition",
        "Reason",
        "Evidence Source",
        "Proof Limitations",
        "Developer/Admin Meaning",
        "Verification Criteria",
        "Responsible Function",
        "Primary Lens Reference",
    ]

    # Act
    json_path = generator.generate_json_report(result, str(tmp_path))
    csv_path = generator.generate_csv_report(result, str(tmp_path))
    with open(json_path, encoding="utf-8") as report_file:
        report_data = json.load(report_file)
    with open(csv_path, newline="", encoding="utf-8") as report_file:
        rows = list(csv.reader(report_file))

    # Assert
    assert rows[0] == legacy_headers + additive_headers
    assert rows[1][4] == result.instances[0].instance_id
    assert report_data["summary"]["total_records"] == 7
    assert report_data["summary"]["scored_control_numerator"] == 1
    assert report_data["summary"]["scored_control_denominator"] == 2
    assert report_data["summary"]["scored_control_pass_rate"] == 50.0
    failed = next(item for item in report_data["findings"] if item["check_id"] == "control-fail")
    assert failed["disposition"] == "control"
    assert failed["instance_id"] == result.instances[0].instance_id
    assert failed["methodology"]["verification_criteria"].startswith("Confirm")
    legacy = next(item for item in report_data["findings"] if item["check_id"] == "control-pass")
    assert legacy["methodology"] is None


def test_report_html_methodology_filter_data_island_escapes_hostile_content(
    sample_assessment_result,
):
    # Arrange
    hostile = "</ScRiPt><script>alert(1)</script>"
    result = _disposition_matrix_result(sample_assessment_result, hostile)
    generator = ReportGenerator()

    # Act
    html_content = generator.generate_html_report(result)
    island_marker = '<script id="report-data" type="application/json">'
    island_start = html_content.index(island_marker) + len(island_marker)
    island_end = html_content.index("</script>", island_start)
    island_content = html_content[island_start:island_end]
    report_data = json.loads(island_content)
    records = report_data["findings"]

    # Assert
    manual = next(record for record in records if record["disposition"] == "manual_review")
    assert manual["status"] == "fail"
    assert manual["action_label"] == "Review action"
    assert manual["methodology"]["reason"] == hostile
    assert manual["instance_id"] == "test-instance-123"
    assert "Assessment methodology" in html_content
    assert "Why this is assessed" in html_content
    assert "What the evidence cannot prove" in html_content
    assert "Verification and closure" in html_content
    assert "Disposition" in html_content
    assert "</script" not in island_content.lower()
    assert "<script" not in island_content.lower()


class TestSecurityHardening:
    def test_markdown_does_not_render_images_or_links(self):
        out = ReportGenerator._render_markdown(
            "![x](https://evil.test/a.png) [click](https://evil.test) <https://evil.test/auto>"
        )
        assert "<img" not in out
        assert "<a " not in out
        assert "href=" not in out

    def test_markdown_still_renders_formatting(self):
        out = ReportGenerator._render_markdown("**bold** and `code`")
        assert "<strong>bold</strong>" in out and "<code>code</code>" in out

    def test_report_has_restrictive_csp_and_hashed_inline_script(self, sample_assessment_result):
        generator = ReportGenerator()
        out = generator.generate_html_report(sample_assessment_result)
        assert "unsafe-inline" not in out.split("</head>")[0]
        assert "@@" not in out.split('<script id="report-data"')[0]
        assert 'http-equiv="Content-Security-Policy"' in out
        assert "default-src 'none'" in out
        assert "connect-src 'none'" in out

    @pytest.mark.parametrize(
        "url",
        ["https://a.b\\evil.test", "https://a.b/\x00x", "https://a.b/\nx", "javascript:alert(1)"],
    )
    def test_safe_url_rejects_backslash_and_control_chars(self, url):
        assert ReportGenerator()._safe_url(url) == "#"

    def test_safe_url_allows_normal_urls(self):
        generator = ReportGenerator()
        assert (
            generator._safe_url("https://docs.aws.amazon.com/x") == "https://docs.aws.amazon.com/x"
        )
        assert generator._safe_url("/relative") == "/relative"

    def test_json_data_island_sanitizes_non_finite_and_unknown_types(self):
        out = ReportGenerator._json_data_island(
            {
                "a": float("nan"),
                "b": [float("inf"), -float("inf")],
                "c": datetime(2024, 1, 1),
                "d": "</script>",
            }
        )
        decoded = json.loads(out)
        assert decoded["a"] is None and decoded["b"] == [None, None]
        assert decoded["c"].startswith("2024-01-01")
        assert "</script" not in out

    @pytest.mark.parametrize("lead", ["=", "+", "-", "@", "|", " =", "\t=", "\n@", "\u00a0+"])
    def test_csv_safe_prefixes_formula_payloads(self, lead):
        assert ReportGenerator._csv_safe(f"{lead}cmd").startswith("'")

    def test_csv_safe_leaves_benign_values(self):
        assert ReportGenerator._csv_safe("plain = text") == "plain = text"
        assert ReportGenerator._csv_safe(5) == 5

    def test_generate_csv_report_neutralises_formulas(self, sample_assessment_result, tmp_path):
        sample_assessment_result.findings[0].description = '  =HYPERLINK("http://evil")'
        path = ReportGenerator().generate_csv_report(sample_assessment_result, str(tmp_path))
        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
        assert "'  =HYPERLINK" in rows[1][13]


def test_csp_script_hash_matches_inline_bundle(sample_assessment_result):
    import base64
    import hashlib
    import re

    out = ReportGenerator().generate_html_report(sample_assessment_result)
    body = re.search(r"<script>(.*?)</script>\s*</body>", out, re.S).group(1)
    expected = "'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'"
    assert f"script-src {expected}" in out
    style = re.search(r"<style>(.*?)</style>", out, re.S).group(1)
    expected_style = (
        "'sha256-" + base64.b64encode(hashlib.sha256(style.encode()).digest()).decode() + "'"
    )
    assert f"style-src {expected_style}" in out


def test_template_renderer_is_single_pass_and_escapes_text():
    rendered = ReportGenerator._render_template(
        "<t>@@REPORT_TITLE@@</t><s>@@APP_JS@@</s>",
        {"REPORT_TITLE": '<b>"x"</b> @@APP_JS@@', "APP_JS": "@@REPORT_TITLE@@"},
    )
    assert rendered == "<t>&lt;b&gt;&quot;x&quot;&lt;/b&gt; @@APP_JS@@</t><s>@@REPORT_TITLE@@</s>"


def _write_custom_template(template_dir, content: str) -> None:
    template_dir.mkdir()
    (template_dir / "assessment_report.html").write_text(content, encoding="utf-8")


def test_custom_template_directory_missing_fails_instead_of_falling_back(tmp_path):
    # Arrange
    missing = tmp_path / "missing-templates"

    # Act / Assert
    with pytest.raises(FileNotFoundError, match="Custom report template directory"):
        ReportGenerator(template_dir=str(missing))


def test_custom_template_with_legacy_jinja_syntax_fails_with_migration_error(tmp_path):
    # Arrange
    template_dir = tmp_path / "templates"
    _write_custom_template(
        template_dir,
        "{{ title }} @@STYLE_SRC@@ @@SCRIPT_SRC@@ @@REPORT_TITLE@@ "
        "@@APP_CSS@@ @@APP_JS@@ @@REPORT_DATA_JSON@@",
    )

    # Act / Assert
    with pytest.raises(ValueError, match="legacy Jinja syntax.*@@NAME@@"):
        ReportGenerator(template_dir=str(template_dir))


def test_custom_template_missing_required_placeholders_lists_complete_contract(tmp_path):
    # Arrange
    template_dir = tmp_path / "templates"
    _write_custom_template(template_dir, "<title>@@REPORT_TITLE@@</title>")

    # Act / Assert
    with pytest.raises(ValueError, match="missing required placeholders") as error:
        ReportGenerator(template_dir=str(template_dir))
    for placeholder in ReportGenerator._REQUIRED_PLACEHOLDERS:
        assert f"@@{placeholder}@@" in str(error.value)


def test_custom_template_with_unsupported_placeholder_fails_fast(tmp_path):
    # Arrange
    template_dir = tmp_path / "templates"
    placeholders = " ".join(
        f"@@{name}@@" for name in sorted(ReportGenerator._REQUIRED_PLACEHOLDERS)
    )
    _write_custom_template(template_dir, f"{placeholders} @@UNKNOWN_VALUE@@")

    # Act / Assert
    with pytest.raises(ValueError, match="unsupported placeholders: @@UNKNOWN_VALUE@@"):
        ReportGenerator(template_dir=str(template_dir))


def test_humanize_key_returns_raw_special_characters_for_react_text_rendering():
    # Arrange
    key = "<queue_&_routing>"

    # Act
    label = ReportGenerator._humanize_key(key)
    evidence = ReportGenerator._evidence_view({key: "safe text"})

    # Assert
    assert label == "<queue & routing>"
    assert evidence["pairs"][0]["label"] == "<queue & routing>"
    assert "&lt;" not in label
