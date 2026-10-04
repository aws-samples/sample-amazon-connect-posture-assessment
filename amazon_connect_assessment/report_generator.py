"""Report generation for the Amazon Connect Customer Posture Assessment Tool.

The HTML report uses the React/Cloudscape application imported from the main
AWS Samples repository. A static HTML shell (single-pass ``@@NAME@@`` placeholders) inlines the committed application
bundle and one script-safe JSON data island. JSON and CSV exports share the same
canonical finding, disposition, methodology, and scored-control contracts.
"""

import base64
import dataclasses
import hashlib
import html
import json
import logging
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from .models import (
    AssessmentResult,
    CheckStatus,
    ConnectInstance,
    Finding,
    FindingDisposition,
    Pillar,
    Severity,
    to_utc,
)
from .report.posture_roadmap import generate_posture_roadmap
from .score_policy import (
    FindingScoreClassification,
    classify_finding,
    compute_scored_control_counts,
    compute_scored_control_pass_rate,
    is_control_failure,
)

_CSV_LEADING_IGNORED = "".join(chr(c) for c in range(0x21)) + "\x7f\u00a0\u200b\ufeff"


def _private_opener(path: str, flags: int) -> int:
    """Create report files owner-only (0o600); they contain account findings."""
    return os.open(path, flags, 0o600)


def validate_report_filename(filename: str) -> str:
    """Reject path components so report names remain files, not paths."""
    if (
        not filename
        or filename in {".", ".."}
        or "\x00" in filename
        or "/" in filename
        or "\\" in filename
    ):
        raise ValueError("Report filename must be a filename, not a path")
    return filename


class ReportGenerator:
    """
    Generates rich HTML reports with interactive features for Amazon Connect assessments.

    Features:
    - Modern, responsive UI design
    - Interactive filtering by severity and status
    - Pillar-based organization
    - Executive summary with charts and statistics
    - Detailed findings with remediation guidance
    - Embedded CSS/JavaScript for offline viewing
    - Color-coded status indicators and visual elements
    """

    _APP_DIR = Path(__file__).parent / "templates" / "app"
    _SERVICE_ICON = Path(__file__).parent / "templates" / "assets" / "amazon-connect.svg"
    _EVIDENCE_ARN_ABBREV = 60
    _EVIDENCE_LONG_STRING_ABBREV = 100
    _EVIDENCE_MAX_DEPTH = 4

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the report generator.

        Args:
            template_dir: Optional custom template directory path
        """
        self.logger = logging.getLogger("report_generator")
        self.template_path = self._resolve_template_path(template_dir)

    _TEMPLATE_NAME = "assessment_report.html"
    _PLACEHOLDER = re.compile(r"@@([A-Z_]+)@@")
    # Placeholders whose values are already script/style-safe (bundle text with
    # closing tags neutralised, the JSON island, generated CSP sources). Every
    # other placeholder is HTML-escaped.
    _RAW_PLACEHOLDERS = frozenset(
        {"APP_CSS", "APP_JS", "REPORT_DATA_JSON", "STYLE_SRC", "SCRIPT_SRC"}
    )

    def _resolve_template_path(self, template_dir: Optional[str]) -> Path:
        """Locate the report shell template (custom directory or packaged)."""
        if template_dir and os.path.exists(template_dir):
            self.logger.info(f"Using custom template directory: {template_dir}")
            directory = Path(template_dir)
        else:
            directory = Path(__file__).parent / "templates" / "html"
        path = directory / self._TEMPLATE_NAME
        if not path.is_file():
            raise FileNotFoundError(f"Could not find report template at {path}")
        return path

    @classmethod
    def _render_template(cls, template: str, values: Dict[str, str]) -> str:
        """Single-pass placeholder substitution; substituted text is never rescanned."""

        def substitute(match: "re.Match[str]") -> str:
            name = match.group(1)
            if name not in values:
                raise KeyError(f"Unknown report template placeholder: {name}")
            value = values[name]
            return value if name in cls._RAW_PLACEHOLDERS else html.escape(value, quote=True)

        return cls._PLACEHOLDER.sub(substitute, template)

    @staticmethod
    def _csp_hash_source(content: str) -> str:
        digest = hashlib.sha256(content.encode("utf-8")).digest()
        return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"

    def generate_html_report(
        self,
        assessment_result: AssessmentResult,
        output_path: Optional[str] = None,
        include_raw_data: bool = False,
        generated_at: Optional[datetime] = None,
    ) -> str:
        """
        Generate a complete HTML report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_path: Optional path to save the report
            include_raw_data: Whether to embed raw JSON data in report (default: False)
            generated_at: Render timestamp to stamp on the report. Defaults to
                now, which is what a real run wants. Pass a fixed value to make
                the output byte-for-byte reproducible — the checked-in sample
                report relies on this so regenerating it after a template or
                styling change produces a diff containing only that change.

        Returns:
            HTML content as string (always returns content, saves to file if output_path provided)
        """
        self.logger.info(f"Generating HTML report for assessment {assessment_result.assessment_id}")

        try:
            # Prepare template context
            context = self._prepare_template_context(
                assessment_result, include_raw_data, generated_at=generated_at
            )

            # Render the main template
            template = self.template_path.read_text(encoding="utf-8")
            html_content = self._render_template(template, context)

            # Save to file if path provided
            if output_path:
                self._save_report(html_content, output_path)
                self.logger.info(f"Report saved to: {output_path}")

            return html_content

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise

    def generate_json_report(
        self,
        assessment_result: AssessmentResult,
        output_dir: str,
        filename_template: Optional[str] = None,
    ) -> str:
        """
        Generate a JSON report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_dir: Directory to save the report
            filename_template: Optional filename template

        Returns:
            Path to the generated JSON report
        """
        self.logger.info(f"Generating JSON report for assessment {assessment_result.assessment_id}")

        try:
            # Generate filename
            if not filename_template:
                filename_template = "connect_assessment_{timestamp}_{account_id}.json"

            filename = self._generate_filename(filename_template, assessment_result, "json")
            output_path = os.path.join(output_dir, filename)

            # Ensure directory exists
            os.makedirs(output_dir, exist_ok=True)

            # Convert assessment result to dictionary
            registered_checks = assessment_result.summary.registered_checks
            if registered_checks is None:
                registered_checks = (
                    assessment_result.summary.total_checks
                    - assessment_result.summary.journey_findings
                )
            report_data = {
                "assessment_id": assessment_result.assessment_id,
                "timestamp": assessment_result.timestamp.isoformat(),
                "account_id": assessment_result.account_id,
                "region": assessment_result.region,
                "journey_map_entries": json.loads(
                    self._journey_map_entries_json(assessment_result)
                ),
                "journey_map_status": getattr(assessment_result, "journey_map_status", None),
                "summary": {
                    "total_checks": assessment_result.summary.total_checks,
                    "passed_checks": assessment_result.summary.passed_checks,
                    "failed_checks": assessment_result.summary.failed_checks,
                    "error_checks": assessment_result.summary.error_checks,
                    "skipped_checks": assessment_result.summary.skipped_checks,
                    "not_applicable_checks": assessment_result.summary.not_applicable_checks,
                    "critical_findings": assessment_result.summary.critical_findings,
                    "high_findings": assessment_result.summary.high_findings,
                    "medium_findings": assessment_result.summary.medium_findings,
                    "low_findings": assessment_result.summary.low_findings,
                    "registered_checks": registered_checks,
                    "journey_findings": assessment_result.summary.journey_findings,
                    **self._disposition_summary(assessment_result.findings),
                },
                "posture_roadmap": self._serialize_roadmap(assessment_result.findings),
                "instances": [
                    {
                        "instance_id": instance.instance_id,
                        "instance_arn": instance.instance_arn,
                        "identity_management_type": instance.identity_management_type,
                        "inbound_calls_enabled": instance.inbound_calls_enabled,
                        "outbound_calls_enabled": instance.outbound_calls_enabled,
                        "instance_alias": getattr(instance, "instance_alias", None),
                        "service_role": getattr(instance, "service_role", None),
                        "status": getattr(instance, "status", None),
                    }
                    for instance in assessment_result.instances
                ],
                "findings": [
                    self._serialize_finding(finding) for finding in assessment_result.findings
                ],
                "metadata": {
                    "tool_version": assessment_result.metadata.tool_version,
                    "execution_time_seconds": assessment_result.metadata.execution_time_seconds,
                    "aws_account_id": assessment_result.metadata.aws_account_id,
                    "aws_region": assessment_result.metadata.aws_region,
                    "execution_environment": assessment_result.metadata.execution_environment,
                    "python_version": assessment_result.metadata.python_version,
                },
                "execution_errors": assessment_result.execution_errors,
            }

            # Save JSON report
            with open(output_path, "w", encoding="utf-8", opener=_private_opener) as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"JSON report saved to: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise

    def _serialize_remediation(self, remediation) -> Optional[Dict[str, Any]]:
        """
        Serialize a structured Remediation into a JSON-friendly dict.

        Returns None when no structured remediation is present, preserving the
        existing report shape for findings that only carry the flat string.
        """
        if remediation is None:
            return None
        return {
            "summary": remediation.summary,
            "steps": [
                {
                    "order": step.order,
                    "instruction": step.instruction,
                    "command": step.command,
                    "console_path": step.console_path,
                }
                for step in sorted(remediation.steps, key=lambda s: s.order)
            ],
            "target_resources": list(remediation.target_resources),
            "references": [{"title": ref.title, "url": ref.url} for ref in remediation.references],
            "applies_if": remediation.applies_if,
            "placeholders": list(remediation.placeholders),
        }

    @staticmethod
    def _serialize_methodology(methodology) -> Optional[Dict[str, Any]]:
        """Serialize methodology while remaining safe for legacy findings."""
        if methodology is None:
            return None
        return {
            "reason": methodology.reason,
            "evidence_source": methodology.evidence_source,
            "proof_limitations": methodology.proof_limitations,
            "developer_admin_meaning": methodology.developer_admin_meaning,
            "verification_criteria": methodology.verification_criteria,
            "responsible_function": methodology.responsible_function,
            "primary_lens_reference": methodology.primary_lens_reference,
        }

    def _serialize_finding(self, finding: Finding) -> Dict[str, Any]:
        """Return the complete additive finding contract shared by JSON and HTML."""
        return {
            "check_id": finding.check_id,
            "check_name": finding.check_name,
            "pillar": finding.pillar.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "description": finding.description,
            "remediation": finding.remediation,
            "structured_remediation": self._serialize_remediation(finding.structured_remediation),
            "evidence": finding.evidence,
            "timestamp": finding.timestamp.isoformat(),
            "disposition": finding.disposition.value,
            "instance_id": finding.instance_id,
            "score_classification": classify_finding(finding).value,
            "methodology": self._serialize_methodology(finding.methodology),
        }

    @staticmethod
    def _disposition_summary(findings: List[Finding]) -> Dict[str, Any]:
        """Compute all score and disposition totals from the shared policy."""
        numerator, denominator = compute_scored_control_counts(findings)
        classifications = [classify_finding(finding) for finding in findings]
        return {
            "total_records": len(findings),
            "control_findings": sum(
                finding.disposition == FindingDisposition.CONTROL for finding in findings
            ),
            "manual_review_findings": sum(
                finding.disposition == FindingDisposition.MANUAL_REVIEW for finding in findings
            ),
            "manual_review_non_scoring_records": sum(
                finding.disposition == FindingDisposition.MANUAL_REVIEW
                and classify_finding(finding) == FindingScoreClassification.NON_SCORING
                for finding in findings
            ),
            "manual_review_candidates": sum(
                finding.disposition == FindingDisposition.MANUAL_REVIEW
                and finding.status == CheckStatus.FAIL
                for finding in findings
            ),
            "informational_findings": sum(
                finding.disposition == FindingDisposition.INFORMATIONAL for finding in findings
            ),
            "informational_non_scoring_records": sum(
                finding.disposition == FindingDisposition.INFORMATIONAL
                and classify_finding(finding) == FindingScoreClassification.NON_SCORING
                for finding in findings
            ),
            "scored_control_passes": classifications.count(FindingScoreClassification.SCORED_PASS),
            "scored_control_failures": classifications.count(
                FindingScoreClassification.SCORED_FAIL
            ),
            "unevaluated_controls": classifications.count(
                FindingScoreClassification.UNEVALUATED_CONTROL
            ),
            "not_applicable_controls": sum(
                finding.disposition == FindingDisposition.CONTROL
                and finding.status == CheckStatus.NOT_APPLICABLE
                for finding in findings
            ),
            "not_applicable_records": classifications.count(
                FindingScoreClassification.NOT_APPLICABLE
            ),
            "scored_control_numerator": numerator,
            "scored_control_denominator": denominator,
            "scored_control_pass_rate": compute_scored_control_pass_rate(findings),
        }

    def _serialize_roadmap(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Serialize disposition-aware posture roadmap records."""
        return {
            pillar: {
                "pillar": posture.pillar.value,
                "total_records": posture.total_checks,
                "scored_control_numerator": posture.passed_checks,
                "scored_control_denominator": posture.scored_control_denominator,
                "pass_rate": posture.pass_rate,
                "maturity_level": posture.maturity_level,
                "improvement_actions": posture.improvement_actions,
            }
            for pillar, posture in generate_posture_roadmap(findings).items()
        }

    @staticmethod
    def _json_data_island(value: Any) -> str:
        """Serialize JSON so data cannot terminate its HTML script element.

        NaN/Infinity are not valid JSON (``JSON.parse`` would reject the whole
        island), so they are replaced with ``None`` first.
        """
        return (
            json.dumps(
                ReportGenerator._replace_non_finite(value),
                ensure_ascii=False,
                default=str,
                allow_nan=False,
            )
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

    @staticmethod
    def _replace_non_finite(value: Any) -> Any:
        """Recursively replace NaN/+-Infinity floats with ``None``."""
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, dict):
            return {k: ReportGenerator._replace_non_finite(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [ReportGenerator._replace_non_finite(v) for v in value]
        return value

    @staticmethod
    def _csv_safe(value: Any) -> Any:
        """Neutralise spreadsheet formula injection in a CSV cell.

        Leading whitespace/control characters are ignored when testing, since
        spreadsheet apps strip them before evaluating a formula.
        """
        if not isinstance(value, str):
            return value
        stripped = value.lstrip(_CSV_LEADING_IGNORED)
        if stripped and stripped[0] in "=+-@|":
            return "'" + value
        return value

    def generate_csv_report(
        self,
        assessment_result: AssessmentResult,
        output_dir: str,
        filename_template: Optional[str] = None,
    ) -> str:
        """
        Generate a CSV report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_dir: Directory to save the report
            filename_template: Optional filename template

        Returns:
            Path to the generated CSV report
        """
        self.logger.info(f"Generating CSV report for assessment {assessment_result.assessment_id}")

        try:
            import csv

            # Generate filename
            if not filename_template:
                filename_template = "connect_assessment_{timestamp}_{account_id}.csv"

            filename = self._generate_filename(filename_template, assessment_result, "csv")
            output_path = os.path.join(output_dir, filename)

            # Ensure directory exists
            os.makedirs(output_dir, exist_ok=True)

            # Define CSV headers
            headers = [
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
                "Disposition",
                "Reason",
                "Evidence Source",
                "Proof Limitations",
                "Developer/Admin Meaning",
                "Verification Criteria",
                "Responsible Function",
                "Primary Lens Reference",
            ]

            # UUID -> instance_alias, so each row shows a human-readable
            # name alongside the raw UUID rather than the UUID alone
            # (reviewer feedback on the HTML report applies equally here).
            alias_by_id = {
                inst.instance_id: inst.instance_alias
                for inst in assessment_result.instances
                if inst.instance_alias
            }

            # Write CSV report
            with open(output_path, "w", newline="", encoding="utf-8", opener=_private_opener) as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for finding in assessment_result.findings:
                    # Prefer the explicit assessed instance added by the atomic
                    # methodology contract. Fall back to the legacy resource-ID
                    # convention for findings created before that field existed.
                    instance_id = finding.instance_id or "unknown"
                    if not finding.instance_id:
                        for instance in assessment_result.instances:
                            if finding.resource_id.startswith(instance.instance_id):
                                instance_id = instance.instance_id
                                break

                    row = [
                        assessment_result.assessment_id,
                        finding.timestamp.isoformat(),
                        assessment_result.account_id,
                        assessment_result.region,
                        instance_id,
                        alias_by_id.get(instance_id, ""),
                        finding.check_id,
                        finding.check_name,
                        finding.pillar.value,
                        finding.severity.value,
                        finding.status.value,
                        finding.resource_type,
                        finding.resource_id,
                        finding.description,
                        finding.remediation,
                        (
                            ", ".join(finding.structured_remediation.target_resources)
                            if finding.structured_remediation
                            else ""
                        ),
                        json.dumps(finding.evidence) if finding.evidence else "",
                        finding.disposition.value,
                        finding.methodology.reason if finding.methodology else "",
                        finding.methodology.evidence_source if finding.methodology else "",
                        finding.methodology.proof_limitations if finding.methodology else "",
                        (
                            finding.methodology.developer_admin_meaning
                            if finding.methodology
                            else ""
                        ),
                        (finding.methodology.verification_criteria if finding.methodology else ""),
                        (
                            finding.methodology.responsible_function
                            if finding.methodology and finding.methodology.responsible_function
                            else ""
                        ),
                        (
                            finding.methodology.primary_lens_reference
                            if finding.methodology and finding.methodology.primary_lens_reference
                            else ""
                        ),
                    ]
                    writer.writerow([self._csv_safe(cell) for cell in row])

            self.logger.info(f"CSV report saved to: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise

    def _generate_filename(
        self,
        template: str,
        assessment_result: AssessmentResult,
        extension: str,
    ) -> str:
        """
        Generate filename from template with variable substitution.

        Args:
            template: Filename template with placeholders
            assessment_result: Assessment result for variable substitution
            extension: File extension

        Returns:
            Generated filename
        """
        # Extract variables for substitution
        timestamp = assessment_result.timestamp.strftime("%Y%m%d_%H%M%S")
        account_id = assessment_result.account_id
        region = assessment_result.region
        assessment_id = assessment_result.assessment_id

        # Substitute variables in template
        filename = template.format(
            timestamp=timestamp,
            account_id=account_id,
            region=region,
            assessment_id=assessment_id,
        )

        # Ensure proper extension
        if not filename.endswith(f".{extension}"):
            filename = f"{filename}.{extension}"

        return validate_report_filename(filename)

    def _prepare_template_context(
        self,
        assessment_result: AssessmentResult,
        include_raw_data: bool,
        generated_at: Optional[datetime] = None,
    ) -> Dict[str, str]:
        """Build the AWS Samples Cloudscape shell and its JSON data island."""
        app_css = self._load_app_asset("report-app.css")
        app_js = self._load_app_asset("report-app.js")
        return {
            "STYLE_SRC": self._csp_hash_source(app_css),
            "SCRIPT_SRC": self._csp_hash_source(app_js),
            "REPORT_TITLE": (
                f"Amazon Connect Customer Posture Assessment Report - "
                f"{assessment_result.account_id}"
            ),
            "APP_CSS": app_css,
            "APP_JS": app_js,
            "REPORT_DATA_JSON": self._json_for_script(
                self._build_report_data(
                    assessment_result,
                    include_raw_data,
                    generated_at=generated_at,
                )
            ),
        }

    def _build_report_data(
        self,
        assessment_result: AssessmentResult,
        include_raw_data: bool,
        generated_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Assemble the data contract consumed by the imported Cloudscape UI."""
        summary = assessment_result.summary
        executive_summary = self._create_executive_summary(assessment_result)
        filters = self._get_filter_options(assessment_result.findings, assessment_result.instances)
        aliases = {
            instance.instance_id: instance.instance_alias
            for instance in assessment_result.instances
            if instance.instance_alias
        }
        instance_ids = [instance.instance_id for instance in assessment_result.instances]
        ordered_findings = [
            finding
            for pillar_findings in self._organize_findings_by_pillar(
                assessment_result.findings
            ).values()
            for finding in pillar_findings
        ]
        metadata = assessment_result.metadata
        generated = generated_at or datetime.now(timezone.utc)

        return {
            "schema_version": 1,
            "title": "Amazon Connect Customer Posture Assessment Report",
            "generated_at": self._format_datetime(generated),
            "assessment": {
                "id": assessment_result.assessment_id,
                "account_id": assessment_result.account_id,
                "region": assessment_result.region,
                "timestamp": self._format_datetime(assessment_result.timestamp),
            },
            "metadata": {
                "tool_version": metadata.tool_version,
                "execution_time": self._format_duration(metadata.execution_time_seconds),
                "execution_environment": metadata.execution_environment,
                "python_version": metadata.python_version,
            },
            "summary": dataclasses.asdict(summary),
            "stats": self._generate_summary_statistics(assessment_result),
            "charts": self._generate_charts_data(assessment_result),
            "posture_roadmap": self._serialize_roadmap(assessment_result.findings),
            "insights": executive_summary["insights"],
            "recommendations": executive_summary["recommendations"],
            "filters": {
                "default_severity": filters["default_severity"],
                "default_status": filters["default_status"],
                "default_disposition": filters.get("default_disposition", "all"),
            },
            "pillars": [
                {"id": pillar.value, "label": pillar.value.replace("_", " ").title()}
                for pillar in Pillar
            ],
            "instances": [
                {
                    "id": instance.instance_id,
                    "alias": instance.instance_alias,
                    "display_name": instance.display_name,
                    "status": instance.status,
                    "identity_management_type": instance.identity_management_type,
                    "inbound_calls_enabled": instance.inbound_calls_enabled,
                    "outbound_calls_enabled": instance.outbound_calls_enabled,
                }
                for instance in assessment_result.instances
            ],
            "findings": [
                self._finding_view(index, finding, aliases, instance_ids)
                for index, finding in enumerate(ordered_findings)
            ],
            "journey": {
                "entries": [
                    {key: value for key, value in entry.items() if key != "diagram_html"}
                    for entry in self._journey_map_entries(assessment_result)
                ],
                "status": getattr(assessment_result, "journey_map_status", None),
            },
            "execution_errors": list(assessment_result.execution_errors or []),
            "raw_data": (
                json.dumps(dataclasses.asdict(assessment_result), default=str, indent=2)
                if include_raw_data
                else None
            ),
            "service_icon": self._service_icon_data_uri(),
        }

    def _finding_view(
        self,
        index: int,
        finding: Finding,
        alias_by_id: Dict[str, str],
        instance_ids: List[str],
    ) -> Dict[str, Any]:
        """Serialize one complete finding for the Cloudscape application."""
        serialized = self._serialize_finding(finding)
        instance_id = finding.instance_id or self._finding_instance_id(finding, instance_ids)
        remediation = finding.structured_remediation
        if finding.disposition == FindingDisposition.MANUAL_REVIEW:
            action_label = "Review action"
        elif finding.disposition == FindingDisposition.INFORMATIONAL:
            action_label = "Suggested follow-up"
        elif finding.status in (CheckStatus.ERROR, CheckStatus.SKIPPED):
            action_label = "Evaluation next step"
        elif finding.status == CheckStatus.FAIL:
            action_label = "Remediation"
        else:
            action_label = "Verification and maintenance"

        return {
            **serialized,
            "key": str(index),
            "instance_id": instance_id,
            "resource_label": self._render_instance_label(finding.resource_id, alias_by_id),
            "instance": (
                alias_by_id.get(instance_id, instance_id) if instance_id else finding.resource_id
            ),
            "description_html": self._render_markdown(finding.description),
            "remediation_html": (
                self._render_markdown(finding.remediation) if remediation is None else ""
            ),
            "action_label": action_label,
            "reason": finding.methodology.reason if finding.methodology else "",
            "evidence_source": (finding.methodology.evidence_source if finding.methodology else ""),
            "proof_limitations": (
                finding.methodology.proof_limitations if finding.methodology else ""
            ),
            "developer_admin_meaning": (
                finding.methodology.developer_admin_meaning if finding.methodology else ""
            ),
            "verification_criteria": (
                finding.methodology.verification_criteria if finding.methodology else ""
            ),
            "responsible_function": (
                finding.methodology.responsible_function
                if finding.methodology and finding.methodology.responsible_function
                else ""
            ),
            "primary_lens_reference": (
                finding.methodology.primary_lens_reference
                if finding.methodology and finding.methodology.primary_lens_reference
                else ""
            ),
            "structured_remediation": (
                {
                    "summary": remediation.summary,
                    "steps": [
                        {
                            "order": step.order,
                            "instruction_html": self._render_markdown(step.instruction),
                            "command": step.command,
                            "console_path": step.console_path,
                        }
                        for step in remediation.steps
                    ],
                    "target_resources": list(remediation.target_resources),
                    "references": [
                        {"title": reference.title, "url": self._safe_url(reference.url)}
                        for reference in remediation.references
                    ],
                    "applies_if": remediation.applies_if,
                }
                if remediation is not None
                else None
            ),
            "evidence": self._evidence_view(finding.evidence),
            "evidence_json": (
                json.dumps(finding.evidence, indent=2, default=str) if finding.evidence else ""
            ),
        }

    @staticmethod
    def _finding_instance_id(finding: Finding, instance_ids: List[str]) -> Optional[str]:
        if finding.instance_id:
            return finding.instance_id
        for instance_id in instance_ids:
            if finding.resource_id == instance_id or finding.resource_id.startswith(
                f"{instance_id}/"
            ):
                return instance_id
        return None

    @staticmethod
    def _json_for_script(value: Any) -> str:
        return ReportGenerator._json_data_island(value)

    def _generate_summary_statistics(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        """Generate report statistics without mixing non-scoring records into posture."""
        findings = assessment_result.findings
        summary = assessment_result.summary
        registered_checks = summary.registered_checks
        if registered_checks is None:
            registered_checks = summary.total_checks - summary.journey_findings

        disposition_summary = self._disposition_summary(findings)
        pass_rate = disposition_summary["scored_control_pass_rate"]
        failed_controls = [finding for finding in findings if is_control_failure(finding)]

        status_breakdown = {
            "passed": disposition_summary["scored_control_passes"],
            "failed": disposition_summary["scored_control_failures"],
            "error": summary.error_checks,
            "skipped": summary.skipped_checks,
            "unevaluated": disposition_summary["unevaluated_controls"],
            "not_applicable": summary.not_applicable_checks,
            "manual_review": disposition_summary["manual_review_findings"],
            "informational": disposition_summary["informational_findings"],
        }
        severity_breakdown = {
            severity.value: sum(finding.severity == severity for finding in failed_controls)
            for severity in Severity
        }
        pillar_issues = {
            pillar.value: sum(finding.pillar == pillar for finding in failed_controls)
            for pillar in Pillar
        }

        return {
            "total_checks": summary.total_checks,
            "total_records": len(findings),
            "registered_checks": registered_checks,
            "journey_findings": summary.journey_findings,
            "pass_rate": round(pass_rate, 1) if pass_rate is not None else None,
            "pass_rate_display": f"{pass_rate:.1f}%" if pass_rate is not None else "Not scored",
            "risk_score": self._calculate_risk_score(findings),
            "status_breakdown": status_breakdown,
            "severity_breakdown": severity_breakdown,
            "pillar_issues": pillar_issues,
            "instances_assessed": len(assessment_result.instances),
            "execution_time": assessment_result.metadata.execution_time_seconds,
            "has_critical_issues": severity_breakdown[Severity.CRITICAL.value] > 0,
            "has_high_issues": severity_breakdown[Severity.HIGH.value] > 0,
            **disposition_summary,
        }

    def _calculate_risk_score(self, findings: List[Finding]) -> int:
        """Calculate risk from failed controls only."""
        failed_findings = [finding for finding in findings if is_control_failure(finding)]

        if not failed_findings:
            return 0

        # Weight by severity: Critical=10, High=7, Medium=4, Low=1
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
        }

        total_weight = sum(severity_weights.get(f.severity, 1) for f in failed_findings)
        max_possible = len(failed_findings) * 10  # If all were critical

        # Scale to 0-100
        risk_score = min(100, int((total_weight / max_possible) * 100)) if max_possible > 0 else 0

        return risk_score

    def _organize_findings_by_pillar(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        # Organize findings by AWS Well-Architected Framework pillar
        organized = {}

        for pillar in Pillar:
            pillar_findings = [finding for finding in findings if finding.pillar == pillar]
            pillar_findings.sort(
                key=lambda finding: (
                    0
                    if is_control_failure(finding)
                    else (
                        1
                        if finding.disposition == FindingDisposition.MANUAL_REVIEW
                        and finding.status == CheckStatus.FAIL
                        else 2
                    ),
                    ["critical", "high", "medium", "low"].index(finding.severity.value),
                )
            )
            organized[pillar.value] = pillar_findings

        return organized

    def _generate_charts_data(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        """Generate chart data using the shared disposition scoring policy."""
        findings = assessment_result.findings
        disposition_summary = self._disposition_summary(findings)
        failed_controls = [finding for finding in findings if is_control_failure(finding)]

        status_chart = {
            "labels": [
                "Scored control passes",
                "Scored control failures",
                "Unevaluated controls",
                "Not applicable records",
                "Manual reviews",
                "Informational records",
            ],
            "data": [
                disposition_summary["scored_control_passes"],
                disposition_summary["scored_control_failures"],
                disposition_summary["unevaluated_controls"],
                disposition_summary["not_applicable_records"],
                disposition_summary["manual_review_non_scoring_records"],
                disposition_summary["informational_non_scoring_records"],
            ],
            "colors": ["#28a745", "#dc3545", "#ffc107", "#adb5bd", "#0972d3", "#6c757d"],
        }

        severity_chart = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "data": [
                sum(finding.severity == severity for finding in failed_controls)
                for severity in (
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                )
            ],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8"],
        }

        pillar_data = {}
        for pillar in Pillar:
            pillar_findings = [finding for finding in findings if finding.pillar == pillar]
            passed, denominator = compute_scored_control_counts(pillar_findings)
            failed = denominator - passed
            pillar_data[pillar.value] = {
                "total_records": len(pillar_findings),
                "scored_control_numerator": passed,
                "scored_control_denominator": denominator,
                "passed": passed,
                "failed": failed,
                "pass_rate": (round(passed / denominator * 100, 1) if denominator > 0 else None),
                "manual_review_candidates": sum(
                    finding.disposition == FindingDisposition.MANUAL_REVIEW
                    and finding.status == CheckStatus.FAIL
                    for finding in pillar_findings
                ),
                "informational_records": sum(
                    finding.disposition == FindingDisposition.INFORMATIONAL
                    for finding in pillar_findings
                ),
                "unevaluated_controls": sum(
                    classify_finding(finding) == FindingScoreClassification.UNEVALUATED_CONTROL
                    for finding in pillar_findings
                ),
                "not_applicable_records": sum(
                    classify_finding(finding) == FindingScoreClassification.NOT_APPLICABLE
                    for finding in pillar_findings
                ),
                "not_applicable_controls": sum(
                    finding.disposition == FindingDisposition.CONTROL
                    and finding.status == CheckStatus.NOT_APPLICABLE
                    for finding in pillar_findings
                ),
            }

        return {
            "status_distribution": status_chart,
            "severity_distribution": severity_chart,
            "pillar_breakdown": pillar_data,
        }

    def _create_executive_summary(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        """Create posture insights and recommendations from failed controls only."""
        findings = assessment_result.findings
        failed_controls = [finding for finding in findings if is_control_failure(finding)]
        critical_findings = [
            finding for finding in failed_controls if finding.severity == Severity.CRITICAL
        ]
        high_findings = [
            finding for finding in failed_controls if finding.severity == Severity.HIGH
        ]
        pass_rate = compute_scored_control_pass_rate(findings)
        disposition_summary = self._disposition_summary(findings)
        insights = []

        if critical_findings:
            insights.append(
                {
                    "type": "critical",
                    "message": (
                        f"Found {len(critical_findings)} critical failed controls requiring "
                        "immediate attention."
                    ),
                }
            )
        if high_findings:
            insights.append(
                {
                    "type": "warning",
                    "message": (
                        f"Identified {len(high_findings)} high-severity failed controls that "
                        "should be addressed soon."
                    ),
                }
            )

        if pass_rate is None:
            insights.append(
                {
                    "type": "info",
                    "message": "Control posture is not scored because no controls returned PASS or FAIL.",
                }
            )
        elif pass_rate >= 90:
            insights.append(
                {
                    "type": "success",
                    "message": f"Scored control pass rate is {pass_rate:.1f}%.",
                }
            )
        elif pass_rate >= 75:
            insights.append(
                {
                    "type": "info",
                    "message": f"Scored control pass rate is {pass_rate:.1f}% with room for improvement.",
                }
            )
        else:
            insights.append(
                {
                    "type": "warning",
                    "message": f"Scored control pass rate is {pass_rate:.1f}% and needs attention.",
                }
            )

        if disposition_summary["manual_review_candidates"]:
            count = disposition_summary["manual_review_candidates"]
            insights.append(
                {
                    "type": "info",
                    "message": f"{count} manual-review candidate{'s' if count != 1 else ''} require validation before closure.",
                }
            )

        recommendations = []
        if critical_findings:
            recommendations.append(
                {
                    "priority": "critical",
                    "title": "Address Critical Failed Controls",
                    "description": (
                        f"Review and remediate {len(critical_findings)} critical failed controls."
                    ),
                    "findings_count": len(critical_findings),
                }
            )
        if high_findings:
            recommendations.append(
                {
                    "priority": "high",
                    "title": "Resolve High-Severity Failed Controls",
                    "description": (f"Address {len(high_findings)} high-severity failed controls."),
                    "findings_count": len(high_findings),
                }
            )
        for pillar in Pillar:
            pillar_failed = [finding for finding in failed_controls if finding.pillar == pillar]
            if len(pillar_failed) >= 3:
                pillar_name = pillar.value.replace("_", " ").title()
                recommendations.append(
                    {
                        "priority": "medium",
                        "title": f"Improve {pillar_name}",
                        "description": (
                            f"Focus on {len(pillar_failed)} failed controls in "
                            f"{pillar_name.lower()}."
                        ),
                        "findings_count": len(pillar_failed),
                    }
                )

        return {
            "insights": insights,
            "recommendations": recommendations[:5],
            "assessment_date": assessment_result.timestamp,
            "instances_count": len(assessment_result.instances),
            "total_findings": len(failed_controls),
            "manual_review_candidates": disposition_summary["manual_review_candidates"],
            "scored_control_pass_rate": pass_rate,
        }

    # ------------------------------------------------------------------
    # Caller Journey Map template helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _journey_map_entries(assessment_result: AssessmentResult) -> List[Dict[str, Any]]:
        """Return the raw journey-map entries the engine attached."""
        return getattr(assessment_result, "journey_map_entries", []) or []

    def _journey_map_entries_json(self, assessment_result: AssessmentResult) -> str:
        """Serialize journey entries safely for an HTML JSON data island."""
        return self._json_data_island(self._journey_map_entries(assessment_result))

    def _get_filter_options(
        self,
        findings: List[Finding],
        instances: List[ConnectInstance],
    ) -> Dict[str, Any]:
        """
        Build the filter dropdown options.

        For the instance filter we return a list of ``{"id", "label"}`` dicts
        so the dropdown can display the friendly alias (``label``) while the
        option's underlying value stays as the UUID (``id``). That preserves
        matching against ``finding.resource_id`` which is still a raw UUID.
        Instances discovered in the assessment take precedence for label
        resolution; instances that only appear in findings (e.g. from
        historical data) fall back to the UUID.
        """
        severities = list({finding.severity.value for finding in findings})
        statuses = list({finding.status.value for finding in findings})
        pillars = list({finding.pillar.value for finding in findings})
        dispositions = list({finding.disposition.value for finding in findings})
        failed_controls = [finding for finding in findings if is_control_failure(finding)]
        default_status = CheckStatus.FAIL.value if failed_controls else "all"

        failed_severities = {finding.severity for finding in failed_controls}
        if Severity.CRITICAL in failed_severities:
            default_severity = Severity.CRITICAL.value
        elif Severity.HIGH in failed_severities:
            default_severity = Severity.HIGH.value
        else:
            default_severity = "all"

        alias_by_id: Dict[str, str] = {inst.instance_id: inst.display_name for inst in instances}
        finding_instance_ids = {
            finding.instance_id
            or (finding.resource_id if finding.resource_type == "ConnectInstance" else None)
            for finding in findings
        }
        instance_ids = sorted(
            set(alias_by_id) | {instance_id for instance_id in finding_instance_ids if instance_id}
        )
        instance_options = [
            {"id": instance_id, "label": alias_by_id.get(instance_id, instance_id)}
            for instance_id in instance_ids
        ]

        return {
            "severities": sorted(
                severities, key=lambda value: ["critical", "high", "medium", "low"].index(value)
            ),
            "default_severity": default_severity,
            "statuses": sorted(statuses),
            "default_status": default_status,
            "pillars": sorted(pillars),
            "dispositions": sorted(dispositions),
            "default_disposition": (FindingDisposition.CONTROL.value if failed_controls else "all"),
            "instances": instance_options,
        }

    def _save_report(self, html_content: str, output_path: str) -> None:
        # Save HTML report to specified path
        try:
            # Ensure directory exists (only if there's a directory component)
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(output_path, "w", encoding="utf-8", opener=_private_opener) as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {str(e)}")
            raise

    @staticmethod
    def _render_instance_label(resource_id: str, alias_by_id: Dict[str, str]) -> str:
        """
        Render a Finding.resource_id as "'alias' (uuid)" when the alias is
        known, otherwise just the bare UUID.

        ``alias_by_id`` is built once per report in
        ``_prepare_template_context`` from the assessment's instance list
        (see ``instance_alias_by_id`` in the template context) — this
        keeps the filter itself a pure function of its arguments rather
        than reaching back into instance state, so it's trivial to test
        and doesn't depend on render order.
        """
        alias = alias_by_id.get(resource_id)
        if alias:
            return f"'{alias}' ({resource_id})"
        return resource_id

    # ------------------------------------------------------------------
    # Markdown filter
    # ------------------------------------------------------------------
    #
    # The instance is built lazily and cached because parser construction
    # is expensive relative to the per-finding render cost; the same
    # parser is safe to reuse across renders (stateless per call).
    _MARKDOWN_PARSER = None
    # Set once if markdown-it-py cannot be imported, so the fallback path is
    # taken without retrying a failed import for every finding in the report.
    _MARKDOWN_UNAVAILABLE = False

    @classmethod
    def _get_markdown_parser(cls):
        """
        Return a shared, XSS-safe markdown-it parser, or ``None`` if the
        renderer is not installed.

        Returning ``None`` rather than raising is deliberate. markdown-it-py is
        a declared runtime dependency, so a missing import means the
        environment went stale — typically an editable install whose
        dependencies were never re-resolved after markdown rendering was
        added. In that situation the assessment itself has already completed
        every AWS call it was going to make, and aborting the report would
        discard all of that work over a text formatter. Degrading to escaped
        plain text keeps the findings readable.
        """
        if cls._MARKDOWN_PARSER is None and not cls._MARKDOWN_UNAVAILABLE:
            try:
                from markdown_it import MarkdownIt
            except ImportError:
                cls._MARKDOWN_UNAVAILABLE = True
                logging.getLogger("report_generator").warning(
                    "markdown-it-py is not installed, so finding text will render as "
                    "plain text instead of formatted markdown. Reinstall the package "
                    "to restore formatting: pip install -e ."
                )
                return None

            # ``commonmark`` preset with html=False means the parser
            # renders ``<script>`` in source as literal escaped text,
            # never as an HTML tag. That's the security posture we
            # need since a finding description can interpolate flow-
            # authored strings (queue names, prompt text, attribute
            # names) which we do not fully trust.
            # Images, links and autolinks are disabled as well: flow-authored
            # text must never render remote <img> (tracking/exfiltration) or
            # clickable links. Structured references are rendered by the UI.
            parser = MarkdownIt("commonmark", {"html": False, "breaks": False})
            parser.disable(["image", "link", "autolink"])
            cls._MARKDOWN_PARSER = parser
        return cls._MARKDOWN_PARSER

    @staticmethod
    def _render_escaped_paragraphs(text: str) -> str:
        """
        Render text as escaped HTML paragraphs, splitting on blank lines.

        The fallback for a missing markdown renderer. Markdown syntax is left
        visible as literal characters, which is honest about what happened and
        still readable. Everything is escaped, so this path carries the same
        no-raw-HTML guarantee as the markdown parser it stands in for.
        """
        blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]
        return "".join(f"<p>{html.escape(block)}</p>" for block in blocks)

    @classmethod
    def _render_markdown(cls, text) -> str:
        """
        Convert a markdown string to HTML for embedding in a template.

        Non-string / empty / None values pass through as empty strings so
        the filter never crashes a template render. Callers who want a
        placeholder for empty descriptions should handle that in the
        template rather than here.
        """
        if not text:
            return ""
        if not isinstance(text, str):
            text = str(text)
        parser = cls._get_markdown_parser()
        if parser is None:
            return cls._render_escaped_paragraphs(text)
        return parser.render(text)

    # ------------------------------------------------------------------
    # Evidence renderer
    # ------------------------------------------------------------------
    #
    # Checks stash raw diagnostics on ``Finding.evidence`` — dicts of
    # scalars, lists of dicts, ARNs, nested dicts. The old template just
    # dumped this as one big JSON blob in a ``<pre>`` block. That was
    # unreadable once evidence grew past a handful of fields; a 10-item
    # ``hardcoded_details`` list plus a couple of scalars ran ~60 lines
    # of dense JSON.
    #
    # This filter turns evidence into structured HTML: a definition list
    # for top-level scalars, a real HTML table for any list-of-dicts key
    # (one row per entry, columns pulled from the union of keys), and
    # nested sub-blocks for dict-of-dict evidence. ARN-shaped values are
    # abbreviated in-place with the full value kept in a ``title=``
    # tooltip so the reader can hover to see the full string but doesn't
    # get a wall of ``arn:aws:connect:us-east-1:...`` on screen.
    #
    # Falls back to pretty-printed JSON only for shapes it can't
    # recognise (rare in practice; every check we ship uses one of the
    # patterns above).

    _EVIDENCE_ARN_ABBREV = 60
    _EVIDENCE_LONG_STRING_ABBREV = 100

    @classmethod
    def _evidence_view(cls, evidence: Any) -> Optional[Dict[str, Any]]:
        """Structure evidence for the imported Cloudscape detail panel."""
        if not evidence:
            return None
        if not isinstance(evidence, dict):
            return {"fallback": cls._evidence_json(evidence)}
        return cls._evidence_block(evidence, depth=0)

    @classmethod
    def _evidence_block(cls, evidence: Dict[str, Any], depth: int) -> Dict[str, Any]:
        if depth > cls._EVIDENCE_MAX_DEPTH:
            return {"fallback": cls._evidence_json(evidence)}
        pairs: List[Dict[str, Any]] = []
        tables: List[Dict[str, Any]] = []
        lists: List[Dict[str, Any]] = []
        sections: List[Dict[str, Any]] = []
        for key, value in evidence.items():
            label = cls._humanize_key(key)
            if isinstance(value, dict):
                sections.append({"title": label, "block": cls._evidence_block(value, depth + 1)})
            elif (
                isinstance(value, list) and value and all(isinstance(item, dict) for item in value)
            ):
                tables.append(cls._evidence_table(label, value))
            elif isinstance(value, list):
                lists.append(
                    {"title": label, "items": [cls._evidence_cell(item) for item in value]}
                )
            else:
                pairs.append({"label": label, "value": cls._evidence_cell(value)})
        if not (pairs or tables or lists or sections):
            return {"fallback": cls._evidence_json(evidence)}
        return {
            "pairs": pairs,
            "tables": tables,
            "lists": lists,
            "sections": sections,
        }

    @classmethod
    def _evidence_table(cls, title: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        columns: List[str] = []
        seen: Set[str] = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
        return {
            "title": title,
            "columns": [cls._humanize_key(column) for column in columns],
            "rows": [
                [cls._evidence_cell(row.get(column, "")) for column in columns] for row in rows
            ],
        }

    @classmethod
    def _evidence_cell(cls, value: Any) -> Dict[str, str]:
        if value is None:
            return {"text": "—", "kind": "null"}
        if isinstance(value, bool):
            return {"text": "true" if value else "false", "kind": "bool"}
        if isinstance(value, (int, float)):
            return {"text": str(value), "kind": "number"}
        if isinstance(value, (list, tuple)):
            text = ", ".join(cls._evidence_cell(item)["text"] for item in value) or "—"
            return {"text": text, "full": cls._evidence_json(value), "kind": "text"}
        if isinstance(value, dict):
            text = ", ".join(
                f"{key}={cls._evidence_cell(item)['text']}" for key, item in value.items()
            )
            return {"text": text, "full": cls._evidence_json(value), "kind": "text"}
        rendered = str(value)
        if rendered.startswith("arn:aws:"):
            return {"text": cls._abbrev_arn(rendered), "full": rendered, "kind": "arn"}
        if len(rendered) > cls._EVIDENCE_LONG_STRING_ABBREV:
            return {
                "text": rendered[: cls._EVIDENCE_LONG_STRING_ABBREV - 1] + "…",
                "full": rendered,
                "kind": "text",
            }
        return {"text": rendered, "kind": "text"}

    @staticmethod
    def _evidence_json(value: Any) -> str:
        try:
            return json.dumps(value, indent=2, default=str)
        except TypeError:
            return str(value)

    @staticmethod
    def _humanize_key(key: Any) -> str:
        """Turn ``hardcoded_details`` into ``Hardcoded details``."""
        import html as _html

        s = str(key).replace("_", " ").strip()
        return _html.escape(s[:1].upper() + s[1:]) if s else ""

    @classmethod
    def _abbrev_arn(cls, arn: str) -> str:
        """
        Shorten a Connect / Lambda / etc ARN for on-screen readability.

        Keep the service name and the *last* segment of the resource
        path so the reader can tell what it points at (flow id, function
        name, etc) — the account ID and region live in the tooltip.
        """
        # arn:aws:<svc>:<region>:<acct>:<resource path>
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return arn if len(arn) <= cls._EVIDENCE_ARN_ABBREV else arn[:57] + "\u2026"
        svc = parts[2]
        resource = parts[5]
        tail = resource.rsplit("/", 1)[-1] if "/" in resource else resource
        prefix = resource.rsplit("/", 1)[0] if "/" in resource else ""
        # Show the resource type (e.g. "contact-flow") when it fits.
        if prefix and "/" in prefix:
            resource_type = prefix.rsplit("/", 1)[-1]
            short = f"{svc}:…/{resource_type}/{tail}"
        elif prefix:
            short = f"{svc}:{prefix}/{tail}"
        else:
            short = f"{svc}:{tail}"
        if len(short) > cls._EVIDENCE_ARN_ABBREV:
            short = short[: cls._EVIDENCE_ARN_ABBREV - 1] + "\u2026"
        return short

    # Template filter functions
    def _safe_url(self, url: Any) -> str:
        """
        Return ``url`` only if it uses a safe scheme, else ``"#"``.

        Guards ``href`` sinks against ``javascript:``/``data:``/``vbscript:``
        URIs. Allows absolute http(s) links and root-relative paths; anything
        else (including scheme-relative ``//host`` and unparseable values)
        collapses to ``"#"``. Autoescaping still handles quote/entity
        escaping — this only constrains the scheme.
        """
        if not isinstance(url, str):
            return "#"
        candidate = url.strip()
        if "\\" in candidate or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
            return "#"
        if candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        try:
            scheme = urlparse(candidate).scheme.lower()
        except ValueError:
            return "#"
        return candidate if scheme in ("http", "https", "mailto") else "#"

    def _format_datetime(self, dt: datetime) -> str:
        # Format datetime for display in UTC.
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return dt
        return to_utc(dt).strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""

    def _format_duration(self, seconds: float) -> str:
        # Format duration in seconds to human readable format
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            return f"{seconds / 3600:.1f}h"

    def _load_app_asset(self, name: str) -> str:
        """Load an AWS Samples pre-built Cloudscape asset for inline use."""
        path = self._APP_DIR / name
        if not path.exists():
            raise FileNotFoundError(
                f"Report UI bundle not found: {path}. Rebuild it with "
                "`npm ci && npm run build` in frontend/."
            )
        content = path.read_text(encoding="utf-8")
        tag = "script" if name.endswith(".js") else "style"
        return re.sub(rf"</({tag})", r"<\\/\1", content, flags=re.IGNORECASE)

    def _service_icon_data_uri(self) -> Optional[str]:
        try:
            svg = self._SERVICE_ICON.read_bytes()
        except OSError as error:
            self.logger.warning("Service icon not available: %s", error)
            return None
        return "data:image/svg+xml;base64," + base64.b64encode(svg).decode("ascii")
