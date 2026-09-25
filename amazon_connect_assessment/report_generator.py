"""
HTML report generator for Amazon Connect Assessment Tool.

The HTML report is a single self-contained file: a thin Jinja shell that inlines
the pre-built Cloudscape Design System UI (``templates/app/report-app.{js,css}``,
built from ``frontend/``) plus one ``<script type="application/json">`` data island
carrying everything the UI renders. All assessment content travels as JSON data —
never as live markup — except finding markdown, which is rendered server-side by an
XSS-safe markdown-it parser (raw HTML disabled). JSON and CSV exports are produced
directly by this module.
"""

import base64
import dataclasses
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from jinja2 import Environment, TemplateNotFound, select_autoescape

from .models import (
    AssessmentResult,
    CheckStatus,
    Finding,
    Pillar,
    Severity,
    to_utc,
)


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
    Generates HTML, JSON and CSV reports for Amazon Connect assessments.

    The HTML report is built with Cloudscape components (see ``frontend/``):
    executive summary, charts, a filterable findings table with a details split
    panel, and the interactive Caller Journey Map. It works offline — the UI
    bundle, fonts and data are all embedded.
    """

    _APP_DIR = Path(__file__).parent / "templates" / "app"
    _SERVICE_ICON = Path(__file__).parent / "templates" / "assets" / "amazon-connect.svg"

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the report generator.

        Args:
            template_dir: Optional custom template directory path
        """
        self.logger = logging.getLogger("report_generator")
        self.template_env = self._setup_template_environment(template_dir)

    def _setup_template_environment(self, template_dir: Optional[str]) -> Environment:
        """Set up the Jinja2 environment that renders the HTML shell template."""
        from jinja2 import FileSystemLoader, PackageLoader

        if template_dir and os.path.exists(template_dir):
            # Use custom template directory if provided
            loader = FileSystemLoader(template_dir)
            self.logger.info(f"Using custom template directory: {template_dir}")
        else:
            # Use package templates
            try:
                loader = PackageLoader("amazon_connect_assessment", "templates/html")
                self.logger.info("Using package templates")
            except Exception as e:
                self.logger.error(f"Failed to load package templates: {e}")
                # Fallback to relative path for development
                template_path = Path(__file__).parent / "templates" / "html"
                if template_path.exists():
                    loader = FileSystemLoader(str(template_path))
                    self.logger.info(f"Using development templates: {template_path}")
                else:
                    raise TemplateNotFound(f"Could not find templates at {template_path}")

        return Environment(
            loader=loader,
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_html_report(
        self,
        assessment_result: AssessmentResult,
        output_path: Optional[str] = None,
        include_raw_data: bool = False,
    ) -> str:
        """
        Generate a complete HTML report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_path: Optional path to save the report
            include_raw_data: Whether to embed raw JSON data in report (default: False)

        Returns:
            HTML content as string (always returns content, saves to file if output_path provided)
        """
        self.logger.info(f"Generating HTML report for assessment {assessment_result.assessment_id}")

        try:
            # Prepare template context
            context = self._prepare_template_context(assessment_result, include_raw_data)

            # Render the main template
            template = self.template_env.get_template("assessment_report.html")
            html_content = template.render(**context)

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
                "timestamp": to_utc(assessment_result.timestamp).isoformat(),
                "account_id": assessment_result.account_id,
                "region": assessment_result.region,
                "journey_map_entries": self._journey_map_entries(assessment_result),
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
                },
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
                    {
                        "check_id": finding.check_id,
                        "check_name": finding.check_name,
                        "pillar": finding.pillar.value,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "resource_id": finding.resource_id,
                        "resource_type": finding.resource_type,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "structured_remediation": self._serialize_remediation(
                            finding.structured_remediation
                        ),
                        "evidence": finding.evidence,
                        "timestamp": to_utc(finding.timestamp).isoformat(),
                    }
                    for finding in assessment_result.findings
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
            with open(output_path, "w", encoding="utf-8") as f:
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
            ]

            # UUID -> instance_alias, so each row shows a human-readable
            # name alongside the raw UUID rather than the UUID alone
            # (reviewer feedback on the HTML report applies equally here).
            alias_by_id = {
                inst.instance_id: inst.instance_alias
                for inst in assessment_result.instances
                if inst.instance_alias
            }
            instance_ids = [inst.instance_id for inst in assessment_result.instances]

            # Write CSV report
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for finding in assessment_result.findings:
                    # Find the instance for this finding
                    instance_id = self._finding_instance_id(finding, instance_ids) or "unknown"

                    writer.writerow(
                        [
                            assessment_result.assessment_id,
                            to_utc(finding.timestamp).isoformat(),
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
                        ]
                    )

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
        timestamp = to_utc(assessment_result.timestamp).strftime("%Y%m%d_%H%M%S")
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
        self, assessment_result: AssessmentResult, include_raw_data: bool
    ) -> Dict[str, Any]:
        """Build the shell-template context: UI bundle plus the JSON data island."""
        return {
            "report_title": f"Amazon Connect Assessment Tool Report - {assessment_result.account_id}",
            "app_css": self._load_app_asset("report-app.css"),
            "app_js": self._load_app_asset("report-app.js"),
            "report_data_json": self._json_for_script(
                self._build_report_data(assessment_result, include_raw_data)
            ),
        }

    def _build_report_data(
        self, assessment_result: AssessmentResult, include_raw_data: bool
    ) -> Dict[str, Any]:
        """
        Assemble the data contract the Cloudscape report UI renders.

        Everything here must be JSON-serializable. Markdown fields
        (``*_html``) are the only pre-rendered markup, and they come from the
        XSS-safe markdown parser; every other string is rendered as text by React.
        """
        summary = assessment_result.summary
        executive_summary = self._create_executive_summary(assessment_result)
        filter_options = self._default_filters(assessment_result.findings)
        alias_by_id = {
            inst.instance_id: inst.instance_alias
            for inst in assessment_result.instances
            if inst.instance_alias
        }
        instance_ids = [inst.instance_id for inst in assessment_result.instances]
        ordered_findings = [
            finding
            for pillar_findings in self._organize_findings_by_pillar(
                assessment_result.findings
            ).values()
            for finding in pillar_findings
        ]
        metadata = assessment_result.metadata

        return {
            "schema_version": 1,
            "title": "Amazon Connect Assessment Report",
            "generated_at": self._format_datetime(datetime.now(timezone.utc)),
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
            "insights": executive_summary["insights"],
            "recommendations": executive_summary["recommendations"],
            "filters": {
                "default_severity": filter_options["default_severity"],
                "default_status": filter_options["default_status"],
            },
            "pillars": [
                {"id": pillar.value, "label": pillar.value.replace("_", " ").title()}
                for pillar in Pillar
            ],
            "instances": [
                {
                    "id": inst.instance_id,
                    "alias": inst.instance_alias,
                    "display_name": inst.display_name,
                    "status": inst.status,
                    "identity_management_type": inst.identity_management_type,
                    "inbound_calls_enabled": inst.inbound_calls_enabled,
                    "outbound_calls_enabled": inst.outbound_calls_enabled,
                }
                for inst in assessment_result.instances
            ],
            "findings": [
                self._finding_view(index, finding, alias_by_id, instance_ids)
                for index, finding in enumerate(ordered_findings)
            ],
            "journey": {
                # diagram_html is the legacy server-rendered markup; the UI draws
                # from diagram_model["layout"] instead, so don't ship it twice.
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
        """Serialize one finding for the report UI."""
        instance_id = self._finding_instance_id(finding, instance_ids)
        remediation = finding.structured_remediation
        return {
            "key": str(index),
            "check_id": finding.check_id,
            "check_name": finding.check_name,
            "pillar": finding.pillar.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "resource_label": self._render_instance_label(finding.resource_id, alias_by_id),
            "instance": (
                alias_by_id.get(instance_id, instance_id) if instance_id else finding.resource_id
            ),
            "timestamp": self._format_datetime(finding.timestamp),
            "description": finding.description,
            "description_html": self._render_markdown(finding.description),
            "remediation_html": (
                self._render_markdown(finding.remediation) if remediation is None else ""
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
                        {"title": ref.title, "url": self._safe_url(ref.url)}
                        for ref in remediation.references
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

    def _generate_summary_statistics(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        # Generate comprehensive summary statistics for the report
        findings = assessment_result.findings
        summary = assessment_result.summary
        registered_checks = summary.registered_checks
        if registered_checks is None:
            registered_checks = summary.total_checks - summary.journey_findings

        # Pass rate reflects the checks that actually assessed something.
        # Exclude SKIPPED (couldn't evaluate — usually AccessDenied) and
        # NOT_APPLICABLE (evaluated and determined the check doesn't apply)
        # from the denominator, so those don't distort the score.
        evaluated_checks = (
            summary.total_checks - summary.skipped_checks - summary.not_applicable_checks
        )
        pass_rate = (summary.passed_checks / evaluated_checks * 100) if evaluated_checks > 0 else 0

        # Risk score calculation (weighted by severity)
        risk_score = self._calculate_risk_score(findings)

        # Findings by status
        status_breakdown = {
            "passed": summary.passed_checks,
            "failed": summary.failed_checks,
            "error": summary.error_checks,
            "skipped": summary.skipped_checks,
            "not_applicable": summary.not_applicable_checks,
        }

        # Findings by severity (failed only)
        severity_breakdown = {
            "critical": summary.critical_findings,
            "high": summary.high_findings,
            "medium": summary.medium_findings,
            "low": summary.low_findings,
        }

        # Top issues by pillar
        pillar_issues = {}
        for pillar in Pillar:
            pillar_findings = [
                f for f in findings if f.pillar == pillar and f.status == CheckStatus.FAIL
            ]
            pillar_issues[pillar.value] = len(pillar_findings)

        return {
            "total_checks": summary.total_checks,
            "registered_checks": registered_checks,
            "journey_findings": summary.journey_findings,
            "pass_rate": round(pass_rate, 1),
            "risk_score": risk_score,
            "status_breakdown": status_breakdown,
            "severity_breakdown": severity_breakdown,
            "pillar_issues": pillar_issues,
            "instances_assessed": len(assessment_result.instances),
            "execution_time": assessment_result.metadata.execution_time_seconds,
            "has_critical_issues": summary.critical_findings > 0,
            "has_high_issues": summary.high_findings > 0,
        }

    def _calculate_risk_score(self, findings: List[Finding]) -> int:
        # Calculate overall risk score based on failed findings and their severity
        failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]

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
            pillar_findings = [f for f in findings if f.pillar == pillar]
            # Sort by severity (critical first) then by status (failed first)
            pillar_findings.sort(
                key=lambda x: (
                    0 if x.status == CheckStatus.FAIL else 1,  # Failed first
                    ["critical", "high", "medium", "low"].index(x.severity.value),  # Severity order
                )
            )
            organized[pillar.value] = pillar_findings

        return organized

    def _create_executive_summary(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        # Create executive summary with key insights and recommendations
        findings = assessment_result.findings
        summary = assessment_result.summary

        # Key insights
        insights = []

        if summary.critical_findings > 0:
            insights.append(
                {
                    "type": "critical",
                    "message": f"Found {summary.critical_findings} critical security or compliance issues requiring immediate attention.",
                }
            )

        if summary.high_findings > 0:
            insights.append(
                {
                    "type": "warning",
                    "message": f"Identified {summary.high_findings} high-priority issues that should be addressed soon.",
                }
            )

        # Pass rate for insight thresholds — exclude NOT_APPLICABLE and SKIPPED
        # from the denominator so the number reflects checks that actually
        # assessed something.
        evaluated_checks = (
            summary.total_checks - summary.skipped_checks - summary.not_applicable_checks
        )
        pass_rate = (summary.passed_checks / evaluated_checks * 100) if evaluated_checks > 0 else 0

        if pass_rate >= 90:
            insights.append(
                {
                    "type": "success",
                    "message": f"Excellent compliance rate of {pass_rate:.1f}% indicates a well-configured Connect deployment.",
                }
            )
        elif pass_rate >= 75:
            insights.append(
                {
                    "type": "info",
                    "message": f"Good compliance rate of {pass_rate:.1f}% with room for improvement in some areas.",
                }
            )
        else:
            insights.append(
                {
                    "type": "warning",
                    "message": f"Compliance rate of {pass_rate:.1f}% indicates significant configuration issues need attention.",
                }
            )

        # Top recommendations
        recommendations = []

        # Get top failed checks by severity
        failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]
        critical_findings = [f for f in failed_findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in failed_findings if f.severity == Severity.HIGH]

        if critical_findings:
            recommendations.append(
                {
                    "priority": "critical",
                    "title": "Address Critical Security Issues",
                    "description": f"Immediately review and remediate {len(critical_findings)} critical findings to ensure security and compliance.",
                    "findings_count": len(critical_findings),
                }
            )

        if high_findings:
            recommendations.append(
                {
                    "priority": "high",
                    "title": "Resolve High-Priority Configuration Issues",
                    "description": f"Address {len(high_findings)} high-priority findings to improve system reliability and performance.",
                    "findings_count": len(high_findings),
                }
            )

        # Pillar-specific recommendations
        for pillar in Pillar:
            pillar_failed = [f for f in failed_findings if f.pillar == pillar]
            if len(pillar_failed) >= 3:  # Only recommend if significant issues
                pillar_name = pillar.value.replace("_", " ").title()
                recommendations.append(
                    {
                        "priority": "medium",
                        "title": f"Improve {pillar_name}",
                        "description": f"Focus on {pillar_name.lower()} improvements with {len(pillar_failed)} findings to address.",
                        "findings_count": len(pillar_failed),
                    }
                )

        return {
            "insights": insights,
            "recommendations": recommendations[:5],  # Limit to top 5
            "assessment_date": assessment_result.timestamp,
            "instances_count": len(assessment_result.instances),
            "total_findings": len(failed_findings),
        }

    # ------------------------------------------------------------------
    # Caller Journey Map template helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _journey_map_entries(assessment_result: AssessmentResult) -> List[Dict[str, Any]]:
        """Return the raw journey-map entries the engine attached."""
        return getattr(assessment_result, "journey_map_entries", []) or []

    @staticmethod
    def _default_filters(findings: List[Finding]) -> Dict[str, str]:
        """
        Initial findings-table filter: failed findings at the highest failing
        severity (critical, else high). ``"all"`` means no filter on that field.
        """
        failed_severities = {f.severity for f in findings if f.status == CheckStatus.FAIL}
        if Severity.CRITICAL in failed_severities:
            default_severity = Severity.CRITICAL.value
        elif Severity.HIGH in failed_severities:
            default_severity = Severity.HIGH.value
        else:
            default_severity = "all"
        has_failures = any(f.status == CheckStatus.FAIL for f in findings)
        return {
            "default_severity": default_severity,
            "default_status": CheckStatus.FAIL.value if has_failures else "all",
        }

    @staticmethod
    def _finding_instance_id(finding: Finding, instance_ids: List[str]) -> Optional[str]:
        """
        Resolve the Connect instance a finding belongs to.

        Most checks use the instance ID as ``resource_id``. Journey findings use
        the phone number and record the instance in ``evidence["instance_id"]``;
        the prefix match covers resource IDs composed from the instance ID.
        """
        if finding.resource_id in instance_ids:
            return finding.resource_id
        evidence_instance = (finding.evidence or {}).get("instance_id")
        if evidence_instance:
            return str(evidence_instance)
        return next((iid for iid in instance_ids if finding.resource_id.startswith(iid)), None)

    def _save_report(self, html_content: str, output_path: str) -> None:
        # Save HTML report to specified path
        try:
            # Ensure directory exists (only if there's a directory component)
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {str(e)}")
            raise

    @staticmethod
    def _json_for_script(value: Any) -> str:
        """
        Serialize ``value`` for a ``<script type="application/json">`` island.

        ``<``, ``>`` and ``&`` are escaped as JSON unicode escapes so no string
        — including a mixed-case ``</ScRiPt>`` — can close the element early,
        and U+2028/U+2029 are escaped for older JavaScript parsers.
        """
        serialized = json.dumps(value, ensure_ascii=False, default=str)
        return (
            serialized.replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

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

    @classmethod
    def _get_markdown_parser(cls):
        """Return a shared, XSS-safe markdown-it parser."""
        if cls._MARKDOWN_PARSER is None:
            from markdown_it import MarkdownIt

            # ``commonmark`` preset with html=False means the parser
            # renders ``<script>`` in source as literal escaped text,
            # never as an HTML tag. That's the security posture we
            # need since a finding description can interpolate flow-
            # authored strings (queue names, prompt text, attribute
            # names) which we do not fully trust.
            md = MarkdownIt("commonmark", {"html": False, "breaks": False})
            # The rendered HTML is injected into the report as live markup, so
            # links get the same scheme allowlist as remediation references,
            # minus relative URLs (in a file:// report they'd point at the
            # reader's disk). Rejected links render as plain text.
            md.validateLink = cls._is_allowed_markdown_link
            md.add_render_rule("image", cls._render_markdown_image)
            md.add_render_rule("link_open", cls._render_markdown_link_open)
            cls._MARKDOWN_PARSER = md
        return cls._MARKDOWN_PARSER

    @staticmethod
    def _is_allowed_markdown_link(url: str) -> bool:
        """Allow only absolute http(s) and mailto URLs in finding markdown."""
        candidate = url.strip()
        if candidate.startswith("//"):
            return False
        try:
            scheme = urlparse(candidate).scheme.lower()
        except ValueError:
            return False
        return scheme in ("http", "https", "mailto")

    @staticmethod
    def _render_markdown_image(renderer: Any, tokens: Any, idx: int, options: Any, env: Any) -> str:
        """Render images as their alt text: the report never fetches remote content."""
        from markdown_it.common.utils import escapeHtml

        token = tokens[idx]
        return escapeHtml(renderer.renderInlineAsText(token.children or [], options, env))

    @staticmethod
    def _render_markdown_link_open(
        renderer: Any, tokens: Any, idx: int, options: Any, env: Any
    ) -> str:
        """Open links in a new tab so following one doesn't navigate away from the report."""
        tokens[idx].attrSet("target", "_blank")
        tokens[idx].attrSet("rel", "noopener noreferrer")
        return renderer.renderToken(tokens, idx, options, env)

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
        return cls._get_markdown_parser().render(text)

    # ------------------------------------------------------------------
    # Evidence view
    # ------------------------------------------------------------------
    #
    # Checks stash raw diagnostics on ``Finding.evidence`` — dicts of
    # scalars, lists of dicts, ARNs, nested dicts. Dumping that as one JSON
    # blob is unreadable once evidence grows past a handful of fields, so
    # this turns it into a structure the UI renders with Cloudscape
    # components: key-value pairs for scalars, a table per list-of-dicts key
    # (columns = union of row keys), lists for list-of-scalars, and nested
    # sections for dict values. ARN-shaped and very long values are
    # abbreviated with the full value kept alongside for a hover tooltip.

    _EVIDENCE_ARN_ABBREV = 60
    _EVIDENCE_LONG_STRING_ABBREV = 100
    # Nested evidence deeper than this renders as JSON rather than more
    # nested sections — no check produces anything close to it.
    _EVIDENCE_MAX_DEPTH = 4

    @classmethod
    def _evidence_view(cls, evidence: Any) -> Optional[Dict[str, Any]]:
        """Structure a Finding's evidence for the report UI (``None`` when empty)."""
        if not evidence:
            return None
        if not isinstance(evidence, dict):
            # A check may have stashed a non-dict for legacy reasons.
            return {"fallback": cls._evidence_json(evidence)}
        return cls._evidence_block(evidence, depth=0)

    @classmethod
    def _evidence_block(cls, evidence: Dict[str, Any], depth: int) -> Dict[str, Any]:
        """Split a dict into pairs / tables / lists / nested sections."""
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
            elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                tables.append(cls._evidence_table(label, value))
            elif isinstance(value, list):
                lists.append({"title": label, "items": [cls._evidence_cell(v) for v in value]})
            else:
                pairs.append({"label": label, "value": cls._evidence_cell(value)})
        if not (pairs or tables or lists or sections):
            return {"fallback": cls._evidence_json(evidence)}
        return {"pairs": pairs, "tables": tables, "lists": lists, "sections": sections}

    @classmethod
    def _evidence_table(cls, title: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Table for a list of dicts. Column order = keys of the first row, then
        any additional keys a later row introduces (in insertion order).
        """
        columns: List[str] = []
        seen: set = set()
        for row in rows:
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    columns.append(k)
        return {
            "title": title,
            "columns": [cls._humanize_key(c) for c in columns],
            "rows": [[cls._evidence_cell(row.get(c, "")) for c in columns] for row in rows],
        }

    @classmethod
    def _evidence_cell(cls, value: Any) -> Dict[str, str]:
        """
        Format a scalar for display: ``{"text", "kind"}`` plus ``"full"`` when
        the text is abbreviated. ``kind`` is one of null / bool / number /
        arn / text.
        """
        if value is None:
            return {"text": "—", "kind": "null"}
        if isinstance(value, bool):
            return {"text": "true" if value else "false", "kind": "bool"}
        if isinstance(value, (int, float)):
            return {"text": str(value), "kind": "number"}
        if isinstance(value, (list, tuple)):
            # Inline mini-list, comma-separated.
            text = ", ".join(cls._evidence_cell(v)["text"] for v in value) or "—"
            return {"text": text, "kind": "text"}
        if isinstance(value, dict):
            # Nested dict inside a cell — render as key=value pairs.
            text = ", ".join(f"{k}={cls._evidence_cell(v)['text']}" for k, v in value.items())
            return {"text": text, "kind": "text"}
        s = str(value)
        if s.startswith("arn:aws:"):
            return {"text": cls._abbrev_arn(s), "full": s, "kind": "arn"}
        if len(s) > cls._EVIDENCE_LONG_STRING_ABBREV:
            return {
                "text": s[: cls._EVIDENCE_LONG_STRING_ABBREV - 1] + "\u2026",
                "full": s,
                "kind": "text",
            }
        return {"text": s, "kind": "text"}

    @staticmethod
    def _evidence_json(value: Any) -> str:
        """Pretty-print JSON as a last resort."""
        try:
            return json.dumps(value, indent=2, default=str)
        except TypeError:
            return str(value)

    @staticmethod
    def _humanize_key(key: Any) -> str:
        """Turn ``hardcoded_details`` into ``Hardcoded details``."""
        s = str(key).replace("_", " ").strip()
        return s[:1].upper() + s[1:] if s else ""

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
        if candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        try:
            scheme = urlparse(candidate).scheme.lower()
        except ValueError:
            return "#"
        return candidate if scheme in ("http", "https", "mailto") else "#"

    def _format_datetime(self, dt: datetime) -> str:
        # Format datetime for display
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
        """
        Read a pre-built report UI asset (``report-app.js`` / ``report-app.css``).

        The bundle is what renders the report, so a missing file is an error
        rather than a silently blank page.
        """
        path = self._APP_DIR / name
        if not path.exists():
            raise FileNotFoundError(
                f"Report UI bundle not found: {path}. Rebuild it with "
                "`npm ci && npm run build` in the frontend/ directory."
            )
        content = path.read_text(encoding="utf-8")
        # The asset is inlined into a <script>/<style> element; make sure no
        # literal end tag inside it can terminate that element early.
        tag = "script" if name.endswith(".js") else "style"
        return re.sub(rf"</({tag})", r"<\\/\1", content, flags=re.IGNORECASE)

    def _service_icon_data_uri(self) -> Optional[str]:
        """Return the bundled Amazon Connect icon as a data URI for the top navigation."""
        try:
            svg = self._SERVICE_ICON.read_bytes()
        except OSError as e:
            self.logger.warning(f"Service icon not available: {e}")
            return None
        return "data:image/svg+xml;base64," + base64.b64encode(svg).decode("ascii")
