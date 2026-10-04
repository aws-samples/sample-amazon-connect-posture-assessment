# Documentation Index

This directory contains the current user guides, implementation references, and
design records for the Amazon Connect Customer Posture Assessment Tool.

## Table of Contents

- [Start Here](#start-here)
- [Current Behavior](#current-behavior)
- [AWS Documentation](#aws-documentation)
- [Contributors and Maintainers](#contributors-and-maintainers)
- [Design and Historical Reference](#design-and-historical-reference)
- [Source-of-Truth Rules](#source-of-truth-rules)

## Start Here

- [Project README](../README.md) — installation, AWS access, common CLI usage, and report overview.
- [User guide](user-guide.md) — detailed installation, AWS access, CLI usage, report operations, and CI/CD.
- [Deployment architecture](architecture.svg) — rendered deployment diagram;
  [editable Draw.io source](architecture.drawio).
- [Configuration guide](configuration.md) — YAML/JSON settings, precedence, output naming, and execution tuning.
- [Troubleshooting guide](troubleshooting.md) — installation, credentials, permissions, runtime, and report failures.

## Current Behavior

- [Check catalog](check-catalog.md) — all 64 canonical controls, dispositions, methodology, executor ownership, aliases, and unified filter behavior.
- [Report formats](report-formats.md) — HTML, JSON, CSV, and failed-control-only ASFF contracts, including the scored-control denominator.
- [Performance guide](performance-optimization.md) — parallel execution, retry tuning, and journey-scoring bounds.
- [IAM policy template](iam-policy-template.json) — canonical read permissions for the assessment.

## AWS Documentation

- [Amazon Connect Customer overview](https://docs.aws.amazon.com/connect/latest/adminguide/what-is-amazon-connect.html) — current product name and contact center scope.
- [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) — the framework that informs the assessment checks.
- [Amazon Connect Customer API reference](https://docs.aws.amazon.com/connect/latest/APIReference/Welcome.html) and [AWS CLI `connect` commands](https://docs.aws.amazon.com/cli/latest/reference/connect/index.html) — technical identifiers and operations.

## Contributors and Maintainers

- [Development guide](development-guide.md) — setup, tests, code quality, architecture, and adding checks.
- [Threat model](threat-model.md) — current trust boundaries, attack surfaces, and mitigations.

## Design and Historical Reference

These documents describe design intent, decisions, or broader future capabilities. They
should not override the current behavior documented in the check catalog and
configuration guide.

- [Health-check framework](design/health-check-framework.md) — broader customer health-review model and proposed roadmap.
- [Same-account IAM CloudFormation spec](design/specs/same-account-iam-cloudformation-spec.md) — implementation record and design rationale.

## Source-of-Truth Rules

- Runtime behavior: source code and tests.
- Canonical controls, aliases, disposition, and methodology:
  `checks/control_registry.py`, `checks/registration.py`, and the
  [check catalog](check-catalog.md).
- Scoring: `score_policy.py`. Only passed and failed `CONTROL` records enter
  the scored-control denominator.
- Configuration keys and precedence: [configuration guide](configuration.md).
- Required read permissions: `iam_permissions.py`, [IAM policy template](iam-policy-template.json), and the consistency tests.
- Design proposals: documents under `design/`; they may describe capabilities not yet implemented.
