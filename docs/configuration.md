# Amazon Connect Customer Posture Assessment Tool Configuration

[Back to the documentation index](README.md)

This is the canonical configuration reference for the Amazon Connect Customer Posture Assessment Tool.
The sample configuration files remain in `config/`; `config/README.md` points here.
Configuration controls assessment behavior, check selection, execution settings, and
report generation.

## Table of Contents

- [Configuration File Formats](#configuration-file-formats)
- [Main Configuration Structure](#main-configuration-structure)
  - [Global Settings](#global-settings)
  - [AWS Configuration](#aws-configuration)
  - [Output Configuration](#output-configuration)
  - [Pillar and Severity Filtering](#pillar-and-severity-filtering)
  - [Individual Check Configuration](#individual-check-configuration)
- [Performance Configuration](#performance-configuration)
  - [Parallel Execution and Network Resilience Settings](#parallel-execution-and-network-resilience-settings)
- [Using Configuration Files](#using-configuration-files)
  - [Command Line Usage](#command-line-usage)
  - [Configuration File Search Order](#configuration-file-search-order)
  - [Environment Variable Overrides](#environment-variable-overrides)
  - [Other top-level keys](#other-top-level-keys)
- [Configuration Examples](#configuration-examples)
  - [Minimal Configuration](#minimal-configuration)
  - [Development Configuration](#development-configuration)
  - [Production Configuration](#production-configuration)
- [Check Configuration Options](#check-configuration-options)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
- [Configuration Validation](#configuration-validation)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Configuration Loading](#debug-configuration-loading)

## Configuration File Formats

The tool supports both JSON and YAML configuration formats:

- `assessment_config.json` - JSON format configuration
- `assessment_config.yaml` - YAML format configuration (recommended for readability)
- `performance_config.yaml` - Example of the performance-tuning keys. **Note:** this file is not loaded on its own — the tool only auto-discovers/loads `assessment_config.{yaml,json}` (or the file passed to `--config`). Put these keys under `global_settings` in your main config, or pass most of them as CLI flags (`--max-workers`, `--batch-size`, `--sequential`, retry flags).

## Main Configuration Structure

### Global Settings

Global settings affect the overall assessment execution:

```yaml
global_settings:
  timeout: 300                    # Timeout in seconds for AWS API calls
  max_retry_attempts: 5           # Maximum retry attempts for network operations
  retry_base_delay: 1.0          # Base delay between retries in seconds
  retry_max_delay: 60.0          # Maximum delay between retries in seconds
  enable_rate_limiting: true      # Enable automatic rate limiting for AWS API calls
  parallel_execution: true        # Enable parallel check execution
  max_workers: null              # Maximum worker threads (null = auto-detect)
  batch_size: 10                 # Number of checks per batch
  log_level: "INFO"              # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### AWS Configuration

Configure AWS credentials and region settings:

```yaml
aws:
  region: null                   # AWS region
  profile: null                  # AWS profile
```

Region precedence: `--region` > `AWS_REGION` > `aws.region` >
`AWS_DEFAULT_REGION` > `us-east-1`. `AWS_REGION` overrides `aws.region` even
when the config file sets it. The resolved region is passed explicitly to
boto3, so a region configured in an AWS profile is not used.

Profile precedence: `--profile` > `AWS_PROFILE` > `aws.profile`. With no
profile, the standard boto3 credential chain applies.

### Output Configuration

Control report generation and output:

```yaml
output:
  format: ['html']               # Output formats: html, json, csv, asff
  directory: './reports'         # Output directory
  filename_template: 'connect_assessment_{timestamp}_{account_id}'
                                  # Tokens: {timestamp}, {account_id}, {region}, {assessment_id}
                                  # Filename only; directory separators are not allowed
```

The CLI `--output-dir`, `--output-format`, and `--output-filename` flags override
these values only when explicitly supplied. If `--output-format` is omitted, the
configured `output.format` value is preserved. When neither CLI nor configuration
specifies a format, HTML is generated.

### Pillar and Severity Filtering

Control which canonical catalog records are selected. Pillar and severity
filters apply to both BaseCheck and Journey-backed controls:

```yaml
# Enable specific AWS Well-Architected Framework pillars
enabled_pillars:
  - "resilience"
  - "security"
  - "cost_optimization"

# Enable specific severity levels
enabled_severities:
  - "critical"
  - "high"
  - "medium"
  - "low"
```

### Individual Check Configuration

Configure whether specific checks are enabled and override their severity:

```yaml
checks:
  security-iam-001:
    enabled: true                    # Enable/disable this check
    severity: "critical"             # Override default severity
```

The configuration loader applies `enabled` and `severity` to the unified
selection. Config keys may use canonical IDs. The legacy keys
`journey-sec-001` and `journey-cost-001` are also accepted and normalize to
`sec-flow-auth-001` and `cost-containment-001`; reports never emit the aliases.
Journey-backed controls use catalog severity, so a configured severity override
for one is ignored with a warning. `--list-checks` shows all selected canonical
controls, including Journey-backed controls, with disposition and effective
severity.

The `parameters`, `remediation_template`, and `description` keys are not applied by
the current check registry and should not be used as if they changed execution.
The sample files preserve examples of these unsupported fields under the
top-level `future_only.check_overrides` section; that section is intentionally
ignored at runtime.

## Performance Configuration

`performance_config.yaml` illustrates the settings for optimizing assessment execution. As noted above, it is **not** auto-loaded as a standalone file — place these keys under `global_settings` in your main `assessment_config.yaml`, or pass them as CLI flags. The keys below are the ones the tool actually reads:

### Parallel Execution and Network Resilience Settings

```yaml
global_settings:
  parallel_execution: true
  max_workers: null              # Auto-detect based on CPU count
  batch_size: 10
  max_retry_attempts: 5
  retry_base_delay: 1.0
  retry_max_delay: 60.0
  timeout: 300
  enable_rate_limiting: true
```

These settings are read from `global_settings`; the standalone
`parallel_execution` and `network_resilience` blocks are not loaded.

## Using Configuration Files

### Command Line Usage

```bash
# Run assessment with custom configuration
amazon-connect-assessment --config config/assessment_config.yaml

# Run with JSON configuration
amazon-connect-assessment --config config/assessment_config.json

# Override specific settings via CLI
amazon-connect-assessment --config config/assessment_config.yaml --region us-west-2 --max-workers 8
```

CLI flags override configuration values only when explicitly supplied. For example,
omitting `--output-format` preserves `output.format` from the configuration file.

### Configuration File Search Order

The tool searches for configuration files in this order:
1. File specified with `--config` option
2. `./assessment_config.yaml`
3. `./assessment_config.json`
4. `./config/assessment_config.yaml`
5. `./config/assessment_config.json`
6. `~/.amazon-connect-assessment/config.yaml`
7. `~/.amazon-connect-assessment/config.json`

### Environment Variable Overrides

Environment variables override config-file values; CLI flags override both.

| Variable | Config key |
|---|---|
| `CONNECT_ASSESSMENT_LOG_LEVEL` | `global_settings.log_level` |
| `CONNECT_ASSESSMENT_TIMEOUT` | `global_settings.timeout` |
| `CONNECT_ASSESSMENT_MAX_RETRY_ATTEMPTS` | `global_settings.max_retry_attempts` |
| `CONNECT_ASSESSMENT_RETRY_BASE_DELAY` | `global_settings.retry_base_delay` |
| `CONNECT_ASSESSMENT_RETRY_MAX_DELAY` | `global_settings.retry_max_delay` |
| `CONNECT_ASSESSMENT_PARALLEL_EXECUTION` | `global_settings.parallel_execution` (`true`, `1`, `yes`, or `on` enable it; any other value disables it) |
| `CONNECT_ASSESSMENT_MAX_WORKERS` | `global_settings.max_workers` |
| `CONNECT_ASSESSMENT_BATCH_SIZE` | `global_settings.batch_size` |
| `CONNECT_ASSESSMENT_OUTPUT_DIR` | `output.directory` |
| `AWS_REGION` | `aws.region` |
| `AWS_PROFILE` | `aws.profile` |

Numeric values that cannot be parsed are silently ignored, and the existing
value is kept. For example, `CONNECT_ASSESSMENT_TIMEOUT=abc` leaves the timeout
at its configured value.

```bash
export CONNECT_ASSESSMENT_LOG_LEVEL=DEBUG
export CONNECT_ASSESSMENT_TIMEOUT=600
export CONNECT_ASSESSMENT_MAX_WORKERS=16
export AWS_REGION=us-east-1
export AWS_PROFILE=my-profile
```

### Other top-level keys

- `skip_flow_analysis: true` has the same effect as `--skip-flow-analysis`.
- Checkpoints are written to `~/.amazon-connect-assessment/checkpoints`
  (created `0700`) unless `--checkpoint-dir` names another directory.

## Configuration Examples

### Minimal Configuration

```yaml
# Enable only critical security checks
enabled_pillars:
  - "security"
enabled_severities:
  - "critical"
```

This selects the two Critical security controls. `sec-storage-001` has a High
default severity, so it is excluded by this filter.

### Development Configuration

```yaml
# Development settings with verbose logging
global_settings:
  log_level: "DEBUG"
  timeout: 600
  parallel_execution: false  # Disable for easier debugging
  max_workers: 1

# Include all pillars and severity levels for comprehensive testing
enabled_pillars:
  - "resilience"
  - "security"
  - "cost_optimization"
  - "operational_excellence"
  - "performance_efficiency"
enabled_severities:
  - "critical"
  - "high"
  - "medium"
  - "low"
```

### Production Configuration

```yaml
# Production settings optimized for performance
global_settings:
  timeout: 300
  max_retry_attempts: 3
  parallel_execution: true
  max_workers: 16
  batch_size: 20
  log_level: "INFO"

# Focus on critical and high severity issues
enabled_severities:
  - "critical"
  - "high"

# Configure output for multiple formats
output:
  format: ["html", "json", "csv", "asff"]
  directory: "/var/reports/connect-assessments"

# Caller journey scoring tuning (path discovery; does not change HTML map entries)
journey_map:
  max_paths_per_did: 200     # Max paths per phone number (reduce for speed)
  max_depth: 50              # Max DFS depth per path
  traffic_lookback_days: 30  # Usage window in days, 1-34 (API limit: under 35)
```

### Channel classification

A flow's own metadata cannot tell you which channel uses it. `ContactFlowType`
describes a position in the contact lifecycle (`CONTACT_FLOW`,
`CUSTOMER_QUEUE`, `AGENT_WHISPER`, …) and carries no channel dimension, and a
single flow legitimately serves voice, chat and task at once. So the assessment
resolves channel empirically, using `connect:GetMetricDataV2` to count contacts
started per flow per channel (`VOICE`, `CHAT`, `TASK`, `EMAIL`) over
`traffic_lookback_days`.

This also determines tiering:

| Tier | Meaning | Journey enumeration |
|---|---|---|
| 1 | An entry point's flow, or reachable from one: phone, SMS, WhatsApp, email, or an *observed* entry flow | Yes, scored with the entry's channel rules |
| 2 | A queue, hold, whisper, or transfer flow that started contacts but is not reachable from any entry | No — listed in `journey-scope-001` |
| 3 | Not reachable from any entry and no contacts in the window | No — dormant-flow review |

An *observed* entry flow is how web chat, tasks, and API-started contacts are
found: they have no control-plane association (`StartChatContact` takes the
flow ID from the caller), so a contact flow that started contacts on a channel
without being reachable from that channel's associations is treated as an entry
point for it. Tier 2 is therefore only ever queue, hold, whisper, or transfer
flows, which run inside other contacts' journeys rather than starting one.

The usage window ends one minute before the run, so contacts from earlier the
same day count. Metrics are only requested for flows whose tier they can change
(entry-capable flows, and flows no association reaches).

If an association or phone-number lookup fails, `journey-scope-001` names the
failed discovery and reports SKIPPED rather than "no dormant flows", because
real entry flows may then look unreachable.

`traffic_lookback_days` must be an integer from 1 to 34, because
`GetMetricDataV2` with a `TOTAL` interval requires a window under 35 days.
Out-of-range values are clamped and invalid ones fall back to 30, each with a
warning.

Without the `connect:GetMetricDataV2` permission, or if any metrics request
fails, the run discards the usage data rather than classifying on partial
counts. Tiering then falls back to reachability alone, and `journey-scope-001`
says its dormant labels are reachability-only.

The HTML Customer Journey Map renders every discovered entry point — phone,
SMS, and WhatsApp numbers, email addresses, and observed entry flows — that
reaches an available contact flow. It has no `top_n` setting. The
`journey_map` values above control the separate journey-scoring pipeline and its
findings. That pipeline performs bounded static enumeration, not exhaustive
runtime exploration: it uses depth 50 and 200 paths per entry point by default,
with a fixed 5,000-path cap per instance. Cycle edges are pruned without reducing
static structural reachability; reached caps, dynamic targets, and unresolved
flow references mark enumeration incomplete.

## Check Configuration Options

### Required Fields

Each entry under `checks:` is keyed by a canonical ID from the 64-control
catalog. The two documented legacy aliases are accepted as keys and normalized
before selection. There is no separate `check_id` field.

### Optional Fields

- `enabled`: Boolean to enable/disable the check (default: true)
- `severity`: Override the default severity level ("critical", "high", "medium", "low")
`parameters`, `remediation_template`, and `description` are not currently
consumed by the check registry.

The following fields are reserved for future support and are not live settings:
`parameters`, `remediation_template`, and `description`. Keep them under
`future_only.check_overrides` if documenting proposed per-check behavior.

## Configuration Validation

The CLI validates local inputs in the effective configuration (defaults, config
file, environment variables, then CLI flags) before contacting AWS.
`--validate-config` performs these local checks and exits; it does not verify
AWS credentials, permissions, or whether a target instance exists. An assessment
run checks those AWS-dependent conditions by calling AWS before executing checks.
Local validation covers:

- Numeric settings: `timeout`, `max_retry_attempts`, and `batch_size` must be
  positive integers, and `max_workers` must be a positive integer or `null`;
  retry delays must be non-negative, with `retry_max_delay >= retry_base_delay`.
- `enable_rate_limiting` and `parallel_execution` must be booleans; `log_level`
  must be `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.
- Pillars, severities, and output formats must be known values.
- `--checks` / `--exclude-checks` IDs must exist in the unified 64-control
  catalog (see `--list-checks`). Canonical IDs and the two backward-compatible
  aliases are accepted. Selection uses AND semantics, and at least one control
  must remain after `--pillars`, `--severity`, `--checks`, `--exclude-checks`,
  `--skip-flow-analysis`, and `enabled: false` entries are applied.
- Unknown control IDs and unsupported keys under the `checks:` config section
  are **not** validation errors. They are ignored with a warning during an
  assessment run, and `--validate-config` suppresses that warning, so a typo in
  a `checks:` key can pass validation silently. Confirm the effective selection
  with `--list-checks`.
- The output directory must be a directory, or creatable: its nearest existing parent must
  be a writable directory.
- The filename template may only use `{timestamp}`, `{account_id}`, `{region}`, and
  `{assessment_id}`, and must produce a filename, not a path. Unknown or legacy
  placeholders fail validation before AWS is contacted; they are not rendered
  as literal text or silently ignored.
- `--s3-bucket` must be a valid S3 bucket name; `--diff` must be an existing JSON report;
  `--log-file` must be in an existing, writable directory.
- `--instance-id` must have the syntax of an instance ID (UUID). An assessment
  run checks whether it exists in the target region after contacting AWS.

An assessment run using `--resume-assessment` also requires an existing
checkpoint and cannot combine it with `--no-checkpoints`. `--validate-config`
does not check checkpoint availability.

`--parallel`/`--sequential` and `--verbose`/`--quiet` are mutually exclusive.

## Best Practices

1. **Use YAML format** for better readability and comments
2. **Version control** your configuration files
3. **Test configurations** in development before using in production
4. **Use environment-specific** configurations (dev, staging, prod)
5. **Keep sensitive data** out of configuration files (use environment variables)
6. **Start with defaults** and only override what you need to change
7. **Tune `global_settings.max_workers` and `batch_size`** (or `--max-workers` and `--batch-size`) for large-scale assessments

## Troubleshooting

### Common Issues

1. **File not found**: Ensure the configuration file path is correct
2. **Invalid YAML/JSON**: Use a validator to check file syntax
3. **Unknown check IDs**: `--checks` / `--exclude-checks` reject unknown IDs, but unknown keys under `checks:` are ignored with only a warning. Compare against `--list-checks`
4. **Invalid severity levels**: Use only "critical", "high", "medium", "low"
5. **Invalid pillar names**: Use only "resilience", "security", "cost_optimization", "operational_excellence", "performance_efficiency"
6. **Performance issues**: Adjust `global_settings.max_workers` and `batch_size` in your main config, or use `--max-workers` and `--batch-size`

### Debug Configuration Loading

Print which configuration file was found and the merged effective
configuration (shown even when validation fails):

```bash
amazon-connect-assessment --config config/assessment_config.yaml --show-config
```

Configuration loading itself does not log. Add `-vv` to an assessment run to
see check-registration details, such as warnings for unknown or unsupported
`checks:` entries.
