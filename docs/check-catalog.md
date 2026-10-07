# Amazon Connect Customer Posture Assessment Tool — Check Catalog

The assessment has **64 canonical controls** in one catalog. The catalog contains
60 `BaseCheck` executors and 4 Journey-backed executors. Every selected control
produces one outcome per assessed Amazon Connect Customer instance when the
control applies to that execution path.

The catalog has 23 `CONTROL`, 25 `MANUAL_REVIEW`, and 16 `INFORMATIONAL`
records. The pillar totals are Security 19, Resilience 18, Cost Optimization 16,
Operational Excellence 8, and Performance Efficiency 3.

Run `amazon-connect-assessment --list-checks` to see the controls selected from
this catalog after configuration and CLI filters. Journey-backed controls
appear in that output and use the same filters as BaseCheck controls.

## Status and disposition

`CheckStatus` describes what happened when the executor ran:

- **Pass**: evaluation completed and did not find the control's root condition.
- **Fail**: evaluation completed and found the root condition.
- **Not Applicable**: evaluation completed, but the control did not apply to the
  instance. This result is excluded from the scored-control denominator.
- **Skipped**: evaluation could not complete because evidence, permission, or a
  stable resource state was unavailable. Partial evidence is retained.
- **Error**: an unexpected execution failure occurred. Treat this as an
  unevaluated result and investigate the error.

Disposition describes how to interpret that outcome. It is separate from
`CheckStatus`:

- **CONTROL**: a pass or fail can affect posture scoring.
- **MANUAL_REVIEW**: the result identifies a review candidate. It does not prove
  that a defect, risk, or savings opportunity exists.
- **INFORMATIONAL**: the result is inventory or context. It does not assert a
  required change.

Only `CONTROL` records with `Pass` or `Fail` enter the score. The numerator is
passed controls. The denominator is passed controls plus failed controls.
Skipped controls and errors are unevaluated. Not Applicable records,
manual-review records, and informational records do not enter the denominator.
A report with no scored controls shows **Not scored**, not 100%.

## Canonical identity and evidence contract

Each catalog record owns one canonical control ID and one canonical root
condition. A root condition cannot belong to two controls. Each emitted outcome
uses the canonical ID, even when a user selected the control through a legacy
alias.

`journey-sec-001` and `journey-cost-001` remain accepted as input aliases for
backward compatibility:

- `journey-sec-001` resolves to `sec-flow-auth-001`.
- `journey-cost-001` resolves to `cost-containment-001`.

The aliases are never emitted in findings, `--list-checks`, JSON, CSV, or the
catalog. `journey-res-001` and `journey-scope-001` are canonical IDs.

Each outcome carries the catalog's pillar, default severity, disposition, and
methodology. The methodology fields are:

- **reason**: why the question is assessed;
- **evidence source**: the API, configuration, or path evidence inspected;
- **proof limitations**: what the evidence cannot establish;
- **developer/admin meaning**: how to interpret the result;
- **verification criteria**: what closes the control or review;
- optional **responsible function** and **primary lens reference**.

This evidence contract distinguishes measured proof from review candidates and
inventory. A `Fail` on a manual-review record remains a candidate for human
validation. A `Pass` on an informational record means inventory completed.

## Unified catalog

### Security — 19 controls

| Control ID | Name | Severity | Disposition | Executor |
|---|---|---|---|---|
| `security-iam-001` | IAM Service Role Presence and ARN Format | Critical | Control | BaseCheck |
| `security-data-001` | User Security Profile Assignment | Medium | Control | BaseCheck |
| `sec-iam-deep-001` | IAM Service Role Policy Inspection | High | Control | BaseCheck |
| `sec-storage-001` | Instance Storage Encryption Check | High | Control | BaseCheck |
| `sec-origins-001` | Approved Origins / CCP Access Control Check | High | Manual Review | BaseCheck |
| `sec-cloudtrail-001` | CloudTrail Connect Management Write-Event Coverage | High | Control | BaseCheck |
| `sec-federation-001` | Identity Federation / MFA Check | Low | Informational | BaseCheck |
| `sec-profile-audit-001` | Security Profile Permissions Audit | High | Manual Review | BaseCheck |
| `ai-ops-guardrail-001` | Q in Connect AI Guardrail Coverage | High | Control | BaseCheck |
| `ai-ops-encryption-001` | Q in Connect Customer-Managed Key Encryption | Medium | Manual Review | BaseCheck |
| `sec-lex-convlogs-001` | Lex Conversation Log Encryption | Medium | Control | BaseCheck |
| `sec-prompt-inject-001` | Potential Unsafe Dynamic Content in Prompts | Medium | Manual Review | BaseCheck |
| `sec-lambda-validation-001` | Lambda Branch Default Fallback Review | Medium | Manual Review | BaseCheck |
| `sec-toll-fraud-001` | External Transfer Toll Fraud Risk | Critical | Manual Review | BaseCheck |
| `sec-sensitive-data-001` | Sensitive Data in Contact Attributes | High | Manual Review | BaseCheck |
| `sec-pii-prompts-001` | PII Exposure in Voice Prompts | High | Manual Review | BaseCheck |
| `sec-excessive-agency-001` | Excessive Agency / Lambda Identity-Policy Scope | High | Control | BaseCheck |
| `sec-flow-auth-001` | Contact Flow Authentication Pattern | Low | Manual Review | Journey |
| `cx-personalization-001` | Personalization & Transfer Analysis | Low | Informational | BaseCheck |

`sec-storage-001` returns PASS only when every returned destination has verified encryption
and every storage-type read completes. A failed read or a Kinesis stream destination whose
encryption was not inspected returns SKIPPED; an observed unencrypted destination returns
FAIL. If no storage configuration is returned, the control is not applicable.

### Resilience — 18 controls

| Control ID | Name | Severity | Disposition | Executor |
|---|---|---|---|---|
| `ai-ops-cross-region-001` | Bedrock Cross-Region Inference Availability | Low | Informational | BaseCheck |
| `res-quota-config-001` | Configuration Object Quota Utilization | Medium | Control | BaseCheck |
| `res-quota-headroom-001` | Concurrent Calls Quota Headroom | High | Control | BaseCheck |
| `res-quota-growth-001` | Call Volume Growth Against Quota | Medium | Control | BaseCheck |
| `res-acgr-config-001` | Amazon Connect Global Resiliency Configuration | Low | Informational | BaseCheck |
| `res-acgr-identity-001` | ACGR Identity Management (SAML required) | High | Control | BaseCheck |
| `res-acgr-tdg-status-001` | ACGR Traffic Distribution Group Status | High | Control | BaseCheck |
| `res-acgr-traffic-dist-001` | ACGR Traffic Distribution Inventory | High | Informational | BaseCheck |
| `res-acgr-failover-test-001` | ACGR Failover Testing Evidence | High | Control | BaseCheck |
| `res-acgr-numbers-001` | ACGR Phone Number Binding | High | Manual Review | BaseCheck |
| `res-cloudwatch-001` | CloudWatch Alarm Coverage | High | Control | BaseCheck |
| `res-carrier-diversity-001` | Phone Number Carrier Diversity | Medium | Informational | BaseCheck |
| `res-hardcoded-routing-001` | Hardcoded Routing Configuration | Low | Informational | BaseCheck |
| `res-lambda-dependency-001` | Lambda Error Routing Completeness | Medium | Control | BaseCheck |
| `res-acxd-error-routing-001` | Agentic CX Error and Idle-Timeout Routing | High | Control | BaseCheck |
| `res-flow-errors-001` | Non-Lambda Error Routing Completeness | High | Control | BaseCheck |
| `res-flow-loops-001` | Contact Flow Loop Detection | Medium | Control | BaseCheck |
| `journey-res-001` | Dead-End Caller Path | High | Control | Journey |

### Cost Optimization — 16 controls

| Control ID | Name | Severity | Disposition | Executor |
|---|---|---|---|---|
| `cost-unused-001` | Unused Resources Check | Low | Manual Review | BaseCheck |
| `cost-inefficient-001` | Inefficient Resource Allocation Check | Medium | Manual Review | BaseCheck |
| `cost-oversized-001` | Oversized Configuration Check | Low | Manual Review | BaseCheck |
| `cost-usage-metrics-001` | CloudWatch Usage Metrics Analysis | Medium | Manual Review | BaseCheck |
| `cost-unused-numbers-001` | Claimed Phone Number Inventory | Medium | Informational | BaseCheck |
| `cost-premium-features-001` | Premium Feature Enablement Inventory | Low | Informational | BaseCheck |
| `cost-hours-mismatch-001` | Hours of Operation Inventory | Low | Informational | BaseCheck |
| `ai-ops-model-cost-001` | AI Prompt Model Cost Review | Low | Manual Review | BaseCheck |
| `cost-containment-001` | Self-Service Containment Analysis | High | Manual Review | Journey |
| `cost-wait-time-001` | Queue Callback Availability Review | High | Manual Review | BaseCheck |
| `cost-occupancy-001` | Agent Occupancy Monitoring Guidance | Medium | Informational | BaseCheck |
| `cost-fcr-001` | Returning Caller Pattern Review | Medium | Manual Review | BaseCheck |
| `cost-acw-001` | After-Contact-Work Monitoring Guidance | Low | Informational | BaseCheck |
| `cost-data-continuity-001` | IVR-to-Agent Data Continuity | Medium | Manual Review | BaseCheck |
| `cost-self-service-tier-001` | Legacy DTMF-Only Self-Service | Low | Manual Review | BaseCheck |
| `journey-scope-001` | Dormant Flows Detected | Low | Manual Review | Journey |

### Operational Excellence — 8 controls

| Control ID | Name | Severity | Disposition | Executor |
|---|---|---|---|---|
| `ops-logging-001` | Contact Flow Logging | High | Control | BaseCheck |
| `ops-early-media-001` | Early Media for Outbound Calls | Low | Manual Review | BaseCheck |
| `ops-auto-resolve-001` | SSML Voice Locale Fallback (`AUTO_RESOLVE_BEST_VOICES`) | Low | Informational | BaseCheck |
| `ai-ops-kb-sync-001` | Q in Connect Knowledge Base Lifecycle and Ingestion Health | Medium | Control | BaseCheck |
| `ai-ops-bedrock-logging-001` | Bedrock Model Invocation Logging | Medium | Control | BaseCheck |
| `ops-acxd-handoff-001` | Agentic CX Handoff Inventory | Low | Informational | BaseCheck |
| `ops-acxd-escalation-001` | Agentic CX Escalation Path Review | Medium | Manual Review | BaseCheck |
| `ops-unreachable-blocks-001` | Unreachable Contact Flow Blocks | Low | Manual Review | BaseCheck |

### Performance Efficiency — 3 controls

| Control ID | Name | Severity | Disposition | Executor |
|---|---|---|---|---|
| `perf-lambda-count-001` | Lambda Usage Structure Review | Low | Informational | BaseCheck |
| `perf-sequential-lambda-001` | Sequential Lambda Invocations | Low | Manual Review | BaseCheck |
| `perf-flow-complexity-001` | Contact Flow Structure Review | Low | Informational | BaseCheck |

## Connect-side Agentic CX execution

The three Agentic CX controls inspect reachable
`ConnectParticipantWithAgenticCX` actions in parsed customer-authored flows.
They exclude Amazon default sample flows and aggregate one outcome per control
and instance. `ops-acxd-handoff-001` inventories the reachable Connect-side
workspace, application, and alias references plus optional feature presence and
context-variable names; values are never retained. `ops-acxd-escalation-001`
checks whether a reachable handoff has an authored condition operand whose
case-insensitive exact token is `Escalation`. It reports missing exact tokens as
manual-review candidates because the token does not prove that escalation
succeeded or reached an agent at runtime, and human escalation depends on
workload intent.
`res-acxd-error-routing-001` requires `InputTimeLimitExceeded` and
`NoMatchingError` routes. `NoMatchingCondition` is reported as the readable
**Other outcome** branch but does not substitute for either required resilience
route.

The evidence retains flow/action identity, configured field names, and raw route
tokens, but never context-variable values. Optional `ContextVariables`,
`SpeechRecognitionConfiguration`, and `AudioFillerConfiguration` are inventoried
without becoming required. A known defect fails even if another flow is
incomplete. A clean incomplete scan is Skipped. Not Applicable is emitted only
when complete analysis finds no reachable Agentic CX action. These controls call
no Agentic CX APIs and cannot prove anything about application prompts, tools,
logic, deployment, or runtime outcomes.

## Hardcoded routing execution

`res-hardcoded-routing-001` requires parsed customer-authored flow content, so
`--skip-flow-analysis` excludes it from the selected execution plan. When flow
analysis is enabled, it is an informational inventory control: a complete empty
flow inventory reports `Pass` with zero observed literals, while observed
literals remain review context rather than a scored failure. Incomplete parsing
reports `Skipped` with the partial inventory retained. AWS sample flows are
excluded and phone-number values are masked.

## Journey-backed execution

The four Journey-backed controls use phone-number and contact-flow topology, but
they are catalog records rather than a second findings model:

- `sec-flow-auth-001` evaluates authentication patterns under Security.
- `cost-containment-001` evaluates self-service opportunities under Cost
  Optimization.
- `journey-res-001` evaluates structural dead ends under Resilience.
- `journey-scope-001` inventories flows outside the phone-anchored static
  closure under Cost Optimization.

The journey pipeline resolves phone-number associations, builds an instance-wide
flow graph, and performs bounded static path enumeration with a maximum depth of
50, 200 paths per phone number, and 5,000 paths per instance. Path-local cycle
edges are pruned, while the separate iterative structural closure still reaches
every statically resolvable node. A depth, path, or step cap, dynamic target, or
unresolved flow reference marks enumeration incomplete. These limits prevent an
exhaustive-runtime claim: a known structural defect can still fail, while clean
but incomplete evidence is not treated as proof that every possible route is
safe. The pipeline emits one aggregate outcome for each selected Journey-backed
control. `--skip-flow-analysis` excludes all controls that require flow analysis,
including these four.

## Filter behavior

Selection uses AND semantics. The tool first applies flow-analysis availability,
then pillar, effective severity, explicit `--checks` inclusion,
`--exclude-checks`, and config `enabled: false` settings. A control must survive
every active filter.

`--checks`, `--exclude-checks`, config keys, and validation accept canonical IDs
and the two legacy aliases described in [Canonical identity and evidence
contract](#canonical-identity-and-evidence-contract). Inputs are normalized and
deduplicated before selection. `--list-checks` displays the unified selected
controls, including Journey-backed controls, with effective severity and
disposition. It never displays an alias. The table above shows catalog default
severities; configuration can override a BaseCheck severity. In this checkout,
`config/assessment_config.yaml` disables `ops-auto-resolve-001` and raises
`cost-unused-001` from Low to Medium.

Examples:

```bash
# List controls selected by the effective configuration without calling AWS
# From the repository root, the bundled config selects 63 of 64 controls
amazon-connect-assessment --list-checks

# Select one BaseCheck control and one Journey-backed control
amazon-connect-assessment --region us-east-1 \
  --checks sec-cloudtrail-001 journey-res-001

# Exclude flow analysis and every flow-dependent control, including
# res-hardcoded-routing-001
amazon-connect-assessment --region us-east-1 --skip-flow-analysis
```

## Permissions and closure

[`docs/iam-policy-template.json`](iam-policy-template.json) is the canonical
read-permission document. The equivalent deployable template is
[`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`](../cloudformation/AmazonConnectSelfAssessmentPolicy.yaml).
A denied or incomplete read produces `Skipped`, not an unqualified pass.

Use each record's methodology in the HTML, JSON, or CSV report when validating a
result. Control evidence can support posture closure. Manual-review evidence
identifies what a person must verify. Informational evidence records inventory
and planning context.
