# Amazon Connect Customer Posture Assessment Tool — Threat Model

This document identifies the security boundaries, trust zones, threat actors, attack surfaces, and mitigations for the Amazon Connect Customer Posture Assessment Tool. It follows the STRIDE framework.

> **Architecture note:** The Amazon Connect Customer Posture Assessment Tool is a
> **command-line tool**. It has no
> listening socket or daemon.

## Table of Contents

- [System overview](#system-overview)
- [Trust zones](#trust-zones)
- [Threat actors](#threat-actors)
- [Attack surfaces and mitigations](#attack-surfaces-and-mitigations)
- [STRIDE summary](#stride-summary)
- [Data flow diagram](#data-flow-diagram)
- [Assumptions](#assumptions)
- [Residual risks](#residual-risks)
- [Recommendations for future hardening](#recommendations-for-future-hardening)

---

## System overview

The Amazon Connect Customer Posture Assessment Tool is a **read-oriented** assessment tool that:
- Runs as a CLI process on a user's workstation, AWS CloudShell, or a CI runner
- Authenticates to AWS using existing credentials (profile, role assumption, or environment variables)
- Uses read-only `List`, `Get`, and `Describe` operations, plus `cloudtrail:LookupEvents`, against Amazon Connect Customer and supporting services
- Produces HTML/JSON/CSV/ASFF reports on the local filesystem
- Optionally (`--s3-output`) creates or hardens the selected S3 report bucket and uploads reports
- Never modifies, creates, or deletes any AWS resource it assesses

The consequential opt-in write path is `--s3-output`. It may create the selected
bucket (by default `amazon-connect-assessment-report-<account-id>`), and it also
applies Block Public Access and versioning and ensures default encryption on an
existing selected bucket before upload. If hardening a bucket it has just created
fails, it attempts to delete that empty bucket. `--s3-bucket` accepts any valid
bucket name, so a bucket named there — including one that is itself in scope for
the assessment — receives the same hardening changes. If the account ID cannot be
resolved, the default name falls back to
`amazon-connect-assessment-report-unknown`; pass `--s3-bucket` in that case.

---

## Trust zones

| Zone | Description | Trust level |
|---|---|---|
| **Z1 — Execution host** | The workstation, CloudShell, or CI runner running the CLI. Has access to AWS credentials, the local filesystem, and report output. | Fully trusted |
| **Z2 — AWS APIs** | Amazon Connect Customer, IAM/STS, CloudTrail, CloudWatch, KMS, Lambda, S3, Lex, Connect AI agents (formerly Amazon Q in Connect), Bedrock, and Service Quotas. Data source and (for `--s3-output`) report sink. | Trusted (authenticated, TLS) |
| **Z3 — Generated reports** | HTML files with embedded JavaScript, plus JSON/CSV/ASFF. Opened directly in a browser or shared. Contain configuration detail, and the HTML and JSON Caller Journey Map data includes claimed phone numbers in full. | Untrusted content (flow names/parameters from AWS could contain payloads); sensitive |
| **Z4 — Contact flow content** | JSON retrieved from the assessed AWS account. Parsed and traversed by the tool. | Untrusted (customer-controlled, potentially adversarial) |

---

## Threat actors

| Actor | Motivation | Access |
|---|---|---|
| **Malicious contact flow author** | Craft flow JSON to exploit the parser, cause DoS, or inject XSS into reports | Controls flow content in the assessed AWS account |
| **Credential thief** | Steal AWS credentials exposed by the tool | Access to the host, log files, or report output |
| **Report recipient** | Trick the assessor by manipulating findings after report generation | Access to the report file or S3 object |

---

## Attack surfaces and mitigations

### AS-1: Contact flow parser and journey mapping

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Deeply nested or circular flow graphs cause stack overflow | Denial of Service | High | All graph traversal is **iterative** (explicit stack), never recursive. Static path enumeration is bounded by default at depth 50 and 200 paths per phone number (configurable through `journey_map.max_depth` and `journey_map.max_paths_per_did`), and by fixed caps of 5,000 paths per instance and 100,000 steps per entry point. Path-local cycle edges are pruned without preventing the separate structural closure from reaching every statically resolvable node. |
| Combinatorial explosion from highly branching flows | Denial of Service | Medium | Depth, per-number path, per-instance path, and step caps bound path enumeration. A reached cap, dynamic target, or unresolved cross-flow reference marks enumeration incomplete; clean partial evidence is not treated as exhaustive proof. |
| Adversarial flow parameters crafted for XSS in reports | Elevation of Privilege | Medium | The static report shell HTML-escapes its title and pins the inline bundle with a CSP hash, assessment data is serialized into a script-safe JSON island, React renders ordinary strings as text, and markdown disables raw HTML. |
| Malformed flow JSON crashes the parser | Denial of Service | Low | Parser validates input type, skips non-dict actions gracefully, and uses `.get()` with defaults throughout. |
| Dynamic attribute references used to confuse graph analysis | Spoofing | Low | Dynamic references are detected and recorded in `dynamic_references` — never followed as if they were static edges. |

### AS-2: AWS credential handling

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Credentials leaked into logs | Information Disclosure | High | Credentials are never logged. Logging references operation names, not parameters containing secrets. |
| Credentials leaked into report output | Information Disclosure | High | Reports contain only findings, metadata (account ID, region), and evidence data. No credential material is serialized. |
| Overly broad permissions on the assessment principal | Elevation of Privilege | Medium | The CloudFormation template (`AmazonConnectSelfAssessmentPolicy.yaml`) creates a customer-managed read-only policy with the actions listed in `iam_permissions.py`; it does not attach AWS managed policies such as `SecurityAudit` or `ViewOnlyAccess`. The policy can be attached to a named role or granted to a user through a group. The tool uses the caller's resolved credentials and does not assume a cross-account role itself. |
| Checkpoint files expose sensitive state | Information Disclosure | Low | The default checkpoint directory (`~/.amazon-connect-assessment/checkpoints`) is created `0o700`; a directory supplied with `--checkpoint-dir` is used as-is. Checkpoint files are created `0o600` (an existing file keeps its mode). Contains only assessment progress metadata, not credentials. |
| Session token reuse after expiration | Spoofing | Low | boto3 handles credential refresh natively from the caller's configured credentials (profile, environment, or instance/SSO). |

### AS-3: Report output

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| XSS in HTML report via injected flow names or parameters | Elevation of Privilege | Medium | Shell placeholder escaping and CSP script hash, script-safe JSON encoding, React text rendering, and raw-HTML-disabled markdown protect all assessment values. |
| Local report file accessible to unauthorized users | Information Disclosure | Medium | HTML, JSON, and CSV reports are created owner-only (`0o600`). ASFF output and the output directory are created with the process umask (commonly world-readable). Restrict the output directory or umask on shared hosts. |
| Report tampering after generation | Tampering | Low | Reports are static, point-in-time snapshots with no integrity protection (see [Recommendations](#recommendations-for-future-hardening)). Security Hub import validates only the ASFF schema; it cannot detect a modified report. |
| Phone numbers disclosed through shared reports | Information Disclosure | Medium | Caller Journey Map entries carry claimed phone numbers unmasked in the HTML and JSON reports; only some finding text masks them. Treat reports as sensitive and share them only with people entitled to that configuration. |

### AS-4: S3 report publishing (`--s3-output`)

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Auto-created or pre-existing selected report bucket is publicly exposed | Information Disclosure | High | Before every upload, the publisher applies S3 Block Public Access (all four flags), enables versioning, and preserves the bucket's existing default encryption setting or adds SSE-S3 when absent. Report objects are always uploaded with SSE-S3 (`AES256`), even when the bucket default is SSE-KMS, so a bucket policy that requires SSE-KMS rejects the upload. If hardening a newly created bucket fails, the publisher attempts to delete that empty bucket and reports the error. Changes to an existing selected bucket are not rolled back, and enabled versioning can only be suspended, not removed. |
| Over-broad write permissions on the assessment principal | Elevation of Privilege | Medium | The CloudFormation policy is read-only and does not grant S3 report-publishing writes. When `--s3-output` is enabled, operators must add a separate policy scoped to the selected report bucket and its objects. Publishing is opt-in. |
| Bucket-name takeover (global S3 namespace) | Spoofing | Low | `head_bucket` confirms the bucket exists and is reachable; a `403` surfaces an error rather than uploading. It does not verify the owning account (no `ExpectedBucketOwner`), so a bucket in another account that grants the caller access would be hardened and written to. Use `--s3-bucket` to name a bucket you own. |
| Failed upload aborts the assessment | Denial of Service | Low | Upload failures are caught and reported; the assessment still succeeds and local reports remain. |

---

## STRIDE summary

| Category | Key risks | Primary controls |
|---|---|---|
| **Spoofing** | Credential misuse; bucket-name takeover | Same-account read-only customer-managed policy; `head_bucket` reachability check before upload (owner not verified) |
| **Tampering** | Adversarial flow content | Iterative bounded parsing; Script-safe JSON and React text rendering |
| **Repudiation** | Assessment actions not auditable | Verify CloudTrail coverage for the relevant API events and account; event recording depends on event type and trail configuration |
| **Information Disclosure** | Credential leakage; public report bucket; phone numbers in reports | No credentials in logs/reports; Block Public Access + SSE on report bucket; owner-only HTML/JSON/CSV files (ASFF uses the umask) |
| **Denial of Service** | Graph explosion | Bounded path enumeration (default depth 50 and 200 paths per number; fixed 5,000 paths per instance) |
| **Elevation of Privilege** | XSS in reports; over-broad IAM | Script-safe JSON and React text rendering; customer-managed read-only policy, with optional S3 writes granted separately for the report bucket |

CloudTrail [event selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html)
determine which management and data events a trail logs. A trail's default
selectors include read and write management events but no data events; do not
assume every assessment API call appears in the configured trail.

---

## Data flow diagram

```
┌──────────────────────────────────────────────────────────────┐
│ Z1: Execution host (workstation / CloudShell / CI runner)     │
│                                                                │
│   ┌──────────────────────┐                                    │
│   │ Assessment CLI        │                                    │
│   │  ├─ Engine            │                                    │
│   │  ├─ Analyzers         │                                    │
│   │  ├─ Checks            │                                    │
│   │  ├─ Journey Mapping   │                                    │
│   │  └─ Report Generator  │                                    │
│   └──────────┬───────────┘                                    │
│              │                                                 │
│      ┌───────┼────────────┐                                   │
│      ▼       ▼            ▼                                    │
│  ┌────────┐ ┌──────────────┐                                  │
│  │ Z3:    │ │ Checkpoint   │                                  │
│  │ Reports│ │ files (0o600)│                                  │
│  └───┬────┘ └──────────────┘                                  │
│      │ optional --s3-output                                   │
└──────┼─────────────────────────────────────────────────────── ┘
       │                          │
       │ HTTPS (TLS)              │ Read-oriented API calls (TLS)
       ▼                          ▼
┌────────────────────┐  ┌───────────────────────────────┐
│ Z2: S3 report      │  │ Z2: AWS APIs                   │
│ bucket (hardened,  │  │  ├─ Amazon Connect Customer    │
│ BPA + SSE + ver.)  │  │  ├─ IAM / STS                  │
└────────────────────┘  │  ├─ CloudTrail                 │
                        │  ├─ CloudWatch / KMS           │
                        │  ├─ Lambda / Lex               │
                        │  ├─ Connect AI agents/Bedrock  │
                        │  └─ Service Quotas             │
                        └──────────────┬────────────────┘
                                       │ Returns
                                       ▼
                        ┌───────────────────────────────┐
                        │ Z4: Contact Flow Content       │
                        │  (customer-controlled JSON)    │
                        │  Parsed → Graph → Scored       │
                        └───────────────────────────────┘
```

---

## Assumptions

1. The execution host is not compromised — if it is, all bets are off (the attacker already has credential access).
2. AWS API responses are authentic (TLS verified by boto3/botocore).
3. Contact flow JSON may contain arbitrary string values but conforms to the Connect flow schema structure (dict with `Actions` array).
4. When `--s3-output` is used, the operator intends to create or modify the selected report bucket in the assessed account by applying hardening settings and uploading reports.

---

## Residual risks

| Risk | Likelihood | Impact | Acceptance rationale |
|---|---|---|---|
| Local attacker on same host accesses reports | Low | Medium | HTML/JSON/CSV are owner-only; ASFF output follows the umask. Mitigate with OS-level access controls on the output directory |
| Malicious flow content reaches a future frontend change that introduces an unsafe HTML sink | Low | Medium | Covered by script-safe JSON, React text rendering, raw-HTML-disabled markdown, report-contract tests, and code review |
| boto3 dependency has a vulnerability | Low | High | Mitigated by dependency scanning in CI and regular updates |
| Large account with 1000+ flows causes high memory during graph construction | Medium | Low | `MAX_TOTAL_PATHS` bounds enumerated paths per instance, not super-graph construction or total memory across instances. Large accounts still require monitoring and output-size limits. |
| Report bucket retains historical reports indefinitely | Low | Low | Versioning is enabled by design; operators can apply lifecycle rules |

---

## Recommendations for future hardening

1. **Add HMAC signature to generated reports** — allows recipients to verify report integrity
2. **Add Subresource Integrity (SRI) hashes** if external CDN resources are ever included in reports
3. **Consider encrypting checkpoint files at rest** — currently plain JSON with restrictive permissions
4. **Keep `connect:ListPhoneNumbersV2` in the minimum permission validation** — journey mapping and its phone-number topology require it
5. **Offer a bucket lifecycle policy / KMS (SSE-KMS) option** for the report bucket in regulated environments
6. **Implement output size limits on report generation** — guard against reports exceeding reasonable sizes from extremely large accounts
7. **Pass `ExpectedBucketOwner` on S3 publishing calls** — so `--s3-output` refuses a bucket owned by another account
8. **Create ASFF output owner-only (`0o600`)** — match the HTML, JSON, and CSV writers
9. **Optionally mask phone numbers in Caller Journey Map data** — for reports shared outside the operating team
