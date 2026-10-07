# Spec: Same-Account IAM CloudFormation Template

**Status:** Implemented. `cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`
is the only current CloudFormation template. An earlier cross-account
`AmazonConnectScanRole.yaml` was deleted after cross-account execution was
removed from scope. References below describe historical rationale only; they
do not describe a current artifact or supported workflow.
**Author:** susbhaga (drafted with agent assistance)
**Delivered artifacts:**
- [`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`](../../../cloudformation/AmazonConnectSelfAssessmentPolicy.yaml)
- Drift tests in [`tests/test_iam_policy_consistency.py`](../../../tests/test_iam_policy_consistency.py)
- README's "Setting up AWS access" section

## Table of Contents

- [Motivation](#motivation)
- [Goals](#goals)
- [Non-goals](#non-goals)
- [Design](#design)
  - [File](#file)
  - [Parameters](#parameters)
  - [Resources](#resources)
  - [Outputs](#outputs)
  - [Drift with `docs/iam-policy-template.json`](#drift-with-docsiam-policy-templatejson)
  - [README changes](#readme-changes)
- [User workflow with the new template](#user-workflow-with-the-new-template)
- [Alternatives considered](#alternatives-considered)
- [Testing](#testing)
- [Historical rollout plan](#historical-rollout-plan)
- [Historical open questions and resolutions](#historical-open-questions-and-resolutions)

---

## Motivation

Self-assessment users (running the tool against their own AWS account) currently do this to grant themselves the assessment permissions:

```bash
aws iam create-policy \
  --policy-name AmazonConnectReadOnly \
  --policy-document file://docs/iam-policy-template.json

aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AmazonConnectReadOnly
```

Two AWS CLI commands with placeholders they have to substitute. If the user is a role rather than a user (e.g. federated), the second command is different (`attach-role-policy`). If they want to reuse the policy across principals, they have to remember which they attached to which. The imperative shape doesn't play well with change control — nothing about the policy state lives in version control on the user's side.

At the time this design was drafted, an earlier **cross-account** workflow used
a CloudFormation role template. That historical precedent showed that one
reviewable deployment step was easier to audit than imperative IAM commands.
The cross-account workflow was later removed, and its role template was
deleted. The delivered same-account policy keeps the useful CloudFormation
approach without any trust policy or role-assumption path.

## Goals

1. Replace the two `aws iam …` commands with a single CloudFormation deployment.
2. Support granting the policy to any combination of a user through a group, a role, or nothing (create the policy standalone for later attachment).
3. Keep the delivered JSON and CloudFormation policies synchronized with the
   canonical action set in `amazon_connect_assessment/iam_permissions.py`.
4. Follow the repository's established CloudFormation naming and drift-test
   conventions.
5. Document the same-account deployment in the README.

## Non-goals

- Cross-region policy replication. IAM is global; one deployment covers all regions.
- Managing the assessment-running principal itself. The template attaches to an existing user/role; it does not create one.
- Optional `--s3-output` bucket permissions. The delivered template remains
  read-only and intentionally excludes opt-in S3 report publishing permissions.

## Design

### File

`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`

This is the only current template in `cloudformation/`. The filename states
that the stack creates a same-account assessment policy, not a role or a
cross-account trust relationship.

### Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `PolicyName` | `String` | `AmazonConnectReadOnly` | Name of the managed policy. Kept as a parameter so users deploying multiple stacks (rare, but supported) can distinguish. |
| `AttachToUserName` | `String` | `""` (empty) | Optional IAM user to add to the stack-managed group. Empty means "don't grant access to any user." |
| `AttachToRoleName` | `String` | `""` (empty) | Optional IAM role to attach the policy to. Empty means "don't attach to any role." |

`AttachToUserName` and `AttachToRoleName` are independent — a user could set both if they run assessments from both a user principal and a role principal (e.g. an EC2 instance role for CI). Setting neither is valid: the policy is created and its ARN is emitted as a stack output, ready for manual attachment.

`Conditions` use `Fn::Not [Fn::Equals ["", !Ref AttachTo…Name]]` to gate role attachment and optional user group membership. CloudFormation supports conditional list contents via `Fn::If`.

### Resources

**`AmazonConnectReadOnlyPolicy`** — a single `AWS::IAM::ManagedPolicy`.

- `ManagedPolicyName: !Ref PolicyName`
- `Description`: identifies the read-only Amazon Connect Customer posture
  assessment permission set.
- `PolicyDocument`: explicit actions kept equivalent to the canonical
  `POLICY_STATEMENTS` in `amazon_connect_assessment/iam_permissions.py` by drift
  tests. `docs/iam-policy-template.json` is generated from the same Python
  source.
- `Roles`: conditional list — `[!Ref AttachToRoleName]` when set, `AWS::NoValue` otherwise.

**`AmazonConnectAssessmentGroup`** — conditional `AWS::IAM::Group` created when `AttachToUserName` is set.

- `GroupName`: omitted so CloudFormation generates a stack-scoped name and avoids name collisions.
- `ManagedPolicyArns`: attaches the managed policy to the group.

**`AmazonConnectUserGroupMembership`** — conditional `AWS::IAM::UserToGroupAddition` created when `AttachToUserName` is set.

- `GroupName: !Ref AmazonConnectAssessmentGroup`
- `Users`: `[!Ref AttachToUserName]`

The policy is intentionally not attached directly to an IAM user. User-based access flows through a group to satisfy `cfn-nag` rule F12.

### Outputs

| Output | Value | Purpose |
|---|---|---|
| `PolicyArn` | `!Ref AmazonConnectReadOnlyPolicy` | The ARN to hand to `aws iam attach-…-policy` if the user chose not to auto-attach via parameters. |
| `PolicyName` | `!Ref PolicyName` | Echo the name for readability. |
| `AttachmentStatus` | Human-readable string built from `AttachToUserName` and `AttachToRoleName` | e.g. "Added user alice to group <generated-group-name>", "Attached to role: MyAssessmentRole", "Added user alice to group <generated-group-name> and attached to role MyAssessmentRole", or "Created without attachment — attach manually with the PolicyArn above." |

### Drift with `docs/iam-policy-template.json`

`tests/test_iam_policy_consistency.py` asserts:

1. `docs/iam-policy-template.json` matches
   `iam_permissions.py::render_policy_json()` byte-for-byte.
2. `AmazonConnectSelfAssessmentPolicy.yaml` grants exactly the expected
   canonical actions, with no missing or stray permissions.

The JSON file is a generated derivative. `iam_permissions.py::POLICY_STATEMENTS`
is the source of truth, while the CloudFormation template is hand-maintained
because its parameters, conditions, resources, and outputs do not round-trip
through the JSON renderer.

Implementation sketch for the drift check:

```python
def _extract_actions_from_selfassessment_yaml(path: Path) -> Set[str]:
    """Parse the SelfAssessmentPolicy YAML and return every action listed
    in the single ManagedPolicy's Statements."""
    doc = yaml.safe_load(path.read_text())
    policy = doc["Resources"]["AmazonConnectReadOnlyPolicy"]
    return {
        a
        for stmt in policy["Properties"]["PolicyDocument"]["Statement"]
        for a in stmt["Action"]
    }


def test_self_assessment_policy_matches_canonical():
    canonical = all_actions()  # from iam_permissions.py
    on_policy = _extract_actions_from_selfassessment_yaml(
        REPO_ROOT / "cloudformation" / "AmazonConnectSelfAssessmentPolicy.yaml"
    )
    missing = canonical - on_policy
    assert not missing, (
        f"Actions in the canonical set but missing from "
        f"AmazonConnectSelfAssessmentPolicy.yaml: {sorted(missing)}"
    )
```

The existing cfn-lint CI step already validates syntax; nothing new needed there.

### README changes

Replace the existing "Step 1 — Confirm your CLI access" IAM block in **Setting up AWS access → Option B: Self-assessment**:

**Before:**

```bash
aws iam create-policy \
  --policy-name AmazonConnectReadOnly \
  --policy-document file://docs/iam-policy-template.json

aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AmazonConnectReadOnly
```

**After:**

> Deploy the same-account CloudFormation template — one step, no CLI substitutions:
>
> ```bash
> aws cloudformation deploy \
>   --stack-name amazon-connect-assessment-permissions \
>   --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
>   --parameter-overrides AttachToUserName=YOUR_USERNAME \
>   --capabilities CAPABILITY_NAMED_IAM \
>   --region us-east-1
> ```
>
> To attach to a role instead of granting access through a user group, pass `AttachToRoleName=YOUR_ROLE_NAME`. To create the policy without auto-attaching (useful for SSO or federated principals), omit both `AttachTo…` parameters and use the stack's `PolicyArn` output.
>
> Or deploy via the AWS Console: **CloudFormation → Create stack → Upload `cloudformation/AmazonConnectSelfAssessmentPolicy.yaml` → set `AttachToUserName` to add the user to the generated group → Deploy**.

## User workflow with the new template

**IAM user, one command:**

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToUserName=alice \
  --capabilities CAPABILITY_NAMED_IAM
```

**IAM role (e.g. EC2, Lambda, or an SSO permission set's role):**

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToRoleName=AssessmentRunner \
  --capabilities CAPABILITY_NAMED_IAM
```

**Create-only, attach later** (useful for SSO federated principals where you attach to the permission set separately):

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --capabilities CAPABILITY_NAMED_IAM

# Grab the ARN
aws cloudformation describe-stacks \
  --stack-name amazon-connect-permissions \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicyArn`].OutputValue' --output text
```

## Alternatives considered

**Historical alternative: extend the deleted cross-account role template.**
This was rejected because it would have combined cross-account trust and
same-account attachment in one parameter-heavy template. The cross-account
workflow was later removed, so the role template no longer exists.

**Ship a helper shell script** in `scripts/setup-self-assessment.sh` that runs
the two `aws iam` commands. Rejected: still imperative and hard to keep
synchronized with the canonical action set. It would also have weakened the
reviewable CloudFormation deployment model selected for same-account access.

**Add a CLI subcommand** `amazon-connect-assessment setup-permissions --user alice`. Rejected: bootstrapping a tool's IAM permissions from within the tool itself is a chicken-and-egg problem — the user needs some permission (at least `iam:CreatePolicy` + `iam:AttachUserPolicy`) before the tool can bootstrap its own. That's a wider grant than what the tool actually needs at runtime, which contradicts the principle of least privilege. CloudFormation avoids this by making the deployment step visible and auditable, and the deployer's permissions are a separate concern.

## Testing

- **Drift tests** — `tests/test_iam_policy_consistency.py` verifies that the
  generated JSON and the explicit actions in the self-assessment CloudFormation
  template match the canonical Python action set.
- **cfn-lint** — CI validates the current YAML under `cloudformation/`.
- **Manual smoke** — in a development account, deploy with
  `AttachToUserName`, run
  `python -m amazon_connect_assessment.cli --check-permissions`, and repeat with
  `AttachToRoleName` and with neither parameter to validate the standalone
  policy path.

## Historical rollout plan

1. Land the template + drift test + README update as one commit.
2. Existing self-assessment users' `aws iam …`-created policies still work; they can migrate at their own pace. Add a note in the README's Troubleshooting section that CloudFormation is now the recommended path.
3. No breaking changes to any existing artifact.

## Historical open questions and resolutions

1. **Policy name collision.** The default `AmazonConnectReadOnly` can collide
   with a policy created by the earlier imperative workflow. Deployment fails
   visibly; users can choose another `PolicyName` or migrate the old policy.
2. **SCP interaction.** Organization SCPs can block `iam:CreatePolicy` or IAM
   attachment operations. CloudFormation surfaces that failure to the deployer.
3. **Template generation.** Resolved in favor of a hand-maintained
   `AmazonConnectSelfAssessmentPolicy.yaml`. Drift tests compare its explicit
   action set with `iam_permissions.py::POLICY_STATEMENTS`; the simpler JSON
   policy remains generated by `render_policy_json()`.
