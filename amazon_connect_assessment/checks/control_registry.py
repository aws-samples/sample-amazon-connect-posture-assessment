"""Immutable catalog of atomic assessment controls and their executors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Iterable, Iterator, Mapping

from ..models import FindingDisposition, FindingMethodology, Pillar, Severity

if TYPE_CHECKING:
    from .base import BaseCheck


class ExecutionSource(Enum):
    """Execution subsystem responsible for producing a control result."""

    BASE_CHECK = "base_check"
    JOURNEY = "journey"


@dataclass(frozen=True)
class AtomicControl:
    """Canonical identity and evidence contract for one atomic assessment question."""

    control_id: str
    root_condition_key: str
    name: str
    pillar: Pillar
    default_severity: Severity
    disposition: FindingDisposition
    methodology: FindingMethodology
    execution_source: ExecutionSource
    executor_key: str
    requires_flow_analysis: bool
    legacy_aliases: tuple[str, ...] = ()
    secondary_lens_references: tuple[str, ...] = ()


class AtomicControlRegistry:
    """Validated immutable index of canonical controls and legacy aliases."""

    __slots__ = ("_aliases", "_by_id", "_controls")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("AtomicControlRegistry is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, controls: Iterable[AtomicControl]):
        canonical = tuple(controls)
        by_id: dict[str, AtomicControl] = {}
        aliases: dict[str, str] = {}
        root_owners: dict[str, str] = {}

        for control in canonical:
            self._validate_control(control)
            if control.control_id in by_id:
                raise ValueError(f"Duplicate canonical control ID: {control.control_id}")
            if control.root_condition_key in root_owners:
                owner = root_owners[control.root_condition_key]
                raise ValueError(
                    "Duplicate root condition ownership: "
                    f"{control.root_condition_key} ({owner}, {control.control_id})"
                )
            by_id[control.control_id] = control
            root_owners[control.root_condition_key] = control.control_id

        for control in canonical:
            for alias in control.legacy_aliases:
                if alias in by_id:
                    raise ValueError(f"Alias collides with canonical control ID: {alias}")
                if alias in aliases:
                    raise ValueError(f"Alias is owned by multiple controls: {alias}")
                aliases[alias] = control.control_id

        self._controls = canonical
        self._by_id: Mapping[str, AtomicControl] = MappingProxyType(by_id)
        self._aliases: Mapping[str, str] = MappingProxyType(aliases)

    @staticmethod
    def _validate_control(control: AtomicControl) -> None:
        for label, value in (
            ("control_id", control.control_id),
            ("root_condition_key", control.root_condition_key),
            ("name", control.name),
            ("executor_key", control.executor_key),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Atomic control has blank {label}")

        if not isinstance(control.legacy_aliases, tuple):
            raise ValueError("legacy_aliases must be an immutable tuple")
        if not isinstance(control.secondary_lens_references, tuple):
            raise ValueError("secondary_lens_references must be an immutable tuple")
        if not isinstance(control.requires_flow_analysis, bool):
            raise ValueError("requires_flow_analysis must be a bool")

        methodology = control.methodology
        for field_name in (
            "reason",
            "evidence_source",
            "proof_limitations",
            "developer_admin_meaning",
            "verification_criteria",
        ):
            value = getattr(methodology, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Control {control.control_id} has blank methodology.{field_name}")

        primary = methodology.primary_lens_reference
        if primary and primary in control.secondary_lens_references:
            raise ValueError(
                f"Control {control.control_id} repeats its primary lens as a secondary lens"
            )
        if any(not reference.strip() for reference in control.secondary_lens_references):
            raise ValueError(f"Control {control.control_id} has a blank secondary lens reference")
        if any(not alias.strip() for alias in control.legacy_aliases):
            raise ValueError(f"Control {control.control_id} has a blank legacy alias")

        if control.execution_source == ExecutionSource.BASE_CHECK:
            if not control.executor_key.startswith("amazon_connect_assessment.checks."):
                raise ValueError(
                    f"Control {control.control_id} has mismatched BaseCheck executor metadata"
                )
        elif control.execution_source == ExecutionSource.JOURNEY:
            if control.executor_key != _JOURNEY_EXECUTOR_KEY:
                raise ValueError(
                    f"Control {control.control_id} has mismatched Journey executor metadata"
                )
        else:
            raise ValueError(f"Control {control.control_id} has an unsupported execution source")

    def __len__(self) -> int:
        return len(self._controls)

    def __iter__(self) -> Iterator[AtomicControl]:
        return iter(self._controls)

    @property
    def controls(self) -> tuple[AtomicControl, ...]:
        """Return canonical controls in stable catalog order."""
        return self._controls

    @property
    def aliases(self) -> Mapping[str, str]:
        """Return the read-only legacy alias map."""
        return self._aliases

    def resolve_id(self, control_id: str) -> str:
        """Resolve a canonical ID or legacy alias to its canonical ID."""
        if control_id in self._by_id:
            return control_id
        try:
            return self._aliases[control_id]
        except KeyError as error:
            raise KeyError(f"Unknown atomic control ID or alias: {control_id}") from error

    def get(self, control_id: str) -> AtomicControl:
        """Return a canonical control, accepting a legacy alias."""
        return self._by_id[self.resolve_id(control_id)]

    def select(self, control_ids: Iterable[str]) -> tuple[AtomicControl, ...]:
        """Resolve and deduplicate a selection while preserving request order."""
        selected: list[AtomicControl] = []
        seen: set[str] = set()
        for control_id in control_ids:
            canonical_id = self.resolve_id(control_id)
            if canonical_id not in seen:
                selected.append(self._by_id[canonical_id])
                seen.add(canonical_id)
        return tuple(selected)

    def hydrate_base_checks(
        self, checks: Iterable[BaseCheck], *, include_flow_analysis: bool = True
    ) -> None:
        """Validate and attach canonical metadata to the exact BaseCheck inventory."""
        checks_by_id: dict[str, BaseCheck] = {}
        for check in checks:
            if check.check_id in self._aliases:
                raise ValueError(f"BaseCheck emits legacy alias ID: {check.check_id}")
            if check.check_id in checks_by_id:
                raise ValueError(f"Duplicate BaseCheck executor for {check.check_id}")
            checks_by_id[check.check_id] = check

        expected_ids = {
            control.control_id
            for control in self._controls
            if control.execution_source == ExecutionSource.BASE_CHECK
            and (include_flow_analysis or not control.requires_flow_analysis)
        }
        actual_ids = set(checks_by_id)
        unexpected = sorted(actual_ids - expected_ids)
        missing = sorted(expected_ids - actual_ids)
        if missing or unexpected:
            raise ValueError(
                f"BaseCheck/catalog coverage mismatch; missing={missing}, unexpected={unexpected}"
            )

        for control_id, check in checks_by_id.items():
            control = self._by_id[control_id]
            executor_key = f"{type(check).__module__}.{type(check).__qualname__}"
            mismatches: list[str] = []
            if check.pillar != control.pillar:
                mismatches.append("pillar")
            if check.severity != control.default_severity:
                mismatches.append("severity")
            if executor_key != control.executor_key:
                mismatches.append("executor_key")
            if mismatches:
                raise ValueError(
                    f"Executor metadata mismatch for {control_id}: {', '.join(mismatches)}"
                )
            check.disposition = control.disposition
            check.methodology = control.methodology


_JOURNEY_EXECUTOR_KEY = "amazon_connect_assessment.journey.journey_scorer.generate_journey_findings"


def _methodology(
    reason: str,
    evidence_source: str,
    proof_limitations: str,
    developer_admin_meaning: str,
    verification_criteria: str,
) -> FindingMethodology:
    return FindingMethodology(
        reason=reason,
        evidence_source=evidence_source,
        proof_limitations=proof_limitations,
        developer_admin_meaning=developer_admin_meaning,
        verification_criteria=verification_criteria,
    )


def _base_executor(module: str, class_name: str) -> str:
    return f"amazon_connect_assessment.checks.{module}.{class_name}"


def _control(
    control_id: str,
    root_condition_key: str,
    name: str,
    pillar: Pillar,
    severity: Severity,
    disposition: FindingDisposition,
    methodology: FindingMethodology,
    executor_key: str,
    requires_flow_analysis: bool,
    *,
    execution_source: ExecutionSource = ExecutionSource.BASE_CHECK,
    legacy_aliases: tuple[str, ...] = (),
) -> AtomicControl:
    return AtomicControl(
        control_id=control_id,
        root_condition_key=root_condition_key,
        name=name,
        pillar=pillar,
        default_severity=severity,
        disposition=disposition,
        methodology=methodology,
        execution_source=execution_source,
        executor_key=executor_key,
        requires_flow_analysis=requires_flow_analysis,
        legacy_aliases=legacy_aliases,
        secondary_lens_references=(),
    )


_C = FindingDisposition.CONTROL
_M = FindingDisposition.MANUAL_REVIEW
_I = FindingDisposition.INFORMATIONAL
_S = Pillar.SECURITY
_R = Pillar.RESILIENCE
_CO = Pillar.COST_OPTIMIZATION
_O = Pillar.OPERATIONAL_EXCELLENCE
_P = Pillar.PERFORMANCE_EFFICIENCY


_CONTROLS = (
    _control(
        "security-iam-001",
        "connect.instance.service_role_arn_valid",
        "IAM Service Role Presence and ARN Format",
        _S,
        Severity.CRITICAL,
        _C,
        _methodology(
            "A Connect instance must report a service-role ARN in a supported AWS partition and IAM role ARN format.",
            "The service-role value returned during Connect instance discovery is checked for presence and IAM role ARN syntax in the aws, aws-us-gov, or aws-cn partition.",
            "This check does not verify that the role exists and does not inspect its trust policy, permissions, permission scope, or effective access.",
            "A pass confirms only service-role value presence and ARN format; it does not prove least privilege or that Connect can assume or use the role.",
            "Configure the intended service-role ARN or correct its syntax, then validate role existence, trust, and permissions through separate controls.",
        ),
        _base_executor("security_checks", "IAMServiceRoleCheck"),
        False,
    ),
    _control(
        "security-data-001",
        "connect.user.security_profile_assignment_missing",
        "User Security Profile Assignment",
        _S,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Every discovered Connect user must have at least one security profile to establish an explicit permission boundary.",
            "The executor inspects security_profile_ids on users supplied by instance discovery.",
            "It cannot prove completeness when user discovery is empty or partial, and it does not evaluate the permissions inside assigned profiles.",
            "A failure identifies a discovered user without an assignment; a pass covers only the user records available to the assessment.",
            "Complete ListUsers/DescribeUser discovery, assign an appropriate least-privilege profile to each user, and rerun with no unassigned users.",
        ),
        _base_executor("security_checks", "DataProtectionCheck"),
        False,
    ),
    _control(
        "cost-unused-001",
        "connect.configuration.possibly_unreferenced_resources",
        "Unused Resources Check",
        _CO,
        Severity.LOW,
        _M,
        _methodology(
            "Loose users, queues, routing profiles, and security profiles can indicate unfinished or ownerless configuration that merits cleanup review.",
            "The check cross-references discovered collection counts and direct user routing-profile assignments.",
            "Count ratios and missing direct assignments do not prove a resource is unused, unreferenced by flows, or safe to remove; these objects have no per-resource charge.",
            "Treat each item as an administrative-hygiene candidate, not as measured savings or deletion authorization.",
            "Trace assignments, flow references, traffic, seasonal/DR purpose, and ownership for every candidate before retaining or removing it.",
        ),
        _base_executor("cost_optimization_checks", "UnusedResourcesCheck"),
        False,
    ),
    _control(
        "cost-inefficient-001",
        "connect.configuration.allocation_ratio_outlier",
        "Inefficient Resource Allocation Check",
        _CO,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Unusual user, queue, routing-profile, integration, and flow ratios can reveal a configuration shape that needs operational explanation.",
            "The executor applies local thresholds to the enriched instance collections and direct routing-profile IDs.",
            "The thresholds are not AWS limits or cost measurements, and incomplete discovery can distort every ratio.",
            "A failure is a solution-architecture review lead; it does not establish inefficiency or a billable waste condition.",
            "Reconcile each ratio with queue membership, staffing, traffic, integration purpose, and the documented modular-flow design.",
        ),
        _base_executor("cost_optimization_checks", "InefficientResourceAllocationCheck"),
        False,
    ),
    _control(
        "cost-oversized-001",
        "connect.configuration.cardinality_maintainability_outlier",
        "Oversized Configuration Check",
        _CO,
        Severity.LOW,
        _M,
        _methodology(
            "High profile-to-user or queue-to-profile ratios can signal duplicated configuration that is harder to maintain.",
            "The check computes security-profile/user, routing-profile/user, and queue/routing-profile ratios from discovered resources.",
            "Its numeric cutoffs are local heuristics, ignore permission and routing semantics, and do not represent Connect pricing or service quotas.",
            "The result asks administrators to justify or simplify the configuration; it does not prove over-provisioning.",
            "Compare flagged ratios with the operating model and consolidate only objects proven behaviorally equivalent and dependency-free.",
        ),
        _base_executor("cost_optimization_checks", "OversizedConfigurationCheck"),
        False,
    ),
    _control(
        "sec-iam-deep-001",
        "iam.connect_service_role.identity_policy_excessive_allow",
        "IAM Service Role Policy Inspection",
        _S,
        Severity.HIGH,
        _C,
        _methodology(
            "The Connect service role should not grant broad write-like actions on wildcard resources or unrelated high-impact actions in its identity policies.",
            "Every ListRolePolicies and ListAttachedRolePolicies page is read; each inline document comes from GetRolePolicy, and each attached managed policy's default version comes from GetPolicy plus GetPolicyVersion. Object and URL-encoded JSON documents are analyzed case-insensitively for the selected Action patterns, with policy and statement context retained in bounded evidence.",
            "Only identity-policy documents are inspected. Trust policies, permission boundaries, SCPs, session policies, resource policies, NotAction effective permissions, effective-policy combinations, and business necessity are not evaluated. Any unread or malformed source prevents a clean pass.",
            "A failure proves at least one selected identity-policy pattern in the material read; it remains a failure with inspection_complete=false if other sources were unavailable. Skipped means no known violation was found but inspection was incomplete. Pass means every listed identity-policy document was read and no selected pattern was found, within the stated proof boundaries.",
            "Read every inline policy and every attached managed policy default version, resolve all source or parse failures, scope required actions, resources, and conditions, and rerun until inspection_complete=true with no selected broad wildcard or out-of-scope Action pattern.",
        ),
        _base_executor("security_deep_checks", "IAMServiceRolePolicyCheck"),
        False,
    ),
    _control(
        "sec-storage-001",
        "connect.storage.encryption_missing",
        "Instance Storage Encryption Check",
        _S,
        Severity.HIGH,
        _C,
        _methodology(
            "Every configured Amazon Connect storage destination must use encryption at rest.",
            "Connect ListInstanceStorageConfigs is read for each supported storage resource type and each returned encryption key identifier is classified as absent, AWS-managed, or customer-managed.",
            "The key identifier does not prove key health, policy correctness, destination encryption, or historical-object coverage; any incomplete resource-type read prevents a clean pass.",
            "A failure proves a returned storage configuration lacks encryption; AWS-managed and customer-managed encryption both satisfy this control.",
            "Enable encryption for every unencrypted destination; if policy requires customer-managed keys, separately validate key ownership, state, policy, grants, and destination coverage.",
        ),
        _base_executor("security_deep_checks", "InstanceStorageEncryptionCheck"),
        False,
    ),
    _control(
        "sec-origins-001",
        "connect.ccp.approved_origin_requires_context_review",
        "Approved Origins / CCP Access Control Check",
        _S,
        Severity.HIGH,
        _M,
        _methodology(
            "CCP embedding origins should be constrained to explicitly trusted application origins when a custom agent application is used.",
            "Connect ListApprovedOrigins is scanned for wildcard, localhost, and broad scheme-only entries.",
            "The check does not prove CCP embedding is used, parse complete URL trust boundaries, require HTTPS, or validate ownership of listed domains.",
            "Broad entries are concrete review candidates; an empty allowlist can be the correct safe state for deployments without embedded CCP.",
            "Confirm embedding requirements and replace each relevant entry with an exact owned HTTPS origin; document no-embedding cases.",
        ),
        _base_executor("security_deep_checks", "ApprovedOriginsCheck"),
        False,
    ),
    _control(
        "sec-cloudtrail-001",
        "cloudtrail.connect_management_event_coverage_missing",
        "CloudTrail Connect Management Write-Event Coverage",
        _S,
        Severity.HIGH,
        _C,
        _methodology(
            "Connect management write activity needs active CloudTrail selector coverage for change attribution and forensic reconstruction.",
            "For every trail returned by CloudTrail DescribeTrails, GetTrailStatus verifies active logging and GetEventSelectors evaluates basic or advanced selectors against a Connect management write event.",
            "Returned-trail configuration does not prove delivery, destination availability, retention, immutability, log-file integrity, or successful recording of a recent event.",
            "A pass proves at least one returned applicable trail was actively logging with a selector that includes Connect management writes; failures on other trails remain disclosed.",
            "Start an applicable trail, include management write events without excluding connect.amazonaws.com, then separately validate delivery, retention, destination controls, and a recent test event.",
        ),
        _base_executor("security_deep_checks", "CloudTrailIntegrationCheck"),
        False,
    ),
    _control(
        "sec-federation-001",
        "connect.identity_management_type.inventory",
        "Identity Federation / MFA Check",
        _S,
        Severity.LOW,
        _I,
        _methodology(
            "Identity-management type is useful context for deciding where agent MFA and lifecycle controls must be administered.",
            "Connect DescribeInstance reports IdentityManagementType.",
            "The value cannot prove MFA enforcement, IdP availability, conditional access, native-identity controls, or a successful sign-in path.",
            "This is identity architecture inventory; SAML and Connect-managed identities can both be viable with external MFA controls.",
            "Review the actual IdP or native sign-in policy, test MFA and break-glass access, and record the governing identity control.",
        ),
        _base_executor("security_deep_checks", "IdentityFederationCheck"),
        False,
    ),
    _control(
        "sec-profile-audit-001",
        "connect.security_profile.admin_permission_candidate",
        "Security Profile Permissions Audit",
        _S,
        Severity.HIGH,
        _M,
        _methodology(
            "Profiles outside the known administrator names should be reviewed when they directly grant selected administrative permissions.",
            "Connect ListSecurityProfiles and ListSecurityProfilePermissions expose profile names and direct permission strings.",
            "Profile names do not prove intended job function; the selected permission set is incomplete and user assignments or inherited access are not evaluated.",
            "A failure identifies an apparent non-admin profile with a known admin-capable permission, not a proven least-privilege violation.",
            "Confirm the profile's approved role, review all effective permissions and assignments, and remove grants not required for that role.",
        ),
        _base_executor("security_deep_checks", "SecurityProfileAuditCheck"),
        False,
    ),
    _control(
        "cost-usage-metrics-001",
        "connect.instance.concurrent_calls_absent_30d",
        "CloudWatch Usage Metrics Analysis",
        _CO,
        Severity.MEDIUM,
        _M,
        _methodology(
            "An instance with no observable call activity for 30 days should be reviewed for intentional standby, migration, or retirement status.",
            "CloudWatch GetMetricStatistics reads daily AWS/Connect ConcurrentCalls for the InstanceId and VoiceCalls metric group.",
            "No datapoints do not prove zero contacts and exclude chat/task traffic, seasonal demand, metric publication issues, and instance purpose.",
            "The finding is an ownership and usage investigation trigger, never authority to delete an instance or release numbers.",
            "Validate account, region, dimensions, all-channel CTR/history, DR purpose, attached resources, and owner approval over an appropriate period.",
        ),
        _base_executor("cost_intelligence_checks", "UsageMetricsCheck"),
        False,
    ),
    _control(
        "cost-unused-numbers-001",
        "connect.phone_number.holding_cost_inventory",
        "Claimed Phone Number Inventory",
        _CO,
        Severity.MEDIUM,
        _I,
        _methodology(
            "Claimed-number inventory and worst-case holding cost help a telephony owner prioritize a separate usage reconciliation.",
            "Connect ListPhoneNumbersV2 returns one page of claimed-number country/type metadata; static reference rates estimate an aggregate upper bound.",
            "The API evidence contains no per-number traffic, can truncate after 50, and the estimate is neither measured waste nor confirmed savings.",
            "A pass means inventory was reported, not that numbers are used, unused, or safe to release.",
            "Build a complete paginated inventory and reconcile each number to historical metrics or CTRs, ownership, associations, and contracted rates.",
        ),
        _base_executor("cost_intelligence_checks", "UnusedPhoneNumbersCheck"),
        False,
    ),
    _control(
        "cost-premium-features-001",
        "connect.contact_lens.enablement_inventory",
        "Premium Feature Enablement Inventory",
        _CO,
        Severity.LOW,
        _I,
        _methodology(
            "Contact Lens enablement is planning context for a cost owner because charges arise only when flows invoke the feature.",
            "Connect DescribeInstanceAttribute reads the CONTACT_LENS instance flag.",
            "Enablement alone costs nothing and does not reveal flow-level analytics use, analyzed volume, regional price, or billed spend; Wisdom and Cases are not inspected.",
            "The result reports feature availability and asks for usage reconciliation rather than declaring waste.",
            "Identify flows that enable analytics and reconcile analyzed voice/chat usage with billing and an approved business purpose.",
        ),
        _base_executor("cost_intelligence_checks", "PremiumFeaturesCostCheck"),
        False,
    ),
    _control(
        "cost-hours-mismatch-001",
        "connect.hours_of_operation.schedule_inventory",
        "Hours of Operation Inventory",
        _CO,
        Severity.LOW,
        _I,
        _methodology(
            "Hours-of-operation names give operations staff a starting inventory for schedule and staffing alignment work.",
            "Connect ListHoursOfOperations returns at most the first 25 schedule summaries.",
            "The executor reads no schedule intervals, queue associations, holidays, time zones, CloudWatch traffic, or staffing data and therefore cannot detect a mismatch.",
            "A pass only records schedule inventory; it makes no claim about callers arriving outside staffed periods.",
            "Fetch all schedule definitions and associations, compare interval traffic and staffing across time zones/holidays, and test both routing states.",
        ),
        _base_executor("cost_intelligence_checks", "HoursOfOperationMismatchCheck"),
        False,
    ),
    _control(
        "ops-logging-001",
        "connect.contact_flow_logging.disabled",
        "Contact Flow Logging",
        _O,
        Severity.HIGH,
        _C,
        _methodology(
            "Contact-flow logs are required to reconstruct branch choices, integration responses, and routing failures.",
            "Connect DescribeInstanceAttribute reads the CONTACTFLOW_LOGS switch.",
            "The switch does not prove any flow is active or that records reach a log group with suitable retention, encryption, access, and alarms.",
            "A failure proves the instance logging switch is off; a pass is only the prerequisite configuration state.",
            "Enable the switch, rerun, then send a controlled contact and confirm expected records arrive in the protected destination.",
        ),
        _base_executor("operational_excellence_checks", "ContactFlowLoggingCheck"),
        False,
    ),
    _control(
        "ops-early-media-001",
        "connect.outbound_call.early_media_disabled",
        "Early Media for Outbound Calls",
        _O,
        Severity.LOW,
        _M,
        _methodology(
            "Outbound agents may need early-media ring and busy tones to understand call setup progress.",
            "Connect DescribeInstanceAttribute reads the EARLY_MEDIA switch.",
            "The setting does not reveal whether outbound calling is used, carriers supply early media, or the desired agent experience requires it.",
            "A disabled value is a workload-conditional experience review, not a universal operational defect.",
            "Confirm outbound scope and desired behavior, enable if appropriate, and place test calls covering ringing, busy, and failure outcomes.",
        ),
        _base_executor("operational_excellence_checks", "EarlyMediaCheck"),
        False,
    ),
    _control(
        "ops-auto-resolve-001",
        "connect.ssml_voice.auto_resolve_inventory",
        "SSML Voice Locale Fallback (AUTO_RESOLVE_BEST_VOICES)",
        _O,
        Severity.LOW,
        _I,
        _methodology(
            "The auto-resolve voice setting is useful resilience context when authored SSML explicitly selects Polly voices.",
            "Connect DescribeInstanceAttribute reads AUTO_RESOLVE_BEST_VOICES and reports the boolean.",
            "The executor always passes, swallows API errors as false, and does not inspect SSML voice overrides or exercise fallback behavior.",
            "This is a setting inventory row whose relevance depends on actual prompt authoring.",
            "Obtain a successful attribute read, inventory SSML voice tags, and test same-locale substitution if the application relies on fallback.",
        ),
        _base_executor("operational_excellence_checks", "AutoResolveTasksCheck"),
        False,
    ),
    _control(
        "ai-ops-guardrail-001",
        "qconnect.serving_agent.guardrail_attachment_missing",
        "Q in Connect AI Guardrail Coverage",
        _S,
        Severity.HIGH,
        _C,
        _methodology(
            "Guardrail-capable Q in Connect agents serving traffic should reference an active published guardrail.",
            "Connect ListIntegrationAssociations plus Q GetAssistant, ListAIGuardrails, ListAIAgents, and GetAIAgent join serving bindings to guardrail IDs and states.",
            "Attachment and publication do not prove filter contents, denied topics, sensitive-information policy, version suitability, or runtime behavior.",
            "A pass confirms bounded attachment/status coverage for discovered guardrail-capable agents, excluding API variants that cannot express a guardrail.",
            "Resolve every bound agent to the intended published guardrail version, inspect all filters, and run representative allowed/blocked prompt tests.",
        ),
        _base_executor("ai_ops_maturity_checks", "AIGuardrailCoverageCheck"),
        False,
    ),
    _control(
        "ai-ops-encryption-001",
        "qconnect.resource.customer_managed_key_policy_review",
        "Q in Connect Customer-Managed Key Encryption",
        _S,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Q assistants and knowledge bases without customer-managed keys require a policy decision about whether AWS-owned encryption meets requirements.",
            "Connect integration associations are joined to Q GetAssistant/GetKnowledgeBase serverSideEncryptionConfiguration.kmsKeyId values.",
            "Missing customer-managed key metadata does not mean data is unencrypted, and present IDs do not prove key state, policy, grants, rotation, or coverage outside associated resources.",
            "The result distinguishes encryption-key ownership choices for security review; it is not proof of an encryption failure.",
            "Map data classification to key-ownership requirements and, when CMKs are required, validate each key ARN, state, policy, grants, and association.",
        ),
        _base_executor("ai_ops_maturity_checks", "QConnectEncryptionCheck"),
        False,
    ),
    _control(
        "ai-ops-kb-sync-001",
        "qconnect.knowledge_base.lifecycle_or_ingestion_unhealthy",
        "Q in Connect Knowledge Base Lifecycle and Ingestion Health",
        _O,
        Severity.MEDIUM,
        _C,
        _methodology(
            "A Q knowledge base must be active and have successful ingestion before it can reliably supply current content.",
            "Paginated Connect integration discovery and Q GetKnowledgeBase return lifecycle status, ingestion status, and bounded failure reasons.",
            "This point-in-time state does not prove source completeness, freshness between syncs, retrieval quality, answer quality, or assistant usage.",
            "A failure proves a terminal lifecycle or ingestion state; transient or incomplete evidence is skipped rather than passed.",
            "Repair the reported lifecycle/source/IAM cause and rerun until every discovered knowledge base is ACTIVE with SYNC_SUCCESS.",
        ),
        _base_executor("ai_ops_maturity_checks", "KnowledgeBaseSyncHealthCheck"),
        False,
    ),
    _control(
        "ai-ops-model-cost-001",
        "qconnect.prompt.premium_model_cost_review",
        "AI Prompt Model Cost Review",
        _CO,
        Severity.LOW,
        _M,
        _methodology(
            "Prompts naming premium model families should receive a workload-specific cost and quality comparison before a model change is proposed.",
            "Paginated Connect assistant associations and Q ListAIPrompts expose assistant-scoped modelId summaries matched to premium-family name hints.",
            "Name matching is not authoritative pricing and reveals no request count, tokens, cache use, regional rates, output quality, or cheaper-model suitability.",
            "The finding is an evaluation candidate; premium model use can be intentional and economically justified.",
            "Measure exact model usage and billed cost, evaluate alternatives on representative conversations and safety criteria, and change only if quality targets hold.",
        ),
        _base_executor("ai_ops_maturity_checks", "AIPromptModelCostCheck"),
        False,
    ),
    _control(
        "ai-ops-bedrock-logging-001",
        "bedrock.region.invocation_log_destination_missing",
        "Bedrock Model Invocation Logging",
        _O,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Regions hosting Q assistant integrations need a Bedrock invocation-log destination for model-use investigation.",
            "Connect ListIntegrationAssociations establishes Q presence and Bedrock GetModelInvocationLoggingConfiguration returns CloudWatch or S3 destination objects.",
            "The regional setting does not prove per-assistant coverage, selected data types, destination health, encryption, retention, policy, or actual event delivery.",
            "A failure proves no destination object was configured in the assessed region; a pass is regional configuration evidence only.",
            "Configure the intended destination and data types, validate its controls, then send a safe invocation and confirm delivery.",
        ),
        _base_executor("ai_ops_maturity_checks", "BedrockInvocationLoggingCheck"),
        False,
    ),
    _control(
        "ai-ops-cross-region-001",
        "bedrock.region.cross_region_profile_inventory",
        "Bedrock Cross-Region Inference Availability",
        _R,
        Severity.LOW,
        _I,
        _methodology(
            "Available system-defined inference profiles are planning input for Q workload regional-resilience design.",
            "Connect assistant associations establish relevance and paginated Bedrock ListInferenceProfiles inventories system-defined profiles.",
            "Availability does not prove the assistant selects a profile, its model is covered, requests cross regions, capacity exists, or failover was tested.",
            "This is an account/region capability inventory and never establishes adoption.",
            "Resolve the assistant's deployed model and routing configuration, choose a supported profile if required, and test regional failure behavior.",
        ),
        _base_executor("ai_ops_maturity_checks", "CrossRegionInferenceAvailabilityCheck"),
        False,
    ),
    _control(
        "sec-lex-convlogs-001",
        "lexv2.audio_conversation_log.customer_key_missing",
        "Lex Conversation Log Encryption",
        _S,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Lex V2 audio conversation logs should name a customer-managed KMS key so recording access is governed by customer key policy.",
            "Connect ListBots identifies associated Lex V2 aliases and Lex DescribeBotAlias exposes conversationLogSettings audio S3 kmsKeyArn.",
            "Lex V1 is excluded; text-log KMS is not exposed by this API; key health, policy, bucket encryption, retention, and historical objects are not verified.",
            "A failure proves an enabled V2 audio destination lacks kmsKeyArn; text destinations remain separate inventory.",
            "Configure and validate the audio destination CMK, then inspect CloudWatch log-group kmsKeyId separately for text logs.",
        ),
        _base_executor("lex_security_checks", "LexConversationLogEncryptionCheck"),
        False,
    ),
    _control(
        "res-quota-config-001",
        "connect.quota.configuration_object_headroom_low",
        "Configuration Object Quota Utilization",
        _R,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Connect configuration counts near hard quotas can block user, queue, profile, flow, or phone-number changes.",
            "Analyzer counts plus paginated Connect user/number calls are compared with instance-level applied, account-level applied, then default Service Quotas values.",
            "Only evidence marked measured is evaluated; empty analyzer collections, bounded counts, unknown quota-name matches, or denied reads can leave dimensions unmeasured.",
            "A failure directly identifies a measured subject at or above 80 percent, while a pass does not cover listed unmeasured subjects.",
            "Resolve every unmeasured reason, confirm the applicable quota context, and reduce count or obtain quota headroom below the threshold.",
        ),
        _base_executor("capacity_checks", "ConfigurationQuotaUtilizationCheck"),
        False,
    ),
    _control(
        "res-quota-headroom-001",
        "connect.quota.concurrent_calls_headroom_low",
        "Concurrent Calls Quota Headroom",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Peak concurrent calls must retain headroom below the instance's resolved hard quota to avoid rejected contacts.",
            "CloudWatch GetMetricStatistics returns 30-day ConcurrentCalls maxima and Service Quotas resolution selects instance, account, or default capacity.",
            "The ratio covers observed voice peaks only and cannot predict campaigns, seasonality, future growth, missing metric periods, or other channels.",
            "A failure is direct measured capacity evidence at 80 percent or more, escalating at 95 percent.",
            "Confirm the resolved quota and peak window, then reduce peak demand or complete a quota increase and rerun below 80 percent.",
        ),
        _base_executor("capacity_checks", "ConcurrentCallsHeadroomCheck"),
        False,
    ),
    _control(
        "res-quota-growth-001",
        "connect.quota.concurrent_calls_growth_runway_short",
        "Call Volume Growth Against Quota",
        _R,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Sustained call-growth trends can exhaust a real concurrent-calls quota before operators have time to obtain capacity.",
            "Ninety days of daily CloudWatch ConcurrentCalls maxima are grouped into full weeks and fitted by least squares against the resolved quota.",
            "Linear projection cannot prove future demand and excludes seasonality, launches, campaigns, missing weeks, and business forecasts; stale or sparse series are not evaluated.",
            "A failure means the bounded observed trend projects quota contact within 26 weeks, not that exhaustion is certain.",
            "Compare the projection with the business forecast, confirm quota context, and obtain sufficient capacity before the documented runway closes.",
        ),
        _base_executor("capacity_checks", "CallVolumeGrowthTrendCheck"),
        False,
    ),
    _control(
        "res-acgr-config-001",
        "connect.acgr.configuration_inventory",
        "Amazon Connect Global Resiliency Configuration",
        _R,
        Severity.LOW,
        _I,
        _methodology(
            "Traffic distribution group discovery establishes whether ACGR-specific follow-up controls apply to the instance.",
            "Connect ListTrafficDistributionGroups provides TDG names and identifiers associated with the instance.",
            "A single unpaginated response and fail-open non-access errors do not prove complete discovery or ACGR correctness.",
            "This is applicability inventory; absence of ACGR is an architecture choice and is not a resilience failure.",
            "Confirm complete TDG discovery and, when present, evaluate identity, lifecycle, traffic, exercise, and number-binding controls.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRConfigurationCheck"),
        False,
    ),
    _control(
        "res-acgr-identity-001",
        "connect.acgr.global_sign_in.identity_not_saml",
        "ACGR Identity Management (SAML required)",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "ACGR Global Sign-in requires SAML identity so agents can authenticate to the surviving region during failover.",
            "TDG presence establishes applicability and Connect instance discovery supplies IdentityManagementType.",
            "The value does not prove IdP configuration, availability, MFA, successful Global Sign-in, or cross-region identity dependencies.",
            "A failure directly identifies an ACGR instance whose declared identity mode is not SAML.",
            "Configure and validate SAML for the ACGR instance, then test Global Sign-in and agent access in both regions.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRIdentityManagementCheck"),
        False,
    ),
    _control(
        "res-acgr-tdg-status-001",
        "connect.acgr.tdg.lifecycle_not_active",
        "ACGR Traffic Distribution Group Status",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Every ACGR traffic distribution group must be ACTIVE before it can be relied on for regional routing.",
            "Connect ListTrafficDistributionGroups and DescribeTrafficDistributionGroup provide each TDG control-plane status.",
            "ACTIVE does not prove telephony reachability, replicated dependencies, usable capacity, or successful failover; list-summary fallback can mask a detail-read gap.",
            "A failure proves at least one discovered TDG reports a non-ACTIVE or unknown lifecycle state.",
            "Resolve each TDG lifecycle error and rerun until all complete detail reads report ACTIVE, then test traffic separately.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRTrafficDistributionGroupStatusCheck"),
        False,
    ),
    _control(
        "res-acgr-traffic-dist-001",
        "connect.acgr.telephony_distribution_inventory",
        "ACGR Traffic Distribution Inventory",
        _R,
        Severity.HIGH,
        _I,
        _methodology(
            "Configured ACGR telephony percentages inventory the selected regional routing design without prescribing active-active operation.",
            "Connect GetTrafficDistribution must return a complete TelephonyConfig distribution for every discovered TDG; 100/0, single-region, and multi-region distributions are retained as valid inventory.",
            "Percentages do not prove traffic delivery, dependency readiness, capacity, failover success, or that the selected architecture meets the workload recovery objectives.",
            "PASS means complete distribution evidence was collected; SKIPPED means discovery or any TDG distribution evidence was incomplete or denied; NOT_APPLICABLE means no ACGR TDG was discovered.",
            "Confirm the chosen recovery design against workload objectives, then exercise traffic movement and regional dependencies separately.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRTrafficDistributionCheck"),
        False,
    ),
    _control(
        "res-acgr-failover-test-001",
        "connect.acgr.failover_exercise_event_missing_90d",
        "ACGR Failover Testing Evidence",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Recent traffic-distribution changes provide bounded, auditable evidence that an assessed ACGR TDG received an update request.",
            "CloudTrail LookupEvents is fully paginated over the last 90 days for UpdateTrafficDistribution; an event counts only when requestParameters.Id or a LookupEvents ResourceName matches an assessed TDG ID or ARN.",
            "Malformed or identity-free events cannot be scoped, unrelated TDG events are rejected, and a matched API event does not prove a meaningful shift, successful calls, agent access, notification, or dependency recovery.",
            "PASS means at least one event matched an assessed TDG; FAIL means the complete lookup contained no match, including when candidates were unrelated or unscopable; SKIPPED means TDG discovery, pagination, or access prevented complete evaluation.",
            "Review the matched TDG and percentage change, then retain an operational test record proving calls, agents, and regional dependencies worked.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRFailoverTestCheck"),
        False,
    ),
    _control(
        "res-acgr-numbers-001",
        "connect.acgr.phone_number.binding_requires_review",
        "ACGR Phone Number Binding",
        _R,
        Severity.HIGH,
        _M,
        _methodology(
            "Inbound numbers on an ACGR deployment should be reviewed to determine which must follow a TDG and which are intentionally regional.",
            "Connect ListPhoneNumbersV2 is called for the instance ARN and each discovered TDG ARN to compare target bindings.",
            "Binding does not prove carrier reachability or expected-number completeness; bounded pages and fail-open errors can omit numbers, and regional numbers may be intentional.",
            "A direct instance binding is a failover-scope review candidate rather than an automatic defect.",
            "Inventory every expected number, document regional exceptions, and bind required global numbers to the intended TDG before failover testing.",
        ),
        _base_executor("resilience_advanced_checks", "ACGRPhoneNumberBindingCheck"),
        False,
    ),
    _control(
        "res-cloudwatch-001",
        "connect.monitoring.critical_alarm_coverage_missing",
        "CloudWatch Alarm Coverage",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Operational teams need configured metric alarms for Connect voice capacity, throttling, missed calls, and call-volume conditions.",
            "CloudWatch DescribeAlarms is fully paginated; a metric alarm counts only with exact AWS/Connect namespace, a required metric name, InstanceId equal to the assessed instance, MetricGroup=VoiceCalls, ActionsEnabled not false, and at least one nonblank AlarmActions target.",
            "Composite alarms alone do not establish underlying metric coverage, and configured action targets do not prove threshold quality, ownership, state behavior, or successful runtime notification delivery.",
            "PASS means every required voice metric has a qualifying instance-specific metric alarm; rejected candidates are counted by wrong instance, missing or wrong dimensions, disabled actions, and absent action targets.",
            "Verify thresholds, missing-data behavior, action ownership, and runtime delivery for each qualifying alarm, and test the notification path separately.",
        ),
        _base_executor("resilience_advanced_checks", "CloudWatchAlarmMonitoringCheck"),
        False,
    ),
    _control(
        "res-carrier-diversity-001",
        "connect.phone_number.country_inventory",
        "Phone Number Carrier Diversity",
        _R,
        Severity.MEDIUM,
        _I,
        _methodology(
            "Phone-number country distribution supplies limited context for telephony concentration discussions.",
            "One Connect ListPhoneNumbersV2 response groups instance-bound numbers by PhoneNumberCountryCode.",
            "Country is not carrier or regional-failover diversity; TDG-bound numbers, pagination, reachability, and non-access API failures are not reliably covered.",
            "This inventory cannot declare a domestic-only contact center deficient or resilient.",
            "Review actual carriers, number targets, business geography, ACGR design, and tested failover paths outside this country summary.",
        ),
        _base_executor("resilience_advanced_checks", "CarrierDiversityCheck"),
        False,
    ),
    _control(
        "res-hardcoded-routing-001",
        "connect.flow.literal_routing_destination_inventory",
        "Hardcoded Routing Configuration",
        _R,
        Severity.LOW,
        _I,
        _methodology(
            "Literal queue, flow, endpoint, and phone destinations identify configuration that may need portability discussion.",
            "Parsed customer-authored flows are scanned for literal routing parameters; dynamic JSONPath values and default sample flows are excluded.",
            "Hardcoding is common and valid; the inventory does not establish environment variability, change frequency, reachability, or complete results when a flow cannot be parsed.",
            "This is a maintainability inventory, not proof of a resilience defect.",
            "For each literal, decide whether it varies by environment/region; externalize only values with a real portability requirement.",
        ),
        _base_executor("resilience_advanced_checks", "HardcodedRoutingCheck"),
        True,
    ),
    _control(
        "res-lambda-dependency-001",
        "connect.flow.lambda_error_transition_missing",
        "Lambda Error Routing Completeness",
        _R,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Every reachable customer-authored Lambda call site needs an explicit Error transition so invocation failure has a defined route.",
            "Parsed customer-authored flow graphs establish reachability and expose Error transitions per Lambda action; static Lambda resolution and GetFunction/VPC data add context only.",
            "Incomplete flow parsing, entry validation, or reachability prevents a clean conclusion; static analysis does not prove an Error target is caller-safe or that runtime recovery succeeds, and dynamic targets or failed Lambda lookups limit enrichment only.",
            "A failure proves a specific reachable Lambda action lacks an explicit Error transition, regardless of target resolution or Lambda network configuration.",
            "Add and test a caller-safe Error route at every flagged Lambda call site, including timeout, throttle, network, and function-error cases.",
        ),
        _base_executor("resilience_advanced_checks", "LambdaDependencyRiskCheck"),
        True,
    ),
    _control(
        "sec-prompt-inject-001",
        "connect.flow.dynamic_prompt_content_review",
        "Potential Unsafe Dynamic Content in Prompts",
        _S,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Reachable prompts containing non-system dynamic references need provenance, character-set, escaping, and error-route review.",
            "Parsed flow reachability and prompt/SSML text expose JSONPath references, which are classified against constrained Connect system and DTMF sources.",
            "The static scan does not trace attribute writers, prove caller control, evaluate sanitization/escaping, execute Polly, or demonstrate injection.",
            "A failure is a concrete unsafe-content candidate, not evidence of exploitation, code execution, or account compromise.",
            "Trace each value to its writer, enforce length/character rules and XML escaping, validate audience/error branches, and test safely at runtime.",
        ),
        _base_executor("contact_flow_security_checks", "DynamicPromptInjectionCheck"),
        True,
    ),
    _control(
        "sec-lambda-validation-001",
        "connect.flow.lambda_response_fallback_review",
        "Lambda Branch Default Fallback Review",
        _S,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Conditional routing on Lambda output needs expected-shape validation and a safe fallback for missing or malformed values.",
            "Parsed flow graphs identify Lambda actions with condition transitions and whether the same action has a default transition.",
            "The check does not inspect ResponseValidation, function code/output schema, downstream validation blocks, Error branches, or call-site reachability.",
            "A failure proves only that a conditional Lambda action lacks a parser-visible default edge.",
            "For each reachable call site, validate required types/values and test malformed, missing, timeout, and error responses through safe fallback routes.",
        ),
        _base_executor("contact_flow_security_checks", "LambdaResponseValidationCheck"),
        True,
    ),
    _control(
        "sec-toll-fraud-001",
        "connect.flow.dynamic_external_transfer_review",
        "External Transfer Toll Fraud Risk",
        _S,
        Severity.CRITICAL,
        _M,
        _methodology(
            "Dynamic external-transfer destinations can become toll-fraud paths unless upstream logic constrains them to approved numbers.",
            "Parsed flow transfer actions are inspected for destination parameters beginning with JSONPath syntax.",
            "The executor does not trace predecessors, reachability, allowlists, CheckAttribute/Lambda validation, destination format, or parse failures.",
            "A failure proves a dynamic destination exists, not that an attacker controls it or that validation is absent.",
            "Trace every reachable route to the transfer, enforce an approved-number allowlist with fail-closed fallback, and test rejected destinations.",
        ),
        _base_executor("contact_flow_security_checks", "ExternalTransferTollFraudCheck"),
        True,
    ),
    _control(
        "sec-sensitive-data-001",
        "connect.flow.sensitive_attribute_name_review",
        "Sensitive Data in Contact Attributes",
        _S,
        Severity.HIGH,
        _M,
        _methodology(
            "Attribute keys suggesting credentials or regulated identifiers warrant review because contact attributes can propagate to CTRs and logs.",
            "Parsed Set/UpdateContactAttributes keys are matched case-insensitively against sensitive-name hints.",
            "Names do not reveal values, provenance, tokenization, reachability, retention, or actual CTR/log exposure; custom names can evade the hints.",
            "The result is a data-lineage candidate and can include benign or already-tokenized fields.",
            "Inspect actual values and routes, remove secrets, tokenize or mask necessary identifiers, and verify logging, retention, and access controls.",
        ),
        _base_executor("contact_flow_security_checks", "SensitiveDataInAttributesCheck"),
        True,
    ),
    _control(
        "sec-pii-prompts-001",
        "connect.flow.potential_unmasked_pii_prompt_review",
        "PII Exposure in Voice Prompts",
        _S,
        Severity.HIGH,
        _M,
        _methodology(
            "Prompts that appear to speak regulated identifiers need proof that only an approved masked form reaches the caller.",
            "PlayPrompt and MessageParticipant text is matched to sensitive-name hints and simple masking terms.",
            "The scan does not establish reachability, resolved values, provenance, audience, transform correctness, SSML content, recording, or runtime speech.",
            "A failure is a potential disclosure path, not proof that full PII was spoken.",
            "Resolve the prompt at runtime, constrain it to the approved masked representation, confirm channel/audience, and test recording/redaction behavior.",
        ),
        _base_executor("contact_flow_security_checks", "PIIInPromptsCheck"),
        True,
    ),
    _control(
        "sec-excessive-agency-001",
        "iam.flow_lambda.sensitive_permission_scope",
        "Excessive Agency / Lambda Identity-Policy Scope",
        _S,
        Severity.HIGH,
        _C,
        _methodology(
            "Lambda execution roles referenced by Connect flows should not contain selected high-risk Allow actions beyond demonstrated function requirements.",
            "Flow Lambda ARNs are resolved with Lambda GetFunction; all pages of IAM ListRolePolicies/GetRolePolicy and ListAttachedRolePolicies plus GetPolicy/GetPolicyVersion default documents are inspected.",
            "The scan does not establish call-site reachability or evaluate NotAction, permission boundaries, SCPs, session policies, resource policies, trust policies, code behavior, business necessity, or resource/condition combinations as effective permissions.",
            "A failure proves a selected high-risk Allow action exists in an inspected identity-policy document; a pass covers only complete inline and attached managed identity-policy inspection.",
            "Validate function requirements and all omitted policy layers, then scope each identity-policy action, resource, and condition to the demonstrated behavior.",
        ),
        _base_executor("ai_agent_security_checks", "ExcessiveAgencyCheck"),
        True,
    ),
    _control(
        "cost-containment-001",
        "caller_path.agent_routing_without_self_service",
        "Self-Service Containment Analysis",
        _CO,
        Severity.HIGH,
        _M,
        _methodology(
            "Phone-reachable agent routes without effective automation are candidates for a business-specific containment opportunity review.",
            "Phone associations, stitched flow topology, bounded caller paths, and recognized DTMF, Lambda, Lex, or Agentic CX actions identify routes without self-service.",
            "Path enumeration is bounded and static analysis cannot prove intent suitability, production volume, successful containment, or savings.",
            "The result asks flow owners to investigate viable automation; it is not a failed cost control or a guaranteed deflection benefit.",
            "Trace each material inbound queue route, validate a real Lex, Agentic CX, DTMF, or Lambda resolution opportunity with production volume, and test success/fallback outcomes.",
        ),
        _JOURNEY_EXECUTOR_KEY,
        True,
        legacy_aliases=("journey-cost-001",),
        execution_source=ExecutionSource.JOURNEY,
    ),
    _control(
        "cost-wait-time-001",
        "connect.flow.queue_route_callback_review",
        "Queue Callback Availability Review",
        _CO,
        Severity.HIGH,
        _M,
        _methodology(
            "Queue routes without a callback option should be reviewed where actual waits create caller experience and telephony cost.",
            "Parsed flow action sets identify queue-transfer and callback action types.",
            "Whole-flow presence does not prove callback reachability, ordering, operation, acceptance, wait thresholds, traffic, or regional telephony rates.",
            "A failure is a callback-design candidate rather than proof of excessive wait or avoidable cost.",
            "Use historical queue waits to select material routes, then test callback offer, acceptance, queue placement, errors, and fallback before transfer.",
        ),
        _base_executor("cost_containment_checks", "QueueWaitTimeCheck"),
        True,
    ),
    _control(
        "cost-occupancy-001",
        "connect.agent_occupancy.analysis_not_performed",
        "Agent Occupancy Monitoring Guidance",
        _CO,
        Severity.MEDIUM,
        _I,
        _methodology(
            "Occupancy is useful staffing context, so the report should direct operations to an authoritative workforce analysis.",
            "The current executor makes no API call and always emits guidance with example occupancy thresholds.",
            "It proves nothing about agents, queues, intervals, shrinkage, service levels, seasonality, or actual occupancy.",
            "This is a reminder to perform analysis outside the assessment and must not be read as a pass.",
            "Query historical occupancy by queue, routing profile, and interval, then reconcile representative periods with staffing and service-level objectives.",
        ),
        _base_executor("cost_containment_checks", "AgentOccupancyCheck"),
        False,
    ),
    _control(
        "cost-fcr-001",
        "connect.flow.returning_caller_detection_review",
        "Returning Caller Pattern Review",
        _CO,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Returning-caller identification can support repeat-contact routing and FCR measurement when the business defines those outcomes.",
            "Parsed action types and parameter text are searched for previous/history/contact/CRM/profile name hints.",
            "Substring matches do not prove lookup semantics, route reachability, same-issue detection, production association, or measured first-contact resolution.",
            "A result is a flow-design review lead; one hint anywhere is not evidence of effective FCR tracking.",
            "Trace a phone-reachable authoritative history lookup, test new and returning callers, and reconcile the agreed FCR definition with CTR/reporting data.",
        ),
        _base_executor("cost_containment_checks", "RepeatContactFCRCheck"),
        True,
    ),
    _control(
        "cost-acw-001",
        "connect.after_contact_work.analysis_not_performed",
        "After-Contact-Work Monitoring Guidance",
        _CO,
        Severity.LOW,
        _I,
        _methodology(
            "After-contact work duration is staffing context that requires interval and queue-level operational data.",
            "The current executor makes no metric call and always returns guidance referencing a sample duration.",
            "It proves nothing about ACW duration, distribution, queue differences, required documentation, quality, workflow, or cost.",
            "This is an operations reminder, not an automated efficiency result.",
            "Query authoritative ACW over representative periods and review outliers against required workflow, quality outcomes, and tooling constraints.",
        ),
        _base_executor("cost_containment_checks", "AfterContactWorkCheck"),
        False,
    ),
    _control(
        "cost-data-continuity-001",
        "connect.flow.ivr_agent_context_continuity_review",
        "IVR-to-Agent Data Continuity",
        _CO,
        Severity.MEDIUM,
        _M,
        _methodology(
            "Material data collected before queue transfer should reach the agent workspace so callers are not asked to repeat it.",
            "Parsed flows count input/lookup actions, contact-attribute keys, and queue transfers using local three-input/two-attribute thresholds.",
            "The global unordered counts do not prove value lineage, same-route ordering, screen-pop delivery, caller repetition, or alternative CRM/Profile state paths.",
            "A failure is a context-transfer investigation candidate, not measured handle-time waste.",
            "Map each representative queue route's collected values to the agent desktop, test transfer/screen pop, and confirm with QA recordings and handle-time data.",
        ),
        _base_executor("cost_containment_checks", "IVRToAgentDataContinuityCheck"),
        True,
    ),
    _control(
        "cost-self-service-tier-001",
        "connect.flow.dtmf_without_conversational_ai_route_review",
        "Legacy DTMF-Only Self-Service",
        _CO,
        Severity.LOW,
        _M,
        _methodology(
            "A reachable queue route using DTMF without Lex or Agentic CX can be evaluated as a conversational-modernization opportunity.",
            "Bounded iterative route enumeration inspects customer-authored entry-to-queue paths for DTMF indicators and conversational AI actions or parameters.",
            "Static indicators can misclassify input mode, bounded simple paths omit repeated cycles, and conversational AI absence does not make DTMF defective or prove better economics.",
            "The finding identifies a specific route for usability and containment experimentation, not a mandatory migration.",
            "Confirm each route and volume, A/B test Lex or Agentic CX on containment, accessibility, quality, and fallback, and retain DTMF when it performs better.",
        ),
        _base_executor("cost_containment_checks", "LegacySelfServiceTierCheck"),
        True,
    ),
    _control(
        "sec-flow-auth-001",
        "caller_path.agent_queue_without_authentication",
        "Contact Flow Authentication Pattern",
        _S,
        Severity.LOW,
        _M,
        _methodology(
            "Agent-bound caller routes need an authentication review when their destination "
            "supports sensitive account operations because an unverified caller may obtain "
            "protected information or request unauthorized changes.",
            "Phone associations, stitched flow topology, and bounded path evidence identify queue "
            "routes without recognized authentication indicators.",
            "Hints do not prove successful fail-closed authentication, queue sensitivity, complete "
            "path enumeration, or dynamic cross-flow targets.",
            "A finding means a route may reach an agent without a recognized gate. If the queue "
            "handles sensitive requests, the route can increase unauthorized disclosure or "
            "account-change risk; the evidence does not prove authentication is required for that "
            "queue or exclude agent-side verification.",
            "Classify queue sensitivity, then trace every reachable route and test that successful "
            "fail-closed authentication dominates the transfer where required.",
        ),
        _JOURNEY_EXECUTOR_KEY,
        True,
        legacy_aliases=("journey-sec-001",),
        execution_source=ExecutionSource.JOURNEY,
    ),
    _control(
        "cx-personalization-001",
        "connect.flow.personalization_transfer_inventory",
        "Personalization & Transfer Analysis",
        _S,
        Severity.LOW,
        _I,
        _methodology(
            "Personalization and transfer-pattern inventory gives experience designers context for a separate customer-journey review.",
            "Parsed flow action types and parameters are searched for personalization hints and transfer categories.",
            "The executor always passes and does not establish reachability, production use, quality, effectiveness, completeness, or a security condition.",
            "This is descriptive CX inventory under the current pillar assignment, not a compliance outcome.",
            "Review reported flows against intended caller segments and transfer experience; validate changes with journey tests and outcome metrics.",
        ),
        _base_executor("contact_flow_behavior_checks", "PersonalizationAnalysisCheck"),
        True,
    ),
    _control(
        "ops-acxd-handoff-001",
        "connect.flow.acxd_handoff_inventory",
        "Agentic CX Handoff Inventory",
        _O,
        Severity.LOW,
        _I,
        _methodology(
            "A reachable Agentic CX handoff should be visible in the assessment so builders can verify which Connect flows delegate the participant to which configured application reference.",
            "Parsed customer-authored flow graphs establish reachability and read AgentConfiguration WorkspaceId, ApplicationId, and Alias plus optional-feature presence and context-variable names; context values are discarded.",
            "The Connect flow proves only the handoff and authored branches. It does not prove that the application, alias, build, or deployment exists; inspect application content or guardrails; or establish runtime containment.",
            "A pass means the redacted Connect-side handoff inventory completed, not that the Agentic CX application is healthy, deployed, guarded, or effective.",
            "Confirm each workspace, application, and alias reference against the intended Agentic CX deployment, then test the published Connect flow without exposing context-variable values.",
        ),
        _base_executor("acxd_checks", "ACXDHandoffInventoryCheck"),
        True,
    ),
    _control(
        "res-acxd-error-routing-001",
        "connect.flow.acxd_error_or_idle_timeout_route_missing",
        "Agentic CX Error and Idle-Timeout Routing",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Every reachable Agentic CX handoff needs explicit routes for participant inactivity and action failure so Connect has a defined caller outcome.",
            "Parsed customer-authored flow graphs establish reachability and inspect each Agentic CX action for InputTimeLimitExceeded and NoMatchingError error transitions; NoMatchingCondition is retained as separate evidence.",
            "Static Connect edges do not prove that a target is caller-safe, that the application emits an outcome, or that recovery works at runtime. Incomplete flow evidence prevents a clean pass.",
            "A failure proves that a reachable Connect handoff lacks an idle-timeout or catch-all error edge. It does not assess the internal Agentic CX application.",
            "Connect both required outputs to intentional caller-safe routes, publish the flow, and test idle-timeout and action-error scenarios end to end.",
        ),
        _base_executor("acxd_checks", "ACXDErrorRoutingCheck"),
        True,
    ),
    _control(
        "ops-acxd-escalation-001",
        "connect.flow.acxd_escalation_path_review",
        "Agentic CX Escalation Path Review",
        _O,
        Severity.MEDIUM,
        _M,
        _methodology(
            "A reachable Agentic CX handoff without an explicit Escalation condition should be reviewed against the intended human-support experience.",
            "Parsed customer-authored flow graphs establish reachability and inspect condition operands for the exact Escalation outcome.",
            "The flow cannot prove that human escalation is required, that the application emits Escalation, that the target reaches a staffed agent, or that the experience succeeds at runtime.",
            "A failure is a workload-specific review candidate, not a proven defect. A pass confirms only that an explicit escalation edge is authored.",
            "Document whether human escalation is required. If required, connect and test the Escalation route; otherwise record the intentional no-escalation design and its caller outcome.",
        ),
        _base_executor("acxd_checks", "ACXDEscalationReviewCheck"),
        True,
    ),
    _control(
        "res-flow-errors-001",
        "connect.flow.non_lambda_error_transition_missing",
        "Non-Lambda Error Routing Completeness",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "Every reachable customer-authored error-capable non-Lambda action needs an explicit Error transition so service or routing failure has a defined route.",
            "Parsed customer-authored flow graphs establish reachability and inspect Error transitions on the defined set of integration, input, transfer, and flow-module action types; Lambda actions are excluded.",
            "Incomplete flow parsing, entry validation, or reachability prevents a clean conclusion; static analysis does not prove an Error target is caller-safe, reachable at runtime, or operationally effective.",
            "A failure proves at least one specific reachable non-Lambda action lacks an explicit Error transition; any known missing transition fails without a tolerance threshold.",
            "Add and test a caller-safe Error transition on every flagged non-Lambda action for each supported service and error outcome.",
        ),
        _base_executor("contact_flow_behavior_checks", "ErrorHandlingCompletenessCheck"),
        True,
    ),
    _control(
        "res-flow-loops-001",
        "connect.flow.cycle_without_recognized_exit",
        "Contact Flow Loop Detection",
        _R,
        Severity.MEDIUM,
        _C,
        _methodology(
            "Reachable unbounded flow cycles can trap callers and consume contact capacity indefinitely.",
            "Iterative graph cycle detection classifies a cycle as bounded when it finds counter/comparison hints, input timeout, or a transition leaving the cycle.",
            "An exit edge may be infeasible and an unrecognized valid retry guard may fail; parse gaps and runtime branch conditions are not modeled.",
            "A failure proves a structural cycle without one of the recognized escape patterns, not that callers loop at runtime.",
            "Inspect each cycle's branch feasibility, add a tested maximum-attempt/timeout exit, and verify callers reach a safe terminal outcome.",
        ),
        _base_executor("contact_flow_behavior_checks", "LoopDetectionCheck"),
        True,
    ),
    _control(
        "ops-unreachable-blocks-001",
        "connect.flow.unreachable_action_review",
        "Unreachable Contact Flow Blocks",
        _O,
        Severity.LOW,
        _M,
        _methodology(
            "Actions unreachable from a valid flow entry should be reviewed as stale code or intentionally staged configuration.",
            "Parsed customer-authored graphs are traversed across default, conditional, and error transitions; unvisited action IDs and types are retained.",
            "Static reachability does not prove business usefulness, publication state, branch feasibility, traffic, or whether a staged block is intentionally disconnected.",
            "A failure proves graph-level unreachability in a complete export, while removal remains a human ownership decision.",
            "Confirm the block's intended future use and dependencies; reconnect it or remove it, republish/export, and rerun complete traversal.",
        ),
        _base_executor("contact_flow_behavior_checks", "UnreachableActionsCheck"),
        True,
    ),
    _control(
        "perf-lambda-count-001",
        "connect.flow.lambda_structure_inventory",
        "Lambda Usage Structure Review",
        _P,
        Severity.LOW,
        _I,
        _methodology(
            "Route-aware Lambda counts and call-site details provide neutral input for performance architecture review.",
            "Parsed flows report authored, reachable, and unreachable Lambda actions plus a bounded maximum on one simple route.",
            "AWS publishes no compliant block-count maximum; capped traversal values are lower bounds and do not reveal runtime frequency, duration, retries, concurrency, cost, or function health.",
            "A pass means structural inventory was produced, not that Lambda use is efficient or complete when flows were skipped.",
            "Reconcile skipped/capped analysis and review each material route with latency, dependency, traffic, and function telemetry.",
        ),
        _base_executor("performance_efficiency_checks", "LambdaInvocationCountCheck"),
        True,
    ),
    _control(
        "perf-sequential-lambda-001",
        "connect.flow.sequential_lambda_route_review",
        "Sequential Lambda Invocations",
        _P,
        Severity.LOW,
        _M,
        _methodology(
            "Two reachable Lambda calls before a caller-facing interaction merit latency, timeout, and dependency review.",
            "Breadth-first graph traversal records the first and next Lambda, intermediate path, transition labels, modes, timeouts, responses, and error targets.",
            "Static reachability does not prove runtime order/frequency, caller silence, combined latency, data dependency, or that consolidation/parallelism is safe.",
            "A failure identifies a concrete sequence for engineering review; dependent calls may be the correct design.",
            "Test success, timeout, throttle, service, and function-error paths; preserve dependencies and error semantics when changing the sequence.",
        ),
        _base_executor("performance_efficiency_checks", "SequentialLambdaCheck"),
        True,
    ),
    _control(
        "perf-flow-complexity-001",
        "connect.flow.structure_metrics_inventory",
        "Contact Flow Structure Review",
        _P,
        Severity.LOW,
        _I,
        _methodology(
            "Flow structure metrics help engineers focus a maintainability review without inventing a numerical compliance threshold.",
            "Parsed graphs report actions, reachable actions, longest simple route, integration points, cycles, bounded paths, and module calls.",
            "Capped metrics are lower bounds and static shape does not prove maintainability, correctness, runtime frequency, latency, ownership, or test coverage.",
            "A pass reports descriptive structure and does not certify an uncapped or maintainable flow when exports were skipped.",
            "Confirm all exports parsed and cap flags are clear, then assess high-change flows against ownership, tests, purpose, and observed caller outcomes.",
        ),
        _base_executor("performance_efficiency_checks", "FlowComplexityCheck"),
        True,
    ),
    _control(
        "journey-res-001",
        "caller_path.structural_dead_end",
        "Dead-End Caller Path",
        _R,
        Severity.HIGH,
        _C,
        _methodology(
            "A phone-anchored path that reaches an unrecognized successorless action has no modeled route to a supported caller outcome.",
            "Connect phone-number/flow associations, parsed flows, static cross-flow stitching, and bounded iterative path enumeration identify disconnect/dead_end terminals.",
            "Explicit DisconnectParticipant is not this predicate; dynamic transfers, parse/API gaps, cycles, depth limits, and path caps can hide paths, so missing findings cannot prove absence.",
            "A finding is direct evidence of one enumerated structural sink; the flow owner must still decide whether the outcome is intentional.",
            "Trace each recorded path in the current published flow, add a caller-safe terminal or document intent, and rerun with complete uncapped discovery.",
        ),
        _JOURNEY_EXECUTOR_KEY,
        True,
        execution_source=ExecutionSource.JOURNEY,
    ),
    _control(
        "journey-scope-001",
        "connect.flow.not_phone_reachable_usage_review",
        "Dormant Flows Detected",
        _CO,
        Severity.LOW,
        _M,
        _methodology(
            "Flows outside the discovered phone-anchored static closure are candidates for ownership and usage review.",
            "Connect ListPhoneNumbersV2/ListFlowAssociations plus static flow/module transfer resolution classify non-reachable parsed flows.",
            "No traffic metric or Tier 2 classification is implemented; dynamic references, non-phone entry points, seasonal/test/DR use, and fail-open API gaps can create false dormant labels.",
            "The result means not statically phone-reachable, never proven unused or safe to delete.",
            "Complete association discovery and inspect static/dynamic references, all channels, logs, CTRs, metrics, ownership, and seasonal/DR plans before cleanup.",
        ),
        _JOURNEY_EXECUTOR_KEY,
        True,
        execution_source=ExecutionSource.JOURNEY,
    ),
)


_ATOMIC_CONTROL_REGISTRY = AtomicControlRegistry(_CONTROLS)


def get_atomic_control_registry() -> AtomicControlRegistry:
    """Return the process-wide immutable atomic control catalog."""
    return _ATOMIC_CONTROL_REGISTRY
