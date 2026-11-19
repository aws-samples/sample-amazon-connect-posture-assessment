"""
Data models for Caller Journey Mapping.

These represent the entry-point topology (phone numbers, SMS/WhatsApp
numbers, email addresses, and traffic-observed entry flows), the cross-flow
super-graph, enumerated paths, and per-journey scoring used by the journey
mapping pipeline.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PhoneNumberEntry:
    """A phone number (DID or toll-free) mapped to its entry flow."""

    phone_number: str
    number_type: str  # "DID" | "TOLL_FREE"
    country_code: str
    contact_flow_id: Optional[str] = None
    contact_flow_name: Optional[str] = None
    target_arn: Optional[str] = None


# Contact channels as Amazon Connect reports them. SMS and WhatsApp contacts
# are CHAT-channel contacts (subtype connect:SMS / connect:WhatsApp).
# Customer-facing channels first; this order is used for sorting and summaries.
CHANNELS = ("VOICE", "CHAT", "EMAIL", "TASK")


@dataclass
class EntryPoint:
    """
    Where a customer contact enters the instance, on any channel.

    ``entry_type`` says how the entry was discovered:

    * ``DID`` / ``TOLL_FREE`` — a voice phone number association
    * ``SMS`` / ``WHATSAPP`` — a messaging number association (CHAT channel)
    * ``EMAIL_ADDRESS`` — an inbound email address association
    * ``OBSERVED_FLOW`` — a contact flow that started contacts on this channel
      without any discoverable association (web chat, tasks, API-started
      contacts). Chat in particular has no control-plane entry point:
      ``StartChatContact`` takes the flow ID from the caller.
    """

    channel: str  # one of CHANNELS
    entry_type: str
    identifier: str  # E.164 number, email address, or flow name
    contact_flow_id: str
    contact_flow_name: Optional[str] = None
    source: str = ""  # API or signal the entry was discovered from
    country_code: str = ""
    description: str = ""
    observed_contact_count: Optional[int] = None

    @property
    def key(self) -> str:
        """Stable identity: the same number can be both a voice and an SMS entry."""
        return f"{self.channel}|{self.entry_type}|{self.identifier}"


@dataclass
class TierAssignment:
    """Tier classification for a flow with rationale."""

    flow_id: str
    flow_name: str
    tier: str  # "tier1_did" | "tier1_tollfree" | "tier2_traffic" | "tier3_dormant"
    rationale: str
    # Contacts observed starting this flow over ``observed_window_days``
    # (GetMetricDataV2). Both are None when usage metrics were unavailable,
    # which is distinct from an observed count of 0.
    observed_contact_count: Optional[int] = None
    observed_window_days: Optional[int] = None
    # Observed contacts per channel ("VOICE" | "CHAT" | "TASK" | "EMAIL").
    # A flow's own metadata carries no channel dimension, so this is the only
    # reliable signal for which channels actually use a flow.
    channel_mix: Dict[str, int] = field(default_factory=dict)


@dataclass
class JourneyNode:
    """A node in the super-graph, referencing both its source flow and action."""

    flow_id: str
    flow_name: str
    action_id: str
    action_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Unique key combining flow and action for graph lookups."""
        return f"{self.flow_id}::{self.action_id}"


@dataclass
class JourneyPath:
    """A complete customer journey from an entry point to a terminal outcome."""

    entry_identifier: str  # phone number, email address, or flow name
    entry_type: str  # EntryPoint.entry_type
    nodes: List[JourneyNode] = field(default_factory=list)
    terminal_type: str = ""
    # "agent_queue" | "disconnect" | "callback" | "bot_resolved" |
    # "external_transfer" | "voicemail"
    terminal_details: Dict[str, Any] = field(default_factory=dict)
    flows_traversed: List[str] = field(default_factory=list)
    entry_channel: str = "VOICE"

    @property
    def entry_number(self) -> str:
        """Deprecated alias for ``entry_identifier`` (voice-era name)."""
        return self.entry_identifier

    @property
    def entry_number_type(self) -> str:
        """Deprecated alias for ``entry_type`` (voice-era name)."""
        return self.entry_type

    @property
    def entry_key(self) -> str:
        return f"{self.entry_channel}|{self.entry_type}|{self.entry_identifier}"

    @property
    def path_hash(self) -> str:
        """Deterministic hash for deduplication and scoring lookup.

        Scoring is channel-specific, so the same node sequence reached from a
        voice and an SMS entry must hash differently. VOICE keeps the original
        node-only key so voice hashes are unchanged across releases.
        """
        key = "|".join(n.key for n in self.nodes)
        if self.entry_channel != "VOICE":
            key = f"{self.entry_channel}#{key}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def depth(self) -> int:
        return len(self.nodes)


@dataclass
class JourneyScore:
    """Scoring results for a single journey path."""

    # Security
    has_authentication: bool = False
    auth_position: Optional[int] = None

    # Self-service / containment
    has_self_service: bool = False
    self_service_actions: List[str] = field(default_factory=list)

    # Resilience
    has_callback_offering: bool = False
    dead_end_count: int = 0
    consecutive_no_error_max: int = 0
    single_queue_funnel: bool = False

    # CX
    has_personalization: bool = False
    has_returning_caller_detection: bool = False
    has_dynamic_prompt: bool = False
    has_nlu_bot: bool = False

    # Aggregate
    cx_maturity: str = "Basic"  # "Basic" | "Intermediate" | "Advanced"
    deficiencies: List[str] = field(default_factory=list)
    channel: str = "VOICE"

    @property
    def cx_feature_count(self) -> int:
        """CX features present, counting only those meaningful on this channel."""
        from .channels import rules_for

        return sum(bool(getattr(self, name)) for name in rules_for(self.channel).cx_features)


@dataclass
class SuperGraph:
    """
    Instance-wide directed graph spanning multiple contact flows.

    Nodes are JourneyNodes; edges cross flow boundaries at transfer points.
    """

    nodes: Dict[str, JourneyNode] = field(default_factory=dict)
    adjacency: Dict[str, List[str]] = field(default_factory=dict)
    entry_points: Dict[str, str] = field(default_factory=dict)
    # flow_id → entry node key
    dynamic_references: List[Dict[str, Any]] = field(default_factory=list)

    def successors(self, node_key: str) -> List[str]:
        return self.adjacency.get(node_key, [])

    def get_node(self, node_key: str) -> Optional[JourneyNode]:
        return self.nodes.get(node_key)


@dataclass
class JourneyMapResult:
    """Complete journey mapping results for the instance."""

    phone_entries: List[PhoneNumberEntry] = field(default_factory=list)
    # Every entry point on every channel that journeys were enumerated from.
    entry_points: List["EntryPoint"] = field(default_factory=list)
    tier_assignments: List[TierAssignment] = field(default_factory=list)
    journeys: List[JourneyPath] = field(default_factory=list)
    scores: Dict[str, JourneyScore] = field(default_factory=dict)
    dormant_flows: List[str] = field(default_factory=list)
    # Observed starting contacts, but not reachable from any entry point and
    # not an entry point themselves — typically queue, hold, and whisper
    # flows, or sub-flows invoked dynamically. In use, so not dormant.
    traffic_observed_flows: List[str] = field(default_factory=list)
    # "complete" when usage metrics were resolved; otherwise why not
    # ("access_denied" | "error" | "not_requested"). When not complete,
    # dormant labels are reachability-only.
    usage_metrics_status: str = "not_requested"
    usage_window_days: int = 0
    dynamic_edges: List[Dict[str, Any]] = field(default_factory=list)
    containment_scores: Dict[str, float] = field(default_factory=dict)
    enumeration_complete: bool = True
    enumeration_limitations: List[str] = field(default_factory=list)
    # Per-channel coverage: {channel: {"complete": bool, "limitations": [...],
    # "entry_points": int, "journeys": int}}. A gap on one channel (say, a
    # dynamic transfer inside a chat flow) must not mark voice incomplete.
    channel_coverage: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Why some entry points could not be discovered (permission denied, API
    # error), per source. These narrow coverage without failing the run.
    entry_discovery_limitations: List[str] = field(default_factory=list)
    # Channels whose entry-point discovery failed (denied or errored
    # association/phone-number lookups). Reachability, and so every tier
    # label, is unreliable for these channels.
    discovery_incomplete_channels: List[str] = field(default_factory=list)

    def mark_incomplete(self, limitation: str) -> None:
        """Record an instance-wide gap: every channel becomes incomplete."""
        self.enumeration_complete = False
        self.enumeration_limitations = list(
            dict.fromkeys([*self.enumeration_limitations, limitation])
        )
        for coverage in self.channel_coverage.values():
            coverage["complete"] = False
            coverage["limitations"] = list(
                dict.fromkeys([*coverage.get("limitations", []), limitation])
            )

    def channel_complete(self, channel: str) -> bool:
        coverage = self.channel_coverage.get(channel)
        if coverage is None:
            return self.enumeration_complete
        return bool(coverage.get("complete"))

    @property
    def total_journeys(self) -> int:
        return len(self.journeys)

    @property
    def journeys_without_auth(self) -> int:
        return sum(
            1
            for j in self.journeys
            if j.terminal_type == "agent_queue"
            and not self.scores.get(j.path_hash, JourneyScore()).has_authentication
        )

    @property
    def journeys_without_self_service(self) -> int:
        return sum(
            1
            for j in self.journeys
            if not self.scores.get(j.path_hash, JourneyScore()).has_self_service
        )
