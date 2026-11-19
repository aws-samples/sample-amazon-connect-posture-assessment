"""
Per-channel journey scoring rules.

The journey controls were written for voice: "no authentication before the
agent queue", "no self-service menu", "no callback offered". Applied
unchanged to other channels they produce wrong findings — a task has no
customer to authenticate, and an email cannot be offered a callback. Each
rule below states, per channel, whether it applies and why not when it
doesn't, so a finding can say which channels it covered and which it
excluded instead of silently scoring everything as a phone call.

SMS and WhatsApp contacts are CHAT-channel contacts in Amazon Connect, so
they share the CHAT rules.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass(frozen=True)
class ChannelRules:
    channel: str
    # Rule applicability. A False rule is excluded from that channel's
    # findings, with ``not_applicable`` explaining why.
    authentication: bool
    self_service: bool
    callback: bool
    dead_end: bool
    # CX features that are meaningful on this channel (JourneyScore fields).
    cx_features: Tuple[str, ...]
    not_applicable: Dict[str, str] = field(default_factory=dict)

    def applies(self, rule: str) -> bool:
        return bool(getattr(self, rule))

    def maturity(self, feature_count: int) -> str:
        """Basic / Intermediate / Advanced, scaled to the channel's feature set.

        Voice keeps its original thresholds (4 of 5 Advanced, 2 Intermediate).
        """
        total = len(self.cx_features)
        if total and feature_count >= math.ceil(total * 0.8):
            return "Advanced"
        if total and feature_count >= math.ceil(total * 0.4):
            return "Intermediate"
        return "Basic"


CHANNEL_RULES: Dict[str, ChannelRules] = {
    "VOICE": ChannelRules(
        channel="VOICE",
        authentication=True,
        self_service=True,
        callback=True,
        dead_end=True,
        cx_features=(
            "has_personalization",
            "has_callback_offering",
            "has_returning_caller_detection",
            "has_dynamic_prompt",
            "has_nlu_bot",
        ),
    ),
    "CHAT": ChannelRules(
        channel="CHAT",
        authentication=True,
        self_service=True,
        callback=False,
        dead_end=True,
        cx_features=(
            "has_personalization",
            "has_returning_caller_detection",
            "has_dynamic_prompt",
            "has_nlu_bot",
        ),
        not_applicable={
            "callback": "a chat customer stays in the conversation, so there is no call to call back",
        },
    ),
    "EMAIL": ChannelRules(
        channel="EMAIL",
        authentication=False,
        self_service=False,
        callback=False,
        dead_end=True,
        cx_features=("has_personalization", "has_returning_caller_detection"),
        not_applicable={
            "authentication": (
                "an email flow has no interactive step in which to verify the sender, so "
                "identity verification belongs with the agent or a sender-based lookup"
            ),
            "self_service": (
                "an email flow cannot prompt for input, so there is no menu or bot to contain "
                "the contact before an agent"
            ),
            "callback": "email is asynchronous, so there is no queue wait to replace",
        },
    ),
    "TASK": ChannelRules(
        channel="TASK",
        authentication=False,
        self_service=False,
        callback=False,
        dead_end=True,
        cx_features=("has_personalization",),
        not_applicable={
            "authentication": (
                "tasks are created by agents, rules, or APIs rather than by an unverified customer"
            ),
            "self_service": "a task is work for an agent by design, not a customer to contain",
            "callback": "a task has no waiting customer",
        },
    ),
}


def rules_for(channel: str) -> ChannelRules:
    """Rules for a channel; unknown channels are scored conservatively as voice."""
    return CHANNEL_RULES.get(channel, CHANNEL_RULES["VOICE"])
