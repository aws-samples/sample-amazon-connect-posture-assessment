# Improvement backlog

Known gaps in the control catalog and the journey pipeline, with enough detail
to pick one up cold. Ordered by value within each section.

Entries here are deliberately *not* filed as issues against individual checks —
several of them are gaps in what the catalog covers at all, which only show up
when you walk a real incident against it.

---

## A. Agent-initiated outbound toll fraud

Source: a post-incident walkthrough of a real toll-fraud case. The attack chain
was: Connect-managed password with no MFA → sign-in from an arbitrary location →
authenticated CCP session → agent-initiated outbound dialing → premium-rate
international destinations → ten days before anyone noticed.

**None of the 64 controls would have caught it.** Audited 2026-11-18; the
findings below were verified against the current code, not assumed.

### A1. `sec-federation-001` cannot fail (highest value, smallest change)

[`security_deep_checks.py:1272`](../../amazon_connect_assessment/checks/security_deep_checks.py)

This is the control closest to the root cause. It reads
`IdentityManagementType` correctly, but it is `Severity.LOW` /
informational and **both** branches `return CheckStatus.PASS` — the
non-SAML path emits a PASS whose description just asks the reader to verify MFA
themselves. On the incident account it would have sat in the report as a passing
informational record.

Connect-managed identity with no evidence of an external MFA layer is a real
finding, not inventory. Promote to High / Manual Review and have the non-SAML
branch return something other than PASS. Registry entry to update in parallel:
[`control_registry.py:442`](../../amazon_connect_assessment/checks/control_registry.py)
(`Severity.LOW`, disposition `_I`).

### A2. No check for IP-based access control

The customer in the incident had explicitly asked AWS to enable IP-based
restrictions — which means it was absent, and that they now consider it the
load-bearing control. Nothing in the catalog looks at it.

Note that `sec-origins-001` is **not** this control despite "Access Control" in
its name: it checks CCP *embedding* origins for wildcards.

### A3. No visibility into who can dial out

`sec-profile-audit-001` is High / Manual Review, but its `_ADMIN_PERMISSIONS`
set is only `Users.*`, `SecurityProfiles.*`, `InstanceSettings.Edit`
([`security_deep_checks.py:1323`](../../amazon_connect_assessment/checks/security_deep_checks.py)).
Outbound-calling permission is not in it, so the compromised agent's profile
would not have registered.

Inventory security profiles that grant outbound calling and flag broad
assignment. Today the only outbound signal anywhere in the codebase is
instance-level `OutboundCallsEnabled`.

### A4. No check for outbound destination restriction

Country or premium-rate prefix allowlisting. **Scope this one only after
confirming what Connect actually exposes via API for agent-initiated outbound** —
it may not be assessable, in which case it belongs in guidance rather than as a
check.

### A5. No detection control for outbound cost/destination anomaly

The ten-day dwell time was the expensive part of the incident, and nothing in
the catalog looks for it.

`res-cloudwatch-001` is the closest and may well have failed on this account,
but it would not have helped: it requires alarms on `ConcurrentCalls`,
`ThrottledCalls`, `MissedCalls`, `CallsPerInterval`, none of which move
meaningfully for low-volume premium-rate dialing.

### A6. Dormant *instances* are not flagged

The incident account had a second, older Connect instance in the same Region.
If an instance like that still has enabled users with outbound access, it is
unmonitored attack surface. `journey-scope-001` covers dormant *flows* only.

### Also worth knowing

`sec-toll-fraud-001` is Critical / Manual Review and its name matches this
incident, but it is scoped to **contact flow** transfer blocks with JSONPath
destinations — i.e. caller-driven IVR fraud. This was an authenticated agent
dialing out. Right name, wrong vector; don't assume it covers this.

---

## B. Multi-channel journey mapping

The journey pipeline maps voice only. Groundwork landed on
`feature/journey-channel-classification`: per-flow, per-channel contact counts
via `GetMetricDataV2`, which promotes traffic-carrying unreachable flows to
tier 2. That makes non-voice flows *visible*; it does not make them
*traversable* from their own entry points.

### B1. Email entry points

Smallest remaining win and structurally identical to the voice path already
built: `SearchEmailAddresses` + `ListFlowAssociations(ResourceType=INBOUND_EMAIL)`
→ email address ARN → flow ID.

### B2. SMS entry points

`ListFlowAssociations` **cannot** enumerate these — `SMS_PHONE_NUMBER` is not in
its ResourceType enum (only the singular `GetFlowAssociation` accepts it).
Enumerate via AWS End User Messaging `pinpoint-sms-voice-v2:DescribePhoneNumbers`,
then `GetFlowAssociation` per ARN. Needs a new client and a new IAM permission.

WhatsApp *is* enumerable through `ListFlowAssociations`, but its ResourceIds are
`arn:aws:social-messaging:…` ARNs, so it needs the same channel-aware entry-point
model as SMS to be useful.

### B3. Chat entry points have no control-plane source

`StartChatContact` takes `ContactFlowId` from the caller, so the widget→flow
mapping lives in the widget snippet or your own application, not in Connect.
There is no widget API to enumerate (only `StartChatContact`,
`StartOutboundChatContact`, `SendChatIntegrationEvent`). Options are
user-supplied mappings in config, or relying on the traffic-derived
classification from B's groundwork.

### B4. Generalize the entry-point model

`PhoneNumberEntry` → `EntryPoint(channel, identifier, identifier_type, flow_id)`,
and `JourneyPath.entry_number` / `entry_number_type` →
`entry_identifier` / `entry_channel`. The super-graph, DFS and terminal
classification are already channel-agnostic and need no changes; the rename
touches `renderer.py`, `view_model.py`, `journey_scorer.py` and ~4 test files.

### B5. Per-channel scoring rules

`JourneyScore` is voice-shaped. `has_callback_offering` and
`consecutive_no_error_max` are meaningless for email, and chat should not be
penalized for lacking a callback offer. Needs per-channel rule sets plus new
terminal types (`task_created`, `case_created`).

---

## Notes for whoever picks these up

- **Do not put customer identifiers in this repo.** The incident behind
  section A has been genericized deliberately — no account names, instance
  aliases, user names or dollar amounts. This repository is public.
- `connect:GetMetricDataV2` is already in the IAM policy template, so B's
  groundwork needed no permission change. A2–A5 likely will.
- Section A items are catalog changes and will need `docs/check-catalog.md`
  updates; `tests/test_documentation_consistency.py` enforces that consistency.
