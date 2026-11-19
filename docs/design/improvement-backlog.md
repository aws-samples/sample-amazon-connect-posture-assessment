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

**Status: A1–A5 are done in PR #23; A6 is open.** The controls are
`sec-federation-001` (A1, now failable), `sec-ip-access-001` (A2),
`sec-outbound-scope-001` (A3), `sec-outbound-dest-001` (A4, reviews observed
destinations because the AWS-managed allowlist is unreadable), and
`sec-fraud-alerting-001` (A5). The analysis below is kept as the record of
why each exists.

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

**Status: B1, B2, B4 and B5 are done; B3 is addressed by observed entries.**
Journeys are now discovered, enumerated and scored on every channel. What
remains is listed under "Open" below.

### Done

- **B1. Email entry points.** `ListFlowAssociations(INBOUND_EMAIL)`, labelled
  through `SearchEmailAddresses` (optional: without it the entry keeps its
  address ID).
- **B2. SMS and WhatsApp entry points.** `ListFlowAssociations` for
  `SMS_PHONE_NUMBER` and `WHATSAPP_MESSAGING_PHONE_NUMBER`. Verified live:
  a Connect-claimed number's SMS association uses the same `arn:aws:connect`
  phone-number ARN as `ListPhoneNumbersV2`, so it resolves to its E.164 number
  with no End User Messaging call. An earlier note here said to enumerate SMS
  via `pinpoint-sms-voice-v2:DescribePhoneNumbers`; that turned out to be
  unnecessary for Connect-claimed numbers.
- **B3. Chat entry points.** Still no control-plane source (`StartChatContact`
  takes the flow ID from the caller), so web chat, task, and API-started entry
  flows are discovered from `GetMetricDataV2` `FLOWS_STARTED` by flow and
  channel: an entry-capable flow that starts contacts on a channel without
  being reachable from that channel's associations is an *observed* entry.
- **B4. Entry-point model.** `journey.models.EntryPoint(channel, entry_type,
  identifier, contact_flow_id, …)`, keyed by channel and resource, and
  `JourneyPath.entry_identifier` / `entry_type` / `entry_channel`
  (`entry_number` remains as an alias).
- **B5. Per-channel scoring.** `journey/channels.py` defines per-channel rule
  applicability (authentication, self-service, callback, dead end), CX
  features, and the reason each excluded rule does not apply. Coverage is
  tracked per channel, so a gap on one channel does not mark another
  incomplete.

### Open

- **Observed entries depend on traffic in the window.** A web chat or task
  flow with no contacts in the last `traffic_lookback_days` (max 34) is not
  discovered. Seasonal chat flows will be missed outside their season.
- **Observed entries are heuristic.** A flow started by
  `StartOutboundVoiceContact`, or one reached only through a dynamic
  transfer, also qualifies. Labels say "observed" for that reason.
  `INITIATION_METHOD` grouping on the same metric could separate inbound
  from outbound; not done yet.
- **End User Messaging–only numbers** (not claimed in Connect) are mapped,
  but labelled by resource ID rather than E.164; resolving them needs
  `pinpoint-sms-voice-v2` / `social-messaging` read permissions.
- **Chat authentication recognition** counts any action type containing
  "Authenticat" (for the Authenticate Customer block), since the flow-language
  action name for that block is not documented. Confirm it against an
  exported flow that uses the block.

## Notes for whoever picks these up

- **Do not put customer identifiers in this repo.** The incident behind
  section A has been genericized deliberately — no account names, instance
  aliases, user names or dollar amounts. This repository is public.
- `connect:GetMetricDataV2` is already in the IAM policy template, so B's
  groundwork needed no permission change. A2–A5 likely will.
- Section A items are catalog changes and will need `docs/check-catalog.md`
  updates; `tests/test_documentation_consistency.py` enforces that consistency.
