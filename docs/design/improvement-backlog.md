# Improvement backlog

Known gaps in the control catalog and the journey pipeline, with enough detail
to pick one up cold. Ordered by value within each section.

Entries here are deliberately *not* filed as issues against individual checks —
several of them are gaps in what the catalog covers at all, which only show up
when you walk a real incident against it.

---

## A. Agent-initiated outbound toll fraud — open follow-up

Found by walking a real toll-fraud incident against the catalog. The controls
that cover the attack chain itself live in the catalog; this is the one gap
that remains.

### A6. Dormant *instances* are not flagged

The incident account had a second, older Connect instance in the same Region.
If an instance like that still has enabled users with outbound access, it is
unmonitored attack surface. `journey-scope-001` covers dormant *flows* only.

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

- **Do not put customer identifiers in this repo.** Incident-derived items
  here have been genericized deliberately — no account names, instance
  aliases, user names or dollar amounts. This repository is public.
- Catalog changes need `docs/check-catalog.md` updates;
  `tests/test_documentation_consistency.py` enforces that consistency.
