# Toll-fraud controls: analysis and coverage

Why `sec-federation-001`, `sec-ip-access-001`, `sec-outbound-scope-001`,
`sec-outbound-dest-001`, and `sec-fraud-alerting-001` exist, and what each
does and does not establish.

Source: a post-incident walkthrough of a real agent-initiated toll-fraud case.
The attack chain was: Connect-managed password with no MFA → sign-in from an
arbitrary location → authenticated CCP session → agent-initiated outbound
dialing → premium-rate international destinations → ten days before anyone
noticed. The incident is genericized deliberately — no account names, instance
aliases, user names or dollar amounts; this repository is public.

## Coverage

| Gap | Control | Status |
|---|---|---|
| A1. MFA path | `sec-federation-001` | Can fail: HIGH for Connect-managed identity, MEDIUM for directory-backed, SKIPPED when the type is unknown |
| A2. IP-based access control | `sec-ip-access-001` | Added |
| A3. Who can dial out | `sec-outbound-scope-001` | Added |
| A4. Outbound destinations | `sec-outbound-dest-001` | Added. Reviews observed destinations, because the outbound country allowlist is AWS-managed and cannot be read through the API |
| A5. Cost-anomaly detection | `sec-fraud-alerting-001` | Added |

All five are read-only Manual Review records: non-scoring, and not exported to
Security Hub. Dormant *instances* (a second, older instance with enabled users)
are not covered by these controls.

## The analysis behind each control

None of the controls that existed at the time would have caught this
incident. `sec-toll-fraud-001` matches by name but covers contact-flow transfer
blocks with dynamic destinations — caller-driven IVR fraud — not an
authenticated agent dialing out.

### A1. MFA path — `sec-federation-001`

The closest control to the root cause read `IdentityManagementType` correctly,
but was Low/Informational and returned PASS on **both** branches. The non-SAML
branch only asked the reader to verify MFA themselves, so a Connect-managed
instance with no MFA anywhere produced a passing record that read as
reassurance.

It is now a failable Manual Review: HIGH for Connect-managed identity, MEDIUM
for directory-backed (MFA is possible through RADIUS but unverified), and
SKIPPED when the identity type is missing or unrecognised, never guessed.
Identity management cannot be changed on an existing instance, so remediation
leads with compensating controls and treats SAML as a new-instance migration.

### A2. IP-based access control — `sec-ip-access-001`

The customer in the incident had asked AWS to enable IP-based restrictions,
which means they were absent and are now considered load-bearing. Nothing in
the catalog looked at them: `sec-origins-001` despite its name checks CCP
*embedding* origins, not where agents sign in from.

### A3. Who can dial out — `sec-outbound-scope-001`

`sec-profile-audit-001` audits administrative permissions only, so a profile
granting outbound calling never registered. The CCP "Make outbound calls"
permission is `OutboundCallAccess`, and Connect's default Agent profile grants
it, so an unscoped instance sits near 100%.

### A4. Where calls went — `sec-outbound-dest-001`

The outbound country allowlist is AWS-managed and cannot be read through any
API, so the control reviews outcomes instead: recent agent-dialed, callback and
API-started calls, by country calling code, against the instance's own numbers.
Dialed numbers are reduced to a calling code in memory and never logged or
reported.

### A5. Detection — `sec-fraud-alerting-001`

The ten-day dwell time was the expensive part. `res-cloudwatch-001` could not
help: the call-volume metrics it requires barely move for low-volume
premium-rate dialing. This control checks instead for a Cost Anomaly Detection
alert (IMMEDIATE or DAILY) or a Connect-filtered budget that actually
notifies someone.

## Limits worth knowing

- `SearchContacts` caps its time range at 1345 hours; `sec-outbound-dest-001`
  uses a fixed 14-day window and samples the 100 most recent contacts.
- Authentication profiles are enabled per account by AWS. Until they are, the
  API answers that the account "is not allowed to use this feature", which
  `sec-ip-access-001` reports as a finding.
- Cost Anomaly Detection monitors and Budgets in an AWS Organizations
  management account are not visible from a member account.
