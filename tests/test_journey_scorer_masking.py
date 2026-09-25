"""Tests for phone-number masking in journey finding evidence."""

from amazon_connect_assessment.journey.journey_scorer import _mask_number


class TestMaskNumber:
    def test_masks_e164_number_keeping_last_four(self):
        assert _mask_number("+18005551212") == "***-***-1212"

    def test_masks_formatted_number_keeping_last_four(self):
        assert _mask_number("(800) 555-6789") == "***-***-6789"

    def test_short_number_is_fully_masked(self):
        assert _mask_number("911") == "***"

    def test_empty_string_returned_unchanged(self):
        assert _mask_number("") == ""

    def test_full_number_is_never_present_in_output(self):
        number = "+441632960123"
        masked = _mask_number(number)
        assert number not in masked
        assert masked.endswith("0123")


class TestJourneyFindingInstance:
    def _result(self):
        from amazon_connect_assessment.journey.models import (
            JourneyMapResult,
            JourneyNode,
            JourneyPath,
        )

        node = JourneyNode(flow_id="f1", flow_name="Main", action_id="a1", action_type="Transfer")
        path = JourneyPath(
            entry_number="+18005551212",
            entry_number_type="TOLL_FREE",
            nodes=[node],
            terminal_type="agent_queue",
            terminal_details={"queue": "Sales"},
            flows_traversed=["Main"],
        )
        return JourneyMapResult(journeys=[path])

    def test_per_number_findings_record_owning_instance(self):
        from amazon_connect_assessment.journey.journey_scorer import generate_journey_findings

        findings = generate_journey_findings(self._result(), instance_id="inst-1")

        per_number = [f for f in findings if f.resource_type == "PhoneNumberJourney"]
        assert per_number
        assert all(f.evidence["instance_id"] == "inst-1" for f in per_number)

    def test_instance_id_omitted_when_unknown(self):
        from amazon_connect_assessment.journey.journey_scorer import generate_journey_findings

        findings = generate_journey_findings(self._result())

        assert all("instance_id" not in f.evidence for f in findings)
