"""Tests for the control mapping knowledge base.

The mapping is the contribution of this project, so it is tested as data: every control
reference must resolve, every mapping must carry a reason, and the protocol coverage must
be complete. A broken mapping produces a confidently wrong compliance report, which is the
worst failure mode this tool has.
"""

import pytest

from policyprobe import kb
from policyprobe.data.catalog import DEVICE_PROFILES


def test_knowledge_base_validates():
    assert kb.validate() == []


def test_every_weakness_maps_to_both_frameworks():
    for weakness in kb.load_mapping()["weaknesses"]:
        assert weakness["iso27001"], f"{weakness['id']} has no ISO 27001 mapping"
        assert weakness["nist80053"], f"{weakness['id']} has no NIST 800-53 mapping"


def test_every_weakness_degrades_at_least_one_control():
    """A weakness mapped only to 'evidence' rows would never surface in a posture, which
    would make it invisible in the report it was written for."""
    for weakness in kb.load_mapping()["weaknesses"]:
        relations = {r["relation"] for r in weakness["iso27001"] + weakness["nist80053"]}
        assert relations & {"violates", "weakens"}, f"{weakness['id']} affects nothing"


def test_severity_agrees_with_relation():
    """Severity and mapping must tell the same story.

    A High or Critical weakness has to fail a control outright — if it only ever weakens
    one, either the severity is overstated or the mapping is understated. Conversely a
    weakness that fails nothing must not be rated above Medium. W-ROLLING-REPLAY is the
    case this guards: a rolling code genuinely does provide partial protection, so it
    weakens controls rather than failing them, and it is rated Medium to match.
    """
    for weakness in kb.load_mapping()["weaknesses"]:
        relations = {r["relation"] for r in weakness["iso27001"] + weakness["nist80053"]}
        fails = "violates" in relations
        severity = weakness["base_severity"]
        if severity in ("High", "Critical"):
            assert fails, f"{weakness['id']} is {severity} but fails no control"
        if not fails:
            assert severity in ("Informational", "Low", "Medium"), weakness["id"]


def test_control_ids_resolve_to_catalogued_controls():
    for weakness in kb.load_mapping()["weaknesses"]:
        for framework, key in kb.MAPPING_KEY.items():
            index = kb.controls_index(framework)
            for ref in weakness[key]:
                assert ref["id"] in index
                assert index[ref["id"]]["title"]


def test_rationales_are_substantive():
    """A one-word rationale is not defensible in front of an auditor."""
    for weakness in kb.load_mapping()["weaknesses"]:
        for ref in weakness["iso27001"] + weakness["nist80053"]:
            assert len(ref["rationale"].split()) >= 6, f"{weakness['id']} -> {ref['id']}"


def test_every_protocol_has_weaknesses_and_devices():
    mapping = kb.load_mapping()
    for protocol in mapping["protocols"]:
        assert kb.weaknesses_for_protocol(protocol), f"{protocol} has no weaknesses"
        assert any(p["protocol"] == protocol for p in DEVICE_PROFILES.values())


def test_every_weakness_has_a_remediation_with_steps():
    for weakness in kb.load_mapping()["weaknesses"]:
        rem = weakness["remediation"]
        assert rem["summary"] and rem["steps"]
        assert rem["priority"] in {"P0", "P1", "P2", "P3"}
        assert rem["effort"] in {"Low", "Medium", "High"}


def test_device_intrinsic_weaknesses_are_protocol_consistent():
    """A device cannot carry a weakness that its own protocol is not in scope for."""
    index = kb.weakness_index()
    for device, profile in DEVICE_PROFILES.items():
        for weakness_id in profile["intrinsic"]:
            assert weakness_id in index, f"{device}: unknown weakness {weakness_id}"
            assert profile["protocol"] in index[weakness_id]["protocols"], device


def test_broken_cipher_generations_are_real_devices():
    for device in kb.broken_cipher_device_types():
        assert device in DEVICE_PROFILES


@pytest.mark.parametrize("zone", ["public", "general", "restricted", "secure"])
def test_zone_exposure_is_monotonic(zone):
    order = ["public", "general", "restricted", "secure"]
    values = [kb.zone_exposure(z) for z in order]
    assert values == sorted(values)
