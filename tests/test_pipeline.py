"""End-to-end tests for the pipeline stages."""

import random

import pytest

from policyprobe.bridge import get_bridge
from policyprobe.bridge.flipper_cli import FlipperCLIBridge
from policyprobe.classify.features import FEATURE_NAMES, extract_features
from policyprobe.classify.model import WeaknessClassifier, build_training_set
from policyprobe.data.facility import generate_facility
from policyprobe.mapping.engine import MappingEngine
from policyprobe.normalize import normalize_facility
from policyprobe.score.risk import score_findings


@pytest.fixture(scope="module")
def classifier():
    return WeaknessClassifier(seed=42, n_estimators=80).fit(
        build_training_set(list(range(100, 112)))
    )


@pytest.fixture(scope="module")
def facility():
    return generate_facility(seed=7, n_access_points=20)


@pytest.fixture(scope="module")
def pipeline(facility, classifier):
    observations = get_bridge("mock", seed=99).probe_all(facility.access_points)
    findings = normalize_facility(facility, observations, classifier)
    findings = score_findings(findings, facility.access_points)
    engine = MappingEngine()
    return engine.map_findings(findings), engine


def test_facility_generation_is_deterministic():
    a = generate_facility(seed=7, n_access_points=12)
    b = generate_facility(seed=7, n_access_points=12)
    assert [ap.to_dict() for ap in a.access_points] == [ap.to_dict() for ap in b.access_points]


def test_mock_bridge_produces_one_observation_per_access_point(facility):
    observations = get_bridge("mock", seed=1).probe_all(facility.access_points)
    assert len(observations) == len(facility.access_points)
    assert {o.access_point_id for o in observations} == {ap.id for ap in facility.access_points}


def test_feature_vector_length_matches_names(facility):
    obs = get_bridge("mock", seed=1).probe(facility.access_points[0])
    assert len(extract_features(obs)) == len(FEATURE_NAMES)


def test_features_exclude_unobservable_properties():
    """The cipher a credential uses and its formal namespace size are not observable from
    a read; including them as features would leak the label."""
    assert "cipher_class" not in FEATURE_NAMES
    assert "namespace_bits" not in FEATURE_NAMES


def test_findings_only_carry_weaknesses_valid_for_their_protocol(pipeline):
    from policyprobe import kb
    index = kb.weakness_index()
    findings, _ = pipeline
    for f in findings:
        assert f.protocol in index[f.weakness_id]["protocols"]


def test_inventory_findings_are_full_confidence(pipeline):
    findings, _ = pipeline
    for f in findings:
        if f.source == "inventory":
            assert f.confidence == 1.0


def test_every_finding_maps_to_at_least_one_control(pipeline):
    findings, _ = pipeline
    for f in findings:
        assert f.controls, f"{f.id} ({f.weakness_id}) mapped to nothing"
        assert {r.framework for r in f.controls} == {"iso27001", "nist80053"}


def test_risk_rises_with_zone_sensitivity(classifier):
    """The same weakness must rate higher on a server room than on a general office."""
    from policyprobe.schema import Finding
    from policyprobe.score.risk import score_finding
    from policyprobe.schema import AccessPoint

    def rate(zone):
        ap = AccessPoint(id="AP-001", name="t", zone=zone, protocol="rfid_lf",
                         device_type="EM4100/EM4102", reader_interface="wiegand")
        f = Finding(id="F-1", access_point_id="AP-001", access_point_name="t", zone=zone,
                    protocol="rfid_lf", device_type="EM4100/EM4102",
                    weakness_id="W-STATIC-ID", weakness_title="t", source="inventory",
                    confidence=1.0, evidence="t", base_severity="High")
        return score_finding(f, ap).risk_score

    assert rate("public") < rate("general") < rate("restricted") < rate("secure")


def test_posture_excludes_unassessable_controls(pipeline):
    findings, engine = pipeline
    for framework, posture in engine.posture_all(findings).items():
        scored = [s for s in posture.control_statuses if s.status != "not_assessed"]
        assert 0 <= posture.overall_posture <= 100
        assert posture.coverage["controls_assessed"] == len(scored)
        assert posture.coverage["controls_not_assessed"] > 0, (
            "a method that claims to assess every control is overstating itself")


def test_unassessable_controls_are_never_scored_as_met(pipeline):
    from policyprobe import kb
    findings, engine = pipeline
    for framework, posture in engine.posture_all(findings).items():
        catalogue = kb.controls_index(framework)
        for status in posture.control_statuses:
            assessable = catalogue[status.control_id].get("assessable_via_policyprobe")
            if assessable in (False, "no"):
                assert status.status == "not_assessed"


def test_crosswalk_covers_every_weakness():
    engine = MappingEngine()
    rows = engine.crosswalk()
    from policyprobe import kb
    assert len(rows) == len(kb.load_mapping()["weaknesses"])
    for row in rows:
        assert row["iso27001"] and row["nist80053"]


def test_roadmap_is_priority_ordered(pipeline):
    findings, engine = pipeline
    priorities = [r["priority"] for r in engine.remediation_roadmap(findings)]
    assert priorities == sorted(priorities)


def test_flipper_cli_dry_run_sends_nothing():
    """The hardware backend must be inspectable without a device attached."""
    bridge = FlipperCLIBridge(dry_run=True)
    facility = generate_facility(seed=3, n_access_points=2)
    observations = bridge.probe_all(facility.access_points)
    assert len(observations) == 2
    assert all(o.backend == "flipper-cli" for o in observations)


def test_flipper_cli_parser_handles_a_transcript():
    transcript = "Protocol: EM4100\nData: 1A 2B 3C 4D 5E\n40 bits\nSAK: 08\nCnt: 42"
    payload = FlipperCLIBridge.parse_payload("nfc_hf", transcript)
    assert payload["reads"] == ["1A:2B:3C:4D:5E"]
    assert payload["bit_length"] == 40
    assert payload["sak"] == 0x08
    assert payload["counter_value"] == 42
