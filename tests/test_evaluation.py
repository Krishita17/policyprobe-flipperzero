"""Tests for the evaluation claims made in the README.

These are the ones that matter most: if the posture score does not order a known-weak
estate below a known-strong one, the headline number in the report is meaningless no
matter how good the components are.
"""

import pytest

from policyprobe import evaluate as ev
from policyprobe.classify.model import WeaknessClassifier, build_training_set
from policyprobe.data.facility import generate_facility
from policyprobe.data.real_loader import load_real_samples


@pytest.fixture(scope="module")
def classifier():
    return WeaknessClassifier(seed=42, n_estimators=80).fit(
        build_training_set(list(range(100, 116)))
    )


def test_posture_orders_weak_below_strong(classifier):
    rows = ev.posture_ordering(classifier, seeds=[301, 302])
    for framework in ("iso27001", "nist80053"):
        assert ev.ordering_is_monotonic(rows, framework), rows
        assert rows[0][framework] < rows[-1][framework]


def test_detection_recall_is_usable(classifier):
    facilities = [generate_facility(seed=s, n_access_points=20) for s in (500, 501, 502)]
    metrics = ev.detection_metrics(facilities, classifier)
    assert metrics["recall"] > 0.8
    assert metrics["precision"] > 0.8


def test_control_assignment_tracks_detection(classifier):
    """Control assignment is a deterministic lookup, so it should not be meaningfully
    worse than the detection that feeds it."""
    facilities = [generate_facility(seed=s, n_access_points=20) for s in (500, 501)]
    detection = ev.detection_metrics(facilities, classifier)
    control = ev.control_metrics(facilities, classifier)
    assert control["overall"]["f1"] >= detection["f1"] - 0.15


def test_real_sample_loader_is_safe_when_empty():
    """An empty real-sample set is a normal state and must not be an error, or the
    repository would not run from a clean clone."""
    samples = load_real_samples()
    assert isinstance(samples, list)


def test_real_sample_loader_rejects_unowned_media(tmp_path):
    import json
    (tmp_path / "bad.json").write_text(json.dumps({
        "sample_id": "x", "device_type": "EM4100/EM4102", "protocol": "rfid_lf",
        "owned_by_author": False, "payload": {},
    }))
    with pytest.raises(ValueError, match="author's own device"):
        load_real_samples(tmp_path)
