"""Evaluation: does the pipeline produce the right findings and the right controls?

Four questions are answered here, and they are deliberately separated because they fail
for different reasons.

1. **Knowledge-base integrity.** Does every mapping resolve to a real control with a
   relation and a rationale? Checked by :func:`policyprobe.kb.validate` and the tests.
2. **Detection accuracy.** Against ground-truth facilities, which weaknesses does the
   pipeline find and which does it miss?
3. **Control assignment accuracy.** Given detection, does the right set of controls end
   up marked as failed? Because the mapping is a deterministic lookup, any error here is
   inherited from (2); reporting it separately shows how detection error propagates into
   the compliance conclusion, which is what actually matters to an auditor.
4. **Posture ordering.** Does the score rank a known-weak estate below a known-strong one?
   A posture score that does not order obviously different estates correctly is worthless
   regardless of how precise its components are. Both scores are checked, and they behave
   differently on purpose: strict conformity is close to flat across estates, because one
   unreplaced door fails a control as completely as forty, while the estate score tracks
   how much of the site each control actually holds across. The ordering test is the
   reason the second score exists.
"""

from __future__ import annotations

import random
from typing import Any

from . import kb
from .bridge import get_bridge
from .classify.model import WeaknessClassifier, build_training_set
from .data.catalog import device_family
from .data.facility import generate_facility
from .data.real_loader import ground_truth as real_ground_truth
from .data.real_loader import load_real_samples, to_observations
from .mapping.engine import MappingEngine
from .normalize import normalize_facility
from .schema import Facility, Finding
from .score.risk import score_findings


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def run_pipeline(facility: Facility, classifier: WeaknessClassifier, seed: int = 99,
                 engine: MappingEngine | None = None) -> tuple[list[Finding], MappingEngine]:
    """Scan, normalise, score and map a facility. The single path used everywhere."""
    engine = engine or MappingEngine()
    observations = get_bridge("mock", seed=seed).probe_all(facility.access_points)
    findings = normalize_facility(facility, observations, classifier)
    findings = score_findings(findings, facility.access_points)
    return engine.map_findings(findings), engine


def postures_for(facility: Facility, findings: list[Finding], engine: MappingEngine):
    """Posture for a facility, scored against its full access point count."""
    return engine.posture_all(findings, n_access_points=len(facility.access_points))


def detection_metrics(facilities: list[Facility], classifier: WeaknessClassifier,
                      seed: int = 99) -> dict[str, Any]:
    """Finding-level precision/recall against the generator's ground truth."""
    tp = fp = fn = 0
    per_weakness: dict[str, dict[str, int]] = {}
    for i, facility in enumerate(facilities):
        findings, _ = run_pipeline(facility, classifier, seed=seed + i)
        found = {(f.access_point_id, f.weakness_id) for f in findings}
        truth = {(ap.id, w) for ap in facility.access_points
                 for w in ap.ground_truth_weaknesses}
        tp += len(found & truth)
        fp += len(found - truth)
        fn += len(truth - found)
        for key, bucket in ((found & truth, "tp"), (found - truth, "fp"), (truth - found, "fn")):
            for _ap, w in key:
                per_weakness.setdefault(w, {"tp": 0, "fp": 0, "fn": 0})[bucket] += 1

    result = _prf(tp, fp, fn)
    result["per_weakness"] = {
        w: _prf(c["tp"], c["fp"], c["fn"]) for w, c in sorted(per_weakness.items())
    }
    return result


def control_metrics(facilities: list[Facility], classifier: WeaknessClassifier,
                    seed: int = 99) -> dict[str, Any]:
    """Control-level precision/recall: are the right controls marked as failed?

    Ground truth is built by pushing the generator's true weaknesses through the same
    mapping table, so this isolates the effect of detection error on the compliance
    conclusion.
    """
    weaknesses = kb.weakness_index()
    per_framework: dict[str, dict[str, int]] = {}

    for i, facility in enumerate(facilities):
        findings, engine = run_pipeline(facility, classifier, seed=seed + i)
        for framework in engine.frameworks:
            key = kb.MAPPING_KEY[framework]
            predicted = {
                (f.access_point_id, r.control_id)
                for f in findings for r in f.controls
                if r.framework == framework and r.relation == "violates"
            }
            truth = {
                (ap.id, ref["id"])
                for ap in facility.access_points
                for w in ap.ground_truth_weaknesses
                for ref in weaknesses[w].get(key, [])
                if ref["relation"] == "violates"
            }
            c = per_framework.setdefault(framework, {"tp": 0, "fp": 0, "fn": 0})
            c["tp"] += len(predicted & truth)
            c["fp"] += len(predicted - truth)
            c["fn"] += len(truth - predicted)

    out = {fw: _prf(c["tp"], c["fp"], c["fn"]) for fw, c in per_framework.items()}
    total = {k: sum(c[k] for c in per_framework.values()) for k in ("tp", "fp", "fn")}
    out["overall"] = _prf(total["tp"], total["fp"], total["fn"])
    return out


POSTURE_PROFILES = [
    ("Known weak", dict(credential_strength_mix="weak", legacy_prevalence=0.85,
                        monitoring_maturity=0.1)),
    ("Legacy mixed", dict(credential_strength_mix="mixed", legacy_prevalence=0.55,
                          monitoring_maturity=0.35)),
    ("Modernising", dict(credential_strength_mix="mixed", legacy_prevalence=0.2,
                         monitoring_maturity=0.7)),
    ("Known strong", dict(credential_strength_mix="strong", legacy_prevalence=0.02,
                          monitoring_maturity=0.95)),
]


def posture_ordering(classifier: WeaknessClassifier, seeds: list[int] | None = None
                     ) -> list[dict[str, Any]]:
    """Posture scores for labelled weak-to-strong estates, averaged over seeds."""
    seeds = seeds or [301, 302, 303]
    rows = []
    for label, knobs in POSTURE_PROFILES:
        strict: dict[str, list[float]] = {}
        estate: dict[str, list[float]] = {}
        for seed in seeds:
            facility = generate_facility(seed=seed, n_access_points=28, **knobs)
            findings, engine = run_pipeline(facility, classifier, seed=seed)
            for fw, posture in postures_for(facility, findings, engine).items():
                strict.setdefault(fw, []).append(posture.overall_posture)
                estate.setdefault(fw, []).append(posture.overall_estate_posture)
        row: dict[str, Any] = {"profile": label}
        row.update({fw: round(sum(v) / len(v), 1) for fw, v in strict.items()})
        row.update({f"{fw}_estate": round(sum(v) / len(v), 1) for fw, v in estate.items()})
        rows.append(row)
    return rows


def ordering_is_monotonic(rows: list[dict[str, Any]], framework: str,
                          key_suffix: str = "_estate") -> bool:
    """True if posture rises monotonically from the weakest to the strongest profile.

    Checked on the estate score by default: strict conformity is deliberately insensitive
    to how much of an estate is affected, so requiring it to rise would be testing the
    wrong property.
    """
    values = [r[framework + key_suffix] for r in rows]
    return all(a <= b for a, b in zip(values, values[1:]))


def real_sample_metrics(classifier: WeaknessClassifier) -> dict[str, Any] | None:
    """Score the classifier on committed real Flipper reads, if any are present."""
    records = load_real_samples()
    if not records:
        return None
    observations = to_observations(records)
    truth = real_ground_truth(records)
    rf_labels = set(classifier.weakness_labels) | {"W-BROKEN-CRYPTO"}

    exact = family = 0
    tp = fp = fn = 0
    for obs in observations:
        device, _conf = classifier.predict_device(obs)
        expected = truth[obs.access_point_id]
        exact += int(device == expected["device_type"])
        family += int(device_family(device) == device_family(expected["device_type"]))
        predicted = set(classifier.predict_weaknesses(obs))
        actual = expected["weaknesses"] & rf_labels
        tp += len(predicted & actual)
        fp += len(predicted - actual)
        fn += len(actual - predicted)

    n = len(observations)
    prf = _prf(tp, fp, fn)
    return {
        "n_samples": n,
        "device_accuracy": round(exact / n, 4),
        "device_family_accuracy": round(family / n, 4),
        "weakness_micro_precision": prf["precision"],
        "weakness_micro_recall": prf["recall"],
        "weakness_micro_f1": prf["f1"],
    }


def train_default_classifier(train_seeds: list[int] | None = None,
                             seed: int = 42) -> WeaknessClassifier:
    """Train the classifier used by every reproducible run in this repository."""
    train_seeds = train_seeds or list(range(100, 150))
    return WeaknessClassifier(seed=seed).fit(build_training_set(train_seeds))
