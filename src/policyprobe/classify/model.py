"""The classification layer: device type plus weak-implementation flags.

Two heads share one feature vector:

* a multi-class random forest predicting the credential generation, which is what tells
  an assessor *what* is deployed and drives the vendor-specific remediation advice; and
* a multi-label random forest predicting which RF-observable weaknesses are present.

Random forests are used deliberately. They train in seconds, are reproducible from a
seed, need no scaling, and — most importantly for an audit tool — expose feature
importances, so every flag can be explained in terms of what was observed.

One weakness is deliberately *not* given a head of its own. ``W-BROKEN-CRYPTO`` is a
property of a product generation, not of anything visible in a single exchange: you
cannot see that a cipher is broken, you can only see which product you are talking to and
then consult the published cryptanalysis. It is therefore derived from the predicted
device type via ``broken_cipher_generations`` in the mapping file, and inherits the
device head's error rather than being scored as if it were directly observable.

Weaknesses whose source is ``inventory`` are never predicted here. They are derived
deterministically from access point attributes in :mod:`policyprobe.normalize`, because
guessing at them would put unverifiable claims into a compliance report.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from .. import kb
from ..data.catalog import DEVICE_PROFILES, DEVICE_TYPES, device_family
from ..data.facility import generate_facility
from ..data.observations import simulate_observation
from ..schema import Observation
from .features import FEATURE_NAMES, extract_features

DEFAULT_MODEL_PATH = kb.REPO_ROOT / "results" / "classifier.json"

# Weaknesses derived from the identified product generation rather than predicted directly.
DERIVED_WEAKNESSES = {"W-BROKEN-CRYPTO"}


@dataclass
class TrainingSet:
    X: np.ndarray
    y_device: np.ndarray
    y_weak: np.ndarray
    weakness_labels: list[str]


def build_training_set(
    seeds: list[int],
    noise: dict[str, float] | None = None,
    access_points_per_facility: int = 40,
) -> TrainingSet:
    """Generate labelled observations from synthetic facilities.

    Labels come from the facility generator's ground truth, restricted to the
    RF-observable weaknesses — the only ones this layer is allowed to claim.
    """
    rf_weaknesses = sorted(set(kb.weaknesses_by_source("rf_probe")) - DERIVED_WEAKNESSES)
    features: list[np.ndarray] = []
    devices: list[str] = []
    weak_rows: list[list[int]] = []

    for seed in seeds:
        # Vary the generator knobs across seeds so the model sees the whole estate space.
        rng = random.Random(seed)
        facility = generate_facility(
            seed=seed,
            n_access_points=access_points_per_facility,
            credential_strength_mix=rng.choice(["weak", "mixed", "strong"]),
            protocol_diversity=rng.uniform(0.3, 1.0),
            legacy_prevalence=rng.uniform(0.1, 0.8),
            monitoring_maturity=rng.uniform(0.1, 0.9),
        )
        obs_rng = random.Random(seed * 31 + 7)
        for ap in facility.access_points:
            sequential = "W-SEQUENTIAL-ID" in ap.ground_truth_weaknesses
            obs = simulate_observation(ap, obs_rng, noise=noise,
                                       sequential_neighbourhood=sequential)
            features.append(extract_features(obs))
            devices.append(ap.device_type)
            weak_rows.append([
                1 if w in ap.ground_truth_weaknesses else 0 for w in rf_weaknesses
            ])

    return TrainingSet(
        X=np.vstack(features),
        y_device=np.asarray(devices),
        y_weak=np.asarray(weak_rows),
        weakness_labels=rf_weaknesses,
    )


class WeaknessClassifier:
    """Device-type and weak-implementation classifier."""

    def __init__(self, seed: int = 42, n_estimators: int = 300):
        self.seed = seed
        self.n_estimators = n_estimators
        self.device_model: RandomForestClassifier | None = None
        self.weak_models: dict[str, RandomForestClassifier] = {}
        self.weakness_labels: list[str] = []
        self.metrics: dict[str, Any] = {}

    # ------------------------------------------------------------------- training --
    def fit(self, ts: TrainingSet) -> "WeaknessClassifier":
        self.weakness_labels = ts.weakness_labels
        self.device_model = RandomForestClassifier(
            n_estimators=self.n_estimators, random_state=self.seed, n_jobs=-1,
            min_samples_leaf=1,
        ).fit(ts.X, ts.y_device)

        # One binary forest per weakness. Separate models keep a rare weakness from being
        # swamped by a common one, and let each flag carry its own decision threshold.
        # Prediction happens one access point at a time, where joblib's thread pool costs
        # far more than it saves; parallelism is worth it only during the fit.
        self.device_model.n_jobs = 1

        self.weak_models = {}
        for i, label in enumerate(ts.weakness_labels):
            y = ts.y_weak[:, i]
            if y.sum() == 0 or y.sum() == len(y):
                self.weak_models[label] = _ConstantModel(int(y[0]) if len(y) else 0)
                continue
            model = RandomForestClassifier(
                n_estimators=self.n_estimators, random_state=self.seed, n_jobs=-1,
                class_weight="balanced_subsample", min_samples_leaf=1,
            ).fit(ts.X, y)
            model.n_jobs = 1
            self.weak_models[label] = model
        return self

    # ----------------------------------------------------------------- prediction --
    def predict_device(self, obs: Observation) -> tuple[str, float]:
        """Predict the credential generation and the model's confidence in it."""
        if self.device_model is None:
            raise RuntimeError("classifier is not trained")
        return self._predict_device_from(extract_features(obs).reshape(1, -1))

    def _predict_device_from(self, x) -> tuple[str, float]:
        proba = self.device_model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        return str(self.device_model.classes_[idx]), float(proba[idx])

    def predict_weaknesses(self, obs: Observation, threshold: float = 0.5
                           ) -> dict[str, float]:
        """Return ``{weakness_id: confidence}`` for flags above the threshold.

        Includes the generation-derived weaknesses, whose confidence is the device head's
        confidence in the generation they were derived from.
        """
        x = extract_features(obs).reshape(1, -1)
        out: dict[str, float] = {}
        for label, model in self.weak_models.items():
            p = float(model.predict_proba(x)[0][-1]) if hasattr(model, "predict_proba") else 0.0
            if p >= threshold:
                out[label] = round(p, 3)

        device, device_conf = self._predict_device_from(x)
        if device_is_known_broken(device):
            out["W-BROKEN-CRYPTO"] = round(device_conf, 3)
        return out

    # ----------------------------------------------------------------- evaluation --
    def evaluate(self, ts: TrainingSet) -> dict[str, Any]:
        """Score both heads on a held-out set."""
        device_pred = self.device_model.predict(ts.X)
        per_weakness = {}
        y_true_all, y_pred_all = [], []
        for i, label in enumerate(ts.weakness_labels):
            model = self.weak_models[label]
            pred = model.predict(ts.X)
            y_true = ts.y_weak[:, i]
            per_weakness[label] = {
                "support": int(y_true.sum()),
                "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
                "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
                "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
            }
            y_true_all.append(y_true)
            y_pred_all.append(pred)

        y_true_flat = np.concatenate(y_true_all)
        y_pred_flat = np.concatenate(y_pred_all)
        fam_true = np.array([device_family(d) for d in ts.y_device])
        fam_pred = np.array([device_family(d) for d in device_pred])

        self.metrics = {
            "device_accuracy": round(float(accuracy_score(ts.y_device, device_pred)), 4),
            "device_family_accuracy": round(float(accuracy_score(fam_true, fam_pred)), 4),
            "n_device_classes": int(len(set(ts.y_device))),
            "n_device_families": int(len(set(fam_true))),
            "weakness_micro_precision": round(
                float(precision_score(y_true_flat, y_pred_flat, zero_division=0)), 4),
            "weakness_micro_recall": round(
                float(recall_score(y_true_flat, y_pred_flat, zero_division=0)), 4),
            "weakness_micro_f1": round(
                float(f1_score(y_true_flat, y_pred_flat, zero_division=0)), 4),
            "weakness_macro_f1": round(
                float(np.mean([m["f1"] for m in per_weakness.values()])), 4),
            "per_weakness": per_weakness,
            "n_samples": int(ts.X.shape[0]),
        }
        return self.metrics

    def feature_importance(self, top_n: int = 10) -> list[tuple[str, float]]:
        """Most influential features for device-type identification."""
        imp = self.device_model.feature_importances_
        ranked = sorted(zip(FEATURE_NAMES, imp), key=lambda t: t[1], reverse=True)
        return [(n, round(float(v), 4)) for n, v in ranked[:top_n]]

    # ------------------------------------------------------------------ reporting --
    def save_metrics(self, path: Path = DEFAULT_MODEL_PATH) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "seed": self.seed,
            "n_estimators": self.n_estimators,
            "weakness_labels": self.weakness_labels,
            "metrics": self.metrics,
            "top_features": self.feature_importance(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path


class _ConstantModel:
    """Stand-in for a weakness that is absent (or universal) in the training data."""

    def __init__(self, value: int):
        self.value = value

    def predict(self, X):            # noqa: N803 - sklearn naming
        return np.full(len(X), self.value)

    def predict_proba(self, X):      # noqa: N803
        p = float(self.value)
        return np.tile([1.0 - p, p], (len(X), 1))


def device_is_known_broken(device_type: str) -> bool:
    """True if the identified generation uses a publicly broken proprietary cipher."""
    return device_type in kb.broken_cipher_device_types()


def noise_sweep(train_seeds: list[int], test_seeds: list[int],
                levels: list[float], seed: int = 42) -> list[dict[str, Any]]:
    """Retrain and re-evaluate across a range of measurement-noise levels.

    ``levels`` scales every noise probability in the observation model. The resulting
    curve is the honest answer to "how well does this work?": the weak-scheme flags are
    close to deterministic on clean reads, so what matters operationally is how far the
    read quality can degrade before the findings — and therefore the control gaps derived
    from them — stop being trustworthy.
    """
    from ..data.observations import DEFAULT_NOISE

    rows: list[dict[str, Any]] = []
    for level in levels:
        noise = {k: min(0.95, v * level) for k, v in DEFAULT_NOISE.items()}
        noise["jitter"] = DEFAULT_NOISE["jitter"] * level
        tr = build_training_set(train_seeds, noise=noise)
        te = build_training_set(test_seeds, noise=noise)
        clf = WeaknessClassifier(seed=seed).fit(tr)
        m = clf.evaluate(te)
        rows.append({
            "noise_level": level,
            "device_accuracy": m["device_accuracy"],
            "device_family_accuracy": m["device_family_accuracy"],
            "weakness_micro_f1": m["weakness_micro_f1"],
            "weakness_macro_f1": m["weakness_macro_f1"],
        })
    return rows


def device_strength(device_type: str) -> str:
    return DEVICE_PROFILES.get(device_type, {}).get("strength", "unknown")


__all__ = ["WeaknessClassifier", "TrainingSet", "build_training_set", "noise_sweep",
           "device_is_known_broken", "device_strength", "DEVICE_TYPES"]
