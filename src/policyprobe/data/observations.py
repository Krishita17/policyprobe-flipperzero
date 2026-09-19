"""Simulation of what the Flipper front-end observes at an access point.

The mock bridge uses this to produce observations without hardware, and the classifier
training set is built from it. Measurement noise is deliberate: without it the
classification problem is trivial and the reported accuracy would be meaningless.

Noise model
-----------
* ``jitter``        gaussian noise on response timing, which is the least reliable feature
* ``partial_read``  one read of the repeat-read pair fails, weakening the static/variable signal
* ``sak_misread``   the 13.56 MHz select acknowledge byte is misread, blurring device families
* ``counter_miss``  a sub-GHz press is not captured, so the counter step looks wrong
* ``format_misdecode`` the bit length is decoded wrongly, which is common on marginal reads
* ``probe_unavailable`` a test (default-key dictionary, legacy-format presentation) could
  not be run on site, so its result is unknown rather than negative — the distinction
  matters, because "not tested" must never be reported to an auditor as "passed"
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from ..schema import AccessPoint, Observation
from .catalog import DEVICE_PROFILES

DEFAULT_NOISE = {
    "jitter": 0.14,
    "partial_read": 0.08,
    "sak_misread": 0.06,
    "counter_miss": 0.08,
    "format_misdecode": 0.07,
    "probe_unavailable": 0.10,
}

N_READS = 3


def simulate_observation(
    ap: AccessPoint,
    rng: random.Random,
    noise: dict[str, float] | None = None,
    sequential_neighbourhood: bool = False,
) -> Observation:
    """Simulate probing one access point and return the raw observation.

    ``sequential_neighbourhood`` reflects that the assessor sampled several credentials
    from the same issuing batch and can therefore see whether identifiers are allocated
    sequentially.
    """
    noise = {**DEFAULT_NOISE, **(noise or {})}
    profile = DEVICE_PROFILES[ap.device_type]
    sig = profile["signal"]

    # --- repeat reads: identical payloads mean a static credential -------------------
    base_id = rng.getrandbits(max(8, min(sig["bit_length"], 64)))
    reads: list[str] = []
    for _ in range(N_READS):
        if sig["variable_bits"] > 0:
            varying = rng.getrandbits(min(sig["variable_bits"], 48))
            reads.append(f"{base_id:x}:{varying:x}")
        else:
            reads.append(f"{base_id:x}")
    if rng.random() < noise["partial_read"]:
        reads = reads[:1]           # only one usable read: the static signal is unavailable

    distinct = len(set(reads))
    # --- protocol-level observations -------------------------------------------------
    sak = sig["sak"]
    if ap.protocol == "nfc_hf" and rng.random() < noise["sak_misread"]:
        sak = rng.choice([0, 8, 32])

    response_us = sig["response_us"]
    if response_us:
        response_us = max(1.0, rng.gauss(response_us, response_us * noise["jitter"]))

    bit_length = sig["bit_length"]
    if rng.random() < noise.get("format_misdecode", 0.0):
        bit_length = max(4, bit_length + rng.choice([-8, -4, 4, 8, 16]))

    counter_step = sig.get("counter_step", -1)
    if ap.protocol == "subghz" and counter_step >= 0 and rng.random() < noise["counter_miss"]:
        counter_step = counter_step + rng.choice([1, 2])

    # A default-key dictionary authentication is attempted read-only, and only where a
    # keyed credential is present.
    if sig["cipher"] == 0 or ap.protocol != "nfc_hf":
        default_key_auth = -1           # not applicable
    elif rng.random() < noise.get("probe_unavailable", 0.0):
        default_key_auth = -1           # could not be attempted during the site visit
    else:
        default_key_auth = 1 if ap.default_keys_in_use else 0

    # Legacy-format acceptance is probed by presenting a legacy-format credential.
    if rng.random() < noise.get("probe_unavailable", 0.0):
        legacy_probe = -1               # no legacy specimen available to present
    else:
        legacy_probe = 1 if ap.legacy_format_accepted else 0

    # Sequential allocation is inferred from a sample of sibling credentials.
    if sequential_neighbourhood and sig["variable_bits"] == 0:
        seq_variance = round(abs(rng.gauss(1.0, 0.4)), 3)   # near-constant first difference
    else:
        seq_variance = round(rng.uniform(40.0, 5000.0), 3)

    payload = {
        "reads": reads,
        "n_reads": len(reads),
        "distinct_reads": distinct,
        "bit_length": bit_length,
        "variable_bits_observed": 0 if distinct <= 1 else sig["variable_bits"],
        "challenge_observed": sig["challenge"],
        "auth_rounds": sig["auth_rounds"],
        "cipher_class": sig["cipher"],
        "namespace_bits": sig["namespace_bits"],
        "sak": sak,
        "response_us": round(response_us, 1),
        "counter_step": counter_step,
        "default_key_auth": default_key_auth,
        "legacy_format_probe": legacy_probe,
        "seq_first_diff_variance": seq_variance,
        "credential_population": ap.credential_population,
        "reader_interface": ap.reader_interface,
        "device_type_truth": ap.device_type,   # present in simulation only; never used as a feature
    }
    return Observation(
        access_point_id=ap.id,
        protocol=ap.protocol,
        backend="mock",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        payload=payload,
    )
