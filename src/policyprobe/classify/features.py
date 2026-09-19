"""Feature extraction from a raw observation.

Every feature here is something an assessor could point at in a transcript and explain
to an auditor. That matters more than raw accuracy: a finding that leads to a control
gap in a report has to be defensible, so the classifier deliberately uses interpretable
structural features rather than learned representations of the signal.

Feature reference
-----------------
``proto_*``               one-hot protocol indicator
``bit_length``            decoded payload length in bits
``read_repeat_ratio``     distinct payloads / reads; 1/n means a perfectly static credential
``variable_bits``         bits observed changing between reads
``challenge_observed``    reader issued a challenge the credential had to answer
``auth_rounds``           number of authentication exchanges seen
``namespace_pressure``    log2(population) / bit_length; approaches 1 as the identifier space fills

Two things an assessor *cannot* observe are deliberately absent: the cipher a credential
uses, and the formal size of its identifier namespace. Both are properties of a product
generation, knowable only once the generation has been identified. Feeding them in as
features would leak the answer and inflate every score in the evaluation.
``sak``                   13.56 MHz select acknowledge byte (device family discriminator)
``response_us``           credential response time; noisy, weak but non-zero signal
``counter_step``          sub-GHz counter increment per press; 0 means fixed code
``default_key_auth``      1 default-key authentication succeeded, 0 failed, -1 not applicable
``legacy_format_probe``   1 reader accepted a legacy-format credential
``seq_diff_variance``     variance of first differences across sampled sibling identifiers
"""

from __future__ import annotations

import math

import numpy as np

from ..schema import PROTOCOLS, Observation

FEATURE_NAMES: list[str] = (
    [f"proto_{p}" for p in PROTOCOLS]
    + [
        "bit_length",
        "read_repeat_ratio",
        "variable_bits",
        "challenge_observed",
        "auth_rounds",
        "namespace_pressure",
        "sak",
        "response_us",
        "counter_step",
        "default_key_auth",
        "legacy_format_probe",
        "seq_diff_variance",
    ]
)


def extract_features(obs: Observation) -> np.ndarray:
    """Turn one observation into the fixed-length feature vector the models expect."""
    p = obs.payload
    onehot = [1.0 if obs.protocol == proto else 0.0 for proto in PROTOCOLS]

    n_reads = max(1, int(p.get("n_reads", 1)))
    distinct = max(1, int(p.get("distinct_reads", 1)))
    repeat_ratio = distinct / n_reads

    bit_length = float(p.get("bit_length", 0) or 0)
    population = float(p.get("credential_population", 0) or 0)
    if bit_length > 0 and population > 1:
        pressure = math.log2(population) / bit_length
    else:
        pressure = 0.0

    seq_var = float(p.get("seq_first_diff_variance", -1.0))
    # Compress the heavy tail so a single large-variance sample cannot dominate splits.
    seq_var = math.log10(seq_var + 1.0) if seq_var >= 0 else -1.0

    # A single usable read tells us nothing about whether the payload varies: record the
    # variable-bit count as "unknown" rather than as zero, which would read as "static".
    variable_bits = float(p.get("variable_bits_observed", 0) or 0) if n_reads > 1 else -1.0

    values = [
        bit_length,
        repeat_ratio,
        variable_bits,
        float(p.get("challenge_observed", 0) or 0),
        float(p.get("auth_rounds", 0) or 0),
        pressure,
        float(p.get("sak", 0) or 0),
        float(p.get("response_us", 0) or 0) / 1000.0,
        float(p.get("counter_step", -1)),
        float(p.get("default_key_auth", -1)),
        float(p.get("legacy_format_probe", 0) or 0),
        seq_var,
    ]
    return np.asarray(onehot + values, dtype=float)


def feature_matrix(observations: list[Observation]) -> np.ndarray:
    """Stack features for a list of observations."""
    return np.vstack([extract_features(o) for o in observations])
