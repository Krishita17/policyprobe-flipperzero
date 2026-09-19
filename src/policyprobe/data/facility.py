"""Synthetic facility profile generator.

Produces a plausible physical-access inventory for a site — doors, gates, turnstiles,
technical rooms — together with the ground-truth weaknesses of each access point. The
ground truth is what the evaluation in ``experiments/`` scores the pipeline against, and
it is also what lets the whole project run from a clean clone with no hardware.

Knobs
-----
credential_strength_mix
    ``weak`` / ``mixed`` / ``strong`` — how much of the estate is on modern credentials.
protocol_diversity
    0.0-1.0; higher values scatter more protocols across the site.
legacy_prevalence
    0.0-1.0; probability an access point runs an end-of-life generation or still accepts
    a legacy format alongside a modern one.
monitoring_maturity
    0.0-1.0; probability tamper supervision, event logging and video coverage are present.
"""

from __future__ import annotations

import random

from ..schema import AccessPoint, Facility
from .catalog import BY_PROTOCOL, BY_STRENGTH, DEVICE_PROFILES

# (name template, zone, weight) — the mix of access point kinds a real site contains.
ACCESS_POINT_KINDS = [
    ("Main entrance turnstile {n}", "general", 0.16),
    ("Staff entrance {n}", "general", 0.14),
    ("Floor {n} office door", "general", 0.18),
    ("Meeting suite door {n}", "general", 0.06),
    ("Loading bay roller door {n}", "restricted", 0.08),
    ("Vehicle gate {n}", "restricted", 0.06),
    ("Records room {n}", "restricted", 0.08),
    ("Plant room {n}", "restricted", 0.06),
    ("Comms room {n}", "secure", 0.08),
    ("Server room {n}", "secure", 0.06),
    ("Data hall door {n}", "secure", 0.04),
]

# Access point kinds that are inherently radio-operated rather than card-read.
GATE_KINDS = {"Loading bay roller door {n}", "Vehicle gate {n}"}
IR_KINDS = {"Meeting suite door {n}"}

SECTORS = ["Financial services", "Healthcare", "Manufacturing", "Higher education",
           "Logistics", "Professional services"]

STRENGTH_MIX = {
    "weak":   {"weak": 0.70, "legacy": 0.25, "strong": 0.05},
    "mixed":  {"weak": 0.35, "legacy": 0.30, "strong": 0.35},
    "strong": {"weak": 0.08, "legacy": 0.17, "strong": 0.75},
}


def _weighted_choice(rng: random.Random, options: list[tuple[str, str, float]]):
    total = sum(o[2] for o in options)
    r = rng.random() * total
    upto = 0.0
    for opt in options:
        upto += opt[2]
        if r <= upto:
            return opt
    return options[-1]


def _pick_device(rng: random.Random, protocol: str, strength_mix: dict[str, float]) -> str:
    """Pick a device generation for a protocol, respecting the requested strength mix."""
    candidates = [d for d in BY_PROTOCOL[protocol]]
    weights = [strength_mix.get(DEVICE_PROFILES[d]["strength"], 0.1) for d in candidates]
    if sum(weights) == 0:
        return rng.choice(candidates)
    return rng.choices(candidates, weights=weights, k=1)[0]


def _derive_ground_truth(ap: AccessPoint, sequential_issuance: bool) -> list[str]:
    """Ground-truth weaknesses of an access point: intrinsic to the technology, plus
    those introduced by how it is deployed."""
    profile = DEVICE_PROFILES[ap.device_type]
    truths = set(profile["intrinsic"])

    # Deployment-introduced weaknesses (the "inventory" source in the knowledge base).
    if ap.protocol in ("rfid_lf", "nfc_hf") and ap.reader_interface in ("wiegand", "osdp"):
        truths.add("W-WIRE-CLEARTEXT")
    if not ap.tamper_supervised:
        truths.add("W-NO-TAMPER")
    if not ap.events_logged:
        truths.add("W-NO-EVENT-LOG")
    if ap.shared_credential:
        truths.add("W-SHARED-CREDENTIAL")
    if ap.factors < 2 and ap.zone in ("restricted", "secure"):
        truths.add("W-SINGLE-FACTOR-HIGH")
    if ap.lifecycle == "eol":
        truths.add("W-LEGACY-EOL")
    if ap.legacy_format_accepted:
        truths.add("W-MIXED-MODE")
    if ap.default_keys_in_use:
        truths.add("W-DEFAULT-KEYS")
    # Sequential issuance only matters where the identifier is the credential.
    if sequential_issuance and "W-STATIC-ID" in truths:
        truths.add("W-SEQUENTIAL-ID")
    return sorted(truths)


def generate_facility(
    seed: int = 7,
    n_access_points: int = 24,
    credential_strength_mix: str = "mixed",
    protocol_diversity: float = 0.6,
    legacy_prevalence: float = 0.35,
    monitoring_maturity: float = 0.6,
    sequential_issuance: bool | None = None,
    name: str | None = None,
    sector: str | None = None,
) -> Facility:
    """Generate one synthetic facility profile with ground-truth weaknesses."""
    rng = random.Random(seed)
    strength_mix = STRENGTH_MIX[credential_strength_mix]
    if sequential_issuance is None:
        sequential_issuance = rng.random() < 0.45

    facility = Facility(
        id=f"FAC-{seed:04d}",
        name=name or f"Synthetic Site {seed:04d}",
        sector=sector or rng.choice(SECTORS),
        seed=seed,
    )

    # A site normally has one dominant card technology plus outliers.
    dominant_protocol = rng.choices(
        ["nfc_hf", "rfid_lf", "ibutton"], weights=[0.55, 0.38, 0.07], k=1
    )[0]
    dominant_device = _pick_device(rng, dominant_protocol, strength_mix)

    counters: dict[str, int] = {}
    for i in range(n_access_points):
        template, zone, _w = _weighted_choice(rng, ACCESS_POINT_KINDS)
        counters[template] = counters.get(template, 0) + 1
        ap_name = template.format(n=counters[template])

        if template in GATE_KINDS:
            protocol = "subghz"
        elif template in IR_KINDS and rng.random() < 0.5:
            protocol = "ir"
        elif rng.random() < protocol_diversity * 0.45:
            protocol = rng.choice(["rfid_lf", "nfc_hf", "ibutton", "ir"])
        else:
            protocol = dominant_protocol

        if protocol == dominant_protocol and rng.random() > protocol_diversity * 0.5:
            device = dominant_device
        else:
            device = _pick_device(rng, protocol, strength_mix)

        # Reader-to-controller interface: only card readers have one.
        if protocol in ("rfid_lf", "nfc_hf"):
            interface = rng.choices(
                ["wiegand", "osdp", "osdp_secure_channel"],
                weights=[0.45 + legacy_prevalence * 0.3, 0.2, 0.45 - legacy_prevalence * 0.2],
                k=1,
            )[0]
        else:
            interface = "native"

        secure_zone = zone in ("restricted", "secure")
        ap = AccessPoint(
            id=f"AP-{i + 1:03d}",
            name=ap_name,
            zone=zone,
            protocol=protocol,
            device_type=device,
            reader_interface=interface,
            factors=2 if (secure_zone and rng.random() < 0.25 + monitoring_maturity * 0.35) else 1,
            tamper_supervised=rng.random() < 0.25 + monitoring_maturity * 0.65,
            events_logged=(protocol not in ("subghz", "ir"))
            and rng.random() < 0.35 + monitoring_maturity * 0.6,
            shared_credential=rng.random() < 0.18 if protocol in ("subghz", "ibutton") else rng.random() < 0.08,
            legacy_format_accepted=(
                DEVICE_PROFILES[device]["strength"] == "strong"
                and protocol in ("rfid_lf", "nfc_hf")
                and rng.random() < legacy_prevalence
            ),
            default_keys_in_use=(
                DEVICE_PROFILES[device]["strength"] == "legacy"
                and protocol == "nfc_hf"
                and rng.random() < 0.25 + legacy_prevalence * 0.45
            ),
            lifecycle="eol" if rng.random() < legacy_prevalence * 0.6 else "supported",
            perimeter_facing=template in GATE_KINDS or "entrance" in template.lower()
            or rng.random() < 0.15,
            monitored=rng.random() < 0.3 + monitoring_maturity * 0.6,
            high_traffic="entrance" in template.lower() or "turnstile" in template.lower(),
            escort_enforced=zone == "secure" and rng.random() < monitoring_maturity * 0.4,
            credential_population=rng.randint(40, 2600),
        )
        ap.ground_truth_weaknesses = _derive_ground_truth(ap, sequential_issuance)
        facility.access_points.append(ap)

    return facility


def generate_cohort(seeds: list[int], **kwargs) -> list[Facility]:
    """Generate several facilities that share generator settings but differ by seed."""
    return [generate_facility(seed=s, **kwargs) for s in seeds]
