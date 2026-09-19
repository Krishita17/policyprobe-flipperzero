"""Common data structures shared by every stage of the pipeline.

The single most important type here is :class:`Finding`. Every protocol the Flipper
front-end can speak reduces to a Finding, which is what makes a one-page,
cross-protocol compliance posture possible at the end of the pipeline.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

# Ordered from least to most severe; index is the numeric base score.
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

ZONES = ["public", "general", "restricted", "secure"]

PROTOCOLS = ["rfid_lf", "nfc_hf", "subghz", "ir", "ibutton"]


def severity_score(name: str) -> int:
    """Return the 1-5 numeric base score for a severity label."""
    return SEVERITY_ORDER.index(name) + 1


@dataclass
class AccessPoint:
    """One physically distinct place where a credential is presented.

    Attributes beginning with ``reader_`` or describing monitoring are *inventory*
    attributes: they are recorded by the assessor from the access point itself and
    are not derivable from an RF read.
    """

    id: str
    name: str
    zone: str                      # one of ZONES
    protocol: str                  # one of PROTOCOLS
    device_type: str               # true credential generation in use
    reader_interface: str          # wiegand | osdp | osdp_secure_channel | native
    factors: int = 1               # number of authentication factors enforced
    tamper_supervised: bool = True
    events_logged: bool = True
    shared_credential: bool = False
    legacy_format_accepted: bool = False
    default_keys_in_use: bool = False
    lifecycle: str = "supported"   # supported | eol
    perimeter_facing: bool = False
    monitored: bool = True         # video or guard coverage
    high_traffic: bool = False
    escort_enforced: bool = False
    credential_population: int = 0  # holders whose credential works here
    ground_truth_weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Facility:
    """A site: a named collection of access points plus assessment metadata."""

    id: str
    name: str
    sector: str
    seed: int
    access_points: list[AccessPoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        return d


@dataclass
class Observation:
    """Raw, protocol-specific result of probing one access point.

    Produced by a bridge backend (mock or real Flipper). Deliberately permissive:
    ``payload`` carries whatever the protocol yields, and the normalizer is the only
    component that has to understand every variant.
    """

    access_point_id: str
    protocol: str
    backend: str                    # "mock" or "flipper-cli"
    timestamp: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ControlRef:
    """A single mapped control, with the reason it was mapped."""

    framework: str                  # iso27001 | nist80053
    control_id: str
    title: str
    family: str
    relation: str                   # violates | weakens | evidence
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Finding:
    """One weakness observed at one access point, with its risk and control mappings.

    This is the common schema referred to throughout the project. A 125 kHz cloneable
    fob, a fixed-code loading-bay remote and an unlogged iButton door all arrive here
    in the same shape, which is what lets them roll into a single posture score.
    """

    id: str
    access_point_id: str
    access_point_name: str
    zone: str
    protocol: str
    device_type: str
    weakness_id: str
    weakness_title: str
    source: str                     # rf_probe | inventory
    confidence: float               # 0-1; 1.0 for deterministic inventory findings
    evidence: str                   # what was observed, in the assessor's words
    base_severity: str = "Medium"
    risk_score: float = 0.0
    risk_rating: str = "Medium"
    exposure_factors: list[str] = field(default_factory=list)
    controls: list[ControlRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        return d


@dataclass
class ControlStatus:
    """Rolled-up assessment status for a single control across the whole facility."""

    framework: str
    control_id: str
    title: str
    family: str
    status: str                     # not_met | partially_met | met | not_assessed
    finding_ids: list[str] = field(default_factory=list)
    score: float = 0.0              # strict rollup: 0.0 not met, 0.5 partial, 1.0 met
    failing_access_points: int = 0  # access points where this control is violated
    weakened_access_points: int = 0 # access points where it is weakened but not failed
    assessed_access_points: int = 0 # access points in the assessment
    estate_score: float = 1.0       # share of the estate where the control holds

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)
