"""Loader for the control frameworks and the protocol -> weakness -> control mapping.

Everything policy-related lives in editable YAML under ``frameworks/`` and
``mappings/``. No control identifier or mapping decision is hard-coded in Python, so
an assessor can extend the tool to another framework without touching the pipeline.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_DIR = REPO_ROOT / "frameworks"
MAPPING_FILE = REPO_ROOT / "mappings" / "protocol_weakness_control.yaml"

FRAMEWORK_FILES = {
    "iso27001": FRAMEWORK_DIR / "iso27001_2022.yaml",
    "nist80053": FRAMEWORK_DIR / "nist_800_53_r5.yaml",
}

# Key used inside the mapping file for each framework's control list.
MAPPING_KEY = {"iso27001": "iso27001", "nist80053": "nist80053"}


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@functools.lru_cache(maxsize=None)
def load_framework(framework_id: str) -> dict[str, Any]:
    """Load one control framework catalogue by id (``iso27001`` or ``nist80053``)."""
    if framework_id not in FRAMEWORK_FILES:
        raise KeyError(f"unknown framework {framework_id!r}")
    return _load_yaml(FRAMEWORK_FILES[framework_id])


@functools.lru_cache(maxsize=None)
def load_mapping() -> dict[str, Any]:
    """Load the protocol -> weakness -> control knowledge base."""
    return _load_yaml(MAPPING_FILE)


@functools.lru_cache(maxsize=None)
def controls_index(framework_id: str) -> dict[str, dict[str, Any]]:
    """Return ``{control_id: control_record}`` for a framework."""
    return {c["id"]: c for c in load_framework(framework_id)["controls"]}


@functools.lru_cache(maxsize=None)
def weakness_index() -> dict[str, dict[str, Any]]:
    """Return ``{weakness_id: weakness_record}``."""
    return {w["id"]: w for w in load_mapping()["weaknesses"]}


def weaknesses_for_protocol(protocol: str) -> list[str]:
    """Weakness ids that can apply to a given protocol."""
    return [w["id"] for w in load_mapping()["weaknesses"] if protocol in w["protocols"]]


def weaknesses_by_source(source: str) -> list[str]:
    """Weakness ids detected by a given source (``rf_probe`` or ``inventory``)."""
    return [w["id"] for w in load_mapping()["weaknesses"] if w["source"] == source]


def broken_cipher_device_types() -> dict[str, dict[str, Any]]:
    """Device generations whose proprietary cipher is publicly broken."""
    return {e["device_type"]: e for e in load_mapping().get("broken_cipher_generations", [])}


def zone_exposure(zone: str) -> float:
    """Exposure multiplier for a zone sensitivity class."""
    return float(load_mapping()["zone_sensitivity"][zone]["exposure"])


def exposure_modifiers() -> dict[str, dict[str, Any]]:
    return load_mapping()["exposure_modifiers"]


def validate() -> list[str]:
    """Check the knowledge base for dangling references. Returns a list of problems."""
    problems: list[str] = []
    mapping = load_mapping()
    valid_relations = {"violates", "weakens", "evidence"}
    valid_protocols = set(mapping["protocols"])
    for weakness in mapping["weaknesses"]:
        wid = weakness["id"]
        for proto in weakness["protocols"]:
            if proto not in valid_protocols:
                problems.append(f"{wid}: unknown protocol {proto!r}")
        if weakness["source"] not in {"rf_probe", "inventory"}:
            problems.append(f"{wid}: unknown source {weakness['source']!r}")
        for fw, key in MAPPING_KEY.items():
            index = controls_index(fw)
            if not weakness.get(key):
                problems.append(f"{wid}: no {fw} mapping")
            for ref in weakness.get(key, []):
                if ref["id"] not in index:
                    problems.append(f"{wid}: {fw} control {ref['id']} not in catalogue")
                if ref["relation"] not in valid_relations:
                    problems.append(f"{wid}: bad relation {ref['relation']!r}")
                if not ref.get("rationale", "").strip():
                    problems.append(f"{wid}: empty rationale for {ref['id']}")
    return problems
