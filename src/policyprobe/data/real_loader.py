"""Loader for genuine Flipper Zero reads of the author's own test credentials.

Tier 2 of the project runs the same pipeline on real hardware. Reads are captured with
``policyprobe scan --backend flipper-cli``, saved as JSON under ``data/real_samples/``,
and loaded here so the classifier can be scored on real signals as well as simulated
ones.

Only the author's own blank, development and spare media belong here — dev NFC cards, a
blank fob, an iButton, a spare remote. Nothing tied to a facility or system the author
does not own is ever committed, and the schema carries no facility identifiers: each
sample records the technology and the observation, not where it was found.

Sample file format (one JSON object per file, or a JSON list)::

    {
      "sample_id": "own-em4100-01",
      "device_type": "EM4100/EM4102",
      "protocol": "rfid_lf",
      "owned_by_author": true,
      "notes": "blank development tag, purchased new",
      "ground_truth_weaknesses": ["W-STATIC-ID", "W-NO-CRYPTO"],
      "payload": { ... same keys the mock bridge produces ... }
    }
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import kb
from ..schema import Observation

REAL_SAMPLE_DIR = kb.REPO_ROOT / "data" / "real_samples"

REQUIRED_FIELDS = {"sample_id", "device_type", "protocol", "payload"}


def _records_from_file(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def load_real_samples(directory: Path | None = None) -> list[dict[str, Any]]:
    """Load every committed real read. Returns an empty list if none are present.

    An empty result is a normal state, not an error: the repository runs end to end in
    mock mode, and the real-hardware comparison is populated only once the author has run
    a Tier 2 capture session.
    """
    directory = directory or REAL_SAMPLE_DIR
    if not directory.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.name.upper().startswith("TEMPLATE"):
            continue
        for record in _records_from_file(path):
            missing = REQUIRED_FIELDS - set(record)
            if missing:
                raise ValueError(f"{path.name}: sample missing fields {sorted(missing)}")
            if not record.get("owned_by_author", False):
                raise ValueError(
                    f"{path.name}: sample {record['sample_id']!r} is not marked as the "
                    "author's own device; only owned or explicitly authorised media may "
                    "be committed to this repository"
                )
            records.append(record)
    return records


def to_observations(records: list[dict[str, Any]]) -> list[Observation]:
    """Convert loaded sample records into observations the pipeline can consume."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return [
        Observation(
            access_point_id=r["sample_id"],
            protocol=r["protocol"],
            backend="flipper-cli",
            timestamp=r.get("captured_at", now),
            payload=r["payload"],
        )
        for r in records
    ]


def ground_truth(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{sample_id: {device_type, weaknesses}}`` for scoring the classifier."""
    return {
        r["sample_id"]: {
            "device_type": r["device_type"],
            "weaknesses": set(r.get("ground_truth_weaknesses", [])),
        }
        for r in records
    }
