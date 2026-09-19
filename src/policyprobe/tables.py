"""Generate the Markdown tables embedded in the README.

The signature artefact of this project is a table, not a chart, so it is generated from
the knowledge base by code like everything else. Editing
``mappings/protocol_weakness_control.yaml`` and running ``make tables`` updates the README
tables, which means the documented mapping can never drift from the one the engine uses.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import kb
from .mapping.engine import MappingEngine

TABLE_DIR = kb.REPO_ROOT / "results" / "tables"

PROTOCOL_SHORT = {
    "rfid_lf": "125 kHz", "nfc_hf": "13.56 MHz", "subghz": "Sub-GHz",
    "ir": "IR", "ibutton": "1-Wire",
}


def _protocols(weakness: dict) -> str:
    return " · ".join(PROTOCOL_SHORT[p] for p in weakness["protocols"])


def _controls(weakness: dict, key: str, relation: str = "violates") -> str:
    ids = [r["id"] for r in weakness.get(key, []) if r["relation"] == relation]
    return ", ".join(f"`{i}`" for i in ids) or "—"


def mapping_table() -> str:
    """The protocol -> weakness -> control table, in full."""
    lines = [
        "| Protocol | Weakness | Sev. | Detected by | ISO/IEC 27001:2022 controls failed "
        "| NIST SP 800-53 Rev. 5 controls failed |",
        "|---|---|---|---|---|---|",
    ]
    for w in kb.load_mapping()["weaknesses"]:
        source = "RF probe" if w["source"] == "rf_probe" else "Inventory"
        lines.append(
            f"| {_protocols(w)} | **{w['title']}**<br/>`{w['id']}` | {w['base_severity']} "
            f"| {source} | {_controls(w, 'iso27001')} | {_controls(w, 'nist80053')} |"
        )
    return "\n".join(lines)


def crosswalk_table() -> str:
    """Same finding, both frameworks: the framework-agnostic view."""
    engine = MappingEngine()
    lines = [
        "| Weakness | Protocols | ISO/IEC 27001:2022 | NIST SP 800-53 Rev. 5 |",
        "|---|---|---|---|",
    ]
    for row in engine.crosswalk():
        iso = ", ".join(f"`{c.strip()}`" for c in row["iso27001"].split(",") if c.strip())
        nist = ", ".join(f"`{c.strip()}`" for c in row["nist80053"].split(",") if c.strip())
        lines.append(f"| {row['weakness']}<br/>`{row['weakness_id']}` | {row['protocols']} "
                     f"| {iso} | {nist} |")
    lines.append("")
    lines.append("`*` marks a control the weakness fails outright; the rest are controls it "
                 "weakens or provides supporting evidence against.")
    return "\n".join(lines)


def remediation_table() -> str:
    """Gap -> mapped control -> recommended fix -> priority, straight from the KB."""
    lines = [
        "| Priority | Gap | Effort | Controls failed (ISO / NIST) | Recommended action |",
        "|---|---|---|---|---|",
    ]
    rows = sorted(kb.load_mapping()["weaknesses"],
                  key=lambda w: (w["remediation"]["priority"], w["id"]))
    for w in rows:
        iso = _controls(w, "iso27001").replace("`", "")
        nist = _controls(w, "nist80053").replace("`", "")
        lines.append(
            f"| **{w['remediation']['priority']}** | {w['title']} "
            f"| {w['remediation']['effort']} | {iso} / {nist} "
            f"| {w['remediation']['summary']} |"
        )
    return "\n".join(lines)


def coverage_table() -> str:
    """Which controls this method can speak to, and which it cannot."""
    lines = ["| Framework | Control | Title | PolicyProbe coverage |", "|---|---|---|---|"]
    label = {True: "Full", "yes": "Full", "partial": "Partial", False: "None", "no": "None"}
    for fw in ("iso27001", "nist80053"):
        name = kb.load_framework(fw)["framework"]["name"]
        for cid, control in kb.controls_index(fw).items():
            cov = label.get(control.get("assessable_via_policyprobe"), "None")
            lines.append(f"| {name} | `{cid}` | {control['title']} | {cov} |")
    return "\n".join(lines)


def results_summary_table() -> str:
    """Headline numbers from the last evaluation run."""
    metrics_path = kb.REPO_ROOT / "results" / "metrics.json"
    posture_path = kb.REPO_ROOT / "results" / "posture.json"
    if not metrics_path.exists() or not posture_path.exists():
        return "_Run `make all` to populate this table._"
    m = json.loads(metrics_path.read_text(encoding="utf-8"))
    p = json.loads(posture_path.read_text(encoding="utf-8"))

    c, d, ca = m["classifier"], m["detection"], m["control_assignment"]
    rows = [
        ("Device generation identified exactly", f"{c['device_accuracy']:.3f}",
         f"over {c['n_device_classes']} generations"),
        ("Device identification family correct", f"{c['device_family_accuracy']:.3f}",
         f"over {c['n_device_families']} families — this is what drives the mapping"),
        ("Weak-scheme flags (micro-F1)", f"{c['weakness_micro_f1']:.3f}",
         f"{len(c['per_weakness'])} RF-observable weaknesses"),
        ("Finding detection (F1)", f"{d['f1']:.3f}",
         f"P {d['precision']:.3f} / R {d['recall']:.3f} against ground truth"),
        ("Control assignment (F1)", f"{ca['overall']['f1']:.3f}",
         f"P {ca['overall']['precision']:.3f} / R {ca['overall']['recall']:.3f}, "
         "both frameworks"),
    ]
    for fw, posture in p.items():
        rows.append((f"{posture['framework_name']} — strict conformity, sample facility",
                     f"{posture['overall_posture']}%",
                     f"control met only where it holds at every access point; "
                     f"coverage {posture['coverage']['coverage_pct']}% of the catalogue"))
        rows.append((f"{posture['framework_name']} — estate score, sample facility",
                     f"{posture['overall_estate_posture']}%",
                     "share of access points at which the control actually holds"))
    rows.append(("Posture ordering weak → strong",
                 "monotonic" if all(m["posture_ordering_monotonic"].values()) else "NOT monotonic",
                 "estate score across four labelled estate profiles"))
    rows.append(("Knowledge base size",
                 f"{m['knowledge_base']['control_mappings']} mappings",
                 f"{m['knowledge_base']['weaknesses']} weaknesses across 5 protocols"))

    lines = ["| Measure | Result | Notes |", "|---|---|---|"]
    lines += [f"| {a} | **{b}** | {c_} |" for a, b, c_ in rows]
    return "\n".join(lines)


TABLES = {
    "mapping_table.md": mapping_table,
    "crosswalk_table.md": crosswalk_table,
    "remediation_table.md": remediation_table,
    "coverage_table.md": coverage_table,
    "results_summary.md": results_summary_table,
}


README_PATH = kb.REPO_ROOT / "README.md"

# README region name -> table builder. The region markers in README.md are
# <!-- BEGIN:name --> ... <!-- END:name -->.
README_REGIONS = {
    "mapping_table": mapping_table,
    "crosswalk_table": crosswalk_table,
    "remediation_table": remediation_table,
    "results_summary": results_summary_table,
}


def inject_into_readme(path: Path | None = None) -> list[str]:
    """Replace each marked region of the README with its freshly generated table.

    The README is documentation of the knowledge base, so it is generated from it. A table
    in the README that disagreed with the table the engine uses would be worse than no
    table at all.
    """
    import re

    path = path or README_PATH
    text = path.read_text(encoding="utf-8")
    updated: list[str] = []
    for name, builder in README_REGIONS.items():
        pattern = re.compile(
            rf"(<!-- BEGIN:{re.escape(name)} -->\n).*?(\n<!-- END:{re.escape(name)} -->)",
            re.DOTALL,
        )
        if not pattern.search(text):
            continue
        text = pattern.sub(lambda m: m.group(1) + builder() + m.group(2), text)
        updated.append(name)
    path.write_text(text, encoding="utf-8")
    return updated


def write_all(out_dir: Path | None = None) -> list[Path]:
    out_dir = out_dir or TABLE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, builder in TABLES.items():
        path = out_dir / filename
        path.write_text(builder() + "\n", encoding="utf-8")
        written.append(path)
    regions = inject_into_readme()
    if regions:
        written.append(README_PATH)
    return written
