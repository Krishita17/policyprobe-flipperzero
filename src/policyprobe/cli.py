"""Command line interface.

Each subcommand is one stage of the pipeline and each writes its output to disk, so the
stages can be run individually, inspected, and re-run without repeating the ones before
them. ``policyprobe all`` runs the lot, and is what ``make all`` calls.

    policyprobe validate      check the knowledge base for dangling references
    policyprobe data          generate synthetic facility profiles
    policyprobe scan          probe a facility (mock backend, or a real Flipper)
    policyprobe map           map findings onto controls and compute posture
    policyprobe report        write the compliance report (Markdown + HTML)
    policyprobe evaluate      score detection, control assignment and posture ordering
    policyprobe figures       regenerate every figure
    policyprobe tables        regenerate the README tables from the knowledge base
    policyprobe all           everything above, in order
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from . import __version__, kb
from .bridge import get_bridge
from .data.facility import generate_facility
from .data.real_loader import load_real_samples, to_observations
from .mapping.engine import MappingEngine
from .normalize import normalize_facility
from .schema import AccessPoint, Facility, Finding, Observation
from .score.risk import score_findings

REPO = kb.REPO_ROOT
RESULTS = REPO / "results"
FIGURES = REPO / "figures"
REPORTS = REPO / "reports"
SYNTH = REPO / "data" / "synthetic"
CONFIG = REPO / "config" / "default.yaml"


# ------------------------------------------------------------------------ utilities --
def load_config(path: Path | None = None) -> dict[str, Any]:
    path = path or CONFIG
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _write_json(obj: Any, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    return path


def _write_csv(rows: list[dict[str, Any]], path: Path) -> Path:
    import csv
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return path
    fieldnames = list(rows[0])
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _facility_from_dict(d: dict[str, Any]) -> Facility:
    aps = [AccessPoint(**ap) for ap in d.pop("access_points", [])]
    return Facility(**d, access_points=aps)


def _load_facility(path: Path) -> Facility:
    return _facility_from_dict(json.loads(path.read_text(encoding="utf-8")))


def _findings_to_rows(findings: list[Finding]) -> list[dict[str, Any]]:
    rows = []
    for f in findings:
        rows.append({
            "finding_id": f.id,
            "access_point_id": f.access_point_id,
            "access_point": f.access_point_name,
            "zone": f.zone,
            "protocol": f.protocol,
            "device_type": f.device_type,
            "weakness_id": f.weakness_id,
            "weakness": f.weakness_title,
            "source": f.source,
            "confidence": f.confidence,
            "base_severity": f.base_severity,
            "risk_score": f.risk_score,
            "risk_rating": f.risk_rating,
            "iso27001_failed": ", ".join(sorted({r.control_id for r in f.controls
                                                 if r.framework == "iso27001"
                                                 and r.relation == "violates"})),
            "nist80053_failed": ", ".join(sorted({r.control_id for r in f.controls
                                                  if r.framework == "nist80053"
                                                  and r.relation == "violates"})),
            "evidence": f.evidence,
        })
    return rows


# ------------------------------------------------------------------------- commands --
def cmd_validate(args) -> int:
    problems = kb.validate()
    mapping = kb.load_mapping()
    if problems:
        print("Knowledge base validation FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    n_maps = sum(len(w["iso27001"]) + len(w["nist80053"]) for w in mapping["weaknesses"])
    print(f"Knowledge base OK: {len(mapping['weaknesses'])} weaknesses, "
          f"{n_maps} control mappings, {len(mapping['protocols'])} protocols.")
    for fw in ("iso27001", "nist80053"):
        meta = kb.load_framework(fw)["framework"]
        print(f"  {meta['name']} {meta['edition']}: {len(kb.controls_index(fw))} controls")
    return 0


def cmd_data(args) -> int:
    cfg = load_config(args.config)
    g = cfg["facility"]
    facility = generate_facility(
        seed=args.seed if args.seed is not None else g["seed"],
        n_access_points=args.access_points or g["n_access_points"],
        credential_strength_mix=g["credential_strength_mix"],
        protocol_diversity=g["protocol_diversity"],
        legacy_prevalence=g["legacy_prevalence"],
        monitoring_maturity=g["monitoring_maturity"],
        name=g.get("name"),
        sector=g.get("sector"),
    )
    path = _write_json(facility.to_dict(), SYNTH / f"{facility.id}.json")
    _write_json(facility.to_dict(), SYNTH / "current.json")
    gt = sum(len(ap.ground_truth_weaknesses) for ap in facility.access_points)
    print(f"Generated {facility.name}: {len(facility.access_points)} access points, "
          f"{gt} ground-truth weaknesses -> {path.relative_to(REPO)}")
    return 0


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    facility = _load_facility(SYNTH / "current.json")

    if args.backend in ("flipper-cli", "flipper"):
        bridge = get_bridge("flipper-cli", port=args.port, dry_run=args.dry_run)
        observations = bridge.probe_all(facility.access_points)
        bridge.close()
    elif args.backend == "real-samples":
        records = load_real_samples()
        if not records:
            print("No real samples found under data/real_samples/. "
                  "Capture some with --backend flipper-cli first.", file=sys.stderr)
            return 1
        observations = to_observations(records)
    else:
        bridge = get_bridge("mock", seed=cfg["scan"]["seed"])
        observations = bridge.probe_all(facility.access_points)

    _write_json([o.to_dict() for o in observations], RESULTS / "observations.json")
    print(f"Captured {len(observations)} observations with backend "
          f"'{args.backend}' -> results/observations.json")
    return 0


def _load_observations() -> list[Observation]:
    raw = json.loads((RESULTS / "observations.json").read_text(encoding="utf-8"))
    return [Observation(**o) for o in raw]


def cmd_map(args) -> int:
    from .evaluate import train_default_classifier

    cfg = load_config(args.config)
    facility = _load_facility(SYNTH / "current.json")
    observations = _load_observations()

    classifier = train_default_classifier(
        train_seeds=list(range(*cfg["classifier"]["train_seed_range"])),
        seed=cfg["classifier"]["seed"],
    )
    classifier.save_metrics(RESULTS / "classifier.json")

    findings = normalize_facility(facility, observations, classifier,
                                  threshold=cfg["classifier"]["threshold"])
    findings = score_findings(findings, facility.access_points)

    engine = MappingEngine(frameworks=cfg["frameworks"])
    findings = engine.map_findings(findings)
    postures = engine.posture_all(findings, n_access_points=len(facility.access_points))

    _write_json([dataclasses.asdict(f) for f in findings], RESULTS / "findings.json")
    _write_csv(_findings_to_rows(findings), RESULTS / "findings.csv")
    _write_json({fw: p.to_dict() for fw, p in postures.items()}, RESULTS / "posture.json")
    _write_csv([s.to_dict() | {"finding_ids": ", ".join(s.finding_ids)}
                for p in postures.values() for s in p.control_statuses],
               RESULTS / "control_status.csv")
    _write_csv(engine.remediation_roadmap(findings), RESULTS / "roadmap.csv")
    _write_csv(engine.crosswalk(), RESULTS / "crosswalk.csv")

    print(f"Mapped {len(findings)} findings onto {len(cfg['frameworks'])} frameworks:")
    for fw, p in postures.items():
        not_met = sum(1 for s in p.control_statuses if s.status == "not_met")
        print(f"  {p.framework_name:<16} conformity {p.overall_posture:5.1f}%   "
              f"estate {p.overall_estate_posture:5.1f}%   "
              f"{not_met} controls not met   coverage {p.coverage['coverage_pct']}%")
    return 0


def cmd_report(args) -> int:
    from .mapping.engine import PostureResult
    from .report.generator import ReportGenerator
    from .schema import ControlRef, ControlStatus

    cfg = load_config(args.config)
    facility = _load_facility(SYNTH / "current.json")
    findings = [
        Finding(**{**f, "controls": [ControlRef(**c) for c in f.get("controls", [])]})
        for f in json.loads((RESULTS / "findings.json").read_text(encoding="utf-8"))
    ]
    posture_raw = json.loads((RESULTS / "posture.json").read_text(encoding="utf-8"))
    postures = {
        fw: PostureResult(
            framework=p["framework"], framework_name=p["framework_name"],
            edition=p["edition"],
            control_statuses=[ControlStatus(**c) for c in p["control_statuses"]],
            posture_by_family=p["posture_by_family"],
            overall_posture=p["overall_posture"],
            estate_posture_by_family=p["estate_posture_by_family"],
            overall_estate_posture=p["overall_estate_posture"],
            coverage=p["coverage"],
        )
        for fw, p in posture_raw.items()
    }
    engine = MappingEngine(frameworks=cfg["frameworks"])
    generator = ReportGenerator(facility, findings, postures, engine,
                                backend=args.backend)
    paths = generator.write(REPORTS)
    for kind, path in paths.items():
        print(f"Wrote {kind:<9} -> {path.relative_to(REPO)}")
    return 0


def cmd_evaluate(args) -> int:
    from .classify.model import build_training_set, noise_sweep
    from . import evaluate as ev

    cfg = load_config(args.config)
    train_seeds = list(range(*cfg["classifier"]["train_seed_range"]))
    test_seeds = list(range(*cfg["evaluation"]["test_seed_range"]))

    classifier = ev.train_default_classifier(train_seeds, seed=cfg["classifier"]["seed"])
    classifier_metrics = classifier.evaluate(build_training_set(test_seeds))
    classifier.save_metrics(RESULTS / "classifier.json")

    facilities = [generate_facility(seed=s, n_access_points=28) for s in test_seeds]
    detection = ev.detection_metrics(facilities, classifier)
    control = ev.control_metrics(facilities, classifier)
    ordering = ev.posture_ordering(classifier)
    real = ev.real_sample_metrics(classifier)

    sweep = []
    if not args.quick:
        sweep = noise_sweep(train_seeds[:20], test_seeds[:6],
                            levels=cfg["evaluation"]["noise_levels"],
                            seed=cfg["classifier"]["seed"])

    metrics = {
        "policyprobe_version": __version__,
        "config": cfg,
        "classifier": classifier_metrics,
        "top_features": classifier.feature_importance(),
        "detection": detection,
        "control_assignment": control,
        "posture_ordering": ordering,
        "posture_ordering_monotonic": {
            fw: ev.ordering_is_monotonic(ordering, fw) for fw in cfg["frameworks"]
        },
        "noise_sweep": sweep,
        "real_samples": real,
        "knowledge_base": {
            "weaknesses": len(kb.load_mapping()["weaknesses"]),
            "control_mappings": sum(len(w["iso27001"]) + len(w["nist80053"])
                                    for w in kb.load_mapping()["weaknesses"]),
        },
    }
    _write_json(metrics, RESULTS / "metrics.json")
    _write_csv(ordering, RESULTS / "posture_ordering.csv")
    if sweep:
        _write_csv(sweep, RESULTS / "noise_sweep.csv")

    print(f"Classifier      device {classifier_metrics['device_accuracy']:.3f} exact / "
          f"{classifier_metrics['device_family_accuracy']:.3f} family, "
          f"weak-scheme micro-F1 {classifier_metrics['weakness_micro_f1']:.3f}")
    print(f"Detection       P {detection['precision']:.3f}  R {detection['recall']:.3f}  "
          f"F1 {detection['f1']:.3f}")
    print(f"Control assign  P {control['overall']['precision']:.3f}  "
          f"R {control['overall']['recall']:.3f}  F1 {control['overall']['f1']:.3f}")
    for fw, mono in metrics["posture_ordering_monotonic"].items():
        print(f"Posture order   {fw}: {'monotonic weak -> strong' if mono else 'NOT MONOTONIC'}")
    print(f"Real samples    {real['n_samples'] if real else 0} committed")
    print("Wrote results/metrics.json")
    return 0


def cmd_figures(args) -> int:
    from .mapping.engine import PostureResult
    from .report import figures as fig
    from .schema import ControlStatus

    posture_raw = json.loads((RESULTS / "posture.json").read_text(encoding="utf-8"))
    postures = {
        fw: PostureResult(
            framework=p["framework"], framework_name=p["framework_name"],
            edition=p["edition"],
            control_statuses=[ControlStatus(**c) for c in p["control_statuses"]],
            posture_by_family=p["posture_by_family"],
            overall_posture=p["overall_posture"],
            estate_posture_by_family=p["estate_posture_by_family"],
            overall_estate_posture=p["overall_estate_posture"],
            coverage=p["coverage"],
        )
        for fw, p in posture_raw.items()
    }
    findings = [Finding(**{**f, "controls": []})
                for f in json.loads((RESULTS / "findings.json").read_text(encoding="utf-8"))]
    metrics = json.loads((RESULTS / "metrics.json").read_text(encoding="utf-8"))

    written = [
        fig.architecture(FIGURES / "architecture.png"),
        fig.write_mermaid(FIGURES / "architecture.mmd"),
        fig.posture_by_family(postures, FIGURES / "posture_by_family.png"),
        fig.findings_by_risk(findings, FIGURES / "findings_by_risk.png"),
        fig.weakness_prevalence_by_protocol(
            findings, FIGURES / "weakness_prevalence_by_protocol.png"),
        fig.mapping_coverage(postures, FIGURES / "control_coverage.png"),
        fig.classifier_accuracy(metrics["classifier"], FIGURES / "classifier_accuracy.png",
                                real_metrics=metrics.get("real_samples")),
        fig.end_to_end_accuracy(
            {"finding": metrics["detection"], "control": metrics["control_assignment"]["overall"]},
            FIGURES / "end_to_end_accuracy.png"),
        fig.posture_ordering(metrics["posture_ordering"], FIGURES / "posture_ordering.png"),
    ]
    if metrics.get("noise_sweep"):
        written.append(fig.noise_sweep(metrics["noise_sweep"], FIGURES / "noise_sweep.png"))
    for path in written:
        print(f"  {path.relative_to(REPO)}")
    print(f"Wrote {len(written)} figures.")
    return 0


def cmd_tables(args) -> int:
    """Regenerate the Markdown tables embedded in the README from the knowledge base."""
    from .tables import write_all
    for path in write_all():
        print(f"  {path.relative_to(REPO)}")
    return 0


def cmd_all(args) -> int:
    for fn in (cmd_validate, cmd_data, cmd_scan, cmd_map, cmd_evaluate, cmd_figures,
               cmd_report, cmd_tables):
        print(f"\n=== {fn.__name__.removeprefix('cmd_')} ===")
        rc = fn(args)
        if rc != 0:
            return rc
    return 0


# ---------------------------------------------------------------------------- main --
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="policyprobe",
        description="Flipper-driven physical-security compliance scanner mapped to "
                    "ISO/IEC 27001 and NIST SP 800-53 controls.",
    )
    parser.add_argument("--version", action="version", version=f"PolicyProbe {__version__}")
    parser.add_argument("--config", type=Path, default=None, help="config YAML to use")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="check the knowledge base").set_defaults(fn=cmd_validate)

    p = sub.add_parser("data", help="generate a synthetic facility profile")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--access-points", type=int, default=None)
    p.set_defaults(fn=cmd_data)

    p = sub.add_parser("scan", help="probe the current facility")
    p.add_argument("--backend", default="mock",
                   choices=["mock", "flipper-cli", "real-samples"])
    p.add_argument("--port", default=None, help="serial port for the flipper-cli backend")
    p.add_argument("--dry-run", action="store_true",
                   help="print the CLI commands instead of opening the port")
    p.set_defaults(fn=cmd_scan)

    sub.add_parser("map", help="map findings onto controls").set_defaults(fn=cmd_map)

    p = sub.add_parser("report", help="write the compliance report")
    p.add_argument("--backend", default="mock")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("evaluate", help="score the pipeline against ground truth")
    p.add_argument("--quick", action="store_true", help="skip the noise sweep")
    p.set_defaults(fn=cmd_evaluate)

    sub.add_parser("figures", help="regenerate every figure").set_defaults(fn=cmd_figures)
    sub.add_parser("tables", help="regenerate the README tables").set_defaults(fn=cmd_tables)

    p = sub.add_parser("all", help="run the whole pipeline")
    p.add_argument("--backend", default="mock")
    p.add_argument("--port", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--access-points", type=int, default=None)
    p.set_defaults(fn=cmd_all)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
