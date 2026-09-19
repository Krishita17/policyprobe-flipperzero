"""Map findings onto control frameworks and roll them up into a compliance posture.

This is the contribution the rest of the project exists to support. Everything upstream
produces a finding; this module is what turns "the loading bay remote is fixed-code" into
"A.7.2 Physical entry is not met at AP-009, and PE-16 Delivery and Removal is not met",
which is the sentence an auditor can act on.

Design decisions worth stating plainly
--------------------------------------
**The mapping is deterministic, and that is on purpose.** Given a weakness id, the set of
controls it evidences is a table lookup, not a prediction. An assessor must be able to
read the mapping, disagree with a specific row, edit the YAML and re-run. A model that
mapped findings to controls probabilistically would be unauditable, which would defeat
the point of the tool. It follows that the *accuracy* of the control assignment is
entirely inherited from the accuracy of weakness detection upstream — there is no
separate mapping error to measure, only mapping correctness to review, which the tests
and the published table exist for.

**Two scores, because one number cannot do both jobs.** A control is either met across the
site or it is not, so the strict rollup takes the worst access point: any ``violates``
finding makes the control ``not_met``. That is the correct answer for a certification
audit, and it is the ``conformity`` score.

It is also almost useless for managing remediation. One unreplaced door fails a control
just as completely as forty, so an estate halfway through a migration scores the same as
one that has not started — which tells the person funding the migration nothing. The
``estate`` score therefore reports, for each control, the share of assessed access points
where it actually holds. Conformity is what the auditor certifies; the estate score is
what shows whether last quarter's spend moved anything.

**Silence is not a pass.** A control in scope with no findings against it is reported as
``met`` only when PolicyProbe could actually have detected a failure. Controls the tool
cannot assess are reported as ``not_assessed`` and excluded from the posture score, and
the coverage figure reports how large that blind spot is. Scoring an unassessable control
as passing would manufacture assurance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import kb
from ..schema import ControlRef, ControlStatus, Finding

RELATION_RANK = {"evidence": 0, "weakens": 1, "violates": 2}
STATUS_SCORE = {"not_met": 0.0, "partially_met": 0.5, "met": 1.0}

# Confidence below which an rf_probe finding may not by itself fail a control.
FAIL_CONFIDENCE_FLOOR = 0.60


@dataclass
class PostureResult:
    """Everything the report generator needs about one framework."""

    framework: str
    framework_name: str
    edition: str
    control_statuses: list[ControlStatus] = field(default_factory=list)
    posture_by_family: dict[str, float] = field(default_factory=dict)
    overall_posture: float = 0.0
    estate_posture_by_family: dict[str, float] = field(default_factory=dict)
    overall_estate_posture: float = 0.0
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "framework_name": self.framework_name,
            "edition": self.edition,
            "control_statuses": [c.to_dict() for c in self.control_statuses],
            "posture_by_family": self.posture_by_family,
            "overall_posture": self.overall_posture,
            "estate_posture_by_family": self.estate_posture_by_family,
            "overall_estate_posture": self.overall_estate_posture,
            "coverage": self.coverage,
        }


class MappingEngine:
    """Applies the protocol -> weakness -> control knowledge base to a finding set."""

    def __init__(self, frameworks: list[str] | None = None):
        self.frameworks = frameworks or ["iso27001", "nist80053"]
        self.weaknesses = kb.weakness_index()

    # --------------------------------------------------------------- finding level --
    def map_finding(self, finding: Finding) -> Finding:
        """Attach every control this finding bears on, across all selected frameworks."""
        weakness = self.weaknesses.get(finding.weakness_id)
        if weakness is None:
            return finding
        refs: list[ControlRef] = []
        for framework in self.frameworks:
            index = kb.controls_index(framework)
            for ref in weakness.get(kb.MAPPING_KEY[framework], []):
                control = index[ref["id"]]
                refs.append(ControlRef(
                    framework=framework,
                    control_id=ref["id"],
                    title=control["title"],
                    family=control["family"],
                    relation=ref["relation"],
                    rationale=ref["rationale"],
                ))
        finding.controls = refs
        return finding

    def map_findings(self, findings: list[Finding]) -> list[Finding]:
        return [self.map_finding(f) for f in findings]

    # ----------------------------------------------------------------- framework ---
    def _assessable(self, framework: str) -> dict[str, dict]:
        """Controls this tool can produce evidence for at all."""
        return {
            cid: c for cid, c in kb.controls_index(framework).items()
            if c.get("assessable_via_policyprobe") in (True, "yes", "partial")
        }

    def posture(self, framework: str, findings: list[Finding],
                n_access_points: int | None = None) -> PostureResult:
        """Roll mapped findings up into control statuses and a posture score."""
        catalogue = kb.controls_index(framework)
        meta = kb.load_framework(framework)["framework"]
        families = kb.load_framework(framework).get("families", {})
        assessable = self._assessable(framework)

        if n_access_points is None:
            n_access_points = len({f.access_point_id for f in findings}) or 1

        worst: dict[str, str] = {}
        evidence_ids: dict[str, list[str]] = {}
        failing_aps: dict[str, set[str]] = {}
        weakening_aps: dict[str, set[str]] = {}
        for finding in findings:
            for ref in finding.controls:
                if ref.framework != framework:
                    continue
                relation = ref.relation
                # A finding the classifier is unsure of may weaken a control but not fail it.
                if (relation == "violates" and finding.source == "rf_probe"
                        and finding.confidence < FAIL_CONFIDENCE_FLOOR):
                    relation = "weakens"
                current = worst.get(ref.control_id, "evidence")
                if RELATION_RANK[relation] > RELATION_RANK[current]:
                    worst[ref.control_id] = relation
                elif ref.control_id not in worst:
                    worst[ref.control_id] = relation
                evidence_ids.setdefault(ref.control_id, []).append(finding.id)
                if relation == "violates":
                    failing_aps.setdefault(ref.control_id, set()).add(finding.access_point_id)
                elif relation == "weakens":
                    weakening_aps.setdefault(ref.control_id, set()).add(finding.access_point_id)

        statuses: list[ControlStatus] = []
        for cid, control in catalogue.items():
            if cid in worst:
                relation = worst[cid]
                status = {"violates": "not_met", "weakens": "partially_met",
                          "evidence": "met"}[relation]
            elif cid in assessable:
                status = "met"          # in scope, probed, nothing found against it
            else:
                status = "not_assessed"
            failing = failing_aps.get(cid, set())
            # An access point already counted as failing is not counted again as weakened.
            weakened = weakening_aps.get(cid, set()) - failing
            if status == "not_assessed":
                estate_score = 0.0
            else:
                estate_score = max(0.0, 1.0 - (len(failing) + 0.5 * len(weakened))
                                   / n_access_points)
            statuses.append(ControlStatus(
                framework=framework,
                control_id=cid,
                title=control["title"],
                family=control["family"],
                status=status,
                finding_ids=sorted(set(evidence_ids.get(cid, []))),
                score=STATUS_SCORE.get(status, 0.0),
                failing_access_points=len(failing),
                weakened_access_points=len(weakened),
                assessed_access_points=n_access_points,
                estate_score=round(estate_score, 4),
            ))

        scored = [s for s in statuses if s.status != "not_assessed"]
        by_family: dict[str, list[float]] = {}
        estate_by_family: dict[str, list[float]] = {}
        for s in scored:
            by_family.setdefault(s.family, []).append(s.score)
            estate_by_family.setdefault(s.family, []).append(s.estate_score)
        posture_by_family = {
            families.get(fam, fam): round(100.0 * sum(v) / len(v), 1)
            for fam, v in sorted(by_family.items())
        }
        estate_posture_by_family = {
            families.get(fam, fam): round(100.0 * sum(v) / len(v), 1)
            for fam, v in sorted(estate_by_family.items())
        }
        overall = round(100.0 * sum(s.score for s in scored) / len(scored), 1) if scored else 0.0
        overall_estate = (round(100.0 * sum(s.estate_score for s in scored) / len(scored), 1)
                          if scored else 0.0)

        coverage = {
            "controls_in_catalogue": len(catalogue),
            "controls_assessable": len(assessable),
            "controls_assessed": len(scored),
            "controls_not_assessed": len(catalogue) - len(scored),
            "coverage_pct": round(100.0 * len(scored) / len(catalogue), 1) if catalogue else 0.0,
            "controls_with_findings": len(worst),
        }

        return PostureResult(
            framework=framework,
            framework_name=meta["name"],
            edition=meta["edition"],
            control_statuses=sorted(statuses, key=lambda s: s.control_id),
            posture_by_family=posture_by_family,
            overall_posture=overall,
            estate_posture_by_family=estate_posture_by_family,
            overall_estate_posture=overall_estate,
            coverage=coverage,
        )

    def posture_all(self, findings: list[Finding],
                    n_access_points: int | None = None) -> dict[str, PostureResult]:
        return {fw: self.posture(fw, findings, n_access_points) for fw in self.frameworks}

    # ------------------------------------------------------------------ crosswalk --
    def crosswalk(self) -> list[dict[str, Any]]:
        """Rows showing the same weakness mapped into every selected framework.

        This is what makes the mapping framework-agnostic in practice: an organisation
        certified to ISO 27001 and an agency working to NIST SP 800-53 get the same
        findings expressed in their own control language, from one assessment.
        """
        rows = []
        for weakness in kb.load_mapping()["weaknesses"]:
            row: dict[str, Any] = {
                "weakness_id": weakness["id"],
                "weakness": weakness["title"],
                "protocols": ", ".join(weakness["protocols"]),
                "severity": weakness["base_severity"],
                "source": weakness["source"],
            }
            for framework in self.frameworks:
                refs = weakness.get(kb.MAPPING_KEY[framework], [])
                row[framework] = ", ".join(
                    f"{r['id']}{'*' if r['relation'] == 'violates' else ''}" for r in refs
                )
            rows.append(row)
        return rows

    def remediation_roadmap(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Gap -> mapped controls -> recommended fix -> priority, ranked for action.

        Ranked by priority band first, then by how much risk sits behind the gap, so the
        roadmap reflects both urgency and the size of the exposure it closes.
        """
        grouped: dict[str, dict[str, Any]] = {}
        for finding in findings:
            w = self.weaknesses[finding.weakness_id]
            entry = grouped.setdefault(finding.weakness_id, {
                "weakness_id": finding.weakness_id,
                "weakness": finding.weakness_title,
                "priority": w["remediation"]["priority"],
                "effort": w["remediation"]["effort"],
                "recommendation": w["remediation"]["summary"],
                "steps": w["remediation"]["steps"],
                "access_points": set(),
                "zones": set(),
                "risk_total": 0.0,
                "max_rating": "Low",
                "controls": set(),
            })
            entry["access_points"].add(finding.access_point_name)
            entry["zones"].add(finding.zone)
            entry["risk_total"] += finding.risk_score
            from ..score.risk import RATING_ORDER
            if RATING_ORDER.index(finding.risk_rating) > RATING_ORDER.index(entry["max_rating"]):
                entry["max_rating"] = finding.risk_rating
            for ref in finding.controls:
                if ref.relation == "violates":
                    entry["controls"].add(f"{ref.control_id}")

        rows = []
        for entry in grouped.values():
            rows.append({
                **{k: v for k, v in entry.items()
                   if k not in ("access_points", "zones", "controls")},
                "affected_access_points": len(entry["access_points"]),
                "zones": ", ".join(sorted(entry["zones"])),
                "controls_failed": ", ".join(sorted(entry["controls"])) or "-",
                "risk_total": round(entry["risk_total"], 1),
            })
        rows.sort(key=lambda r: (r["priority"], -r["risk_total"]))
        return rows
