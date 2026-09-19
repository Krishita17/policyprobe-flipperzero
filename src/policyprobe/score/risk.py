"""Risk rating: weakness severity modified by exposure.

The model is deliberately simple and fully transparent, because an assessor has to be
able to defend every rating in a report::

    risk = severity_base(1-5) x zone_exposure x product(exposure modifiers)

Zone exposure and the modifier factors are data, not code: they live in
``mappings/protocol_weakness_control.yaml`` so a client with a different risk appetite
can retune the assessment without touching the pipeline.

Confidence is applied last and only downward. A finding the classifier is unsure about is
never allowed to raise a control to "not met" on its own; it is reported at a reduced
rating with its confidence visible.
"""

from __future__ import annotations

from .. import kb
from ..schema import AccessPoint, Finding, severity_score

RATING_ORDER = ["Low", "Medium", "High", "Critical"]

# Upper bounds of each band on the computed score.
BANDS = [(2.5, "Low"), (4.0, "Medium"), (6.0, "High")]


def _band(score: float) -> str:
    for upper, name in BANDS:
        if score < upper:
            return name
    return "Critical"


def applicable_modifiers(ap: AccessPoint) -> list[str]:
    """Exposure modifiers that apply to an access point, by modifier id."""
    mods: list[str] = []
    if ap.perimeter_facing:
        mods.append("perimeter_facing")
    if not ap.monitored:
        mods.append("unmonitored")
    if ap.high_traffic:
        mods.append("high_traffic")
    if ap.factors >= 2:
        mods.append("compensating_second_factor")
    if ap.escort_enforced:
        mods.append("compensating_escort")
    return mods


def score_finding(finding: Finding, ap: AccessPoint) -> Finding:
    """Compute and attach the risk score and rating for one finding."""
    base = float(severity_score(finding.base_severity))
    score = base * kb.zone_exposure(ap.zone)

    modifiers = kb.exposure_modifiers()
    applied = applicable_modifiers(ap)
    for mod_id in applied:
        score *= float(modifiers[mod_id]["factor"])

    # Low-confidence findings are reported, but not at full weight.
    if finding.source == "rf_probe" and finding.confidence < 0.75:
        score *= 0.5 + finding.confidence / 2.0

    finding.risk_score = round(score, 3)
    finding.risk_rating = _band(score)
    finding.exposure_factors = [modifiers[m]["label"] for m in applied]
    return finding


def score_findings(findings: list[Finding], access_points: list[AccessPoint]
                   ) -> list[Finding]:
    """Score every finding against its access point."""
    index = {ap.id: ap for ap in access_points}
    return [score_finding(f, index[f.access_point_id]) for f in findings
            if f.access_point_id in index]
