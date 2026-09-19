"""Compliance report generator.

Produces the deliverable an assessor hands over: a physical-security posture score,
compliance status by control family, a ranked gap list where every gap carries the
evidence it rests on, and a remediation roadmap. Markdown and a self-contained HTML
version are written from the same model, so they can never drift apart.

The report states its own limits. A section on coverage names the controls PolicyProbe
could not assess, because a compliance report that quietly omits its blind spots is worse
than no report.
"""

from __future__ import annotations

import html
from datetime import date
from pathlib import Path
from typing import Any

from .. import kb
from ..mapping.engine import MappingEngine, PostureResult
from ..schema import Facility, Finding
from ..score.risk import RATING_ORDER

RATING_BADGE = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟩"}
STATUS_LABEL = {
    "not_met": "Not met",
    "partially_met": "Partially met",
    "met": "Met",
    "not_assessed": "Not assessed",
}


class ReportGenerator:
    """Builds the compliance report from a scored, mapped finding set."""

    def __init__(self, facility: Facility, findings: list[Finding],
                 postures: dict[str, PostureResult], engine: MappingEngine,
                 assessment_date: str | None = None, backend: str = "mock"):
        self.facility = facility
        self.findings = findings
        self.postures = postures
        self.engine = engine
        self.date = assessment_date or date.today().isoformat()
        self.backend = backend

    # ------------------------------------------------------------------- summaries --
    def risk_breakdown(self) -> dict[str, int]:
        counts = {r: 0 for r in RATING_ORDER}
        for f in self.findings:
            counts[f.risk_rating] = counts.get(f.risk_rating, 0) + 1
        return counts

    def gaps(self) -> list[Finding]:
        """Findings that fail at least one control, worst risk first."""
        failing = [f for f in self.findings
                   if any(r.relation == "violates" for r in f.controls)]
        return sorted(failing, key=lambda f: (-RATING_ORDER.index(f.risk_rating),
                                              -f.risk_score))

    def headline(self) -> dict[str, Any]:
        postures = {fw: p.overall_posture for fw, p in self.postures.items()}
        estate = {fw: p.overall_estate_posture for fw, p in self.postures.items()}
        not_met = {
            fw: sum(1 for s in p.control_statuses if s.status == "not_met")
            for fw, p in self.postures.items()
        }
        return {
            "facility": self.facility.name,
            "sector": self.facility.sector,
            "access_points": len(self.facility.access_points),
            "findings": len(self.findings),
            "gaps": len(self.gaps()),
            "posture": postures,
            "estate_posture": estate,
            "controls_not_met": not_met,
            "risk": self.risk_breakdown(),
        }

    # -------------------------------------------------------------------- markdown --
    def to_markdown(self) -> str:
        h = self.headline()
        out: list[str] = []
        a = out.append

        a(f"# Physical-Security Compliance Assessment — {self.facility.name}")
        a("")
        a(f"**Assessment date:** {self.date}  ")
        a(f"**Sector:** {self.facility.sector}  ")
        a(f"**Access points assessed:** {h['access_points']}  ")
        a(f"**Acquisition backend:** `{self.backend}`  ")
        a(f"**Assessor:** Krishita Sanjay Choksi  ")
        a("**Tool:** PolicyProbe v0.1.0")
        a("")
        a("> This assessment covers the *technology layer* of physical access control: the")
        a("> credentials presented at each access point and the way each reader handles them.")
        a("> It does not cover construction, guarding, CCTV coverage or procedure, and it is")
        a("> not a substitute for a full physical-security assessment. Controls outside its")
        a("> reach are listed as *not assessed* and excluded from the posture score rather")
        a("> than being scored as passing.")
        a("")

        # ---- executive summary
        a("## 1. Executive summary")
        a("")
        posture_str = ", ".join(
            f"**{self.postures[fw].framework_name} {self.postures[fw].overall_posture}%**"
            for fw in self.postures
        )
        a(f"Across {h['access_points']} access points, PolicyProbe raised **{h['findings']} "
          f"findings**, of which **{h['gaps']}** fail at least one control outright. "
          f"Strict conformity is {posture_str}.")
        a("")
        a("| Framework | Edition | Conformity | Estate score | Controls not met "
          "| Controls partially met | Coverage |")
        a("|---|---|---:|---:|---:|---:|---:|")
        for fw, p in self.postures.items():
            nm = sum(1 for s in p.control_statuses if s.status == "not_met")
            pm = sum(1 for s in p.control_statuses if s.status == "partially_met")
            a(f"| {p.framework_name} | {p.edition} | **{p.overall_posture}%** "
              f"| {p.overall_estate_posture}% | {nm} | {pm} "
              f"| {p.coverage['coverage_pct']}% |")
        a("")
        a("**Reading the two scores.** *Conformity* is the answer to the audit question: a")
        a("control is met only if it holds at every access point assessed, so one unreplaced")
        a("door fails it site-wide. *Estate score* is the answer to the management question:")
        a("it reports the share of access points at which each control actually holds. A")
        a("large gap between them means remediation is genuinely under way but not finished —")
        a("which conformity alone cannot show, because it stays flat until the last door is")
        a("done.")
        a("")
        risk = self.risk_breakdown()
        a("**Findings by risk rating:** " + " · ".join(
            f"{RATING_BADGE[r]} {r} {risk[r]}" for r in reversed(RATING_ORDER)))
        a("")

        # ---- posture by family
        a("## 2. Compliance posture by control family")
        a("")
        for fw, p in self.postures.items():
            a(f"### {p.framework_name} — {p.edition}")
            a("")
            a("| Control family | Conformity | Estate score |")
            a("|---|---:|---:|")
            for family, score in p.posture_by_family.items():
                a(f"| {family} | {score}% | {p.estate_posture_by_family.get(family, 0.0)}% |")
            a("")

        # ---- control status detail
        a("## 3. Control status detail")
        a("")
        for fw, p in self.postures.items():
            a(f"### {p.framework_name}")
            a("")
            a("| Control | Title | Status | Access points failing | Estate score | Findings |")
            a("|---|---|---|---:|---:|---:|")
            for s in p.control_statuses:
                if s.status == "not_assessed":
                    continue
                a(f"| `{s.control_id}` | {s.title} | {STATUS_LABEL[s.status]} "
                  f"| {s.failing_access_points} / {s.assessed_access_points} "
                  f"| {s.estate_score * 100:.0f}% | {len(s.finding_ids)} |")
            a("")

        # ---- gap list with evidence
        a("## 4. Gap list with evidence")
        a("")
        a("Each gap below is a finding that fails at least one control. The evidence column")
        a("is what was actually observed at the access point; the controls column names the")
        a("controls that finding provides evidence against.")
        a("")
        a("| Risk | Access point | Zone | Protocol | Weakness | Evidence | Controls failed |")
        a("|---|---|---|---|---|---|---|")
        for f in self.gaps()[:40]:
            failed = ", ".join(sorted({r.control_id for r in f.controls
                                       if r.relation == "violates"}))
            evidence = f.evidence.replace("|", "/")
            a(f"| {RATING_BADGE[f.risk_rating]} {f.risk_rating} | {f.access_point_name} "
              f"| {f.zone} | `{f.protocol}` | {f.weakness_title} | {evidence} | `{failed}` |")
        if len(self.gaps()) > 40:
            a("")
            a(f"*{len(self.gaps()) - 40} further gaps are listed in "
              "`results/findings.csv`.*")
        a("")

        # ---- roadmap
        a("## 5. Remediation roadmap")
        a("")
        a("Ranked by priority band, then by the total risk sitting behind each gap.")
        a("")
        a("| Priority | Gap | Access points | Zones | Effort | Controls failed | Recommended action |")
        a("|---|---|---:|---|---|---|---|")
        for r in self.engine.remediation_roadmap(self.findings):
            a(f"| **{r['priority']}** | {r['weakness']} | {r['affected_access_points']} "
              f"| {r['zones']} | {r['effort']} | `{r['controls_failed']}` "
              f"| {r['recommendation']} |")
        a("")

        # ---- coverage and limits
        a("## 6. Coverage and limitations")
        a("")
        for fw, p in self.postures.items():
            cov = p.coverage
            a(f"**{p.framework_name}:** {cov['controls_assessed']} of "
              f"{cov['controls_in_catalogue']} catalogued controls were assessed "
              f"({cov['coverage_pct']}%). {cov['controls_not_assessed']} could not be "
              "assessed by this method and are excluded from the posture score:")
            a("")
            not_assessed = [s for s in p.control_statuses if s.status == "not_assessed"]
            for s in not_assessed:
                note = kb.controls_index(fw)[s.control_id].get("evidence_note", "")
                a(f"- `{s.control_id}` {s.title} — {note}")
            a("")
        a("Further limitations:")
        a("")
        a("- Findings rest on the credential technology observed at the time of the visit;")
        a("  an estate mid-migration can present differently a month later.")
        a("- Low-confidence classifications are reported at reduced weight and are not")
        a("  permitted to fail a control on their own. Their confidence is recorded in")
        a("  `results/findings.csv`.")
        a("- Where a test could not be run on site (no legacy specimen to present, no safe")
        a("  window for a default-key attempt), the result is recorded as unknown, never as")
        a("  a pass.")
        a("")
        a("---")
        a("")
        a(f"Generated by PolicyProbe v0.1.0 · Krishita Sanjay Choksi · {self.date}")
        return "\n".join(out)

    # ------------------------------------------------------------------------ html --
    def to_html(self) -> str:
        """Self-contained HTML version of the report (print to PDF from a browser)."""
        h = self.headline()
        rows = []
        for fw, p in self.postures.items():
            nm = sum(1 for s in p.control_statuses if s.status == "not_met")
            pm = sum(1 for s in p.control_statuses if s.status == "partially_met")
            rows.append(
                f"<tr><td>{html.escape(p.framework_name)}</td>"
                f"<td>{html.escape(p.edition)}</td>"
                f"<td class='num'><strong>{p.overall_posture}%</strong></td>"
                f"<td class='num'>{p.overall_estate_posture}%</td>"
                f"<td class='num'>{nm}</td><td class='num'>{pm}</td>"
                f"<td class='num'>{p.coverage['coverage_pct']}%</td></tr>"
            )

        family_blocks = []
        for fw, p in self.postures.items():
            bars = "".join(
                f"<div class='bar-row'><span class='bar-label'>{html.escape(fam)}</span>"
                f"<span class='bar'><span class='fill' style='width:{score}%'></span>"
                f"<span class='fill est' style='width:"
                f"{p.estate_posture_by_family.get(fam, 0.0)}%'></span></span>"
                f"<span class='bar-val'>{score}% / "
                f"{p.estate_posture_by_family.get(fam, 0.0)}%</span></div>"
                for fam, score in p.posture_by_family.items()
            )
            family_blocks.append(
                f"<h3>{html.escape(p.framework_name)}</h3><div class='bars'>{bars}</div>")

        gap_rows = "".join(
            "<tr>"
            f"<td><span class='pill {f.risk_rating.lower()}'>{f.risk_rating}</span></td>"
            f"<td>{html.escape(f.access_point_name)}</td>"
            f"<td>{html.escape(f.zone)}</td><td><code>{html.escape(f.protocol)}</code></td>"
            f"<td>{html.escape(f.weakness_title)}</td>"
            f"<td class='ev'>{html.escape(f.evidence)}</td>"
            f"<td><code>{html.escape(', '.join(sorted({r.control_id for r in f.controls if r.relation == 'violates'})))}</code></td>"
            "</tr>"
            for f in self.gaps()[:40]
        )

        road_rows = "".join(
            f"<tr><td><strong>{html.escape(r['priority'])}</strong></td>"
            f"<td>{html.escape(r['weakness'])}</td>"
            f"<td class='num'>{r['affected_access_points']}</td>"
            f"<td>{html.escape(r['effort'])}</td>"
            f"<td><code>{html.escape(r['controls_failed'])}</code></td>"
            f"<td>{html.escape(r['recommendation'])}</td></tr>"
            for r in self.engine.remediation_roadmap(self.findings)
        )

        risk = self.risk_breakdown()
        risk_chips = "".join(
            f"<span class='pill {r.lower()}'>{r}: {risk[r]}</span> "
            for r in reversed(RATING_ORDER)
        )

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Physical-Security Compliance Assessment — {html.escape(self.facility.name)}</title>
<style>
:root {{ --fg:#1a1c1f; --mut:#5c6370; --line:#e3e6ea; --acc:#1f4e79; --bg:#fff; }}
* {{ box-sizing:border-box; }}
body {{ font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--fg); background:var(--bg); margin:0; padding:40px 28px 64px; max-width:1100px;
  margin-inline:auto; }}
h1 {{ font-size:26px; margin:0 0 6px; }}
h2 {{ font-size:19px; margin:38px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--acc); }}
h3 {{ font-size:15px; margin:22px 0 8px; color:var(--acc); }}
.meta {{ color:var(--mut); font-size:13px; margin-bottom:18px; }}
.note {{ background:#f6f8fa; border-left:3px solid var(--acc); padding:12px 16px; font-size:13px;
  color:var(--mut); margin:16px 0 24px; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; margin:10px 0 18px; }}
th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ background:#f6f8fa; font-weight:600; font-size:12px; text-transform:uppercase;
  letter-spacing:.03em; color:var(--mut); }}
td.num, th.num {{ text-align:right; }}
td.ev {{ color:var(--mut); max-width:340px; }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;
  background:#f2f4f7; padding:1px 4px; border-radius:3px; }}
.pill {{ display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px;
  font-weight:600; white-space:nowrap; }}
.pill.critical {{ background:#fbe3e3; color:#8b1a1a; }}
.pill.high {{ background:#fdeade; color:#8a4212; }}
.pill.medium {{ background:#fdf5d8; color:#7a5c07; }}
.pill.low {{ background:#e4f4e6; color:#1d5f2a; }}
.bars {{ margin:8px 0 16px; }}
.bar-row {{ display:flex; align-items:center; gap:10px; margin:5px 0; font-size:13px; }}
.bar-label {{ width:270px; color:var(--mut); }}
.bar {{ flex:1; height:16px; background:#eef1f4; border-radius:4px; overflow:hidden;
  display:flex; flex-direction:column; gap:2px; padding:1px 0; }}
.fill {{ display:block; height:6px; background:var(--acc); border-radius:3px; }}
.fill.est {{ background:#7a9cc0; }}
.bar-val {{ width:86px; text-align:right; font-variant-numeric:tabular-nums; font-size:12px; }}
footer {{ margin-top:44px; padding-top:14px; border-top:1px solid var(--line);
  color:var(--mut); font-size:12px; }}
@media print {{ body {{ padding:0; }} h2 {{ page-break-after:avoid; }} tr {{ page-break-inside:avoid; }} }}
</style></head><body>
<h1>Physical-Security Compliance Assessment</h1>
<div class="meta">{html.escape(self.facility.name)} · {html.escape(self.facility.sector)} ·
assessed {html.escape(self.date)} · backend <code>{html.escape(self.backend)}</code> ·
assessor Krishita Sanjay Choksi · PolicyProbe v0.1.0</div>

<div class="note">This assessment covers the technology layer of physical access control —
the credentials presented at each access point and how each reader handles them. It does not
cover construction, guarding, CCTV coverage or procedure. Controls beyond its reach are listed
as not assessed and excluded from the posture score rather than scored as passing.</div>

<h2>1. Executive summary</h2>
<p>Across <strong>{h['access_points']}</strong> access points, PolicyProbe raised
<strong>{h['findings']}</strong> findings, of which <strong>{h['gaps']}</strong> fail at least
one control outright.</p>
<p>{risk_chips}</p>
<table><thead><tr><th>Framework</th><th>Edition</th><th class="num">Conformity</th><th class="num">Estate</th>
<th class="num">Not met</th><th class="num">Partially met</th><th class="num">Coverage</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table>

<h2>2. Compliance posture by control family</h2>
<p style="font-size:13px;color:var(--mut)">Each row shows two bars: the upper (dark) bar is
strict conformity — the control is met only where it holds at every access point. The lower
(light) bar is the estate score, the share of access points at which it actually holds. The
gap between them is remediation in progress.</p>
{''.join(family_blocks)}

<h2>3. Gap list with evidence</h2>
<table><thead><tr><th>Risk</th><th>Access point</th><th>Zone</th><th>Protocol</th>
<th>Weakness</th><th>Evidence</th><th>Controls failed</th></tr></thead>
<tbody>{gap_rows}</tbody></table>

<h2>4. Remediation roadmap</h2>
<table><thead><tr><th>Priority</th><th>Gap</th><th class="num">Access points</th>
<th>Effort</th><th>Controls failed</th><th>Recommended action</th></tr></thead>
<tbody>{road_rows}</tbody></table>

<footer>Generated by PolicyProbe v0.1.0 · Krishita Sanjay Choksi · {html.escape(self.date)}
· Control identifiers from ISO/IEC 27001:2022 Annex A and NIST SP 800-53 Rev. 5;
requirement text is paraphrased, not reproduced.</footer>
</body></html>"""

    # ------------------------------------------------------------------- filesystem --
    def write(self, out_dir: Path, stem: str = "sample_compliance_report") -> dict[str, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / f"{stem}.md"
        html_path = out_dir / f"{stem}.html"
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        html_path.write_text(self.to_html(), encoding="utf-8")
        return {"markdown": md_path, "html": html_path}
