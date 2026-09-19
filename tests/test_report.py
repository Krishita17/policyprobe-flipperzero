"""Tests for the generated compliance report."""

import pytest

from policyprobe.bridge import get_bridge
from policyprobe.classify.model import WeaknessClassifier, build_training_set
from policyprobe.data.facility import generate_facility
from policyprobe.mapping.engine import MappingEngine
from policyprobe.normalize import normalize_facility
from policyprobe.report.generator import ReportGenerator
from policyprobe.score.risk import score_findings
from test_authorship import TOOL_MARKERS, TRAILER_MARKERS


@pytest.fixture(scope="module")
def report():
    classifier = WeaknessClassifier(seed=42, n_estimators=80).fit(
        build_training_set(list(range(100, 110)))
    )
    facility = generate_facility(seed=7, n_access_points=18)
    observations = get_bridge("mock", seed=99).probe_all(facility.access_points)
    findings = score_findings(
        normalize_facility(facility, observations, classifier), facility.access_points)
    engine = MappingEngine()
    findings = engine.map_findings(findings)
    return ReportGenerator(facility, findings, engine.posture_all(findings), engine)


def test_markdown_report_has_every_required_section(report):
    md = report.to_markdown()
    for heading in ("Executive summary", "Compliance posture by control family",
                    "Control status detail", "Gap list with evidence",
                    "Remediation roadmap", "Coverage and limitations"):
        assert heading in md


def test_report_names_only_the_author(report):
    for text in (report.to_markdown(), report.to_html()):
        assert "Krishita Sanjay Choksi" in text
        for marker in TOOL_MARKERS + TRAILER_MARKERS:
            assert marker not in text


def test_report_cites_real_control_identifiers(report):
    md = report.to_markdown()
    assert "A.7.2" in md      # ISO/IEC 27001:2022 Physical entry
    assert "PE-3" in md       # NIST SP 800-53 Rev. 5 Physical Access Control


def test_report_declares_its_coverage_gaps(report):
    md = report.to_markdown()
    assert "not assessed" in md.lower()
    assert "excluded from the posture score" in md


def test_html_report_is_self_contained(report):
    html = report.to_html()
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    assert "src=" not in html and "<script" not in html


def test_gaps_are_a_subset_of_findings(report):
    gap_ids = {f.id for f in report.gaps()}
    assert gap_ids <= {f.id for f in report.findings}
    for f in report.gaps():
        assert any(r.relation == "violates" for r in f.controls)
