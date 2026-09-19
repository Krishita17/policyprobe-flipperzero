"""The repository names exactly one contributor.

This is enforced rather than trusted: attribution to a tool most often reappears through
a generated artefact or a commit trailer, so the check runs over the whole tree.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AUTHOR = "Krishita Sanjay Choksi"

# Names of code-generation tools. Kept in one place so no other file in the repository has
# to spell them out, which would trip the scan below on the scan's own test data.
TOOL_MARKERS = ["Anthropic", "OpenAI", "Copilot", "ChatGPT"]

# Attribution trailers, split so that referencing them here does not itself trip the scan.
TRAILER_MARKERS = ["Co-Authored" + "-By", "Generated " + "with"]

FORBIDDEN = TOOL_MARKERS + TRAILER_MARKERS

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules", ".ruff_cache"}
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".cff", ".toml", ".txt", ".json", ".html"}


def _tracked_text_files():
    for path in REPO.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            yield path


def test_attribution_files_name_only_the_author():
    for name in ("AUTHORS", "LICENSE"):
        assert AUTHOR in (REPO / name).read_text(encoding="utf-8"), name
    # CITATION.cff stores given and family names separately, as the format requires.
    citation = (REPO / "CITATION.cff").read_text(encoding="utf-8")
    assert "Krishita Sanjay" in citation and "Choksi" in citation


@pytest.mark.parametrize("marker", FORBIDDEN)
def test_no_tool_attribution_anywhere(marker):
    offenders = [
        p.relative_to(REPO) for p in _tracked_text_files()
        if p.name != "test_authorship.py" and marker.lower() in
        p.read_text(encoding="utf-8", errors="ignore").lower()
    ]
    assert not offenders, f"{marker!r} appears in: {offenders}"


def test_citation_file_lists_one_author():
    import yaml
    citation = yaml.safe_load((REPO / "CITATION.cff").read_text(encoding="utf-8"))
    assert len(citation["authors"]) == 1
    author = citation["authors"][0]
    assert author["given-names"] == "Krishita Sanjay"
    assert author["family-names"] == "Choksi"
