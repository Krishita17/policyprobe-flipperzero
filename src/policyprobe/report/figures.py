"""All figures in the repository, generated from pipeline output.

Nothing here is hand-drawn, including the architecture diagram: every image in
``figures/`` is produced by this module from either the knowledge base or a pipeline run,
so ``make figures`` regenerates the whole set after any change to the data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch   # noqa: E402

from .. import kb                         # noqa: E402
from ..schema import Finding, PROTOCOLS   # noqa: E402
from ..score.risk import RATING_ORDER     # noqa: E402

plt.rcParams.update({
    "figure.dpi": 140,
    "savefig.dpi": 140,
    "savefig.bbox": "tight",
    "font.size": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "-",
})

ACCENT = "#1f4e79"
RATING_COLOURS = {"Low": "#4c9a5b", "Medium": "#d9b310", "High": "#d97b28", "Critical": "#b03030"}
PROTOCOL_LABELS = {
    "rfid_lf": "RFID 125 kHz", "nfc_hf": "NFC 13.56 MHz", "subghz": "Sub-GHz",
    "ir": "Infrared", "ibutton": "iButton / 1-Wire",
}


def _save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


# --------------------------------------------------------------------- report figures --
def _wrap(text: str, width: int = 26) -> str:
    """Wrap a control family name onto at most two lines for use as a tick label."""
    import textwrap
    lines = textwrap.wrap(text, width=width)
    if len(lines) <= 2:
        return "\n".join(lines)
    return lines[0] + "\n" + textwrap.shorten(" ".join(lines[1:]), width=width,
                                               placeholder="…")


def posture_by_family(postures: dict[str, Any], out: Path) -> Path:
    """Headline report visual: both posture scores per control family, per framework.

    Strict conformity is what an auditor certifies; the estate score shows how much of the
    site each control actually holds across. Plotting them together is the point — the gap
    between the two bars is the remediation work in progress.

    Both panels are given the same row height so neither framework's families appear
    exaggerated simply because it catalogues fewer of them.
    """
    n = len(postures)
    max_rows = max(len(p.posture_by_family) for p in postures.values())
    fig, axes = plt.subplots(
        1, n, figsize=(6.4 * n, 0.46 * max_rows + 2.2),
        gridspec_kw={"wspace": 0.62},
    )
    if n == 1:
        axes = [axes]

    for ax, (fw, p) in zip(axes, postures.items()):
        families = list(p.posture_by_family)
        strict = [p.posture_by_family[f] for f in families]
        estate = [p.estate_posture_by_family.get(f, 0.0) for f in families]
        y = list(range(len(families)))
        ax.barh([i + 0.2 for i in y], estate, 0.34, color="#7a9cc0",
                label="Estate score — share of the site where the control holds")
        ax.barh([i - 0.2 for i in y], strict, 0.34, color=ACCENT,
                label="Strict conformity — control met at every access point")
        ax.set_yticks(y)
        ax.set_yticklabels([_wrap(f) for f in families], fontsize=8)
        ax.set_ylim(max_rows - 0.45, -0.55)     # equal row height across panels
        ax.set_xlim(0, 112)
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_xlabel("Posture (%)")
        ax.set_title(f"{p.framework_name}\nconformity {p.overall_posture}%  ·  "
                     f"estate {p.overall_estate_posture}%",
                     fontweight="bold", fontsize=9.5)
        for i, (a, b) in enumerate(zip(strict, estate)):
            ax.text(a + 2, i - 0.2, f"{a:.0f}", va="center", fontsize=7.5)
            ax.text(b + 2, i + 0.2, f"{b:.0f}", va="center", fontsize=7.5)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles[::-1], labels[::-1], loc="lower center", ncol=2, frameon=False,
               fontsize=8, bbox_to_anchor=(0.5, -0.02))
    fig.suptitle("Compliance posture by control family", fontweight="bold", y=1.0)
    return _save(fig, out)


def findings_by_risk(findings: list[Finding], out: Path) -> Path:
    """Finding counts by risk rating, split by detection source."""
    sources = ["rf_probe", "inventory"]
    counts = {s: [sum(1 for f in findings if f.risk_rating == r and f.source == s)
                  for r in RATING_ORDER] for s in sources}
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    bottom = [0] * len(RATING_ORDER)
    for s, colour, label in zip(sources, [ACCENT, "#7a9cc0"],
                                ["Observed by RF probe", "Derived from inventory"]):
        ax.bar(RATING_ORDER, counts[s], bottom=bottom, color=colour, label=label, width=0.62)
        bottom = [b + c for b, c in zip(bottom, counts[s])]
    for i, total in enumerate(bottom):
        if total:
            ax.text(i, total + 0.6, str(total), ha="center", fontsize=9, fontweight="bold")
    ax.set_ylabel("Findings")
    ax.set_title("Findings by risk rating", fontweight="bold")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, out)


def weakness_prevalence_by_protocol(findings: list[Finding], out: Path) -> Path:
    """Which access technologies carry the most weaknesses, and which weaknesses."""
    weaknesses = sorted({f.weakness_id for f in findings})
    protocols = [p for p in PROTOCOLS if any(f.protocol == p for f in findings)]
    grid = [[sum(1 for f in findings if f.weakness_id == w and f.protocol == p)
             for p in protocols] for w in weaknesses]

    fig, ax = plt.subplots(figsize=(1.35 * len(protocols) + 3.6, 0.34 * len(weaknesses) + 1.9))
    im = ax.imshow(grid, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(protocols)))
    ax.set_xticklabels([PROTOCOL_LABELS[p] for p in protocols], rotation=22, ha="right")
    ax.set_yticks(range(len(weaknesses)))
    ax.set_yticklabels(weaknesses, fontsize=8)
    ax.grid(False)
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            if v:
                ax.text(j, i, str(v), ha="center", va="center", fontsize=8,
                        color="white" if v > max(max(r) for r in grid) * 0.6 else "#333")
    ax.set_title("Weakness prevalence by protocol", fontweight="bold")
    fig.colorbar(im, ax=ax, shrink=0.75, label="Access points affected")
    return _save(fig, out)


def mapping_coverage(postures: dict[str, Any], out: Path) -> Path:
    """How much of each control catalogue this method can and cannot speak to."""
    frameworks = list(postures)
    assessed = [postures[f].coverage["controls_assessed"] for f in frameworks]
    not_assessed = [postures[f].coverage["controls_not_assessed"] for f in frameworks]
    labels = [postures[f].framework_name for f in frameworks]

    fig, ax = plt.subplots(figsize=(6.0, 3.4))
    ax.barh(labels, assessed, color=ACCENT, label="Assessed by PolicyProbe", height=0.5)
    ax.barh(labels, not_assessed, left=assessed, color="#cfd6de",
            label="Outside the method's reach", height=0.5)
    for i, (a, na) in enumerate(zip(assessed, not_assessed)):
        ax.text(a / 2, i, f"{a}", va="center", ha="center", color="white", fontweight="bold")
        ax.text(a + na / 2, i, f"{na}", va="center", ha="center", color="#444")
        ax.text(a + na + 0.4, i, f"{postures[frameworks[i]].coverage['coverage_pct']}%",
                va="center", fontsize=8)
    ax.set_xlabel("Controls in the reference catalogue")
    ax.set_title("Control coverage: what this method can assess", fontweight="bold")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    return _save(fig, out)


# ----------------------------------------------------------------- evaluation figures --
def classifier_accuracy(metrics: dict[str, Any], out: Path,
                        real_metrics: dict[str, Any] | None = None) -> Path:
    """Device-type, device-family and weak-scheme detection accuracy."""
    names = ["Device generation\n(exact)", "Device family\n(identification class)",
             "Weak-scheme flags\n(micro-F1)"]
    synth = [metrics["device_accuracy"], metrics["device_family_accuracy"],
             metrics["weakness_micro_f1"]]

    fig, ax = plt.subplots(figsize=(6.6, 3.9))
    x = range(len(names))
    width = 0.36 if real_metrics else 0.55
    offs = -width / 2 if real_metrics else 0.0
    ax.bar([i + offs for i in x], synth, width, color=ACCENT, label="Synthetic (held-out)")
    for i, v in zip(x, synth):
        ax.text(i + offs, v + 0.015, f"{v:.3f}", ha="center", fontsize=8, fontweight="bold")

    if real_metrics:
        real = [real_metrics.get("device_accuracy", 0), real_metrics.get("device_family_accuracy", 0),
                real_metrics.get("weakness_micro_f1", 0)]
        ax.bar([i + width / 2 for i in x], real, width, color="#d97b28",
               label="Real Flipper reads")
        for i, v in zip(x, real):
            ax.text(i + width / 2, v + 0.015, f"{v:.3f}", ha="center", fontsize=8)
    else:
        ax.text(0.5, 0.06,
                "No real-hardware sample present in this run.\n"
                "Run `make scan-real` with your own credentials to populate the comparison.",
                transform=ax.transAxes, ha="center", fontsize=8, color="#777",
                bbox=dict(boxstyle="round,pad=0.5", fc="#f6f8fa", ec="#dde2e8"))

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score")
    ax.set_title("Classifier accuracy", fontweight="bold")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    return _save(fig, out)


def noise_sweep(rows: list[dict[str, Any]], out: Path) -> Path:
    """Where read quality stops supporting trustworthy findings."""
    levels = [r["noise_level"] for r in rows]
    fig, ax = plt.subplots(figsize=(6.4, 3.9))
    for key, label, colour, marker in [
        ("device_family_accuracy", "Device family accuracy", ACCENT, "o"),
        ("weakness_micro_f1", "Weak-scheme micro-F1", "#4c9a5b", "s"),
        ("device_accuracy", "Device generation accuracy", "#d97b28", "^"),
    ]:
        ax.plot(levels, [r[key] for r in rows], marker=marker, color=colour, label=label, lw=1.8)
    ax.set_xlabel("Measurement-noise multiplier (1.0 = default site conditions)")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
    ax.set_title("Detection quality against read quality", fontweight="bold")
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    ax.axvline(1.0, color="#999", ls="--", lw=0.9)
    ax.text(1.02, 0.04, "default", fontsize=7, color="#777")
    return _save(fig, out)


def end_to_end_accuracy(rows: list[dict[str, Any]], out: Path) -> Path:
    """Finding-level and control-level precision/recall across evaluation facilities."""
    metrics = ["precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    x = range(len(metrics))
    width = 0.36
    for offset, level, colour in [(-width / 2, "finding", ACCENT),
                                  (width / 2, "control", "#4c9a5b")]:
        vals = [rows[level][m] for m in metrics]
        ax.bar([i + offset for i in x], vals, width, color=colour,
               label=f"{level.capitalize()} level")
        for i, v in zip(x, vals):
            ax.text(i + offset, v + 0.015, f"{v:.3f}", ha="center", fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels([m.capitalize() for m in metrics])
    ax.set_ylim(0, 1.08)
    ax.set_title("End-to-end accuracy against ground truth", fontweight="bold")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    return _save(fig, out)


def posture_ordering(rows: list[dict[str, Any]], out: Path) -> Path:
    """Sanity check: does the posture score order known-weak and known-strong estates?"""
    labels = [r["profile"] for r in rows]
    x = list(range(len(labels)))
    fig, ax = plt.subplots(figsize=(7.0, 4.0))
    series = [
        ("iso27001_estate", "ISO 27001 — estate score", ACCENT, "-", "o"),
        ("nist80053_estate", "NIST 800-53 — estate score", "#4c9a5b", "-", "s"),
        ("iso27001", "ISO 27001 — strict conformity", ACCENT, "--", "o"),
        ("nist80053", "NIST 800-53 — strict conformity", "#4c9a5b", "--", "s"),
    ]
    for key, label, colour, ls, marker in series:
        ax.plot(x, [r[key] for r in rows], marker=marker, color=colour, ls=ls,
                label=label, lw=1.8, ms=5, alpha=1.0 if ls == "-" else 0.55)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylabel("Posture score (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Posture across known-weak to known-strong estates", fontweight="bold")
    ax.legend(frameon=False, fontsize=7.5, loc="upper left")
    ax.text(0.5, 0.03,
            "Strict conformity is near-flat by design: one unreplaced door fails a control "
            "as completely as forty.\nThe estate score is what shows remediation progress.",
            transform=ax.transAxes, ha="center", fontsize=7.5, color="#777")
    return _save(fig, out)


# ------------------------------------------------------------- architecture diagram --
def architecture(out: Path) -> Path:
    """Render the system architecture as a PNG, drawn from the same structure as the
    Mermaid source in ``figures/architecture.mmd``."""
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 58)
    ax.axis("off")

    def box(x, y, w, h, text, fc="#f6f8fa", ec=ACCENT, bold=False, fs=8.5):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.45,rounding_size=1.2",
                                    fc=fc, ec=ec, lw=1.4))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
                fontweight="bold" if bold else "normal", color="#1a1c1f", linespacing=1.4)

    def arrow(x1, y1, x2, y2, style="-|>"):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                     mutation_scale=11, color="#6b7480", lw=1.2,
                                     shrinkA=2, shrinkB=2))

    box(1, 24, 15, 11, "Physical access\ntechnologies\n(owned or authorised)", fc="#eef3f8")
    box(19, 24, 15, 11, "Flipper Zero\nmulti-protocol\nfront-end", fc="#e7eef6", bold=True)
    box(19, 8, 15, 9, "Bridge\nserial CLI · mock\nbackend", fc="#f6f8fa")
    box(37, 24, 15, 11, "Finding\nnormalizer\n(common schema)", fc="#f6f8fa")
    box(37, 40, 15, 9, "Device / weakness\nclassifier (ML)", fc="#f6f8fa")
    box(37, 8, 15, 9, "Risk scorer\nseverity × exposure", fc="#f6f8fa")
    box(56, 24, 17, 11, "CONTROL\nMAPPING ENGINE", fc="#1f4e79", ec="#1f4e79", bold=True)
    ax.text(64.5, 29.5, "CONTROL\nMAPPING ENGINE", ha="center", va="center", fontsize=9.5,
            fontweight="bold", color="white", linespacing=1.4)
    box(56, 40, 17, 9, "Control framework KB\nISO 27001 · NIST 800-53", fc="#eef3f8")
    box(78, 24, 20, 11, "Compliance report\nposture · gaps · evidence\nremediation roadmap",
        fc="#e7f1e9", ec="#4c9a5b", bold=True)
    box(78, 8, 20, 9, "Figures, metrics,\ncrosswalk tables", fc="#f6f8fa", ec="#4c9a5b")

    arrow(16, 29.5, 19, 29.5); arrow(19, 29.5, 16, 29.5)   # probe the technology
    arrow(26.5, 24, 26.5, 17)                              # front-end -> bridge
    arrow(32, 15.5, 39, 24)                                # bridge -> normalizer
    arrow(44.5, 40, 44.5, 35)                              # classifier -> normalizer
    arrow(44.5, 24, 44.5, 17)                              # normalizer -> risk scorer
    arrow(50, 15.5, 58, 24)                                # risk scorer -> mapping engine
    arrow(64.5, 40, 64.5, 35)                              # framework KB -> mapping engine
    arrow(73, 31, 78, 31)                                  # engine -> report
    arrow(73, 26, 82, 17)                                  # engine -> figures and metrics

    ax.text(50, 54, "PolicyProbe — from multi-protocol physical probe to control-mapped report",
            ha="center", fontsize=12, fontweight="bold")
    ax.text(50, 51, "Krishita Sanjay Choksi", ha="center", fontsize=8.5, color="#6b7480")
    ax.text(50, 2.5, "The contribution is the mapping engine: it is what turns a finding "
                     "into control evidence.",
            ha="center", fontsize=8.5, style="italic", color="#1f4e79")
    return _save(fig, out)


MERMAID_SOURCE = """graph LR
    A["Physical access technologies<br/>(owned or authorised)"] <--> B["Flipper Zero<br/>multi-protocol front-end<br/>RFID/NFC · sub-GHz · IR · 1-Wire"]
    B <--> C["Bridge<br/>serial CLI / mock backend"]
    C --> D["Finding normalizer<br/>common finding schema"]
    E["Device &amp; weakness classifier<br/>generation ID · weak-scheme flags"] --> D
    D --> F["Risk scorer<br/>severity × exposure"]
    F --> G["CONTROL MAPPING ENGINE<br/>finding → framework control"]
    H["Control framework KB<br/>ISO/IEC 27001:2022 Annex A<br/>NIST SP 800-53 Rev. 5"] --> G
    G --> I["Compliance report<br/>posture score · gap list<br/>evidence · remediation roadmap"]
    G --> J["Figures, metrics,<br/>framework crosswalk"]

    style G fill:#1f4e79,stroke:#1f4e79,color:#ffffff
    style I fill:#e7f1e9,stroke:#4c9a5b
    style B fill:#e7eef6,stroke:#1f4e79
    style H fill:#eef3f8,stroke:#1f4e79
"""


def write_mermaid(out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(MERMAID_SOURCE, encoding="utf-8")
    return out
