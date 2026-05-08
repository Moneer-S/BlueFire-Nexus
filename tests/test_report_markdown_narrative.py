"""Markdown report narrative tests.

PR3 of the Loop F (flagship-narrative) batch surfaces the
scenario-level ``objective`` and the propagation-edge narrative
in ``report.md`` so a defender reading the markdown alone (no
dashboard) gets the same chain story PR2 added to the static
viewer.

Pinned invariants:

1. **Scenario objective renders as its own section** above the
   pack summary when provided. Multi-paragraph YAML literals
   collapse into one paragraph per blank-line break; single
   newlines within a paragraph collapse to spaces (no hard
   wraps in the rendered markdown).
2. **Empty / missing objective drops the section entirely** —
   no empty header, no whitespace card. Older callers that don't
   pass the kwarg still produce a valid report.
3. **Propagation narrative renders as a bullet list** when edges
   are present. Each line carries the prose narrative plus the
   propagation kind in backticks. The default-empty input drops
   the section entirely so single-step operator paths still
   produce a clean report.
4. **End-to-end through the orchestrator**: running the flagship
   ``enterprise_intrusion_chain`` produces a ``report.md`` whose
   "Scenario objective" + "Propagation narrative" sections both
   land before "Module Results", so defenders see the chain
   story before the per-step technical detail.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.models import ModuleResult, TelemetryEvent
from src.core.reporting.run_reports import (
    _objective_paragraphs,
    _propagation_narrative_lines,
    write_markdown_report,
)


def _result(module: str, technique: str = "T0000") -> ModuleResult:
    return ModuleResult(
        status="success",
        module=module,
        message="ok",
        techniques=[technique],
        artifacts={},
        detection_hints={},
        telemetry=[TelemetryEvent(event_type="x", module=module)],
    )


# ---------------------------------------------------------------------------
# Pure helper unit tests
# ---------------------------------------------------------------------------


def test_objective_paragraphs_handles_multiparagraph_yaml_literal() -> None:
    """A two-paragraph YAML literal produces two report paragraphs."""
    raw = (
        "An attacker registers a domain.\n"
        "They phish the analyst.\n\n"
        "Every step is simulate-only with network_touch=false."
    )
    paragraphs = _objective_paragraphs(raw)
    assert len(paragraphs) == 2
    # Single newlines within a paragraph collapse to spaces — no
    # hard wraps that markdown viewers would render as forced
    # line breaks.
    assert paragraphs[0] == "An attacker registers a domain. They phish the analyst."
    assert paragraphs[1] == "Every step is simulate-only with network_touch=false."


def test_objective_paragraphs_drops_empty_input() -> None:
    """Empty / whitespace-only input returns an empty list (no rendered section)."""
    assert _objective_paragraphs("") == []
    assert _objective_paragraphs("   \n  \n") == []


def test_objective_paragraphs_handles_windows_line_endings() -> None:
    """Author wrote the YAML on Windows; CRLF normalises to LF before splitting."""
    raw = "Para one.\r\n\r\nPara two."
    paragraphs = _objective_paragraphs(raw)
    assert paragraphs == ["Para one.", "Para two."]


def test_propagation_narrative_lines_renders_each_edge_with_kind() -> None:
    """Each edge becomes one bullet with prose + ``(`<kind>`)`` suffix."""
    edges = [
        {
            "kind": "target_from_step",
            "from_step": "enumerate-files",
            "to_step": "harvest-creds",
            "from_module": "discovery",
            "to_module": "credential_access",
            "narrative": (
                "credential_access targets the host produced by the "
                "discovery step 'enumerate-files'"
            ),
        }
    ]
    lines = _propagation_narrative_lines(edges)
    assert lines == [
        "- credential_access targets the host produced by the discovery step "
        "'enumerate-files' (`target_from_step`)"
    ]


def test_propagation_narrative_lines_falls_back_when_narrative_missing() -> None:
    """An edge without prose still renders a structural ``from -> to`` line."""
    edges = [
        {
            "kind": "target_from_step",
            "from_step": "step-a",
            "to_step": "step-b",
        }
    ]
    lines = _propagation_narrative_lines(edges)
    assert lines == ["- `step-a` -> `step-b` (`target_from_step`)"]


def test_propagation_narrative_lines_drops_empty_input() -> None:
    """Default-empty / None input returns an empty list (no rendered section)."""
    assert _propagation_narrative_lines(None) == []
    assert _propagation_narrative_lines([]) == []


# ---------------------------------------------------------------------------
# write_markdown_report direct invocations
# ---------------------------------------------------------------------------


def test_markdown_report_renders_scenario_objective_section(tmp_path: Path) -> None:
    """The objective surfaces as an ``## Scenario objective`` section."""
    report_path = write_markdown_report(
        tmp_path,
        "demo",
        {"discovery:step-1": _result("discovery")},
        {},
        scenario_objective=(
            "An attacker registers a domain and phishes a finance analyst.\n\n"
            "Every step is simulate-only."
        ),
    )
    body = report_path.read_text(encoding="utf-8")
    assert "## Scenario objective" in body
    assert "An attacker registers a domain" in body
    assert "Every step is simulate-only" in body
    # Section orders below: title then objective then pack summary.
    title_idx = body.index("# BlueFire Run Report")
    objective_idx = body.index("## Scenario objective")
    pack_idx = body.index("## Legacy Capability Pack Summary")
    assert title_idx < objective_idx < pack_idx


def test_markdown_report_omits_objective_section_when_empty(tmp_path: Path) -> None:
    """Default-empty objective drops the section entirely.

    Callers that don't opt in (single-module operator paths) keep
    producing a clean report without the new header.
    """
    report_path = write_markdown_report(
        tmp_path,
        "demo",
        {"discovery:step-1": _result("discovery")},
        {},
    )
    body = report_path.read_text(encoding="utf-8")
    assert "## Scenario objective" not in body


def test_markdown_report_renders_propagation_narrative_section(tmp_path: Path) -> None:
    """A non-empty propagation_edges list surfaces as ``## Propagation narrative``."""
    edges = [
        {
            "kind": "target_from_step",
            "from_step": "enumerate-files",
            "to_step": "harvest-creds",
            "from_module": "discovery",
            "to_module": "credential_access",
            "narrative": (
                "credential_access targets the host produced by the "
                "discovery step 'enumerate-files'"
            ),
        }
    ]
    report_path = write_markdown_report(
        tmp_path,
        "demo",
        {"discovery:step-1": _result("discovery")},
        {},
        propagation_edges=edges,
    )
    body = report_path.read_text(encoding="utf-8")
    assert "## Propagation narrative" in body
    assert "credential_access targets the host produced by the discovery step" in body
    # The propagation section sits between coverage and module results
    # so a defender reading top-down sees the story before the per-step
    # technical detail.
    cov_idx = body.find("## ATT&CK Technique Coverage")
    if cov_idx >= 0:
        assert cov_idx < body.index("## Propagation narrative")
    assert body.index("## Propagation narrative") < body.index("## Module Results")


def test_markdown_report_omits_propagation_section_when_empty(tmp_path: Path) -> None:
    """Default-None / empty propagation_edges drops the section."""
    report_path = write_markdown_report(
        tmp_path,
        "demo",
        {"discovery:step-1": _result("discovery")},
        {},
    )
    body = report_path.read_text(encoding="utf-8")
    assert "## Propagation narrative" not in body


# ---------------------------------------------------------------------------
# End-to-end through orchestrator on the flagship scenario
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _flagship_run(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    tmp_path = tmp_path_factory.mktemp("report-narrative")
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    return {"summary": summary, "run_dir": Path(summary["output_dir"])}


def test_flagship_report_md_carries_scenario_objective(
    _flagship_run: Dict[str, Any],
) -> None:
    """Running the flagship scenario produces a report.md with the objective rendered."""
    body = (_flagship_run["run_dir"] / "report.md").read_text(encoding="utf-8")
    assert "## Scenario objective" in body
    # Objective body contains the chain narrative summary.
    assert "attacker-owned domain" in body or "attacker-controlled domain" in body
    assert "ransomware" in body.lower() or "encrypts" in body.lower()


def test_flagship_report_md_carries_propagation_narrative(
    _flagship_run: Dict[str, Any],
) -> None:
    """The flagship's five edges surface as five narrative bullets in report.md."""
    body = (_flagship_run["run_dir"] / "report.md").read_text(encoding="utf-8")
    assert "## Propagation narrative" in body
    # All five flagship edges' narrative lines surface.
    expected_narratives = [
        "credential_access targets the host produced by the discovery step",
        "lateral_movement pivots from the host produced by the credential_access step",
        "exfiltration targets the host produced by the collection step",
        "impact targets the host produced by the collection step",
        "command_control beacons to the endpoint produced by the resource_development step",
    ]
    for narrative in expected_narratives:
        assert narrative in body, f"missing narrative in report.md: {narrative!r}"


def test_flagship_report_md_section_order_tells_story_first(
    _flagship_run: Dict[str, Any],
) -> None:
    """Title -> objective -> pack -> coverage -> propagation -> modules.

    The narrative-first ordering is deliberate: a defender reading
    top-to-bottom should see the chain story before the per-step
    risk and module detail. Pinning the order catches a future
    refactor that accidentally pushes the new sections below the
    technical body.
    """
    body = (_flagship_run["run_dir"] / "report.md").read_text(encoding="utf-8")
    section_order = [
        "# BlueFire Run Report",
        "## Scenario objective",
        "## Legacy Capability Pack Summary",
        "## ATT&CK Technique Coverage",
        "## Propagation narrative",
        "## Module Results",
    ]
    last_idx = -1
    for header in section_order:
        idx = body.find(header)
        assert idx >= 0, f"missing section: {header!r}"
        assert idx > last_idx, (
            f"section {header!r} out of order (idx={idx}, prev={last_idx})"
        )
        last_idx = idx
