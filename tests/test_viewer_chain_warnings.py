"""Run viewer surfaces ``manifest.chain.warnings`` for defenders.

PR #150 introduced the typed chain context that records consumer
warnings (a step's required slot has no upstream emission). PR #157
persisted the warnings list to ``manifest.chain.warnings``. This
test file pins the run viewer's behaviour:

- A scenario with chain warnings renders a "Chain warnings" section
  with one row per warning (step_id / module / missing_type /
  missing_key).
- A clean run (no warnings) suppresses the section entirely - it
  doesn't render an empty placeholder competing with the
  propagation graph for attention.
- Manifests without a chain block (legacy / external) suppress the
  section without raising.
- HTML escaping covers every interpolated warning field.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.reporting.viewer import _render_chain_warnings


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


# ---------------------------------------------------------------------------
# _render_chain_warnings unit tests
# ---------------------------------------------------------------------------


def test_render_chain_warnings_returns_empty_when_chain_absent() -> None:
    """Manifests without a chain block suppress the section entirely."""

    assert _render_chain_warnings({}) == ""
    assert _render_chain_warnings({"chain": None}) == ""


def test_render_chain_warnings_returns_empty_when_warnings_empty() -> None:
    """A clean run (chain present but no warnings) suppresses the
    section so the propagation graph is the headline."""

    assert _render_chain_warnings({"chain": {"warnings": []}}) == ""
    assert _render_chain_warnings({"chain": {}}) == ""


def test_render_chain_warnings_renders_section_when_warnings_present() -> None:
    rendered = _render_chain_warnings(
        {
            "chain": {
                "warnings": [
                    {
                        "step_id": "exfil-1",
                        "module": "exfiltration",
                        "missing_type": "host",
                        "missing_key": "target",
                    },
                ],
            },
        },
    )
    assert "<h2>Chain warnings</h2>" in rendered
    assert "exfil-1" in rendered
    assert "exfiltration" in rendered
    assert "host" in rendered
    assert "target" in rendered


def test_render_chain_warnings_lists_every_warning() -> None:
    rendered = _render_chain_warnings(
        {
            "chain": {
                "warnings": [
                    {
                        "step_id": "exfil-1",
                        "module": "exfiltration",
                        "missing_type": "host",
                        "missing_key": "target",
                    },
                    {
                        "step_id": "creds-1",
                        "module": "credential_access",
                        "missing_type": "host",
                        "missing_key": "target",
                    },
                ],
            },
        },
    )
    assert "exfil-1" in rendered
    assert "creds-1" in rendered


def test_render_chain_warnings_skips_malformed_warning_rows() -> None:
    """A malformed warning entry (not a Mapping) must not crash the
    renderer; just skip it."""

    rendered = _render_chain_warnings(
        {
            "chain": {
                "warnings": [
                    "not a mapping",
                    {
                        "step_id": "exfil-1",
                        "module": "exfiltration",
                        "missing_type": "host",
                        "missing_key": "target",
                    },
                    None,
                    42,
                ],
            },
        },
    )
    assert "exfil-1" in rendered
    assert "not a mapping" not in rendered


def test_render_chain_warnings_suppresses_section_when_only_malformed_rows() -> None:
    """Codex P2 (PR #160): when ``warnings`` is non-empty but every
    entry is malformed (e.g. legacy / external manifests carrying
    a list of strings), the renderer must suppress the section
    entirely - rendering a header with an empty table below would
    imply warnings exist without showing any actionable rows. The
    fix returns "" when the post-filter body has no rows."""

    rendered = _render_chain_warnings(
        {
            "chain": {
                "warnings": [
                    "not a mapping",
                    None,
                    42,
                    ["nested", "list"],
                ],
            },
        },
    )
    assert rendered == "", (
        "expected the section to be suppressed when no valid rows "
        f"survive filtering; got: {rendered!r}"
    )


def test_render_chain_warnings_escapes_html_metacharacters() -> None:
    """A future warning row carrying HTML metacharacters in any field
    must be escaped on the way out."""

    rendered = _render_chain_warnings(
        {
            "chain": {
                "warnings": [
                    {
                        "step_id": "<script>alert(1)</script>",
                        "module": "<img onerror=alert(1) src=x>",
                        "missing_type": "<b>host</b>",
                        "missing_key": "&target",
                    },
                ],
            },
        },
    )
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<img onerror" not in rendered
    assert "&lt;img onerror=alert(1) src=x&gt;" in rendered


# ---------------------------------------------------------------------------
# End-to-end: run_scenario_file -> viewer renders warnings
# ---------------------------------------------------------------------------


def test_run_scenario_file_viewer_renders_chain_warnings(tmp_path: Path) -> None:
    """A scenario with a missing-required-input consumer should
    surface the warning in the rendered run viewer's
    ``Chain warnings`` section."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "warn.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: warn-test",
                "name: Chain warning scenario",
                "objective: trigger a chain warning",
                "attack_coverage: ['T1041']",
                "fail_fast: false",
                "steps:",
                "  - id: exfil-1",
                "    name: Exfil without upstream host",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    viewer = (tmp_path / "output" / run_id / "index.html").read_text(
        encoding="utf-8"
    )
    assert "<h2>Chain warnings</h2>" in viewer
    assert "exfil-1" in viewer
    assert "exfiltration" in viewer


def test_run_scenario_file_viewer_suppresses_section_on_clean_run(
    tmp_path: Path,
) -> None:
    """A scenario whose chain emits every required upstream input
    should NOT render a Chain warnings section - the propagation
    graph stays the headline."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "clean.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: clean-test",
                "name: Clean chain scenario",
                "objective: no chain warnings expected",
                "attack_coverage: ['T1018']",
                "fail_fast: false",
                "steps:",
                "  - id: discover-1",
                "    name: Discover hosts",
                "    module: discovery",
                "    params:",
                "      discovery_type: host_discovery",
                "      targets: ['10.0.0.5']",
                "      network_touch: false",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    viewer = (tmp_path / "output" / run_id / "index.html").read_text(
        encoding="utf-8"
    )
    assert "<h2>Chain warnings</h2>" not in viewer


def test_run_scenario_file_viewer_chain_warnings_section_after_propagation(
    tmp_path: Path,
) -> None:
    """The Chain warnings section should sit *after* the Propagation
    section so a defender sees what propagated before what didn't."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "ordered.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: ordered-test",
                "name: Ordered scenario",
                "objective: section ordering check",
                "attack_coverage: ['T1041']",
                "fail_fast: false",
                "steps:",
                "  - id: exfil-1",
                "    name: Exfil without upstream",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    viewer = (tmp_path / "output" / run_id / "index.html").read_text(
        encoding="utf-8"
    )
    propagation_index = viewer.find("<h2>Propagation</h2>")
    chain_index = viewer.find("<h2>Chain warnings</h2>")
    assert propagation_index != -1
    assert chain_index != -1
    assert propagation_index < chain_index, (
        f"Chain warnings ({chain_index}) should sit after Propagation "
        f"({propagation_index})"
    )
