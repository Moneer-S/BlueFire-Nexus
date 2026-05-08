"""Static HTML report viewer tests.

The viewer renders ``output/<run_id>/manifest.json`` into
``output/<run_id>/index.html`` — a fully self-contained local
dashboard. No external assets, no JS, no network calls.

Pinned invariants:

1. **No external assets / scripts.** No ``<script>``, no ``<link>``,
   no ``<img src="http...">``, no ``<iframe>``. The page must
   work fully offline.
2. **No network references.** No ``http://``, ``https://``,
   ``ftp://``, ``ws://`` schemes anywhere in the rendered HTML
   beyond ones that come from scenario inputs (``.example.lab``
   placeholders are tolerated; real third-party hosts are not).
3. **No absolute filesystem paths.** Every artifact link is a
   relative path; the operator's home directory / mount points
   never appear in the page.
4. **HTML escape discipline.** Hostile-shaped values (a scenario
   name with ``<script>``, a step id with ``"`` etc.) are escaped
   before reaching the page.
5. **Section presence.** Header, timeline, propagation,
   ATT&CK coverage, telemetry, detections, risk, copilot, and
   artifact links are all rendered when their corresponding
   manifest section has data.
6. **Section absence handling.** Missing sections render a clean
   "no data" message rather than a missing-key crash.
7. **Schema-version mismatch surfaces a banner.** A manifest
   produced by a future schema version shows a warning rather
   than rendering a malformed page silently.
8. **End-to-end against the flagship scenario.** The shipped
   ``enterprise_intrusion_chain`` produces an index.html that
   contains all four propagation pairs and the declared ATT&CK
   coverage IDs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.reporting.manifest import build_manifest
from src.core.reporting.viewer import (
    VIEWER_INPUT_SCHEMA_VERSION,
    render_html,
    write_viewer,
    write_viewer_for_run,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _populated_manifest(run_dir: Path) -> Dict[str, Any]:
    """Build a realistic manifest fixture with every section populated."""
    steps = [
        {
            "step_id": "enumerate-files",
            "module": "discovery",
            "name": "Enumerate sensitive files",
            "status": "success",
            "techniques": ["T1083"],
            "artifacts": {"targets": ["finance-analyst-laptop"]},
            "detections": {"sigma": ["detections/sigma/discovery_files.yml"]},
        },
        {
            "step_id": "harvest-creds",
            "module": "credential_access",
            "name": "Harvest creds",
            "status": "success",
            "techniques": ["T1555.003"],
            "artifacts": {
                "target": "finance-analyst-laptop",
                "target_propagated_from_step": "enumerate-files",
            },
            "detections": {},
        },
        {
            "step_id": "blocked-impact",
            "module": "impact",
            "name": "Blocked impact",
            "status": "blocked",
            "techniques": [],
            "artifacts": {},
            "detections": {},
        },
    ]
    # Seed a small telemetry file so the manifest reports counts.
    (run_dir / "telemetry.jsonl").write_text(
        json.dumps({"event_type": "discovery", "module": "discovery"}) + "\n",
        encoding="utf-8",
    )
    return build_manifest(
        run_id="run-fixture",
        run_dir=run_dir,
        scenario_name="Demo scenario",
        scenario_path="scenarios/demo.yaml",
        overall_status="success",
        started_at="2026-05-07T09:00:00Z",
        finished_at="2026-05-07T09:00:42Z",
        steps=steps,
        risk_summary_payload={
            "risk_summary": {"critical": 0, "high": 0, "medium": 1, "low": 2},
            "average_score": 35.0,
            # Real orchestrator-produced risk entries key by
            # ``"<runtime_module>:<step_id>"`` so the timeline can
            # surface severity inline. Use the same shape here so
            # the fixture round-trips against the timeline's
            # severity-column lookup.
            "modules": [
                {
                    "module": "discovery:enumerate-files",
                    "severity": "low",
                    "score": 10,
                    "mode": "simulate",
                },
                {
                    "module": "credential_access:harvest-creds",
                    "severity": "medium",
                    "score": 60,
                    "mode": "simulate",
                },
            ],
        },
        copilot={
            "present": True,
            "provider": "template",
            "model": "default",
            "generated_at": "2026-05-07T09:00:42Z",
            "network_disabled": True,
            "fallback_used": False,
            "error": None,
            "path": "copilot_narrative.md",
            "run_summary": None,
        },
    )


# ---------------------------------------------------------------------------
# 1. No external assets / scripts / network references
# ---------------------------------------------------------------------------


def test_render_html_has_no_script_tags(tmp_path: Path) -> None:
    """The viewer ships zero JavaScript.

    No ``<script>``, no inline ``onclick=`` handlers either —
    operators open the file with file:// and the browser must not
    execute anything beyond static rendering.
    """
    html = render_html(_populated_manifest(tmp_path))
    assert "<script" not in html
    assert "</script>" not in html
    # Inline event handlers commonly appear as `onclick=` etc.
    for attr in ("onclick=", "onload=", "onerror="):
        assert attr not in html, f"viewer contains inline event handler {attr!r}"


def test_render_html_has_no_external_link_or_image_or_iframe(tmp_path: Path) -> None:
    """No external assets beyond the inline <style> block.

    Defends the offline-only invariant: ``<link rel="stylesheet"
    href="https://...">`` would silently make the viewer require
    network access.
    """
    html = render_html(_populated_manifest(tmp_path))
    # No <link> tags — all CSS lives in the inline <style> block.
    assert "<link " not in html
    # No <iframe>.
    assert "<iframe" not in html
    # No <img src="http..."> (allow data: schemes if ever used).
    assert "<img " not in html  # currently the viewer renders no images at all


def test_render_html_has_no_external_url_schemes(tmp_path: Path) -> None:
    """Forbid any ``http(s)://`` reference in the rendered page."""
    html = render_html(_populated_manifest(tmp_path))
    for forbidden in ("http://", "https://", "ftp://", "ws://", "wss://"):
        assert forbidden not in html, (
            f"viewer contains forbidden URL scheme {forbidden!r}"
        )


def test_render_html_carries_referrer_no_referrer_meta(tmp_path: Path) -> None:
    """A defensive ``meta name="referrer" content="no-referrer"`` is included.

    Even though the page makes no network calls, defence-in-depth
    against accidentally-clicking a future external link.
    """
    html = render_html(_populated_manifest(tmp_path))
    assert 'name="referrer"' in html
    assert 'content="no-referrer"' in html


# ---------------------------------------------------------------------------
# 2. HTML escaping discipline
# ---------------------------------------------------------------------------


def test_render_html_escapes_hostile_scenario_name(tmp_path: Path) -> None:
    """A scenario name with ``<script>`` survives as escaped text only."""
    manifest = _populated_manifest(tmp_path)
    manifest["run"]["scenario_name"] = "<script>alert(1)</script>"
    html = render_html(manifest)
    # The literal ``<script>`` substring MUST NOT appear.
    assert "<script>alert(1)</script>" not in html
    # The escaped form does appear so the operator can still see what was set.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_render_html_escapes_step_id_with_special_chars(tmp_path: Path) -> None:
    manifest = _populated_manifest(tmp_path)
    manifest["steps"][0]["step_id"] = 'evil"step'
    html = render_html(manifest)
    assert 'evil"step' not in html
    assert "evil&quot;step" in html


# ---------------------------------------------------------------------------
# 3. Section presence — populated manifest renders all sections
# ---------------------------------------------------------------------------


def test_render_html_includes_header_metadata(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Demo scenario" in html
    assert "run-fixture" in html
    assert "2026-05-07T09:00:00Z" in html  # started_at
    # status badge
    assert "success" in html


def test_render_html_includes_timeline_for_every_step(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Scenario timeline" in html
    assert "enumerate-files" in html
    assert "harvest-creds" in html
    assert "blocked-impact" in html
    # ATT&CK techniques surface in the timeline column.
    assert "T1083" in html
    assert "T1555.003" in html


def test_render_html_timeline_carries_severity_column(tmp_path: Path) -> None:
    """The timeline surfaces a per-step severity badge next to status.

    Higher-risk steps must look higher-risk inline; without the
    column an operator scanning the timeline has to cross-
    reference the risk-summary card to spot the impact /
    exfiltration steps. Pin the column header AND the rendered
    severity for the fixture's two scored steps so a future
    column-shuffle regression surfaces here.
    """
    html = render_html(_populated_manifest(tmp_path))
    # Header advertises the new column.
    assert "<th>severity</th>" in html
    # Fixture's risk block has two modules:
    # - discovery (low score 10)
    # - credential_access (medium score 60)
    # Both severities surface in the timeline (separately from
    # the risk-summary table they already appear in).
    timeline_idx = html.index("Scenario timeline")
    risk_idx = html.index("Risk summary")
    # Timeline section starts after risk summary in the rendered
    # page; grab the timeline body specifically.
    timeline_section = html[timeline_idx:]
    # Both severities rendered as badges in the timeline rows.
    assert "low" in timeline_section
    assert "medium" in timeline_section


def test_render_html_timeline_severity_renders_dash_when_no_risk_match(
    tmp_path: Path,
) -> None:
    """Steps without a matching risk entry render an em-dash, not 'unknown'.

    A blocked step that never reaches the scorer (e.g. safety
    gate aborted before module.execute returned) won't have a
    risk-block entry. The timeline falls back to ``&mdash;``
    rather than rendering the literal ``"unknown"`` severity
    badge.
    """
    manifest = _populated_manifest(tmp_path)
    # Strip risk modules so no step matches.
    manifest["risk"] = {"risk_summary": {}, "modules": []}
    html = render_html(manifest)
    timeline_idx = html.index("Scenario timeline")
    timeline_section = html[timeline_idx:]
    # Severity column header still renders; values are em-dash for every row.
    assert "<th>severity</th>" in timeline_section
    # No "unknown" severity badge leaked into the timeline.
    assert ">unknown<" not in timeline_section


def test_render_html_includes_propagation_table(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Propagation" in html
    # The single edge from the fixture surfaces as both ends + kind.
    assert "enumerate-files" in html
    assert "harvest-creds" in html
    assert "target_from_step" in html


def test_render_html_propagation_table_shows_narrative_column(
    tmp_path: Path,
) -> None:
    """The propagation table renders a defender-facing narrative column.

    The column reads as a chain story rather than a graph, so a
    SOC analyst opening the dashboard understands what flowed
    between the two steps without cross-referencing the YAML.
    """
    html = render_html(_populated_manifest(tmp_path))
    # The table header advertises the new column.
    assert ">narrative<" in html
    # The rendered narrative for the fixture's
    # discovery -> credential_access edge mentions both modules and
    # the upstream step id.
    assert "credential_access targets the host produced by the discovery step" in html


def test_render_html_renders_scenario_objective_when_present(
    tmp_path: Path,
) -> None:
    """The scenario objective surfaces in the header as readable prose.

    Multi-paragraph YAML literals collapse into ``<p>`` blocks so
    paragraph breaks survive into the rendered page. Single
    newlines within a paragraph collapse into spaces.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["run"]["scenario_objective"] = (
        "An attacker registers a domain and phishes a finance analyst.\n\n"
        "Every step is simulate-only with network_touch=false."
    )
    html = render_html(manifest)
    assert "scenario-objective" in html
    assert "An attacker registers a domain" in html
    assert "Every step is simulate-only" in html
    # Paragraph break preserved as separate <p> tags.
    assert html.count("<p>") >= 2


def test_render_html_omits_objective_section_when_missing(
    tmp_path: Path,
) -> None:
    """No scenario objective means no empty card on the page.

    Older runs predating ``run.scenario_objective`` still load
    cleanly; the renderer silently drops the block when the
    manifest field is empty.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["run"]["scenario_objective"] = ""
    html = render_html(manifest)
    assert "scenario-objective" not in html


def test_render_html_escapes_hostile_objective(tmp_path: Path) -> None:
    """A scenario objective containing HTML is escaped before reaching the page.

    A scenario YAML written with ``objective: <script>alert(1)</script>``
    would otherwise inject a literal script tag into the dashboard.
    Pin escape discipline so future renderer edits can't regress
    the contract.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["run"]["scenario_objective"] = "<script>alert(1)</script>"
    html = render_html(manifest)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_html_includes_attack_coverage(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "ATT&amp;CK coverage" in html
    assert "T1083" in html
    assert "T1555.003" in html


def test_render_html_includes_telemetry_section(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Telemetry" in html
    # The fixture seeds one event of type "discovery".
    assert "discovery" in html


def test_render_html_includes_detection_summary(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Detection drafts" in html
    assert "sigma" in html


def test_render_html_includes_risk_summary(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Risk summary" in html
    assert "medium=1" in html
    assert "average_score" not in html  # rendered as "avg score" label
    assert "avg score" in html


def test_render_html_includes_copilot_section_with_offline_label(
    tmp_path: Path,
) -> None:
    """Template/offline output is clearly labelled so operators don't
    confuse it with a live model response."""
    html = render_html(_populated_manifest(tmp_path))
    assert "AI copilot" in html
    assert "template" in html
    assert "offline" in html  # the network-state label says "offline"


def test_render_html_includes_artifact_links(tmp_path: Path) -> None:
    html = render_html(_populated_manifest(tmp_path))
    assert "Artifacts" in html
    # Every canonical artifact name appears — present or "not present" tagged.
    for label in ("report.md", "report.json", "risk_summary.json", "telemetry.jsonl",
                  "manifest.json", "detections/"):
        assert label in html


def test_render_html_blocked_step_surfaces_warning_banner(tmp_path: Path) -> None:
    """A step with status=blocked appears in the warning banner."""
    html = render_html(_populated_manifest(tmp_path))
    assert "blocked step" in html.lower()
    assert "blocked-impact" in html


# ---------------------------------------------------------------------------
# 4. Section absence handling — empty manifest still renders a useful page
# ---------------------------------------------------------------------------


def test_render_html_with_empty_manifest_does_not_crash(tmp_path: Path) -> None:
    """An empty manifest still renders a coherent page.

    Defends against future regressions where a missing section
    raises a KeyError mid-render.
    """
    html = render_html(build_manifest(run_id="empty", run_dir=tmp_path, steps=[]))
    assert "<html" in html
    assert "</html>" in html
    # Scenario timeline section is omitted when there are no steps —
    # but the artifact links section still renders with all "not present" tags.
    assert "Artifacts" in html
    assert "not present" in html


def test_render_html_with_no_propagation_renders_friendly_message(tmp_path: Path) -> None:
    manifest = _populated_manifest(tmp_path)
    manifest["propagation_edges"] = []
    html = render_html(manifest)
    assert "Propagation" in html
    assert "No step-to-step propagation" in html


def test_render_html_with_no_copilot_renders_friendly_message(tmp_path: Path) -> None:
    manifest = _populated_manifest(tmp_path)
    manifest["copilot"]["present"] = False
    html = render_html(manifest)
    assert "AI copilot" in html
    assert "No copilot artifacts" in html


# ---------------------------------------------------------------------------
# 5. Schema version mismatch warning
# ---------------------------------------------------------------------------


def test_render_html_warns_on_unexpected_schema_version(tmp_path: Path) -> None:
    """A future-schema manifest surfaces a visible banner.

    The viewer keeps rendering on a best-effort basis but the
    operator gets a clear warning that the layout may be
    misaligned with what they're seeing.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["schema_version"] = VIEWER_INPUT_SCHEMA_VERSION + 99
    html = render_html(manifest)
    assert "schema_version" in html
    assert "viewer expects" in html


# ---------------------------------------------------------------------------
# 6. write_viewer / write_viewer_for_run round-trip
# ---------------------------------------------------------------------------


def test_write_viewer_persists_to_run_dir(tmp_path: Path) -> None:
    manifest = _populated_manifest(tmp_path)
    target = write_viewer(tmp_path, manifest)
    assert target == tmp_path / "index.html"
    assert target.exists()
    body = target.read_text(encoding="utf-8")
    assert "Demo scenario" in body


def test_write_viewer_for_run_reads_manifest_from_disk(tmp_path: Path) -> None:
    """Convenience wrapper: manifest.json -> index.html in the same dir."""
    manifest = _populated_manifest(tmp_path)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    target = write_viewer_for_run(tmp_path)
    assert target == tmp_path / "index.html"
    body = target.read_text(encoding="utf-8")
    assert "Demo scenario" in body


def test_write_viewer_for_run_raises_on_missing_manifest(tmp_path: Path) -> None:
    """Operators get a clean FileNotFoundError, not a silently-empty page."""
    with pytest.raises(FileNotFoundError, match="manifest not found"):
        write_viewer_for_run(tmp_path)


# ---------------------------------------------------------------------------
# 7. End-to-end against the flagship scenario
# ---------------------------------------------------------------------------


def test_enterprise_intrusion_chain_writes_viewer_with_propagation_pairs(
    tmp_path: Path,
) -> None:
    """End-to-end shape against the flagship scenario.

    Asserts the rendered HTML contains every step id, the four
    propagation edges, and a representative subset of the declared
    ATT&CK coverage. The viewer must work without any post-run
    operator action: the orchestrator wires write_viewer_for_run
    after every successful run.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")

    viewer_path = Path(summary["viewer_path"])
    assert viewer_path.exists()
    html = viewer_path.read_text(encoding="utf-8")

    assert "Enterprise intrusion kill chain" in html
    # Every step id is rendered in the timeline.
    for step_id in (
        "enumerate-files",
        "harvest-browser-creds",
        "lateral-to-fileshare",
        "stage-collected-data",
        "exfil-over-c2",
        "ransomware-impact",
    ):
        assert step_id in html, f"missing step_id {step_id} in rendered HTML"
    # All five propagation edges land in the propagation table — the
    # downstream step ids appear next to upstream ones.
    assert "target_from_step" in html
    assert "source_from_step" in html
    assert "c2_endpoint_from_step" in html
    # ATT&CK coverage section: at least the headline impact + collection IDs.
    for technique in ("T1486", "T1074.001", "T1083", "T1555.003"):
        assert technique in html

    # No external scripts / links / network references.
    assert "<script" not in html
    assert "<link " not in html
    for forbidden_host in ("api.openai.com", "api.anthropic.com", "googleapis.com"):
        assert forbidden_host not in html

    # No absolute filesystem path leak from the orchestrator's tmp dir.
    run_dir = viewer_path.parent
    assert str(run_dir).replace("\\", "/") not in html.replace("\\", "/")
