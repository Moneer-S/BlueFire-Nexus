"""Manifest chain-context summary surface.

The chain context (PR #150) indexes typed artifacts and consumer
warnings in memory during a scenario run. The orchestrator now
threads its snapshot into the manifest builder so the static
viewer / report layer can pivot on chain warnings to flag consumer
steps that ran without an upstream emission for a required slot.

These tests pin:

- ``build_manifest`` accepts the new ``chain=`` kwarg without
  breaking existing callers (default is empty-but-shaped so
  consumers always read the same keys).
- The summarised shape stays compact (counts + warnings list, NOT
  the full by-step / by-type artifact rows).
- An end-to-end run via ``run_scenario_file`` writes the chain
  summary to disk.
- A scenario that triggers a consumer warning records it in the
  manifest's ``chain.warnings`` list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.reporting.manifest import build_manifest, _summarise_chain_snapshot


def _make_isolated_nexus(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return BlueFireNexus(str(cfg_path))


# ---------------------------------------------------------------------------
# _summarise_chain_snapshot
# ---------------------------------------------------------------------------


def test_summarise_chain_snapshot_returns_empty_shape_for_none() -> None:
    """A None / missing snapshot must still produce the documented
    keys with empty defaults so consumers never have to defensively
    check for absent keys."""

    summary = _summarise_chain_snapshot(None)
    assert summary == {
        "produced_types": [],
        "type_counts": {},
        "step_counts": {},
        "warnings": [],
        "warning_count": 0,
    }


def test_summarise_chain_snapshot_counts_artifacts_by_type_and_step() -> None:
    snapshot = {
        "artifacts_by_type": {
            "host": [{"value": "10.0.0.1"}, {"value": "10.0.0.2"}],
            "credential": [{"value": "lsass"}],
        },
        "artifacts_by_step": {
            "disc-1": [{"type": "host"}, {"type": "host"}],
            "cred-1": [{"type": "credential"}],
        },
        "warnings": [],
    }
    summary = _summarise_chain_snapshot(snapshot)
    assert summary["type_counts"] == {"host": 2, "credential": 1}
    assert summary["step_counts"] == {"disc-1": 2, "cred-1": 1}
    assert summary["produced_types"] == ["credential", "host"]
    assert summary["warning_count"] == 0


def test_summarise_chain_snapshot_carries_warnings_verbatim() -> None:
    snapshot = {
        "artifacts_by_type": {},
        "artifacts_by_step": {},
        "warnings": [
            {
                "step_id": "exfil-1",
                "module": "exfiltration",
                "missing_type": "host",
                "missing_key": "target",
            },
        ],
    }
    summary = _summarise_chain_snapshot(snapshot)
    assert summary["warning_count"] == 1
    assert summary["warnings"][0]["module"] == "exfiltration"
    assert summary["warnings"][0]["missing_type"] == "host"


def test_summarise_chain_snapshot_keeps_artifact_rows_out() -> None:
    """The summary must NOT inline the full by-type / by-step rows -
    just counts. A scenario emitting hundreds of typed artifacts
    would otherwise inflate the manifest beyond comfortable size."""

    snapshot = {
        "artifacts_by_type": {
            "host": [{"value": f"10.0.0.{i}", "step_id": "x"} for i in range(50)],
        },
        "artifacts_by_step": {
            "disc-1": [{"type": "host", "value": "x"} for _ in range(50)],
        },
        "warnings": [],
    }
    summary = _summarise_chain_snapshot(snapshot)
    # Only counts + types + warnings - no nested artifact rows.
    assert set(summary.keys()) == {
        "produced_types",
        "type_counts",
        "step_counts",
        "warnings",
        "warning_count",
    }
    assert summary["type_counts"]["host"] == 50


# ---------------------------------------------------------------------------
# build_manifest accepts chain= kwarg
# ---------------------------------------------------------------------------


def test_build_manifest_accepts_chain_kwarg(tmp_path: Path) -> None:
    """The chain kwarg should be optional; existing callers stay
    untouched, and a None chain produces the empty-shaped summary."""

    manifest = build_manifest(
        run_id="rid-test",
        run_dir=tmp_path,
        chain=None,
    )
    assert "chain" in manifest
    assert manifest["chain"]["produced_types"] == []


def test_build_manifest_embeds_chain_snapshot(tmp_path: Path) -> None:
    snapshot = {
        "artifacts_by_type": {"host": [{"value": "10.0.0.5"}]},
        "artifacts_by_step": {"disc-1": [{"type": "host"}]},
        "warnings": [
            {"step_id": "x", "module": "y", "missing_type": "z", "missing_key": "z"},
        ],
    }
    manifest = build_manifest(
        run_id="rid-test",
        run_dir=tmp_path,
        chain=snapshot,
    )
    chain = manifest["chain"]
    assert chain["produced_types"] == ["host"]
    assert chain["type_counts"] == {"host": 1}
    assert chain["warning_count"] == 1


# ---------------------------------------------------------------------------
# End-to-end: run_scenario_file writes chain summary to disk
# ---------------------------------------------------------------------------


def test_run_scenario_file_writes_chain_summary_to_manifest(
    tmp_path: Path,
) -> None:
    """A scenario run must persist the chain summary under
    ``manifest.chain``. The typed propagation graph the runtime built
    in memory should be defender-readable on disk."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "chain.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: chain-summary-test",
                "name: Chain summary scenario",
                "objective: validate chain summary in manifest",
                "attack_coverage: ['T1018', 'T1003.001']",
                "fail_fast: false",
                "steps:",
                "  - id: discover-1",
                "    name: Discover hosts",
                "    module: discovery",
                "    params:",
                "      discovery_type: host_discovery",
                "      targets: ['10.0.0.5']",
                "      network_touch: false",
                "  - id: cred-1",
                "    name: Credential access",
                "    module: credential_access",
                "    params:",
                "      technique: lsass_dump",
                "      target_from_step: discover-1",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    manifest_path = tmp_path / "output" / run_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    chain = manifest.get("chain")
    assert isinstance(chain, dict), f"manifest missing chain field: {manifest.keys()}"
    # Discovery emitted host (and impact_target via discriminator);
    # credential_access emitted a credential.
    assert "host" in chain["produced_types"]
    assert "credential" in chain["produced_types"]
    assert chain["type_counts"]["host"] >= 1
    assert chain["type_counts"]["credential"] >= 1


def test_run_scenario_file_records_warning_for_missing_required_input(
    tmp_path: Path,
) -> None:
    """A scenario with a consumer that has a required input not
    upstream should record a chain warning in the manifest."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "warn.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: chain-warn-test",
                "name: Chain warning scenario",
                "objective: trigger a chain warning",
                "attack_coverage: ['T1041']",
                "fail_fast: false",
                "steps:",
                "  - id: exfil-1",
                "    name: Exfiltration without upstream host",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    manifest = json.loads(
        (tmp_path / "output" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    chain = manifest.get("chain", {})
    warnings = chain.get("warnings") or []
    # Exfiltration's required slot is host; with no upstream emission,
    # the runtime should have recorded the missing-host warning.
    assert any(
        w.get("module") == "exfiltration" and w.get("missing_type") == "host"
        for w in warnings
    ), f"expected exfiltration host-missing warning; got {warnings}"


def test_manifest_chain_field_default_shape_when_no_chain_passed(
    tmp_path: Path,
) -> None:
    """A caller that doesn't pass ``chain=`` should still get the
    empty-shape default rather than a KeyError-prone absence."""

    manifest = build_manifest(run_id="rid-test", run_dir=tmp_path)
    chain = manifest.get("chain")
    assert chain == {
        "produced_types": [],
        "type_counts": {},
        "step_counts": {},
        "warnings": [],
        "warning_count": 0,
    }


# ---------------------------------------------------------------------------
# manifest.chain.graph (static chain graph from scenario YAML)
# ---------------------------------------------------------------------------


def test_manifest_chain_graph_omitted_when_no_scenario_steps(
    tmp_path: Path,
) -> None:
    """The ``chain.graph`` block is the static analyser's view of the
    scenario YAML; runs without a scenario (``execute_operation``
    single-module flow) must NOT carry it.

    Otherwise the graph block would be an empty
    ``{nodes: [], edges: [], warnings: []}`` for every single-module
    invocation, bloating the manifest.
    """

    manifest = build_manifest(run_id="rid-no-scenario", run_dir=tmp_path)
    chain = manifest["chain"]
    assert "graph" not in chain


def test_manifest_chain_graph_omitted_when_scenario_steps_is_empty_list(
    tmp_path: Path,
) -> None:
    """Empty list passes through as no-graph too."""

    manifest = build_manifest(
        run_id="rid-empty",
        run_dir=tmp_path,
        scenario_steps=[],
    )
    assert "graph" not in manifest["chain"]


def test_manifest_chain_graph_embeds_nodes_edges_warnings(tmp_path: Path) -> None:
    """A scenario with two steps + an explicit ``target_from_step`` must
    surface a ``chain.graph`` block with the corresponding node count,
    one explicit edge, and a JSON-serialisable shape."""

    from src.core.scenario import ScenarioStep

    steps = [
        ScenarioStep(
            step_id="disc-1",
            name="Discover hosts",
            module="discovery",
            params={
                "discovery_type": "host_discovery",
                "targets": ["10.0.0.5"],
                "network_touch": False,
            },
        ),
        ScenarioStep(
            step_id="cred-1",
            name="Credential access",
            module="credential_access",
            params={
                "technique": "lsass_dump",
                "target_from_step": "disc-1",
            },
        ),
    ]
    manifest = build_manifest(
        run_id="rid-graph",
        run_dir=tmp_path,
        scenario_steps=steps,
    )
    graph = manifest["chain"].get("graph")
    assert isinstance(graph, dict), f"chain.graph missing: {manifest['chain']}"
    assert len(graph["nodes"]) == 2
    assert graph["nodes"][0]["step_id"] == "disc-1"
    assert graph["nodes"][1]["step_id"] == "cred-1"
    # One explicit edge: disc-1 → cred-1 via host (target_from_step).
    explicit_edges = [e for e in graph["edges"] if e["explicit"]]
    assert len(explicit_edges) == 1
    edge = explicit_edges[0]
    assert edge["source_step_id"] == "disc-1"
    assert edge["target_step_id"] == "cred-1"
    assert edge["artifact_type"] == "host"
    assert edge["target_key"] == "target"


def test_manifest_chain_graph_payload_is_json_serialisable(tmp_path: Path) -> None:
    """The chain.graph block must be a plain dict / list shape so the
    manifest's ``json.dumps`` doesn't choke on a leftover dataclass."""

    from src.core.scenario import ScenarioStep

    steps = [
        ScenarioStep(
            step_id="stage-1",
            name="Stage domain",
            module="resource_development",
            params={"resource_type": "domain", "target": "stage.example.invalid"},
        ),
        ScenarioStep(
            step_id="c2-1",
            name="HTTPS C2",
            module="command_control",
            params={"channel": "https", "c2_endpoint_from_step": "stage-1"},
        ),
    ]
    manifest = build_manifest(
        run_id="rid-json",
        run_dir=tmp_path,
        scenario_steps=steps,
    )
    rendered = json.dumps(manifest, default=str)
    parsed = json.loads(rendered)
    assert "graph" in parsed["chain"]
    assert isinstance(parsed["chain"]["graph"]["nodes"], list)


def test_run_scenario_file_writes_chain_graph_to_manifest(tmp_path: Path) -> None:
    """End-to-end: a scenario run persists ``manifest.chain.graph``
    with the static analyser's predicted nodes / edges / warnings so
    the bundle ships predicted-vs-actual side by side."""

    nexus = _make_isolated_nexus(tmp_path)
    scenario = tmp_path / "graph.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: chain-graph-test",
                "name: Chain graph scenario",
                "objective: validate chain graph in manifest",
                "attack_coverage: ['T1018', 'T1003.001', 'T1071.001']",
                "fail_fast: false",
                "steps:",
                "  - id: stage-1",
                "    name: Stage adversary domain",
                "    module: resource_development",
                "    params:",
                "      resource_type: domain",
                "      target: stage.example.invalid",
                "      network_touch: false",
                "  - id: c2-1",
                "    name: HTTPS C2 to staged domain",
                "    module: command_control",
                "    params:",
                "      channel: https",
                "      c2_endpoint_from_step: stage-1",
                "      network_touch: false",
                "  - id: disc-1",
                "    name: Discover hosts",
                "    module: discovery",
                "    params:",
                "      discovery_type: host_discovery",
                "      targets: ['10.0.0.5']",
                "      network_touch: false",
                "  - id: exfil-1",
                "    name: Exfil over C2",
                "    module: exfiltration",
                "    params:",
                "      method: via_c2",
                "      target_from_step: disc-1",
                "      network_touch: false",
            ]
        ),
        encoding="utf-8",
    )
    result = nexus.run_scenario_file(str(scenario))
    run_id = result["run_id"]
    manifest = json.loads(
        (tmp_path / "output" / run_id / "manifest.json").read_text(encoding="utf-8")
    )
    graph = manifest["chain"].get("graph")
    assert isinstance(graph, dict), (
        f"manifest.chain.graph missing on a scenario run: {manifest['chain']}"
    )
    assert len(graph["nodes"]) == 4
    # Two explicit edges: c2_endpoint_from_step (stage-1 → c2-1) and
    # target_from_step (disc-1 → exfil-1).
    explicit_edges = [e for e in graph["edges"] if e["explicit"]]
    assert len(explicit_edges) == 2
    sources = {(e["source_step_id"], e["target_step_id"]) for e in explicit_edges}
    assert ("stage-1", "c2-1") in sources
    assert ("disc-1", "exfil-1") in sources


def test_manifest_chain_graph_is_deterministic(tmp_path: Path) -> None:
    """Same scenario_steps → same chain.graph payload, byte for byte."""

    from src.core.scenario import ScenarioStep

    steps = [
        ScenarioStep(
            step_id="disc-1",
            name="Discover",
            module="discovery",
            params={"discovery_type": "host_discovery"},
        ),
        ScenarioStep(
            step_id="cred-1",
            name="Creds",
            module="credential_access",
            params={"target_from_step": "disc-1"},
        ),
    ]
    a = build_manifest(run_id="r1", run_dir=tmp_path, scenario_steps=steps)
    b = build_manifest(run_id="r1", run_dir=tmp_path, scenario_steps=steps)
    assert a["chain"]["graph"] == b["chain"]["graph"]


def test_manifest_chain_block_keeps_runtime_summary_when_graph_added(
    tmp_path: Path,
) -> None:
    """Adding ``chain.graph`` must NOT drop the runtime summary keys
    (``produced_types`` / ``type_counts`` / ``step_counts`` /
    ``warnings`` / ``warning_count``). The two are complementary and
    consumers may pivot on either."""

    from src.core.scenario import ScenarioStep

    steps = [
        ScenarioStep(
            step_id="disc-1",
            name="Discover",
            module="discovery",
            params={"discovery_type": "host_discovery"},
        ),
    ]
    snapshot = {
        "artifacts_by_type": {"host": [{"value": "10.0.0.5"}]},
        "artifacts_by_step": {"disc-1": [{"type": "host"}]},
        "warnings": [],
    }
    manifest = build_manifest(
        run_id="r1",
        run_dir=tmp_path,
        scenario_steps=steps,
        chain=snapshot,
    )
    chain = manifest["chain"]
    assert chain["produced_types"] == ["host"]
    assert chain["type_counts"] == {"host": 1}
    assert chain["warning_count"] == 0
    assert "graph" in chain
    assert isinstance(chain["graph"]["nodes"], list)
