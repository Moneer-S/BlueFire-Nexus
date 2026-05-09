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
