"""Replay ancestry must not substitute for a changed experiment or result."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from bluefire.comparison import _delta, _summarize
from bluefire.service import BlueFireService


def test_exact_simulate_replay_is_neutral_and_parameter_variant_remains_material(
    tmp_path: Path,
) -> None:
    service = BlueFireService(runs_dir=tmp_path / "runs")
    try:
        original = service.run(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "simulate",
                "autonomy": "off",
                "target_scope": {"scope_refs": ["sandbox.workspace"]},
            }
        )
        exact = service.replay(original["run_id"], {"exact": True})
        variant = service.replay(
            original["run_id"],
            {"parameter_overrides": {"create_fixture": {"record_count": 3}}},
        )
        exact_variant = service.replay(variant["run_id"], {"exact": True})
        comparison = service.compare(
            {"run_ids": [original["run_id"], exact["run_id"], variant["run_id"]]}
        )
        replay_delta, variant_delta = comparison["deltas"]

        assert replay_delta["replay_lineage_changed"] is True
        assert replay_delta["replay_lineage_delta"]["to_variant_types"] == ["exact"]
        assert replay_delta["replay_lineage_delta"]["source_run_id"] == original["run_id"]
        assert replay_delta["material_changed"] is False
        assert replay_delta["material_changes"] == []
        assert replay_delta["assessment"] == "no_material_change"
        assert replay_delta["dimensions"]["assessment"]["classification"] == "no_material_change"
        assert replay_delta["signals"] == []
        assert variant_delta["material_changed"] is True
        assert variant_delta["material_configuration_changed"] is True
        assert "scenario" in variant_delta["configuration_changes"]
        assert "replay_variant_changed" in variant_delta["signals"]
        assert variant_delta["assessment"] != "no_material_change"
        repeated = service.compare({"run_ids": [variant["run_id"], exact_variant["run_id"]]})
        assert repeated["deltas"][0]["replay_lineage_changed"] is True
        assert repeated["deltas"][0]["material_changed"] is False
        assert repeated["deltas"][0]["assessment"] == "no_material_change"
    finally:
        service.close()


def _snapshot() -> dict[str, Any]:
    return {
        "run_id": "baseline",
        "mode": "simulate",
        "runner_profile_id": "sandbox-simulate.v1",
        "scenario": {"id": "scenario.test.v1", "parameters": {"count": 2}},
        "objective_reached": True,
        "autonomy": "off",
        "ai_provider": {"provider_id": "deterministic-offline.v1"},
        "created_at": "2030-01-01T00:00:00Z",
        "finalized_at": "2030-01-01T00:00:01Z",
        "steps": [
            {
                "step_id": "observe",
                "behavior_id": "sandbox.discovery.v1",
                "action_id": "sandbox.discovery.v1",
                "status": "success",
                "policy": {"status": "allowed"},
                "telemetry": ["fixture.observed"],
            }
        ],
        "evidence": {"records": [{"provenance": "observed", "evidence_id": "one"}]},
        "detections": {
            "candidates": [{"state": "rendered", "match_count": 0, "benign_match_count": 0}]
        },
        "cleanup": {"attempted": True, "success": True, "outstanding_receipt_count": 0},
    }


def test_lineage_source_duration_and_defense_note_alone_are_descriptive() -> None:
    before = _snapshot()
    after = deepcopy(before)
    after.update(
        run_id="replay",
        finalized_at="2030-01-01T00:00:09Z",
        replay={"source_run_id": "baseline", "defense_change": "operator's external change note"},
    )
    delta = _delta(_summarize(before), _summarize(after))
    assert delta["replay_lineage_changed"] is True
    assert delta["replay_lineage_delta"]["defense_change_declared"] is True
    assert delta["replay_lineage_delta"]["defense_change_digest"].startswith("sha256:")
    assert delta["duration_delta_ms"] == 8000
    assert delta["material_changed"] is False
    assert delta["assessment"] == "no_material_change"


@pytest.mark.parametrize(
    ("path", "replacement", "material_field"),
    [
        (("scenario", "parameters", "count"), 3, "configuration"),
        (("runner_profile_id",), "sandbox-other.v1", "configuration"),
        (("mode",), "execute", "configuration"),
        (("steps", 0, "action_id"), "sandbox.alternate.v1", "configuration"),
        (("steps", 0, "policy", "status"), "control_blocked", "controls"),
        (("steps", 0, "status"), "failed", "outcomes"),
        (("evidence", "records", 0, "provenance"), "synthetic", "evidence"),
        (("detections", "candidates", 0, "state"), "parsed", "detection"),
        (("detections", "candidates", 0, "match_count"), 1, "detection"),
        (("cleanup", "success"), False, "cleanup"),
        (("objective_reached",), False, "objective"),
        (("steps", 0, "execution_disposition"), "counterfactual", "counterfactual"),
    ],
)
def test_replay_label_cannot_hide_effective_configuration_or_security_changes(
    path: tuple[str | int, ...], replacement: Any, material_field: str
) -> None:
    before = _snapshot()
    after = deepcopy(before)
    after["replay"] = {"exact": True, "source_run_id": before["run_id"]}
    parent: Any = after
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    delta = _delta(_summarize(before), _summarize(after))
    assert delta["material_changed"] is True
    assert material_field in delta["material_changes"]
    assert delta["assessment"] != "no_material_change"
    assert delta["dimensions"]["assessment"]["classification"] == delta["assessment"]
