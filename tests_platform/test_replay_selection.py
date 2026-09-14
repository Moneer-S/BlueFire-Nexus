from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.replay as replay_module
from bluefire.config import AutonomyLevel
from bluefire.contracts import load_scenario
from bluefire.registry import BehaviorRegistry, load_builtin_registry
from bluefire.replay import ReplayError, ReplayRequest, prepare_replay
from bluefire.replay_checkpoint_binding import checkpoint_source_binding_hash
from bluefire.run_store import RunStore
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = load_scenario(ROOT / "scenarios" / "sandbox_research_chain.yaml")


class _Store(RunStore):
    def __init__(self, source: Mapping[str, Any]) -> None:
        self.source = deepcopy(dict(source))

    def validate_bundle(self, run_id: str) -> Mapping[str, Any]:
        assert run_id == self.source["run_id"]
        return {"valid": True}

    def get_run(self, run_id: str) -> Mapping[str, Any]:
        assert run_id == self.source["run_id"]
        return deepcopy(self.source)


@pytest.fixture
def registry() -> BehaviorRegistry:
    return load_builtin_registry()


def _source(
    *,
    mode: str = "execute",
    step_ids: tuple[str, ...] = (
        "create_fixture",
        "transform_fixture",
        "discover_records",
        "stage_records",
    ),
) -> dict[str, Any]:
    actions = {
        "create_fixture": "sandbox.fixture.create.v1",
        "transform_fixture": "sandbox.fixture.transform.v1",
        "discover_records": "sandbox.discovery.list.v1",
        "stage_records": "sandbox.collection.stage.v1",
    }
    source = {
        "run_id": "run-20260829T120000Z-0123456789abcdef",
        "mode": mode,
        "scenario": SCENARIO.to_dict(),
        "steps": [
            {
                "step_id": step_id,
                "status": "success",
                "artifacts": {},
            }
            for step_id in step_ids
        ],
        "plan": {
            "steps": [{"step_id": step_id, "action_id": actions[step_id]} for step_id in actions]
        },
        "autonomy": "off",
        "ai_provider": "deterministic-offline.v1",
        "runner_profile_id": ("sandbox-execute.v1" if mode == "execute" else "sandbox-simulate.v1"),
        "policy": {"approval_binding": {"state_digest": "sha256:" + "a" * 64}},
    }
    return source


def _checkpoint(source: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_id": "checkpoint-" + "a" * 64,
        "manifest_hash": "sha256:" + "b" * 64,
        "source_run_id": source["run_id"],
        "source_binding_hash": checkpoint_source_binding_hash(
            source_run_id=str(source["run_id"]),
            scenario=source["scenario"],
            plan=source["plan"],
            approval_binding=source["policy"]["approval_binding"],
        ),
        "source_scenario": {"scenario_hash": content_hash(source["scenario"])},
        "checkpoint_before_step_id": "discover_records",
        "executed_steps": [
            {"step_id": "create_fixture"},
            {"step_id": "transform_fixture"},
        ],
        "material_files": [],
    }


def _install_checkpoint_stubs(
    monkeypatch: pytest.MonkeyPatch,
    source: dict[str, Any],
) -> Mapping[str, Any]:
    checkpoint = _checkpoint(source)
    source["replay_checkpoints"] = [checkpoint]

    def select(checkpoints: Any, step_id: str) -> Mapping[str, Any]:
        assert checkpoints == [checkpoint]
        assert step_id == "discover_records"
        return checkpoint

    def validate(
        value: Any,
        *,
        expected_source_run_id: str | None = None,
        expected_step_id: str | None = None,
        expected_source_binding_hash: str | None = None,
    ) -> Mapping[str, Any]:
        assert value == checkpoint
        assert expected_source_run_id == source["run_id"]
        assert expected_step_id == "discover_records"
        assert expected_source_binding_hash == checkpoint["source_binding_hash"]
        return checkpoint

    monkeypatch.setattr(replay_module, "checkpoint_for_step", select)
    monkeypatch.setattr(replay_module, "validate_checkpoint", validate)
    return checkpoint


def test_execute_node_restart_requires_a_trusted_checkpoint(
    registry: BehaviorRegistry,
) -> None:
    source = _source()

    with pytest.raises(ReplayError, match="requires trusted replay checkpoints"):
        prepare_replay(
            _Store(source),
            registry,
            ReplayRequest(source_run_id=source["run_id"], from_step_id="discover_records"),
        )


def test_exact_execute_replay_can_restart_from_a_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    registry: BehaviorRegistry,
) -> None:
    source = _source()
    checkpoint = _install_checkpoint_stubs(monkeypatch, source)

    prepared = prepare_replay(
        _Store(source),
        registry,
        ReplayRequest(
            source_run_id=source["run_id"],
            exact=True,
            from_step_id="discover_records",
        ),
    )

    assert prepared.checkpoint == checkpoint
    assert prepared.seed_artifacts == {}
    assert prepared.resume_from_step_id == "discover_records"
    assert prepared.lineage["exact"] is True
    assert prepared.lineage["checkpoint_id"] == checkpoint["checkpoint_id"]
    assert prepared.lineage["checkpoint_manifest_hash"] == checkpoint["manifest_hash"]
    assert prepared.lineage["checkpoint_materialization_mode"] == "deterministic_prefix_recreation"


@pytest.mark.parametrize(
    "variant",
    [
        {"parameter_overrides": {"discover_records": {}}},
        {"action_implementations": {"discover_records": "sandbox.discovery.list.v1"}},
        {"runner_profile_id": "sandbox-execute.v1"},
        {"autonomy": AutonomyLevel.ASSIST},
        {"defense_change": "changed"},
    ],
)
def test_exact_node_restart_still_refuses_semantic_variants(
    variant: Mapping[str, Any],
) -> None:
    with pytest.raises(ReplayError, match="exact replay cannot include variants"):
        ReplayRequest(
            source_run_id="run-20260829T120000Z-0123456789abcdef",
            exact=True,
            from_step_id="discover_records",
            **variant,
        )


@pytest.mark.parametrize(
    "variant",
    [
        {"parameter_overrides": {"create_fixture": {"record_count": 4}}},
        {"action_implementations": {"create_fixture": "sandbox.fixture.create.v1"}},
        {
            "swap_step_id": "transform_fixture",
            "swap_behavior_id": "sandbox.fixture.transform.v1",
        },
    ],
)
def test_execute_node_restart_refuses_checkpoint_prefix_mutations(
    monkeypatch: pytest.MonkeyPatch,
    registry: BehaviorRegistry,
    variant: Mapping[str, Any],
) -> None:
    source = _source()
    _install_checkpoint_stubs(monkeypatch, source)

    with pytest.raises(ReplayError, match="checkpoint prefix cannot be changed"):
        prepare_replay(
            _Store(source),
            registry,
            ReplayRequest(
                source_run_id=source["run_id"],
                from_step_id="discover_records",
                **variant,
            ),
        )


@pytest.mark.parametrize(
    "step_ids",
    [
        ("create_fixture", "transform_fixture", "stage_records"),
        (
            "create_fixture",
            "transform_fixture",
            "discover_records",
            "stage_records",
            "discover_records",
        ),
    ],
)
def test_simulate_restart_refuses_missing_or_duplicated_target_rows(
    registry: BehaviorRegistry,
    step_ids: tuple[str, ...],
) -> None:
    source = _source(mode="simulate", step_ids=step_ids)

    with pytest.raises(ReplayError, match="must occur exactly once"):
        prepare_replay(
            _Store(source),
            registry,
            ReplayRequest(source_run_id=source["run_id"], from_step_id="discover_records"),
        )


def test_profile_change_uses_identity_not_field_presence(registry: BehaviorRegistry) -> None:
    source = _source()

    unchanged = prepare_replay(
        _Store(source),
        registry,
        ReplayRequest(
            source_run_id=source["run_id"],
            runner_profile_id="sandbox-execute.v1",
        ),
    )
    changed = prepare_replay(
        _Store(source),
        registry,
        ReplayRequest(
            source_run_id=source["run_id"],
            runner_profile_id="sandbox-restricted-owned.v1",
        ),
    )

    assert unchanged.lineage["profile_from"] == "sandbox-execute.v1"
    assert unchanged.lineage["profile_to"] == "sandbox-execute.v1"
    assert unchanged.lineage["profile_changed"] is False
    assert changed.lineage["profile_from"] == "sandbox-execute.v1"
    assert changed.lineage["profile_to"] == "sandbox-restricted-owned.v1"
    assert changed.lineage["profile_changed"] is True


def test_defense_change_is_bounded_normalized_and_hashed(registry: BehaviorRegistry) -> None:
    source = _source()
    prepared = prepare_replay(
        _Store(source),
        registry,
        ReplayRequest(
            source_run_id=source["run_id"],
            defense_change="  Enabled   reviewed   detection revision 2  ",
        ),
    )

    normalized = "Enabled reviewed detection revision 2"
    assert prepared.lineage["defense_change"] == normalized
    assert prepared.lineage["defense_change_declared"] is True
    assert prepared.lineage["defense_change_digest"] == content_hash({"defense_change": normalized})
    with pytest.raises(ReplayError, match="bounded printable text"):
        ReplayRequest(source_run_id=source["run_id"], defense_change="x" * 513)
    with pytest.raises(ReplayError, match="bounded printable text"):
        ReplayRequest(source_run_id=source["run_id"], defense_change="line one\nline two")
    with pytest.raises(ReplayError, match="secret-shaped"):
        ReplayRequest(source_run_id=source["run_id"], defense_change="token=abc123")


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_exact_flag_is_strictly_boolean(value: Any) -> None:
    if value is None:
        ReplayRequest(source_run_id="run-20260829T120000Z-0123456789abcdef")
        return
    with pytest.raises(ReplayError, match="must be a boolean"):
        ReplayRequest(
            source_run_id="run-20260829T120000Z-0123456789abcdef",
            exact=value,
        )
