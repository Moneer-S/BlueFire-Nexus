"""Real orchestration/finalization with a declared software-only gzip executor."""

import gzip
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bluefire.approvals import execution_approval_binding
from bluefire.collectors import CollectionSemanticsCollector, FilesystemCollector
from bluefire.config import AutonomyLevel, RunnerProfile
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.orchestrator import Orchestrator
from bluefire.product_store import ProductStore
from bluefire.replay import ReplayRequest, prepare_replay
from bluefire.run_store import RunStore
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.util import canonical_json_bytes
from tests_platform.test_atomic_gzip import _payload
from tests_platform.test_checkpoint_parameter_resolution import gzip_checkpoint_inputs, restoration
from tests_platform.test_orchestrator import StructuredFakeRunner, _write_bound_receipt

METHOD = "sandbox.collection.atomic-gzip.v1"


class GzipSoftwareExecutor(StructuredFakeRunner):
    """Writes only test fixtures; never launches an executable or live tool."""

    def __init__(self):
        super().__init__()
        self.fixture_paths = []
        self.executed_actions = []

    def inventory(self):
        inventory = dict(super().inventory())
        inventory["platform"] = "linux"
        inventory["actions"].append(
            {
                "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                "action_id": METHOD,
                "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[METHOD],
                "readiness": "ready",
            }
        )
        return inventory

    def execute(self, manifest, profile):
        action = manifest["action_id"]
        self.executed_actions.append(action)
        sandbox = Path(profile["sandbox_root"])
        if action != METHOD:
            result = super().execute(manifest, profile)
            if action in {"sandbox.fixture.create.v1", "sandbox.fixture.transform.v1"}:
                output = result["output"]
                path = sandbox / output["artifact"]
                path.parent.mkdir(parents=True, exist_ok=True)
                data = _payload()
                path.write_bytes(data)
                self.fixture_paths.append(path)
                output.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            elif action == "sandbox.cleanup.v1":
                removed = []
                for path in self.fixture_paths:
                    path.unlink()
                    removed.append(path.relative_to(sandbox).as_posix())
                result["output"].update(removed_paths=removed, verified_removed_paths=len(removed))
            return result
        data = gzip.compress((sandbox / "fixtures/transformed.jsonl").read_bytes(), mtime=0)
        relative = "staged/collection/bundle.jsonl.gz"
        path = sandbox / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.fixture_paths.append(path)
        receipt_id = _write_bound_receipt(manifest, profile)
        return {
            "schema_version": "bluefire.runner-result.v1",
            **{
                key: manifest[key]
                for key in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "request_hash",
                )
            },
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": "success",
            "output": {
                "artifact": relative,
                "container": "gzip",
                "input_count": 1,
                "source_sha256": manifest["params"]["expected_sha256"],
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "tool": {
                    "executable": "/usr/bin/gzip",
                    "sha256": "c" * 64,
                    "arguments": ["-n", "-c"],
                    "source_test": "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af",
                },
            },
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "authored-software-fixture"}],
            "receipt_ids": [receipt_id],
            "cleanup": None,
            "error": None,
            "limitations": ["Authored software fixture; no external gzip executable ran."],
        }


def test_omitted_gzip_default_runs_five_steps_and_finalizes_checkpoint_bundle(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "linux")
    monkeypatch.setattr("bluefire.runner_contracts.current_platform", lambda: "linux")
    kwargs, registry = gzip_checkpoint_inputs()
    scenario = ScenarioDefinition.from_mapping(kwargs["scenario"])
    profile = RunnerProfile.from_mapping(kwargs["source_authority"]["profile"])
    runner = GzipSoftwareExecutor()
    store = RunStore(tmp_path / "runs")
    approvals = ProductStore(tmp_path / "product.sqlite3")
    orchestrator = Orchestrator(
        registry,
        store,
        runner=runner,
        approval_store=approvals,
        catalog_authority=kwargs["source_authority"]["catalog_authority"],
    )
    collector_ids = (FilesystemCollector.descriptor.id, CollectionSemanticsCollector.descriptor.id)
    plan = orchestrator.preflight(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, approval_present=True
    ).plan
    binding = execution_approval_binding(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=kwargs["source_authority"]["target_scope"],
        autonomy=AutonomyLevel.OFF,
        ai_provider=plan["ai_provider"],
        runner_readiness=kwargs["source_authority"]["runner_readiness"],
        catalog_authority=kwargs["source_authority"]["catalog_authority"],
        context={"collector_binding": Orchestrator._collector_binding(collector_ids, None)},
    )
    pending = approvals.create_approval_request(
        run_id="software-checkpoint-intent",
        state_digest=binding["state_digest"],
        plan_digest=binding["plan_digest"],
        profile_id=binding["profile_id"],
        target_scope_digest=binding["target_scope_digest"],
        maximum_tier=binding["maximum_tier"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
    )
    approved = approvals.approve(
        pending["approval_id"],
        approved_by="software-reviewer",
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    consumed = approvals.consume_approval(
        approved["approval_id"],
        nonce=approved["nonce"],
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=kwargs["source_authority"]["target_scope"],
        approved_by="software-reviewer",
        approval_record=consumed,
        runner_readiness=kwargs["source_authority"]["runner_readiness"],
        collector_ids=collector_ids,
    )
    assert runner.executed_actions == [step.behavior_id for step in scenario.steps]
    assert len(result["steps"]) == 5 and all(
        step["status"] == "success" for step in result["steps"]
    )
    assert result["status"] == "completed" and result["objective_reached"] is True
    assert result["finalized_at"] and store.validate_bundle(result["run_id"])["valid"] is True
    assert result["cleanup"] == {"attempted": True, "success": True, "outstanding_receipt_count": 0}
    assert result["scenario"] == scenario.to_dict()
    assert result["scenario"]["steps"][3]["parameters"] == {"stage_variant": "primary"}
    assert result["replay_checkpoints"]
    assert all(
        row["schema_version"] == "bluefire.replay-checkpoint.v2"
        for row in result["replay_checkpoints"]
    )
    assert max(len(canonical_json_bytes(row)) for row in result["replay_checkpoints"]) < 256 * 1024
    prepared = prepare_replay(
        store,
        registry,
        ReplayRequest(source_run_id=result["run_id"], exact=True, from_step_id="select_records"),
    )
    assert prepared.checkpoint is not None
    target = restoration(prepared.checkpoint, kwargs, registry)
    assert target["checkpoint_id"] == prepared.checkpoint["checkpoint_id"]
    assert len(runner.executed_actions) == 5
    assert all(not path.exists() for path in runner.fixture_paths)
