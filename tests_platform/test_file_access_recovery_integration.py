"""Pure recovered proof and original-workspace integration, without native effects."""

import hashlib
import threading
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import file_access_context, file_access_execution, file_access_recovery
from bluefire.file_access_receipts import validate_partial_sources
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding, observation
from tests_platform.test_capability_composition import state as state
from tests_platform.test_capability_file_access import file_state as file_state
from tests_platform.test_file_access_control import operation as operation


@pytest.fixture(params=["baseline", "rollback"])
def completed_reads(request, monkeypatch):
    operation = request.param
    bound = binding()
    probe, owner = observation(bound), observation(bound, owner=True)
    recipe = file_access_execution.recipe(operation)
    tasks = []
    for row in recipe:
        result = {"status": "success"}
        observed = {"probe": probe, "owner": owner}.get(row["step_id"])
        if observed is not None:
            result["output"] = {"observation": observed}
        tasks.append(
            {
                "task": {
                    "step_id": row["step_id"],
                    "request_hash": (
                        content_hash(row["step_id"])
                        if observed is None
                        else observed["request_hash"]
                    ),
                    "manifest": {
                        "requested_at": "1970-01-01T00:16:39Z",
                        "expires_at": "1970-01-01T00:17:00Z",
                    },
                },
                "terminal": {"result": result},
            }
        )
    prior_baseline = {"baseline_digest": content_hash("original verified baseline")}
    prepared = {
        "recipe": recipe,
        "prior": {"baseline": prior_baseline},
        "source": {"fixture": "retained"},
        "target_binding": bound,
        "revision": 1,
    }
    committed, published = [], []
    store = SimpleNamespace(
        file_access_operation_records=lambda _: {"tasks": tasks},
        finish_file_access_operation=lambda *args, **kwargs: committed.append(kwargs),
    )
    control = SimpleNamespace(
        store=store, clock=lambda: 1_000_002, _publish=lambda *args: published.append(args)
    )
    current = {"enrollment": {"document": {"enrollment_id": bound["enrollment_id"]}}}
    monkeypatch.setattr(file_access_context, "binding", lambda *args, **kwargs: deepcopy(bound))
    outputs = {
        "owner": {
            "verification": {
                "probe_observation_digest": content_hash(probe),
                "observation_digest": content_hash(owner),
                "request_hash": owner["request_hash"],
            }
        }
    }
    return SimpleNamespace(
        operation=operation,
        control=control,
        prepared=prepared,
        current=current,
        outputs=outputs,
        probe=probe,
        owner=owner,
        committed=committed,
        published=published,
        prior_baseline=prior_baseline,
    )


def finish(value):
    file_access_execution._finish(
        value.control,
        "job-authored",
        {"review": {"operation": value.operation, "control_owner_id": "job-owner"}},
        value.prepared,
        value.current,
        None,
        value.outputs,
        expected_outcome_digest=content_hash("original unknown"),
    )


def test_recovered_complete_reads_publish_exact_proof(completed_reads):
    value = completed_reads
    finish(value)
    result = value.committed[0]
    assert result["expected_outcome_digest"] == content_hash("original unknown")
    assert result["outcome"]["state"] == "complete"
    assert result["control"]["status"] == (
        "baseline_verified" if value.operation == "baseline" else "rolled_back"
    )
    assert result["verified_observation"]["observed_at_ms"] == value.owner["observed_at_ms"]
    assert value.published == []
    if value.operation == "rollback":
        assert result["control"]["baseline"] == value.prior_baseline
    else:
        assert result["control"]["baseline"]["source_binding"]["operation_job_id"] == "job-authored"


@pytest.mark.parametrize(
    "change",
    ["stale", "future", "expired", "reordered", "probe_link", "owner_link", "request_link"],
)
def test_recovered_reads_refuse_unfresh_or_unlinked_proof(completed_reads, change):
    value = completed_reads
    if change in {"stale", "future", "expired", "reordered"}:
        value.owner["observed_at_ms"] = {
            "stale": 998_999,
            "future": 1_000_003,
            "expired": 1_020_000,
            "reordered": 999_999,
        }[change]
        value.outputs["owner"]["verification"]["observation_digest"] = content_hash(value.owner)
    else:
        key = {
            "probe_link": "probe_observation_digest",
            "owner_link": "observation_digest",
            "request_link": "request_hash",
        }[change]
        value.outputs["owner"]["verification"][key] = content_hash("another original request")
    with pytest.raises(ProductStoreError):
        finish(value)
    assert value.committed == value.published == []


@pytest.fixture
def original_workspaces(tmp_path):
    roots, profiles, snapshots, sources, tasks = {}, {}, {}, {}, []
    for index, workspace in enumerate(("retained", "observation")):
        root = tmp_path / workspace
        (root / "fixtures").mkdir(parents=True)
        path = "fixtures/" + workspace + ".json"
        payload = b'{"authored":true}'
        (root / path).write_bytes(payload)
        receipt_id = str(index + 1) * 64
        request_hash = content_hash(workspace)
        action_id = (
            "sandbox.fixture.transform.v1"
            if index == 0
            else "sandbox.file-access.probe.non-owner.v1"
        )
        receipt = {
            "receipt_id": receipt_id,
            "request_hash": request_hash,
            "action_id": action_id,
            "paths": [
                {
                    "relative_path": path,
                    "kind": "file",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            ],
        }
        profile = {"sandbox_root": str(root), "profile_id": "authored-profile"}
        snapshot = {"documents": {receipt_id: receipt}, "committed": [receipt_id]}
        roots[workspace], profiles[workspace], snapshots[str(root)] = str(root), profile, snapshot
        sources[workspace] = receipt
        if index:
            tasks.append(
                {
                    "task": {
                        "task_id": "task-probe",
                        "request_hash": request_hash,
                        "manifest": {"action_id": action_id},
                        "runner_profile": profile,
                    },
                    "terminal": {
                        "result": {"status": "success"},
                        "receipt_snapshot": deepcopy(snapshot),
                    },
                }
            )
    source = {
        "workspace": roots["retained"],
        "creation_task_id": "task-create",
        "creation_request_hash": sources["retained"]["request_hash"],
        "creation_receipt": sources["retained"],
    }
    prepared = {
        "source": source,
        "profiles": profiles,
        "roots": roots,
        "run_id": "run-original",
        "prior": {"baseline": {"baseline_digest": content_hash("previous baseline")}},
    }

    def discover(root, *, _documents=None, require_commit=False, **kwargs):
        snapshot = snapshots[str(root)]
        if _documents is not None:
            _documents.update(deepcopy(snapshot["documents"]))
        return tuple(snapshot["committed"] if require_commit else snapshot["documents"])

    engine = SimpleNamespace(_discover_runner_receipts=discover)
    return SimpleNamespace(
        prepared=prepared, tasks=tasks, engine=engine, snapshots=snapshots, sources=sources
    )


def test_two_original_workspaces_remain_distinct_reset_authorities(original_workspaces):
    value = original_workspaces
    inventory = file_access_recovery.partial_inventory(
        {"tasks": value.tasks}, value.prepared, value.engine
    )
    assert [row["workspace"] for row in inventory] == ["retained", "observation"]
    control = {
        "status": "recovery_required",
        "source": {"recovery": inventory},
        "binding": None,
        "binding_digest": content_hash(None),
        "baseline": value.prepared["prior"]["baseline"],
    }
    validate_partial_sources(value.prepared, value.tasks, control)
    assert file_access_recovery.validate_inventory(value.engine, inventory) == inventory
    rows = file_access_execution.recipe("reset", control)
    assert [row["step_id"] for row in rows] == ["reset_retained", "reset_observation"]
    for row in rows:
        assert file_access_execution._receipts(row["step_id"], {}, control["source"]) == [
            value.sources[row["workspace"]]["receipt_id"]
        ]


def test_interrupted_reset_keeps_only_verified_surviving_workspace(original_workspaces):
    value = original_workspaces
    inventory = file_access_recovery.partial_inventory(
        {"tasks": value.tasks}, value.prepared, value.engine
    )
    prepared = {**value.prepared, "source": {"recovery": inventory}}
    root = prepared["roots"]["retained"]
    receipt_id = value.sources["retained"]["receipt_id"]
    value.snapshots[root] = {"documents": {}, "committed": []}
    task = {
        "task": {
            "task_id": "task-reset-original",
            "request_hash": content_hash("reset retained"),
            "manifest": {
                "action_id": "sandbox.cleanup.v1",
                "params": {"receipt_ids": [receipt_id]},
            },
            "runner_profile": prepared["profiles"]["retained"],
        },
        "terminal": {
            "result": {"status": "success"},
            "receipt_snapshot": {"documents": {}, "committed": []},
        },
    }
    remaining = file_access_recovery.partial_inventory({"tasks": [task]}, prepared, value.engine)
    assert [row["workspace"] for row in remaining] == ["observation"]
    task["terminal"]["result"]["status"] = "failed"
    with pytest.raises(ProductStoreError, match="disappeared"):
        file_access_recovery.partial_inventory({"tasks": [task]}, prepared, value.engine)


def test_cleanup_cannot_consume_other_original_workspace(original_workspaces):
    value = original_workspaces
    task = {
        "task": {
            "task_id": "task-misbound-cleanup",
            "request_hash": content_hash("wrong workspace"),
            "manifest": {
                "action_id": "sandbox.cleanup.v1",
                "params": {"receipt_ids": [value.sources["retained"]["receipt_id"]]},
            },
            "runner_profile": value.prepared["profiles"]["observation"],
        },
        "terminal": {
            "result": {"status": "success"},
            "receipt_snapshot": {"documents": {}, "committed": []},
        },
    }
    with pytest.raises(ProductStoreError, match="another original workspace"):
        file_access_recovery.partial_inventory(
            {"tasks": value.tasks + [task]}, value.prepared, value.engine
        )


def test_missing_committed_file_is_only_absent_reset_inventory(original_workspaces):
    value = original_workspaces
    root = Path(value.prepared["roots"]["observation"])
    (root / "fixtures/observation.json").unlink()
    inventory = file_access_recovery.partial_inventory(
        {"tasks": value.tasks}, value.prepared, value.engine
    )
    assert inventory[1]["preimage"]["paths"] == {"fixtures/observation.json": {"present": False}}
    assert inventory[1]["snapshot"]["committed"] == [value.sources["observation"]["receipt_id"]]


@pytest.mark.parametrize("operation_name", ["baseline", "rollback"])
def test_control_observation_profiles_include_only_required_filesystem_scope(
    operation, operation_name
):
    from bluefire.runner_contracts import build_runner_profile

    _, plan = file_access_execution._plan(
        operation.engine,
        {"registry": operation.registry, "profile": operation.profile},
        operation_name,
    )
    scope = operation.engine._filesystem_scope(plan)
    assert scope == ("fixtures",)
    profile = build_runner_profile(
        operation.profile,
        sandbox_root=operation.prepared["roots"]["retained"],
        filesystem_scope=scope,
        network_destinations=(),
    )
    assert profile["target_scope"] == {"filesystem": ["fixtures"], "network": []}


def test_composed_endpoint_profile_keeps_observation_artifact_scope(operation, file_state):
    from bluefire import capability_file_access
    from bluefire.capability_composition import compile_initial_graph
    from bluefire.contracts import ExecutionMode, ScenarioDefinition

    compiled = compile_initial_graph(capability_file_access.initial_proposal(), **file_state)
    plan = operation.engine.planner.compile(
        ScenarioDefinition.from_mapping(compiled["scenario"]),
        mode=ExecutionMode.EXECUTE,
        profile=operation.profile,
    )
    assert operation.engine._filesystem_scope(plan) == ("fixtures",)
    assert operation.engine._network_destinations(plan) == ()


def test_fixed_recipe_cannot_silently_drop_a_required_binding(operation):
    original = file_access_execution.plan_step(operation.prepared["plan"]["steps"][0])
    step = replace(original, execution_binding={"unreviewed": "package"})
    plan = SimpleNamespace(steps=[step])
    with pytest.raises(ProductStoreError, match="fixed built-in"):
        file_access_execution._prepare(None, None, None, None, None, None, plan)


@pytest.mark.parametrize("change_remaining", [False, True])
def test_two_workspace_reset_runs_shared_pipeline_and_rechecks_remaining_inventory(
    operation, original_workspaces, monkeypatch, change_remaining
):
    from bluefire import policy, runner_contracts
    from bluefire.file_access_preparation import validate_task

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(2, tz or timezone.utc)

    monkeypatch.setattr(policy, "datetime", FixedDatetime)
    monkeypatch.setattr(runner_contracts, "datetime", FixedDatetime)
    value = original_workspaces
    inventory = file_access_recovery.partial_inventory(
        {"tasks": value.tasks}, value.prepared, value.engine
    )
    prior = {
        "control_owner_id": "job-original",
        "revision": 1,
        "status": "recovery_required",
        "source": {"recovery": inventory},
        "binding": None,
        "binding_digest": content_hash(None),
        "baseline": value.prepared["prior"]["baseline"],
    }
    view = {"document": prior, "document_digest": content_hash(prior)}
    enrolled = {
        "document": {
            "enrollment_id": "file-enrollment-authored",
            "root": {"path": value.prepared["roots"]["retained"]},
        },
        "document_digest": content_hash("authored enrollment"),
    }
    current = {
        "profile": operation.profile,
        "registry": operation.registry,
        "enrollment": enrolled,
        "control": view,
        "context_digest": content_hash("exact reset context"),
        "run_intent": {"target_scope": {"scope_refs": ["sandbox.workspace"]}},
    }
    request = {
        "reviewed_by": "Authored operator",
        "review_digest": content_hash("exact review"),
        "review": {
            "operation": "reset",
            "control_owner_id": prior["control_owner_id"],
            "control_digest": view["document_digest"],
            "context_digest": current["context_digest"],
        },
    }
    records = {"tasks": [], "outcome": None}
    prepared = {}
    outcomes, calls = [], []
    engine = operation.engine
    engine._discover_runner_receipts = value.engine._discover_runner_receipts
    engine.store = SimpleNamespace(root=Path(value.prepared["roots"]["retained"]).parent)

    def register(job_id, *, task_id, step_id, manifest, runner_profile, now_ms, validate_context):
        validate_task(
            prepared, records["tasks"], task_id, step_id, manifest, runner_profile, now_ms=now_ms
        )
        validate_context()
        records["tasks"].append(
            {
                "task": {
                    "task_id": task_id,
                    "step_id": step_id,
                    "request_hash": manifest["request_hash"],
                    "manifest": deepcopy(manifest),
                    "runner_profile": deepcopy(runner_profile),
                },
                "terminal": None,
            }
        )

    def terminal(task_id, *, request_hash, result, receipt_snapshot):
        row = next(row for row in records["tasks"] if row["task"]["task_id"] == task_id)
        row["terminal"] = {
            "result": deepcopy(result),
            "receipt_snapshot": deepcopy(receipt_snapshot),
        }

    def finish_operation(job_id, *, outcome, **kwargs):
        records["outcome"] = outcome
        outcomes.append({"outcome": outcome, **kwargs})

    def execute_task(manifest, profile, **kwargs):
        calls.append(manifest["step_id"])
        root = profile["sandbox_root"]
        snapshot = value.snapshots[root]
        assert manifest["params"]["receipt_ids"] == list(snapshot["documents"])
        removed = []
        for receipt in snapshot["documents"].values():
            for entry in receipt["paths"]:
                (Path(root) / entry["relative_path"]).unlink()
                removed.append(entry["relative_path"])
        snapshot["documents"].clear()
        snapshot["committed"].clear()
        if change_remaining and manifest["step_id"] == "reset_retained":
            (
                Path(value.prepared["roots"]["observation"]) / "fixtures/observation.json"
            ).write_bytes(b"changed after first cleanup")
        report = {
            "requested_receipts": 1,
            "removed_paths": removed,
            "already_absent_receipts": [],
            "retained_paths": [],
            "errors": [],
            "verification_performed": True,
            "verified_removed_paths": len(removed),
            "verified_absent_paths": 0,
            "verified_receipts": 1,
        }
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
                    "policy_digest",
                    "platform",
                )
            },
            "status": "success",
            "receipt_ids": [],
            "output": report,
            "cleanup": report,
        }

    engine.runner = SimpleNamespace(execute_task=execute_task)
    store = SimpleNamespace(
        prepare_file_access_operation=lambda job_id, document: prepared.update(document),
        register_file_access_task=register,
        record_file_access_task_terminal=terminal,
        file_access_operation_records=lambda job_id: records,
        get_file_access_control=lambda owner_id: view,
        finish_file_access_operation=finish_operation,
    )
    control = SimpleNamespace(
        store=store,
        service=SimpleNamespace(store=SimpleNamespace(_new_run_id=lambda: "run-reset-both")),
        clock=lambda: 2000,
        _context=lambda *args: current,
        _publish=lambda *args: None,
    )
    ctx = SimpleNamespace(
        job_id="job-reset-both", checkpoint=lambda: None, cancellation_event=threading.Event()
    )
    monkeypatch.setattr(file_access_execution, "_engine", lambda *args: engine)
    monkeypatch.setattr(
        file_access_execution,
        "_approval",
        lambda *args: {
            **operation.prepared["approval"],
            "approval_id": "authored-approval",
            "nonce": "authored-nonce",
        },
    )
    monkeypatch.setattr(
        file_access_context, "read_file_access_enrollment", lambda **kwargs: enrolled
    )
    if change_remaining:
        with pytest.raises(ProductStoreError, match="changed"):
            file_access_execution.execute(control, ctx, request)
        assert calls == ["reset_retained"]
        assert outcomes[-1]["outcome"]["state"] == "unknown"
        assert len(records["tasks"]) == 1
    else:
        file_access_execution.execute(control, ctx, request)
        assert calls == ["reset_retained", "reset_observation"]
        assert outcomes[-1]["outcome"]["state"] == "complete"
        assert outcomes[-1]["control"]["status"] == "reset"
        assert all(row["terminal"]["result"]["status"] == "success" for row in records["tasks"])
