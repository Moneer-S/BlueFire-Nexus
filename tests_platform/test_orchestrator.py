from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.approvals import execution_approval_binding
from bluefire.collectors import (
    CollectionRequest,
    CollectionSession,
    CollectorReadiness,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    LoopbackReceiverCollector,
)
from bluefire.config import AutonomyLevel, RunnerProfile, load_config
from bluefire.contracts import ExecutionMode, StepOutcome, load_scenario
from bluefire.orchestrator import OrchestrationError, Orchestrator
from bluefire.product_store import ProductStore
from bluefire.registry import load_builtin_registry
from bluefire.replay import ReplayRequest, prepare_replay
from bluefire.run_store import RunStore
from bluefire.runner_client import RunnerTransportError, canonical_runner_inventory
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.runner_transport import AuthenticatedRunnerClient
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "scenarios" / "sandbox_research_chain.yaml"
ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
}
RECEIPT_IDS = {
    "sandbox.fixture.create.v1": "a" * 64,
    "sandbox.fixture.transform.v1": "b" * 64,
    "sandbox.collection.stage.v1": "c" * 64,
    "sandbox.export.local.v1": "d" * 64,
}
FULL_TARGET_SCOPE = {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]}


def _execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(
        profile for profile in config.runner_profiles if profile.mode is ExecutionMode.EXECUTE
    )


def _write_bound_receipt(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    request_hash: str | None = None,
    action_id: str | None = None,
    committed: bool = True,
    created_at: str = "2026-08-24T00:00:00Z",
) -> str:
    sandbox_root = Path(str(profile["sandbox_root"]))
    receipt_root = sandbox_root / ".bluefire" / "receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    workspace_id = hashlib.sha256(
        str(sandbox_root.resolve(strict=True)).replace("\\", "/").encode("utf-8")
    ).hexdigest()
    effective_action_id = action_id or str(manifest["action_id"])
    params = manifest.get("params")
    params = params if isinstance(params, Mapping) else {}
    if effective_action_id == "sandbox.fixture.create.v1":
        owned_path = str(params.get("path", "fixtures/input.jsonl"))
    elif effective_action_id == "sandbox.fixture.transform.v1":
        owned_path = str(params.get("output", "fixtures/transformed.jsonl"))
    elif effective_action_id == "sandbox.collection.stage.v1":
        bundle_format = str(params.get("bundle_format", "jsonl"))
        owned_path = f"staged/bundle.{bundle_format}"
    elif effective_action_id == "sandbox.export.local.v1":
        retention_label = str(params.get("retention_label", "ephemeral"))
        owned_path = f"exports/{retention_label}/bundle.bin"
    else:
        owned_path = "fixtures/recovery.jsonl"
    identity = {
        "schema_version": "bluefire.receipt/v1",
        "request_hash": request_hash or manifest["request_hash"],
        "action_id": effective_action_id,
        "runner_profile_id": profile["profile_id"],
        "workspace_id": workspace_id,
        "created_at": created_at,
        "paths": [
            {
                "relative_path": owned_path,
                "kind": "file",
                "sha256": "0" * 64,
                "size": 0,
            }
        ],
    }
    receipt_id = content_hash(identity).removeprefix("sha256:")
    receipt_path = receipt_root / f"{receipt_id}.json"
    receipt_path.write_text(
        json.dumps({"receipt_id": receipt_id, **identity}),
        encoding="utf-8",
    )
    if committed:
        commit_root = sandbox_root / ".bluefire" / "receipt-commits"
        commit_root.mkdir(parents=True, exist_ok=True)
        (commit_root / f"{receipt_id}.json").write_text(
            json.dumps(
                {
                    "schema_version": "bluefire.receipt-commit/v1",
                    "receipt_id": receipt_id,
                    "runner_profile_id": profile["profile_id"],
                    "workspace_id": workspace_id,
                    "committed_at": "2026-08-24T00:00:01Z",
                }
            ),
            encoding="utf-8",
        )
    return receipt_id


class StructuredFakeRunner:
    def __init__(self, *, network_status: str = "success") -> None:
        self.network_status = network_status
        self.record_count = 6
        self.inventory_calls = 0
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": "0.1.0",
            "action_sdk_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "platform": "windows",
            "actions": [
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": action_id,
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[action_id],
                    "readiness": "ready",
                }
                for action_id in sorted(ACTION_IDS)
            ],
        }

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        manifest_copy = copy.deepcopy(dict(manifest))
        profile_copy = copy.deepcopy(dict(profile))
        self.calls.append((manifest_copy, profile_copy))
        action_id = str(manifest["action_id"])
        status = self.network_status if action_id == "sandbox.network.loopback.v1" else "success"
        if action_id == "sandbox.fixture.create.v1":
            self.record_count = int(manifest["params"]["record_count"])
            output = {
                "artifact": manifest["params"]["path"],
                "sha256": "1" * 64,
                "size": 128,
                "template": "telemetry-seed",
                "record_count": manifest["params"]["record_count"],
                "format": "jsonl",
            }
        elif action_id == "sandbox.fixture.transform.v1":
            output = {
                "artifact": manifest["params"]["output"],
                "sha256": "2" * 64,
                "size": 128,
                "record_count": self.record_count,
                "redact_values": manifest["params"]["redact_values"],
                "redacted_value_count": (
                    self.record_count if manifest["params"]["redact_values"] else 0
                ),
                "format": "jsonl",
                "implementation": "in_process_reviewed_jsonl_transform",
            }
        elif action_id == "sandbox.discovery.list.v1":
            output = {
                "path": "fixtures/transformed.jsonl",
                "entries": [
                    {
                        "path": "fixtures/transformed.jsonl",
                        "name": "transformed.jsonl",
                        "kind": "file",
                        "size": 16,
                    }
                ],
                "returned_entries": 1,
                "target_cardinality": "one",
            }
        elif action_id == "sandbox.discovery.metadata.v1":
            output = {
                "entries": [
                    {
                        "path": "fixtures/transformed.jsonl",
                        "name": "transformed.jsonl",
                        "kind": "file",
                        "size": 16,
                        "readonly": True,
                    }
                ],
                "path": "fixtures/transformed.jsonl",
                "returned_entries": 1,
                "target_cardinality": "one",
            }
        elif action_id == "sandbox.collection.stage.v1":
            output = {
                "artifact": f"staged/bundle.{manifest['params']['bundle_format']}",
                "format": manifest["params"]["bundle_format"],
                "record_count": self.record_count,
                "size": 16,
                "sha256": "3" * 64,
                "input_count": 1,
                "accepted_input_count": 1,
                "rejected_input_count": 0,
                "complete": True,
            }
        elif action_id == "sandbox.network.loopback.v1":
            output = {"bytes_sent": 16}
        elif action_id == "sandbox.export.local.v1":
            output = {
                "source": manifest["params"]["source"],
                "artifact": (f"exports/{manifest['params']['retention_label']}/bundle.bin"),
                "size": 16,
                "retention_label": manifest["params"]["retention_label"],
                "sha256": "3" * 64,
                "destination_policy": "runner_fixed_retention_destination",
            }
        else:
            requested = list(manifest["params"].get("receipt_ids", []))
            output = {
                "requested_receipts": len(requested),
                "removed_paths": [],
                "already_absent_receipts": [],
                "retained_paths": [],
                "errors": [],
                "verification_performed": True,
                "verified_removed_paths": 0,
                "verified_absent_paths": 0,
                "verified_receipts": len(requested),
            }
        receipts: list[str] = []
        if action_id in RECEIPT_IDS:
            receipt_id = _write_bound_receipt(manifest, profile)
            RECEIPT_IDS[action_id] = receipt_id
            receipts.append(receipt_id)
        error = None
        if status != "success":
            error = {"code": f"fake_{status}", "message": f"structured {status} result"}
        if action_id == "sandbox.cleanup.v1":
            receipt_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipts"
            commit_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipt-commits"
            for receipt_id in manifest["params"].get("receipt_ids", []):
                (receipt_root / f"{receipt_id}.json").unlink(missing_ok=True)
                (commit_root / f"{receipt_id}.json").unlink(missing_ok=True)
        cleanup_report = output if action_id == "sandbox.cleanup.v1" else None
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest["request_id"],
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": action_id,
            "runner_id": manifest["runner_id"],
            "runner_profile_id": manifest["runner_profile_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": status,
            "output": output,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "fake-runner", "status": status}],
            "receipt_ids": receipts,
            "cleanup": cleanup_report,
            "error": error,
            "limitations": ["Structured local fake; no runner side effect occurred."],
        }


class SlowFirstRunner(StructuredFakeRunner):
    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if not self.calls:
            time.sleep(0.8)
        return super().execute(manifest, profile)


class RunnerMustNotBeCalled:
    def __init__(self) -> None:
        self.calls = 0

    def inventory(self) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("Simulate must not inspect runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("Simulate must not dispatch a runner action")


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("request_id", "request-forged"),
        ("runner_id", "runner-forged.v1"),
        ("runner_profile_id", "profile-forged.v1"),
        ("platform", "linux" if _execute_profile().platforms[0] != "linux" else "windows"),
    ],
)
def test_runner_result_identity_is_bound_to_the_exact_request(
    field: str,
    forged: str,
) -> None:
    manifest = {
        "request_id": "request-exact",
        "run_id": "run-exact",
        "step_id": "step-exact",
        "behavior_id": "behavior.exact.v1",
        "action_id": "action.exact.v1",
        "runner_id": "runner.exact.v1",
        "runner_profile_id": "profile.exact.v1",
        "request_hash": "sha256:" + "a" * 64,
    }
    profile = {
        "platform": "windows",
        "policy_digest": "sha256:" + "b" * 64,
    }
    result = {
        "schema_version": "bluefire.runner-result.v1",
        **manifest,
        "platform": profile["platform"],
        "policy_digest": profile["policy_digest"],
    }
    result[field] = forged

    with pytest.raises(RunnerTransportError, match=field):
        Orchestrator._validate_runner_result(manifest, profile, result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_receipts", True),
        ("verified_receipts", True),
        ("verified_removed_paths", True),
        ("verified_absent_paths", False),
    ],
)
def test_cleanup_success_rejects_boolean_receipt_and_verification_counters(
    field: str, value: object
) -> None:
    cleanup: dict[str, object] = {
        "requested_receipts": 1,
        "removed_paths": [],
        "already_absent_receipts": [],
        "retained_paths": [],
        "errors": [],
        "verification_performed": True,
        "verified_removed_paths": 0,
        "verified_absent_paths": 1,
        "verified_receipts": 1,
    }
    cleanup[field] = value
    manifest = {
        "action_id": "sandbox.cleanup.v1",
        "params": {"receipt_ids": ["a" * 64]},
    }
    result = {
        "status": "success",
        "output": cleanup,
        "cleanup": cleanup,
    }

    with pytest.raises(RunnerTransportError, match="cleanup"):
        Orchestrator._validate_cleanup_result(manifest, result)


def test_receipt_root_inspection_io_failure_is_a_transport_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    receipt_root = sandbox / ".bluefire" / "receipts"
    original_lstat = Path.lstat

    def fail_receipt_root_inspection(path: Path):
        if path == receipt_root:
            raise OSError("injected receipt root metadata failure")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_receipt_root_inspection)
    with pytest.raises(RunnerTransportError):
        Orchestrator._discover_runner_receipts(
            sandbox,
            expected_profile_id="sandbox-execute.v1",
        )


def test_receipt_discovery_requires_full_identity_and_optional_commit(tmp_path: Path) -> None:
    sandbox = tmp_path / "receipt-contract-sandbox"
    sandbox.mkdir()
    manifest = {
        "request_hash": "sha256:" + "1" * 64,
        "action_id": "sandbox.fixture.create.v1",
        "params": {"path": "fixtures/input.jsonl"},
    }
    profile = {"sandbox_root": str(sandbox), "profile_id": "sandbox-execute.v1"}
    receipt_id = _write_bound_receipt(manifest, profile, committed=False)
    discovery = {
        "expected_profile_id": profile["profile_id"],
        "expected_request_hash": manifest["request_hash"],
        "expected_action_id": manifest["action_id"],
        "max_files": 32,
        "max_bytes": 1024 * 1024,
    }

    assert Orchestrator._discover_runner_receipts(sandbox, **discovery) == (receipt_id,)
    assert Orchestrator._discover_runner_receipts(sandbox, require_commit=True, **discovery) == ()

    assert _write_bound_receipt(manifest, profile, committed=True) == receipt_id
    assert Orchestrator._discover_runner_receipts(sandbox, require_commit=True, **discovery) == (
        receipt_id,
    )

    receipt_path = sandbox / ".bluefire" / "receipts" / f"{receipt_id}.json"
    tampered = json.loads(receipt_path.read_text(encoding="utf-8"))
    tampered["paths"][0]["size"] = 1
    receipt_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(RunnerTransportError, match="content digest"):
        Orchestrator._discover_runner_receipts(sandbox, **discovery)


def test_receipt_discovery_accepts_rust_nanosecond_timestamp(tmp_path: Path) -> None:
    sandbox = tmp_path / "receipt-nanosecond-sandbox"
    sandbox.mkdir()
    manifest = {
        "request_hash": "sha256:" + "2" * 64,
        "action_id": "sandbox.fixture.create.v1",
        "params": {"path": "fixtures/input.jsonl"},
    }
    profile = {"sandbox_root": str(sandbox), "profile_id": "sandbox-execute.v1"}
    receipt_id = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-09-02T19:49:03.527817100Z",
    )

    assert Orchestrator._discover_runner_receipts(
        sandbox,
        expected_profile_id=profile["profile_id"],
        expected_request_hash=manifest["request_hash"],
        expected_action_id=manifest["action_id"],
        require_commit=True,
    ) == (receipt_id,)


class FailAfterFirstEffectStore(RunStore):
    def append_event(self, run_id: str, event_type: str, data: Mapping[str, Any]) -> None:
        if event_type == "step.completed" and data.get("action_id") == "sandbox.fixture.create.v1":
            raise RuntimeError("injected event-store failure")
        super().append_event(run_id, event_type, data)


class IncompleteCleanupFakeRunner(StructuredFakeRunner):
    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = dict(super().execute(manifest, profile))
        if manifest["action_id"] == "sandbox.cleanup.v1":
            result["cleanup"] = {
                "requested_receipts": 0,
                "removed_paths": [],
                "already_absent_receipts": [],
                "retained_paths": [],
                "errors": [],
                "verification_performed": False,
                "verified_removed_paths": 0,
                "verified_absent_paths": 0,
                "verified_receipts": 0,
            }
            result["output"] = dict(result["cleanup"])
        return result


class ReceiptThenTransportFailureRunner(StructuredFakeRunner):
    RECEIPT_ID = "e" * 64
    UNRELATED_RECEIPT_ID = "f" * 64

    def __init__(self) -> None:
        super().__init__()
        self.failed_once = False

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        action_id = str(manifest["action_id"])
        receipt_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipts"
        if action_id != "sandbox.cleanup.v1" and not self.failed_once:
            self.failed_once = True
            self.calls.append((copy.deepcopy(dict(manifest)), copy.deepcopy(dict(profile))))
            self.RECEIPT_ID = _write_bound_receipt(manifest, profile, committed=False)
            self.UNRELATED_RECEIPT_ID = _write_bound_receipt(
                manifest,
                profile,
                request_hash="sha256:" + "9" * 64,
                action_id="sandbox.fixture.transform.v1",
                committed=False,
            )
            raise RunnerTransportError("injected result transport failure")
        if action_id == "sandbox.cleanup.v1":
            for receipt_id in manifest["params"]["receipt_ids"]:
                (receipt_root / f"{receipt_id}.json").unlink(missing_ok=True)
        return super().execute(manifest, profile)


class UncommittedSuccessRunner(StructuredFakeRunner):
    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = super().execute(manifest, profile)
        if manifest["action_id"] == "sandbox.fixture.create.v1":
            for receipt_id in result["receipt_ids"]:
                commit = (
                    Path(str(profile["sandbox_root"]))
                    / ".bluefire"
                    / "receipt-commits"
                    / f"{receipt_id}.json"
                )
                commit.unlink()
        return result


def _orchestrator(tmp_path: Path, runner: object) -> Orchestrator:
    return Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=runner,  # type: ignore[arg-type]
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
    )


def _corrupt_runner_inventory(corruption: str, *, target: str) -> Mapping[str, Any]:
    value = copy.deepcopy(dict(StructuredFakeRunner().inventory()))
    actions = value["actions"]
    assert isinstance(actions, list)
    target_index = next(index for index, row in enumerate(actions) if row["action_id"] == target)
    if corruption == "missing":
        actions.pop(target_index)
    elif corruption == "duplicate":
        actions.append(copy.deepcopy(actions[target_index]))
    elif corruption == "wrong_version":
        actions[target_index]["action_version"] = "9.0.0"
    elif corruption == "not_ready":
        actions[target_index]["readiness"] = "structural"
    elif corruption == "missing_action_schema":
        actions[target_index].pop("schema_version")
    elif corruption == "missing_inventory_action_schema":
        value.pop("action_sdk_version")
    else:
        canonical = copy.deepcopy(dict(canonical_runner_inventory(value)))
        canonical_actions = canonical["actions"]
        assert isinstance(canonical_actions, list)
        canonical_target = next(row for row in canonical_actions if row["action_id"] == target)
        if corruption == "missing_source_digest":
            canonical.pop("source_digest")
        elif corruption == "malformed_source_digest":
            canonical["source_digest"] = "sha256:invalid"
        elif corruption == "missing_contract_digest":
            canonical_target.pop("contract_digest")
        elif corruption == "malformed_contract_digest":
            canonical_target["contract_digest"] = "sha256:invalid"
        else:  # pragma: no cover - guarded by the parametrizations below.
            raise AssertionError(f"unknown inventory corruption: {corruption}")
        return canonical
    return value


def test_inventory_gates_accept_raw_and_canonical_authoritative_contracts(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    plan = orchestrator.planner.compile(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
    )
    raw = runner.inventory()
    canonical = canonical_runner_inventory(raw)

    Orchestrator._validate_inventory(plan, raw)
    Orchestrator._validate_inventory(plan, canonical)
    Orchestrator._validate_cleanup_inventory(raw)
    Orchestrator._validate_cleanup_inventory(canonical)


@pytest.mark.parametrize(
    "corruption",
    [
        "missing",
        "duplicate",
        "wrong_version",
        "not_ready",
        "missing_action_schema",
        "missing_inventory_action_schema",
        "missing_source_digest",
        "malformed_source_digest",
        "missing_contract_digest",
        "malformed_contract_digest",
    ],
)
def test_planned_inventory_gate_rejects_non_authoritative_action_rows(
    tmp_path: Path,
    corruption: str,
) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    plan = orchestrator.planner.compile(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
    )

    with pytest.raises(OrchestrationError, match="planned action contracts"):
        Orchestrator._validate_inventory(
            plan,
            _corrupt_runner_inventory(
                corruption,
                target="sandbox.fixture.create.v1",
            ),
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "missing",
        "duplicate",
        "wrong_version",
        "not_ready",
        "missing_action_schema",
        "missing_inventory_action_schema",
        "missing_contract_digest",
        "malformed_contract_digest",
    ],
)
def test_cleanup_recovery_inventory_gate_requires_the_exact_ready_contract(
    corruption: str,
) -> None:
    with pytest.raises(OrchestrationError, match="cleanup action contract"):
        Orchestrator._validate_cleanup_inventory(
            _corrupt_runner_inventory(
                corruption,
                target="sandbox.cleanup.v1",
            )
        )


def _approval_kwargs(
    orchestrator: Orchestrator,
    *,
    scenario: Any,
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    approved_by: str = "operator@example.test",
    action_implementations: Mapping[str, str] | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    approval_store = orchestrator.approval_store
    assert isinstance(approval_store, ProductStore)
    plan = orchestrator.planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        autonomy=AutonomyLevel.OFF,
        action_implementations=action_implementations,
    )
    binding = execution_approval_binding(
        registry=orchestrator.registry,
        scenario=scenario,
        plan=plan.to_dict(),
        profile=profile,
        target_scope=target_scope,
        autonomy=plan.autonomy,
        ai_provider=plan.ai_provider,
        context=context,
    )
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    pending = approval_store.create_approval_request(
        run_id="test-execution-intent",
        state_digest=binding["state_digest"],
        plan_digest=binding["plan_digest"],
        profile_id=binding["profile_id"],
        target_scope_digest=binding["target_scope_digest"],
        maximum_tier=binding["maximum_tier"],
        expires_at=expires_at,
    )
    approved = approval_store.approve(
        str(pending["approval_id"]),
        approved_by=approved_by,
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    consumed = approval_store.consume_approval(
        str(approved["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    return {"approved_by": approved_by, "approval_record": consumed}


def test_action_implementation_choices_are_execute_only_and_profile_bound(
    tmp_path: Path,
) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(OrchestrationError, match="Simulate does not accept"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.SIMULATE,
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        )

    selected = orchestrator.preflight(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=True,
        action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
    )
    assert selected.plan["steps"][0]["action_id"] == "sandbox.fixture.create.v1"

    with pytest.raises(OrchestrationError, match="not registered to behavior"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            approval_present=True,
            action_implementations={"create_fixture": "sandbox.discovery.list.v1"},
        )

    with pytest.raises(OrchestrationError, match="disabled by"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=replace(
                profile,
                enabled_actions=tuple(
                    action
                    for action in profile.enabled_actions
                    if action != "sandbox.fixture.create.v1"
                ),
            ),
            approval_present=True,
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        )


def test_execute_replay_preserves_action_choices_and_records_explicit_overrides(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    selections = {"create_fixture": "sandbox.fixture.create.v1"}
    approval = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
        action_implementations=selections,
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path,
        target_scope=FULL_TARGET_SCOPE,
        autonomy=AutonomyLevel.OFF,
        action_implementations=selections,
        **approval,
    )

    prepared = prepare_replay(
        orchestrator.store,
        orchestrator.registry,
        ReplayRequest(
            source_run_id=str(result["run_id"]),
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        ),
    )

    assert prepared.action_implementations["create_fixture"] == "sandbox.fixture.create.v1"
    assert prepared.lineage["action_implementations_from"]
    assert prepared.lineage["action_implementation_overrides"] == selections
    assert prepared.lineage["action_implementations_changed"] is True

    swapped = prepare_replay(
        orchestrator.store,
        orchestrator.registry,
        ReplayRequest(
            source_run_id=str(result["run_id"]),
            swap_step_id="discover_records",
            swap_behavior_id="sandbox.discovery.metadata.v1",
        ),
    )
    assert "discover_records" not in swapped.action_implementations
    assert swapped.lineage["action_reselection_steps"] == ["discover_records"]
    assert swapped.lineage["action_implementations_from"]["discover_records"] == (
        "sandbox.discovery.list.v1"
    )
    resolved_swap = orchestrator.planner.compile(
        swapped.scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        action_implementations=swapped.action_implementations,
    )
    resolved_discovery = next(
        step for step in resolved_swap.steps if step.step_id == "discover_records"
    )
    assert resolved_discovery.action_id == "sandbox.discovery.metadata.v1"


def _rows_by_step(result: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(row["step_id"]): row for row in result["steps"]}


def _evidence_by_step(result: Mapping[str, Any], step_id: str) -> list[Mapping[str, Any]]:
    return [row for row in result["evidence"]["records"] if row["step_id"] == step_id]


def test_simulate_never_calls_runner_inventory_or_execute(tmp_path: Path) -> None:
    runner = RunnerMustNotBeCalled()
    result = _orchestrator(tmp_path, runner).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.SIMULATE,
    )

    assert runner.calls == 0
    assert result["mode"] == "simulate"
    assert result["objective_reached"] is True
    assert result["cleanup"] == {
        "attempted": False,
        "success": None,
        "outstanding_receipt_count": 0,
    }
    assert {record["provenance"] for record in result["evidence"]["records"]} == {"synthetic"}
    assert all(step["action_id"] is None for step in result["steps"])


def test_simulate_persists_canonical_autonomy_and_provider_metadata(tmp_path: Path) -> None:
    provider = {
        "provider_id": "deterministic-offline.v1",
        "kind": "deterministic",
        "model": "deterministic-planner.v1",
    }
    result = _orchestrator(tmp_path, RunnerMustNotBeCalled()).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.SIMULATE,
        autonomy=AutonomyLevel.ASSIST,
        ai_provider=provider,
    )

    assert result["autonomy"] == "assist"
    assert result["ai_enabled"] is True
    assert result["ai_provider"] == provider
    assert result["plan"]["autonomy"] == "assist"
    assert result["policy"]["autonomy"] == "assist"
    assert result["policy"]["ai_provider"] == provider


def test_execute_refuses_missing_profile_and_approval_before_runner_use(tmp_path: Path) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)

    with pytest.raises(OrchestrationError, match="explicit runner profile"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            sandbox_root=tmp_path / "sandbox-missing-profile",
            approved_by="operator",
        )

    profile = _execute_profile()
    report = orchestrator.preflight(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=False,
    )
    assert report.status == "approval_required"
    assert report.approval_required is True
    assert report.problems == ("Explicit operator approval is required.",)
    with pytest.raises(OrchestrationError, match="operator approval"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-missing-approval",
        )
    assert runner.inventory_calls == 0
    assert runner.calls == []


def test_execute_requires_explicit_profile_bounded_target_scope_before_runner_use(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(OrchestrationError, match="explicit target scope"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-missing-scope",
            approved_by="operator@example.test",
            approval_record={},
        )
    with pytest.raises(OrchestrationError, match="expands beyond"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-expanded-scope",
            target_scope={"scope_refs": ["sandbox.workspace", "external.network"]},
            approved_by="operator@example.test",
            approval_record={},
        )

    assert runner.inventory_calls == 0
    assert runner.calls == []


def test_execute_rejects_forged_rebound_and_replayed_approval_capabilities(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    authorization = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
    )
    forged = copy.deepcopy(authorization)
    forged["approval_record"]["nonce"] = "forged-capability"
    with pytest.raises(OrchestrationError, match="unavailable|mismatched"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "forged",
            target_scope=FULL_TARGET_SCOPE,
            **forged,
        )
    with pytest.raises(OrchestrationError, match="exact plan and target scope"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "rebound",
            target_scope={"scope_refs": ["sandbox.workspace", "export.local"]},
            **authorization,
        )
    assert runner.inventory_calls == 0

    orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "valid",
        target_scope=FULL_TARGET_SCOPE,
        **authorization,
    )
    inventory_calls = runner.inventory_calls
    with pytest.raises(OrchestrationError, match="already claimed"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "replayed",
            target_scope=FULL_TARGET_SCOPE,
            **authorization,
        )
    assert runner.inventory_calls == inventory_calls


def test_operator_scope_refuses_unapproved_action_but_preserves_registered_fallback(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    target_scope = {"scope_refs": ["sandbox.workspace", "export.local"]}
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=target_scope,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=target_scope,
        ),
    )

    rows = _rows_by_step(result)
    network = rows["try_loopback"]
    assert network["status"] == "blocked"
    assert network["policy"]["status"] == "refused"
    assert network["error"]["code"] == "target_scope_refused"
    assert rows["export_locally"]["status"] == "success"
    assert result["authorized_target_scope"] == {
        "scope_refs": ["sandbox.workspace", "export.local"]
    }
    called_actions = [call[0]["action_id"] for call in runner.calls]
    assert "sandbox.network.loopback.v1" not in called_actions
    assert called_actions[-2:] == ["sandbox.export.local.v1", "sandbox.cleanup.v1"]


def test_execute_checkpoints_each_action_and_seals_remaining_time_in_manifest(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    checkpoints: list[Mapping[str, Any]] = []

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "checkpoint-sandbox",
        target_scope=FULL_TARGET_SCOPE,
        checkpoint=lambda progress: checkpoints.append(dict(progress)),
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    assert checkpoints[0]["phase"] == "planning"
    assert any(str(item.get("run_id", "")).startswith("run-") for item in checkpoints)
    assert len([item for item in checkpoints if item["phase"] == "running"]) >= 2 * len(
        result["steps"]
    )
    configured_ms = profile.budgets.max_seconds * 1000
    assert all(1 <= call[0]["limits"]["timeout_ms"] <= configured_ms for call in runner.calls)
    assert runner.calls[0][0]["limits"]["timeout_ms"] < configured_ms


def test_overall_time_budget_refuses_further_effects_but_uses_cleanup_reserve(
    tmp_path: Path,
) -> None:
    runner = SlowFirstRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    base_profile = _execute_profile()
    profile = replace(
        base_profile,
        budgets=replace(base_profile.budgets, max_seconds=1),
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "deadline-sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert result["runtime_budget"]["exhausted"] is True
    assert rows["transform_fixture"]["status"] == "blocked"
    assert rows["transform_fixture"]["error"]["code"] == "runtime_budget_exhausted"
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]


def test_transport_failure_discovers_fsynced_receipt_and_forces_cleanup(
    tmp_path: Path,
) -> None:
    runner = ReceiptThenTransportFailureRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    sandbox = tmp_path / "receipt-failure-sandbox"

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=sandbox,
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert rows["create_fixture"]["status"] == "failed"
    assert rows["create_fixture"]["receipts"] == [runner.RECEIPT_ID]
    assert rows["cleanup_workspace"]["status"] == "success"
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]
    cleanup_manifest = runner.calls[-1][0]
    assert cleanup_manifest["params"]["receipt_ids"] == [runner.RECEIPT_ID]
    assert not (sandbox / ".bluefire" / "receipts" / f"{runner.RECEIPT_ID}.json").exists()
    assert (sandbox / ".bluefire" / "receipts" / f"{runner.UNRELATED_RECEIPT_ID}.json").exists()


def test_success_cannot_claim_an_uncommitted_receipt(tmp_path: Path) -> None:
    runner = UncommittedSuccessRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "uncommitted-success-sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    create = rows["create_fixture"]
    assert create["status"] == "failed"
    assert create["error"]["code"] == "runner_transport_failed"
    assert "committed" in create["error"]["message"]
    assert create["receipts"]
    assert rows["cleanup_workspace"]["status"] == "success"
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]


def test_missing_independent_observation_is_explicit_unknown_evidence(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    delivery = _evidence_by_step(result, "create_fixture")
    assert [row["provenance"] for row in delivery] == ["executed", "unknown"]
    assert delivery[0]["producer"] == "bluefire-rust-runner"
    assert delivery[1]["producer"] == "sandbox-observer.v1"
    assert delivery[1]["content"]["artifact_type"] == "evidence_gap"
    assert delivery[1]["parent_evidence_ids"] == [delivery[0]["evidence_id"]]


def test_execute_observable_paths_can_be_bound_to_declared_collector(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    collector_ids = ("collector.filesystem.sandbox.v1",)
    collector_binding = {
        "schema_version": "bluefire.collector-binding.v1",
        "collectors": list(collector_ids),
        "authority": "declared-per-run-observable-artifacts",
    }

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        collector_ids=collector_ids,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
            context={"collector_binding": collector_binding},
        ),
    )

    delivery = _evidence_by_step(result, "create_fixture")
    assert [row["provenance"] for row in delivery] == ["executed", "unknown"]
    assert delivery[0]["producer"] == "bluefire-rust-runner"
    assert delivery[1]["producer"] == "collector.filesystem.sandbox.v1"
    assert delivery[1]["content"]["artifact_type"] == "evidence_gap"
    assert delivery[1]["content"]["requested_artifact"] == "fixtures/input.jsonl"
    assert delivery[1]["parent_evidence_ids"] == [delivery[0]["evidence_id"]]


def test_execute_persists_approval_bound_runtime_collector_session(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    orchestrator = Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=StructuredFakeRunner(),
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
        collector_registry=CollectorRegistry((FilesystemCollector(sandbox),)),
    )
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            }
        }
    )
    collector_binding = Orchestrator._collector_binding((), runtime)
    assert orchestrator.collector_registry is not None
    collector_authority = orchestrator.collector_registry.authority_snapshot(
        runtime,
        expected_sandbox=sandbox,
    )

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=sandbox,
        target_scope=FULL_TARGET_SCOPE,
        collector_runtime_settings=runtime,
        collector_registry_authority=collector_authority,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
            context={
                "collector_binding": collector_binding,
                "collector_registry_authority": collector_authority,
            },
        ),
    )

    assert result["collector_session"]["settings_hash"] == runtime.settings_hash
    collector_record = next(
        row
        for row in result["evidence"]["records"]
        if row["producer"] == FilesystemCollector.descriptor.id
    )
    stage = _rows_by_step(result)["stage_records"]
    assert collector_record["run_id"] == result["run_id"]
    assert collector_record["provenance"] == "unknown"
    assert collector_record["evidence_id"] in stage["evidence_ids"]
    assert collector_record["parent_evidence_ids"] == [stage["evidence_ids"][0]]
    assert all(row["producer"] != "sandbox-observer.v1" for row in result["evidence"]["records"])


def test_retry_collector_session_retains_worst_health_and_all_attempt_evidence(
    tmp_path: Path,
) -> None:
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {"paths": ["retry-observed.txt"]},
            }
        }
    )
    registry = CollectorRegistry((FilesystemCollector(tmp_path),))

    def collect(parent: str) -> CollectionSession:
        return registry.collect_configured(
            runtime,
            CollectionRequest(
                run_id="run-retry",
                step_id="stage_records",
                behavior_id="collection.independent-observation.v1",
                action_id="sandbox.collection.stage.v1",
                runner_profile_id="profile.test.v1",
                target_scope_ref="runner-profile:profile.test.v1",
                parent_evidence_ids=(parent,),
            ),
        )

    first = collect("evidence-first")
    (tmp_path / "retry-observed.txt").write_text("observed", encoding="utf-8")
    second = collect("evidence-second")

    merged = Orchestrator._merge_collection_sessions(first, second)
    result = merged.results[FilesystemCollector.descriptor.id]
    assert result.health.readiness is CollectorReadiness.DEGRADED
    assert result.health.details["attempt_count"] == 2
    assert result.health.details["observation_count"] == 1
    assert result.health.details["gap_count"] == 1
    assert len(result.records) == 2


def test_collector_schedule_must_be_reachable_from_replay_continuation(
    tmp_path: Path,
) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    plan = Orchestrator(load_builtin_registry(), RunStore(tmp_path / "runs")).planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
    )
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            }
        }
    )

    with pytest.raises(OrchestrationError, match="not reachable from the continuation"):
        Orchestrator._collector_schedule(
            plan,
            runtime,
            start_step_id="cleanup_workspace",
        )


def test_runner_task_identity_matches_the_authenticated_execute_payload() -> None:
    manifest = {
        "request_id": "request-first",
        "request_hash": "sha256:" + "1" * 64,
    }
    profile = {"policy_digest": "sha256:" + "2" * 64}

    first = Orchestrator._execution_task_id(manifest, profile)
    authenticated, request_hash = AuthenticatedRunnerClient.execution_identity(
        manifest,
        profile,
    )
    retry_manifest = {**manifest, "request_id": "request-retry"}
    retry = Orchestrator._execution_task_id(retry_manifest, profile)

    assert request_hash == content_hash({"manifest": manifest, "profile": profile})
    assert first.startswith("execute-") and len(first) == 72
    assert first == authenticated
    assert retry.startswith("execute-") and len(retry) == 72
    assert first != retry


def test_approved_retry_transition_revisits_the_selected_node(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    orchestrator = Orchestrator(load_builtin_registry(), RunStore(tmp_path / "runs"))
    current = "try_loopback"
    applied, selected = orchestrator._approved_replay_transition(
        replay={
            "proposal_resolution": {
                "schema_version": "bluefire.ai-proposal-resolution-lineage.v3",
                "apply_after_step_id": current,
                "proposal_type": "retry_registered",
                "selected_step_id": current,
                "observed_outcome": "blocked",
            }
        },
        scenario=scenario,
        current_step_id=current,
        outcome=StepOutcome.BLOCKED,
        planner_decision=None,  # type: ignore[arg-type]
    )

    assert applied is True
    assert selected == current


def test_approved_retry_transition_refuses_a_changed_outcome(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    orchestrator = Orchestrator(load_builtin_registry(), RunStore(tmp_path / "runs"))
    current = "try_loopback"

    with pytest.raises(OrchestrationError, match="stale for the replayed outcome"):
        orchestrator._approved_replay_transition(
            replay={
                "proposal_resolution": {
                    "schema_version": "bluefire.ai-proposal-resolution-lineage.v3",
                    "apply_after_step_id": current,
                    "proposal_type": "retry_registered",
                    "selected_step_id": current,
                    "observed_outcome": "blocked",
                }
            },
            scenario=scenario,
            current_step_id=current,
            outcome=StepOutcome.SUCCESS,
            planner_decision=None,  # type: ignore[arg-type]
        )


def test_receiver_runtime_requires_task_aware_runner_before_approval(tmp_path: Path) -> None:
    orchestrator = Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=StructuredFakeRunner(),
    )
    runtime = CollectorRuntimeSettings(
        collectors={
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": True,
                "settings": {"collect_after_step": "stage_records"},
            }
        }
    )

    report = orchestrator.preflight(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
        approval_present=True,
        collector_runtime_settings=runtime,
    )

    assert report.status == "refused"
    assert "Receiver collection requires a task-aware runner transport." in report.problems


@pytest.mark.parametrize(
    ("runner_status", "step_status", "provenance"),
    [
        pytest.param("control_blocked", "blocked", "control_blocked", id="control-blocked"),
        pytest.param("failed", "failed", "executed", id="failed-after-dispatch"),
    ],
)
def test_structured_runner_status_preserves_provenance_branch_and_cleanup(
    tmp_path: Path,
    runner_status: str,
    step_status: str,
    provenance: str,
) -> None:
    runner = StructuredFakeRunner(network_status=runner_status)
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert rows["try_loopback"]["status"] == step_status
    assert rows["try_loopback"]["runner_status"] == runner_status
    assert rows["export_locally"]["status"] == "success"
    assert rows["cleanup_workspace"]["status"] == "success"
    assert result["objective_reached"] is True
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.discovery.list.v1",
        "sandbox.collection.stage.v1",
        "sandbox.network.loopback.v1",
        "sandbox.export.local.v1",
        "sandbox.cleanup.v1",
    ]
    cleanup_manifest = runner.calls[-1][0]
    assert cleanup_manifest["params"]["receipt_ids"] == [
        RECEIPT_IDS["sandbox.export.local.v1"],
        RECEIPT_IDS["sandbox.collection.stage.v1"],
        RECEIPT_IDS["sandbox.fixture.transform.v1"],
        RECEIPT_IDS["sandbox.fixture.create.v1"],
    ]
    assert all(str(call[0]["request_hash"]).startswith("sha256:") for call in runner.calls)
    assert all(str(call[1]["policy_digest"]).startswith("sha256:") for call in runner.calls)

    network_evidence = _evidence_by_step(result, "try_loopback")
    assert len(network_evidence) == 1
    assert network_evidence[0]["provenance"] == provenance
    assert network_evidence[0]["producer"] == "bluefire-rust-runner"
    assert network_evidence[0]["content"]["runner_status"] == runner_status
    assert network_evidence[0]["content"]["runner_evidence"] == [
        {"kind": "fake-runner", "status": runner_status}
    ]
    assert network_evidence[0]["content_hash"].startswith("sha256:")
    assert network_evidence[0]["record_hash"].startswith("sha256:")

    network_decision = next(
        decision
        for decision in result["planner_decisions"]
        if decision["selected_step_id"] == "export_locally"
    )
    assert network_decision["execution_disposition"] == "execute"
    assert network_decision["selected_edge"]["outcome"] == step_status


def test_profile_control_block_prevents_dispatch_but_keeps_real_fallback_and_cleanup(
    tmp_path: Path,
) -> None:
    raw = _execute_profile().to_dict()
    raw["blocked_actions"] = ["sandbox.network.loopback.v1"]
    profile = RunnerProfile.from_mapping(raw)
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    network = rows["try_loopback"]
    assert network["status"] == "blocked"
    assert network["policy"]["status"] == "control_blocked"
    assert network["error"]["code"] == "control_blocked"
    called_actions = [call[0]["action_id"] for call in runner.calls]
    assert "sandbox.network.loopback.v1" not in called_actions
    assert called_actions[-2:] == ["sandbox.export.local.v1", "sandbox.cleanup.v1"]
    assert result["objective_reached"] is True
    assert result["cleanup"]["outstanding_receipt_count"] == 0

    evidence = _evidence_by_step(result, "try_loopback")
    assert len(evidence) == 1
    assert evidence[0]["provenance"] == "control_blocked"
    assert evidence[0]["producer"] == "policy-engine.v1"
    assert evidence[0]["content"]["side_effects_started"] is False


def test_unexpected_post_effect_exception_dispatches_lifo_cleanup(tmp_path: Path) -> None:
    runner = StructuredFakeRunner()
    orchestrator = Orchestrator(
        load_builtin_registry(),
        FailAfterFirstEffectStore(tmp_path / "runs"),
        runner=runner,
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
    )
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(RuntimeError, match="injected event-store failure"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox",
            target_scope=FULL_TARGET_SCOPE,
            **_approval_kwargs(
                orchestrator,
                scenario=scenario,
                profile=profile,
                target_scope=FULL_TARGET_SCOPE,
            ),
        )

    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]
    assert runner.calls[-1][0]["params"]["receipt_ids"] == [
        RECEIPT_IDS["sandbox.fixture.create.v1"]
    ]


def test_execute_preflight_rejects_profile_that_blocks_cleanup(tmp_path: Path) -> None:
    raw = _execute_profile().to_dict()
    raw["blocked_actions"] = ["sandbox.cleanup.v1"]
    profile = RunnerProfile.from_mapping(raw)
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)

    report = orchestrator.preflight(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=True,
    )

    assert report.status == "refused"
    assert "control-blocks its required cleanup action" in " ".join(report.problems)
    assert runner.calls == []


def test_cleanup_success_requires_a_complete_runner_report(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path, IncompleteCleanupFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    cleanup = _rows_by_step(result)["cleanup_workspace"]
    assert cleanup["status"] == "failed"
    assert cleanup["error"]["code"] == "runner_transport_failed"
    assert result["cleanup"]["success"] is False
    assert result["cleanup"]["outstanding_receipt_count"] == 4
