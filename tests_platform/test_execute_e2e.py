from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from bluefire.contracts import load_scenario
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig
from bluefire.receiver_auth import derive_receiver_task_key
from bluefire.runner_client import SubprocessRustRunner
from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]
RUNNER_ENV = "BLUEFIRE_E2E_RUNNER"
E2E_ENROLLMENT_KEY = bytes(range(32))


@pytest.mark.skipif(
    not os.environ.get(RUNNER_ENV),
    reason=f"set {RUNNER_ENV} to a freshly built runner binary",
)
@pytest.mark.parametrize(
    ("scenario_name", "create_step", "stage_step", "required_behaviors"),
    [
        (
            "sandbox_research_chain.yaml",
            "create_fixture",
            "stage_records",
            {"sandbox.collection.stage.v1"},
        ),
        (
            "linux_container_validation.yaml",
            "create_fixture",
            "stage_records",
            {
                "endpoint.discovery.system.v1",
                "endpoint.discovery.processes.v1",
                "sandbox.discovery.recursive.v1",
                "sandbox.archive.tar.v1",
                "sandbox.network.loopback.v1",
            },
        ),
        (
            "windows_endpoint_validation.yaml",
            "create_fixture",
            "stage_fixture",
            {
                "endpoint.discovery.system.v1",
                "endpoint.discovery.processes.v1",
                "sandbox.discovery.recursive.v1",
                "sandbox.archive.tar.v1",
            },
        ),
    ],
)
def test_real_execute_chain_uses_rust_runner_observes_and_cleans(
    tmp_path: Path,
    scenario_name: str,
    create_step: str,
    stage_step: str,
    required_behaviors: set[str],
) -> None:
    runner_binary = Path(os.environ[RUNNER_ENV]).resolve(strict=True)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = SubprocessRustRunner(
        runner_binary,
        tmp_path / "transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
        receiver_task_key_factory=lambda task_id: derive_receiver_task_key(
            E2E_ENROLLMENT_KEY,
            task_id,
        ),
    )
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    scenario = load_scenario(ROOT / "scenarios" / scenario_name)
    needs_receiver = any(
        step.behavior_id == "sandbox.network.loopback.v1" for step in scenario.steps
    )
    receiver = (
        LoopbackArtifactReceiver(
            ReceiverConfig(
                authentication_key=E2E_ENROLLMENT_KEY,
                port=4317,
                max_requests=1,
            )
        )
        if needs_receiver
        else None
    )
    receiver_result: dict[str, Any] = {}
    receiver_thread = (
        threading.Thread(
            target=lambda: receiver_result.update(receiver.serve()),
            name="bluefire-e2e-loopback-receiver",
        )
        if receiver is not None
        else None
    )
    if receiver_thread is not None:
        receiver_thread.start()

    try:
        result = service.run(
            {
                "scenario": scenario.to_dict(),
                "mode": "execute",
                "runner_profile_id": "sandbox-execute.v1",
                "target_scope": {
                    "scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]
                },
                "autonomy": "off",
                "approval": {
                    "confirmed": True,
                    "approved_by": "integration-test-operator",
                },
            }
        )
    finally:
        if receiver_thread is not None:
            receiver_thread.join(timeout=5)
        if receiver is not None and receiver_thread is not None and receiver_thread.is_alive():
            receiver.close()
            receiver_thread.join(timeout=2)

    rows = {row["step_id"]: row for row in result["steps"]}
    assert result["objective_reached"] is True
    assert rows[create_step]["status"] == "success"
    assert rows[stage_step]["status"] == "success"
    assert rows["cleanup_workspace"]["status"] == "success"
    assert required_behaviors.issubset({str(row["behavior_id"]) for row in result["steps"]})
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    provenance = {row["provenance"] for row in result["evidence"]["records"]}
    assert {"executed", "observed"}.issubset(provenance)
    assert result["approval"]["status"] == "claimed"
    assert "nonce" not in result["approval"]
    assert service.store.validate_bundle(str(result["run_id"]))["valid"] is True
    assert not [path for path in sandbox.rglob("*") if path.is_file()]
    if needs_receiver:
        network_step = next(
            row for row in result["steps"] if row["behavior_id"] == "sandbox.network.loopback.v1"
        )
        assert network_step["status"] == "success", json.dumps(network_step, indent=2)
        assert receiver_result == {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }


@pytest.mark.skipif(
    not os.environ.get(RUNNER_ENV),
    reason=f"set {RUNNER_ENV} to a freshly built runner binary",
)
def test_restricted_canary_requires_narrow_profile_and_reconciles_to_zero(
    tmp_path: Path,
) -> None:
    runner_binary = Path(os.environ[RUNNER_ENV]).resolve(strict=True)
    # Keep the runner root comfortably below legacy Windows MAX_PATH after
    # approval-specific workspace and receipt components are appended.
    with tempfile.TemporaryDirectory(prefix="bf-restricted-") as short_root:
        sandbox = Path(short_root)
        runner = SubprocessRustRunner(
            runner_binary,
            tmp_path / "restricted-transport",
            timeout_seconds=30.0,
            output_limit_bytes=4 * 1024 * 1024,
        )
        service = BlueFireService(
            project_root=ROOT,
            runs_dir=tmp_path / "restricted-runs",
            product_db_path=tmp_path / "restricted-product.sqlite3",
            runner_factory=lambda _profile: (runner, sandbox),
        )
        scenario = load_scenario(ROOT / "scenarios" / "restricted_persistence_canary.yaml")

        result = service.run(
            {
                "scenario": scenario.to_dict(),
                "mode": "execute",
                "runner_profile_id": "sandbox-restricted-owned.v1",
                "target_scope": {"scope_refs": ["sandbox.workspace"]},
                "autonomy": "off",
                "approval": {
                    "confirmed": True,
                    "approved_by": "integration-test-operator",
                },
            }
        )

        rows = {row["step_id"]: row for row in result["steps"]}
        assert result["objective_reached"] is True
        assert rows["create_persistence_canary"]["action_id"] == (
            "sandbox.restricted.persistence-marker.v1"
        )
        assert rows["create_persistence_canary"]["status"] == "success"
        assert rows["cleanup_workspace"]["status"] == "success"
        assert result["cleanup"] == {
            "attempted": True,
            "success": True,
            "outstanding_receipt_count": 0,
        }
        assert service.store.validate_bundle(str(result["run_id"]))["valid"] is True
        assert not [path for path in sandbox.rglob("*") if path.is_file()]
