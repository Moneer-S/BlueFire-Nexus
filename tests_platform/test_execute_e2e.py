from __future__ import annotations

import base64
import copy
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_packages import (
    build_signed_action_package,
    canonical_public_key_b64u,
)
from bluefire.contracts import load_scenario
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig
from bluefire.receiver_auth import derive_receiver_task_key
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_trust import create_local_enrollment
from bluefire.service import BlueFireService
from tests_platform.test_action_package_lifecycle import (
    ACTION_ID as PACKAGE_ACTION_ID,
)
from tests_platform.test_action_package_lifecycle import (
    BEHAVIOR_ID as PACKAGE_BEHAVIOR_ID,
)
from tests_platform.test_action_package_lifecycle import (
    KEY_ID as PACKAGE_KEY_ID,
)
from tests_platform.test_action_package_lifecycle import (
    PACKAGE_ID,
    PUBLISHER_ID,
)
from tests_platform.test_action_package_lifecycle import (
    _manifest as package_manifest,
)
from tests_platform.test_action_package_lifecycle import (
    _payload as package_payload,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER_ENV = "BLUEFIRE_E2E_RUNNER"
E2E_ENROLLMENT_KEY = bytes(range(32))


def _scenario_with_bound_loopback_port(
    scenario_document: dict[str, Any], *, port: int
) -> dict[str, Any]:
    assert isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65_535
    rebound_scenario = copy.deepcopy(scenario_document)
    steps = rebound_scenario.get("steps")
    assert isinstance(steps, list)
    loopback_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("behavior_id") == "sandbox.network.loopback.v1"
    ]
    assert len(loopback_steps) == 1
    parameters = loopback_steps[0].get("parameters")
    assert isinstance(parameters, dict)
    parameters["port"] = port
    return rebound_scenario


def _read_process_line(stream: Any, *, timeout_seconds: float) -> str:
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=lambda: lines.put(stream.readline()), daemon=True)
    reader.start()
    try:
        return lines.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise AssertionError(
            "receiver did not publish readiness within the bounded deadline"
        ) from exc


def _start_disposable_peer_receiver(
    tmp_path: Path,
) -> tuple[subprocess.Popen[str], dict[str, Any], bytes]:
    if os.name != "nt":
        pytest.skip("managed disposable receiver enrollment currently requires Windows DPAPI")
    state_root = tmp_path / "receiver-state"
    enrollment = create_local_enrollment(
        state_root / "BlueFire Nexus" / "enrollment",
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=("sandbox-endpoint-deep-lab.v1", "sandbox-execute.v1"),
    )
    child_environment = {
        name: os.environ[name]
        for name in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if name in os.environ
    }
    child_environment["LOCALAPPDATA"] = str(state_root)
    child_environment["PYTHONPATH"] = os.pathsep.join(
        (str(ROOT), str(Path(sys.prefix) / "Lib" / "site-packages"))
    )
    child_environment["PYTHONIOENCODING"] = "utf-8"
    child_environment["PYTHONUTF8"] = "1"
    receiver_python = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    process = subprocess.Popen(
        [
            str(receiver_python),
            "-m",
            "bluefire.cli",
            "receiver",
            "--host",
            "127.0.0.1",
            "--port",
            "4317",
            "--max-requests",
            "1",
            "--disposable-peer",
        ],
        cwd=ROOT,
        env=child_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        assert process.stderr is not None
        ready_line = _read_process_line(process.stderr, timeout_seconds=10.0)
        if not ready_line:
            stdout, stderr = process.communicate(timeout=10)
            raise AssertionError(f"receiver exited before readiness: {stdout!r} {stderr!r}")
        ready = json.loads(ready_line)
        assert ready == {
            "schema_version": "bluefire.loopback-receiver-ready.v2",
            "mode": "disposable_peer",
            "process_id": process.pid,
            "host": "127.0.0.1",
            "port": 4317,
            "max_requests": 1,
            "max_connections": 8,
            "storage": "memory_only",
        }
    except BaseException:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        raise
    return process, ready, enrollment.hmac_key()


@pytest.mark.skipif(
    not os.environ.get(RUNNER_ENV),
    reason=f"set {RUNNER_ENV} to a freshly built runner binary",
)
def test_signed_package_alias_executes_through_real_native_runner(tmp_path: Path) -> None:
    runner_binary = Path(os.environ[RUNNER_ENV]).resolve(strict=True)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = SubprocessRustRunner(
        runner_binary,
        tmp_path / "transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
    )
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    key = Ed25519PrivateKey.generate()
    envelope = json.loads(
        build_signed_action_package(
            manifest=package_manifest("1.2.3"),
            payload=package_payload(),
            key_id=PACKAGE_KEY_ID,
            private_key=key,
        )
    )
    profile = next(item for item in service.config.runner_profiles if item.mode.value == "execute")
    try:
        service.trust_action_package_publisher(
            {
                "publisher_id": PUBLISHER_ID,
                "key_id": PACKAGE_KEY_ID,
                "public_key": canonical_public_key_b64u(key.public_key()),
                "provenance": {
                    "source": "local native acceptance",
                    "purpose": "verify signed package alias execution",
                },
                "trusted_by": "native-acceptance-reviewer",
            }
        )
        service.install_action_package(
            {"envelope": envelope, "installed_by": "native-acceptance-installer"}
        )
        activated = service.activate_action_package(
            PACKAGE_ID,
            "1.2.3",
            {
                "runner_profile_id": profile.id,
                "activated_by": "native-acceptance-operator",
                "reason": "prove an exact reviewed alias through the native boundary",
            },
        )
        result = service.run(
            {
                "scenario": {
                    "schema_version": "bluefire.scenario.v1",
                    "id": "scenario.package.native-alias.v1",
                    "title": "Native signed-package alias acceptance",
                    "purpose": "Execute one reviewed logical alias through its bound native opcode.",
                    "start": "observe_system",
                    "steps": [
                        {
                            "id": "observe_system",
                            "behavior_id": PACKAGE_BEHAVIOR_ID,
                        }
                    ],
                    "edges": [],
                    "provenance": {
                        "source": "BlueFire native acceptance",
                        "reference": "scenario.package.native-alias.v1",
                        "license": "MIT",
                        "derived": False,
                        "notes": "No external content.",
                    },
                    "limitations": ["Observes bounded operating-system identity only."],
                },
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
                "approval": {
                    "confirmed": True,
                    "approved_by": "native-acceptance-reviewer",
                },
            }
        )
    finally:
        service.close()

    assert activated["catalog"]["generation"] == 1
    assert result["status"] == "completed"
    assert result["objective_reached"] is True
    assert result["steps"][0]["behavior_id"] == PACKAGE_BEHAVIOR_ID
    assert result["steps"][0]["action_id"] == PACKAGE_ACTION_ID
    assert result["steps"][0]["status"] == "success"
    assert result["policy"]["preflight"]["catalog_authority"]["generation"] == 1
    assert not [path for path in sandbox.rglob("*") if path.is_file()]


def test_bound_loopback_port_rewrite_clones_and_changes_only_the_port() -> None:
    scenario_document = load_scenario(
        ROOT / "scenarios" / "linux_container_validation.yaml"
    ).to_dict()
    with LoopbackArtifactReceiver(
        ReceiverConfig(authentication_key=E2E_ENROLLMENT_KEY, port=0)
    ) as receiver:
        bound_port = receiver.port
        assert 1 <= bound_port <= 65_535
        expected = copy.deepcopy(scenario_document)
        expected_loopback_step = next(
            step
            for step in expected["steps"]
            if step["behavior_id"] == "sandbox.network.loopback.v1"
        )
        expected_loopback_step["parameters"]["port"] = bound_port
        rebound_scenario = _scenario_with_bound_loopback_port(
            scenario_document,
            port=bound_port,
        )

    assert rebound_scenario == expected
    assert rebound_scenario is not scenario_document
    original_loopback_step = next(
        step
        for step in scenario_document["steps"]
        if step["behavior_id"] == "sandbox.network.loopback.v1"
    )
    assert original_loopback_step["parameters"]["port"] == 4_317


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
        (
            "operator_representative_validation.yaml",
            "create_fixture",
            "stage_records",
            {
                "sandbox.execution.native-canary.v1",
                "sandbox.identity-material.seed.v1",
                "sandbox.identity-material.inspect.v1",
                "sandbox.observability.variant.v1",
                "sandbox.peer.handoff.v1",
            },
        ),
        (
            "endpoint_deep_behavior_lab.yaml",
            "create_fixture",
            "stage_records",
            {
                "sandbox.execution.native-canary.v1",
                "endpoint.discovery.system.v1",
                "endpoint.discovery.processes.v1",
                "sandbox.restricted.persistence-marker.v1",
                "sandbox.collection.stage.v1",
                "sandbox.observability.variant.v1",
                "sandbox.credential.peer-challenge.v1",
                "sandbox.cleanup.v1",
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
    scenario = load_scenario(ROOT / "scenarios" / scenario_name)
    peer_receiver_required = any(
        step.behavior_id in {"sandbox.credential.peer-challenge.v1", "sandbox.peer.handoff.v1"}
        for step in scenario.steps
    )
    receiver_process: subprocess.Popen[str] | None = None
    receiver_ready: dict[str, Any] | None = None
    receiver_enrollment_key = E2E_ENROLLMENT_KEY
    if peer_receiver_required:
        receiver_process, receiver_ready, receiver_enrollment_key = _start_disposable_peer_receiver(
            tmp_path
        )
    receiver_task_keys: list[bytes] = []

    def receiver_task_key(task_id: str) -> bytes:
        key = derive_receiver_task_key(receiver_enrollment_key, task_id)
        receiver_task_keys.append(key)
        return key

    runner = SubprocessRustRunner(
        runner_binary,
        tmp_path / "transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
        receiver_task_key_factory=receiver_task_key,
    )
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    generic_receiver_required = any(
        step.behavior_id == "sandbox.network.loopback.v1" for step in scenario.steps
    )
    scenario_document = scenario.to_dict()
    receiver = (
        LoopbackArtifactReceiver(
            ReceiverConfig(
                authentication_key=E2E_ENROLLMENT_KEY,
                port=0,
                max_requests=1,
            )
        )
        if generic_receiver_required
        else None
    )
    if receiver is not None:
        scenario_document = _scenario_with_bound_loopback_port(
            scenario_document,
            port=receiver.port,
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
                "scenario": scenario_document,
                "mode": "execute",
                "runner_profile_id": (
                    "sandbox-endpoint-deep-lab.v1"
                    if scenario_name == "endpoint_deep_behavior_lab.yaml"
                    else "sandbox-execute.v1"
                ),
                "target_scope": {
                    "scope_refs": (
                        ["sandbox.workspace", "network.loopback"]
                        if scenario_name == "endpoint_deep_behavior_lab.yaml"
                        else ["sandbox.workspace", "network.loopback", "export.local"]
                    )
                },
                "autonomy": "off",
                "approval": {
                    "confirmed": True,
                    "approved_by": "integration-test-operator",
                },
            }
        )
        if receiver_process is not None and result["objective_reached"] is True:
            receiver_process.wait(timeout=10)
    finally:
        if receiver_thread is not None:
            receiver_thread.join(timeout=5)
        if receiver is not None and receiver_thread is not None and receiver_thread.is_alive():
            receiver.close()
            receiver_thread.join(timeout=2)
        if receiver_process is not None and receiver_process.poll() is None:
            receiver_process.terminate()
            receiver_process.wait(timeout=5)

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
    if generic_receiver_required or peer_receiver_required:
        network_step = next(
            row
            for row in result["steps"]
            if row["behavior_id"]
            in {
                "sandbox.network.loopback.v1",
                "sandbox.credential.peer-challenge.v1",
                "sandbox.peer.handoff.v1",
            }
        )
        assert network_step["status"] == "success", json.dumps(network_step, indent=2)
        expected_receiver_result = {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
        receiver_stdout = ""
        receiver_stderr = ""
        if receiver_process is not None:
            receiver_stdout, receiver_stderr = receiver_process.communicate(timeout=10)
            receiver_result = json.loads(receiver_stdout)
            assert receiver_process.returncode == 0
            assert receiver_stderr == ""
        assert receiver_result == expected_receiver_result
        if network_step["behavior_id"] in {
            "sandbox.credential.peer-challenge.v1",
            "sandbox.peer.handoff.v1",
        }:
            receipt = network_step["artifacts"]["receipt"]
            authorization = receipt["lab_authorization"]
            peers = receipt["lab_peers"]
            assert authorization["scope"] == "approved_task"
            assert authorization["challenge_verified"] is True
            assert authorization["raw_credential_exposed"] is False
            assert len(authorization["credential_handle"]) == 64
            assert peers["scope"] == "authorized_disposable_loopback_lab"
            assert peers["distinct_processes"] is True
            assert peers["transfer_acknowledged"] is True
            assert peers["source_process_id"] != peers["destination_process_id"]
            assert receiver_ready is not None
            assert peers["destination_process_id"] == receiver_ready["process_id"]
            assert peers["source_handle"] != peers["destination_handle"]
            rendered = json.dumps(result, sort_keys=True) + receiver_stdout + receiver_stderr
            evidence_payloads = [rendered.encode("utf-8")]
            evidence_payloads.extend(
                path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()
            )
            for secret in [receiver_enrollment_key, *receiver_task_keys]:
                encodings = {
                    secret,
                    secret.hex().encode("ascii"),
                    secret.hex().upper().encode("ascii"),
                    base64.b64encode(secret),
                    base64.b32encode(secret),
                    base64.urlsafe_b64encode(secret),
                    base64.urlsafe_b64encode(secret).rstrip(b"="),
                }
                assert all(
                    encoding not in payload
                    for encoding in encodings
                    for payload in evidence_payloads
                )


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
