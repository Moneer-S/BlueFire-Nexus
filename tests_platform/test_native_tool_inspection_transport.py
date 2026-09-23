from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.runner_transport as wire
from bluefire.contracts import ContractError
from bluefire.native_tool_installations import SCHEMA, NativeToolInstallation
from bluefire.native_tool_readiness import validate_native_tool_inspection
from bluefire.runner_client import (
    InventoryBoundRunner,
    RunnerReadinessError,
    SubprocessRustRunner,
    canonical_runner_inventory,
    runner_transport_identity,
)
from bluefire.runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    RunnerRemoteError,
)
from bluefire.tool_adapters.chmod import CONTRACT
from bluefire.util import file_hash
from tests_platform import test_authenticated_runner_transport as transport_support


@pytest.fixture
def secret_provider() -> Any:
    return transport_support.InMemorySecretProvider()


@pytest.fixture
def enrollment_root(tmp_path: Path, secret_provider: Any) -> Path:
    root = tmp_path / "trust"
    transport_support.create_local_enrollment(
        root,
        runner_id=transport_support.RUNNER_ID,
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=[transport_support.PROFILE_ID],
        secret_provider=secret_provider,
    )
    return root


def record() -> dict[str, object]:
    return {
        "schema_version": SCHEMA,
        "adapter_id": "sandbox.permission.chmod.v1",
        "adapter_version": "1.0.0",
        "adapter_contract_digest": CONTRACT.digest,
        "tool_id": "gnu.coreutils.chmod.v1",
        "tool_version": "9.5",
        "platform": "linux",
        "architecture": "x86_64",
        "content_sha256": "sha256:" + "b" * 64,
        "size_bytes": 1234,
        "installation_location": "/usr/bin/chmod",
    }


def result(record_value: dict[str, object], **changes: object) -> dict[str, object]:
    installation = NativeToolInstallation.from_mapping(record_value)
    return {
        "schema_version": "bluefire.native-tool-inspection.v1",
        "installation_digest": installation.digest,
        "status": "ready",
        "code": "verified",
        "content_sha256": record_value["content_sha256"],
        "size_bytes": record_value["size_bytes"],
        "platform": "linux",
        "architecture": "x86_64",
        **changes,
    }


def transport_record() -> dict[str, object]:
    value = record()
    value["adapter_id"] = "sandbox.fixture.create.v1"
    return value


class InspectingRunner:
    timeout_seconds = 10.0

    def __init__(self, *, binary: Path | None = None) -> None:
        self.binary = binary
        self.inspect_calls = 0
        self.execute_calls = 0

    def inventory(self) -> Mapping[str, Any]:
        inventory = dict(transport_support._inventory())
        inventory["platform"] = "linux"
        inventory["actions"] = [
            *inventory["actions"],
            {
                "schema_version": "bluefire.runner-action-sdk.v1",
                "action_id": "sandbox.permission.chmod.v1",
                "action_version": "1.0.0",
                "readiness": "structural",
                "native_tool_binding": {
                    "adapter_id": "sandbox.permission.chmod.v1",
                    "adapter_version": "1.0.0",
                    "adapter_contract_digest": CONTRACT.digest,
                    "tool_id": "gnu.coreutils.chmod.v1",
                },
            },
        ]
        return inventory

    def inspect_native_tool(self, installation: Mapping[str, Any]) -> Mapping[str, Any]:
        self.inspect_calls += 1
        if self.binary is not None:
            self.binary.write_bytes(b"changed-runner")
        return result(dict(installation))

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.execute_calls += 1
        raise AssertionError("native inspection must not dispatch execute")


def test_inspection_result_is_bound_to_full_record() -> None:
    value = record()
    assert validate_native_tool_inspection(value, result(value))["code"] == "verified"
    changed = dict(value, tool_version="9.6")
    with pytest.raises(ContractError):
        validate_native_tool_inspection(changed, result(value))


def test_unavailable_result_carries_no_success_evidence() -> None:
    value = record()
    unavailable = result(
        value,
        status="unavailable",
        code="inspection_unavailable",
        content_sha256=None,
        size_bytes=None,
    )
    assert validate_native_tool_inspection(value, unavailable)["status"] == "unavailable"
    with pytest.raises(ContractError):
        validate_native_tool_inspection(value, result(value, status="unavailable", code="verified"))


def test_unavailable_host_identity_is_preserved_without_becoming_success() -> None:
    value = record()
    unavailable = result(
        value,
        status="unavailable",
        code="unsupported_platform",
        platform="windows",
        architecture="aarch64",
        content_sha256=None,
        size_bytes=None,
    )
    assert validate_native_tool_inspection(value, unavailable)["platform"] == "windows"


@pytest.mark.parametrize("field", ["status", "code", "platform", "architecture"])
def test_inspection_result_rejects_unhashable_identity_fields(field: str) -> None:
    value = record()
    invalid = result(value)
    invalid[field] = []
    with pytest.raises(ContractError):
        validate_native_tool_inspection(value, invalid)


def test_subprocess_inspection_uses_private_canonical_record_file(tmp_path: Path) -> None:
    runner = object.__new__(SubprocessRustRunner)
    runner.work_root = tmp_path
    runner.runner_binary = Path("/opt/bluefire/runner")
    seen: dict[str, object] = {}

    def invoke(argv: list[str]) -> bytes:
        assert argv[1:] == [
            "inspect-native-tool",
            "--installation",
            argv[3],
            "--json",
        ]
        path = Path(argv[3])
        assert path.is_relative_to(tmp_path)
        seen["record"] = json.loads(path.read_text(encoding="utf-8"))
        return json.dumps(result(record())).encode()

    runner._invoke = invoke  # type: ignore[method-assign]
    observed = runner.inspect_native_tool(record())
    assert observed["code"] == "verified"
    assert seen["record"] == record()
    assert list(tmp_path.iterdir()) == []


def test_subprocess_inspection_cleans_private_record_on_invalid_result(tmp_path: Path) -> None:
    runner = object.__new__(SubprocessRustRunner)
    runner.work_root = tmp_path
    runner.runner_binary = Path("/opt/bluefire/runner")
    runner._invoke = lambda _argv: json.dumps({"unexpected": True}).encode()  # type: ignore[method-assign]
    with pytest.raises(ContractError):
        runner.inspect_native_tool(record())
    assert list(tmp_path.iterdir()) == []


def test_authenticated_client_sends_exact_installation_payload(monkeypatch) -> None:
    client = object.__new__(AuthenticatedRunnerClient)
    client.profile_id = "profile.execute.v1"
    captured: dict[str, object] = {}

    def call(operation, payload, *, task_id, request_hash=None, abort_event=None):
        captured.update({"operation": operation, "payload": payload, "task_id": task_id})
        return {"inspection": result(record())}

    client._call = call  # type: ignore[method-assign]
    observed = client.inspect_native_tool(record())
    assert observed["code"] == "verified"
    assert captured["operation"] == "inspect_native_tool"
    assert set(captured["payload"]) == {"installation"}  # type: ignore[arg-type]


def test_authenticated_server_routes_exact_inspection_without_execute(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
) -> None:
    runner = InspectingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        inspected = transport_support._client(
            enrollment_root, server, secret_provider
        ).inspect_native_tool(record())
    assert inspected["code"] == "verified"
    assert runner.inspect_calls == 1
    assert runner.execute_calls == 0


def test_authenticated_server_refuses_unbound_fixture_action_before_inspection(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
) -> None:
    runner = InspectingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerRemoteError) as caught:
            transport_support._client(enrollment_root, server, secret_provider).inspect_native_tool(
                transport_record()
            )
    assert caught.value.code == "runner_failure"
    assert runner.inspect_calls == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action_version", "9.9.9"),
        ("adapter_contract_digest", "sha256:" + "c" * 64),
        ("tool_id", "gnu.coreutils.other.v1"),
    ],
)
def test_authenticated_server_refuses_mismatched_compiled_binding_before_inspection(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    runner = InspectingRunner()
    original_inventory = runner.inventory

    def inventory_with_mismatch() -> Mapping[str, Any]:
        inventory = dict(original_inventory())
        actions = [dict(action) for action in inventory["actions"]]
        chmod = dict(actions[-1])
        if field == "action_version":
            chmod[field] = value
        else:
            binding = dict(chmod["native_tool_binding"])
            binding[field] = value
            chmod["native_tool_binding"] = binding
        actions[-1] = chmod
        inventory["actions"] = actions
        return inventory

    runner.inventory = inventory_with_mismatch  # type: ignore[method-assign]
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerRemoteError) as caught:
            transport_support._client(enrollment_root, server, secret_provider).inspect_native_tool(
                record()
            )
    assert caught.value.code == "runner_failure"
    assert runner.inspect_calls == 0


def test_authenticated_server_rejects_extra_installation_fields(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
) -> None:
    installation = dict(transport_record(), extra="reject")
    with AuthenticatedRunnerServer(
        enrollment_root,
        InspectingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        enrollment = transport_support.load_local_enrollment(
            enrollment_root, secret_provider=secret_provider
        )
        unsigned = transport_support._unsigned_request(
            enrollment,
            operation="inspect_native_tool",
            task_id="inspect-extra",
            payload={"installation": installation},
        )
        response = transport_support._raw_exchange_enrollment(
            enrollment, server, wire._sign_request(enrollment, unsigned)
        )
    assert response["status"] == "refused"
    assert response["error_code"] == "request_invalid"


def test_authenticated_server_fails_closed_without_optional_inspector(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
) -> None:
    class InventoryOnlyRunner:
        def inventory(self) -> Mapping[str, Any]:
            return InspectingRunner().inventory()

    with AuthenticatedRunnerServer(
        enrollment_root,
        InventoryOnlyRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerRemoteError) as caught:
            transport_support._client(enrollment_root, server, secret_provider).inspect_native_tool(
                record()
            )
    assert caught.value.code == "request_invalid"


def test_authenticated_server_rejects_runner_binary_change_during_inspection(
    enrollment_root: Path,
    secret_provider,
    tmp_path: Path,
) -> None:
    binary = tmp_path / "runner"
    binary.write_bytes(b"runner-v1")
    runner = InspectingRunner(binary=binary)
    runner.runner_binary = binary
    runner.runner_binary_digest = file_hash(binary)
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerRemoteError) as caught:
            transport_support._client(enrollment_root, server, secret_provider).inspect_native_tool(
                record()
            )
    assert caught.value.code == "runner_failure"
    assert runner.inspect_calls == 1


def test_inventory_bound_inspection_requires_unchanged_identity_and_inventory() -> None:
    class StableRunner(InspectingRunner):
        def __init__(self, inventory_rows: list[Mapping[str, Any]]) -> None:
            super().__init__()
            self.inventory_rows = inventory_rows
            self.inventory_calls = 0

        def inventory(self) -> Mapping[str, Any]:
            row = self.inventory_rows[min(self.inventory_calls, len(self.inventory_rows) - 1)]
            self.inventory_calls += 1
            return row

    value = record()
    raw = transport_support._inventory()
    canonical = canonical_runner_inventory(raw)
    runner = StableRunner([raw, raw])
    bound = InventoryBoundRunner(
        runner,
        expected_inventory_digest=transport_support.content_hash(canonical),
        expected_identity_digest=transport_support.content_hash(
            runner_transport_identity(runner, raw)
        ),
        recovery_identity={},
    )
    assert bound.inspect_native_tool(value)["code"] == "verified"
    assert runner.inventory_calls == 2
    assert runner.execute_calls == 0


@pytest.mark.parametrize("change", ["inventory", "binary"])
def test_inventory_bound_inspection_refuses_drift_without_execute(
    tmp_path: Path, change: str
) -> None:
    class DriftingRunner(InspectingRunner):
        def __init__(self) -> None:
            binary = tmp_path / "runner"
            binary.write_bytes(b"runner-v1")
            super().__init__(binary=binary if change == "binary" else None)
            if self.binary is not None:
                self.runner_binary = self.binary
                self.runner_binary_digest = file_hash(self.binary)
            self.inventory_calls = 0

        def inventory(self) -> Mapping[str, Any]:
            self.inventory_calls += 1
            value = dict(transport_support._inventory())
            if change == "inventory" and self.inventory_calls > 1:
                value["runner_version"] = "0.2.0"
            return value

    runner = DriftingRunner()
    initial = runner.inventory()
    canonical = canonical_runner_inventory(initial)
    bound = InventoryBoundRunner(
        runner,
        expected_inventory_digest=transport_support.content_hash(canonical),
        expected_identity_digest=transport_support.content_hash(
            runner_transport_identity(runner, initial)
        ),
        recovery_identity={},
    )
    with pytest.raises(RunnerReadinessError):
        bound.inspect_native_tool(record())
    assert runner.execute_calls == 0
