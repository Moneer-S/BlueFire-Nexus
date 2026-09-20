from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from bluefire.native_tool_setup_transport import managed_setup_transport
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError


class FakeClient:
    socket_timeout_seconds = 10.0

    def __init__(self) -> None:
        self.inventory_calls = 0
        self.identity_calls = 0
        self.inspect_calls = 0

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        return {"platform": "linux", "actions": []}

    def transport_identity(self) -> Mapping[str, Any]:
        self.identity_calls += 1
        return {"schema_version": "bluefire.runner-transport-identity.v1"}

    def inspect_native_tool_candidate(self, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        self.inspect_calls += 1
        return {"candidate": dict(candidate)}


class FakeLifecycle:
    def __init__(self, *, status: Mapping[str, Any], client: FakeClient | None = None) -> None:
        self._status = status
        self.client = client or FakeClient()
        self.client_for_profile_calls: list[str] = []

    def status(self) -> Mapping[str, Any]:
        return self._status

    def client_for_profile(self, profile_id: str):
        self.client_for_profile_calls.append(profile_id)
        return self.client, Path("C:/managed/sandbox")


def ready_status() -> dict[str, Any]:
    return ManagedRunnerLifecycle._status_payload(
        SimpleNamespace(runner_id="runner.test"),
        state="ready",
        enrollment_state="active",
        process_state="authenticated",
        profile_id="profile.execute.v1",
    )


def test_setup_transport_binds_default_authenticated_host_without_execute() -> None:
    lifecycle = FakeLifecycle(status=ready_status())
    transport = managed_setup_transport(lifecycle)

    assert lifecycle.client_for_profile_calls == ["profile.execute.v1"]
    assert not hasattr(transport, "execute")
    assert transport.timeout_seconds == 15.0
    assert lifecycle.client.socket_timeout_seconds == 15.0
    candidate = {"action_id": "sandbox.permission.chmod.v1"}
    assert transport.inspect_native_tool_candidate(candidate)["candidate"] == candidate
    assert lifecycle.client.inspect_calls == 1


@pytest.mark.parametrize(
    "status",
    [
        ManagedRunnerLifecycle._status_payload(
            SimpleNamespace(runner_id="runner.test"),
            state="stopped",
            enrollment_state="active",
            process_state="absent",
        ),
        ManagedRunnerLifecycle._status_payload(
            SimpleNamespace(runner_id="runner.test"),
            state="ready",
            enrollment_state="absent",
            process_state="authenticated",
        ),
        ManagedRunnerLifecycle._status_payload(
            SimpleNamespace(runner_id="runner.test"),
            state="ready",
            enrollment_state="active",
            process_state="stale",
        ),
    ],
)
def test_setup_transport_refuses_missing_or_nonready_host(status: Mapping[str, Any]) -> None:
    lifecycle = FakeLifecycle(status=status)
    with pytest.raises(RunnerLifecycleError, match="not authenticated and ready"):
        managed_setup_transport(lifecycle)
    assert not lifecycle.client_for_profile_calls


def test_setup_transport_uses_only_enrolled_default_profile() -> None:
    lifecycle = FakeLifecycle(status=ready_status())
    transport = managed_setup_transport(lifecycle)

    assert lifecycle.client_for_profile_calls == ["profile.execute.v1"]
    assert transport.inspect_native_tool_candidate({"candidate": "draft"})["candidate"] == {
        "candidate": "draft"
    }


def test_setup_transport_refuses_host_change_before_binding() -> None:
    class ChangedHost(FakeLifecycle):
        def client_for_profile(self, profile_id: str):
            raise RunnerLifecycleError("Runner host is not authenticated and ready.")

    with pytest.raises(RunnerLifecycleError, match="not authenticated and ready"):
        managed_setup_transport(ChangedHost(status=ready_status()))
