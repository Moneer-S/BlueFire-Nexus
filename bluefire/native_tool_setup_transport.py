"""Narrow transport for operator initiated native tool setup inspection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from .runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError

if TYPE_CHECKING:
    from .runner_transport import AuthenticatedRunnerClient

# Leave room for the native inspection's five-second operation bound plus TLS,
# authenticated framing, and response validation.
_SETUP_SOCKET_TIMEOUT_SECONDS = 15.0


class ManagedSetupTransport:
    """Read-only view of an already authenticated managed runner."""

    def __init__(self, client: AuthenticatedRunnerClient) -> None:
        self._client = client
        self.timeout_seconds = _SETUP_SOCKET_TIMEOUT_SECONDS
        # Keep candidate inspection within the short setup operation budget.
        self._client.socket_timeout_seconds = self.timeout_seconds

    def inventory(self) -> Mapping[str, Any]:
        return self._client.inventory()

    def transport_identity(self) -> Mapping[str, Any]:
        return self._client.transport_identity()

    def inspect_native_tool_candidate(self, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._client.inspect_native_tool_candidate(candidate)


def managed_setup_transport(lifecycle: ManagedRunnerLifecycle) -> ManagedSetupTransport:
    """Bind setup to the current active/default managed runner only.

    This function never bootstraps, starts, enrolls, or mutates lifecycle state.
    Managed profiles share this one local host. Its existing enrolled control
    identity authenticates inspection; the target draft remains separately
    validated by the setup service and receives no execution authority.
    The lifecycle status probe and ``client_for_profile`` repeat the enrollment,
    bootstrap record, process record, authenticated health, and profile checks.
    """

    status = lifecycle.status()
    if (
        not isinstance(status, Mapping)
        or status.get("state") != "ready"
        or status.get("enrollment_state") != "active"
        or status.get("process_state") != "authenticated"
    ):
        raise RunnerLifecycleError("Managed runner is not authenticated and ready.")
    profile_id = status.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id:
        raise RunnerLifecycleError("Managed runner has no active default profile.")
    client, _sandbox = lifecycle.client_for_profile(profile_id)
    return ManagedSetupTransport(client)


__all__ = ["ManagedSetupTransport", "managed_setup_transport"]
