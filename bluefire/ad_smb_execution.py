"""Saved AD execution through exact prior enrollment, never automatic setup.

Installed configuration enables only the fixed admitted channel. No controller
reader credential, enrollment, substitute host or general action is available.
Tests inject synthetic boundaries privately, never through request fields.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, cast

from .ad_smb_contract import AdSmbError, AdSmbScope
from .ad_smb_installed import InstalledEnvironment, load_installed
from .ad_smb_receiver_results import context
from .ad_smb_results import execution_manifest, now, original_context, validate_execution
from .ad_smb_workspace_results import project_original
from .runner_transport_errors import RunnerTransportError
from .runner_trust import RunnerTrustError
from .util import content_hash


class AdSmbExecutor(Protocol):
    def environments(self) -> list[dict[str, Any]]: ...

    def readiness(self, scope: AdSmbScope) -> dict[str, Any]: ...

    def execute(
        self,
        request: Mapping[str, Any],
        *,
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]: ...

    def recover_original(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> dict[str, Any]: ...


class UnavailableAdSmbExecutor:
    def environments(self) -> list[dict[str, Any]]:
        return []

    def readiness(self, scope: AdSmbScope) -> dict[str, Any]:
        AdSmbScope.from_mapping(scope.to_dict())
        return {
            "available": False,
            "member_observation": False,
            "client_read_admission": False,
            "secret_channel_available": False,
            "problem": "native_admission_unavailable",
            "binding_digest": None,
        }

    def execute(
        self,
        request: Mapping[str, Any],
        *,
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        return validate_execution(
            request,
            {
                "schema_version": "bluefire.ad-smb-execution.v1",
                "request_digest": content_hash(request),
                "provenance": "runner_reported",
                "dispatch": "not_started",
                "cleanup": "verified",
                "observation": None,
            },
        )

    def recover_original(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> dict[str, Any]:
        original_context(request, context)
        return {"status": "unavailable", "execution": None}


class InstalledAdSmbExecutor:
    """Join existing configuration, authenticated transport and original receipts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        load_installed(root)

    def environments(self) -> list[dict[str, Any]]:
        return [entry.public for entry in load_installed(self.root)]

    def _scope(self, scope: AdSmbScope) -> InstalledEnvironment:
        matches = [
            entry
            for entry in load_installed(self.root)
            if AdSmbScope.from_mapping(entry.public["scope"]).digest == scope.digest
        ]
        if len(matches) != 1:
            raise AdSmbError("The exact installed AD environment is unavailable.")
        return matches[0]

    def _selected(self, request: Mapping[str, Any]) -> tuple[InstalledEnvironment, str]:
        entry = self._scope(AdSmbScope.from_mapping(request["scope"]))
        role = "client" if request["step"].startswith("read_") else "member"
        if (
            request["environment_digest"] != content_hash(entry.public)
            or request["host"] != entry.public[role]
            or request["principal_binding_digest"] != entry.public["principal_binding_digest"]
        ):
            raise AdSmbError("The original AD environment or role binding changed.")
        return entry, role

    @staticmethod
    def _identity(entry: InstalledEnvironment, role: str, client: Any) -> None:
        identity = client.transport_identity()
        expected = entry.public[role]
        if (
            identity.get("ad_smb_execution_available") is not True
            or identity.get("readiness_scope") != "configuration_only"
            or identity.get("host_role") != role
            or any(
                identity.get(key) != expected[key]
                for key in ("host_id", "profile_digest", "channel_digest")
            )
        ):
            raise AdSmbError("AD configured channel admission changed.")

    def readiness(self, scope: AdSmbScope) -> dict[str, Any]:
        unavailable = UnavailableAdSmbExecutor().readiness(scope)
        try:
            scope.assert_current(now)
        except AdSmbError:
            return {**unavailable, "problem": "scope_not_current"}
        try:
            entry = self._scope(scope)
        except (AdSmbError, RunnerTransportError, RunnerTrustError, OSError):
            return {**unavailable, "problem": "enrollment_unavailable"}
        roles = {}
        for role in ("member", "client"):
            try:
                self._identity(entry, role, entry.client(role))
                roles[role] = True
            except (AdSmbError, RunnerTransportError, RunnerTrustError, OSError):
                roles[role] = False
        available = all(roles.values())
        problem = None
        if not available:
            problem = (
                "member_channel_unavailable"
                if roles["client"]
                else (
                    "client_channel_unavailable" if roles["member"] else "role_channels_unavailable"
                )
            )
        return {
            "available": available,
            "member_observation": roles["member"],
            "client_read_admission": roles["client"],
            "secret_channel_available": roles["client"],
            "problem": problem,
            "binding_digest": entry.digest if available else None,
        }

    def execute(
        self,
        request: Mapping[str, Any],
        *,
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        if cancellation_event.is_set():
            return UnavailableAdSmbExecutor().execute(
                request, cancellation_event=cancellation_event, before_dispatch=before_dispatch
            )
        entry, role = self._selected(request)
        client = entry.client(role)
        self._identity(entry, role, client)
        profile = entry.to_dict()["profiles"][role]
        manifest = execution_manifest(request, profile)
        original = context(manifest, profile)
        # This callback is synchronous durable checkpointing, before any Execute.
        if cast(Callable[[dict[str, Any]], object], before_dispatch)(original) is not None:
            raise AdSmbError("AD original checkpoint callback did not complete synchronously.")
        current, current_role = self._selected(request)
        if current.digest != entry.digest or current_role != role:
            raise AdSmbError("AD installed configuration changed before dispatch.")
        if cancellation_event.is_set():
            return UnavailableAdSmbExecutor().execute(
                request, cancellation_event=cancellation_event, before_dispatch=before_dispatch
            )
        result = client.execute_task(
            manifest,
            profile,
            task_id=original["task_id"],
            cancel_event=cancellation_event,
            durable_result_path=self.root / "results" / (original["task_id"] + ".json"),
        )
        return project_original(request, original, entry.channel(role), result)

    def recover_original(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> dict[str, Any]:
        original = original_context(request, context)
        entry, role = self._selected(request)
        if original["profile"] != entry.to_dict()["profiles"][role]:
            raise AdSmbError("AD recovery profile differs from the original task.")
        # No inventory, health, readiness, credential resolution or Execute.
        recovered = entry.client(role).recover_original(original["manifest"], original["profile"])
        if recovered["state"] != "completed":
            return {"status": "unavailable", "execution": None}
        return {
            "status": "terminal",
            "execution": project_original(
                request, original, entry.channel(role), recovered["result"]
            ),
        }


def configured_executor(service: Any) -> AdSmbExecutor:
    try:
        root = service.runner_lifecycle.root / "ad-smb"
        return InstalledAdSmbExecutor(root)
    except (AttributeError, AdSmbError, RunnerTrustError, OSError):
        return UnavailableAdSmbExecutor()
