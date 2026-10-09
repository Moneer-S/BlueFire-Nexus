"""AD executor injection boundary; no native capability is advertised yet.

The default deliberately cannot enroll, discover a substitute host, read a
credential, run SMB from Python, or dispatch the unregistered native action.
Tests inject a synthetic executor privately, never through a request field.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Mapping, Protocol

from .ad_smb_contract import AdSmbScope
from .ad_smb_results import original_context, validate_execution
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


def configured_executor(_service: Any) -> AdSmbExecutor:
    # Replace only after enrolled host admission, protected delivery and native
    # original-result authentication exist together, not when a flag is toggled.
    return UnavailableAdSmbExecutor()
