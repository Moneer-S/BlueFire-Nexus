"""Product-facing fixed S3 execution interface and safe result validation.

Only an already-running, authenticated managed host can supply this transport.
Tests may inject a synthetic executor directly into the product coordinator;
request data can never select an implementation or enroll a runtime.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .runner_client import execution_task_identity
from .runner_transport import AuthenticatedRunnerClient
from .s3_access_admission import ACTION, approved_request
from .s3_access_contract import S3AccessError, S3AccessScope, document, exact
from .s3_access_execution_contract import validate_execution as validate_execution
from .s3_access_recovery import SCHEMA, validate_recovery_context
from .s3_access_recovery import execution_manifest as _manifest
from .s3_access_wire import S3WorkerRequest, timestamp
from .util import canonical_json_bytes


class S3AccessExecutor(Protocol):
    def environments(self) -> list[dict[str, Any]]: ...

    def readiness(self, scope: S3AccessScope) -> dict[str, Any]: ...

    def execute(
        self,
        request: S3WorkerRequest,
        *,
        authorization: Mapping[str, Any],
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]: ...

    def recover_original(
        self, request: S3WorkerRequest, context: Mapping[str, Any]
    ) -> dict[str, Any]: ...


class _UnavailableExecutor:
    def environments(self) -> list[dict[str, Any]]:
        return []

    def readiness(self, scope: S3AccessScope) -> dict[str, Any]:
        S3AccessScope.from_mapping(scope.to_dict())
        return {
            "available": False,
            "problem": "runtime_unavailable",
            "runner_profile_id": None,
            "worker_generation": None,
            "runtime_digest": None,
        }

    def execute(
        self,
        request: S3WorkerRequest,
        *,
        authorization: Mapping[str, Any],
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        return validate_execution(
            request,
            {
                "schema_version": "bluefire.s3-execution.v1",
                "request_digest": request.digest,
                "admission": {
                    "accepted": False,
                    "problem": (
                        "cancelled" if cancellation_event.is_set() else "runtime_unavailable"
                    ),
                },
                "dispatch": "not_started",
                "send_debits": 0,
                "result": None,
                "cleanup": "verified",
                "provenance": "runner_reported",
                "reservation_digest": None,
            },
        )

    def recover_original(
        self, request: S3WorkerRequest, context: Mapping[str, Any]
    ) -> dict[str, Any]:
        validate_recovery_context(request, context)
        return {"status": "unavailable", "execution": None}


def _execution_result(
    request: S3WorkerRequest, manifest: Mapping[str, Any], result: Any
) -> dict[str, Any]:
    result = document(result, limit=64 * 1024)
    if result.get("schema_version") != "bluefire.runner-result.v1" or any(
        result.get(field) != manifest[field]
        for field in (
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "runner_id",
            "runner_profile_id",
            "platform",
            "request_hash",
            "policy_digest",
        )
    ):
        raise S3AccessError("S3 runner result identity is invalid")
    output = result.get("output")
    if not isinstance(output, Mapping):
        raise S3AccessError("S3 runner output is invalid")
    exact(output, {"s3_execution"}, "S3 runner output")
    execution = validate_execution(request, output["s3_execution"])
    if execution["provenance"] != "runner_reported":
        raise S3AccessError("Enrolled S3 runner returned synthetic evidence")
    return execution


class _ConfiguredExecutor(_UnavailableExecutor):
    def __init__(self, service: Any) -> None:
        self.service = service

    def _discovered(self) -> list[tuple[AuthenticatedRunnerClient, Path, dict[str, Any]]]:
        found = []
        profiles = getattr(getattr(self.service, "config", None), "runner_profiles", ())
        lifecycle = getattr(self.service, "runner_lifecycle", None)
        if lifecycle is None:
            return []
        for profile in profiles:
            if (
                profile.mode.value != "execute"
                or "linux" not in profile.platforms
                or "cloud.aws.s3.access" not in profile.capabilities
                or ACTION not in profile.enabled_actions
                or ACTION in profile.blocked_actions
            ):
                continue
            try:
                client, sandbox = lifecycle.client_for_profile(
                    profile.id, profile_budget_seconds=min(60, profile.budgets.max_seconds)
                )
                if not isinstance(client, AuthenticatedRunnerClient):
                    continue
                for row in client.s3_access_environments():
                    found.append((client, sandbox, row))
            except (OSError, ValueError, RuntimeError):
                continue
        # A changed scope must not hide a second journal for the same bucket.
        # This covers visible configured hosts, not undiscovered controllers.
        identifiers = [row[2]["environment"]["environment_id"] for row in found]
        buckets = [
            tuple(row[2]["environment"]["scope"][key] for key in ("account_id", "region", "bucket"))
            for row in found
        ]
        return [
            row
            for index, row in enumerate(found)
            if identifiers.count(identifiers[index]) == 1 and buckets.count(buckets[index]) == 1
        ]

    def environments(self) -> list[dict[str, Any]]:
        return [row["environment"] for _client, _sandbox, row in self._discovered()]

    def readiness(self, scope: S3AccessScope) -> dict[str, Any]:
        scope = S3AccessScope.from_mapping(scope.to_dict())
        for _client, _sandbox, row in self._discovered():
            if canonical_json_bytes(row["environment"]["scope"]) == canonical_json_bytes(
                scope.to_dict()
            ):
                return {
                    "available": row["available"],
                    "problem": row["problem"],
                    "runner_profile_id": row["profile"]["profile_id"],
                    "worker_generation": row["worker_generation"],
                    "runtime_digest": row["runtime_digest"],
                }
        return super().readiness(scope)

    def execute(
        self,
        request: S3WorkerRequest,
        *,
        authorization: Mapping[str, Any],
        cancellation_event: threading.Event,
        before_dispatch: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        request = S3WorkerRequest.from_mapping(request.to_dict())
        request.assert_current(lambda: datetime.now(timezone.utc))
        if cancellation_event.is_set():
            return super().execute(
                request, authorization=authorization, cancellation_event=cancellation_event
            )
        value = request.to_dict()
        selected = [
            (client, sandbox, row)
            for client, sandbox, row in self._discovered()
            if row["available"]
            and row["environment"]["environment_id"] == authorization.get("environment_id")
            and canonical_json_bytes(row["environment"]["scope"])
            == canonical_json_bytes(value["scope"])
            and row["runtime_digest"] == value["runtime_digest"]
            and row["worker_generation"] == value["worker_generation"]
        ]
        if len(selected) != 1:
            return super().execute(
                request, authorization=authorization, cancellation_event=cancellation_event
            )
        client, sandbox, row = selected[0]
        profile = row["profile"]
        manifest = _manifest(request, authorization, profile)
        task_id, request_hash = execution_task_identity(manifest, profile)
        approved_request(manifest, profile, task_id=task_id, now=datetime.now(timezone.utc))
        if not callable(before_dispatch):
            raise S3AccessError("S3 original task must be durably saved before dispatch")
        try:
            context = validate_recovery_context(
                request,
                {
                    "schema_version": SCHEMA,
                    "request_digest": request.digest,
                    "task_id": task_id,
                    "transport_request_hash": request_hash,
                    "manifest": manifest,
                    "profile": profile,
                    "transport_identity": client.transport_identity(),
                },
            )
            if before_dispatch(context) is not None:
                raise S3AccessError(
                    "S3 original checkpoint callback did not complete synchronously"
                )
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            raise S3AccessError(
                "S3 original task could not be saved; execution was not dispatched"
            ) from None
        if cancellation_event.is_set():
            return super().execute(
                request, authorization=authorization, cancellation_event=cancellation_event
            )
        try:
            result = client.execute_task(
                manifest,
                profile,
                task_id=task_id,
                cancel_event=cancellation_event,
                durable_result_path=Path(sandbox) / (task_id + ".json"),
            )
            return _execution_result(request, manifest, result)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            # After transport dispatch, failure is not proof of non-execution.
            # The job records an unsealed operation requiring reconciliation.
            raise S3AccessError(
                "The S3 operation has no verified final runner result; inspect the saved operation before further effects."
            ) from None

    def recover_original(
        self, request: S3WorkerRequest, context: Mapping[str, Any]
    ) -> dict[str, Any]:
        context = validate_recovery_context(request, context)
        manifest, profile = context["manifest"], context["profile"]
        # Historical consistency is checked at the original issue time, never
        # with a refreshed deadline or a newly discovered runtime/credential.
        approved_request(
            manifest, profile, task_id=context["task_id"], now=timestamp(manifest["requested_at"])
        )
        try:
            client, _sandbox = self.service.runner_lifecycle.client_for_profile(
                profile["profile_id"]
            )
            if not isinstance(client, AuthenticatedRunnerClient) or canonical_json_bytes(
                client.transport_identity()
            ) != canonical_json_bytes(context["transport_identity"]):
                raise S3AccessError("S3 original authenticated host is unavailable")
            recovered = document(
                client.recover(context["task_id"], context["transport_request_hash"]),
                limit=96 * 1024,
            )
            exact(
                recovered,
                {
                    "original_task_id",
                    "original_request_hash",
                    "state",
                    "result",
                    "error_code",
                    "cancellation_requested",
                    "receipt_ids",
                    "cleanup_required",
                },
                "S3 original recovery response",
            )
            if (
                recovered["original_task_id"] != context["task_id"]
                or recovered["original_request_hash"] != context["transport_request_hash"]
                or type(recovered["cancellation_requested"]) is not bool
                or type(recovered["cleanup_required"]) is not bool
                or recovered["receipt_ids"] != []
            ):
                raise S3AccessError("S3 original recovery identity is invalid")
            state = recovered["state"]
            if state == "completed":
                if (
                    recovered["cleanup_required"]
                    or recovered["receipt_ids"]
                    or recovered["error_code"] is not None
                ):
                    raise S3AccessError("S3 original result lacks final cleanup evidence")
                execution = _execution_result(request, manifest, recovered["result"])
                return {"status": "finalized", "execution": execution}
            if recovered["result"] is not None:
                raise S3AccessError("S3 unresolved original result is inconsistent")
            return {
                "status": {"running": "running", "not_found": "absent"}.get(state, "unavailable"),
                "execution": None,
            }
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError):
            return {"status": "unavailable", "execution": None}


def configured_executor(service: Any) -> S3AccessExecutor:
    return _ConfiguredExecutor(service)
