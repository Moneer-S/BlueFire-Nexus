"""Client-side authenticated runner task lifecycle and recovery."""

from __future__ import annotations

import hmac
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from .owned_service_authority import OwnedServiceAuthorityError, OwnedServiceGrant
from .owned_service_transport import execute_owned_service_request, prepare_client_service_payload
from .runner_transport_errors import RunnerAuthenticationError


def execute_authenticated_task(
    client: Any,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    task_id: str,
    cancel_event: threading.Event,
    durable_result_path: str | Path,
    owned_service_grant: OwnedServiceGrant | Mapping[str, Any] | None = None,
    task_id_validator: Callable[[str], str],
    remote_error: type[BaseException],
    connection_error: type[BaseException],
    cancelled_error: type[BaseException],
    timed_out_error: type[BaseException],
) -> Mapping[str, Any]:
    """Execute and cancel one exact remote task through separate mTLS requests.

    The durable path belongs to the local orchestration interface only. It
    is validated but never read, written, or sent to the runner host; the
    authenticated server derives its own ledger-bound result namespace.
    """

    expected_task_id, _base_request_hash = client.execution_identity(manifest, profile)
    checked_task_id = task_id_validator(task_id)
    if not hmac.compare_digest(checked_task_id, expected_task_id):
        raise RunnerAuthenticationError("Runner execution identity is invalid.")
    if profile.get("profile_id") != client.profile_id:
        raise RunnerAuthenticationError("Runner profile does not match the enrolled client.")
    if owned_service_grant is not None:
        try:
            payload, request_hash = prepare_client_service_payload(
                manifest=manifest,
                profile=profile,
                grant_value=owned_service_grant,
                task_id=checked_task_id,
            )
        except OwnedServiceAuthorityError:
            raise RunnerAuthenticationError("Runner service grant is invalid.") from None
    else:
        payload = {"manifest": dict(manifest), "profile": dict(profile)}
        request_hash = _base_request_hash
    if not callable(getattr(cancel_event, "is_set", None)) or not callable(
        getattr(cancel_event, "wait", None)
    ):
        raise RunnerAuthenticationError("Runner cancellation signal is invalid.")
    caller_path = Path(durable_result_path).expanduser()
    if not caller_path.is_absolute() or caller_path.name in {"", ".", ".."}:
        raise RunnerAuthenticationError("Runner durable result identity is invalid.")

    monitor_stop = threading.Event()
    monitor_payload: list[Mapping[str, Any]] = []
    monitor_error: list[BaseException] = []

    def monitor_cancellation() -> None:
        not_found_attempts = 0
        connection_attempts = 0
        while not monitor_stop.wait(0.01):
            if not cancel_event.is_set():
                continue
            while not monitor_stop.is_set():
                try:
                    monitor_payload.append(
                        client._cancel_for_execute_task(
                            checked_task_id,
                            request_hash,
                            abort_event=monitor_stop,
                        )
                    )
                    return
                except remote_error as exc:
                    if getattr(exc, "code", None) != "task_not_found" or not_found_attempts >= 20:
                        monitor_error.append(exc)
                        return
                    not_found_attempts += 1
                except connection_error as exc:
                    connection_attempts += 1
                    if connection_attempts >= client.recovery_attempts:
                        monitor_error.append(exc)
                        return
                except BaseException as exc:
                    monitor_error.append(exc)
                    return
                if monitor_stop.wait(max(client.recovery_delay_seconds, 0.01)):
                    return

    monitor = threading.Thread(
        target=monitor_cancellation,
        name=f"bluefire-runner-cancel-{checked_task_id[-12:]}",
        daemon=True,
    )
    monitor.start()
    execution_result: Mapping[str, Any] | None = None
    execution_error: BaseException | None = None
    try:
        if owned_service_grant is None:
            execution_result = client.execute(manifest, profile)
        else:
            execution_result = execute_owned_service_request(
                client,
                payload,
                task_id=checked_task_id,
                request_hash=request_hash,
                remote_error=remote_error,
                connection_error=connection_error,
                cancelled_error=cancelled_error,
                timed_out_error=timed_out_error,
            )
    except BaseException as exc:
        execution_error = exc
    finally:
        monitor_stop.set()
        monitor.join(timeout=max(client.socket_timeout_seconds + 1.0, 2.0))
    if monitor.is_alive():
        raise connection_error(
            "Runner cancellation request did not stop within its transport deadline."
        )
    if execution_result is not None:
        return execution_result
    assert execution_error is not None
    if not isinstance(execution_error, connection_error):
        raise execution_error

    terminal = monitor_payload[-1] if monitor_payload else None
    if terminal is not None and terminal.get("state") == "cancelled":
        raise cancelled_error("Runner task was cancelled after its process tree stopped.")
    if cancel_event.is_set() or terminal is not None or monitor_error:
        recovered_error: BaseException | None = None
        for attempt in range(client.recovery_attempts):
            if attempt and client.recovery_delay_seconds:
                time.sleep(client.recovery_delay_seconds)
            try:
                recovered = client.recover(checked_task_id, request_hash)
            except connection_error as exc:
                recovered_error = exc
                continue
            state = recovered.get("state")
            if state == "completed":
                return cast(Mapping[str, Any], client._recovered_result_payload(recovered))
            if state == "cancelled":
                raise cancelled_error("Runner task was cancelled after its process tree stopped.")
            if state == "timed_out":
                raise timed_out_error("Runner task timed out after its process tree stopped.")
            if state == "recovery_required":
                raise remote_error("recovery_required")
            if state == "failed" and isinstance(recovered.get("error_code"), str):
                raise remote_error(str(recovered["error_code"]))
        if monitor_error and isinstance(monitor_error[-1], RunnerAuthenticationError):
            raise monitor_error[-1]
        if recovered_error is not None:
            raise recovered_error
    raise execution_error
