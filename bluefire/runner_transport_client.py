"""Client-side authenticated runner task lifecycle and recovery."""

from __future__ import annotations

import hmac
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from . import runner_transport_framing as framing
from . import s3_access_setup_status, s3_access_transport
from . import windows_file_access_managed_session as windows_correction_session
from .owned_service_authority import GRANT_SCHEMA, OwnedServiceAuthorityError, OwnedServiceGrant
from .owned_service_transport import execute_owned_service_request, prepare_client_service_payload
from .runner_client import (
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
    canonical_runner_inventory,
    execution_task_identity,
)
from .runner_transport_errors import (
    TRANSPORT_FAILURE_REASONS,
    AuthenticatedRunnerTransportError,
    RunnerAuthenticationError,
    RunnerConnectionError,
    validated_cancellation_proof,
)
from .runner_transport_security import (
    client_context as _client_context,
)
from .runner_transport_security import (
    enrollment_binding,
    request_authentication,
)
from .runner_transport_security import (
    loopback_host as _loopback_host,
)
from .runner_transport_security import (
    port as _port,
)
from .runner_transport_security import (
    sign_request as _sign_request,
)
from .runner_transport_security import (
    verify_peer as _verify_peer,
)
from .runner_trust import RunnerEnrollment, RunnerTrustError, load_local_enrollment
from .secret_store import SecretProvider
from .util import content_hash

TRANSPORT_SCHEMA_VERSION = "bluefire.runner-transport.v1"
DEFAULT_MAX_FRAME_BYTES = 4 * 1024 * 1024
_FRAME_HEADER = struct.Struct("!I")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "operation",
        "runner_id",
        "client_id",
        "profile_id",
        "task_id",
        "nonce",
        "request_hash",
        "ok",
        "status",
        "payload",
        "response_hash",
        "error_code",
        "authentication",
    }
)
_REMOTE_ERROR_MESSAGES = {
    "authentication_failed": "Runner request authentication failed.",
    "profile_not_allowed": "Runner profile is not enrolled for this transport.",
    "request_invalid": "Runner request is invalid or unsupported.",
    "replay_detected": "Runner refused a replayed request.",
    "duplicate_request": "Runner task was already recorded.",
    "task_conflict": "Runner task identity conflicts with an existing request.",
    "task_not_found": "Runner task was not found.",
    "task_identity_mismatch": "Runner task recovery identity does not match.",
    "runner_failure": "Runner could not complete the requested operation.",
    "ledger_unavailable": "Runner recovery state is unavailable.",
    "ledger_capacity": "Runner recovery ledger has reached its safe capacity.",
    "runner_busy": "Runner request capacity is temporarily unavailable.",
    "runner_draining": "Runner is draining and is not accepting new execution tasks.",
    "active_tasks": "Runner shutdown is waiting for active execution tasks to finish.",
    "outcome_indeterminate": "Runner outcome is indeterminate and requires recovery.",
    "recovery_required": "Runner effects require receipt-based cleanup recovery.",
    "task_cancelled": "Runner task was cancelled after its process tree stopped.",
    "task_timed_out": "Runner task timed out after its process tree stopped.",
}

_RECOVERY_RECEIPT_ID = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECOVERY_RECEIPTS = 512


class RunnerRemoteError(AuthenticatedRunnerTransportError):
    """An authenticated refusal returned by the runner service."""

    def __init__(self, code: str, *, transport_failure_reason: str | None = None) -> None:
        self.code = code if code in _REMOTE_ERROR_MESSAGES else "request_invalid"
        if (
            isinstance(transport_failure_reason, str)
            and transport_failure_reason in TRANSPORT_FAILURE_REASONS
        ):
            self.transport_failure_reason = transport_failure_reason
        super().__init__(_REMOTE_ERROR_MESSAGES[self.code])


class _EnrollmentCache:
    """Reuse validated material until the public trust document changes."""

    def __init__(self, root: Path, *, secret_provider: SecretProvider | None = None) -> None:
        self.root = root
        self.secret_provider = secret_provider
        self._lock = threading.Lock()
        self._enrollment, self._marker = self._load_stable()

    def active(self) -> RunnerEnrollment:
        try:
            marker = self._trust_marker()
        except OSError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None
        with self._lock:
            if marker != self._marker:
                self._enrollment, self._marker = self._load_stable()
            if self._enrollment.status != "active":
                raise RunnerAuthenticationError("Runner enrollment is unavailable or inactive.")
            return self._enrollment

    def _load_stable(self) -> tuple[RunnerEnrollment, tuple[int, int, int, int]]:
        try:
            for _attempt in range(2):
                before = self._trust_marker()
                enrollment = self._load()
                after = self._trust_marker()
                if before == after:
                    return enrollment, after
        except OSError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None
        raise RunnerAuthenticationError("Runner enrollment changed while it was validated.")

    def _load(self) -> RunnerEnrollment:
        try:
            return load_local_enrollment(self.root, secret_provider=self.secret_provider)
        except RunnerTrustError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None

    def _trust_marker(self) -> tuple[int, int, int, int]:
        status = (self.root / "trust.json").stat()
        return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise RunnerAuthenticationError("Runner message identity is invalid.")
    return value


def _receive_exact(
    connection: ssl.SSLSocket,
    length: int,
    *,
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> bytes:
    return framing._receive_exact(
        connection,
        length,
        deadline=deadline,
        abort_event=abort_event,
        monotonic=time.monotonic,
    )


def _receive_frame(
    connection: ssl.SSLSocket,
    maximum: int,
    *,
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> dict[str, Any]:
    return framing._receive_frame(
        connection,
        maximum,
        deadline=deadline,
        abort_event=abort_event,
        receive_exact=_receive_exact,
        decode_json=framing._decode_json_object,
        frame_header=_FRAME_HEADER,
    )


def _send_frame(
    connection: ssl.SSLSocket, value: Mapping[str, Any], maximum: int
) -> None:
    framing._send_frame(connection, value, maximum, frame_header=_FRAME_HEADER)


def validated_transport_identity(client: Any) -> Mapping[str, Any]:
    """Validate the reported host identity against the current client enrollment."""
    health = client.health()
    enrollment = client._active_enrollment()
    client_fingerprint = str(enrollment.metadata["client_fingerprint"])
    expected_generation = enrollment_binding(enrollment, client_fingerprint)[
        "enrollment_generation"
    ]
    binary_digest = health.get("runner_binary_digest")
    inventory_digest = health.get("inventory_digest")
    expected = {
        "runner_id": enrollment.runner_id,
        "client_id": enrollment.client_id,
        "transport": client._transport_kind,
        "tls": "TLSv1.3",
        "server_fingerprint": enrollment.metadata["server_fingerprint"],
        "client_fingerprint": client_fingerprint,
        "authenticated_peer_fingerprint": client_fingerprint,
        "enrollment_generation": expected_generation,
    }
    if (
        any(health.get(field) != value for field, value in expected.items())
        or not isinstance(inventory_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", inventory_digest) is None
        or (
            binary_digest is not None
            and (
                not isinstance(binary_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", binary_digest) is None
            )
        )
    ):
        raise RunnerAuthenticationError("Runner transport identity is invalid.")
    return {
        "schema_version": "bluefire.runner-transport-identity.v1",
        **expected,
        "runner_binary_digest": binary_digest,
        "inventory_digest": inventory_digest,
    }


def validated_cancellation_payload(
    payload: Mapping[str, Any], task_id: str, request_hash: str
) -> Mapping[str, Any]:
    if (
        set(payload)
        != {
            "original_task_id",
            "original_request_hash",
            "state",
            "cancellation_requested",
            "cancelled",
        }
        or payload.get("original_task_id") != task_id
        or payload.get("original_request_hash") != request_hash
        or not isinstance(payload.get("state"), str)
        or not isinstance(payload.get("cancellation_requested"), bool)
        or not isinstance(payload.get("cancelled"), bool)
        or (payload.get("cancelled") is True and payload.get("state") != "cancelled")
    ):
        raise RunnerAuthenticationError("Runner cancellation response is invalid.")
    return payload


def validated_recovered_cancellation_proof(
    payload: Mapping[str, Any], task_id: str, request_hash: str
) -> dict[str, bool]:
    if payload.get("state") == "recovery_required":
        validated_recovery_required_payload(payload, task_id, request_hash)
        return {}
    has_proof = "cancellation_proof" in payload
    if not has_proof and payload.get("state") != "cancelled":
        return {}
    if (
        set(payload)
        != {
            "original_task_id",
            "original_request_hash",
            "state",
            "result",
            "error_code",
            "cancellation_requested",
            "receipt_ids",
            "cleanup_required",
        }
        | ({"cancellation_proof"} if has_proof else set())
        or payload.get("original_task_id") != task_id
        or payload.get("original_request_hash") != request_hash
        or payload.get("state") != "cancelled"
        or payload.get("result") is not None
        or payload.get("error_code") != "task_cancelled"
        or payload.get("cancellation_requested") is not True
        or payload.get("receipt_ids") != []
        or payload.get("cleanup_required") is not False
    ):
        raise RunnerAuthenticationError("Runner cancellation recovery is invalid.")
    return validated_cancellation_proof(payload["cancellation_proof"]) if has_proof else {}


def validated_recovery_required_payload(
    payload: Mapping[str, Any], task_id: str, request_hash: str
) -> None:
    receipt_ids = payload.get("receipt_ids")
    if (
        set(payload)
        != {
            "original_task_id",
            "original_request_hash",
            "state",
            "result",
            "error_code",
            "cancellation_requested",
            "receipt_ids",
            "cleanup_required",
        }
        or payload.get("original_task_id") != task_id
        or payload.get("original_request_hash") != request_hash
        or payload.get("state") != "recovery_required"
        or payload.get("result") is not None
        or payload.get("error_code") != "recovery_required"
        or type(payload.get("cancellation_requested")) is not bool
        or payload.get("cleanup_required") is not True
        or not isinstance(receipt_ids, list)
        or not 1 <= len(receipt_ids) <= _MAX_RECOVERY_RECEIPTS
        or any(
            not isinstance(receipt_id, str) or _RECOVERY_RECEIPT_ID.fullmatch(receipt_id) is None
            for receipt_id in receipt_ids
        )
        or len(receipt_ids) != len(set(receipt_ids))
    ):
        raise RunnerAuthenticationError("Runner recovery-required response is invalid.")


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
            proof = validated_recovered_cancellation_proof(recovered, checked_task_id, request_hash)
            if state == "completed":
                return cast(Mapping[str, Any], client._recovered_result_payload(recovered))
            if state == "cancelled":
                raise cancelled_error(
                    "Runner task was cancelled after its process tree stopped.", **proof
                )
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


class AuthenticatedRunnerClientMixin:
    """RunnerTransport client with exact-task reconnect recovery semantics."""

    owned_service_grant_protocol = GRANT_SCHEMA
    _transport_kind = "mutual-tls-loopback"
    _checked_host = staticmethod(_loopback_host)

    def _enrollment_cache(self, root: Path, provider: SecretProvider | None) -> _EnrollmentCache:
        return _EnrollmentCache(root, secret_provider=provider)

    def _connect_socket(self) -> socket.socket:
        return socket.create_connection((self.host, self.port), timeout=self.socket_timeout_seconds)

    def __init__(
        self,
        enrollment_root: str | Path,
        *,
        profile_id: str,
        host: str = "127.0.0.1",
        port: int,
        socket_timeout_seconds: float = 10.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        recovery_attempts: int = 3,
        recovery_delay_seconds: float = 0.05,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        if (
            socket_timeout_seconds <= 0
            or max_frame_bytes < 4096
            or isinstance(recovery_attempts, bool)
            or not 1 <= recovery_attempts <= 20
            or not 0 <= recovery_delay_seconds <= 5
        ):
            raise AuthenticatedRunnerTransportError("Runner transport bounds are invalid.")
        self.enrollment_root = Path(enrollment_root).expanduser()
        self._enrollments = self._enrollment_cache(self.enrollment_root, secret_provider)
        self.profile_id = _token(profile_id)
        self.host = self._checked_host(host)
        self.port = _port(port, allow_zero=False)
        self.socket_timeout_seconds = float(socket_timeout_seconds)
        self.max_frame_bytes = int(max_frame_bytes)
        self.recovery_attempts = int(recovery_attempts)
        self.recovery_delay_seconds = float(recovery_delay_seconds)
        self._last_execution: tuple[str, str] | None = None

    @property
    def last_execution_identity(self) -> tuple[str, str] | None:
        return self._last_execution

    def health(self) -> Mapping[str, Any]:
        return self._call("health", {}, task_id=self._random_task("health"))

    def inventory(self) -> Mapping[str, Any]:
        payload = self._call("inventory", {}, task_id=self._random_task("inventory"))
        inventory = payload.get("inventory")
        if not isinstance(inventory, dict) or set(payload) != {"inventory"}:
            raise RunnerAuthenticationError("Runner inventory response is invalid.")
        canonical_runner_inventory(inventory)
        return inventory

    def s3_access_environments(self) -> list[dict[str, Any]]:
        return s3_access_transport.client_environments(self)

    def s3_access_setup_status(self) -> Mapping[str, Any]:
        return s3_access_setup_status.client_status(self)

    def transport_identity(self) -> Mapping[str, Any]:
        """Return the validated, secret-free identity of the authenticated host."""
        return validated_transport_identity(self)

    @staticmethod
    def execution_identity(
        manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> tuple[str, str]:
        return execution_task_identity(manifest, profile)

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        if profile.get("profile_id") != self.profile_id:
            raise RunnerAuthenticationError("Runner profile does not match the enrolled client.")
        manifest_profile = manifest.get("runner_profile_id")
        if manifest_profile is not None and manifest_profile != self.profile_id:
            raise RunnerAuthenticationError("Runner profile does not match the execution request.")
        payload = {"manifest": dict(manifest), "profile": dict(profile)}
        task_id, request_hash = self.execution_identity(manifest, profile)
        self._last_execution = (task_id, request_hash)
        try:
            response = self._call("execute", payload, task_id=task_id, request_hash=request_hash)
            return self._execution_result(response)
        except RunnerRemoteError as exc:
            if exc.code == "task_cancelled":
                return self._recovered_execution(task_id, request_hash)
            if exc.code == "task_timed_out":
                raise RunnerTaskTimedOut(
                    "Runner task timed out after its process tree stopped."
                ) from None
            if exc.code != "duplicate_request":
                raise
            return self._recovered_execution(task_id, request_hash)
        except RunnerConnectionError:
            return self._recover_after_connection_loss(payload, task_id, request_hash)

    def execute_windows_correction_session(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        descriptor_value: Mapping[str, Any],
        *,
        cancel_event: threading.Event,
        ready_consumer: Callable[[bytes, bytes, Mapping[str, Any]], Any],
    ) -> Mapping[str, Any]:
        """Execute one live correction session; recovery never redispatches it."""

        if profile.get("profile_id") != self.profile_id:
            raise RunnerAuthenticationError("Runner profile does not match the enrolled client.")
        descriptor = windows_correction_session.validate_descriptor(
            descriptor_value, manifest, profile
        )
        if not callable(getattr(cancel_event, "is_set", None)) or not callable(
            ready_consumer
        ):
            raise RunnerAuthenticationError("Runner correction session callback is invalid.")
        task_id = str(descriptor.value["task_id"])
        request_hash = str(descriptor.value["transport_request_hash"])
        payload = {
            "manifest": dict(manifest),
            "profile": dict(profile),
            "windows_correction_session": dict(descriptor.value),
        }
        self._last_execution = (task_id, request_hash)
        responses: list[Mapping[str, Any]] = []
        failures: list[BaseException] = []

        def execute_request() -> None:
            try:
                responses.append(
                    self._call(
                        "execute", payload, task_id=task_id, request_hash=request_hash
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(
            target=execute_request,
            name=f"bluefire-windows-correction-{task_id[-12:]}",
            daemon=True,
        )
        worker.start()
        acknowledgement_attempted = False
        cancellation_attempted = False
        poll_deadline = descriptor.packet_deadline
        while worker.is_alive() and time.monotonic() < poll_deadline:
            if cancel_event.is_set() and not cancellation_attempted:
                cancellation_attempted = True
                try:
                    self.cancel(task_id, request_hash)
                except (RunnerConnectionError, RunnerRemoteError):
                    pass
            if acknowledgement_attempted or cancellation_attempted:
                worker.join(timeout=0.01)
                continue
            try:
                status = self.windows_correction_status(descriptor)
            except RunnerRemoteError as exc:
                if exc.code != "task_not_found":
                    failures.append(exc)
                    break
                worker.join(timeout=0.01)
                continue
            except RunnerConnectionError as exc:
                failures.append(exc)
                break
            if status["state"] == "failed":
                break
            if status["state"] == "ready":
                ready = windows_correction_session.ready_bytes_from_status(status, descriptor)
                try:
                    consume_identity = windows_correction_session.ready_consume_identity(
                        status, descriptor
                    )
                    persisted = ready_consumer(
                        descriptor.packet,
                        ready,
                        consume_identity,
                    )
                    consume_receipt = windows_correction_session.callback_consume_receipt(
                        persisted,
                        descriptor,
                        ready_digest=str(status["ready_digest"]),
                        ack_nonce=str(status["ack_nonce"]),
                    )
                except BaseException:
                    try:
                        self.cancel(task_id, request_hash)
                    except (RunnerConnectionError, RunnerRemoteError):
                        pass
                    worker.join(timeout=max(self.socket_timeout_seconds + 1.0, 2.0))
                    raise
                acknowledgement_attempted = True
                try:
                    self.windows_correction_ack(
                        descriptor,
                        status,
                        persisted_consume_receipt=consume_receipt,
                    )
                except (RunnerConnectionError, RunnerRemoteError) as exc:
                    failures.append(exc)
                    break
            worker.join(timeout=0.01)

        worker.join(timeout=max(self.socket_timeout_seconds + 1.0, 2.0))
        if worker.is_alive():
            raise RunnerConnectionError(
                "Runner correction session did not reach a terminal response."
            )
        if responses:
            return self._execution_result(responses[-1])
        failure = failures[-1] if failures else RunnerConnectionError(
            "Runner correction session ended without an authenticated response."
        )
        if isinstance(failure, RunnerRemoteError) and failure.code not in {
            "duplicate_request",
            "outcome_indeterminate",
        }:
            raise failure
        if not isinstance(failure, (RunnerConnectionError, RunnerRemoteError)):
            raise failure
        # The only post-loss operation is exact recovery.  In particular, a
        # missing live Ready/ack channel is never reconstructed or resent.
        recovered_error: BaseException | None = failure
        for attempt in range(self.recovery_attempts):
            if attempt and self.recovery_delay_seconds:
                time.sleep(self.recovery_delay_seconds)
            try:
                recovered = self.recover(task_id, request_hash)
            except RunnerConnectionError as exc:
                recovered_error = exc
                continue
            state = recovered.get("state")
            if state == "completed":
                return self._recovered_result_payload(recovered)
            if state == "cancelled":
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped."
                )
            if state == "timed_out":
                raise RunnerTaskTimedOut(
                    "Runner task timed out after its process tree stopped."
                )
            if state in {"failed", "indeterminate", "recovery_required"}:
                break
        raise RunnerConnectionError(
            "Runner correction outcome could not be recovered without redispatch."
        ) from recovered_error

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
        owned_service_grant: OwnedServiceGrant | Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Execute and cancel one exact remote task through separate mTLS requests."""
        return execute_authenticated_task(
            self,
            manifest,
            profile,
            task_id=task_id,
            cancel_event=cancel_event,
            durable_result_path=durable_result_path,
            owned_service_grant=owned_service_grant,
            task_id_validator=_token,
            remote_error=RunnerRemoteError,
            connection_error=RunnerConnectionError,
            cancelled_error=RunnerTaskCancelled,
            timed_out_error=RunnerTaskTimedOut,
        )

    def recover(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        _token(task_id)
        if _DIGEST.fullmatch(request_hash) is None:
            raise RunnerAuthenticationError("Runner recovery identity is invalid.")
        payload = self._call(
            "recover",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("recover"),
        )
        validated_recovered_cancellation_proof(payload, task_id, request_hash)
        return payload

    def cancel(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        _token(task_id)
        if _DIGEST.fullmatch(request_hash) is None:
            raise RunnerAuthenticationError("Runner cancellation identity is invalid.")
        payload = self._call(
            "cancel",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("cancel"),
        )
        return self._validated_cancellation_payload(payload, task_id, request_hash)

    def windows_correction_status(
        self,
        descriptor: windows_correction_session.ManagedCorrectionDescriptor,
    ) -> Mapping[str, Any]:
        payload = self._call(
            "windows_correction_status",
            {
                "original_task_id": descriptor.value["task_id"],
                "original_request_hash": descriptor.value["transport_request_hash"],
                "session_nonce": descriptor.value["session_nonce"],
            },
            task_id=self._random_task("windows-correction-status"),
        )
        return windows_correction_session.validate_status(payload, descriptor)

    def windows_correction_ack(
        self,
        descriptor: windows_correction_session.ManagedCorrectionDescriptor,
        status: Mapping[str, Any],
        *,
        persisted_consume_receipt: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        checked_status = windows_correction_session.validate_status(status, descriptor)
        if checked_status["state"] != "ready":
            raise RunnerAuthenticationError("Runner correction readiness is invalid.")
        consume_receipt = windows_correction_session._consume_receipt_document(
            persisted_consume_receipt,
            task_id=str(descriptor.value["task_id"]),
            request_hash=str(descriptor.value["transport_request_hash"]),
            session_nonce=str(descriptor.value["session_nonce"]),
            packet_digest=descriptor.packet_digest,
            ready_digest=str(checked_status["ready_digest"]),
            ack_nonce=str(checked_status["ack_nonce"]),
        )
        consume_digest = windows_correction_session.persisted_consume_digest(consume_receipt)
        ack = {
            "schema_version": windows_correction_session.ACK_SCHEMA,
            "original_task_id": descriptor.value["task_id"],
            "original_request_hash": descriptor.value["transport_request_hash"],
            "session_nonce": descriptor.value["session_nonce"],
            "packet_digest": descriptor.packet_digest,
            "ready_digest": checked_status["ready_digest"],
            "ack_nonce": checked_status["ack_nonce"],
            "persisted_consume_receipt": consume_receipt,
            "persisted_consume_digest": consume_digest,
        }
        payload = self._call(
            "windows_correction_ack",
            ack,
            task_id=self._random_task("windows-correction-ack"),
        )
        return windows_correction_session.validate_ack_response(
            payload, descriptor, consume_digest
        )

    def _cancel_for_execute_task(
        self,
        task_id: str,
        request_hash: str,
        *,
        abort_event: threading.Event,
    ) -> Mapping[str, Any]:
        payload = self._call(
            "cancel",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("cancel"),
            abort_event=abort_event,
        )
        return self._validated_cancellation_payload(payload, task_id, request_hash)

    _validated_cancellation_payload = staticmethod(validated_cancellation_payload)

    def shutdown(self, server_instance_id: str | None = None) -> Mapping[str, Any]:
        """Request an authenticated managed-host shutdown acknowledgement.

        Lifecycle callers may supply the instance identity from the authenticated
        process record so shutdown remains available when runner inventory health
        is quarantined. Callers without that record retain health discovery.
        """

        instance_id = (
            _token(self.health().get("server_instance_id"))
            if server_instance_id is None
            else _token(server_instance_id)
        )
        payload = self._call(
            "shutdown",
            {"server_instance_id": instance_id},
            task_id=self._random_task("shutdown"),
        )
        enrollment = self._active_enrollment()
        if payload != {
            "schema_version": "bluefire.runner-lifecycle.v1",
            "status": "shutdown_acknowledged",
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "server_instance_id": instance_id,
        }:
            raise RunnerAuthenticationError("Runner lifecycle response is invalid.")
        return payload

    def _recover_after_connection_loss(
        self, payload: Mapping[str, Any], task_id: str, request_hash: str
    ) -> Mapping[str, Any]:
        resent = False
        for attempt in range(self.recovery_attempts):
            if attempt and self.recovery_delay_seconds:
                time.sleep(self.recovery_delay_seconds)
            try:
                recovered = self.recover(task_id, request_hash)
            except RunnerConnectionError:
                continue
            state = recovered.get("state")
            proof = validated_recovered_cancellation_proof(recovered, task_id, request_hash)
            if state == "completed":
                return self._recovered_result_payload(recovered)
            if state == "cancelled":
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped.", **proof
                )
            if state == "timed_out":
                raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
            if state == "recovery_required":
                raise RunnerRemoteError("recovery_required")
            if state == "not_found" and not resent:
                resent = True
                try:
                    response = self._call(
                        "execute", payload, task_id=task_id, request_hash=request_hash
                    )
                    return self._execution_result(response)
                except RunnerRemoteError as exc:
                    if exc.code != "duplicate_request":
                        raise
                except RunnerConnectionError:
                    continue
            if state in {
                "failed",
                "indeterminate",
                "cancelled",
                "timed_out",
            }:
                break
        raise RunnerConnectionError(
            "Runner outcome could not be recovered; inspect the recorded task before retrying."
        )

    def _recovered_execution(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        recovered = self.recover(task_id, request_hash)
        proof = validated_recovered_cancellation_proof(recovered, task_id, request_hash)
        if recovered.get("state") == "cancelled":
            raise RunnerTaskCancelled(
                "Runner task was cancelled after its process tree stopped.", **proof
            )
        if recovered.get("state") == "timed_out":
            raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
        if recovered.get("state") == "recovery_required":
            raise RunnerRemoteError("recovery_required")
        if recovered.get("state") != "completed":
            raise RunnerConnectionError(
                "Runner task exists but has no completed result; inspect recovery state."
            )
        return self._recovered_result_payload(recovered)

    @staticmethod
    def _recovered_result_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RunnerAuthenticationError("Runner recovery result is invalid.")
        return result

    @staticmethod
    def _execution_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = payload.get("result")
        if not isinstance(result, dict) or set(payload) != {"result"}:
            raise RunnerAuthenticationError("Runner execution response is invalid.")
        return result

    @staticmethod
    def _random_task(prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(24)}"

    def _active_enrollment(self) -> RunnerEnrollment:
        enrollment = self._enrollments.active()
        if self.profile_id not in enrollment.allowed_profile_ids:
            raise RunnerAuthenticationError("Runner profile is not enrolled for this transport.")
        return enrollment

    def _call(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        request_hash: str | None = None,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        enrollment = self._active_enrollment()
        checked_hash = request_hash or content_hash(dict(payload))
        unsigned = {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "kind": "request",
            "operation": operation,
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "profile_id": self.profile_id,
            "task_id": task_id,
            "nonce": secrets.token_hex(32),
            "request_hash": checked_hash,
            "payload": dict(payload),
        }
        request = _sign_request(enrollment, unsigned)
        response = self._exchange(request, enrollment, abort_event=abort_event)
        return self._validated_response(response, request, enrollment)

    def _exchange(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        *,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        context = _client_context(enrollment)
        deadline = time.monotonic() + self.socket_timeout_seconds
        try:
            with self._connect_socket() as raw_connection:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerConnectionError("Runner connection deadline expired.")
                raw_connection.settimeout(remaining)
                with context.wrap_socket(
                    raw_connection,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                ) as connection:
                    connection.settimeout(max(deadline - time.monotonic(), 0.001))
                    connection.do_handshake()
                    _verify_peer(
                        connection,
                        expected_fingerprint=str(enrollment.metadata["server_fingerprint"]),
                        expected_common_name=enrollment.runner_id,
                    )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RunnerConnectionError("Runner connection deadline expired.")
                    connection.settimeout(remaining)
                    _send_frame(connection, request, self.max_frame_bytes)
                    return _receive_frame(
                        connection,
                        self.max_frame_bytes,
                        deadline=deadline,
                        abort_event=abort_event,
                    )
        except RunnerAuthenticationError:
            raise
        except ssl.SSLError:
            raise RunnerAuthenticationError(
                "Runner TLS authentication could not be completed."
            ) from None
        except (OSError, RunnerConnectionError):
            raise RunnerConnectionError("Runner loopback service is unavailable.") from None

    @staticmethod
    def _validated_response(
        response: Mapping[str, Any],
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
    ) -> Mapping[str, Any]:
        if set(response) != _RESPONSE_FIELDS:
            raise RunnerAuthenticationError("Runner response has an unsupported shape.")
        if (
            response.get("schema_version") != TRANSPORT_SCHEMA_VERSION
            or response.get("kind") != "response"
        ):
            raise RunnerAuthenticationError("Runner response schema is unsupported.")
        for field in (
            "operation",
            "runner_id",
            "client_id",
            "profile_id",
            "task_id",
            "nonce",
            "request_hash",
        ):
            actual = response.get(field)
            expected = request.get(field)
            if (
                not isinstance(actual, str)
                or not isinstance(expected, str)
                or not hmac.compare_digest(actual, expected)
            ):
                raise RunnerAuthenticationError(
                    "Runner response identity does not match its request."
                )
        payload = response.get("payload")
        authentication = response.get("authentication")
        response_hash = response.get("response_hash")
        if (
            not isinstance(payload, dict)
            or not isinstance(authentication, str)
            or _DIGEST.fullmatch(authentication) is None
            or not isinstance(response_hash, str)
            or _DIGEST.fullmatch(response_hash) is None
            or content_hash(payload) != response_hash
        ):
            raise RunnerAuthenticationError("Runner response authentication is invalid.")
        unsigned = {key: response[key] for key in response if key != "authentication"}
        if not hmac.compare_digest(authentication, request_authentication(enrollment, unsigned)):
            raise RunnerAuthenticationError("Runner response authentication is invalid.")
        ok = response.get("ok")
        status = response.get("status")
        error_code = response.get("error_code")
        if ok is True and status == "completed" and error_code is None:
            return payload
        if ok is False and status == "refused" and isinstance(error_code, str):
            reason = payload.get("transport_failure_reason")
            if payload and (
                request.get("operation") != "execute"
                or set(payload) != {"transport_failure_reason"}
                or not isinstance(reason, str)
                or reason not in TRANSPORT_FAILURE_REASONS
            ):
                raise RunnerAuthenticationError("Runner response diagnostic is invalid.")
            raise RunnerRemoteError(error_code, transport_failure_reason=reason)
        raise RunnerAuthenticationError("Runner response status is invalid.")
