"""Linux client for the external Docker exec lifetime supervisor.

The protected service is a separate process.  It owns one durable journal and
starts a per-operation guardian before returning an arm receipt.  A guardian
monitors the physical controller and broker identities plus the absolute
operation deadline.  It can therefore clean the exact attempt-owned container
even after the controller or broker exits.

This module deliberately exposes no raw Docker request or subprocess command.
The separately installed process accepts only the fixed protocol implemented by
``linux_exec_lifetime_supervisor_process``.  Recovery never arms new work: it
only reconciles retained operations and replays unacknowledged terminal events.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from .engine_docker_transport import LinuxDockerDaemonEndpoint
from .engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2
from .engine_exec_operation_supervisor import (
    EngineExecOperationSupervisorError,
    ExecLifetimeOperationRequestV2,
    ExecLifetimeSupervisorActivationV2,
    ExecLifetimeSupervisorBindingV2,
    ExecLifetimeTerminalReceiptV2,
)
from .linux_exec_supervisor_docker import SupervisorDockerContainerIdentity
from .util import content_hash


class LinuxExecLifetimeSupervisorError(EngineExecOperationSupervisorError):
    """The protected Linux supervisor is unavailable or changed identity."""


_SUPPORTED_API_VERSION = "v1.43"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMANDS = frozenset(
    {
        "activate",
        "reopen",
        "arm",
        "live",
        "complete",
        "terminate",
        "terminal_events",
        "ack_terminal",
        "close",
    }
)
_MAX_FRAME_BYTES = 64 * 1024
_TOKEN_BYTES = 32
_SO_PEERCRED_SIZE = struct.calcsize("3i")
_PROCESS_MODULE = "bluefire.linux_exec_lifetime_supervisor_process"


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LinuxExecLifetimeSupervisorError(f"{label} is invalid")
    return value


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LinuxExecLifetimeSupervisorError("supervisor message is not canonical JSON") from exc
    if len(encoded) > _MAX_FRAME_BYTES:
        raise LinuxExecLifetimeSupervisorError("supervisor message exceeds its bound")
    return encoded


def _strict_object(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_FRAME_BYTES:
        raise LinuxExecLifetimeSupervisorError("supervisor response exceeds its bound")

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise LinuxExecLifetimeSupervisorError(
                    "supervisor response contains duplicate fields"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                LinuxExecLifetimeSupervisorError("supervisor response is non-finite")
            ),
        )
    except LinuxExecLifetimeSupervisorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LinuxExecLifetimeSupervisorError("supervisor response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise LinuxExecLifetimeSupervisorError("supervisor response is not an object")
    return value


def _mac(token: bytes, document: Mapping[str, object]) -> str:
    return hmac.new(token, _canonical(document), hashlib.sha256).hexdigest()


def _proc_start_ticks(process_id: int) -> int:
    if sys.platform != "linux":
        raise LinuxExecLifetimeSupervisorError("Linux supervisor requires Linux")
    try:
        raw = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        closing = raw.rfind(")")
        values = raw[closing + 2 :].split()
        value = int(values[19])
    except (OSError, ValueError, IndexError) as exc:
        raise LinuxExecLifetimeSupervisorError(
            "controller process identity is unavailable"
        ) from exc
    if value <= 0:
        raise LinuxExecLifetimeSupervisorError("controller process identity is invalid")
    return value


def _secure_directory(path: Path, *, create: bool) -> tuple[int, int]:
    if not path.is_absolute():
        raise LinuxExecLifetimeSupervisorError("supervisor state directory must be absolute")
    if create:
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as exc:
            raise LinuxExecLifetimeSupervisorError(
                "supervisor state directory could not be created"
            ) from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise LinuxExecLifetimeSupervisorError("supervisor state directory is unavailable") from exc
    expected_uid = os.geteuid()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != expected_uid
    ):
        raise LinuxExecLifetimeSupervisorError("supervisor state directory is not private")
    return int(info.st_dev), int(info.st_ino)


LinuxExecSupervisorContainerV2 = SupervisorDockerContainerIdentity


@dataclass(frozen=True, slots=True)
class LinuxExecLifetimeSupervisorProfileV2:
    """Protected construction profile; no field comes from model output."""

    state_directory: Path
    daemon_endpoint: LinuxDockerDaemonEndpoint
    api_version: str
    containers: tuple[SupervisorDockerContainerIdentity, ...]
    supervisor_qualification_ref: str
    heartbeat_interval_milliseconds: int = 200
    controller_loss_grace_milliseconds: int = 1500
    cleanup_timeout_milliseconds: int = 10_000
    startup_timeout_milliseconds: int = 5_000

    def __post_init__(self) -> None:
        if not isinstance(self.state_directory, Path) or not self.state_directory.is_absolute():
            raise LinuxExecLifetimeSupervisorError("supervisor state directory is invalid")
        if type(self.daemon_endpoint) is not LinuxDockerDaemonEndpoint:
            raise LinuxExecLifetimeSupervisorError("supervisor Docker endpoint is invalid")
        if self.api_version != _SUPPORTED_API_VERSION:
            raise LinuxExecLifetimeSupervisorError("supervisor Docker API version is invalid")
        if (
            type(self.containers) is not tuple
            or not self.containers
            or len(self.containers) > 128
            or any(type(item) is not SupervisorDockerContainerIdentity for item in self.containers)
            or tuple(sorted(self.containers, key=lambda item: item.container_id)) != self.containers
            or len({item.container_id for item in self.containers}) != len(self.containers)
        ):
            raise LinuxExecLifetimeSupervisorError("supervisor container inventory is invalid")
        _digest(self.supervisor_qualification_ref, "supervisor qualification")
        for value, minimum, maximum, label in (
            (self.heartbeat_interval_milliseconds, 50, 1_000, "heartbeat interval"),
            (self.controller_loss_grace_milliseconds, 250, 5_000, "controller loss grace"),
            (self.cleanup_timeout_milliseconds, 1_000, 30_000, "cleanup timeout"),
            (self.startup_timeout_milliseconds, 500, 15_000, "startup timeout"),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise LinuxExecLifetimeSupervisorError(f"supervisor {label} is invalid")
        if self.controller_loss_grace_milliseconds <= self.heartbeat_interval_milliseconds:
            raise LinuxExecLifetimeSupervisorError("supervisor heartbeat grace is too short")

    @property
    def profile_ref(self) -> str:
        return content_hash(self.document())

    def document(self) -> dict[str, object]:
        endpoint = self.daemon_endpoint
        return {
            "schema_version": "bluefire.linux-exec-supervisor-profile.v2",
            "state_directory": str(self.state_directory),
            "daemon_endpoint": {
                "socket_path": endpoint.socket_path,
                "daemon_instance_digest": endpoint.daemon_instance_digest,
                "socket_device": endpoint.socket_device,
                "socket_inode": endpoint.socket_inode,
                "peer_uid": endpoint.peer_uid,
                "peer_gid": endpoint.peer_gid,
                "peer_pid": endpoint.peer_pid,
            },
            "api_version": self.api_version,
            "containers": [asdict(item) for item in self.containers],
            "supervisor_qualification_ref": self.supervisor_qualification_ref,
            "heartbeat_interval_milliseconds": self.heartbeat_interval_milliseconds,
            "controller_loss_grace_milliseconds": self.controller_loss_grace_milliseconds,
            "cleanup_timeout_milliseconds": self.cleanup_timeout_milliseconds,
            "startup_timeout_milliseconds": self.startup_timeout_milliseconds,
        }


@dataclass(frozen=True, slots=True)
class LinuxExecTerminalEventV2:
    """A replayable terminal receipt retained until explicit acknowledgement."""

    cursor: int
    reason: str
    request_ref: str
    receipt: ExecLifetimeTerminalReceiptV2
    evidence_digest: str

    def __post_init__(self) -> None:
        if type(self.cursor) is not int or not 1 <= self.cursor < 2**63:
            raise LinuxExecLifetimeSupervisorError("terminal event cursor is invalid")
        if (
            not isinstance(self.reason, str)
            or not self.reason
            or len(self.reason) > 64
            or not self.reason.replace("_", "").isalnum()
        ):
            raise LinuxExecLifetimeSupervisorError("terminal event reason is invalid")
        _digest(self.request_ref, "terminal event request")
        _digest(self.evidence_digest, "terminal event evidence")
        if type(self.receipt) is not ExecLifetimeTerminalReceiptV2:
            raise LinuxExecLifetimeSupervisorError("terminal event receipt is invalid")
        if self.receipt.request_ref != self.request_ref:
            raise LinuxExecLifetimeSupervisorError("terminal event receipt changed")


def _proof_from_document(value: object) -> VerifiedExecLifetimeCustodyV2:
    if not isinstance(value, dict) or set(value) != set(
        VerifiedExecLifetimeCustodyV2.__dataclass_fields__
    ):
        raise LinuxExecLifetimeSupervisorError("supervisor live proof is invalid")
    try:
        return VerifiedExecLifetimeCustodyV2(**value)
    except (TypeError, ValueError) as exc:
        raise LinuxExecLifetimeSupervisorError("supervisor live proof is invalid") from exc


def _receipt_from_document(value: object) -> ExecLifetimeTerminalReceiptV2:
    fields = set(ExecLifetimeTerminalReceiptV2.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields:
        raise LinuxExecLifetimeSupervisorError("supervisor terminal receipt is invalid")
    try:
        return ExecLifetimeTerminalReceiptV2(**value)
    except (TypeError, ValueError) as exc:
        raise LinuxExecLifetimeSupervisorError("supervisor terminal receipt is invalid") from exc


def _event_from_document(value: object) -> LinuxExecTerminalEventV2:
    if not isinstance(value, dict) or set(value) != {
        "cursor",
        "reason",
        "request_ref",
        "receipt",
        "evidence_digest",
    }:
        raise LinuxExecLifetimeSupervisorError("supervisor terminal event is invalid")
    return LinuxExecTerminalEventV2(
        cursor=value["cursor"],
        reason=value["reason"],
        request_ref=value["request_ref"],
        receipt=_receipt_from_document(value["receipt"]),
        evidence_digest=value["evidence_digest"],
    )


class LinuxExternalExecLifetimeSupervisorV2:
    """Concrete protected supervisor client.

    ``new`` and ``reconcile`` are intentionally distinct.  Reconciliation can
    never arm new work, even if a caller invokes :meth:`arm` directly.
    """

    def __init__(
        self,
        profile: LinuxExecLifetimeSupervisorProfileV2,
        *,
        mode: Literal["new", "reconcile"],
    ) -> None:
        if type(profile) is not LinuxExecLifetimeSupervisorProfileV2:
            raise LinuxExecLifetimeSupervisorError("supervisor profile is invalid")
        if mode not in {"new", "reconcile"}:
            raise LinuxExecLifetimeSupervisorError("supervisor mode is invalid")
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise LinuxExecLifetimeSupervisorError("Linux supervisor is unsupported here")
        self._profile = profile
        self._mode = mode
        self._token: bytes | None = None
        self._binding: ExecLifetimeSupervisorBindingV2 | None = None
        self._socket: socket.socket | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._rpc_lock = threading.RLock()
        self._cursor = 0
        self._heartbeat_sequence = 0
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._cleanup_uncertain = False
        self._closed = False
        self._physical_pid = os.getpid()
        self._physical_uid = os.geteuid()
        self._physical_gid = os.getegid()
        self._physical_start_ticks = _proc_start_ticks(self._physical_pid)

    @classmethod
    def new(
        cls, profile: LinuxExecLifetimeSupervisorProfileV2
    ) -> LinuxExternalExecLifetimeSupervisorV2:
        return cls(profile, mode="new")

    @classmethod
    def reconcile(
        cls, profile: LinuxExecLifetimeSupervisorProfileV2
    ) -> LinuxExternalExecLifetimeSupervisorV2:
        return cls(profile, mode="reconcile")

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain

    @property
    def recovery_only(self) -> bool:
        return self._mode == "reconcile"

    def activate_new(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2:
        if self._mode != "new":
            raise LinuxExecLifetimeSupervisorError("recovery supervisor cannot activate new work")
        self._start(binding)
        response = self._rpc("activate", {"binding": asdict(binding)})
        activation = self._activation(response, expected_action="activated")
        self._start_heartbeat()
        return activation

    def reopen_existing(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2:
        if self._mode != "reconcile":
            raise LinuxExecLifetimeSupervisorError("new supervisor cannot reopen old work")
        self._start(binding)
        response = self._rpc("reopen", {"binding": asdict(binding)})
        activation = self._activation(response, expected_action="reopened")
        self._start_heartbeat()
        return activation

    def arm(self, request: ExecLifetimeOperationRequestV2) -> VerifiedExecLifetimeCustodyV2:
        if self._mode != "new":
            raise LinuxExecLifetimeSupervisorError("recovery supervisor cannot arm work")
        self._validate_request(request)
        return _proof_from_document(self._rpc("arm", {"request": asdict(request)})["proof"])

    def require_live(
        self, request: ExecLifetimeOperationRequestV2
    ) -> VerifiedExecLifetimeCustodyV2:
        self._validate_request(request)
        if self._mode != "new":
            raise LinuxExecLifetimeSupervisorError("recovery supervisor has no live leases")
        return _proof_from_document(self._rpc("live", {"request": asdict(request)})["proof"])

    def complete(self, request: ExecLifetimeOperationRequestV2) -> ExecLifetimeTerminalReceiptV2:
        self._validate_request(request)
        # EOF is never completion evidence.  The guardian always performs the
        # same whole-container absence path used by cancellation.
        return _receipt_from_document(
            self._rpc("complete", {"request": asdict(request)})["receipt"]
        )

    def terminate(
        self, request: ExecLifetimeOperationRequestV2, *, reason: str
    ) -> ExecLifetimeTerminalReceiptV2:
        self._validate_request(request)
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason):
            raise LinuxExecLifetimeSupervisorError("supervisor termination reason is invalid")
        return _receipt_from_document(
            self._rpc("terminate", {"request": asdict(request), "reason": reason})["receipt"]
        )

    def terminal_events(self) -> tuple[LinuxExecTerminalEventV2, ...]:
        response = self._rpc("terminal_events", {})
        values = response.get("events")
        if not isinstance(values, list) or len(values) > 128:
            raise LinuxExecLifetimeSupervisorError("supervisor terminal events are invalid")
        events = tuple(_event_from_document(item) for item in values)
        if tuple(sorted(events, key=lambda item: item.cursor)) != events:
            raise LinuxExecLifetimeSupervisorError("supervisor terminal event order changed")
        return events

    def acknowledge_terminal(self, *, cursor: int, receipt_ref: str) -> None:
        if type(cursor) is not int or not 1 <= cursor < 2**63:
            raise LinuxExecLifetimeSupervisorError("terminal acknowledgement cursor is invalid")
        _digest(receipt_ref, "terminal acknowledgement receipt")
        self._rpc("ack_terminal", {"cursor": cursor, "receipt_ref": receipt_ref})

    def detach(self) -> None:
        """Disconnect without acknowledging or discarding terminal evidence."""
        self._stop_heartbeat()
        with self._rpc_lock:
            self._close_socket()

    def close(self) -> None:
        if self._closed:
            if self._cleanup_uncertain:
                raise LinuxExecLifetimeSupervisorError("supervisor cleanup remains uncertain")
            return
        self._stop_heartbeat()
        try:
            self._rpc("close", {})
        except Exception:
            self._cleanup_uncertain = True
            self._close_socket()
            raise
        self._closed = True
        self._close_socket()
        process = self._process
        if process is not None:
            try:
                process.wait(timeout=self._profile.cleanup_timeout_milliseconds / 1000)
            except subprocess.TimeoutExpired as exc:
                self._cleanup_uncertain = True
                raise LinuxExecLifetimeSupervisorError("supervisor process did not close") from exc
            if process.returncode != 0:
                self._cleanup_uncertain = True
                raise LinuxExecLifetimeSupervisorError("supervisor process close failed")

    def _start(self, binding: ExecLifetimeSupervisorBindingV2) -> None:
        if type(binding) is not ExecLifetimeSupervisorBindingV2:
            raise LinuxExecLifetimeSupervisorError("supervisor binding is invalid")
        if self._binding is not None or self._socket is not None:
            raise LinuxExecLifetimeSupervisorError("supervisor is already started")
        if binding.supervisor_qualification_ref != self._profile.supervisor_qualification_ref:
            raise LinuxExecLifetimeSupervisorError("supervisor qualification changed")
        state = self._profile.state_directory
        device, inode = _secure_directory(state, create=self._mode == "new")
        token_path = state / "controller.capability"
        launch_path = state / (f"broker-launch-{self._physical_pid}-{secrets.token_hex(8)}.json")
        if self._mode == "new":
            token = secrets.token_bytes(_TOKEN_BYTES)
            self._write_private(token_path, token)
        else:
            token = self._read_private_token(token_path)
        launch = {
            "schema_version": "bluefire.linux-exec-supervisor-launch.v2",
            "mode": self._mode,
            "profile": self._profile.document(),
            "profile_ref": self._profile.profile_ref,
            "binding": asdict(binding),
            "binding_ref": binding.binding_ref,
            "state_device": device,
            "state_inode": inode,
            "controller": {
                "pid": self._physical_pid,
                "uid": self._physical_uid,
                "gid": self._physical_gid,
                "start_ticks": self._physical_start_ticks,
            },
        }
        self._write_private(launch_path, _canonical(launch))
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8",
        }
        package_root = Path(__file__).resolve().parent.parent
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    _PROCESS_MODULE,
                    "broker",
                    str(launch_path),
                ],
                cwd=str(package_root),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise LinuxExecLifetimeSupervisorError("supervisor process could not start") from exc
        self._binding = binding
        self._token = token
        self._process = process
        try:
            self._connect(process, launch_path)
        except Exception:
            self._cleanup_uncertain = self._mode == "reconcile"
            if process.poll() is None and self._mode == "new":
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            raise

    def _connect(self, process: subprocess.Popen[bytes], launch_path: Path) -> None:
        path = self._profile.state_directory / "broker.sock"
        deadline = time.monotonic() + self._profile.startup_timeout_milliseconds / 1000
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            error_path = launch_path.with_name(launch_path.name + ".error.json")
            if error_path.exists():
                try:
                    error = _strict_object(error_path.read_bytes())
                    code = error.get("code")
                except Exception:
                    code = "unavailable"
                raise LinuxExecLifetimeSupervisorError(f"supervisor startup refused {code}")
            if process.poll() is not None:
                raise LinuxExecLifetimeSupervisorError("supervisor process exited during startup")
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            candidate.settimeout(0.2)
            try:
                candidate.connect(str(path))
                peer = struct.unpack(
                    "3i",
                    candidate.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _SO_PEERCRED_SIZE),
                )
                if peer[0] != process.pid or peer[1] != self._physical_uid:
                    raise LinuxExecLifetimeSupervisorError("supervisor peer identity changed")
                candidate.settimeout(1.0)
                self._socket = candidate
                self._hello()
                return
            except OSError as exc:
                last_error = exc
                candidate.close()
                time.sleep(0.02)
            except Exception:
                candidate.close()
                raise
        raise LinuxExecLifetimeSupervisorError("supervisor startup timed out") from last_error

    def _hello(self) -> None:
        if self._socket is None or self._token is None or self._binding is None:
            raise LinuxExecLifetimeSupervisorError("supervisor hello is unavailable")
        document: dict[str, object] = {
            "schema_version": "bluefire.linux-exec-supervisor-hello.v2",
            "binding_ref": self._binding.binding_ref,
            "controller_instance_ref": self._binding.controller_instance_ref,
            "controller_pid": self._physical_pid,
            "controller_uid": self._physical_uid,
            "controller_gid": self._physical_gid,
            "controller_start_ticks": self._physical_start_ticks,
        }
        raw = _canonical({**document, "mac": _mac(self._token, document)})
        try:
            if self._socket.send(raw) != len(raw):
                raise OSError("short hello")
            response = _strict_object(self._socket.recv(_MAX_FRAME_BYTES + 1))
        except (OSError, TimeoutError) as exc:
            raise LinuxExecLifetimeSupervisorError("supervisor hello failed") from exc
        mac = response.pop("mac", None)
        if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(self._token, response)):
            raise LinuxExecLifetimeSupervisorError("supervisor hello authentication failed")
        if set(response) != {
            "schema_version",
            "binding_ref",
            "last_rpc_cursor",
            "pending_rpc",
        }:
            raise LinuxExecLifetimeSupervisorError("supervisor hello fields changed")
        cursor = response["last_rpc_cursor"]
        if (
            response["schema_version"] != "bluefire.linux-exec-supervisor-hello-ack.v2"
            or response["binding_ref"] != self._binding.binding_ref
            or type(cursor) is not int
            or not 0 <= cursor < 2**63
            or type(response["pending_rpc"]) is not bool
            or response["pending_rpc"]
        ):
            raise LinuxExecLifetimeSupervisorError("supervisor hello binding changed")
        self._cursor = cursor

    def _rpc(self, command: str, payload: Mapping[str, object]) -> dict[str, Any]:
        if command not in _COMMANDS:
            raise LinuxExecLifetimeSupervisorError("supervisor command is invalid")
        with self._rpc_lock:
            if self._closed or self._socket is None or self._token is None or self._binding is None:
                raise LinuxExecLifetimeSupervisorError("supervisor connection is unavailable")
            cursor = self._cursor + 1
            document: dict[str, object] = {
                "schema_version": "bluefire.linux-exec-supervisor-rpc.v2",
                "cursor": cursor,
                "command": command,
                "binding_ref": self._binding.binding_ref,
                "controller_instance_ref": self._binding.controller_instance_ref,
                "controller_pid": self._physical_pid,
                "controller_uid": self._physical_uid,
                "controller_gid": self._physical_gid,
                "controller_start_ticks": self._physical_start_ticks,
                "payload": dict(payload),
            }
            signed = {**document, "mac": _mac(self._token, document)}
            raw = _canonical(signed)
            try:
                if command == "arm":
                    # Arm includes a separately spawned guardian and its
                    # authenticated first heartbeat before it can return.
                    timeout = self._profile.startup_timeout_milliseconds / 1000 + 2
                elif command in {"reopen", "close"}:
                    # Reopening may need to reconcile every retained owned
                    # container. The broker binds its socket before doing so.
                    timeout = (
                        len(self._profile.containers)
                        * (
                            self._profile.cleanup_timeout_milliseconds
                            + self._profile.controller_loss_grace_milliseconds
                            + 2_000
                        )
                        / 1000
                        + 2
                    )
                elif command in {"complete", "terminate"}:
                    timeout = self._profile.cleanup_timeout_milliseconds / 1000 + 2
                elif command == "live":
                    timeout = 2.0
                else:
                    timeout = 1.0
                self._socket.settimeout(timeout)
                sent = self._socket.send(raw)
                if sent != len(raw):
                    raise LinuxExecLifetimeSupervisorError("supervisor request was truncated")
                response = _strict_object(self._socket.recv(_MAX_FRAME_BYTES + 1))
            except (OSError, TimeoutError) as exc:
                self._cleanup_uncertain = True
                raise LinuxExecLifetimeSupervisorError(
                    "supervisor response is unavailable"
                ) from exc
            finally:
                if self._socket is not None:
                    try:
                        self._socket.settimeout(1.0)
                    except OSError:
                        self._cleanup_uncertain = True
            mac = response.pop("mac", None)
            if not isinstance(mac, str) or not hmac.compare_digest(
                mac, _mac(self._token, response)
            ):
                self._cleanup_uncertain = True
                raise LinuxExecLifetimeSupervisorError("supervisor response authentication failed")
            if set(response) != {"schema_version", "cursor", "request_digest", "ok", "result"}:
                raise LinuxExecLifetimeSupervisorError("supervisor response fields changed")
            if (
                response["schema_version"] != "bluefire.linux-exec-supervisor-response.v2"
                or response["cursor"] != cursor
                or response["request_digest"] != content_hash(document)
                or type(response["ok"]) is not bool
                or not isinstance(response["result"], dict)
            ):
                raise LinuxExecLifetimeSupervisorError("supervisor response binding changed")
            self._cursor = cursor
            if not response["ok"]:
                code = response["result"].get("code")
                if not isinstance(code, str) or not code:
                    code = "refused"
                if code in {
                    "cleanup_uncertain",
                    "guardian_unavailable",
                    "deadline_elapsed",
                    "recovered_uncertain",
                }:
                    self._cleanup_uncertain = True
                raise LinuxExecLifetimeSupervisorError(f"supervisor refused {code}")
            return response["result"]

    def _heartbeat(self) -> None:
        with self._rpc_lock:
            if self._socket is None or self._token is None or self._binding is None:
                return
            self._heartbeat_sequence += 1
            document: dict[str, object] = {
                "schema_version": "bluefire.linux-exec-supervisor-heartbeat.v2",
                "sequence": self._heartbeat_sequence,
                "binding_ref": self._binding.binding_ref,
                "controller_instance_ref": self._binding.controller_instance_ref,
                "controller_pid": self._physical_pid,
                "controller_start_ticks": self._physical_start_ticks,
            }
            raw = _canonical({**document, "mac": _mac(self._token, document)})
            try:
                if self._socket.send(raw) != len(raw):
                    raise OSError("short heartbeat")
                response = _strict_object(self._socket.recv(_MAX_FRAME_BYTES + 1))
                mac = response.pop("mac", None)
                if (
                    not isinstance(mac, str)
                    or not hmac.compare_digest(mac, _mac(self._token, response))
                    or response
                    != {
                        "schema_version": "bluefire.linux-exec-supervisor-heartbeat-ack.v2",
                        "sequence": self._heartbeat_sequence,
                    }
                ):
                    raise OSError("heartbeat authentication failed")
            except (OSError, TimeoutError, LinuxExecLifetimeSupervisorError):
                self._cleanup_uncertain = True
                self._heartbeat_stop.set()

    def _start_heartbeat(self) -> None:
        if self._heartbeat_thread is not None:
            raise LinuxExecLifetimeSupervisorError("supervisor heartbeat is already active")
        thread = threading.Thread(
            target=self._heartbeat_loop,
            name="bluefire-exec-supervisor-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread = thread
        thread.start()

    def _heartbeat_loop(self) -> None:
        interval = self._profile.heartbeat_interval_milliseconds / 1000
        while not self._heartbeat_stop.wait(interval):
            self._heartbeat()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
            if thread.is_alive():
                self._cleanup_uncertain = True

    def _close_socket(self) -> None:
        current, self._socket = self._socket, None
        if current is not None:
            try:
                current.close()
            except OSError:
                self._cleanup_uncertain = True

    def _activation(
        self, response: Mapping[str, object], *, expected_action: Literal["activated", "reopened"]
    ) -> ExecLifetimeSupervisorActivationV2:
        value = response.get("activation")
        if not isinstance(value, dict):
            raise LinuxExecLifetimeSupervisorError("supervisor activation is invalid")
        expected = set(ExecLifetimeSupervisorActivationV2.__dataclass_fields__)
        if set(value) != expected:
            raise LinuxExecLifetimeSupervisorError("supervisor activation fields changed")
        row = dict(value)
        active = row.get("active_leases")
        terminals = row.get("terminal_receipts")
        if not isinstance(active, list) or not isinstance(terminals, list):
            raise LinuxExecLifetimeSupervisorError("supervisor activation inventory is invalid")
        row["active_leases"] = tuple(_proof_from_document(item) for item in active)
        row["terminal_receipts"] = tuple(_receipt_from_document(item) for item in terminals)
        try:
            activation = ExecLifetimeSupervisorActivationV2(**row)
        except (TypeError, ValueError) as exc:
            raise LinuxExecLifetimeSupervisorError("supervisor activation is invalid") from exc
        if activation.action != expected_action:
            raise LinuxExecLifetimeSupervisorError("supervisor activation action changed")
        return activation

    def _validate_request(self, request: ExecLifetimeOperationRequestV2) -> None:
        if type(request) is not ExecLifetimeOperationRequestV2 or self._binding is None:
            raise LinuxExecLifetimeSupervisorError("supervisor operation request is invalid")
        binding = self._binding
        inventory = {item.container_id for item in self._profile.containers}
        if (
            request.container_id not in inventory
            or request.attempt_id != binding.attempt_id
            or request.claim_ref != binding.claim_ref
            or request.controller_fence != binding.controller_fence
            or request.custody_plan_digest != binding.custody_plan_digest
            or request.network_policy_digest != binding.network_policy_digest
            or request.controller_instance_ref != binding.controller_instance_ref
        ):
            raise LinuxExecLifetimeSupervisorError("supervisor operation authority changed")

    @staticmethod
    def _write_private(path: Path, value: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise LinuxExecLifetimeSupervisorError(
                "supervisor private launch material could not be retained"
            ) from exc

    @staticmethod
    def _read_private_token(path: Path) -> bytes:
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid()
            ):
                raise LinuxExecLifetimeSupervisorError("supervisor capability is not private")
            value = path.read_bytes()
        except OSError as exc:
            raise LinuxExecLifetimeSupervisorError("supervisor capability is unavailable") from exc
        if len(value) != _TOKEN_BYTES:
            raise LinuxExecLifetimeSupervisorError("supervisor capability is invalid")
        return value


__all__ = [
    "LinuxExecLifetimeSupervisorError",
    "LinuxExecLifetimeSupervisorProfileV2",
    "LinuxExecSupervisorContainerV2",
    "LinuxExecTerminalEventV2",
    "LinuxExternalExecLifetimeSupervisorV2",
]
