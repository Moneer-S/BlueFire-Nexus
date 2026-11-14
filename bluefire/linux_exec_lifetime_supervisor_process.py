"""Fixed broker and per-operation guardian for Linux exec supervision.

This is an installed controller entrypoint, not a worker or model tool.  Its
only command-line surface selects one of two fixed roles and one controller-
written private launch file.  Neither role accepts Docker methods, paths,
bodies, shell text, or arbitrary executable content over IPC.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, NoReturn

from .engine_docker_transport import LinuxDockerDaemonEndpoint
from .engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2
from .engine_exec_operation_supervisor import (
    ExecLifetimeOperationRequestV2,
    ExecLifetimeSupervisorActivationV2,
    ExecLifetimeSupervisorBindingV2,
    ExecLifetimeTerminalReceiptV2,
)
from .linux_exec_lifetime_supervisor import (
    LinuxExecLifetimeSupervisorProfileV2,
    LinuxExecSupervisorContainerV2,
)
from .linux_exec_supervisor_docker import (
    ControllerOwnedDockerCleanupCancellation,
    FixedDockerExecCleanup,
    LinuxExecSupervisorDockerError,
    SupervisorDockerContainerIdentity,
)
from .linux_exec_supervisor_journal import (
    ExecSupervisorJournalIdentityV2,
    LinuxExecSupervisorJournalError,
    SQLiteLinuxExecSupervisorJournalV2,
    SupervisorOperationRecordV2,
)
from .util import content_hash

_MAX_FRAME = 64 * 1024
_MAX_GUARDIANS = 128
_TOKEN_BYTES = 32
_SO_PEERCRED_SIZE = struct.calcsize("3i")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_BROKER_COMMANDS = frozenset(
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


class _ProcessError(RuntimeError):
    def __init__(self, code: str, *, uncertain: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _ProcessError("message_invalid") from exc
    if not result or len(result) > _MAX_FRAME:
        raise _ProcessError("message_limit")
    return result


def _object(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_FRAME:
        raise _ProcessError("message_limit")

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise _ProcessError("message_duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(_ProcessError("message_number")),
        )
    except _ProcessError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _ProcessError("message_invalid") from exc
    if not isinstance(value, dict):
        raise _ProcessError("message_invalid")
    return value


def _mac(token: bytes, value: Mapping[str, object]) -> str:
    return hmac.new(token, _canonical(value), hashlib.sha256).hexdigest()


def _verified_message(raw: bytes, token: bytes) -> dict[str, Any]:
    value = _object(raw)
    supplied = value.pop("mac", None)
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, _mac(token, value)):
        raise _ProcessError("message_authentication")
    return value


def _signed(value: Mapping[str, object], token: bytes) -> bytes:
    document = dict(value)
    return _canonical({**document, "mac": _mac(token, document)})


def _strict_file(path: Path, *, maximum: int = _MAX_FRAME) -> bytes:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
            or info.st_size <= 0
            or info.st_size > maximum
        ):
            raise _ProcessError("private_file_identity")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise _ProcessError("private_file_changed")
            value = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _ProcessError("private_file_unavailable") from exc
    if not value or len(value) > maximum:
        raise _ProcessError("private_file_limit")
    return value


def _secure_state(path: Path, device: int, inode: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise _ProcessError("state_unavailable") from exc
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid()
        or (info.st_dev, info.st_ino) != (device, inode)
    ):
        raise _ProcessError("state_identity")


def _write_atomic(path: Path, value: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(value)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise _ProcessError("private_write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _proc_start_ticks(process_id: int) -> int:
    try:
        raw = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        closing = raw.rfind(")")
        result = int(raw[closing + 2 :].split()[19])
    except (OSError, ValueError, IndexError) as exc:
        raise _ProcessError("process_identity") from exc
    if result <= 0:
        raise _ProcessError("process_identity")
    return result


def _pidfd(process_id: int, start_ticks: int) -> int:
    if _proc_start_ticks(process_id) != start_ticks:
        raise _ProcessError("process_identity")
    opener = getattr(os, "pidfd_open", None)
    if not callable(opener):
        raise _ProcessError("pidfd_unavailable")
    try:
        descriptor = int(opener(process_id, 0))
    except OSError as exc:
        raise _ProcessError("pidfd_unavailable") from exc
    if _proc_start_ticks(process_id) != start_ticks:
        os.close(descriptor)
        raise _ProcessError("process_identity")
    return descriptor


def _pidfd_ready(descriptor: int) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _boot_epoch() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise _ProcessError("boot_identity") from exc
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise _ProcessError("boot_identity")
    return content_hash({"schema_version": "bluefire.linux-clock-epoch.v1", "boot_id": value})


def _endpoint(value: object) -> LinuxDockerDaemonEndpoint:
    fields = set(LinuxDockerDaemonEndpoint.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields:
        raise _ProcessError("endpoint_invalid")
    try:
        return LinuxDockerDaemonEndpoint(**value)
    except (TypeError, ValueError) as exc:
        raise _ProcessError("endpoint_invalid") from exc


def _container(value: object) -> SupervisorDockerContainerIdentity:
    fields = set(SupervisorDockerContainerIdentity.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields:
        raise _ProcessError("container_identity")
    row = dict(value)
    labels = row.get("required_labels")
    if not isinstance(labels, list):
        raise _ProcessError("container_identity")
    row["required_labels"] = tuple(tuple(item) for item in labels)
    try:
        return LinuxExecSupervisorContainerV2(**row)
    except (TypeError, ValueError) as exc:
        raise _ProcessError("container_identity") from exc


def _profile(value: object) -> LinuxExecLifetimeSupervisorProfileV2:
    fields = {
        "schema_version",
        "state_directory",
        "daemon_endpoint",
        "api_version",
        "containers",
        "supervisor_qualification_ref",
        "heartbeat_interval_milliseconds",
        "controller_loss_grace_milliseconds",
        "cleanup_timeout_milliseconds",
        "startup_timeout_milliseconds",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise _ProcessError("profile_invalid")
    containers = value["containers"]
    if value["schema_version"] != "bluefire.linux-exec-supervisor-profile.v2" or not isinstance(
        containers, list
    ):
        raise _ProcessError("profile_invalid")
    try:
        return LinuxExecLifetimeSupervisorProfileV2(
            state_directory=Path(value["state_directory"]),
            daemon_endpoint=_endpoint(value["daemon_endpoint"]),
            api_version=value["api_version"],
            containers=tuple(_container(item) for item in containers),
            supervisor_qualification_ref=value["supervisor_qualification_ref"],
            heartbeat_interval_milliseconds=value["heartbeat_interval_milliseconds"],
            controller_loss_grace_milliseconds=value["controller_loss_grace_milliseconds"],
            cleanup_timeout_milliseconds=value["cleanup_timeout_milliseconds"],
            startup_timeout_milliseconds=value["startup_timeout_milliseconds"],
        )
    except (TypeError, ValueError) as exc:
        raise _ProcessError("profile_invalid") from exc


def _binding(value: object) -> ExecLifetimeSupervisorBindingV2:
    if not isinstance(value, dict) or set(value) != set(
        ExecLifetimeSupervisorBindingV2.__dataclass_fields__
    ):
        raise _ProcessError("binding_invalid")
    try:
        return ExecLifetimeSupervisorBindingV2(**value)
    except (TypeError, ValueError) as exc:
        raise _ProcessError("binding_invalid") from exc


def _request(value: object) -> ExecLifetimeOperationRequestV2:
    if not isinstance(value, dict) or set(value) != set(
        ExecLifetimeOperationRequestV2.__dataclass_fields__
    ):
        raise _ProcessError("request_invalid")
    try:
        return ExecLifetimeOperationRequestV2(**value)
    except (TypeError, ValueError) as exc:
        raise _ProcessError("request_invalid") from exc


def _proof(value: object) -> VerifiedExecLifetimeCustodyV2:
    if not isinstance(value, dict) or set(value) != set(
        VerifiedExecLifetimeCustodyV2.__dataclass_fields__
    ):
        raise _ProcessError("proof_invalid")
    try:
        return VerifiedExecLifetimeCustodyV2(**value)
    except (TypeError, ValueError) as exc:
        raise _ProcessError("proof_invalid") from exc


def _request_document(value: ExecLifetimeOperationRequestV2) -> dict[str, object]:
    return {"schema_version": "bluefire.exec-lifetime-operation-request.v2", **asdict(value)}


def _proof_document(value: VerifiedExecLifetimeCustodyV2) -> dict[str, object]:
    return {"schema_version": "bluefire.verified-exec-lifetime-custody.v2", **asdict(value)}


def _receipt_from_document(value: Mapping[str, Any]) -> ExecLifetimeTerminalReceiptV2:
    row = dict(value)
    if row.pop("schema_version", None) != "bluefire.exec-lifetime-terminal-receipt.v2":
        raise _ProcessError("receipt_invalid")
    try:
        return ExecLifetimeTerminalReceiptV2(**row, receipt_ref=content_hash(value))
    except (TypeError, ValueError) as exc:
        raise _ProcessError("receipt_invalid") from exc


def _physical(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"pid", "uid", "gid", "start_ticks"}:
        raise _ProcessError(f"{label}_identity")
    if any(
        type(value[name]) is not int or value[name] < (1 if name in {"pid", "start_ticks"} else 0)
        for name in value
    ):
        raise _ProcessError(f"{label}_identity")
    return {name: int(value[name]) for name in value}


def _socket_listener(path: Path) -> socket.socket:
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise _ProcessError("socket_identity")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.settimeout(0.05)
                probe.connect(str(path))
            except OSError:
                path.unlink()
            else:
                raise _ProcessError("supervisor_already_running")
            finally:
                probe.close()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(1)
        listener.settimeout(0.1)
        return listener
    except OSError as exc:
        raise _ProcessError("socket_unavailable") from exc


def _peer(channel: socket.socket) -> tuple[int, int, int]:
    try:
        return struct.unpack(
            "3i",
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _SO_PEERCRED_SIZE),
        )
    except OSError as exc:
        raise _ProcessError("peer_identity") from exc


def _send(channel: socket.socket, raw: bytes) -> None:
    try:
        if channel.send(raw) != len(raw):
            raise _ProcessError("channel_truncated")
    except OSError as exc:
        raise _ProcessError("channel_unavailable") from exc


def _receive(channel: socket.socket) -> bytes:
    try:
        value = channel.recv(_MAX_FRAME + 1)
    except socket.timeout:
        raise
    except OSError as exc:
        raise _ProcessError("channel_unavailable") from exc
    if not value:
        raise EOFError
    if len(value) > _MAX_FRAME:
        raise _ProcessError("message_limit")
    return value


def _terminal(
    request: ExecLifetimeOperationRequestV2,
    proof: VerifiedExecLifetimeCustodyV2,
    *,
    clock_epoch_ref: str,
    final_inventory_digest: str,
) -> ExecLifetimeTerminalReceiptV2:
    return ExecLifetimeTerminalReceiptV2.create(
        request_ref=request.request_ref,
        lease_ref=proof.lease_ref,
        lease_generation=proof.lease_generation,
        outcome="verified_absent",
        completion_qualification_ref=None,
        final_inventory_digest=final_inventory_digest,
        clock_epoch_ref=clock_epoch_ref,
        observed_monotonic_ns=max(1, time.monotonic_ns()),
        background_work_absent=True,
        container_absent=True,
    )


def _cleanup_exact(
    profile: LinuxExecLifetimeSupervisorProfileV2,
    request: ExecLifetimeOperationRequestV2,
    proof: VerifiedExecLifetimeCustodyV2,
    *,
    clock_epoch_ref: str,
) -> tuple[ExecLifetimeTerminalReceiptV2, str]:
    identities = {item.container_id: item for item in profile.containers}
    identity = identities.get(request.container_id)
    if identity is None:
        raise _ProcessError("container_unowned", uncertain=True)
    deadline = time.monotonic_ns() + profile.cleanup_timeout_milliseconds * 1_000_000
    try:
        result = FixedDockerExecCleanup.open(
            profile.daemon_endpoint,
            api_version=profile.api_version,
            stop_timeout_seconds=min(10, profile.cleanup_timeout_milliseconds // 1000),
        ).cleanup(
            identity,
            deadline_monotonic_ns=deadline,
            cancellation=ControllerOwnedDockerCleanupCancellation(),
        )
    except LinuxExecSupervisorDockerError as exc:
        raise _ProcessError("cleanup_uncertain", uncertain=True) from exc
    if not result.live_daemon_proof or result.test_provider:
        raise _ProcessError("cleanup_unqualified", uncertain=True)
    receipt = _terminal(
        request,
        proof,
        clock_epoch_ref=clock_epoch_ref,
        final_inventory_digest=result.final_inventory_digest,
    )
    evidence = content_hash(
        {
            "schema_version": "bluefire.linux-exec-supervisor-terminal-evidence.v2",
            "request_ref": request.request_ref,
            "proof_ref": proof.proof_ref,
            "container_identity_digest": identity.identity_digest,
            "daemon_instance_digest": result.daemon_instance_digest,
            "request_digests": list(result.request_digests),
            "response_digests": list(result.response_digests),
            "final_inventory_digest": result.final_inventory_digest,
        }
    )
    return receipt, evidence


def _load_launch(path: Path, expected_schema: str) -> dict[str, Any]:
    value = _object(_strict_file(path))
    if value.get("schema_version") != expected_schema:
        raise _ProcessError("launch_schema")
    return value


def _guardian_terminal_path(directory: Path) -> Path:
    return directory / "terminal.json"


def _guardian_uncertain_path(directory: Path) -> Path:
    return directory / "cleanup-uncertain.json"


def _finish_guardian(
    profile: LinuxExecLifetimeSupervisorProfileV2,
    request: ExecLifetimeOperationRequestV2,
    proof: VerifiedExecLifetimeCustodyV2,
    *,
    clock_epoch_ref: str,
    directory: Path,
    reason: str,
) -> int:
    """Retain exact absence or uncertainty, including startup failure paths."""

    try:
        receipt, evidence = _cleanup_exact(profile, request, proof, clock_epoch_ref=clock_epoch_ref)
        terminal = {
            "schema_version": "bluefire.linux-exec-guardian-terminal.v2",
            "reason": reason,
            "request": _request_document(request),
            "proof": _proof_document(proof),
            "receipt": receipt.document(include_ref=False),
            "receipt_ref": receipt.receipt_ref,
            "evidence_digest": evidence,
        }
        _write_atomic(_guardian_terminal_path(directory), _canonical(terminal))
        return 0
    except Exception:
        _write_atomic(
            _guardian_uncertain_path(directory),
            _canonical(
                {
                    "schema_version": "bluefire.linux-exec-guardian-uncertain.v2",
                    "reason": reason,
                    "request_ref": request.request_ref,
                    "proof_ref": proof.proof_ref,
                }
            ),
        )
        return 70


def _guardian_process(launch_path: Path) -> int:
    launch = _load_launch(launch_path, "bluefire.linux-exec-guardian-launch.v2")
    expected = {
        "schema_version",
        "profile",
        "profile_ref",
        "binding_ref",
        "request",
        "request_ref",
        "proof",
        "proof_ref",
        "clock_epoch_ref",
        "controller",
        "broker",
        "guardian_directory",
    }
    if set(launch) != expected:
        raise _ProcessError("guardian_launch_fields")
    profile = _profile(launch["profile"])
    if profile.profile_ref != launch["profile_ref"]:
        raise _ProcessError("guardian_profile_changed")
    request = _request(launch["request"])
    proof = _proof(launch["proof"])
    if request.request_ref != launch["request_ref"] or proof.proof_ref != launch["proof_ref"]:
        raise _ProcessError("guardian_operation_changed")
    controller = _physical(launch["controller"], "controller")
    broker = _physical(launch["broker"], "broker")
    directory = Path(launch["guardian_directory"])
    if directory.parent != profile.state_directory or directory.name != request.operation_id:
        raise _ProcessError("guardian_directory_changed")
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise _ProcessError("guardian_directory_identity")
    controller_pidfd: int | None = None
    broker_pidfd: int | None = None
    listener: socket.socket | None = None
    try:
        token = _strict_file(directory / "guardian.capability", maximum=_TOKEN_BYTES)
        if len(token) != _TOKEN_BYTES:
            raise _ProcessError("guardian_capability")
        controller_pidfd = _pidfd(controller["pid"], controller["start_ticks"])
        broker_pidfd = _pidfd(broker["pid"], broker["start_ticks"])
        listener = _socket_listener(directory / "guardian.sock")
        _write_atomic(
            directory / "guardian.ready.json",
            _canonical(
                {
                    "schema_version": "bluefire.linux-exec-guardian-ready.v2",
                    "guardian_pid": os.getpid(),
                    "request_ref": request.request_ref,
                    "proof_ref": proof.proof_ref,
                }
            ),
        )
    except Exception:
        # If either parent exits during guardian startup, pidfd_open can fail
        # before the monitor loop begins. The admitted container must still be
        # removed; startup failure cannot silently drop its final owner.
        if listener is not None:
            listener.close()
        if controller_pidfd is not None:
            os.close(controller_pidfd)
        if broker_pidfd is not None:
            os.close(broker_pidfd)
        return _finish_guardian(
            profile,
            request,
            proof,
            clock_epoch_ref=launch["clock_epoch_ref"],
            directory=directory,
            reason="guardian_start_failed",
        )
    heartbeat_deadline = (
        time.monotonic_ns() + profile.controller_loss_grace_milliseconds * 1_000_000
    )
    channel: socket.socket | None = None
    last_sequence = 0
    reason = "guardian_unavailable"
    current_proof = proof
    try:
        while True:
            now = time.monotonic_ns()
            if now >= request.operation_deadline_monotonic_ns:
                reason = "deadline_elapsed"
                break
            if _pidfd_ready(controller_pidfd):
                reason = "controller_lost"
                break
            if _pidfd_ready(broker_pidfd):
                reason = "broker_lost"
                break
            if now >= heartbeat_deadline:
                reason = "heartbeat_elapsed"
                break
            if channel is None:
                try:
                    candidate, _ = listener.accept()
                    candidate.settimeout(0.1)
                    if _peer(candidate) != (broker["pid"], broker["uid"], broker["gid"]):
                        candidate.close()
                        continue
                    channel = candidate
                except socket.timeout:
                    continue
            try:
                message = _verified_message(_receive(channel), token)
            except socket.timeout:
                continue
            except EOFError:
                reason = "broker_channel_lost"
                break
            if message.get("schema_version") != "bluefire.linux-exec-guardian-command.v2":
                reason = "guardian_protocol_changed"
                break
            command = message.get("command")
            if message.get("request_ref") != request.request_ref:
                reason = "guardian_request_changed"
                break
            if command == "heartbeat":
                sequence = message.get("sequence")
                if type(sequence) is not int or sequence != last_sequence + 1:
                    reason = "guardian_heartbeat_replayed"
                    break
                last_sequence = sequence
                heartbeat_deadline = (
                    time.monotonic_ns() + profile.controller_loss_grace_milliseconds * 1_000_000
                )
                _send(
                    channel,
                    _signed(
                        {
                            "schema_version": "bluefire.linux-exec-guardian-ack.v2",
                            "command": "heartbeat",
                            "sequence": sequence,
                            "proof": asdict(current_proof),
                        },
                        token,
                    ),
                )
            elif command == "live":
                generation = message.get("lease_generation")
                if type(generation) is not int or generation != current_proof.lease_generation + 1:
                    reason = "guardian_generation_changed"
                    break
                current_proof = VerifiedExecLifetimeCustodyV2(
                    **{
                        **asdict(current_proof),
                        "lease_generation": generation,
                    }
                )
                _write_atomic(
                    directory / "guardian-proof.json",
                    _canonical(_proof_document(current_proof)),
                )
                heartbeat_deadline = (
                    time.monotonic_ns() + profile.controller_loss_grace_milliseconds * 1_000_000
                )
                _send(
                    channel,
                    _signed(
                        {
                            "schema_version": "bluefire.linux-exec-guardian-ack.v2",
                            "command": "live",
                            "sequence": generation,
                            "proof": asdict(current_proof),
                        },
                        token,
                    ),
                )
            elif command == "cleanup":
                supplied = message.get("reason")
                if not isinstance(supplied, str) or _REASON.fullmatch(supplied) is None:
                    reason = "guardian_reason_invalid"
                else:
                    reason = supplied
                break
            else:
                reason = "guardian_command_refused"
                break
    except Exception:
        # A broken broker channel, malformed authenticated frame, failed ACK,
        # or proof persistence error must still reach whole-container cleanup.
        # The guardian is the last owner after broker loss; letting an IPC
        # exception escape here would leave the admitted container running.
        reason = "guardian_monitor_failed"
    finally:
        listener.close()
        if channel is not None:
            channel.close()
        os.close(controller_pidfd)
        os.close(broker_pidfd)
    return _finish_guardian(
        profile,
        request,
        current_proof,
        clock_epoch_ref=launch["clock_epoch_ref"],
        directory=directory,
        reason=reason,
    )


class _GuardianClient:
    def __init__(
        self,
        *,
        operation_id: str,
        request_ref: str,
        directory: Path,
        token: bytes,
        process: subprocess.Popen[bytes],
        channel: socket.socket,
    ) -> None:
        self.operation_id = operation_id
        self.request_ref = request_ref
        self.directory = directory
        self.token = token
        self.process = process
        self.channel = channel
        self.heartbeat_sequence = 0

    def command(self, command: str, **values: object) -> dict[str, Any]:
        document = {
            "schema_version": "bluefire.linux-exec-guardian-command.v2",
            "command": command,
            "request_ref": self.request_ref,
            **values,
        }
        _send(self.channel, _signed(document, self.token))
        return _verified_message(_receive(self.channel), self.token)

    def heartbeat(self) -> None:
        self.heartbeat_sequence += 1
        response = self.command("heartbeat", sequence=self.heartbeat_sequence)
        if response != {
            "schema_version": "bluefire.linux-exec-guardian-ack.v2",
            "command": "heartbeat",
            "sequence": self.heartbeat_sequence,
            "proof": response.get("proof"),
        } or not isinstance(response.get("proof"), dict):
            raise _ProcessError("guardian_heartbeat_changed")

    def live(self, generation: int) -> VerifiedExecLifetimeCustodyV2:
        response = self.command("live", lease_generation=generation)
        if (
            response.get("schema_version") != "bluefire.linux-exec-guardian-ack.v2"
            or response.get("command") != "live"
            or response.get("sequence") != generation
        ):
            raise _ProcessError("guardian_live_changed")
        return _proof(response.get("proof"))

    def request_cleanup(self, reason: str) -> None:
        document = {
            "schema_version": "bluefire.linux-exec-guardian-command.v2",
            "command": "cleanup",
            "request_ref": self.request_ref,
            "reason": reason,
        }
        _send(self.channel, _signed(document, self.token))
        # The guardian intentionally closes the channel before cleanup.  Only
        # its fsynced terminal file is authoritative.
        self.channel.close()


def _spawn_guardian(
    *,
    profile: LinuxExecLifetimeSupervisorProfileV2,
    binding: ExecLifetimeSupervisorBindingV2,
    request: ExecLifetimeOperationRequestV2,
    proof: VerifiedExecLifetimeCustodyV2,
    clock_epoch_ref: str,
    controller: Mapping[str, int],
) -> _GuardianClient:
    directory = profile.state_directory / request.operation_id
    try:
        directory.mkdir(mode=0o700, exist_ok=False)
    except OSError as exc:
        raise _ProcessError("guardian_directory_unavailable") from exc
    token = secrets.token_bytes(_TOKEN_BYTES)
    _write_atomic(directory / "guardian.capability", token)
    broker = {
        "pid": os.getpid(),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "start_ticks": _proc_start_ticks(os.getpid()),
    }
    launch = {
        "schema_version": "bluefire.linux-exec-guardian-launch.v2",
        "profile": profile.document(),
        "profile_ref": profile.profile_ref,
        "binding_ref": binding.binding_ref,
        "request": asdict(request),
        "request_ref": request.request_ref,
        "proof": asdict(proof),
        "proof_ref": proof.proof_ref,
        "clock_epoch_ref": clock_epoch_ref,
        "controller": dict(controller),
        "broker": broker,
        "guardian_directory": str(directory),
    }
    launch_path = directory / "guardian.launch.json"
    _write_atomic(launch_path, _canonical(launch))
    package_root = Path(__file__).resolve().parent.parent
    environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", __name__, "guardian", str(launch_path)],
            cwd=str(package_root),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise _ProcessError("guardian_start_failed") from exc
    deadline = time.monotonic() + profile.startup_timeout_milliseconds / 1000
    socket_path = directory / "guardian.sock"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise _ProcessError("guardian_start_failed")
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        channel.settimeout(0.2)
        try:
            channel.connect(str(socket_path))
            pid, uid, gid = _peer(channel)
            if (pid, uid, gid) != (process.pid, os.geteuid(), os.getegid()):
                raise _ProcessError("guardian_peer_changed")
            # These commands only exchange bounded guardian frames. Container
            # cleanup happens after the channel closes and has its own bound.
            channel.settimeout(1.0)
            return _GuardianClient(
                operation_id=request.operation_id,
                request_ref=request.request_ref,
                directory=directory,
                token=token,
                process=process,
                channel=channel,
            )
        except Exception as exc:
            last_error = exc
            channel.close()
            time.sleep(0.02)
    raise _ProcessError("guardian_start_timeout") from last_error


class _Broker:
    def __init__(self, launch_path: Path) -> None:
        launch = _load_launch(launch_path, "bluefire.linux-exec-supervisor-launch.v2")
        expected = {
            "schema_version",
            "mode",
            "profile",
            "profile_ref",
            "binding",
            "binding_ref",
            "state_device",
            "state_inode",
            "controller",
        }
        if set(launch) != expected or launch["mode"] not in {"new", "reconcile"}:
            raise _ProcessError("broker_launch_fields")
        self.mode: str = launch["mode"]
        self.profile = _profile(launch["profile"])
        if self.profile.profile_ref != launch["profile_ref"]:
            raise _ProcessError("broker_profile_changed")
        self.binding = _binding(launch["binding"])
        if self.binding.binding_ref != launch["binding_ref"]:
            raise _ProcessError("broker_binding_changed")
        _secure_state(
            self.profile.state_directory,
            int(launch["state_device"]),
            int(launch["state_inode"]),
        )
        self.controller = _physical(launch["controller"], "controller")
        self.controller_pidfd = _pidfd(self.controller["pid"], self.controller["start_ticks"])
        self.token = _strict_file(
            self.profile.state_directory / "controller.capability", maximum=_TOKEN_BYTES
        )
        if len(self.token) != _TOKEN_BYTES:
            raise _ProcessError("controller_capability")
        token_digest = content_hash(self.token.hex())
        self.supervisor_instance_ref = content_hash(
            {
                "schema_version": "bluefire.linux-exec-supervisor-instance.v2",
                "binding_ref": self.binding.binding_ref,
                "profile_ref": self.profile.profile_ref,
                "capability_digest": token_digest,
            }
        )
        self.supervisor_session_ref = content_hash(
            {
                "schema_version": "bluefire.linux-exec-supervisor-session.v2",
                "supervisor_instance_ref": self.supervisor_instance_ref,
                "state_device": launch["state_device"],
                "state_inode": launch["state_inode"],
            }
        )
        self.clock_epoch_ref = _boot_epoch()
        self.identity = ExecSupervisorJournalIdentityV2(
            binding_ref=self.binding.binding_ref,
            attempt_id=self.binding.attempt_id,
            claim_ref=self.binding.claim_ref,
            controller_fence=self.binding.controller_fence,
            custody_plan_digest=self.binding.custody_plan_digest,
            network_policy_digest=self.binding.network_policy_digest,
            controller_instance_ref=self.binding.controller_instance_ref,
            daemon_instance_digest=self.profile.daemon_endpoint.daemon_instance_digest,
            docker_endpoint_ref=content_hash(
                {
                    "schema_version": "bluefire.linux-docker-daemon-endpoint.v1",
                    **asdict(self.profile.daemon_endpoint),
                }
            ),
            supervisor_instance_ref=self.supervisor_instance_ref,
            supervisor_session_ref=self.supervisor_session_ref,
            clock_epoch_ref=self.clock_epoch_ref,
            supervisor_qualification_ref=self.binding.supervisor_qualification_ref,
        )
        self.journal = (
            SQLiteLinuxExecSupervisorJournalV2.create(self.profile.state_directory, self.identity)
            if self.mode == "new"
            else SQLiteLinuxExecSupervisorJournalV2.reopen(
                self.profile.state_directory, self.identity
            )
        )
        self.guardians: dict[str, _GuardianClient] = {}
        self.cleanup_uncertain = False
        self.exit_requested = False
        self.heartbeat_deadline = (
            time.monotonic_ns() + self.profile.controller_loss_grace_milliseconds * 1_000_000
        )
        self.heartbeat_sequence = 0
        # Serve the authenticated socket before potentially slow Docker
        # reconciliation. Reopen performs it synchronously under a bounded
        # command deadline; a startup timeout must not strand this broker's
        # exclusive journal lock while cleanup is still in progress.
        self._settle_pending_rpc()

    @property
    def origin_activation(self) -> ExecLifetimeSupervisorActivationV2:
        return ExecLifetimeSupervisorActivationV2.create(
            action="activated",
            binding_ref=self.binding.binding_ref,
            controller_instance_ref=self.binding.controller_instance_ref,
            supervisor_instance_ref=self.supervisor_instance_ref,
            supervisor_session_ref=self.supervisor_session_ref,
            clock_epoch_ref=self.clock_epoch_ref,
            supervisor_qualification_ref=self.binding.supervisor_qualification_ref,
        )

    def _settle_pending_rpc(self) -> None:
        pending = self.journal.pending_rpc
        if pending is None:
            return
        cursor, request_digest = pending
        response = self._response(
            cursor,
            request_digest,
            ok=False,
            result={"code": "recovered_uncertain"},
        )
        self.journal.complete_rpc(cursor, request_digest, response)

    def _reconcile_startup(self) -> None:
        records = self.journal.operations(phases=("active", "cleanup_pending"))
        for record in records:
            directory = self.profile.state_directory / record.operation_id
            terminal: dict[str, Any] | None = None
            try:
                terminal = self._read_guardian_terminal(directory)
                if terminal is None:
                    deadline = time.monotonic() + min(
                        2.0, self.profile.controller_loss_grace_milliseconds / 1000
                    )
                    while time.monotonic() < deadline and terminal is None:
                        time.sleep(0.02)
                        terminal = self._read_guardian_terminal(directory)
                if terminal is not None:
                    self._retain_terminal(record, terminal)
                else:
                    self._cleanup_direct(record, reason="supervisor_recovery")
            except Exception:
                # A malformed guardian file is evidence of uncertainty, not a
                # reason to leave the exact owned container running. Retain
                # the file and try the fixed cleanup grammar independently.
                self.cleanup_uncertain = True
                try:
                    self._cleanup_direct(record, reason="supervisor_recovery")
                except Exception:
                    pass

    def _operation_values(
        self, record: SupervisorOperationRecordV2
    ) -> tuple[ExecLifetimeOperationRequestV2, VerifiedExecLifetimeCustodyV2]:
        request_document = dict(record.request)
        proof_document = dict(record.proof)
        if (
            request_document.pop("schema_version", None)
            != "bluefire.exec-lifetime-operation-request.v2"
        ):
            raise _ProcessError("retained_request_changed", uncertain=True)
        if (
            proof_document.pop("schema_version", None)
            != "bluefire.verified-exec-lifetime-custody.v2"
        ):
            raise _ProcessError("retained_proof_changed", uncertain=True)
        return _request(request_document), _proof(proof_document)

    def _cleanup_direct(
        self, record: SupervisorOperationRecordV2, *, reason: str
    ) -> ExecLifetimeTerminalReceiptV2:
        request, proof = self._operation_values(record)
        selected_reason = record.cleanup_reason or reason
        self.journal.mark_cleanup_pending(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            reason=selected_reason,
        )
        receipt, _evidence = _cleanup_exact(
            self.profile,
            request,
            proof,
            clock_epoch_ref=self.clock_epoch_ref,
        )
        self.journal.record_terminal(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            reason=selected_reason,
            receipt_ref=receipt.receipt_ref,
            receipt=receipt.document(include_ref=False),
        )
        return receipt

    def _read_guardian_terminal(self, directory: Path) -> dict[str, Any] | None:
        path = _guardian_terminal_path(directory)
        if not path.exists():
            if _guardian_uncertain_path(directory).exists():
                self.cleanup_uncertain = True
            return None
        value = _object(_strict_file(path))
        if value.get("schema_version") != "bluefire.linux-exec-guardian-terminal.v2":
            raise _ProcessError("guardian_terminal_changed", uncertain=True)
        return value

    def _retain_terminal(
        self, record: SupervisorOperationRecordV2, terminal: Mapping[str, Any]
    ) -> ExecLifetimeTerminalReceiptV2:
        expected = {
            "schema_version",
            "reason",
            "request",
            "proof",
            "receipt",
            "receipt_ref",
            "evidence_digest",
        }
        if set(terminal) != expected:
            raise _ProcessError("guardian_terminal_fields", uncertain=True)
        request = _request(
            {key: value for key, value in terminal["request"].items() if key != "schema_version"}
        )
        proof = _proof(
            {key: value for key, value in terminal["proof"].items() if key != "schema_version"}
        )
        reason = terminal["reason"]
        if (
            request.operation_id != record.operation_id
            or request.request_ref != record.request_ref
            or proof.operation_id != record.operation_id
            or proof.lease_ref != record.proof.get("lease_ref")
            or not isinstance(reason, str)
            or _REASON.fullmatch(reason) is None
            or not isinstance(terminal["evidence_digest"], str)
            or _DIGEST.fullmatch(terminal["evidence_digest"]) is None
        ):
            raise _ProcessError("guardian_terminal_binding", uncertain=True)
        receipt_document = terminal["receipt"]
        if not isinstance(receipt_document, dict):
            raise _ProcessError("guardian_terminal_receipt", uncertain=True)
        receipt = _receipt_from_document(receipt_document)
        if receipt.receipt_ref != terminal["receipt_ref"]:
            raise _ProcessError("guardian_terminal_receipt", uncertain=True)
        selected_reason = record.cleanup_reason or reason
        self.journal.mark_cleanup_pending(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            reason=selected_reason,
        )
        self.journal.record_terminal(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            reason=selected_reason,
            receipt_ref=receipt.receipt_ref,
            receipt=receipt.document(include_ref=False),
        )
        return receipt

    def _terminal_for(self, record: SupervisorOperationRecordV2) -> ExecLifetimeTerminalReceiptV2:
        if record.phase != "terminal" or record.terminal_receipt is None:
            raise _ProcessError("terminal_unavailable", uncertain=True)
        return _receipt_from_document(record.terminal_receipt)

    def _validate_request(self, request: ExecLifetimeOperationRequestV2) -> None:
        if (
            request.attempt_id != self.binding.attempt_id
            or request.claim_ref != self.binding.claim_ref
            or request.controller_fence != self.binding.controller_fence
            or request.custody_plan_digest != self.binding.custody_plan_digest
            or request.network_policy_digest != self.binding.network_policy_digest
            or request.controller_instance_ref != self.binding.controller_instance_ref
            or request.supervisor_instance_ref != self.supervisor_instance_ref
            or request.container_id not in {item.container_id for item in self.profile.containers}
        ):
            raise _ProcessError("operation_binding_changed")

    def activation(self, action: str) -> ExecLifetimeSupervisorActivationV2:
        if action == "activated":
            if self.mode != "new" or self.journal.operations():
                raise _ProcessError("new_activation_changed")
            return self.origin_activation
        if action != "reopened" or self.mode != "reconcile" or self.cleanup_uncertain:
            raise _ProcessError("recovery_unavailable", uncertain=self.cleanup_uncertain)
        self._reconcile_startup()
        if self.cleanup_uncertain:
            raise _ProcessError("recovery_unavailable", uncertain=True)
        pending = self.journal.pending_terminal_events()
        receipts = tuple(_receipt_from_document(item.receipt) for item in pending)
        return ExecLifetimeSupervisorActivationV2.create(
            action="reopened",
            binding_ref=self.binding.binding_ref,
            controller_instance_ref=self.binding.controller_instance_ref,
            supervisor_instance_ref=self.supervisor_instance_ref,
            supervisor_session_ref=self.supervisor_session_ref,
            clock_epoch_ref=self.clock_epoch_ref,
            supervisor_qualification_ref=self.binding.supervisor_qualification_ref,
            origin_activation_ref=self.origin_activation.activation_ref,
            terminal_receipts=receipts,
        )

    def arm(self, request: ExecLifetimeOperationRequestV2) -> VerifiedExecLifetimeCustodyV2:
        if self.mode != "new" or self.cleanup_uncertain:
            raise _ProcessError("arm_unavailable", uncertain=self.cleanup_uncertain)
        self._validate_request(request)
        if time.monotonic_ns() >= request.operation_deadline_monotonic_ns:
            raise _ProcessError("deadline_elapsed")
        for record in self.journal.operations(phases=("active", "cleanup_pending")):
            retained, _proof_value = self._operation_values(record)
            if retained.container_id == request.container_id:
                raise _ProcessError("container_already_supervised")
        proof = VerifiedExecLifetimeCustodyV2(
            admission_digest=request.admission_digest,
            attempt_id=request.attempt_id,
            operation_id=request.operation_id,
            container_id=request.container_id,
            claim_ref=request.claim_ref,
            controller_fence=request.controller_fence,
            custody_plan_digest=request.custody_plan_digest,
            network_policy_digest=request.network_policy_digest,
            operation_deadline_monotonic_ns=request.operation_deadline_monotonic_ns,
            controller_instance_ref=request.controller_instance_ref,
            supervisor_instance_ref=self.supervisor_instance_ref,
            lease_ref=content_hash(
                {
                    "schema_version": "bluefire.linux-exec-supervisor-lease.v2",
                    "request_ref": request.request_ref,
                    "supervisor_instance_ref": self.supervisor_instance_ref,
                    "nonce": secrets.token_hex(32),
                }
            ),
            lease_generation=1,
        )
        guardian: _GuardianClient | None = None
        record: SupervisorOperationRecordV2 | None = None
        try:
            guardian = _spawn_guardian(
                profile=self.profile,
                binding=self.binding,
                request=request,
                proof=proof,
                clock_epoch_ref=self.clock_epoch_ref,
                controller=self.controller,
            )
            guardian.heartbeat()
            # The independent guardian must be alive before a journal row can
            # authorize the controller to dispatch an exec. If this broker is
            # killed in between, the guardian still removes the container.
            record = self.journal.record_active(
                operation_id=request.operation_id,
                request_ref=request.request_ref,
                request=_request_document(request),
                proof_ref=proof.proof_ref,
                proof=_proof_document(proof),
            )
            # A slow fsync may consume the guardian's heartbeat grace. Prove
            # that it still owns the container after the durable write.
            guardian.heartbeat()
            self.guardians[request.operation_id] = guardian
            return proof
        except Exception as exc:
            if guardian is not None:
                try:
                    guardian.request_cleanup("guardian_start_failed")
                except Exception:
                    pass
            try:
                if record is None:
                    record = self.journal.record_active(
                        operation_id=request.operation_id,
                        request_ref=request.request_ref,
                        request=_request_document(request),
                        proof_ref=proof.proof_ref,
                        proof=_proof_document(proof),
                    )
                self._cleanup_direct(record, reason="guardian_start_failed")
            except Exception:
                self.cleanup_uncertain = True
            raise _ProcessError("guardian_start_failed", uncertain=self.cleanup_uncertain) from exc

    def live(self, request: ExecLifetimeOperationRequestV2) -> VerifiedExecLifetimeCustodyV2:
        if self.mode != "new" or self.cleanup_uncertain:
            raise _ProcessError("live_unavailable", uncertain=self.cleanup_uncertain)
        self._validate_request(request)
        rows = {item.operation_id: item for item in self.journal.operations()}
        record = rows.get(request.operation_id)
        if record is None or record.phase != "active" or record.request_ref != request.request_ref:
            raise _ProcessError("operation_not_live")
        guardian = self.guardians.get(request.operation_id)
        if guardian is None:
            raise _ProcessError("guardian_unavailable", uncertain=True)
        current = _proof(
            {key: value for key, value in record.proof.items() if key != "schema_version"}
        )
        try:
            proof = guardian.live(current.lease_generation + 1)
        except Exception as exc:
            self.cleanup_uncertain = True
            raise _ProcessError("guardian_unavailable", uncertain=True) from exc
        if (
            proof.lease_ref != current.lease_ref
            or proof.lease_generation != current.lease_generation + 1
        ):
            self.cleanup_uncertain = True
            raise _ProcessError("guardian_proof_changed", uncertain=True)
        self.journal.update_live_proof(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            proof_ref=proof.proof_ref,
            proof=_proof_document(proof),
        )
        return proof

    def terminate(
        self, request: ExecLifetimeOperationRequestV2, reason: str
    ) -> ExecLifetimeTerminalReceiptV2:
        self._validate_request(request)
        if not isinstance(reason, str) or _REASON.fullmatch(reason) is None:
            raise _ProcessError("termination_reason")
        rows = {item.operation_id: item for item in self.journal.operations()}
        record = rows.get(request.operation_id)
        if record is None or record.request_ref != request.request_ref:
            raise _ProcessError("operation_unavailable")
        if record.phase == "terminal":
            return self._terminal_for(record)
        self.journal.mark_cleanup_pending(
            operation_id=request.operation_id,
            request_ref=request.request_ref,
            reason=record.cleanup_reason or reason,
        )
        guardian = self.guardians.pop(request.operation_id, None)
        untrusted_terminal = False
        if guardian is not None:
            try:
                guardian.request_cleanup(record.cleanup_reason or reason)
            except Exception:
                pass
            deadline = time.monotonic() + self.profile.cleanup_timeout_milliseconds / 1000 + 1
            terminal = None
            while time.monotonic() < deadline and terminal is None:
                try:
                    terminal = self._read_guardian_terminal(guardian.directory)
                except Exception:
                    untrusted_terminal = True
                    break
                if terminal is None:
                    time.sleep(0.02)
            if terminal is not None:
                try:
                    return self._retain_terminal(
                        {item.operation_id: item for item in self.journal.operations()}[
                            request.operation_id
                        ],
                        terminal,
                    )
                except Exception:
                    untrusted_terminal = True
        try:
            current = {item.operation_id: item for item in self.journal.operations()}[
                request.operation_id
            ]
            receipt = self._cleanup_direct(current, reason=record.cleanup_reason or reason)
        except Exception as exc:
            self.cleanup_uncertain = True
            raise _ProcessError("cleanup_uncertain", uncertain=True) from exc
        if untrusted_terminal:
            self.cleanup_uncertain = True
            raise _ProcessError("guardian_terminal_untrusted", uncertain=True)
        return receipt

    def heartbeat_guardians(self) -> None:
        failed: list[str] = []
        for operation_id, guardian in tuple(self.guardians.items()):
            try:
                guardian.heartbeat()
            except Exception:
                failed.append(operation_id)
        for operation_id in failed:
            guardian = self.guardians.pop(operation_id)
            records = {item.operation_id: item for item in self.journal.operations()}
            record = records.get(operation_id)
            if record is None or record.phase == "terminal":
                continue
            try:
                terminal = self._read_guardian_terminal(guardian.directory)
                if terminal is not None:
                    self._retain_terminal(record, terminal)
                else:
                    self._cleanup_direct(record, reason="guardian_unavailable")
            except Exception:
                self.cleanup_uncertain = True
                try:
                    self._cleanup_direct(record, reason="guardian_unavailable")
                except Exception:
                    pass

    def terminate_all(self, reason: str) -> None:
        for record in self.journal.operations(phases=("active", "cleanup_pending")):
            request, _proof_value = self._operation_values(record)
            try:
                self.terminate(request, record.cleanup_reason or reason)
            except Exception:
                self.cleanup_uncertain = True

    def _response(
        self,
        cursor: int,
        request_digest: str,
        *,
        ok: bool,
        result: Mapping[str, object],
    ) -> bytes:
        return _signed(
            {
                "schema_version": "bluefire.linux-exec-supervisor-response.v2",
                "cursor": cursor,
                "request_digest": request_digest,
                "ok": ok,
                "result": dict(result),
            },
            self.token,
        )

    def handle_rpc(self, document: Mapping[str, Any]) -> bytes:
        required = {
            "schema_version",
            "cursor",
            "command",
            "binding_ref",
            "controller_instance_ref",
            "controller_pid",
            "controller_uid",
            "controller_gid",
            "controller_start_ticks",
            "payload",
        }
        if (
            set(document) != required
            or document.get("schema_version") != "bluefire.linux-exec-supervisor-rpc.v2"
        ):
            raise _ProcessError("rpc_fields")
        cursor = document["cursor"]
        command = document["command"]
        payload = document["payload"]
        if (
            type(cursor) is not int
            or cursor < 1
            or command not in _BROKER_COMMANDS
            or not isinstance(payload, dict)
            or document["binding_ref"] != self.binding.binding_ref
            or document["controller_instance_ref"] != self.binding.controller_instance_ref
            or (
                document["controller_pid"],
                document["controller_uid"],
                document["controller_gid"],
                document["controller_start_ticks"],
            )
            != (
                self.controller["pid"],
                self.controller["uid"],
                self.controller["gid"],
                self.controller["start_ticks"],
            )
        ):
            raise _ProcessError("rpc_binding")
        request_digest = content_hash(document)
        reservation = self.journal.reserve_rpc(cursor, request_digest)
        if reservation.disposition == "replay":
            if reservation.response is None:
                raise _ProcessError("rpc_replay_changed")
            return reservation.response
        if reservation.disposition == "pending":
            raise _ProcessError("rpc_pending", uncertain=True)
        ok = True
        try:
            result = self._execute(command, payload)
        except _ProcessError as exc:
            ok = False
            if exc.uncertain:
                self.cleanup_uncertain = True
            result = {"code": exc.code}
        except Exception:
            ok = False
            self.cleanup_uncertain = True
            result = {"code": "internal_failure"}
        response = self._response(cursor, request_digest, ok=ok, result=result)
        return self.journal.complete_rpc(cursor, request_digest, response)

    def _execute(self, command: str, payload: Mapping[str, Any]) -> dict[str, object]:
        if command in {"activate", "reopen"}:
            if set(payload) != {"binding"} or _binding(payload["binding"]) != self.binding:
                raise _ProcessError("activation_binding_changed")
            activation = self.activation("activated" if command == "activate" else "reopened")
            return {"activation": asdict(activation)}
        if command == "arm":
            if set(payload) != {"request"}:
                raise _ProcessError("arm_fields")
            return {"proof": asdict(self.arm(_request(payload["request"])))}
        if command == "live":
            if set(payload) != {"request"}:
                raise _ProcessError("live_fields")
            return {"proof": asdict(self.live(_request(payload["request"])))}
        if command in {"complete", "terminate"}:
            expected = {"request"} if command == "complete" else {"request", "reason"}
            if set(payload) != expected:
                raise _ProcessError("termination_fields")
            reason = "completed_cleanup" if command == "complete" else payload["reason"]
            receipt = self.terminate(_request(payload["request"]), reason)
            return {"receipt": asdict(receipt)}
        if command == "terminal_events":
            if payload:
                raise _ProcessError("terminal_event_fields")
            events = []
            for event in self.journal.pending_terminal_events():
                receipt = _receipt_from_document(event.receipt)
                record = {
                    item.operation_id: item
                    for item in self.journal.operations(phases=("terminal",))
                }[event.operation_id]
                events.append(
                    {
                        "cursor": event.cursor,
                        "reason": record.cleanup_reason,
                        "request_ref": event.request_ref,
                        "receipt": asdict(receipt),
                        # The receipt binds the final exact-container 404
                        # exchange. Do not substitute a synthetic event hash
                        # for observed Docker absence evidence.
                        "evidence_digest": receipt.final_inventory_digest,
                    }
                )
            return {"events": events}
        if command == "ack_terminal":
            if set(payload) != {"cursor", "receipt_ref"}:
                raise _ProcessError("terminal_ack_fields")
            self.journal.acknowledge_terminal(
                cursor=payload["cursor"], receipt_ref=payload["receipt_ref"]
            )
            return {}
        if command == "close":
            if payload:
                raise _ProcessError("close_fields")
            self.terminate_all("controller_close")
            if self.cleanup_uncertain:
                raise _ProcessError("cleanup_uncertain", uncertain=True)
            self.exit_requested = True
            return {}
        raise _ProcessError("command_refused")

    def close(self) -> None:
        for guardian in self.guardians.values():
            try:
                guardian.channel.close()
            except OSError:
                pass
        self.guardians.clear()
        self.journal.close()
        os.close(self.controller_pidfd)


def _hello(channel: socket.socket, broker: _Broker) -> None:
    raw = _receive(channel)
    value = _verified_message(raw, broker.token)
    required = {
        "schema_version",
        "binding_ref",
        "controller_instance_ref",
        "controller_pid",
        "controller_uid",
        "controller_gid",
        "controller_start_ticks",
    }
    if (
        set(value) != required
        or value["schema_version"] != "bluefire.linux-exec-supervisor-hello.v2"
        or value["binding_ref"] != broker.binding.binding_ref
        or value["controller_instance_ref"] != broker.binding.controller_instance_ref
        or (
            value["controller_pid"],
            value["controller_uid"],
            value["controller_gid"],
            value["controller_start_ticks"],
        )
        != (
            broker.controller["pid"],
            broker.controller["uid"],
            broker.controller["gid"],
            broker.controller["start_ticks"],
        )
    ):
        raise _ProcessError("hello_binding")
    _send(
        channel,
        _signed(
            {
                "schema_version": "bluefire.linux-exec-supervisor-hello-ack.v2",
                "binding_ref": broker.binding.binding_ref,
                "last_rpc_cursor": broker.journal.last_rpc_cursor,
                "pending_rpc": broker.journal.pending_rpc is not None,
            },
            broker.token,
        ),
    )


def _broker_process(launch_path: Path) -> int:
    broker = _Broker(launch_path)
    listener = _socket_listener(broker.profile.state_directory / "broker.sock")
    channel: socket.socket | None = None
    try:
        while not broker.exit_requested:
            if _pidfd_ready(broker.controller_pidfd):
                broker.terminate_all("controller_lost")
                return 0 if not broker.cleanup_uncertain else 70
            if time.monotonic_ns() >= broker.heartbeat_deadline:
                broker.terminate_all("heartbeat_elapsed")
                return 0 if not broker.cleanup_uncertain else 70
            if channel is None:
                try:
                    candidate, _ = listener.accept()
                    candidate.settimeout(0.1)
                    if _peer(candidate) != (
                        broker.controller["pid"],
                        broker.controller["uid"],
                        broker.controller["gid"],
                    ):
                        candidate.close()
                        continue
                    _hello(candidate, broker)
                    channel = candidate
                    broker.heartbeat_deadline = (
                        time.monotonic_ns()
                        + broker.profile.controller_loss_grace_milliseconds * 1_000_000
                    )
                except socket.timeout:
                    continue
            try:
                raw = _receive(channel)
            except socket.timeout:
                continue
            except EOFError:
                broker.terminate_all("controller_channel_lost")
                return 0 if not broker.cleanup_uncertain else 70
            value = _verified_message(raw, broker.token)
            schema = value.get("schema_version")
            if schema == "bluefire.linux-exec-supervisor-heartbeat.v2":
                required = {
                    "schema_version",
                    "sequence",
                    "binding_ref",
                    "controller_instance_ref",
                    "controller_pid",
                    "controller_start_ticks",
                }
                sequence = value.get("sequence")
                if (
                    set(value) != required
                    or type(sequence) is not int
                    or sequence != broker.heartbeat_sequence + 1
                    or value["binding_ref"] != broker.binding.binding_ref
                    or value["controller_instance_ref"] != broker.binding.controller_instance_ref
                    or value["controller_pid"] != broker.controller["pid"]
                    or value["controller_start_ticks"] != broker.controller["start_ticks"]
                ):
                    raise _ProcessError("heartbeat_binding")
                broker.heartbeat_sequence = sequence
                broker.heartbeat_deadline = (
                    time.monotonic_ns()
                    + broker.profile.controller_loss_grace_milliseconds * 1_000_000
                )
                broker.heartbeat_guardians()
                _send(
                    channel,
                    _signed(
                        {
                            "schema_version": "bluefire.linux-exec-supervisor-heartbeat-ack.v2",
                            "sequence": sequence,
                        },
                        broker.token,
                    ),
                )
            else:
                response = broker.handle_rpc(value)
                # The controller cannot send a heartbeat while its RPC owns
                # the shared socket. A bounded guardian startup or recovery
                # may outlast the ordinary heartbeat grace. Check its pidfd,
                # then begin a fresh grace window before the next exchange.
                if _pidfd_ready(broker.controller_pidfd):
                    broker.terminate_all("controller_lost")
                    return 0 if not broker.cleanup_uncertain else 70
                broker.heartbeat_deadline = (
                    time.monotonic_ns()
                    + broker.profile.controller_loss_grace_milliseconds * 1_000_000
                )
                _send(channel, response)
        return 0
    finally:
        listener.close()
        if channel is not None:
            channel.close()
        broker.close()


def _die(code: str) -> NoReturn:
    try:
        os.write(2, ("BlueFire exec supervisor refused: " + code + "\n").encode("ascii"))
    except OSError:
        pass
    raise SystemExit(70)


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if sys.platform != "linux" or len(values) != 2 or values[0] not in {"broker", "guardian"}:
        _die("entrypoint")
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    path = Path(values[1])
    if not path.is_absolute():
        _die("launch_path")
    try:
        return _broker_process(path) if values[0] == "broker" else _guardian_process(path)
    except (OSError, ValueError, _ProcessError, LinuxExecSupervisorJournalError) as exc:
        code = exc.code if isinstance(exc, _ProcessError) else "internal_failure"
        try:
            _write_atomic(
                path.with_name(path.name + ".error.json"),
                _canonical(
                    {
                        "schema_version": "bluefire.linux-exec-supervisor-startup-error.v1",
                        "role": values[0],
                        "code": code,
                    }
                ),
            )
        except Exception:
            pass
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
