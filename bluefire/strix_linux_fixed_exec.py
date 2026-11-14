"""Authenticated live authority and durable evidence for fixed Strix exec.

A serialized receipt is evidence only.  It never grants launch or relay
authority.  ``FixedExecAuthority`` is retained by the controller and joins a
live pidfd-bound, credential-authenticated native observation channel to the
descriptor-pinned runtime closure.  The native helper must report the exact
kernel identities it observed after pivot and after the worker armed its
final no-exec seccomp policy.
"""

from __future__ import annotations

import json
import os
import re
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, cast

from .strix_linux_runtime_closure import (
    FIXED_ARGV,
    FIXED_CONTROL_SOCKET,
    FIXED_ENVIRONMENT,
    FIXED_GUEST_PROJECTION_DIGEST,
    FIXED_INPUT_PATHS,
    PRIVATE_DEVICE_POLICY_DIGEST,
    PRIVATE_OVERMOUNTS,
    PinnedStrixRuntimeClosure,
    StrixLinuxRuntimeClosureError,
    StrixLinuxRuntimeClosurePlan,
)
from .util import canonical_json_bytes, content_hash

RECEIPT_SCHEMA = "bluefire.strix-linux-fixed-exec-receipt.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_UTC = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_PACKET = 64 * 1024
_ENVELOPE_SCHEMA = "bluefire.strix-fixed-exec-observation-envelope.v1"
_ARMED_SCHEMA = "bluefire.strix-fixed-exec-armed.v1"
_MAX_STARTUP_SECONDS = 120.0
_RECEIPT_CONSTRUCTION = object()


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StrixLinuxRuntimeClosureError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise StrixLinuxRuntimeClosureError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    result = _text(value, label, 71)
    if _DIGEST.fullmatch(result) is None:
        raise StrixLinuxRuntimeClosureError(f"{label} must be a sha256 digest")
    return result


def _integer(value: Any, label: str, minimum: int = 1, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StrixLinuxRuntimeClosureError(f"{label} is outside its bound")
    return value


def _true(value: Any, label: str) -> bool:
    if value is not True:
        raise StrixLinuxRuntimeClosureError(f"{label} was not established")
    return True


@dataclass(frozen=True, slots=True)
class FixedExecExpectedBindings:
    """Controller-known identities that a native receipt must reproduce."""

    attempt_id: str
    resource_claim_ref: str
    worker_activation_ref: str
    worker_containment_ref: str
    boundary_helper_digest: str
    worker_custody_identity_digest: str
    cgroup_ref: str
    seccomp_profile_digest: str
    input_bindings_ref: str
    sealed_inputs_ref: str
    startup_overlay_ref: str
    installed_projection_ref: str
    controller_socket_identity_ref: str
    model_listener_ref: str
    caido_listener_ref: str
    endpoint_cleanup_authority_ref: str
    endpoint_directory_identity_ref: str
    native_observation_ref: str
    controller_boot_id: str
    worker_host_pid: int
    worker_uid: int
    worker_gid: int
    worker_start_ticks: int
    worker_nspid: tuple[int, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "FixedExecExpectedBindings":
        row = _exact(value, set(cls.__dataclass_fields__), "fixed exec expected bindings")
        result = cls(
            attempt_id=_text(row["attempt_id"], "attempt identity", 128),
            resource_claim_ref=_digest(row["resource_claim_ref"], "resource claim"),
            worker_activation_ref=_digest(row["worker_activation_ref"], "worker activation"),
            worker_containment_ref=_digest(
                row["worker_containment_ref"], "worker containment"
            ),
            boundary_helper_digest=_digest(
                row["boundary_helper_digest"], "boundary helper"
            ),
            worker_custody_identity_digest=_digest(
                row["worker_custody_identity_digest"], "worker custody identity"
            ),
            cgroup_ref=_digest(row["cgroup_ref"], "worker cgroup"),
            seccomp_profile_digest=_digest(
                row["seccomp_profile_digest"], "seccomp profile"
            ),
            input_bindings_ref=_digest(row["input_bindings_ref"], "input bindings"),
            sealed_inputs_ref=_digest(row["sealed_inputs_ref"], "sealed inputs"),
            startup_overlay_ref=_digest(row["startup_overlay_ref"], "startup overlay"),
            installed_projection_ref=_digest(
                row["installed_projection_ref"], "installed projection"
            ),
            controller_socket_identity_ref=_digest(
                row["controller_socket_identity_ref"], "controller socket identity"
            ),
            model_listener_ref=_digest(row["model_listener_ref"], "model listener"),
            caido_listener_ref=_digest(row["caido_listener_ref"], "Caido listener"),
            endpoint_cleanup_authority_ref=_digest(
                row["endpoint_cleanup_authority_ref"], "endpoint cleanup authority"
            ),
            endpoint_directory_identity_ref=_digest(
                row["endpoint_directory_identity_ref"], "endpoint directory identity"
            ),
            native_observation_ref=_digest(
                row["native_observation_ref"], "native observation"
            ),
            controller_boot_id=_text(row["controller_boot_id"], "controller boot identity", 36),
            worker_host_pid=_integer(row["worker_host_pid"], "worker host pid"),
            worker_uid=_integer(row["worker_uid"], "worker uid", 1, 2**32 - 2),
            worker_gid=_integer(row["worker_gid"], "worker gid", 1, 2**32 - 2),
            worker_start_ticks=_integer(row["worker_start_ticks"], "worker start ticks"),
            worker_nspid=tuple(
                _integer(item, "worker namespace pid")
                for item in row["worker_nspid"]
            )
            if isinstance(row["worker_nspid"], list)
            and 1 <= len(row["worker_nspid"]) <= 8
            else (),
        )
        if _BOOT_ID.fullmatch(result.controller_boot_id) is None or (
            not result.worker_nspid or result.worker_nspid[0] != result.worker_host_pid
        ):
            raise StrixLinuxRuntimeClosureError("controller boot identity is invalid")
        return result

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["worker_nspid"] = list(self.worker_nspid)
        return result


_RECEIPT_FIELDS = {
    "schema_version",
    "observed_at",
    "attempt_id",
    "resource_claim_ref",
    "worker_activation_ref",
    "worker_containment_ref",
    "boundary_helper_digest",
    "worker_custody_identity_digest",
    "cgroup_ref",
    "seccomp_profile_digest",
    "input_bindings_ref",
    "sealed_inputs_ref",
    "startup_overlay_ref",
    "installed_projection_ref",
    "controller_socket_identity_ref",
    "model_listener_ref",
    "caido_listener_ref",
    "endpoint_cleanup_authority_ref",
    "endpoint_directory_identity_ref",
    "native_observation_ref",
    "controller_boot_id",
    "worker_host_pid",
    "worker_uid",
    "worker_gid",
    "worker_start_ticks",
    "worker_nspid",
    "plan_ref",
    "source_root_identity_digest",
    "closure_inventory_digest",
    "interpreter_digest",
    "strix_entrypoint_digest",
    "bootstrap_digest",
    "lockdown_source_digest",
    "private_root_mount_id",
    "private_root_st_dev",
    "private_root_st_ino",
    "mount_namespace_inode",
    "network_namespace_inode",
    "ipc_namespace_inode",
    "uts_namespace_inode",
    "argv_digest",
    "environment_digest",
    "input_paths_digest",
    "guest_projection_digest",
    "private_device_policy_digest",
    "control_socket_path",
    "private_overmounts",
    "execveat_empty_path",
    "fresh_address_space",
    "ambient_credentials_absent",
    "closure_copy_verified",
    "closure_mount_read_only",
    "closure_mount_nosuid",
    "closure_mount_nodev",
    "private_devices_exact",
    "private_etc_exact",
    "proc_absent",
    "sys_absent",
    "host_root_detached",
    "sealed_inputs_bound",
    "controller_socket_bound",
    "model_listener_bound",
    "caido_listener_bound",
    "supplementary_groups_empty",
    "capabilities_empty",
    "no_new_privileges",
    "seccomp_tsync_armed",
    "exec_process_probes_refused",
    "startup_imports_verified",
    "required_threads_verified",
    "endpoint_cleanup_capability_held",
    "production_activation_eligible",
    "receipt_ref",
}


class StrixLinuxFixedExecReceipt:
    """Durable native observation; never sufficient as live authority."""

    __slots__ = ("_canonical",)
    _canonical: bytes

    def __new__(cls, token: object = None) -> "StrixLinuxFixedExecReceipt":
        if token is not _RECEIPT_CONSTRUCTION:
            raise TypeError("fixed exec receipts come only from authenticated native evidence")
        return super().__new__(cls)

    def __init__(self, token: object = None) -> None:
        if token is not _RECEIPT_CONSTRUCTION:
            raise TypeError("fixed exec receipts come only from authenticated native evidence")

    @classmethod
    def _from_authenticated_native(
        cls,
        value: Any,
        *,
        plan: StrixLinuxRuntimeClosurePlan,
        expected: FixedExecExpectedBindings,
    ) -> "StrixLinuxFixedExecReceipt":
        plan = StrixLinuxRuntimeClosurePlan.from_mapping(plan.to_dict())
        expected = FixedExecExpectedBindings.from_mapping(expected.to_dict())
        row = _exact(value, _RECEIPT_FIELDS, "native fixed exec observation")
        canonical: dict[str, Any] = {}
        for name in (
            "resource_claim_ref",
            "worker_activation_ref",
            "worker_containment_ref",
            "boundary_helper_digest",
            "worker_custody_identity_digest",
            "cgroup_ref",
            "seccomp_profile_digest",
            "input_bindings_ref",
            "sealed_inputs_ref",
            "startup_overlay_ref",
            "installed_projection_ref",
            "controller_socket_identity_ref",
            "model_listener_ref",
            "caido_listener_ref",
            "endpoint_cleanup_authority_ref",
            "endpoint_directory_identity_ref",
            "native_observation_ref",
            "plan_ref",
            "source_root_identity_digest",
            "closure_inventory_digest",
            "interpreter_digest",
            "strix_entrypoint_digest",
            "bootstrap_digest",
            "lockdown_source_digest",
            "argv_digest",
            "environment_digest",
            "input_paths_digest",
            "guest_projection_digest",
            "private_device_policy_digest",
            "receipt_ref",
        ):
            canonical[name] = _digest(row[name], name.replace("_", " "))
        canonical.update(
            {
                "schema_version": _text(row["schema_version"], "receipt schema"),
                "observed_at": _text(row["observed_at"], "observation time", 20),
                "attempt_id": _text(row["attempt_id"], "attempt identity", 128),
                "controller_boot_id": _text(
                    row["controller_boot_id"], "controller boot identity", 36
                ),
                "control_socket_path": _text(
                    row["control_socket_path"], "controller socket path", 128
                ),
                "private_overmounts": row["private_overmounts"],
                "worker_nspid": row["worker_nspid"],
            }
        )
        for name in (
            "worker_host_pid",
            "worker_uid",
            "worker_gid",
            "worker_start_ticks",
            "private_root_mount_id",
            "private_root_st_dev",
            "private_root_st_ino",
            "mount_namespace_inode",
            "network_namespace_inode",
            "ipc_namespace_inode",
            "uts_namespace_inode",
        ):
            canonical[name] = _integer(row[name], name.replace("_", " "), 1, 2**64 - 1)
        if (
            not isinstance(canonical["worker_nspid"], list)
            or not 1 <= len(canonical["worker_nspid"]) <= 8
        ):
            raise StrixLinuxRuntimeClosureError("worker namespace pid tuple is invalid")
        canonical["worker_nspid"] = [
            _integer(item, "worker namespace pid")
            for item in canonical["worker_nspid"]
        ]
        for name in _RECEIPT_FIELDS - set(canonical) - {"receipt_ref"}:
            canonical[name] = _true(row[name], name.replace("_", " "))
        if _UTC.fullmatch(canonical["observed_at"]) is None:
            raise StrixLinuxRuntimeClosureError("fixed exec observation time is invalid")
        exact_bindings = expected.to_dict()
        if any(canonical[name] != value for name, value in exact_bindings.items()):
            raise StrixLinuxRuntimeClosureError("native fixed exec identity does not match custody")
        if (
            canonical["schema_version"] != RECEIPT_SCHEMA
            or canonical["plan_ref"] != plan.plan_ref
            or canonical["source_root_identity_digest"] != plan.root_identity_digest
            or canonical["closure_inventory_digest"] != plan.inventory_digest
            or canonical["interpreter_digest"] != plan.interpreter_digest
            or canonical["strix_entrypoint_digest"] != plan.strix_entrypoint_digest
            or canonical["bootstrap_digest"] != plan.bootstrap_digest
            or canonical["lockdown_source_digest"] != plan.lockdown_source_digest
            or canonical["seccomp_profile_digest"] != plan.seccomp_profile_digest
            or canonical["argv_digest"] != content_hash(list(FIXED_ARGV))
            or canonical["environment_digest"]
            != content_hash([list(item) for item in FIXED_ENVIRONMENT])
            or canonical["input_paths_digest"]
            != content_hash([list(item) for item in FIXED_INPUT_PATHS])
            or canonical["guest_projection_digest"] != FIXED_GUEST_PROJECTION_DIGEST
            or canonical["installed_projection_ref"] != FIXED_GUEST_PROJECTION_DIGEST
            or canonical["startup_overlay_ref"] != plan.startup_overlay_ref
            or canonical["private_device_policy_digest"] != PRIVATE_DEVICE_POLICY_DIGEST
            or canonical["control_socket_path"] != FIXED_CONTROL_SOCKET
            or canonical["private_overmounts"] != list(PRIVATE_OVERMOUNTS)
        ):
            raise StrixLinuxRuntimeClosureError("native fixed exec evidence is inconsistent")
        expected_ref = content_hash(
            {name: item for name, item in canonical.items() if name != "receipt_ref"}
        )
        if canonical["receipt_ref"] != expected_ref:
            raise StrixLinuxRuntimeClosureError("native fixed exec receipt digest is invalid")
        result = cls(_RECEIPT_CONSTRUCTION)
        result._canonical = canonical_json_bytes(canonical)
        return result

    @property
    def receipt_ref(self) -> str:
        return cast(str, json.loads(self._canonical)["receipt_ref"])

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))


class LinuxSeqpacketFixedExecChannel:
    """Controller-owned native channel authenticated on every receipt packet."""

    def __init__(
        self,
        channel: socket.socket,
        pidfd: int,
        expected: FixedExecExpectedBindings,
    ) -> None:
        if sys.platform != "linux":
            raise StrixLinuxRuntimeClosureError("native fixed exec channel requires Linux")
        self._channel: socket.socket = channel
        self._pidfd: int = pidfd
        self.expected: FixedExecExpectedBindings = FixedExecExpectedBindings.from_mapping(
            expected.to_dict()
        )
        self._closed: bool = False
        if channel.family != socket.AF_UNIX or channel.type & 0xF != socket.SOCK_SEQPACKET:
            raise StrixLinuxRuntimeClosureError("native observation channel is not seqpacket")
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.verify()

    def _pidfd_identity(self) -> tuple[int, tuple[int, ...]]:
        try:
            rows = PathLike.read_text(f"/proc/self/fdinfo/{self._pidfd}")
        except OSError as error:
            raise StrixLinuxRuntimeClosureError("native helper pidfd is unavailable") from error
        values = {
            key: value.strip()
            for line in rows.splitlines()
            if ":" in line
            for key, value in [line.split(":", 1)]
        }
        pid = int(values.get("Pid", "0"))
        nspid = tuple(int(item) for item in values.get("NSpid", "").split())
        return pid, nspid

    def verify(self) -> None:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("native observation channel is closed")
        pid, nspid = self._pidfd_identity()
        if pid != self.expected.worker_host_pid or nspid != self.expected.worker_nspid:
            raise StrixLinuxRuntimeClosureError("native helper pidfd identity changed")
        try:
            stat_row = PathLike.read_text(f"/proc/{pid}/stat")
            status = PathLike.read_text(f"/proc/{pid}/status")
        except OSError as error:
            raise StrixLinuxRuntimeClosureError("native helper process is unavailable") from error
        tail = stat_row[stat_row.rfind(")") + 2 :].split()
        start_ticks = int(tail[19]) if len(tail) > 19 else 0
        status_values = {
            key: value.strip()
            for line in status.splitlines()
            if ":" in line
            for key, value in [line.split(":", 1)]
        }
        uid = int(status_values.get("Uid", "0").split()[0])
        gid = int(status_values.get("Gid", "0").split()[0])
        if (
            start_ticks != self.expected.worker_start_ticks
            or uid != self.expected.worker_uid
            or gid != self.expected.worker_gid
        ):
            raise StrixLinuxRuntimeClosureError("native helper custody identity changed")

    def receive(
        self,
        *,
        expected_phase: str,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> Mapping[str, Any]:
        self.verify()
        poller = cast(Any, select).poll()
        poller.register(
            self._channel.fileno(),
            cast(Any, select).POLLIN
            | cast(Any, select).POLLERR
            | cast(Any, select).POLLHUP,
        )
        while True:
            if cancelled():
                raise StrixLinuxRuntimeClosureError("native fixed exec startup was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StrixLinuxRuntimeClosureError("native fixed exec startup timed out")
            events = poller.poll(max(1, min(100, int(remaining * 1000))))
            if not events:
                continue
            if any(event & (cast(Any, select).POLLERR | cast(Any, select).POLLHUP) for _, event in events):
                raise StrixLinuxRuntimeClosureError("native fixed exec channel closed early")
            break
        credential_size = struct.calcsize("3i")
        cmsg_space = cast(Any, socket).CMSG_SPACE
        scm_credentials = cast(Any, socket).SCM_CREDENTIALS
        packet, ancillary, flags, _address = cast(
            tuple[bytes, list[tuple[int, int, bytes]], int, Any],
            cast(Any, self._channel).recvmsg(
                _MAX_PACKET + 1, cmsg_space(credential_size)
            ),
        )
        if not packet or len(packet) > _MAX_PACKET or flags != 0:
            raise StrixLinuxRuntimeClosureError("native observation packet is invalid")
        credentials = [
            struct.unpack("3i", data[:credential_size])
            for level, kind, data in ancillary
            if level == socket.SOL_SOCKET
            and kind == scm_credentials
            and len(data) >= credential_size
        ]
        expected = (
            self.expected.worker_host_pid,
            self.expected.worker_uid,
            self.expected.worker_gid,
        )
        if credentials != [expected]:
            raise StrixLinuxRuntimeClosureError("native observation credentials are invalid")
        try:
            value = json.loads(packet)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StrixLinuxRuntimeClosureError("native observation is not JSON") from error
        if canonical_json_bytes(value) != packet:
            raise StrixLinuxRuntimeClosureError("native observation is not canonical")
        envelope = _exact(
            value,
            {"schema_version", "phase", "payload", "payload_ref"},
            "fixed exec observation envelope",
        )
        phase = _text(envelope["phase"], "fixed exec observation phase", 16)
        payload = envelope["payload"]
        if (
            envelope["schema_version"] != _ENVELOPE_SCHEMA
            or phase != expected_phase
            or not isinstance(payload, Mapping)
            or _digest(envelope["payload_ref"], "observation payload")
            != content_hash(payload)
        ):
            raise StrixLinuxRuntimeClosureError("native observation envelope is invalid")
        self.verify()
        return cast(Mapping[str, Any], payload)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._channel.close()
        os.close(self._pidfd)


class FixedExecAuthority:
    """Live controller authority required before any model/effect lease."""

    def __init__(
        self,
        pinned: PinnedStrixRuntimeClosure,
        channel: LinuxSeqpacketFixedExecChannel,
        *,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> None:
        pinned.verify()
        channel.verify()
        if channel.expected.controller_boot_id != pinned.plan.controller_boot_id:
            raise StrixLinuxRuntimeClosureError("fixed exec boot identity is inconsistent")
        if not 0.0 < timeout_seconds <= _MAX_STARTUP_SECONDS:
            raise StrixLinuxRuntimeClosureError("fixed exec startup timeout is invalid")
        deadline = time.monotonic() + timeout_seconds
        armed = channel.receive(
            expected_phase="armed", deadline=deadline, cancelled=cancelled
        )
        self._validate_armed(armed, pinned.plan, channel.expected)
        value = channel.receive(
            expected_phase="qualified", deadline=deadline, cancelled=cancelled
        )
        self.receipt: StrixLinuxFixedExecReceipt = (
            StrixLinuxFixedExecReceipt._from_authenticated_native(
            value, plan=pinned.plan, expected=channel.expected
            )
        )
        self._pinned: PinnedStrixRuntimeClosure = pinned
        self._channel: LinuxSeqpacketFixedExecChannel = channel
        self._closed: bool = False

    @staticmethod
    def _validate_armed(
        value: Mapping[str, Any],
        plan: StrixLinuxRuntimeClosurePlan,
        expected: FixedExecExpectedBindings,
    ) -> None:
        row = _exact(
            value,
            {
                "schema_version",
                "attempt_id",
                "plan_ref",
                "worker_custody_identity_digest",
                "seccomp_profile_digest",
                "no_new_privileges",
                "seccomp_mode",
                "tsync",
            },
            "fixed exec armed observation",
        )
        if (
            row["schema_version"] != _ARMED_SCHEMA
            or row["attempt_id"] != expected.attempt_id
            or _digest(row["plan_ref"], "armed plan") != plan.plan_ref
            or _digest(row["worker_custody_identity_digest"], "armed custody")
            != expected.worker_custody_identity_digest
            or _digest(row["seccomp_profile_digest"], "armed seccomp")
            != plan.seccomp_profile_digest
            or _true(row["no_new_privileges"], "armed no-new-privileges") is not True
            or _integer(row["seccomp_mode"], "armed seccomp mode", 2, 2) != 2
            or _true(row["tsync"], "armed TSYNC") is not True
        ):
            raise StrixLinuxRuntimeClosureError("fixed exec armed evidence is invalid")

    @property
    def custody_identity(self) -> tuple[int, int, int, int, tuple[int, ...]]:
        expected = self._channel.expected
        return (
            expected.worker_host_pid,
            expected.worker_uid,
            expected.worker_gid,
            expected.worker_start_ticks,
            expected.worker_nspid,
        )

    @property
    def custody_identity_digest(self) -> str:
        return self._channel.expected.worker_custody_identity_digest

    @property
    def containment_ref(self) -> str:
        return self._channel.expected.worker_containment_ref

    @property
    def startup_overlay_ref(self) -> str:
        return self._channel.expected.startup_overlay_ref

    @property
    def installed_projection_ref(self) -> str:
        return self._channel.expected.installed_projection_ref

    @property
    def sealed_inputs_ref(self) -> str:
        return self._channel.expected.sealed_inputs_ref

    def verify(self) -> None:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("fixed exec authority is closed")
        self._pinned.verify()
        self._channel.verify()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._channel.close()
        self._pinned.close()


class PathLike:
    """Tiny indirection kept replaceable in bounded Linux tests."""

    @staticmethod
    def read_text(path: str) -> str:
        with open(path, encoding="utf-8") as handle:
            return handle.read()


__all__ = [
    "FixedExecAuthority",
    "FixedExecExpectedBindings",
    "LinuxSeqpacketFixedExecChannel",
    "RECEIPT_SCHEMA",
    "StrixLinuxFixedExecReceipt",
]
