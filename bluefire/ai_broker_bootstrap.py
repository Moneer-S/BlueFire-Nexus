"""Linux-only protected, exact-peer transfer of an anonymous inference descriptor."""

from __future__ import annotations

import array
import ctypes
import json
import os
import select
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from .ai_broker_contract import _nonfinite, _pairs, refusal
from .runner_linux_containment import LinuxPrivateProcessContainment
from .util import canonical_json_bytes

BOOTSTRAP_LIMIT = 16_384


def protect_process(expected_uid: int, *, parent: int | None = None) -> None:
    if (
        sys.platform != "linux"
        or os.getuid() != expected_uid
        or os.getgid() != expected_uid
        or os.getgroups()
    ):
        raise refusal("broker_unavailable")
    library = ctypes.CDLL(None, use_errno=True)
    prctl = library.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if parent is not None:
        from .runner_parent_death import _arm_parent_death

        if not _arm_parent_death(parent):
            raise refusal("broker_unavailable")
    if prctl(4, 0, 0, 0, 0) != 0 or prctl(3, 0, 0, 0, 0) != 0:
        raise refusal("broker_unavailable")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if status.get("NoNewPrivs", "").strip() != "1" or any(
        int(status.get(key, "1"), 16) != 0
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ):
        raise refusal("broker_unavailable")


def protected_identity(process_id: int, expected_uid: int) -> tuple[int, int, int, int]:
    before = LinuxPrivateProcessContainment.process_identity(process_id)
    root = Path("/proc") / str(process_id)
    status = dict(
        line.split(":", 1) for line in (root / "status").read_text().splitlines() if ":" in line
    )
    details = (root / "fd").stat()
    if (
        [int(value) for value in status.get("Uid", "").split()] != [expected_uid] * 4
        or [int(value) for value in status.get("Gid", "").split()] != [expected_uid] * 4
        or status.get("NoNewPrivs", "").strip() != "1"
        or status.get("Groups", "").strip()
        or any(
            int(status.get(key, "1"), 16) != 0
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        or details.st_uid != 0
        or details.st_gid != 0
        or before != LinuxPrivateProcessContainment.process_identity(process_id)
    ):
        raise refusal("broker_unavailable")
    return before


def bootstrap_pair() -> tuple[socket.socket, socket.socket]:
    if (
        sys.platform != "linux"
        or not hasattr(socket, "SCM_CREDENTIALS")
        or not hasattr(socket, "MSG_CMSG_CLOEXEC")
    ):
        raise refusal("broker_unavailable")
    pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        for endpoint in pair:
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            endpoint.setblocking(False)
            endpoint.set_inheritable(False)
        return pair
    except BaseException:
        for endpoint in pair:
            endpoint.close()
        raise


def adopt_bootstrap(descriptor: int) -> socket.socket:
    if type(descriptor) is not int or descriptor <= 2:
        raise refusal("broker_unavailable")
    endpoint = socket.socket(fileno=descriptor)
    try:
        if (
            endpoint.family != getattr(socket, "AF_UNIX", -1)
            or endpoint.type != socket.SOCK_SEQPACKET
            or endpoint.getsockname()
            or endpoint.getpeername()
        ):
            raise refusal("broker_unavailable")
        endpoint.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PASSCRED", -1), 1)
        endpoint.setblocking(False)
        endpoint.set_inheritable(False)
        return endpoint
    except BaseException:
        endpoint.close()
        raise


def _ready(endpoint: socket.socket, writing: bool, deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise refusal("request_timed_out")
        readable, writable, _ = select.select(
            [] if writing else [endpoint], [endpoint] if writing else [], [], min(0.05, remaining)
        )
        if readable or writable:
            return


def send_bootstrap(
    endpoint: socket.socket, value: Mapping[str, Any], *, descriptor: int | None = None
) -> None:
    sendmsg = getattr(endpoint, "sendmsg", None)
    if sendmsg is None:
        raise refusal("broker_unavailable")
    payload = canonical_json_bytes(value)
    if not 1 <= len(payload) <= BOOTSTRAP_LIMIT:
        raise refusal()
    ancillary = (
        []
        if descriptor is None
        else [
            (socket.SOL_SOCKET, getattr(socket, "SCM_RIGHTS", -1), array.array("i", [descriptor]))
        ]
    )
    deadline = time.monotonic() + 5.0
    while True:
        _ready(endpoint, True, deadline)
        try:
            if sendmsg([payload], ancillary) != len(payload):
                raise refusal("broker_unavailable")
            return
        except BlockingIOError:
            continue


def receive_bootstrap(
    endpoint: socket.socket,
    *,
    expected_uid: int,
    expected_pid: int,
    descriptor_required: bool = False,
) -> tuple[Mapping[str, Any], int | None]:
    recvmsg = getattr(endpoint, "recvmsg", None)
    cmsg_space = getattr(socket, "CMSG_SPACE", None)
    if recvmsg is None or cmsg_space is None:
        raise refusal("broker_unavailable")
    deadline = time.monotonic() + 10.0
    descriptors: list[int] = []
    try:
        while True:
            _ready(endpoint, False, deadline)
            try:
                payload, ancillary, flags, _address = recvmsg(
                    BOOTSTRAP_LIMIT + 1,
                    cmsg_space(12) + cmsg_space(16),
                    getattr(socket, "MSG_CMSG_CLOEXEC", -1),
                )
                break
            except BlockingIOError:
                continue
        credentials = []
        unexpected = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == getattr(socket, "SCM_RIGHTS", -1):
                values = array.array("i")
                values.frombytes(data[: len(data) - len(data) % values.itemsize])
                descriptors.extend(values)
            elif (
                level == socket.SOL_SOCKET
                and kind == getattr(socket, "SCM_CREDENTIALS", -1)
                and len(data) == 12
            ):
                credentials.append(struct.unpack("3i", data))
            else:
                unexpected = True
        if (
            flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or unexpected
            or credentials != [(expected_pid, expected_uid, expected_uid)]
            or len(descriptors) != int(descriptor_required)
            or not 1 <= len(payload) <= BOOTSTRAP_LIMIT
        ):
            raise refusal("broker_unavailable")
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite
        )
        if not isinstance(value, dict):
            raise refusal()
        result = descriptors.pop() if descriptors else None
        return value, result
    except (ValueError, UnicodeError, RecursionError):
        raise refusal("broker_unavailable") from None
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def adopt_inference(descriptor: int) -> socket.socket:
    try:
        if (
            descriptor <= 2
            or not stat.S_ISSOCK(os.fstat(descriptor).st_mode)
            or os.get_inheritable(descriptor)
        ):
            raise refusal()
        endpoint = socket.socket(fileno=descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    try:
        if (
            endpoint.family != getattr(socket, "AF_UNIX", -1)
            or endpoint.type != socket.SOCK_STREAM
            or endpoint.getsockname()
            or endpoint.getpeername()
        ):
            raise refusal()
        endpoint.set_inheritable(False)
        return endpoint
    except BaseException:
        endpoint.close()
        raise
