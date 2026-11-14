"""Credentialed Linux packet transport for one controlled Strix worker.

Every packet carries kernel-supplied process credentials.  A forked child or
another same-UID process therefore cannot continue an authenticated channel by
inheriting or receiving its file descriptor.  The existing canonical worker
frames remain unchanged above this bounded packet layer.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable

PACKET_BYTES = 64 * 1024
_MAGIC = b"BFP1"
_HEADER = struct.Struct("!4s16sIIII")
_CREDENTIALS = struct.Struct("3i")
_PAYLOAD_BYTES = PACKET_BYTES - _HEADER.size
_TERMINAL = 1


class CredentialedPacketError(RuntimeError):
    """A packet, sender credential, or frame boundary was not exact."""


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if (
            type(self.pid) is not int
            or self.pid <= 0
            or type(self.uid) is not int
            or self.uid < 0
            or type(self.gid) is not int
            or self.gid < 0
        ):
            raise CredentialedPacketError("credentialed packet refused")

    def accepts(self, observed: "PeerIdentity") -> bool:
        return type(observed) is PeerIdentity and (observed.pid, observed.uid, observed.gid) == (
            self.pid,
            self.uid,
            self.gid,
        )


def _remaining(deadline_ns: int) -> float:
    seconds = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if seconds <= 0:
        raise CredentialedPacketError("credentialed packet refused")
    return seconds


async def _ready(
    connection: socket.socket,
    deadline_ns: int,
    register: Callable[[int, Callable[[], None]], None],
    unregister: Callable[[int], bool],
) -> None:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[None] = loop.create_future()

    def available() -> None:
        if not future.done():
            future.set_result(None)

    descriptor = connection.fileno()
    register(descriptor, available)
    try:
        await asyncio.wait_for(future, _remaining(deadline_ns))
    finally:
        with contextlib.suppress(Exception):
            unregister(descriptor)


async def _send_packet(connection: socket.socket, packet: bytes, deadline_ns: int) -> None:
    loop = asyncio.get_running_loop()
    flags = getattr(socket, "MSG_NOSIGNAL", 0)
    while True:
        _remaining(deadline_ns)
        try:
            sent = connection.send(packet, flags)
        except (BlockingIOError, InterruptedError):
            await _ready(connection, deadline_ns, loop.add_writer, loop.remove_writer)
            continue
        if sent != len(packet):
            raise CredentialedPacketError("credentialed packet refused")
        return


def _packet_credentials(ancillary: list[tuple[int, int, bytes]]) -> PeerIdentity:
    values = [
        data
        for level, kind, data in ancillary
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
    ]
    if len(values) != 1 or len(values[0]) != _CREDENTIALS.size:
        raise CredentialedPacketError("credentialed packet refused")
    return PeerIdentity(*_CREDENTIALS.unpack(values[0]))


async def _receive_packet(
    connection: socket.socket, deadline_ns: int, expected_peer: PeerIdentity
) -> bytes:
    loop = asyncio.get_running_loop()
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0) | getattr(socket, "MSG_DONTWAIT", 0)
    control_bytes = socket.CMSG_SPACE(_CREDENTIALS.size)
    while True:
        try:
            packet, ancillary, message_flags, _address = connection.recvmsg(
                PACKET_BYTES, control_bytes, flags
            )
        except (BlockingIOError, InterruptedError):
            await _ready(connection, deadline_ns, loop.add_reader, loop.remove_reader)
            continue
        if (
            not packet
            or message_flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))
            or not expected_peer.accepts(_packet_credentials(ancillary))
        ):
            raise CredentialedPacketError("credentialed packet refused")
        return packet


def configure_socket(connection: socket.socket) -> None:
    if (
        connection.family != socket.AF_UNIX
        or connection.type & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET
        or not hasattr(socket, "SO_PASSCRED")
        or not hasattr(socket, "SCM_CREDENTIALS")
    ):
        raise CredentialedPacketError("credentialed packet refused")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    connection.set_inheritable(False)
    connection.setblocking(False)


def _packets_for_frame(frame: bytes, *, frame_id: bytes | None = None) -> tuple[bytes, ...]:
    if type(frame) is not bytes or not frame:
        raise CredentialedPacketError("credentialed packet refused")
    selected_id = secrets.token_bytes(16) if frame_id is None else frame_id
    if type(selected_id) is not bytes or len(selected_id) != 16:
        raise CredentialedPacketError("credentialed packet refused")
    total = len(frame)
    result = []
    for offset in range(0, total, _PAYLOAD_BYTES):
        payload = frame[offset : offset + _PAYLOAD_BYTES]
        terminal = _TERMINAL if offset + len(payload) == total else 0
        packet = _HEADER.pack(_MAGIC, selected_id, total, offset, len(payload), terminal) + payload
        result.append(packet)
    return tuple(result)


async def write_frame(connection: socket.socket, frame: bytes, deadline_ns: int) -> None:
    for packet in _packets_for_frame(frame):
        await _send_packet(connection, packet, deadline_ns)


async def read_frame(
    connection: socket.socket,
    deadline_ns: int,
    *,
    limit: int,
    expected_peer: PeerIdentity,
    frame_timeout_seconds: float | None = None,
) -> bytes:
    if type(limit) is not int or limit <= 0:
        raise CredentialedPacketError("credentialed packet refused")
    assembled = bytearray()
    frame_id: bytes | None = None
    total: int | None = None
    frame_deadline = deadline_ns
    packets_seen = 0
    maximum_packets = (limit + 4 + _PAYLOAD_BYTES - 1) // _PAYLOAD_BYTES
    while True:
        _remaining(frame_deadline)
        packet = await _receive_packet(connection, frame_deadline, expected_peer)
        packets_seen += 1
        if len(packet) <= _HEADER.size:
            raise CredentialedPacketError("credentialed packet refused")
        magic, observed_id, observed_total, offset, size, terminal = _HEADER.unpack(
            packet[: _HEADER.size]
        )
        payload = packet[_HEADER.size :]
        if (
            magic != _MAGIC
            or size != len(payload)
            or not 0 < size <= _PAYLOAD_BYTES
            or (terminal == 0 and size != _PAYLOAD_BYTES)
            or terminal not in {0, _TERMINAL}
            or packets_seen > maximum_packets
            or observed_total > limit + 4
            or observed_total < 5
            or offset != len(assembled)
            or (frame_id is not None and observed_id != frame_id)
            or (total is not None and observed_total != total)
            or offset + size > observed_total
            or (terminal == _TERMINAL) != (offset + size == observed_total)
        ):
            raise CredentialedPacketError("credentialed packet refused")
        if frame_id is None:
            frame_id = observed_id
            total = observed_total
            if frame_timeout_seconds is not None:
                if (
                    type(frame_timeout_seconds) not in {int, float}
                    or not 0.01 <= frame_timeout_seconds <= 300
                ):
                    raise CredentialedPacketError("credentialed packet refused")
                frame_deadline = min(
                    deadline_ns,
                    time.monotonic_ns() + int(frame_timeout_seconds * 1_000_000_000),
                )
        assembled.extend(payload)
        if terminal == _TERMINAL:
            frame = bytes(assembled)
            body_size = int.from_bytes(frame[:4], "little")
            if body_size <= 0 or body_size > limit or body_size + 4 != len(frame):
                raise CredentialedPacketError("credentialed packet refused")
            return frame
        await asyncio.sleep(0)


__all__ = [
    "CredentialedPacketError",
    "PeerIdentity",
    "configure_socket",
    "read_frame",
    "write_frame",
]
