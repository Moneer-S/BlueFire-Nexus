"""Bounded Docker multiplex output used by controller-owned exec attachment.

Docker's non-TTY exec protocol prefixes every stdout/stderr block with an
eight-byte header. The decoded payload and framing overhead have separate
budgets so many empty or tiny frames cannot bypass the command output limit.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import cast


class DockerAttachedStreamError(ValueError):
    """A bounded reason for rejecting Docker's attached byte stream."""

    def __init__(self, code: str) -> None:
        super().__init__(f"Docker attached stream {code}")
        self.code = code


MAX_DOCKER_STREAM_OVERHEAD_BYTES = 1024 * 1024
_MAX_DECODED_BYTES = 32 * 1024**2


def _bound(value: int, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DockerAttachedStreamError(f"{label}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class DockerAttachedOutput:
    """Validated output retaining both ordered frames and split streams."""

    multiplexed: bytes
    stdout: bytes
    stderr: bytes
    decoded_payload_bytes: int
    framing_overhead_bytes: int
    frame_count: int

    def __post_init__(self) -> None:
        for value in (self.multiplexed, self.stdout, self.stderr):
            if not isinstance(value, bytes):
                raise DockerAttachedStreamError("result_invalid")
        _bound(self.decoded_payload_bytes, "decoded_size", _MAX_DECODED_BYTES)
        _bound(
            self.framing_overhead_bytes,
            "overhead_size",
            MAX_DOCKER_STREAM_OVERHEAD_BYTES,
        )
        _bound(self.frame_count, "frame_count", MAX_DOCKER_STREAM_OVERHEAD_BYTES // 8)
        if (
            self.decoded_payload_bytes != len(self.stdout) + len(self.stderr)
            or self.framing_overhead_bytes != self.frame_count * 8
            or len(self.multiplexed) != self.decoded_payload_bytes + self.framing_overhead_bytes
        ):
            raise DockerAttachedStreamError("result_inconsistent")


class DockerMultiplexAccumulator:
    """Validate and retain one attached stream incrementally, frame by frame."""

    def __init__(self, *, decoded_limit: int, overhead_limit: int) -> None:
        self._decoded_limit = _bound(decoded_limit, "decoded_limit", _MAX_DECODED_BYTES)
        self._overhead_limit = _bound(
            overhead_limit, "overhead_limit", MAX_DOCKER_STREAM_OVERHEAD_BYTES
        )
        self._multiplexed = bytearray()
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._decoded = 0
        self._overhead = 0
        self._frames = 0
        self._reserved_payload: tuple[bytes, int] | None = None

    @staticmethod
    def payload_size(header: bytes) -> int:
        if not isinstance(header, bytes) or len(header) != 8:
            raise DockerAttachedStreamError("header_truncated")
        if header[0] not in {1, 2} or header[1:4] != b"\x00\x00\x00":
            raise DockerAttachedStreamError("header_invalid")
        return cast(int, struct.unpack(">I", header[4:8])[0])

    def admit_header(self, header: bytes) -> int:
        if self._reserved_payload is not None:
            raise DockerAttachedStreamError("frame_unsettled")
        size = self.payload_size(header)
        if self._overhead + 8 > self._overhead_limit:
            raise DockerAttachedStreamError("overhead_limit")
        if self._decoded + size > self._decoded_limit:
            raise DockerAttachedStreamError("payload_limit")
        self._overhead += 8
        self._frames += 1
        self._multiplexed.extend(header)
        self._reserved_payload = (header, size)
        return size

    def admit_payload(self, header: bytes, payload: bytes) -> None:
        reserved = self._reserved_payload
        if reserved is None or header != reserved[0]:
            raise DockerAttachedStreamError("payload_unreserved")
        size = reserved[1]
        if not isinstance(payload, bytes) or len(payload) != size:
            raise DockerAttachedStreamError("payload_truncated")
        self._decoded += size
        self._multiplexed.extend(payload)
        (self._stdout if header[0] == 1 else self._stderr).extend(payload)
        self._reserved_payload = None

    def finish(self) -> DockerAttachedOutput:
        if self._reserved_payload is not None:
            raise DockerAttachedStreamError("payload_truncated")
        return DockerAttachedOutput(
            multiplexed=bytes(self._multiplexed),
            stdout=bytes(self._stdout),
            stderr=bytes(self._stderr),
            decoded_payload_bytes=self._decoded,
            framing_overhead_bytes=self._overhead,
            frame_count=self._frames,
        )


def decode_docker_multiplex_stream(
    body: bytes,
    *,
    decoded_limit: int,
    overhead_limit: int = MAX_DOCKER_STREAM_OVERHEAD_BYTES,
) -> DockerAttachedOutput:
    """Decode a complete retained stream using the incremental limits."""

    if not isinstance(body, bytes):
        raise DockerAttachedStreamError("body_invalid")
    state = DockerMultiplexAccumulator(decoded_limit=decoded_limit, overhead_limit=overhead_limit)
    offset = 0
    while offset < len(body):
        if len(body) - offset < 8:
            raise DockerAttachedStreamError("header_truncated")
        header = body[offset : offset + 8]
        offset += 8
        size = state.admit_header(header)
        if size > len(body) - offset:
            raise DockerAttachedStreamError("payload_truncated")
        state.admit_payload(header, body[offset : offset + size])
        offset += size
    return state.finish()


__all__ = [
    "DockerAttachedOutput",
    "DockerAttachedStreamError",
    "DockerMultiplexAccumulator",
    "MAX_DOCKER_STREAM_OVERHEAD_BYTES",
    "decode_docker_multiplex_stream",
]
