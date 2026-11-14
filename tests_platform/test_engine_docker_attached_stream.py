from __future__ import annotations

import struct

import pytest

from bluefire.engine_docker_attached_stream import (
    DockerAttachedStreamError,
    decode_docker_multiplex_stream,
)


def frame(stream: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream, len(payload)) + payload


def test_demultiplex_retains_order_and_splits_stdout_and_stderr() -> None:
    body = frame(1, b"first") + frame(2, b"warning") + frame(1, b" last")
    result = decode_docker_multiplex_stream(body, decoded_limit=32, overhead_limit=24)
    assert result.multiplexed == body
    assert result.stdout == b"first last"
    assert result.stderr == b"warning"
    assert result.decoded_payload_bytes == 17
    assert result.framing_overhead_bytes == 24
    assert result.frame_count == 3


@pytest.mark.parametrize(
    "body,code",
    [
        (b"short", "header_truncated"),
        (b"\x03\x00\x00\x00\x00\x00\x00\x00", "header_invalid"),
        (frame(1, b"abc")[:-1], "payload_truncated"),
    ],
)
def test_malformed_or_truncated_frame_is_refused(body: bytes, code: str) -> None:
    with pytest.raises(DockerAttachedStreamError) as caught:
        decode_docker_multiplex_stream(body, decoded_limit=64, overhead_limit=64)
    assert caught.value.code == code


def test_decoded_payload_and_framing_overhead_have_separate_bounds() -> None:
    with pytest.raises(DockerAttachedStreamError) as payload:
        decode_docker_multiplex_stream(frame(1, b"12345"), decoded_limit=4, overhead_limit=8)
    assert payload.value.code == "payload_limit"

    many_empty_frames = frame(1, b"") + frame(2, b"")
    with pytest.raises(DockerAttachedStreamError) as overhead:
        decode_docker_multiplex_stream(many_empty_frames, decoded_limit=0, overhead_limit=8)
    assert overhead.value.code == "overhead_limit"
