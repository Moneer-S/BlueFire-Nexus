"""Fixed SDK worker conversation; the native owner supplies admission and deadlines.

This module has no command or factory selection on its wire. ``run_worker`` is
called only by the protected runtime entrypoint; its injected factory is a code
test seam, never request data. Blocking pipe reads remain subject to the native
owner's hard deadline and process cleanup, not a Python clock-check guarantee.
"""

from __future__ import annotations

from typing import Any, BinaryIO, Mapping

from .s3_access_contract import S3AccessError
from .s3_access_sdk import S3SdkAdapter
from .s3_access_sdk_boundary import S3ClientFactory
from .s3_access_wire import (
    MAX_FRAME_BYTES,
    MAX_SECRET_FRAME_BYTES,
    Clock,
    S3WorkerHandshake,
    S3WorkerRequest,
    decode_frame,
    encode_frame,
    validate_result,
)

MAX_INPUT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 64 * 1024


class _Conversation:
    def __init__(self, source: BinaryIO, destination: BinaryIO, clock: Clock):
        self.source = source
        self.destination = destination
        self.clock = clock
        self.request: S3WorkerRequest | None = None
        self.input_bytes = 0
        self.output_bytes = 0
        self.closed = False

    def checkpoint(self) -> None:
        if self.closed:
            raise S3AccessError("worker conversation is closed")
        if self.request is not None:
            self.request.assert_current(self.clock)

    def read(self, maximum: int) -> bytes:
        self.checkpoint()
        payload = self.source.readline(maximum + 1)
        self.checkpoint()
        if not isinstance(payload, bytes):
            raise S3AccessError("worker input is not a byte channel")
        self.input_bytes += len(payload)
        if (
            len(payload) > maximum
            or self.input_bytes > MAX_INPUT_BYTES
            or not payload.endswith(b"\n")
        ):
            raise S3AccessError("worker input frame is incomplete or exceeds its bound")
        return payload

    def write(self, document: Mapping[str, Any]) -> None:
        self.checkpoint()
        payload = encode_frame(document)
        self.output_bytes += len(payload)
        if self.output_bytes > MAX_OUTPUT_BYTES:
            raise S3AccessError("worker output exceeds its bound")
        position = 0
        while position < len(payload):
            self.checkpoint()
            written = self.destination.write(payload[position:])
            if type(written) is not int or written <= 0 or written > len(payload) - position:
                raise S3AccessError("worker output channel is unavailable")
            position += written
        self.destination.flush()
        self.checkpoint()

    def permit(self, preview: Mapping[str, Any]) -> dict[str, Any]:
        self.write(preview)
        return decode_frame(self.read(2048), maximum=2048)

    def close_notice(self) -> None:
        # A failed/expired protocol has no new send authority. This fixed notice
        # contains no exception, input fragment, credentials or SDK error text.
        if self.closed:
            return
        self.closed = True
        payload = encode_frame(
            {
                "kind": "closed",
                "request_digest": self.request.digest if self.request is not None else None,
                "problem": "worker_protocol_failed",
            }
        )
        if self.output_bytes + len(payload) <= MAX_OUTPUT_BYTES:
            try:
                written = self.destination.write(payload)
                if written == len(payload):
                    self.destination.flush()
            except (OSError, ValueError):
                pass


def run_worker(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    factory: S3ClientFactory,
    clock: Clock,
    process_id: int,
    creation_identity: str,
    nonce: str,
    expected_runtime_digest: str,
    expected_worker_generation: str,
) -> int:
    """Serve exactly one admitted request; no continuation or retry is accepted.

    The runtime owner supplies the observed process identity and reviewed factory.
    Matching ready/contained frames is consistency checking, not host isolation.
    """
    channel = _Conversation(source, destination, clock)
    try:
        request = S3WorkerRequest.from_mapping(decode_frame(channel.read(MAX_FRAME_BYTES)))
        channel.request = request
        row = request.to_dict()
        if (
            row["runtime_digest"] != expected_runtime_digest
            or row["worker_generation"] != expected_worker_generation
        ):
            raise S3AccessError("worker request differs from its protected runtime")
        channel.checkpoint()
        handshake = S3WorkerHandshake(
            request,
            process_id=process_id,
            creation_identity=creation_identity,
            nonce=nonce,
        )
        channel.write(handshake.ready())
        handshake.accept_containment_ack(decode_frame(channel.read(2048), maximum=2048))
        credentials = handshake.accept_credentials(
            channel.read(MAX_SECRET_FRAME_BYTES), clock=clock
        )
        result = S3SdkAdapter(
            request,
            credentials,
            factory=factory,
            permit=channel.permit,
            clock=clock,
        ).execute()
        channel.write({"kind": "result", "result": validate_result(request, result)})
        channel.closed = True
        return 0
    except Exception:
        channel.close_notice()
        return 1
