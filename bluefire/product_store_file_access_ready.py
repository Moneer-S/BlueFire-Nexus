"""Shared Ready trail checks; fixed callers retain admission and transactions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import product_store_file_access_native_evidence as native
from . import windows_file_access_native_wire as wire


def _pair_wire(protocol: native._Protocol):
    wire._require(protocol in (native._Protocol.PAIR_V2, native._Protocol.CORRECTION_V3))
    if protocol is native._Protocol.PAIR_V2:
        return wire.pair_public_frame, wire.validate_pair_retained_packet, wire.validate_pair_ready
    return (
        wire.correction_public_frame,
        wire.validate_correction_retained_packet,
        wire.validate_correction_ready,
    )


def _record_ready_at(
    connection: Any,
    context: native._Context,
    prepared: wire.PreparedPacket,
    ready: bytes,
    clock: datetime,
) -> None:
    trail, documents = native._load(connection, context, clock)
    wire._require(trail.packet_bytes == prepared._raw and "ready" not in documents)
    wire._require(native._cleanup_load(connection, context, clock, trail)[1] is None)
    native._record_at(connection, context, "ready", ready, None, clock)


def _allowance_at(
    connection: Any,
    context: native._Context,
    prepared: wire.PreparedPacket,
    ready: bytes,
    clock: datetime,
) -> None:
    trail = native._load(connection, context, clock)[0]
    wire._require(
        trail.packet_bytes == prepared._raw
        and trail.ready_bytes == ready
        and trail.terminal_bytes is None
    )
    wire._require(native._cleanup_load(connection, context, clock, trail)[1] is None)


def _unfinished_at(
    connection: Any, context: native._Context, prepared: wire.PreparedPacket, clock: datetime
) -> None:
    trail = native._load(connection, context, clock)[0]
    wire._require(trail.packet_bytes in (None, prepared._raw) and trail.terminal_bytes is None)
    wire._require(native._cleanup_load(connection, context, clock, trail)[1] is None)
