"""Bounded explicit operator definition; credential travels only over owned stdin."""

from __future__ import annotations

import os
import select
import struct
import time
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from .ai_broker_contract import refusal, strict_object
from .ai_wire import credential_value
from .config import AIProviderConfig
from .util import canonical_json_bytes

LIMIT = 16_384


def operator_definition(
    path: Path, policy: str, max_nodes: int, max_edges: int, *, environ: Mapping[str, str]
) -> Mapping[str, Any]:
    with path.open("rb") as source:
        payload = source.read(LIMIT + 1)
    if len(payload) > LIMIT:
        raise ValueError("public provider definition exceeds 16 KiB")
    config = AIProviderConfig.from_mapping(strict_object(payload))
    credential = credential_value(config, environ) if config.api_key is not None else None
    if config.api_key is not None and not credential:
        raise ValueError("the explicitly configured provider credential is unavailable")
    return {
        "configuration": config.to_dict(),
        "destination_policy": policy,
        "credential": credential,
        "max_nodes": max_nodes,
        "max_edges": max_edges,
    }


def write_definition(stream: BinaryIO, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(value)
    if not 1 <= len(payload) <= LIMIT:
        raise refusal()
    remaining = memoryview(struct.pack("!I", len(payload)) + payload)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise refusal()
        remaining = remaining[written:]
    stream.flush()


def read_definition(descriptor: int) -> Mapping[str, Any]:
    deadline = time.monotonic() + 10

    def exact(count: int) -> bytes:
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise refusal()
            ready, _, _ = select.select([descriptor], [], [], min(0.1, remaining))
            if not ready:
                continue
            block = os.read(descriptor, count - len(result))
            if not block:
                raise refusal()
            result.extend(block)
        return bytes(result)

    size = struct.unpack("!I", exact(4))[0]
    if not 1 <= size <= LIMIT:
        raise refusal()
    return strict_object(exact(size))
