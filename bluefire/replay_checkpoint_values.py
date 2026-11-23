"""Bounded ordinary JSON values shared by checkpoint manifests and proofs."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .util import canonical_json_bytes

MAX_CHECKPOINT_JSON_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_JSON_NODES = 20_000
_SENSITIVE_MARKERS = frozenset(
    "apikey authorization cookie credential nonce password privatekey providerartifact receipt secret token".split()
)


class CheckpointError(ValueError):
    """Raised when checkpoint or restoration data is unsafe or inconsistent."""


def bounded_json_copy(value: Any, context: str, *, reject_sensitive: bool = False) -> Any:
    count = 0

    def inspect(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_CHECKPOINT_JSON_NODES or depth > 12:
            raise CheckpointError(f"{context} exceeds its structural bound")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            return
        if isinstance(item, str):
            if len(item) > 16_384 or "\x00" in item:
                raise CheckpointError(f"{context} contains unsafe text")
            return
        if isinstance(item, Mapping):
            if len(item) > 1_024:
                raise CheckpointError(f"{context} contains an oversized object")
            for key, nested in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise CheckpointError(f"{context} contains an invalid field name")
                compact = re.sub(r"[^a-z0-9]", "", key.casefold())
                if reject_sensitive and any(marker in compact for marker in _SENSITIVE_MARKERS):
                    raise CheckpointError(f"{context} contains forbidden sensitive authority")
                inspect(nested, depth + 1)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > 2_048:
                raise CheckpointError(f"{context} contains an oversized list")
            for nested in item:
                inspect(nested, depth + 1)
            return
        raise CheckpointError(f"{context} is not strict JSON data")

    inspect(value, 0)
    try:
        encoded = canonical_json_bytes(value)
        if len(encoded) > MAX_CHECKPOINT_JSON_BYTES:
            raise CheckpointError(f"{context} exceeds its byte bound")
        return json.loads(encoded)
    except (OverflowError, TypeError, ValueError) as exc:
        raise CheckpointError(f"{context} is not canonical JSON data") from exc


def json_cost(value: Any) -> tuple[int, int]:
    """Bound each compact document before serialization and every expanded use."""
    stack = [(value, 0)]
    nodes = text_bytes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        _bounded(nodes <= MAX_CHECKPOINT_JSON_NODES and depth <= 12)
        if isinstance(item, str):
            _bounded(len(item) <= 16_384 and "\x00" not in item)
            text_bytes += len(item.encode("utf-8"))
        elif isinstance(item, Mapping):
            _bounded(len(item) <= 1024)
            for key, nested in item.items():
                _bounded(isinstance(key, str) and 0 < len(key) <= 256)
                text_bytes += len(key.encode("utf-8"))
                stack.append((nested, depth + 1))
        elif isinstance(item, (list, tuple)):
            _bounded(len(item) <= 2048)
            stack.extend((nested, depth + 1) for nested in item)
        else:
            _bounded(item is None or isinstance(item, (bool, int, float)))
        _bounded(text_bytes <= MAX_CHECKPOINT_JSON_BYTES)
    size = len(canonical_json_bytes(value))
    _bounded(size <= MAX_CHECKPOINT_JSON_BYTES)
    return size, nodes


def _bounded(condition: bool) -> None:
    if not condition:
        raise CheckpointError("checkpoint parameter resolution exceeds its JSON bounds")
