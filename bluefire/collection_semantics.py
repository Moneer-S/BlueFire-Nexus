"""Bounded semantic observation of reviewed synthetic collection artifacts."""

from __future__ import annotations

import json
from typing import Any

from .evidence import EvidenceError

MAX_COLLECTION_BYTES = 1024 * 1024
MAX_COLLECTION_RECORDS = 100
_MEMBER = b"fixtures/transformed.jsonl"
_FIELDS = {"record_id", "synthetic", "template", "value"}


def _refuse() -> EvidenceError:
    return EvidenceError("collection artifact is malformed, unsupported, or incomplete")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise _refuse()
        result[name] = value
    return result


def _constant(_value: str) -> Any:
    raise _refuse()


def parse_collection_semantics(payload: bytes) -> dict[str, str | int]:
    """Return aggregate facts only; no record values leave this parser."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_COLLECTION_BYTES:
        raise _refuse()
    container = "jsonl"
    if len(payload) >= 512 and payload[257:263] == b"ustar\0":
        container = "ustar"
        payload = _ustar_member(payload)
    if not payload.endswith(b"\n"):
        raise _refuse()
    lines = payload[:-1].split(b"\n")
    if not 1 <= len(lines) <= MAX_COLLECTION_RECORDS:
        raise _refuse()
    redacted = retained = empty = 0
    for ordinal, line in enumerate(lines, 1):
        if not 1 <= len(line) <= 2048:
            raise _refuse()
        try:
            row = json.loads(
                line.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant
            )
        except (ValueError, UnicodeError, RecursionError):
            raise _refuse() from None
        if (
            not isinstance(row, dict)
            or set(row) != _FIELDS
            or row["record_id"] != f"synthetic-{ordinal:03}"
            or row["synthetic"] is not True
        ):
            raise _refuse()
        template = row["template"]
        expected = {
            "telemetry-seed": f"telemetry-value-{ordinal:03}",
            "harmless-document": f"document-value-{ordinal:03}",
            "empty": "",
        }
        if not isinstance(template, str) or template not in expected:
            raise _refuse()
        if row["value"] == "synthetic-redacted":
            redacted += 1
        elif row["value"] != expected[template]:
            raise _refuse()
        elif row["value"] == "":
            empty += 1
        else:
            retained += 1
    return {
        "container": container,
        "record_count": len(lines),
        "redacted_record_count": redacted,
        "retained_record_count": retained,
        "empty_record_count": empty,
    }


def _ustar_member(payload: bytes) -> bytes:
    """Accept only the one-member deterministic USTAR format, without extraction."""

    header = payload[:512]
    raw_size = header[124:136]
    if (
        len(raw_size) != 12
        or raw_size[-1:] != b"\0"
        or any(char not in b"01234567" for char in raw_size[:-1])
    ):
        raise _refuse()
    size = int(raw_size[:-1], 8)
    padded = ((size + 511) // 512) * 512
    if not 1 <= size <= MAX_COLLECTION_BYTES or len(payload) != 512 + padded + 1024:
        raise _refuse()
    expected = bytearray(512)
    expected[: len(_MEMBER)] = _MEMBER
    for start, stop, value in (
        (100, 108, 0o644),
        (108, 116, 0),
        (116, 124, 0),
        (124, 136, size),
        (136, 148, 0),
    ):
        expected[start:stop] = f"{value:0{stop - start - 1}o}".encode("ascii") + b"\0"
    expected[148:156] = b"        "
    expected[156] = ord("0")
    expected[257:265] = b"ustar\0" + b"00"
    expected[265:273] = b"bluefire"
    expected[297:305] = b"bluefire"
    expected[148:156] = f"{sum(expected):06o}".encode("ascii") + b"\0 "
    if header != expected or any(payload[512 + size :]):
        raise _refuse()
    return payload[512 : 512 + size]
