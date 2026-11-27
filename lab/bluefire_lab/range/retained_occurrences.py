"""Audit where certified plaintext occurs in retained JSON evidence.

The secret scanner identifies a finding by its value, type and file, not by
its JSON location.  This module supplies the independent location check: it
strictly decodes the original JSON bytes, rejects duplicate object keys, and
requires every substring occurrence of a certified value to be at an approved
key or string-scalar location.
"""

from __future__ import annotations

import json
import stat
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

JsonForm = Literal["document", "ndjson"]
OccurrenceKind = Literal["key", "string"]
OccurrenceLocation = tuple[OccurrenceKind, str]
_AuditKey = tuple[PurePosixPath, OccurrenceKind, str, str]


class RetainedOccurrenceError(ValueError):
    """Retained JSON cannot prove the certified values' exact locations."""


class _DuplicateKey(ValueError):
    pass


class _NonFiniteNumber(ValueError):
    pass


@dataclass(frozen=True)
class CertifiedOccurrence:
    """One allowed plaintext occurrence in one retained JSON source."""

    file: PurePosixPath | str
    pointer: str
    value: str
    kind: OccurrenceKind = "string"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise _DuplicateKey
        found[key] = value
    return found


def _non_finite(_value: str) -> None:
    raise _NonFiniteNumber


def _decode(data: bytes, what: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RetainedOccurrenceError(f"{what} is not UTF-8 at byte {error.start}") from error


def _loads_object_text(text: str, what: str) -> dict[str, object]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_non_finite,
        )
    except _DuplicateKey as error:
        raise RetainedOccurrenceError(f"{what} has a duplicate JSON key") from error
    except _NonFiniteNumber as error:
        raise RetainedOccurrenceError(f"{what} contains a non-finite JSON number") from error
    except json.JSONDecodeError as error:
        raise RetainedOccurrenceError(
            f"{what} is not strict JSON at line {error.lineno} column {error.colno}"
        ) from error
    if not isinstance(value, dict):
        raise RetainedOccurrenceError(f"{what} must be a JSON object")
    return value


def loads_object(data: bytes, what: str) -> dict[str, object]:
    """Strictly decode one UTF-8 JSON object, rejecting repeated keys."""

    return _loads_object_text(_decode(data, what), what)


def loads_ndjson_objects(data: bytes, what: str) -> tuple[dict[str, object], ...]:
    """Strictly decode the nonempty object records of one UTF-8 NDJSON stream."""

    text = _decode(data, what)
    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line:
            records.append(_loads_object_text(line, f"{what} record {number}"))
    return tuple(records)


def _pointer(value: object, what: str) -> str:
    if not isinstance(value, str) or value and not value.startswith("/"):
        raise RetainedOccurrenceError(f"{what} must be an RFC 6901 JSON pointer")
    cursor = 0
    while True:
        cursor = value.find("~", cursor)
        if cursor < 0:
            return value
        if cursor + 1 >= len(value) or value[cursor + 1] not in "01":
            raise RetainedOccurrenceError(f"{what} must be an RFC 6901 JSON pointer")
        cursor += 2


def _escape_pointer(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def _child_pointer(pointer: str, part: str) -> str:
    return f"{pointer}/{_escape_pointer(part)}"


def _substring_count(text: str, needle: str) -> int:
    count = 0
    start = 0
    while True:
        found = text.find(needle, start)
        if found < 0:
            return count
        count += 1
        start = found + 1


def _occurrence_locations(
    value: object,
    needle: str,
    pointer: str,
) -> tuple[Counter[OccurrenceLocation], Counter[OccurrenceLocation]]:
    if not isinstance(needle, str) or not needle:
        raise RetainedOccurrenceError("the certified value must be a non-empty string")
    checked_pointer = _pointer(pointer, "the starting pointer")
    found: Counter[OccurrenceLocation] = Counter()
    exact: Counter[OccurrenceLocation] = Counter()

    def visit(current: object, current_pointer: str) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                child_pointer = _child_pointer(current_pointer, key)
                count = _substring_count(key, needle)
                if count:
                    found[("key", child_pointer)] += count
                if key == needle:
                    exact[("key", child_pointer)] += 1
                visit(child, child_pointer)
            return
        if isinstance(current, list):
            for index, child in enumerate(current):
                visit(child, _child_pointer(current_pointer, str(index)))
            return
        if isinstance(current, str):
            count = _substring_count(current, needle)
            if count:
                found[("string", current_pointer)] += count
            if current == needle:
                exact[("string", current_pointer)] += 1

    visit(value, checked_pointer)
    return found, exact


def occurrence_locations(
    value: object,
    needle: str,
    *,
    pointer: str = "",
) -> Counter[OccurrenceLocation]:
    """Count all overlapping ``needle`` occurrences in keys and string scalars."""

    found, _ = _occurrence_locations(value, needle, pointer)
    return found


def _relative(value: object, what: str) -> PurePosixPath:
    if isinstance(value, PurePosixPath):
        text = value.as_posix()
    elif isinstance(value, str):
        text = value
    else:
        raise RetainedOccurrenceError(f"{what} must be a normalized relative POSIX path")
    path = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or path.is_absolute()
        or path.as_posix() != text
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise RetainedOccurrenceError(f"{what} must be a normalized relative POSIX path")
    return path


def _read_source(root: Path, relative: PurePosixPath) -> bytes:
    path = root.joinpath(*relative.parts)
    try:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_nlink != 1:
            raise RetainedOccurrenceError(
                f"the retained JSON source {relative} must be a single-link regular file"
            )
        return path.read_bytes()
    except RetainedOccurrenceError:
        raise
    except OSError as error:
        raise RetainedOccurrenceError(f"the retained JSON source {relative} cannot be read") from error


def _mismatch_message(
    missing: Counter[_AuditKey],
    unexpected: Counter[_AuditKey],
) -> str:
    parts = []
    if missing:
        by_kind = Counter({kind: 0 for kind in ("key", "string")})
        for (_, kind, _, _), count in missing.items():
            by_kind[kind] += count
        details = ", ".join(f"{count} {kind}" for kind, count in by_kind.items() if count)
        parts.append(f"missing {sum(missing.values())} approved occurrence(s) ({details})")
    if unexpected:
        by_kind = Counter({kind: 0 for kind in ("key", "string")})
        for (_, kind, _, _), count in unexpected.items():
            by_kind[kind] += count
        details = ", ".join(f"{count} {kind}" for kind, count in by_kind.items() if count)
        parts.append(
            f"found {sum(unexpected.values())} occurrence(s) outside the approved locations ({details})"
        )
    return "certified JSON occurrence audit failed: " + "; ".join(parts)


def audit_json_occurrences(
    root: Path,
    *,
    sources: Mapping[PurePosixPath | str, JsonForm],
    certified: Iterable[CertifiedOccurrence],
) -> None:
    """Require the certified occurrence multiset across the exact JSON sources."""

    checked_sources: dict[PurePosixPath, JsonForm] = {}
    for number, (file, form) in enumerate(sources.items(), start=1):
        relative = _relative(file, f"JSON source {number}")
        if relative in checked_sources:
            raise RetainedOccurrenceError("the JSON source list repeats one file")
        if form not in ("document", "ndjson"):
            raise RetainedOccurrenceError(f"JSON source {number} has an unknown form")
        checked_sources[relative] = form

    expected: Counter[_AuditKey] = Counter()
    values: set[str] = set()
    for number, approved in enumerate(certified, start=1):
        if not isinstance(approved, CertifiedOccurrence):
            raise RetainedOccurrenceError(f"certified occurrence {number} has an invalid shape")
        relative = _relative(approved.file, f"certified occurrence {number}'s file")
        if relative not in checked_sources:
            raise RetainedOccurrenceError(f"certified occurrence {number} names an unaudited file")
        pointer = _pointer(approved.pointer, f"certified occurrence {number}'s pointer")
        if approved.kind not in ("key", "string"):
            raise RetainedOccurrenceError(f"certified occurrence {number} has an unknown kind")
        if not isinstance(approved.value, str) or not approved.value:
            raise RetainedOccurrenceError(f"certified occurrence {number}'s value must be a non-empty string")
        expected[(relative, approved.kind, pointer, approved.value)] += 1
        values.add(approved.value)

    decoded: dict[PurePosixPath, dict[str, object] | tuple[dict[str, object], ...]] = {}
    for relative, form in checked_sources.items():
        data = _read_source(root, relative)
        what = f"retained JSON source {relative}"
        if form == "document":
            decoded[relative] = loads_object(data, what)
        else:
            decoded[relative] = loads_ndjson_objects(data, what)

    actual: Counter[_AuditKey] = Counter()
    exact_actual: Counter[_AuditKey] = Counter()
    for relative, form in checked_sources.items():
        content = decoded[relative]
        for needle in values:
            locations: Counter[OccurrenceLocation] = Counter()
            exact_locations: Counter[OccurrenceLocation] = Counter()
            if form == "document":
                found, exact = _occurrence_locations(content, needle, "")
                locations.update(found)
                exact_locations.update(exact)
            else:
                for index, record in enumerate(content):
                    found, exact = _occurrence_locations(record, needle, f"/{index}")
                    locations.update(found)
                    exact_locations.update(exact)
            for (kind, pointer), count in locations.items():
                actual[(relative, kind, pointer, needle)] += count
            for (kind, pointer), count in exact_locations.items():
                exact_actual[(relative, kind, pointer, needle)] += count

    # An approved location certifies the complete key or string scalar.  The
    # substring count remains broader so a copy embedded in any longer text is
    # still an occurrence outside the exact allowlist.
    missing = expected - exact_actual
    unexpected = actual - expected
    if missing or unexpected:
        raise RetainedOccurrenceError(_mismatch_message(missing, unexpected))
