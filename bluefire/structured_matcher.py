"""Pure selection semantics shared by lifecycle and immutable run evaluation."""

from __future__ import annotations

from typing import Any, Mapping

from .util import canonical_json_bytes


def invalid_selection_field(selection: Mapping[str, Any]) -> str | None:
    for field in selection:
        if not isinstance(field, str):
            return f"invalid selection field: {field!r}"
        key, separator, operator = field.partition("|")
        if (
            not key
            or " " in field
            or any(not part for part in key.split("."))
            or (separator and operator not in {"contains", "startswith", "endswith"})
        ):
            return f"invalid selection field: {field!r}"
    return None


def lookup(record: Mapping[str, Any], key: str) -> tuple[bool, Any]:
    actual: Any = record
    for part in key.split("."):
        if not isinstance(actual, Mapping) or part not in actual:
            return False, None
        actual = actual[part]
    return True, actual


def matches_value(actual: Any, expected: Any, operator: str, *, strict: bool = False) -> bool:
    if operator == "contains":
        return str(expected).casefold() in str(actual).casefold()
    if operator == "startswith":
        return str(actual).casefold().startswith(str(expected).casefold())
    if operator == "endswith":
        return str(actual).casefold().endswith(str(expected).casefold())
    if operator:
        return False
    # Keep historical lifecycle matching readable. Immutable run evaluations use
    # JSON type-sensitive equality, so true never matches 1 or "true".
    return (
        canonical_json_bytes(actual) == canonical_json_bytes(expected)
        if strict
        else actual == expected
    )


def matches(selection: Mapping[str, Any], record: Mapping[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        key, _, operator = raw_key.partition("|")
        present, actual = lookup(record, key)
        if not present or not matches_value(actual, expected, operator):
            return False
    return True
