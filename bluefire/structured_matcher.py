"""Pure selection semantics shared by lifecycle and immutable run evaluation."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Mapping


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


def _strict_json_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values while treating int/float as JSON numbers, not booleans."""
    if type(actual) is bool or type(expected) is bool:
        return type(actual) is bool and type(expected) is bool and actual is expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        # Python compares a float to an int using the float's exact binary value.
        # Compare the JSON decimal forms instead, so a parsed exponent such as
        # 1e23 equals the same exact integer without rounding either operand.
        actual_number = Decimal(actual) if type(actual) is int else Decimal(str(actual))
        expected_number = Decimal(expected) if type(expected) is int else Decimal(str(expected))
        return actual_number == expected_number
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(
            _strict_json_equal(actual[key], expected[key]) for key in actual
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _strict_json_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


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
    # JSON equality: equivalent number spellings compare equal while true remains
    # distinct from 1, including inside nested arrays and objects.
    return _strict_json_equal(actual, expected) if strict else actual == expected


def matches(selection: Mapping[str, Any], record: Mapping[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        key, _, operator = raw_key.partition("|")
        present, actual = lookup(record, key)
        if not present or not matches_value(actual, expected, operator):
            return False
    return True
