from __future__ import annotations

from datetime import timezone

import pytest

from bluefire.util import parse_iso8601_datetime


def test_bounded_rfc3339_parser_accepts_rust_fractional_precision() -> None:
    digits = "123456789"
    for length in range(1, 10):
        fraction = digits[:length]
        parsed = parse_iso8601_datetime(f"2026-09-02T19:49:03.{fraction}Z")
        assert parsed.microsecond == int((fraction + "000000")[:6])
        assert parsed.tzinfo == timezone.utc

    assert parse_iso8601_datetime("2026-09-02T19:49:03Z").tzinfo == timezone.utc
    assert parse_iso8601_datetime("2026-09-02T19:49:03+05:30").utcoffset() is not None


@pytest.mark.parametrize(
    "value",
    (
        "20260902T194903Z",
        "2026-09-02 19:49:03Z",
        "2026-09-02X19:49:03Z",
        "2026-09-02T19:49:03,123Z",
        "2026-09-02T19:49:03+0000",
        "2026-09-02T19:49:03+00:00:01",
        "2026-09-02T19:49:03+00:60",
        "2026-09-02T19:49:03+24:00",
        "2026-09-02T19:49:03",
        "2026-09-02T19:49:03.1234567890Z",
        "2026-02-30T19:49:03Z",
    ),
)
def test_bounded_rfc3339_parser_rejects_non_wire_forms(value: str) -> None:
    with pytest.raises(ValueError):
        parse_iso8601_datetime(value)
