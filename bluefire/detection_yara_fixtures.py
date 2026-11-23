"""Bounded YARA fixture matching over one aggregate monotonic budget."""

from __future__ import annotations

import math
import re
from typing import Any, Callable, Mapping, Sequence

_DEADLINE_SECONDS = 2.0
_FIXTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


class YaraFixtureError(ValueError):
    """A fixture batch was invalid or could not finish within its budget."""


def match_fixtures(
    rules: Any,
    backend: Any,
    fixtures: Sequence[Mapping[str, Any]],
    *,
    max_fixture_bytes: int,
    clock: Callable[[], float],
) -> tuple[list[str], list[str]]:
    fixture_ids: list[str] = []
    matched_ids: list[str] = []
    total_bytes = 0
    deadline = clock() + _DEADLINE_SECONDS

    def timed_out() -> YaraFixtureError:
        return YaraFixtureError(
            f"YARA fixture evaluation timed out after {len(fixture_ids)} of "
            f"{len(fixtures)} fixtures; partial results were not accepted"
        )

    for fixture in fixtures:
        if not isinstance(fixture, Mapping):
            raise YaraFixtureError("each YARA fixture must be an object")
        fixture_id = fixture.get("fixture_id")
        if (
            not isinstance(fixture_id, str)
            or _FIXTURE_ID.fullmatch(fixture_id) is None
            or fixture_id in fixture_ids
        ):
            raise YaraFixtureError("YARA fixture IDs must be valid and unique")
        payload = fixture.get("data", b"")
        if isinstance(payload, str):
            data = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            data = payload
        else:
            raise YaraFixtureError("YARA fixture data must be bytes or text")
        total_bytes += len(data)
        if total_bytes > max_fixture_bytes:
            raise YaraFixtureError("YARA fixtures exceed the total byte limit")
        # YARA accepts whole seconds; never grant more than the remaining budget.
        timeout = math.floor(deadline - clock())
        if timeout < 1:
            raise timed_out()
        try:
            matches = rules.match(data=data, timeout=timeout)
        except backend.TimeoutError as exc:
            raise timed_out() from exc
        except backend.Error as exc:
            raise YaraFixtureError(
                f"YARA-Python fixture evaluation failed after {len(fixture_ids)} of "
                f"{len(fixtures)} fixtures; partial results were not accepted"
            ) from exc
        if clock() >= deadline:
            raise timed_out()
        fixture_ids.append(fixture_id)
        if matches:
            matched_ids.append(fixture_id)
    return fixture_ids, matched_ids
