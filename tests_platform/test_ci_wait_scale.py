from __future__ import annotations

import pytest

from bluefire.job_runtime import RunJobController
from tests_platform.conftest import WAIT_SCALE_ENV, scaled_wait_for_state, wait_scale


def test_wait_scale_defaults_to_one_and_accepts_bounded_factors() -> None:
    assert wait_scale({}) == 1.0
    assert wait_scale({WAIT_SCALE_ENV: " "}) == 1.0
    assert wait_scale({WAIT_SCALE_ENV: "4"}) == 4.0
    assert wait_scale({WAIT_SCALE_ENV: "1.5"}) == 1.5


@pytest.mark.parametrize("raw", ["fast", "0.5", "0", "-2", "11", "inf", "nan"])
def test_wait_scale_refuses_values_that_could_hide_or_shorten_waits(raw: str) -> None:
    with pytest.raises(pytest.UsageError):
        wait_scale({WAIT_SCALE_ENV: raw})


def test_scaled_wait_stretches_only_positive_guards() -> None:
    seen: list[float | None] = []

    def original(self: object, job_id: str, states: object, *, timeout: float | None = None):
        seen.append(timeout)
        return {"job_id": job_id}

    wrapped = scaled_wait_for_state(original, 4.0)
    assert wrapped(object(), "job-1", {"completed"}, timeout=3) == {"job_id": "job-1"}
    wrapped(object(), "job-1", {"completed"}, timeout=None)
    wrapped(object(), "job-1", {"completed"}, timeout=0)
    assert seen == [12.0, None, 0]


def test_configured_controller_matches_the_session_scale() -> None:
    marker = getattr(RunJobController.wait_for_state, "__bluefire_wait_scale__", 1.0)
    assert marker == wait_scale()
