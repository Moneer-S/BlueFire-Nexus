"""Shared pytest configuration for the platform suite.

Many tests wait for a real background job with a short wall-clock guard, for
example ``service.job_controller.wait(job_id, timeout=3)``. The guard exists so
a hung job fails instead of blocking the suite; it is not a performance
requirement. Hosted CI runners, Windows and macOS in particular, can be several
times slower than a developer machine, and those guards then report slow
hardware as a product failure.

``BLUEFIRE_TEST_WAIT_SCALE`` stretches every such guard by one factor instead of
editing hundreds of call sites one timeout at a time. It defaults to 1 (no
change). Only test code calls ``RunJobController.wait_for_state``; product code
never does, and no assertion changes. A job that never settles still fails.
"""

from __future__ import annotations

import functools
import math
import os
from collections.abc import Iterable, Mapping
from typing import Any

import pytest

from bluefire.job_runtime import JobState, RunJobController

WAIT_SCALE_ENV = "BLUEFIRE_TEST_WAIT_SCALE"
MAX_WAIT_SCALE = 10.0


def wait_scale(environ: Mapping[str, str] = os.environ) -> float:
    """Return the configured guard multiplier, refusing unusable values."""

    raw = environ.get(WAIT_SCALE_ENV, "").strip()
    if not raw:
        return 1.0
    try:
        value = float(raw)
    except ValueError:
        raise pytest.UsageError(f"{WAIT_SCALE_ENV} must be a number, got {raw!r}") from None
    if not math.isfinite(value) or not 1.0 <= value <= MAX_WAIT_SCALE:
        raise pytest.UsageError(f"{WAIT_SCALE_ENV} must be between 1 and {MAX_WAIT_SCALE:g}")
    return value


def scaled_wait_for_state(original: Any, scale: float) -> Any:
    """Wrap ``RunJobController.wait_for_state`` so positive guards are stretched."""

    @functools.wraps(original)
    def wait_for_state(
        self: RunJobController,
        job_id: str,
        states: Iterable[JobState | str],
        *,
        timeout: float | None = None,
    ) -> Mapping[str, Any]:
        if timeout is not None and timeout > 0:
            timeout *= scale
        return original(self, job_id, states, timeout=timeout)

    wait_for_state.__bluefire_wait_scale__ = scale  # type: ignore[attr-defined]
    return wait_for_state


def pytest_configure(config: pytest.Config) -> None:
    scale = wait_scale()
    if scale != 1.0 and not hasattr(RunJobController.wait_for_state, "__bluefire_wait_scale__"):
        RunJobController.wait_for_state = scaled_wait_for_state(  # type: ignore[method-assign]
            RunJobController.wait_for_state, scale
        )


def pytest_report_header(config: pytest.Config) -> str:
    return f"{WAIT_SCALE_ENV}={wait_scale():g}"
