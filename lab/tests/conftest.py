"""Options of the lab's tests."""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--engine",
        type=Path,
        help="the Zircolite program, for the tests that evaluate the lab's own rules with it",
    )


@pytest.fixture
def engine(request: pytest.FixtureRequest) -> Path:
    """The rule engine the lab runs, or a skip when none was given: the package job gives it."""

    given = request.config.getoption("--engine")
    if given is None:
        pytest.skip("needs the rule engine: pass --engine <path to Zircolite 4.7.1>")
    return given
