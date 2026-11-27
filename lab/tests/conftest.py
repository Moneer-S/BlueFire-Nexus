"""Options of the lab's tests, and what several of them share."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

# A rule set made up for the tests, laid out as a repository's folders, and the commit the tests give it.
RULE_SET = Path(__file__).parent / "fixtures" / "range" / "rule-set"
RULE_SET_COMMIT = "b" * 40


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


@pytest.fixture
def served() -> Callable[..., Callable[[str], bytes]]:
    """A fetch that answers from a folder as GitHub answers for the repository example/rules at
    RULE_SET_COMMIT: a folder's listing through the contents API, a file's bytes from the raw address.
    By default the folder is the tests' made-up rule set. Nothing is fetched from a network."""

    def make(folder: Path = RULE_SET, asked: list[str] | None = None) -> Callable[[str], bytes]:
        def get(url: str) -> bytes:
            if asked is not None:
                asked.append(url)
            api = "https://api.github.com/repos/example/rules/contents/"
            if url.startswith(api):
                assert url.endswith(f"?ref={RULE_SET_COMMIT}")
                inside = folder / url.removeprefix(api).removesuffix(f"?ref={RULE_SET_COMMIT}")
                return json.dumps(
                    [
                        {
                            "type": "dir" if entry.is_dir() else "file",
                            "path": entry.relative_to(folder).as_posix(),
                        }
                        for entry in sorted(inside.iterdir())
                    ]
                ).encode()
            assert url.startswith(f"https://raw.githubusercontent.com/example/rules/{RULE_SET_COMMIT}/")
            return (folder / url.split(f"/{RULE_SET_COMMIT}/", 1)[1]).read_bytes()

        return get

    return make
