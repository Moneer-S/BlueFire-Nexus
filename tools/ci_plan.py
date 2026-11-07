"""Choose which CI matrices run for one workflow event.

Every run covers Linux, macOS and Windows: agents cannot validate macOS or
Windows on their own machines, so CI is their only check there. A draft pull
request runs Python 3.10 on Linux only and Python 3.12 on every platform, which
keeps the macOS jobs within GitHub's concurrent macOS limit while a branch is
iterating. A pull request that is ready for review, every push to main and a
manual run use both Python versions on every platform.

Run in the workflow as ``python tools/ci_plan.py``; it reads GITHUB_EVENT_NAME
and BLUEFIRE_CI_DRAFT and appends ``key=json`` lines to GITHUB_OUTPUT.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

PYTHON_VERSIONS = ("3.10", "3.12")
WINDOWS_PARTITIONS = ("a-b", "c-d", "e-q", "r", "remainder")

PACKAGES: tuple[dict[str, str], ...] = (
    {
        "os": "ubuntu-latest",
        "platform": "linux",
        "architecture": "x86_64",
        "runner-path": "runner/target/x86_64-unknown-linux-musl/release/bluefire-runner",
        "wheel-platform-tag": "linux_x86_64",
        "venv-python": "bin/python",
    },
    {
        "os": "windows-latest",
        "platform": "windows",
        "architecture": "x86_64",
        "runner-path": "runner/target/release/bluefire-runner.exe",
        "wheel-platform-tag": "win_amd64",
        "venv-python": "Scripts/python.exe",
    },
    {
        "os": "macos-15-intel",
        "platform": "macos",
        "architecture": "x86_64",
        "runner-path": "runner/target/release/bluefire-runner",
        "wheel-platform-tag": "macosx_11_0_x86_64",
        "venv-python": "bin/python",
    },
    {
        "os": "macos-26",
        "platform": "macos",
        "architecture": "aarch64",
        "runner-path": "runner/target/release/bluefire-runner",
        "wheel-platform-tag": "macosx_11_0_arm64",
        "venv-python": "bin/python",
    },
)


def plan(event_name: str, draft: str) -> dict[str, Any]:
    """Return the matrices for this event; a draft runs Python 3.10 on Linux only."""

    full = not (event_name == "pull_request" and draft.strip().lower() == "true")
    platform_versions = PYTHON_VERSIONS if full else ("3.12",)
    # Linux always runs both versions through python_os x python-version; the
    # include entries add macOS (draft only) and the Windows partitions.
    macos = [] if full else [{"os": "macos-latest", "python-version": "3.12"}]
    windows = [
        {"os": "windows-latest", "python-version": version, "partition": partition}
        for version in platform_versions
        for partition in WINDOWS_PARTITIONS
    ]
    return {
        "full": full,
        "python_os": ["ubuntu-latest", "macos-latest"] if full else ["ubuntu-latest"],
        "python_include": macos + windows,
        "packages": list(PACKAGES),
    }


def main(environ: Mapping[str, str] = os.environ) -> int:
    scope = plan(environ.get("GITHUB_EVENT_NAME", ""), environ.get("BLUEFIRE_CI_DRAFT", ""))
    lines = [f"{key}={json.dumps(value, separators=(',', ':'))}" for key, value in scope.items()]
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
