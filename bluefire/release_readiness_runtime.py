"""Ephemeral runtime helpers for release-readiness suites."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

from .runtime_paths import runtime_temp_parent as temp_parent
from .runtime_paths import trusted_git_environment, trusted_git_executable


def decode_tracked(payload: bytes) -> list[str]:
    """Decode tracked paths while excluding the baseline used as scanner input."""

    try:
        return [
            item.decode("utf-8", "strict")
            for item in payload.split(b"\0")
            if item and item != b".secrets.baseline"
        ]
    except UnicodeError:
        return []


def initialize_scan_repository(root: Path, environment: Mapping[str, str]) -> bool:
    """Create an isolated Git index for the archived baseline hook."""

    try:
        executable = os.fspath(trusted_git_executable())
        git_environment = trusted_git_environment(environment)
    except OSError:
        return False
    for arguments in (("init", "--quiet"), ("add", "--", ".secrets.baseline")):
        try:
            completed = subprocess.run(
                [executable, *arguments],
                cwd=root,
                env=git_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if completed.returncode != 0:
            return False
    return True


__all__ = ["decode_tracked", "initialize_scan_repository", "temp_parent"]
