"""Tests for ExecutionModule platform-aware logsource (roadmap item 4)."""

from __future__ import annotations

import platform as platform_module
from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.modules.impl.standard_modules import (
    ExecutionModule,
    _resolve_target_os,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "execution-logsource-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


@pytest.mark.parametrize(
    "explicit,expected_product",
    [
        ("windows", "windows"),
        ("Windows", "windows"),
        ("WINDOWS", "windows"),
        ("linux", "linux"),
        ("macos", "macos"),
        ("darwin", "macos"),
    ],
)
def test_explicit_target_os_drives_logsource_product(
    explicit: str, expected_product: str, tmp_path: Path
) -> None:
    """`target_os` param shapes detection-hint logsource per OS."""
    mod = ExecutionModule()
    result = mod.execute(
        {"command": "echo test", "target_os": explicit}, _ctx(tmp_path)
    )
    assert result.detection_hints["logsource"]["product"] == expected_product
    assert result.detection_hints["logsource"]["category"] == "process_creation"
    assert result.detection_hints["target_os"] == expected_product
    assert result.artifacts["target_os"] == expected_product
    assert result.telemetry[0].details["target_os"] == expected_product


def test_no_target_os_falls_back_to_host_platform(tmp_path: Path) -> None:
    """Without target_os, the host OS drives logsource."""
    mod = ExecutionModule()
    result = mod.execute({"command": "echo host"}, _ctx(tmp_path))
    host = platform_module.system().lower()
    expected = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(
        host, "linux"
    )
    assert result.detection_hints["logsource"]["product"] == expected


def test_unknown_target_os_falls_back_to_host_platform(tmp_path: Path) -> None:
    """An unrecognized target_os falls through to host platform (then linux as final fallback)."""
    mod = ExecutionModule()
    result = mod.execute(
        {"command": "echo test", "target_os": "freebsd"}, _ctx(tmp_path)
    )
    host = platform_module.system().lower()
    expected = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(
        host, "linux"
    )
    assert _resolve_target_os({"target_os": "freebsd"}) == expected
    assert result.detection_hints["logsource"]["product"] == expected


def test_logsource_title_includes_target_os(tmp_path: Path) -> None:
    """Detection-hint title surfaces the resolved OS so reviewers see at a glance."""
    mod = ExecutionModule()
    for os_name in ("windows", "linux", "macos"):
        result = mod.execute(
            {"command": "echo title", "target_os": os_name}, _ctx(tmp_path)
        )
        assert os_name in result.detection_hints["title"]


def test_resolve_target_os_helper_directly() -> None:
    """`_resolve_target_os` honours explicit value, then platform.system()."""
    assert _resolve_target_os({"target_os": "windows"}) == "windows"
    assert _resolve_target_os({"target_os": "Linux"}) == "linux"
    assert _resolve_target_os({"target_os": "Darwin"}) == "macos"
    # No target_os -> host fallback
    host = platform_module.system().lower()
    expected = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(
        host, "linux"
    )
    assert _resolve_target_os({}) == expected
