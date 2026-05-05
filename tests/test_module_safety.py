"""Strict dry-run safety enforcement.

In ``dry_run=True`` with the lab off, no module is allowed to invoke real
side-effect primitives. The test installs sentinel monkeypatches over every
common subprocess / socket / HTTP entry point and asserts none of them fire
for any module in the registry.

If a module needs to touch one of these primitives to build telemetry, it
must instead synthesise the telemetry directly (the standard modules already
do this — ``ExecutionModule`` builds the event without calling subprocess
in dry-run, etc.).

Also exercises the lab-simulate path with the same sentinels: simulate mode
is local-only by definition, so it must not reach for the network/process
primitives either. Real execution paths require ``dry_run=False`` AND
``allow_real_execution=True`` AND, for the legacy packs, ``emulate`` mode +
lab confirmation. None of those conditions are set here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from src.core.modules.registry import build_runtime_modules
from tests.test_module_contract import (
    _lab_off_config,
    _lab_simulate_config,
    _make_context,
    _params_for,
)


# ---------------------------------------------------------------------------
# Sentinel monkeypatches
# ---------------------------------------------------------------------------


class SafetyViolation(AssertionError):
    """Raised when a module touches a real-world side-effect primitive."""


def _block(name: str, calls: List[str]) -> Callable[..., Any]:
    def _violator(*args: Any, **kwargs: Any) -> Any:
        msg = f"{name} called with args={args!r} kwargs={kwargs!r}"
        calls.append(msg)
        raise SafetyViolation(
            f"Dry-run safety violation: {name} invoked. "
            "Modules must synthesise telemetry/artifacts in dry-run instead "
            "of calling real primitives."
        )

    return _violator


# Pre-import everything we plan to patch (and its transitive imports) so that
# the patches we install later cannot break SSL/socket class hierarchies.
import os  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402,F401
import subprocess  # noqa: E402
import urllib.request  # noqa: E402

try:
    import requests  # noqa: E402
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    import aiohttp  # noqa: E402
except ImportError:
    aiohttp = None  # type: ignore[assignment]


@pytest.fixture
def block_side_effects(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """Install sentinels over every primitive that would cause real side effects."""
    calls: List[str] = []

    for attr in (
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    ):
        if hasattr(subprocess, attr):
            monkeypatch.setattr(subprocess, attr, _block(f"subprocess.{attr}", calls))

    monkeypatch.setattr(os, "system", _block("os.system", calls))
    monkeypatch.setattr(os, "popen", _block("os.popen", calls))

    monkeypatch.setattr(socket, "socket", _block("socket.socket", calls))
    monkeypatch.setattr(socket, "create_connection", _block("socket.create_connection", calls))

    if requests is not None:
        for attr in ("get", "post", "put", "delete", "patch", "head", "options", "request"):
            if hasattr(requests, attr):
                monkeypatch.setattr(requests, attr, _block(f"requests.{attr}", calls))
        monkeypatch.setattr(requests, "Session", _block("requests.Session", calls))

    monkeypatch.setattr(urllib.request, "urlopen", _block("urllib.request.urlopen", calls))

    if aiohttp is not None:
        monkeypatch.setattr(aiohttp, "ClientSession", _block("aiohttp.ClientSession", calls))

    return calls


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _all_module_names() -> list[str]:
    return sorted(build_runtime_modules().keys())


@pytest.fixture(scope="module")
def runtime_modules() -> Dict[str, Any]:
    return build_runtime_modules()


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_makes_no_side_effects_in_dry_run_lab_off(
    module_name: str,
    runtime_modules: Dict[str, Any],
    tmp_path: Path,
    block_side_effects: List[str],
) -> None:
    """With dry_run=True and lab off, no real subprocess/socket/HTTP calls."""
    cfg = _lab_off_config()
    module = runtime_modules[module_name]
    module_cfg = dict(cfg["modules"].get(module_name, {}))
    module_cfg["config_root"] = cfg
    if module_name.startswith("legacy_"):
        module_cfg["enabled"] = False
        module_cfg["mode"] = "simulate"
        module_cfg["lab_confirmation"] = False
    module.update_config(module_cfg)
    context = _make_context(tmp_path, cfg)

    try:
        module.execute(_params_for(module_name), context)
    except RuntimeError:
        # Acceptable: legacy adapter rejected because pack disabled.
        pass
    except SafetyViolation:
        raise
    assert block_side_effects == [], (
        f"{module_name} triggered side-effect primitives in dry-run/lab-off:\n  "
        + "\n  ".join(block_side_effects)
    )


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_makes_no_side_effects_in_dry_run_lab_simulate(
    module_name: str,
    runtime_modules: Dict[str, Any],
    tmp_path: Path,
    block_side_effects: List[str],
) -> None:
    """Even with all legacy packs enabled in simulate mode, no real side effects.

    Simulate mode synthesises telemetry/artifacts locally; it must not touch
    real network/process primitives.
    """
    cfg = _lab_simulate_config()
    module = runtime_modules[module_name]
    module_cfg = dict(cfg["modules"].get(module_name, {}))
    module_cfg["config_root"] = cfg
    if module_name.startswith("legacy_"):
        module_cfg["enabled"] = True
        module_cfg["mode"] = "simulate"
        module_cfg["lab_confirmation"] = True
    module.update_config(module_cfg)
    context = _make_context(tmp_path, cfg)

    try:
        module.execute(_params_for(module_name), context)
    except SafetyViolation:
        raise
    except RuntimeError:
        # Some legacy adapters can still reject under simulate if their wiring
        # disagrees with the test config — that is a contract concern (already
        # covered by test_module_contract), not a safety violation.
        pass
    assert block_side_effects == [], (
        f"{module_name} triggered side-effect primitives in dry-run/lab-simulate:\n  "
        + "\n  ".join(block_side_effects)
    )
