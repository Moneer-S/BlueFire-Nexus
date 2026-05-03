"""Sanity checks for execution layer wiring (imports, subprocess error chaining)."""

from __future__ import annotations

import pytest

from src.core.execution import Execution


def test_execution_dispatcher_selects_handler_for_detected_platform() -> None:
    ex = Execution()
    assert ex.os_type in {"Windows", "Linux", "Darwin"}
    assert ex.os_handler is not None


def test_os_handlers_have_no_broken_self_logger_attribute() -> None:
    """Guards regression: `_run_command` must use module `logger`, not `self.logger`."""
    from src.core.execution.linux_execution import LinuxExecution
    from src.core.execution.macos_execution import MacOSExecution
    from src.core.execution.windows_execution import WindowsExecution

    for cls in (LinuxExecution, WindowsExecution, MacOSExecution):
        inst = cls()
        assert getattr(inst, "logger", None) is None


def test_command_control_package_exports_class() -> None:
    """Public package entrypoint (no transitive psutil dependency)."""
    from src.core.command_control import CommandControl

    assert CommandControl.__name__ == "CommandControl"


def test_discovery_package_exports_class_when_deps_available() -> None:
    """Discovery pulls psutil; skip in minimal CI envs."""
    pytest.importorskip("psutil")
    from src.core.discovery import Discovery

    assert Discovery.__name__ == "Discovery"


def test_relative_imports_inside_core_resolve() -> None:
    """Package-local imports (`from .logger`) must resolve when core is imported as a package."""
    from src.core import rate_limiter as rl
    from src.core import security as sec

    assert rl.RateLimiter is not None
    assert hasattr(sec, "SecurityManager")

    pytest.importorskip("psutil")
    from src.core import anti_detection as ad

    assert hasattr(ad, "AntiDetectionManager")


def test_threat_actor_imports_resolve_with_psutil() -> None:
    pytest.importorskip("psutil")
    from src.core import threat_actor as ta

    assert hasattr(ta, "ThreatActor")
