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


def test_tac_package_surfaces_resolve() -> None:
    """Single import path per tactical subdomain (lazy where noted elsewhere)."""
    from src.core.collection import Collection
    from src.core.credential import CredentialAccess
    from src.core.execution import Execution
    from src.core.impact import Impact
    from src.core.initial_access import InitialAccess
    from src.core.intelligence import APTIntelligence
    from src.core.movement import LateralMovement
    from src.core.network import NetworkObfuscator
    from src.core.persistence import Persistence
    from src.core.privilege import PrivilegeEscalation
    from src.core.reconnaissance import ReconnaissanceManager
    from src.core.resource import ResourceDevelopmentManager

    assert Collection.__name__ == "Collection"
    assert CredentialAccess.__name__ == "CredentialAccess"
    assert Impact.__name__ == "Impact"
    assert InitialAccess.__name__ == "InitialAccess"
    assert APTIntelligence.__name__ == "APTIntelligence"
    assert LateralMovement.__name__ == "LateralMovement"
    assert NetworkObfuscator.__name__ == "NetworkObfuscator"
    assert Persistence.__name__ == "Persistence"
    assert PrivilegeEscalation.__name__ == "PrivilegeEscalation"
    assert ReconnaissanceManager.__name__ == "ReconnaissanceManager"
    assert ResourceDevelopmentManager.__name__ == "ResourceDevelopmentManager"

    Persistence(Execution())


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
