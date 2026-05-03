"""Sanity checks for execution layer wiring (imports, subprocess error chaining)."""

from __future__ import annotations

import logging

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
    from src.core.access import InitialAccessManager
    from src.core.actors import APT29, BaseAPT
    from src.core.collection import Collection
    from src.core.credential import CredentialAccess
    from src.core.defense import AntiDetectionManager
    from src.core.defense_evasion import DefenseEvasion, LinuxDefenseEvasion
    from src.core.evasion import AntiDetection, DefenseEvasionManager
    from src.core.execution import Execution
    from src.core.exfiltration import DataExfiltration, Exfiltration
    from src.core.impact import Impact
    from src.core.initial_access import InitialAccess
    from src.core.intelligence import APTIntelligence
    from src.core.movement import LateralMovement
    from src.core.network import NetworkObfuscator
    from src.core.persistence import Persistence
    from src.core.privilege import PrivilegeEscalation
    from src.core.reconnaissance import ReconnaissanceManager
    from src.core.reporting import APTReporting
    from src.core.resource import ResourceDevelopmentManager
    from src.core.utils import Logger, get_structured_logger

    assert InitialAccessManager.__name__ == "InitialAccessManager"
    assert BaseAPT.__name__ == "BaseAPT"
    assert APT29.__name__ == "APT29"
    assert APTReporting.__name__ == "APTReporting"
    assert Logger.__name__ == "Logger"
    assert callable(get_structured_logger)
    from src.core.logger import get_logger as std_get_logger

    assert isinstance(std_get_logger("bf.coherence.probe"), logging.Logger)
    assert isinstance(get_structured_logger("bf.struct.probe"), Logger)

    assert AntiDetectionManager.__name__ == "AntiDetectionManager"
    assert DefenseEvasion.__name__ == "DefenseEvasion"
    assert LinuxDefenseEvasion.__name__ == "LinuxDefenseEvasion"
    assert AntiDetection.__name__ == "AntiDetection"
    assert DefenseEvasionManager.__name__ == "DefenseEvasionManager"

    assert Collection.__name__ == "Collection"
    assert CredentialAccess.__name__ == "CredentialAccess"
    assert DataExfiltration.__name__ == "DataExfiltration"
    assert Exfiltration.__name__ == "Exfiltration"
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

    from src.core import anti_detection as ad

    assert ad.AntiDetectionManager.__name__ == "AntiDetectionManager"


def test_anti_forensic_imports_without_psutil_when_absent() -> None:
    """anti_forensic module must import even if psutil is unavailable."""
    try:
        import psutil as _ps  # noqa: F401

        pytest.skip("psutil present; no-psutil skip path not exercised here")
    except ImportError:
        pass

    import importlib

    import src.core.anti_forensic as af

    assert af.AntiForensicManager.__name__ == "AntiForensicManager"
    importlib.reload(af)
    mgr = af.AntiForensicManager()
    mgr.detect_sandbox()


def test_anti_forensic_psutil_checks_when_available() -> None:
    pytest.importorskip("psutil")
    from src.core import anti_forensic as af

    assert isinstance(af.AntiForensicManager().detect_sandbox(), bool)


def test_anti_detection_package_imports_without_psutil() -> None:
    try:
        import psutil as _unused_ps  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("psutil installed; exercising no-psutil import path separately")

    from importlib import reload

    import src.core.anti_detection as ad

    reload(ad)

    mgr_cls = ad.AntiDetectionManager
    assert mgr_cls.__name__ == "AntiDetectionManager"


def test_threat_actor_imports_resolve_with_psutil() -> None:
    from src.core import threat_actor as ta

    assert hasattr(ta, "ThreatActor")
