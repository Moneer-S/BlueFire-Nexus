"""OS-backed defense-evasion tactics (delegates to platform handlers)."""

from __future__ import annotations

from typing import Any

from .defense_evasion import DefenseEvasion
from .linux_defense_evasion import LinuxDefenseEvasion
from .macos_defense_evasion import MacOSDefenseEvasion

__all__ = [
    "DefenseEvasion",
    "LinuxDefenseEvasion",
    "MacOSDefenseEvasion",
    "WindowsDefenseEvasion",
]


def __getattr__(name: str) -> Any:
    if name == "WindowsDefenseEvasion":
        from .windows_defense_evasion import WindowsDefenseEvasion

        return WindowsDefenseEvasion
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
