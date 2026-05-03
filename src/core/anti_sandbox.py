import ctypes
import platform
from typing import Any, Optional


def _get_psutil() -> Optional[Any]:
    """Lazy psutil so legacy runtime can load this module in minimal environments."""
    try:
        import psutil as _ps

        return _ps
    except ImportError:
        return None


class EnvironmentValidator:
    @staticmethod
    def is_debugging() -> bool:
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except (AttributeError, OSError):  # Non-Windows or missing API
            return False

    @staticmethod
    def check_memory() -> bool:
        psutil = _get_psutil()
        if psutil is None:
            # Cannot measure; avoid false "low RAM" when dependency is absent
            return True
        return psutil.virtual_memory().total >= 4 * 1024**3  # 4GB RAM check

    @staticmethod
    def detect_sandbox() -> bool:
        blacklist = {
            'hostname': ['SANDBOX', 'VIRUS'],
            'mac': ['00:1C:42', '00:0C:29'],
            'processes': ['vmtoolsd.exe', 'procmon.exe']
        }

        # Hostname check
        if platform.node().upper() in blacklist['hostname']:
            return True

        psutil = _get_psutil()
        if psutil is None:
            return False

        # MAC check
        for _nic, addrs in psutil.net_if_addrs().items():
            if any(a.address[:8] in blacklist['mac'] for a in addrs):
                return True

        # Process check
        return any(
            p.name().lower() in blacklist['processes']
            for p in psutil.process_iter(['name'])
        )
