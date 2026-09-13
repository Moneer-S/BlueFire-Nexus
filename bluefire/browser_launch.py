"""Single-purpose, quiet handoff of an authenticated local console to the desktop."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from typing import Callable
from urllib.parse import urlsplit


def _console_url(value: str) -> bool:
    if len(value) > 256 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        loopback = host == "localhost" or (
            host is not None and ipaddress.ip_address(host).is_loopback
        )
        return bool(
            loopback
            and parsed.scheme == "http"
            and parsed.port is not None
            and 1 <= parsed.port <= 65535
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/"
            and not parsed.query
            and re.fullmatch(r"bluefire-session=[A-Za-z0-9_-]{64}", parsed.fragment)
        )
    except ValueError:
        return False


def _desktop_error(error: OSError) -> str:
    """Keep useful OS codes without copying exception text or local paths."""
    windows = sys.platform == "win32"
    code = getattr(error, "winerror", None) if windows else error.errno
    if type(code) is not int or not -(2**31) <= code < 2**32:
        return "The operating system could not open the browser."
    if windows:
        if code == 1155:
            return "No browser is associated with HTTP links. Choose a default browser in Windows Settings (error 1155)."
        if code in {2, 3}:
            return f"Windows reported a missing file or path (error {code}). Check the default browser in Windows Settings."
        if code == 5:
            return "Windows denied the browser request (error 5)."
        return f"Windows could not open the browser (error {code})."
    return f"The desktop opener could not start (OS error {code})."


def open_console_url(url: str, *, on_failure: Callable[[str], None] | None = None) -> bool:
    """Request one desktop handoff; success does not attest that a page loaded."""

    def failed(reason: str) -> bool:
        if on_failure is not None:
            on_failure(reason)
        return False

    if not _console_url(url):
        return failed("The console address could not be validated.")
    if sys.platform == "win32":
        try:
            os.startfile(url)
        except OSError as error:
            return failed(_desktop_error(error))
        return True
    executable = {"darwin": "/usr/bin/open", "linux": "/usr/bin/xdg-open"}.get(sys.platform)
    if executable is None:
        return failed("Automatic browser opening is unavailable on this platform.")
    # Pass desktop routing only, not provider credentials, Python configuration,
    # arbitrary BROWSER commands, or control-plane descriptors to the opener.
    environment = {"PATH": os.defpath}
    for name in (
        "HOME",
        "USER",
        "LOGNAME",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_DATA_DIRS",
        "LANG",
        "LC_ALL",
    ):
        if name in os.environ:
            environment[name] = os.environ[name]
    try:
        process = subprocess.Popen(
            [executable, url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            shell=False,
            start_new_session=True,
            env=environment,
        )
        returncode = process.wait(timeout=3)
        if returncode == 0:
            return True
        return failed(f"The desktop opener exited with status {returncode}.")
    except subprocess.TimeoutExpired:
        # Some desktop launchers stay attached to the browser. Do not kill a
        # user's browser or block the product service waiting for it to exit.
        return True
    except OSError as error:
        return failed(_desktop_error(error))
