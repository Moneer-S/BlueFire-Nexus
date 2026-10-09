"""Read-only Linux credential and isolation inspection, without setup or lifecycle."""

from __future__ import annotations

import os
import socket
from pathlib import Path

KINDS = ("mnt", "net", "pid", "ipc")


def uid() -> int:
    return int(getattr(os, "getuid", lambda: -1)())


def gid() -> int:
    return int(getattr(os, "getgid", lambda: -1)())


def namespaces() -> dict[str, str]:
    return {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in KINDS}


def isolation_facts() -> dict[str, object]:
    if uid() != 1000 or gid() != 1000 or getattr(os, "getgroups", lambda: [-1])():
        raise ValueError("the lab account must have UID/GID 1000 and no supplementary groups")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if status.get("NoNewPrivs", "").strip() != "1" or any(
        int(status.get(key, "1"), 16) != 0
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    ):
        raise ValueError("the lab still has privileges or can regain them")
    return {
        "uid": uid(),
        "gid": gid(),
        "capabilities": "zero",
        "no_new_privileges": True,
        **isolation_surface_facts(),
    }


def isolation_surface_facts() -> dict[str, object]:
    """Both fixed identities require the same isolated filesystem and network."""
    if socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("the isolated lab has a non-loopback network interface")
    if any(
        Path(path).exists() for path in ("/mnt/c", "/run/WSL", "/tmp/.X11-unix")  # nosec B108
    ):  # nosec B108
        raise ValueError("host filesystem or socket access remains exposed")
    mounts = Path("/proc/self/mountinfo").read_text()
    if any(marker in mounts for marker in (" - 9p ", " - drvfs ", " - virtiofs ")):
        raise ValueError("a host-backed filesystem is still mounted")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(line.split()[0] != "lo" for line in routes if line.split()):
        raise ValueError("a non-loopback IPv4 route remains")
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(line.split()[-1] != "lo" for line in routes6 if line.split()):
        raise ValueError("a non-loopback IPv6 route remains")
    return {
        "namespaces": namespaces(),
        "interfaces": socket.if_nameindex(),
        "routes": routes,
        "routes6": routes6,
    }
