"""Fixed prepared-lab paths, mount isolation and child cleanup shared by its entries."""

from __future__ import annotations

import os
import subprocess  # nosec B404
from pathlib import Path

ROOT = Path("/opt/bluefire-lab")
HOME = Path("/home/bluefire")
BRIDGE = HOME / ".bluefire-lab-ui.sock"
PYTHON = ROOT / "venv/bin/python"
PRODUCT = [str(ROOT / "venv/bin/bluefire"), "--runs-dir", str(HOME / "experiments")]
ENV = {
    "HOME": str(HOME),
    "USER": "bluefire",
    "LOGNAME": "bluefire",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONNOUSERSITE": "1",
}
STOP_FILE = ROOT / "session-stop"
KINDS = ("mnt", "net", "pid", "ipc")


def uid() -> int:
    return int(getattr(os, "getuid", lambda: -1)())


def gid() -> int:
    return int(getattr(os, "getgid", lambda: -1)())


def namespaces() -> dict[str, str]:
    return {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in KINDS}


def guest_command(mode: str, port: int, *args: str) -> list[str]:
    return [str(PYTHON), "-I", "-B", "-m", "bluefire.prepared_lab_guest", mode, str(port), *args]


def isolate_mounts() -> None:
    # Remove host-backed submounts within this already-private mount namespace.
    # Merely covering their parent leaves mountinfo entries and hidden mounts.
    host_mounts = []
    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = row.split(" - ", 1)
        if after.split()[0] in {"9p", "drvfs", "virtiofs"}:
            target = before.split()[4]
            if "\\" in target or not target.startswith(("/mnt/", "/usr/lib/wsl/")):
                raise ValueError("an unexpected host mount cannot be safely detached")
            host_mounts.append(target)
    for target in sorted(host_mounts, key=lambda value: value.count("/"), reverse=True):
        subprocess.run(  # nosec B603
            ["/usr/bin/umount", "--", target], check=True, env=ENV
        )  # nosec B603
    # unshare's explicit --propagation private prevents these mounts escaping.
    for name in (
        "/mnt",
        "/run",
        "/tmp",  # nosec B108
        "/usr/lib/wsl",
        "/dev/shm",  # nosec B108
    ):  # nosec B108
        path = Path(name)
        if not path.is_dir() or path.is_symlink():
            raise ValueError("a required isolation mount point is absent or linked")
        mode = "1777" if name in {"/tmp", "/dev/shm"} else "0755"  # nosec B108
        subprocess.run(  # nosec B603
            [
                "/usr/bin/mount",
                "-t",
                "tmpfs",
                "-o",
                f"nodev,nosuid,noexec,mode={mode}",
                "tmpfs",
                name,
            ],
            check=True,
            env=ENV,
        )  # nosec B603
    if Path("/init").is_file():
        subprocess.run(  # nosec B603
            ["/usr/bin/mount", "--bind", "/dev/null", "/init"], check=True, env=ENV
        )  # nosec B603
    subprocess.run(  # nosec B603
        ["/usr/bin/mount", "--bind", str(ROOT), str(ROOT)], check=True, env=ENV
    )  # nosec B603
    subprocess.run(  # nosec B603
        ["/usr/bin/mount", "-o", "remount,bind,ro", str(ROOT)], check=True, env=ENV
    )  # nosec B603


def stop_child(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
