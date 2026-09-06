"""Fixed clone-only preparation, streamed over stdin before effects are enabled."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tarfile
from pathlib import Path

ROOT = Path("/opt/bluefire-lab")
HOME = Path("/home/bluefire")
ENV = {
    "HOME": str(HOME),
    "USER": "bluefire",
    "LOGNAME": "bluefire",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "PYTHONNOUSERSITE": "1",
}
TOOLS = (
    "/usr/bin/unshare",
    "/usr/bin/setpriv",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/sbin/ip",
    "/usr/sbin/useradd",
    "/usr/sbin/groupadd",
)


def secure_clone_root() -> None:
    """WSL imports may expose a writable filesystem root; seal this new clone."""
    if sys.platform != "linux" or getattr(os, "getuid", lambda: -1)() != 0:
        raise ValueError("clone root preparation requires Linux root")
    root = Path("/")
    before = root.lstat()
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != 0 or before.st_gid != 0:
        raise ValueError("the new clone filesystem root is not root-owned")
    mode = stat.S_IMODE(before.st_mode) & ~0o022
    root.chmod(mode)
    after = root.lstat()
    if (
        (after.st_dev, after.st_ino, after.st_uid, after.st_gid)
        != (before.st_dev, before.st_ino, 0, 0)
        or not stat.S_ISDIR(after.st_mode)
        or stat.S_IMODE(after.st_mode) != mode
    ):
        raise ValueError("the new clone filesystem root could not be secured")


def install() -> None:
    if (
        sys.platform != "linux"
        or getattr(os, "getuid", lambda: -1)() != 0
        or sys.version_info[:2] != (3, 12)
    ):
        raise ValueError("clone preparation requires root and CPython 3.12")
    import grp
    import pwd

    secure_clone_root()
    if not all(Path(path).is_file() for path in TOOLS):
        raise ValueError("base needs util-linux, mount, iproute2, and account-management tools")
    for lookup, value in (
        (pwd.getpwuid, 1000),
        (pwd.getpwnam, "bluefire"),
        (grp.getgrgid, 1000),
        (grp.getgrnam, "bluefire"),
        (pwd.getpwuid, 1001),
        (pwd.getpwnam, "bluefire-broker"),
        (grp.getgrgid, 1001),
        (grp.getgrnam, "bluefire-broker"),
    ):
        try:
            lookup(value)
        except KeyError:
            continue
        raise ValueError("base must reserve UID/GID 1000 and 1001 and the bluefire account names")
    ROOT.mkdir(mode=0o755)
    wheelhouse = ROOT / "wheelhouse"
    wheelhouse.mkdir(mode=0o755)
    # Tar members are copied as bytes, never extracted as links or paths.
    total = count = 0
    names: set[str] = set()
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        for member in archive:
            count += 1
            total += member.size
            if (
                not member.isfile()
                or member.name in names
                or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", member.name)
                or not 0 < member.size <= 128 * 1024 * 1024
                or count > 128
                or total > 512 * 1024 * 1024
            ):
                raise ValueError("wheel stream violated its name, size, or regular-file bounds")
            names.add(member.name)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("wheel content unavailable")
            with source, (wheelhouse / member.name).open("xb") as destination:
                remaining = member.size
                while remaining:
                    block = source.read(min(65536, remaining))
                    if not block:
                        raise ValueError("wheel stream ended early")
                    destination.write(block)
                    remaining -= len(block)
    product = [name for name in names if name.startswith("bluefire_nexus-")]
    if len(product) != 1:
        raise ValueError("exactly one BlueFire product wheel is required")
    subprocess.run(  # nosec B603
        ["/usr/sbin/groupadd", "--gid", "1000", "bluefire"], check=True
    )  # nosec B603
    subprocess.run(  # nosec B603
        [
            "/usr/sbin/useradd",
            "--create-home",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--shell",
            "/bin/false",
            "bluefire",
        ],
        check=True,
    )  # nosec B603
    os.chmod(HOME, 0o700)
    subprocess.run(  # nosec B603
        ["/usr/sbin/groupadd", "--gid", "1001", "bluefire-broker"], check=True
    )
    subprocess.run(  # nosec B603
        [
            "/usr/sbin/useradd",
            "--create-home",
            "--uid",
            "1001",
            "--gid",
            "1001",
            "--shell",
            "/bin/false",
            "bluefire-broker",
        ],
        check=True,
    )
    os.chmod(HOME.with_name("bluefire-broker"), 0o700)
    # Microsoft documents per-distribution settings here; the persistent base
    # is never altered: https://learn.microsoft.com/en-us/windows/wsl/wsl-config
    Path("/etc/wsl.conf").write_text(
        "[boot]\nsystemd=false\n[automount]\nenabled=false\nmountFsTab=false\n[interop]\nenabled=false\nappendWindowsPath=false\n[user]\ndefault=bluefire\n"
    )
    for name in (
        "/mnt",
        "/run",
        "/tmp",  # nosec B108
        "/usr/lib/wsl",
        "/dev/shm",  # nosec B108
    ):  # nosec B108
        Path(name).mkdir(parents=True, exist_ok=True)
    venv = ROOT / "venv"
    venv.mkdir(mode=0o755)
    os.chown(venv, 1000, 1000)
    prefix = [
        "/usr/bin/setpriv",
        "--reuid=1000",
        "--regid=1000",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
    ]
    subprocess.run(  # nosec B603
        [*prefix, "/usr/bin/python3", "-I", "-m", "venv", str(venv)],
        check=True,
        env=ENV,
        cwd=HOME,
        timeout=60,
    )  # nosec B603
    python = str(venv / "bin/python")
    subprocess.run(  # nosec B603
        [
            *prefix,
            python,
            "-I",
            "-m",
            "pip",
            "--disable-pip-version-check",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--find-links",
            str(wheelhouse),
            str(wheelhouse / product[0]),
        ],
        check=True,
        env=ENV,
        cwd=HOME,
        timeout=180,
    )  # nosec B603
    subprocess.run(  # nosec B603
        [
            *prefix,
            python,
            "-I",
            "-c",
            "import bluefire.prepared_lab_guest; import importlib.metadata; print(importlib.metadata.version('bluefire-nexus'))",
        ],
        check=True,
        env=ENV,
        cwd=HOME,
        timeout=15,
    )  # nosec B603
    # Record the installed input set, without claiming it is signed or accepted.
    record = {
        name: hashlib.sha256((wheelhouse / name).read_bytes()).hexdigest() for name in sorted(names)
    }
    (ROOT / "installed-wheels.json").write_text(json.dumps(record, indent=2))
    for base, dirs, files in os.walk(venv):
        for name in [base, *(str(Path(base) / entry) for entry in dirs + files)]:
            os.chown(name, 0, 0, follow_symlinks=False)


if __name__ == "__main__":
    install()
