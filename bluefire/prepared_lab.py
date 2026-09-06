"""Prepare, launch, and remove an owned WSL lab using the existing product.

Run ``python -m bluefire.prepared_lab --help``. This setup utility does not run
acceptance gates, approve experiments, or invoke runner actions. Dependency
installation and interactive effects are separate explicit commands.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tarfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .cross_platform_linux_distribution import (
    DisposableWslDistribution,
    create_disposable_wsl_distribution,
)
from .cross_platform_readiness import _trusted_wsl_executable

SCHEMA = "bluefire.prepared-linux-lab.v1"
NAME = re.compile(r"^BlueFire-Gate11-Run-([0-9a-f]{16})$")
REGISTRY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
GUEST_PYTHON = "/opt/bluefire-lab/venv/bin/python"
CLEAN_ENV = [
    "/usr/bin/env",
    "-i",
    "HOME=/home/bluefire",
    "USER=bluefire",
    "LOGNAME=bluefire",
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "LANG=C.UTF-8",
    "PYTHONNOUSERSITE=1",
    "PYTHONUNBUFFERED=1",
]


def identity(path: Path, *, directory: bool) -> tuple[int, int]:
    details = path.lstat()
    reparse = int(getattr(details, "st_file_attributes", 0)) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    )
    good_type = (
        stat.S_ISDIR(details.st_mode)
        if directory
        else stat.S_ISREG(details.st_mode) and details.st_nlink == 1
    )
    if not good_type or path.is_symlink() or reparse:
        raise ValueError("lab state must use ordinary, unlinked files and directories")
    return int(details.st_dev), int(details.st_ino)


def registration(name: str) -> tuple[str, Path] | None:
    import winreg

    matches = []
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY, 0, winreg.KEY_READ) as root:
        count = winreg.QueryInfoKey(root)[0]
        if not 0 <= count <= 256:
            raise ValueError("WSL registration inventory exceeds its bound")
        for index in range(count):
            key = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, key, 0, winreg.KEY_READ) as entry:
                if winreg.QueryValueEx(entry, "DistributionName")[0] != name:
                    continue
                version = winreg.QueryValueEx(entry, "Version")[0]
                base = winreg.QueryValueEx(entry, "BasePath")[0]
                if version != 2 or not isinstance(base, str):
                    raise ValueError("owned distribution registration is not WSL2")
                matches.append((key, Path(base).resolve(strict=True)))
    if len(matches) > 1:
        raise ValueError("owned distribution name is ambiguous")
    return matches[0] if matches else None


def verify(lease: DisposableWslDistribution, document: Mapping[str, Any]) -> None:
    if identity(lease.runtime, directory=True) != tuple(document["state_identity"]):
        raise ValueError("lab state directory identity changed")
    if identity(lease.install_root, directory=True) != lease.install_identity:
        raise ValueError("owned distribution storage identity changed")
    if identity(lease.runtime / "management.lock", directory=False) != tuple(
        document["lock_identity"]
    ):
        raise ValueError("lab management lock identity changed")
    current = registration(lease.distribution_name)
    if current is None or current != (document["registration_id"], lease.install_root):
        raise ValueError("owned distribution registration identity changed")


def environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if os.environ.get(key)
    }


def options(lease: DisposableWslDistribution) -> dict[str, Any]:
    result: dict[str, Any] = {"cwd": lease.runtime, "env": environment(), "shell": False}
    if os.name == "nt":
        result["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return result


def guest(lease: DisposableWslDistribution, user: str, *arguments: str) -> list[str]:
    return lease.command(
        "--user",
        user,
        "--cd",
        "/home/bluefire" if user == "bluefire" else "/",
        "--exec",
        *CLEAN_ENV,
        *arguments,
    )


def wheel_inputs(product: Path, wheelhouse: Path) -> list[Path]:
    product = product.resolve(strict=True)
    wheelhouse = wheelhouse.resolve(strict=True)
    identity(wheelhouse, directory=True)
    paths = [
        product,
        *(
            path
            for path in sorted(wheelhouse.iterdir())
            if path.suffix == ".whl" and path.resolve() != product
        ),
    ]
    if not 1 <= len(paths) <= 128 or len({path.name for path in paths}) != len(paths):
        raise ValueError("wheel inputs exceed the count bound or duplicate a name")
    size = 0
    for path in paths:
        identity(path, directory=False)
        count = path.stat().st_size
        if (
            not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", path.name)
            or not 0 < count <= 128 * 1024 * 1024
        ):
            raise ValueError("wheel inputs require bounded regular .whl files")
        size += count
    if (
        size > 512 * 1024 * 1024
        or not product.name.startswith("bluefire_nexus-")
        or sum(path.name.startswith("bluefire_nexus-") for path in paths) != 1
    ):
        raise ValueError("provide one BlueFire wheel and a bounded dependency wheelhouse")
    with zipfile.ZipFile(product) as archive:
        if "bluefire/prepared_lab_guest.py" not in archive.namelist():
            raise ValueError("the product wheel predates prepared lab support")
        manifests = [
            name for name in archive.namelist() if name == "bluefire/native/runner-manifest.json"
        ]
        if len(manifests) != 1 or archive.getinfo(manifests[0]).file_size > 64 * 1024:
            raise ValueError("the product wheel lacks its bounded native runner manifest")
        manifest = json.loads(archive.read(manifests[0]))
        artifact = manifest.get("artifact", {})
        if (
            not isinstance(artifact, dict)
            or artifact.get("platform") != "linux"
            or artifact.get("architecture") != "x86_64"
        ):
            raise ValueError("the prepared lab requires a Linux x86_64 product wheel")
    return paths


@contextmanager
def management_lock(handle: Any) -> Iterator[None]:
    """Use one OS lock for prepare/start/destroy, including failure cleanup."""
    handle.seek(0)
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise ValueError("this lab already has an active session or management operation") from exc
    try:
        yield
    finally:
        handle.seek(0)
        if sys.platform == "win32":
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def prepare(state: Path, product: Path, wheelhouse: Path) -> None:
    paths = wheel_inputs(product, wheelhouse)
    state = state.resolve()
    state.mkdir(mode=0o700)  # Deliberately refuses any pre-existing state directory.
    executable = _trusted_wsl_executable()
    if executable is None:
        raise ValueError("prepared WSL labs require a Windows host")
    with (state / "management.lock").open("x+b") as handle, management_lock(handle):
        _prepare_locked(state, paths, executable)


def _prepare_locked(state: Path, paths: list[Path], executable: Path) -> None:
    lease = create_disposable_wsl_distribution(executable, state)
    record: dict[str, Any] | None = None
    try:
        current = registration(lease.distribution_name)
        if current is None or current[1] != lease.install_root.resolve(strict=True):
            raise ValueError("the newly cloned distribution storage does not match its lease")
        record = {
            "schema_version": SCHEMA,
            "distribution_name": lease.distribution_name,
            "state_identity": identity(state, directory=True),
            "install_identity": lease.install_identity,
            "lock_identity": identity(state / "management.lock", directory=False),
            "registration_id": current[0],
        }
        with (state / "lease.json").open("x", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
        # Only reviewed fixed preparation code executes as clone-local root.
        script = Path(__file__).with_name("prepared_lab_install.py").read_text(encoding="utf-8")
        archive_path = state / "wheel-inputs.tar"
        with archive_path.open("xb") as output, tarfile.open(fileobj=output, mode="w|") as archive:
            for path in paths:
                with path.open("rb") as source:
                    info = tarfile.TarInfo(path.name)
                    info.size = path.stat().st_size
                    info.mode = 0o644
                    archive.addfile(info, source)
        verify(lease, record)
        with archive_path.open("rb") as payload:
            subprocess.run(  # nosec B603
                guest(lease, "root", "/usr/bin/python3", "-I", "-c", script),
                stdin=payload,
                check=True,
                timeout=300,
                **options(lease),
            )  # nosec B603
        verify(lease, record)
        subprocess.run(  # nosec B603
            [str(lease.executable), "--terminate", lease.distribution_name],
            check=True,
            timeout=30,
            **options(lease),
        )  # nosec B603
        print("Prepared owned Linux lab. Installation completed; no experiment was run.")
    except BaseException:
        if record is None:
            # No binding was established: a name alone cannot authorize deletion.
            raise
        verify(lease, record)
        lease.cleanup()
        raise


@contextmanager
def owned(state: Path) -> Iterator[tuple[DisposableWslDistribution, Mapping[str, Any]]]:
    state = state.resolve(strict=True)
    identity(state, directory=True)
    lock_path = state / "management.lock"
    original_lock = identity(lock_path, directory=False)
    lease_path = state / "lease.json"
    with lock_path.open("r+b") as lock_handle, management_lock(lock_handle):
        if (
            os.fstat(lock_handle.fileno()).st_dev,
            os.fstat(lock_handle.fileno()).st_ino,
        ) != original_lock:
            raise ValueError("lab management lock changed during open")
        original = identity(lease_path, directory=False)
        with lease_path.open("rb") as handle:
            if (os.fstat(handle.fileno()).st_dev, os.fstat(handle.fileno()).st_ino) != original:
                raise ValueError("lab lease identity changed during open")
            raw = handle.read(16385)
            if len(raw) > 16384:
                raise ValueError("lab lease exceeds its size bound")
            document = json.loads(raw)
            if (
                not isinstance(document, dict)
                or set(document)
                != {
                    "schema_version",
                    "distribution_name",
                    "state_identity",
                    "install_identity",
                    "lock_identity",
                    "registration_id",
                }
                or document.get("schema_version") != SCHEMA
            ):
                raise ValueError("invalid prepared lab lease")
            match = NAME.fullmatch(str(document["distribution_name"]))
            if match is None:
                raise ValueError("the lease does not name an owned disposable distribution")
            executable = _trusted_wsl_executable()
            if executable is None:
                raise ValueError("prepared WSL labs require Windows")
            lease = DisposableWslDistribution(
                executable,
                state,
                match[0],
                state / f"wsl-distribution-{match[1]}",
                tuple(document["install_identity"]),
                may_be_registered=True,
            )
            verify(lease, document)
            yield lease, document


def stop_client(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start(state: Path, port: int) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("choose an unprivileged UI port between 1024 and 65535")
    with owned(state) as (lease, record):
        inner = outer = None
        try:
            inner = subprocess.Popen(  # nosec B603
                guest(
                    lease,
                    "root",
                    GUEST_PYTHON,
                    "-I",
                    "-B",
                    "-m",
                    "bluefire.prepared_lab_guest",
                    "launch",
                    str(port),
                ),
                **options(lease),
            )  # nosec B603
            outer = subprocess.Popen(  # nosec B603
                guest(
                    lease,
                    "root",
                    "/usr/bin/setpriv",
                    "--reuid=1000",
                    "--regid=1000",
                    "--clear-groups",
                    "--no-new-privs",
                    "--bounding-set=-all",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                    GUEST_PYTHON,
                    "-I",
                    "-B",
                    "-m",
                    "bluefire.prepared_lab_guest",
                    "outer",
                    str(port),
                ),
                stdin=subprocess.DEVNULL,
                **options(lease),
            )  # nosec B603
            while inner.poll() is None and outer.poll() is None:
                time.sleep(0.2)
            if inner.poll() not in (None, 0) or outer.poll() not in (None, 0):
                raise ValueError("the isolated product session or UI relay failed")
        except KeyboardInterrupt:
            pass
        finally:
            try:
                verify(lease, record)
                try:
                    subprocess.run(  # nosec B603
                        guest(
                            lease,
                            "root",
                            GUEST_PYTHON,
                            "-I",
                            "-B",
                            "-m",
                            "bluefire.prepared_lab_guest",
                            "stop",
                            str(port),
                        ),
                        stdin=subprocess.DEVNULL,
                        check=True,
                        timeout=50,
                        **options(lease),
                    )
                finally:
                    # WSL client exit does not prove that guest descendants exited.
                    # Terminate only the verified clone, retaining its filesystem.
                    verify(lease, record)
                    subprocess.run(  # nosec B603
                        [str(lease.executable), "--terminate", lease.distribution_name],
                        check=True,
                        timeout=30,
                        **options(lease),
                    )
            finally:
                # These handles remain ours even if registration ownership changes.
                stop_client(outer)
                stop_client(inner)
    print("Lab session stopped. Data remains in the owned clone; use destroy when finished.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser(
        "prepare", help="clone the dedicated base and install local wheels"
    )
    preparation.add_argument("--state-dir", required=True, type=Path)
    preparation.add_argument("--wheel", required=True, type=Path)
    preparation.add_argument("--wheelhouse", required=True, type=Path)
    launch = commands.add_parser(
        "start", help="start the isolated ordinary UI and product command prompt"
    )
    launch.add_argument("--state-dir", required=True, type=Path)
    launch.add_argument("--port", default=8767, type=int)
    removal = commands.add_parser(
        "destroy", help="unregister only the identity-verified owned clone and remove its storage"
    )
    removal.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare(args.state_dir, args.wheel, args.wheelhouse)
        elif args.command == "start":
            start(args.state_dir, args.port)
        else:
            with owned(args.state_dir) as (lease, record):
                verify(lease, record)
                print(json.dumps(lease.cleanup(), indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Prepared lab refused: {exc}\n")


if __name__ == "__main__":
    main()
