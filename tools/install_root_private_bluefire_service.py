"""Stage one offline BlueFire service installation under an exact root-private path.

The root bootstrap must first copy and verify this script, the installed-wheel
verifier, and its binding helper into /root/bluefire-bootstrap-<run>-<attempt>.
Run this script with a root-owned system CPython 3.12 using ``-I -B``. It never
starts the service, native runner, Strix, or Docker.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import time
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence

_RUN_ID = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,4}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\.whl\Z")
_PRODUCT_WHEEL_FILENAME = re.compile(
    r"bluefire_nexus-[A-Za-z0-9_.!+]+(?:-[0-9][A-Za-z0-9_.]*)?"
    r"-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl\Z"
)
_DISTRIBUTIONS = frozenset({"cffi", "cryptography", "pycparser", "PyNaCl", "PyYAML"})
_LOCK_MEMBER = "bluefire/data/gate11_linux_wheelhouse.json"
_MAX_WHEEL_BYTES = 128 * 1024 * 1024


class InstallError(ValueError):
    """Stable, path-free root installation failure."""


def _paths(run_id: str) -> tuple[Path, Path]:
    if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None:
        raise InstallError("run_id_invalid")
    return (
        Path(f"/root/bluefire-bootstrap-{run_id}"),
        Path(f"/root/bluefire-ci-{run_id}"),
    )


def _digest(path: Path, *, maximum: int) -> tuple[int, str]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise InstallError("source_bound")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise InstallError("source_changed")
    return before.st_size, "sha256:" + value.hexdigest()


def _precheck_bootstrap(bootstrap: Path) -> None:
    """Check custody before importing even the hash-pinned verifier helper."""

    for path in (
        Path("/"),
        Path("/root"),
        bootstrap,
        bootstrap / "install_root_private_bluefire_service.py",
        bootstrap / "verify_root_private_bluefire_service.py",
        bootstrap / "verify_installed_engine_experiment.py",
    ):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        directory = path in (Path("/"), Path("/root"), bootstrap)
        if (
            info.st_uid != 0
            or mode & 0o022
            or stat.S_ISLNK(info.st_mode)
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
            or (path == bootstrap and mode != 0o700)
        ):
            raise InstallError("bootstrap_custody_invalid")


def _load_gate(bootstrap: Path, expected: str) -> ModuleType:
    path = bootstrap / "verify_root_private_bluefire_service.py"
    if _digest(path, maximum=256 * 1024)[1] != expected:
        raise InstallError("verifier_changed")
    spec = importlib.util.spec_from_file_location("_bluefire_root_private_gate", path)
    if spec is None or spec.loader is None:
        raise InstallError("verifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "_secure_path", None)):
        raise InstallError("verifier_invalid")
    return module


def _bootstrap(args: argparse.Namespace) -> tuple[ModuleType, Path, Path]:
    if (
        sys.platform != "linux"
        or platform.machine() != "x86_64"
        or sys.version_info[:2] != (3, 12)
        or not sys.flags.isolated
        or not sys.flags.dont_write_bytecode
        or not hasattr(os, "geteuid")
        or os.geteuid() != 0
        or sys.prefix != sys.base_prefix
    ):
        raise InstallError("root_system_python_required")
    bootstrap, root = _paths(args.run_id)
    script = bootstrap / "install_root_private_bluefire_service.py"
    if Path(__file__) != script:
        raise InstallError("bootstrap_location_invalid")
    for value in (
        args.expected_installer_sha256,
        args.expected_verifier_sha256,
        args.expected_helper_sha256,
    ):
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise InstallError("bootstrap_digest_invalid")
    _precheck_bootstrap(bootstrap)
    gate = _load_gate(bootstrap, args.expected_verifier_sha256)
    gate._secure_path(bootstrap, kind="directory", exact_mode=0o700)
    gate._secure_path(script, kind="file")
    gate._secure_path(bootstrap / "verify_root_private_bluefire_service.py", kind="file")
    gate._secure_path(bootstrap / "verify_installed_engine_experiment.py", kind="file")
    if _digest(script, maximum=256 * 1024)[1] != args.expected_installer_sha256:
        raise InstallError("installer_changed")
    if (
        _digest(bootstrap / "verify_installed_engine_experiment.py", maximum=256 * 1024)[1]
        != args.expected_helper_sha256
    ):
        raise InstallError("binding_helper_changed")
    executable = Path(sys.executable)
    if executable != Path("/usr/bin/python3.12"):
        raise InstallError("system_python_location_invalid")
    gate._secure_path(executable, kind="file")
    gate._secure_path(Path(sysconfig.get_path("stdlib")), kind="directory")
    for raw in sys.path:
        if not raw:
            raise InstallError("system_import_path_invalid")
        path = Path(raw)
        if not path.is_absolute():
            raise InstallError("system_import_path_invalid")
        while not path.exists() and path != path.parent:
            path = path.parent
        gate._secure_path(path, kind="directory" if path.is_dir() else "file")
    return gate, bootstrap, root


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InstallError("json_duplicate")
        value[key] = item
    return value


def _locked_wheels(wheel: Path) -> tuple[str, list[dict[str, Any]]]:
    with zipfile.ZipFile(wheel) as archive:
        if archive.namelist().count(_LOCK_MEMBER) != 1:
            raise InstallError("wheelhouse_lock_missing")
        member = archive.getinfo(_LOCK_MEMBER)
        if not 0 < member.file_size <= 16_384:
            raise InstallError("wheelhouse_lock_bound")
        raw = archive.read(member)
    lock = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_unique)
    if (
        not isinstance(lock, dict)
        or set(lock) != {"schema_version", "platform", "architecture", "python", "wheels"}
        or lock["schema_version"] != "bluefire.linux-wheelhouse.v1"
        or lock["platform"] != "linux"
        or lock["architecture"] != "x86_64"
        or lock["python"] != {"implementation": "cpython", "major": 3, "minor": 12}
        or not isinstance(lock["wheels"], list)
        or len(lock["wheels"]) != 5
    ):
        raise InstallError("wheelhouse_lock_invalid")
    rows = lock["wheels"]
    distributions: set[str] = set()
    filenames: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "distribution",
            "version",
            "filename",
            "size",
            "sha256",
        }:
            raise InstallError("wheelhouse_lock_invalid")
        name = row["filename"]
        distribution = row["distribution"]
        version = row["version"]
        if (
            type(distribution) is not str
            or distribution not in _DISTRIBUTIONS
            or distribution in distributions
            or type(version) is not str
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version) is None
            or type(name) is not str
            or _FILENAME.fullmatch(name) is None
            or name in filenames
            or not name.lower().startswith(
                distribution.lower().replace("-", "_") + "-" + version + "-"
            )
            or type(row["size"]) is not int
            or not 0 < row["size"] <= 16 * 1024 * 1024
            or type(row["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
        ):
            raise InstallError("wheelhouse_lock_invalid")
        distributions.add(distribution)
        filenames.add(name)
    if distributions != _DISTRIBUTIONS:
        raise InstallError("wheelhouse_lock_invalid")
    return "sha256:" + hashlib.sha256(raw).hexdigest(), rows


def _inventory_digest(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        sorted(rows, key=lambda item: item["filename"]),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _wheelhouse_source(directory: Path, lock_digest: str, rows: list[dict[str, Any]]) -> None:
    directory = directory.resolve(strict=True)
    receipt_path = directory / "service-wheelhouse-receipt.json"
    if set(entry.name for entry in directory.iterdir()) != {
        *(row["filename"] for row in rows),
        receipt_path.name,
    }:
        raise InstallError("wheelhouse_inventory_invalid")
    if not stat.S_ISREG(receipt_path.lstat().st_mode) or receipt_path.stat().st_size > 8192:
        raise InstallError("wheelhouse_receipt_invalid")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"), object_pairs_hook=_json_unique)
    if receipt != {
        "schema_version": "bluefire.service-wheelhouse-receipt.v1",
        "lock_sha256": lock_digest,
        "platform": "linux",
        "architecture": "x86_64",
        "python": "3.12",
        "wheelhouse_dir": str(directory),
        "wheel_inventory_digest": _inventory_digest(rows),
    }:
        raise InstallError("wheelhouse_receipt_invalid")


def _copy_exact(source: Path, target: Path, *, size: int, sha256: str) -> None:
    if not 0 < size <= _MAX_WHEEL_BYTES or _SHA256.fullmatch(sha256) is None:
        raise InstallError("source_identity_invalid")
    source_stat = source.lstat()
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size != size:
        raise InstallError("source_identity_invalid")
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino, opened.st_size) != (
            source_stat.st_dev,
            source_stat.st_ino,
            source_stat.st_size,
        ):
            raise InstallError("source_changed")
        target_fd = os.open(
            target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            value = hashlib.sha256()
            copied = 0
            while block := os.read(source_fd, min(1024 * 1024, size + 1 - copied)):
                copied += len(block)
                if copied > size:
                    raise InstallError("source_changed")
                value.update(block)
                remaining = memoryview(block)
                while remaining:
                    count = os.write(target_fd, remaining)
                    if count <= 0:
                        raise InstallError("copy_unknown")
                    remaining = remaining[count:]
            if copied != size or "sha256:" + value.hexdigest() != sha256:
                raise InstallError("source_changed")
            os.fsync(target_fd)
        except Exception:
            os.close(target_fd)
            target.unlink(missing_ok=True)
            raise
        else:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def _run(command: list[str], *, root: Path, timeout: int, phase: str) -> None:
    if phase not in {"venv", "pip", "verify"}:
        raise InstallError("child_phase_invalid")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "TMPDIR": str(root / "temp"),
        "XDG_CACHE_HOME": str(root / "temp"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": "/dev/null",
    }
    process = subprocess.Popen(
        command,
        cwd=root / "work",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    retained = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout
    timed_out = False
    assert process.stderr is not None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready = selector.select(remaining)
                if not ready:
                    timed_out = True
                    break
                block = os.read(process.stderr.fileno(), 8192)
                if not block:
                    selector.unregister(process.stderr)
                    break
                available = max(0, 16_384 - len(retained))
                retained.extend(block[:available])
                truncated |= len(block) > available
        if not timed_out:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        outcome = "timeout" if timed_out else "failed" if process.returncode != 0 else "passed"
    finally:
        process.stderr.close()
    if outcome != "passed":
        if truncated:
            retained.extend(b"\n[truncated]\n")
        if timed_out:
            retained.extend(b"\n[timed out]\n")
        descriptor = os.open(
            root / "temp" / f"{phase}-failure.stderr",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, retained or b"no stderr\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise InstallError("child_failed")


def _write_install_receipt(
    root: Path, staged_wheel: Path, purelib: Path, expected_wheel: str, expected_revision: str
) -> None:
    verified_path = root / "installed-service-verification.json"
    if not stat.S_ISREG(verified_path.lstat().st_mode) or verified_path.stat().st_size > 8192:
        raise InstallError("installed_verification_missing")
    verified = json.loads(verified_path.read_text(encoding="utf-8"), object_pairs_hook=_json_unique)
    if (
        not isinstance(verified, dict)
        or verified.get("schema_version")
        != "bluefire.root-private-installed-service-verification.v1"
        or verified.get("verified") is not True
        or verified.get("root_private") is not True
        or verified.get("service_started") is not False
        or verified.get("wheel_sha256") != expected_wheel
        or verified.get("source_revision") != expected_revision
        or not isinstance(verified.get("version"), str)
        or not isinstance(verified.get("installed_payload_digest"), str)
        or _SHA256.fullmatch(verified["installed_payload_digest"]) is None
        or not isinstance(verified.get("wheel_payload_digest"), str)
        or _SHA256.fullmatch(verified["wheel_payload_digest"]) is None
    ):
        raise InstallError("installed_verification_invalid")
    receipt = {
        "schema_version": "bluefire.root-private-service-install.v1",
        "root": str(root),
        "staged_wheel": str(staged_wheel),
        "service_purelib": str(purelib),
        "installed_version": verified["version"],
        "installed_payload_digest": verified["installed_payload_digest"],
        "wheel_payload_digest": verified["wheel_payload_digest"],
        "wheel_sha256": expected_wheel,
        "source_revision": expected_revision,
    }
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    descriptor = os.open(
        root / "installed-service-inputs.json",
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise InstallError("receipt_write_unknown")
            remaining = remaining[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install(args: argparse.Namespace) -> None:
    gate, bootstrap, root = _bootstrap(args)
    if (
        type(args.expected_source_revision) is not str
        or _REVISION.fullmatch(args.expected_source_revision) is None
        or type(args.expected_wheel_sha256) is not str
        or _SHA256.fullmatch(args.expected_wheel_sha256) is None
        or type(args.expected_wheel_size) is not int
        or not 0 < args.expected_wheel_size <= _MAX_WHEEL_BYTES
        or type(args.expected_wheel_name) is not str
        or _PRODUCT_WHEEL_FILENAME.fullmatch(args.expected_wheel_name) is None
    ):
        raise InstallError("candidate_identity_invalid")
    wheel_source = Path(args.wheel_source)
    wheelhouse_source = Path(args.wheelhouse_source)
    if (
        not wheel_source.is_absolute()
        or wheel_source.name != args.expected_wheel_name
        or not wheelhouse_source.is_absolute()
    ):
        raise InstallError("source_path_invalid")
    if root.exists():
        raise InstallError("private_root_exists")
    os.umask(0o077)
    root.mkdir(mode=0o700)
    gate._secure_path(root, kind="directory", exact_mode=0o700)
    for name in ("staged", "wheelhouse", "work", "temp"):
        (root / name).mkdir(mode=0o700)
    staged_wheel = root / "staged" / args.expected_wheel_name
    _copy_exact(
        wheel_source,
        staged_wheel,
        size=args.expected_wheel_size,
        sha256=args.expected_wheel_sha256,
    )
    lock_digest, rows = _locked_wheels(staged_wheel)
    _wheelhouse_source(wheelhouse_source, lock_digest, rows)
    for row in rows:
        _copy_exact(
            wheelhouse_source / row["filename"],
            root / "wheelhouse" / row["filename"],
            size=row["size"],
            sha256="sha256:" + row["sha256"],
        )
    for name, expected in (
        ("verify_root_private_bluefire_service.py", args.expected_verifier_sha256),
        ("verify_installed_engine_experiment.py", args.expected_helper_sha256),
    ):
        source = bootstrap / name
        size, observed = _digest(source, maximum=256 * 1024)
        if observed != expected:
            raise InstallError("bootstrap_source_changed")
        _copy_exact(source, root / name, size=size, sha256=expected)
    _run(
        [sys.executable, "-I", "-B", "-m", "venv", "--copies", str(root / "venv")],
        root=root,
        timeout=120,
        phase="venv",
    )
    candidates = ("python3.12", "python3", "python")
    python = next(
        (
            root / "venv" / "bin" / name
            for name in candidates
            if (root / "venv" / "bin" / name).exists()
            and stat.S_ISREG((root / "venv" / "bin" / name).lstat().st_mode)
        ),
        None,
    )
    if python is None:
        raise InstallError("copied_venv_python_unavailable")
    gate._secure_path(python, kind="file")
    _run(
        [
            str(python),
            "-I",
            "-B",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            *(str(root / "wheelhouse" / row["filename"]) for row in rows),
            str(staged_wheel),
        ],
        root=root,
        timeout=180,
        phase="pip",
    )
    _prune_venv_aliases(root, gate)
    _check_tree_custody(root / "venv", gate)
    gate._secure_path(root / "venv", kind="directory")
    _run(
        [
            str(python),
            "-I",
            "-B",
            str(root / "verify_root_private_bluefire_service.py"),
            "--private-root",
            str(root),
            "--forbid-root",
            args.forbid_root,
            "--expected-source-revision",
            args.expected_source_revision,
            "--expected-wheel-sha256",
            args.expected_wheel_sha256,
            "--expected-helper-sha256",
            args.expected_helper_sha256,
            "--expected-verifier-sha256",
            args.expected_verifier_sha256,
        ],
        root=root,
        timeout=90,
        phase="verify",
    )
    gate._secure_path(root / "installed-service-verification.json", kind="file", exact_mode=0o600)
    purelib = root / "venv" / "lib" / "python3.12" / "site-packages"
    gate._secure_path(purelib, kind="directory")
    gate._secure_path(staged_wheel, kind="file", exact_mode=0o600)
    _write_install_receipt(
        root, staged_wheel, purelib, args.expected_wheel_sha256, args.expected_source_revision
    )
    gate._secure_path(root / "installed-service-inputs.json", kind="file", exact_mode=0o600)


def _check_tree_custody(root: Path, gate: ModuleType, *, exact_mode: int | None = None) -> None:
    device = gate._secure_path(root, kind="directory", exact_mode=exact_mode).st_dev
    count = 0

    def failed(_error: OSError) -> None:
        raise InstallError("cleanup_walk_unknown")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in (*dirs, *files):
            count += 1
            if count > 50_000:
                raise InstallError("cleanup_bound")
            target = Path(directory) / name
            kind = "directory" if name in dirs else "file"
            if gate._secure_path(target, kind=kind).st_dev != device:
                raise InstallError("cleanup_mount_refused")


def _prune_venv_aliases(root: Path, gate: ModuleType) -> None:
    """Unlink only venv's conventional aliases, without following their targets."""

    venv = root / "venv"
    try:
        venv.lstat()
    except FileNotFoundError:
        return
    gate._secure_path(venv, kind="directory")
    bin_dir = venv / "bin"
    try:
        bin_dir.lstat()
    except FileNotFoundError:
        bin_present = False
    else:
        bin_present = True
        gate._secure_path(bin_dir, kind="directory")
    aliases = [venv / "lib64"]
    if bin_present:
        aliases.extend(bin_dir / name for name in ("python", "python3", "python3.12"))
    for alias in aliases:
        try:
            info = alias.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            alias.unlink()


def _assert_no_mounts(root: Path) -> None:
    """Do not recursively remove a bind mount, including one on the same device."""

    descriptor = os.open("/proc/self/mountinfo", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        mountinfo = os.read(descriptor, 4 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(mountinfo) > 4 * 1024 * 1024:
        raise InstallError("mount_inventory_bound")
    prefix = os.fsencode(root)
    for line in mountinfo.splitlines():
        fields = line.split(b" ")
        if len(fields) < 5:
            raise InstallError("mount_inventory_invalid")
        mountpoint = fields[4]
        if mountpoint == prefix or mountpoint.startswith(prefix + b"/"):
            raise InstallError("cleanup_mount_refused")


def cleanup(args: argparse.Namespace) -> str:
    gate, bootstrap, root = _bootstrap(args)
    evidence = bootstrap / "retained-evidence-receipt.json"
    evidence_status = "evidence_missing"
    if evidence.exists() or evidence.is_symlink():
        try:
            gate._secure_path(evidence, kind="file", exact_mode=0o600)
            expected = args.retained_evidence_digest
            if type(expected) is not str or _SHA256.fullmatch(expected) is None:
                raise InstallError("retained_evidence_invalid")
            if _digest(evidence, maximum=8192)[1] != expected:
                raise InstallError("retained_evidence_invalid")
            receipt = json.loads(
                evidence.read_text(encoding="utf-8"), object_pairs_hook=_json_unique
            )
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"schema_version", "run_id", "status", "artifact_digest"}
                or receipt["schema_version"] != "bluefire.root-private-evidence-retention.v1"
                or receipt["run_id"] != args.run_id
                or receipt["status"] != "retained"
                or type(receipt["artifact_digest"]) is not str
                or _SHA256.fullmatch(receipt["artifact_digest"]) is None
            ):
                raise InstallError("retained_evidence_invalid")
        except (OSError, ValueError, UnicodeError):
            evidence_status = "evidence_invalid"
        else:
            evidence_status = "retained"
    try:
        root.lstat()
    except FileNotFoundError:
        root_present = False
    else:
        root_present = True
        gate._secure_path(root, kind="directory", exact_mode=0o700)
        _assert_no_mounts(root)
        _prune_venv_aliases(root, gate)
        _check_tree_custody(root, gate, exact_mode=0o700)
    _assert_no_mounts(bootstrap)
    _check_tree_custody(bootstrap, gate, exact_mode=0o700)
    if not shutil.rmtree.avoids_symlink_attacks:
        raise InstallError("safe_cleanup_unavailable")
    os.chdir("/root")
    if root_present:
        shutil.rmtree(root)
    shutil.rmtree(bootstrap)
    for path in (root, bootstrap):
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise InstallError("cleanup_unknown")
    return evidence_status


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "cleanup"):
        command = commands.add_parser(name)
        command.add_argument("--run-id", required=True)
        command.add_argument("--expected-installer-sha256", required=True)
        command.add_argument("--expected-verifier-sha256", required=True)
        command.add_argument("--expected-helper-sha256", required=True)
        if name == "install":
            command.add_argument("--wheel-source", required=True)
            command.add_argument("--wheelhouse-source", required=True)
            command.add_argument("--expected-wheel-name", required=True)
            command.add_argument("--expected-wheel-size", required=True, type=int)
            command.add_argument("--expected-wheel-sha256", required=True)
            command.add_argument("--expected-source-revision", required=True)
            command.add_argument("--forbid-root", required=True)
        else:
            command.add_argument("--retained-evidence-digest")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            install(args)
        else:
            evidence_status = cleanup(args)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("root-private service installation failed", file=sys.stderr)
        return 2
    if args.command == "cleanup" and evidence_status != "retained":
        print("root-private service removed; " + evidence_status, file=sys.stderr)
        return 3
    print(
        "root-private service installed"
        if args.command == "install"
        else "root-private service removed"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - root-only installed entry
    raise SystemExit(main())
