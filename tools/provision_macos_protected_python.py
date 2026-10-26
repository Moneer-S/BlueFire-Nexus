"""Stage and install the exact hosted macOS qualification runtime.

The stage phase runs as the hosted job user. The install phase runs as root and
accepts only the two reviewed source archives plus a hash-inventoried wheelhouse.
It never writes to system Python, Homebrew, or a shared runtime prefix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

PYTHON_VERSION = "3.11.18"
PYTHON_URL = "https://www.python.org/ftp/python/3.11.18/Python-3.11.18.tgz"
PYTHON_SHA256 = "5f62711b12470fd435f83f1451c1b1ef4a179aebc715c716874b0967567d814e"
OPENSSL_VERSION = "3.5.9"
OPENSSL_URL = (
    "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"
)
OPENSSL_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
MAX_SOURCE_BYTES = 120 * 1024 * 1024
MAX_WHEEL_BYTES = 500 * 1024 * 1024
MAX_FILES = 128
MAX_LINK_DIAGNOSTICS = 8
MAX_RPATH_CANDIDATES = 16
MAX_DIAGNOSTIC_LABEL = 120
_IMPORTABLE_SUFFIXES = {".py", ".pyc", ".so", ".zip"}
_PACKAGE_IMPORT_FILE_LIMIT = 1024
_RUNTIME_IMPORT_FILE_LIMIT = 4096
_RUNTIME_IMPORT_BYTE_LIMIT = 256 * 1024 * 1024
_IMPORT_INVENTORY_SCHEMA = "bluefire.macos-import-custody-inventory.v1"


class DynamicLinkAuditError(ValueError):
    def __init__(self, diagnostics: list[dict[str, object]], *, truncated: bool) -> None:
        super().__init__(
            "A protected Python dynamic dependency is outside its prefix and SIP paths."
        )
        self.diagnostics = diagnostics[:MAX_LINK_DIAGNOSTICS]
        self.truncated = truncated


class ImportInventoryLimitError(RuntimeError):
    def __init__(self, inventory: dict[str, object]) -> None:
        super().__init__("import_custody_limit_exceeded")
        self.inventory = inventory


def _hash(path: Path, limit: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("A staged input exceeds its fixed size limit.")
            digest.update(chunk)
    return digest.hexdigest(), size


def _importable_tree_files(root: Path, prefix: Path) -> list[tuple[Path, str, int]]:
    """Count the same importable file kinds that the runtime custody check sees."""
    try:
        protected_prefix = prefix.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise ValueError("import_custody_root_unavailable") from error
    if not resolved_root.is_relative_to(protected_prefix) or root.is_symlink():
        raise ValueError("import_custody_root_outside_prefix")

    if resolved_root.is_file():
        if resolved_root.suffix != ".zip":
            raise ValueError("import_custody_unexpected_file_root")
        try:
            size = root.stat().st_size
        except OSError as error:
            raise ValueError("import_custody_root_unavailable") from error
        return [(root, ".zip", size)]
    if not resolved_root.is_dir():
        raise ValueError("import_custody_root_not_directory")

    rows: list[tuple[Path, str, int]] = []

    def failed(_error: OSError) -> None:
        raise ValueError("import_custody_tree_unreadable")

    for directory, children, leaves in os.walk(root, followlinks=False, onerror=failed):
        base = Path(directory)
        for child in children:
            child_path = base / child
            if child_path.is_symlink() or not child_path.is_dir():
                raise ValueError("import_custody_indirect_directory")
        for leaf in leaves:
            path = base / leaf
            if path.suffix not in _IMPORTABLE_SUFFIXES:
                continue
            try:
                details = path.lstat()
                resolved_path = path.resolve(strict=True)
            except OSError as error:
                raise ValueError("import_custody_import_unavailable") from error
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("import_custody_nonregular_import")
            if not resolved_path.is_relative_to(protected_prefix):
                raise ValueError("import_custody_import_outside_prefix")
            rows.append((path, path.suffix, details.st_size))
    return rows


def _runtime_import_roots(python: Path) -> list[Path]:
    source = "import json,sys; print(json.dumps(sys.path,separators=(',',':')))"
    try:
        completed = subprocess.run(
            [str(python), "-I", "-S", "-B", "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("runtime_import_roots_unavailable") from error
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 16 * 1024:
        raise ValueError("runtime_import_roots_unavailable")
    try:
        values = json.loads(completed.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("runtime_import_roots_invalid") from error
    if (
        type(values) is not list
        or not 0 < len(values) <= 8
        or any(type(value) is not str or not Path(value).is_absolute() for value in values)
        or len(values) != len(set(values))
    ):
        raise ValueError("runtime_import_roots_invalid")
    return [Path(value) for value in values]


def _import_custody_inventory(python: Path, prefix: Path) -> dict[str, object]:
    """Preflight package and interpreter roots without retaining paths or filenames."""
    package_root = (
        prefix / "venv" / "lib" / f"python{PYTHON_VERSION.rsplit('.', 1)[0]}" / "site-packages"
    )
    package_files = _importable_tree_files(package_root, prefix)

    runtime_files: dict[Path, tuple[str, int]] = {}
    runtime_roots = _runtime_import_roots(python)
    for root in runtime_roots:
        if not root.exists():
            if root.suffix != ".zip":
                raise ValueError("runtime_import_root_missing")
            continue
        for path, suffix, size in _importable_tree_files(root, prefix):
            runtime_files[path] = (suffix, size)

    def counts(rows: list[tuple[str, int]]) -> dict[str, object]:
        by_suffix = {suffix: 0 for suffix in sorted(_IMPORTABLE_SUFFIXES)}
        total_bytes = 0
        for suffix, size in rows:
            by_suffix[suffix] += 1
            total_bytes += size
        return {"file_count": len(rows), "byte_count": total_bytes, "by_suffix": by_suffix}

    package_summary = counts([(suffix, size) for _, suffix, size in package_files])
    runtime_rows = [(suffix, size) for suffix, size in runtime_files.values()]
    runtime_summary = counts(runtime_rows)
    failure_stages: list[str] = []
    failure_reasons: list[str] = []
    if package_summary["file_count"] > _PACKAGE_IMPORT_FILE_LIMIT:
        failure_stages.append("package_import_custody")
        failure_reasons.append("package_file_limit_exceeded")
    if package_summary["byte_count"] > _RUNTIME_IMPORT_BYTE_LIMIT:
        if "package_import_custody" not in failure_stages:
            failure_stages.append("package_import_custody")
        failure_reasons.append("package_byte_limit_exceeded")
    if runtime_summary["file_count"] > _RUNTIME_IMPORT_FILE_LIMIT:
        failure_stages.append("runtime_import_custody")
        failure_reasons.append("runtime_file_limit_exceeded")
    if runtime_summary["byte_count"] > _RUNTIME_IMPORT_BYTE_LIMIT:
        if "runtime_import_custody" not in failure_stages:
            failure_stages.append("runtime_import_custody")
        failure_reasons.append("runtime_byte_limit_exceeded")
    return {
        "schema_version": _IMPORT_INVENTORY_SCHEMA,
        "status": "limit_exceeded" if failure_stages else "within_limits",
        "failure_stages": failure_stages,
        "failure_reasons": failure_reasons,
        "package_imports": {
            **package_summary,
            "file_limit": _PACKAGE_IMPORT_FILE_LIMIT,
            "byte_limit": _RUNTIME_IMPORT_BYTE_LIMIT,
        },
        "runtime_imports": {
            **runtime_summary,
            "file_limit": _RUNTIME_IMPORT_FILE_LIMIT,
            "byte_limit": _RUNTIME_IMPORT_BYTE_LIMIT,
            "root_count": len(runtime_roots),
        },
    }


def _venv_command(interpreter: Path, environment: Path, *, without_pip: bool) -> list[str]:
    command = [str(interpreter), "-m", "venv"]
    if without_pip:
        command.append("--without-pip")
    command.append(str(environment))
    return command


def _cpython_configure_command(python_prefix: Path, openssl_prefix: Path) -> list[str]:
    return [
        "./configure",
        f"--prefix={python_prefix}",
        f"--with-openssl={openssl_prefix}",
        "--with-openssl-rpath=no",
        "--with-ensurepip=no",
        "--disable-test-modules",
    ]


def _offline_install_command(
    installer_python: Path, runtime_python: Path, wheelhouse: Path, project_wheel: Path
) -> list[str]:
    return [
        str(installer_python),
        "-m",
        "pip",
        "--python",
        str(runtime_python),
        "install",
        "--no-index",
        "--only-binary=:all:",
        "--find-links",
        str(wheelhouse),
        "--disable-pip-version-check",
        "--no-compile",
        str(project_wheel),
    ]


def _remove_owned_installer_venv(installer_root: Path, prefix: Path) -> None:
    try:
        protected_prefix = prefix.resolve(strict=True)
    except OSError as error:
        raise ValueError("installer_environment_prefix_unavailable") from error
    expected_root = prefix / "installer-venv"
    if installer_root != expected_root or installer_root.is_symlink():
        raise ValueError("installer_environment_identity_invalid")
    if not installer_root.exists():
        return
    try:
        resolved_root = installer_root.resolve(strict=True)
    except OSError as error:
        raise ValueError("installer_environment_root_unavailable") from error
    if resolved_root.parent != protected_prefix or not resolved_root.is_dir():
        raise ValueError("installer_environment_containment_invalid")
    for directory, children, leaves in os.walk(resolved_root, followlinks=False):
        base = Path(directory)
        for name in children:
            child = base / name
            if child.is_symlink() or not child.is_dir():
                raise ValueError("installer_environment_contains_indirect_entry")
        for name in leaves:
            child = base / name
            if child.is_symlink():
                try:
                    resolved_child = child.resolve(strict=True)
                except OSError as error:
                    raise ValueError("installer_environment_contains_indirect_entry") from error
                if (
                    not resolved_child.is_relative_to(protected_prefix)
                    or not resolved_child.is_file()
                ):
                    raise ValueError("installer_environment_contains_indirect_entry")
            elif not child.is_file():
                raise ValueError("installer_environment_contains_indirect_entry")
    try:
        shutil.rmtree(resolved_root)
    except OSError as error:
        raise ValueError("installer_environment_cleanup_failed") from error
    if installer_root.exists() or installer_root.is_symlink():
        raise ValueError("installer_environment_cleanup_incomplete")


def _install_offline_wheel(
    interpreter: Path,
    installer_root: Path,
    runtime_python: Path,
    wheelhouse: Path,
    project_wheel: Path,
    prefix: Path,
    *,
    cwd: Path,
    env: dict[str, str],
) -> str:
    if installer_root != prefix / "installer-venv":
        raise ValueError("installer_environment_identity_invalid")
    installer_python = installer_root / "bin" / "python"
    try:
        if installer_root.exists() or installer_root.is_symlink():
            raise ValueError("installer_environment_path_not_fresh")
        _run(
            _venv_command(interpreter, installer_root, without_pip=False),
            cwd=cwd,
            env=env,
            timeout=120,
        )
        return _run(
            _offline_install_command(installer_python, runtime_python, wheelhouse, project_wheel),
            cwd=cwd,
            env=env,
            timeout=300,
        )
    finally:
        _remove_owned_installer_venv(installer_root, prefix)


def _download(url: str, target: Path, expected: str, limit: int) -> dict[str, object]:
    request = urllib.request.Request(
        url, headers={"User-Agent": "BlueFire-macOS-runtime-qualification"}
    )
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as output:
        if response.status != 200:
            raise ValueError("An official runtime source download did not return HTTP 200.")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > limit:
                raise ValueError("An official runtime source exceeded its fixed size limit.")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("An official runtime source failed its pinned SHA-256 check.")
    return {"url": url, "sha256": expected, "bytes": count}


def stage(args: argparse.Namespace) -> None:
    stage_root = Path(args.stage_root).resolve()
    if not stage_root.is_absolute() or stage_root.exists():
        raise ValueError("The unique runtime staging directory must not already exist.")
    stage_root.mkdir(mode=0o700, parents=True)
    sources = stage_root / "sources"
    wheelhouse = stage_root / "wheelhouse"
    sources.mkdir(mode=0o700)
    wheelhouse.mkdir(mode=0o700)

    python_tar = sources / "Python-3.11.18.tgz"
    openssl_tar = sources / "openssl-3.5.9.tar.gz"
    python_source = _download(PYTHON_URL, python_tar, PYTHON_SHA256, MAX_SOURCE_BYTES)
    openssl_source = _download(OPENSSL_URL, openssl_tar, OPENSSL_SHA256, MAX_SOURCE_BYTES)

    wheel = Path(args.wheel).resolve(strict=True)
    if wheel.suffix != ".whl" or not wheel.is_file() or wheel.is_symlink():
        raise ValueError("Exactly one built project wheel is required.")
    wheel_digest, wheel_bytes = _hash(wheel, MAX_WHEEL_BYTES)
    inspection = json.loads(Path(args.inspection).read_text(encoding="utf-8"))
    if (
        inspection.get("schema_version") != "bluefire.package-inspection.v1"
        or inspection.get("verified") is not True
        or inspection.get("platform") != "macos"
        or inspection.get("architecture") != "aarch64"
        or inspection.get("wheel") != wheel.name
        or inspection.get("wheel_sha256") != wheel_digest
    ):
        raise ValueError("The wheel does not match the passing macOS arm64 package inspection.")
    with zipfile.ZipFile(wheel) as archive:
        candidates = [
            name
            for name in archive.namelist()
            if name == "bluefire/_build_info.json"
            or (".data/" in name and name.endswith("/bluefire/_build_info.json"))
        ]
        if len(candidates) != 1:
            raise ValueError("The exact wheel has no unique committed source identity.")
        build_info = json.loads(archive.read(candidates[0]))
        if build_info.get("source_provenance") != "git_archive" or not build_info.get(
            "source_revision"
        ):
            raise ValueError("The wheel is not bound to an exact committed source archive.")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "--dest",
            str(wheelhouse),
            str(wheel),
        ],
        check=True,
        timeout=300,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(stage_root)},
    )
    wheels: list[dict[str, object]] = []
    entries = sorted(wheelhouse.iterdir(), key=lambda path: path.name)
    if not entries or len(entries) > MAX_FILES:
        raise ValueError("The resolved binary wheelhouse is empty or exceeds its fixed file limit.")
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix != ".whl":
            raise ValueError("The staged dependency set contains a non-wheel entry.")
        digest, size = _hash(path, MAX_WHEEL_BYTES)
        wheels.append({"name": path.name, "sha256": digest, "bytes": size})
    project_wheels = [item for item in wheels if item["sha256"] == wheel_digest]
    if len(project_wheels) != 1 or project_wheels[0]["bytes"] != wheel_bytes:
        raise ValueError("The exact project wheel is not present in the dependency manifest.")
    manifest = {
        "schema_version": "bluefire.macos-protected-python-stage.v1",
        "python": {"version": PYTHON_VERSION, **python_source},
        "openssl": {"version": OPENSSL_VERSION, **openssl_source},
        "wheelhouse": wheels,
        "wheelhouse_count": len(wheels),
        "wheel": {
            "name": wheel.name,
            "sha256": wheel_digest,
            "source_revision": build_info["source_revision"],
        },
    }
    manifest_path = stage_root / "stage-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(manifest_path, 0o600)
    print(
        json.dumps(
            {
                "status": "staged",
                "manifest_sha256": _hash(manifest_path, 1024 * 1024)[0],
                "wheel_count": len(wheels),
            }
        )
    )


def _run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        output = error.stdout if isinstance(error.stdout, str) else ""
        raise RuntimeError(
            f"Protected build command failed ({error.returncode}): {command[0]}; tail={output[-700:]}"
        ) from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Protected build command exceeded its {timeout}s deadline: {command[0]}"
        ) from None
    return completed.stdout[-12000:]


def install(args: argparse.Namespace) -> None:
    if os.geteuid() != 0 or platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Protected runtime installation requires root on macOS arm64.")
    version = platform.mac_ver()[0]
    if not version.startswith("26."):
        raise ValueError("Protected runtime installation requires the macOS 26 hosted runner.")

    stage_root = Path(args.stage_root).resolve(strict=True)
    prefix = Path(args.prefix)
    if not re.fullmatch(r"[0-9]+-[0-9]+", args.run_identity):
        raise ValueError("The protected runtime identity must be a numeric hosted-run pair.")
    if not prefix.is_absolute() or prefix.exists() or prefix.is_symlink():
        raise ValueError("The unique protected prefix must be absent and absolute.")
    if str(prefix) != f"/private/var/db/bluefire-macos-runtime/{args.run_identity}":
        raise ValueError("The protected prefix is outside the reviewed per-run location.")
    manifest_path = stage_root / "stage-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("The runtime stage manifest is missing or indirect.")
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if manifest.get("schema_version") != "bluefire.macos-protected-python-stage.v1":
        raise ValueError("The runtime stage manifest has an unsupported schema.")
    if (
        manifest.get("python", {}).get("sha256") != PYTHON_SHA256
        or manifest.get("openssl", {}).get("sha256") != OPENSSL_SHA256
    ):
        raise ValueError("Pinned runtime source identities do not match the reviewed values.")
    wheels = manifest.get("wheelhouse")
    if not isinstance(wheels, list) or not 1 <= len(wheels) <= MAX_FILES:
        raise ValueError("The staged dependency manifest is invalid.")
    wheel_identity = manifest.get("wheel")
    package_rows = [
        row
        for row in wheels
        if isinstance(row, dict) and row.get("name", "").startswith("bluefire_nexus-")
    ]
    if (
        not isinstance(wheel_identity, dict)
        or len(package_rows) != 1
        or package_rows[0].get("name") != wheel_identity.get("name")
        or package_rows[0].get("sha256") != wheel_identity.get("sha256")
        or not isinstance(wheel_identity.get("source_revision"), str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", wheel_identity["source_revision"])
        or manifest.get("wheelhouse_count") != len(wheels)
    ):
        raise ValueError(
            "The exact project wheel identity is inconsistent with its staged dependency manifest."
        )
    wheelhouse = stage_root / "wheelhouse"
    staged_entries = sorted(wheelhouse.iterdir(), key=lambda path: path.name)
    if len(staged_entries) != len(wheels):
        raise ValueError("The wheelhouse differs from its pinned pre-promotion manifest.")
    rows_by_name = _wheel_rows_by_name(wheels)
    for path in staged_entries:
        row = rows_by_name.get(path.name)
        if row is None:
            raise ValueError("A staged dependency is absent from its pinned manifest.")
        if path.name != row.get("name") or path.is_symlink() or not path.is_file():
            raise ValueError("A staged dependency changed before protected promotion.")
        if _hash(path, MAX_WHEEL_BYTES) != (row.get("sha256"), row.get("bytes")):
            raise ValueError("A staged dependency hash changed before protected promotion.")

    parent = prefix.parent
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if (
        parent.is_symlink()
        or parent.stat().st_uid != 0
        or stat.S_IMODE(parent.stat().st_mode) & 0o022
    ):
        raise ValueError("The protected runtime parent is not root-owned and non-writable.")
    prefix.mkdir(mode=0o755)
    os.chown(prefix, 0, 0)
    build = prefix / "build"
    protected_stage = prefix / "stage"
    home = prefix / "home"
    temp = prefix / "tmp"
    for directory in (build, protected_stage, home, temp):
        directory.mkdir(mode=0o700)
        os.chown(directory, 0, 0)
    protected_wheels = protected_stage / "wheelhouse"
    protected_wheels.mkdir(mode=0o700)
    _promote_wheels(staged_entries, rows_by_name, protected_wheels)

    for name in ("Python-3.11.18.tgz", "openssl-3.5.9.tar.gz"):
        source = stage_root / "sources" / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("An official runtime source archive is missing or indirect.")
        expected = PYTHON_SHA256 if name.startswith("Python") else OPENSSL_SHA256
        if _hash(source, MAX_SOURCE_BYTES)[0] != expected:
            raise ValueError("An official runtime source archive failed its pinned digest.")
        destination = protected_stage / name
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o400)
        os.chown(destination, 0, 0)
        if _hash(destination, MAX_SOURCE_BYTES)[0] != expected:
            raise ValueError("An official runtime source changed during protected promotion.")
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_sha256:
        raise ValueError("The runtime input manifest changed during protected promotion.")

    openssl_src = build / "openssl-src"
    python_src = build / "python-src"
    openssl_src.mkdir(mode=0o700)
    python_src.mkdir(mode=0o700)
    with tarfile.open(protected_stage / "openssl-3.5.9.tar.gz", "r:gz") as archive:
        archive.extractall(openssl_src, filter="data")
    with tarfile.open(protected_stage / "Python-3.11.18.tgz", "r:gz") as archive:
        archive.extractall(python_src, filter="data")
    openssl_tree = next(openssl_src.iterdir())
    python_tree = next(python_src.iterdir())
    openssl_prefix = prefix / "openssl"
    python_prefix = prefix / "cpython"
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(temp),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": "",
        "CFLAGS": "-fno-common",
        "LDFLAGS": "",
    }
    configure_out = _run(
        [
            "./Configure",
            "darwin64-arm64-cc",
            "no-shared",
            "no-tests",
            f"--prefix={openssl_prefix}",
            f"--openssldir={openssl_prefix / 'ssl'}",
        ],
        cwd=openssl_tree,
        env=env,
        timeout=180,
    )
    openssl_build = _run(["make", "-j2"], cwd=openssl_tree, env=env, timeout=900)
    openssl_install = _run(["make", "install_sw"], cwd=openssl_tree, env=env, timeout=300)
    python_configure = _run(
        _cpython_configure_command(python_prefix, openssl_prefix),
        cwd=python_tree,
        env=env,
        timeout=240,
    )
    python_build = _run(["make", "-j2"], cwd=python_tree, env=env, timeout=1200)
    python_install = _run(["make", "altinstall"], cwd=python_tree, env=env, timeout=300)
    interpreter = python_prefix / "bin" / "python3.11"
    venv_python = prefix / "venv" / "bin" / "python"
    _run(
        _venv_command(interpreter, prefix / "venv", without_pip=True),
        cwd=prefix,
        env=env,
        timeout=120,
    )
    installer_root = prefix / "installer-venv"
    project_wheel = protected_wheels / next(
        row["name"] for row in wheels if row["name"].startswith("bluefire_nexus-")
    )
    install_output = _install_offline_wheel(
        interpreter,
        installer_root,
        venv_python,
        protected_wheels,
        project_wheel,
        prefix,
        cwd=prefix,
        env=env,
    )
    _make_runtime_readable(prefix, (python_prefix, prefix / "venv"))
    identity = _run(
        [
            str(venv_python),
            "-I",
            "-c",
            "import json,platform,ssl,sys; import bluefire; print(json.dumps({'version':list(sys.version_info[:3]),'machine':platform.machine(),'openssl':ssl.OPENSSL_VERSION,'bluefire':bluefire.__file__},sort_keys=True))",
        ],
        cwd=prefix,
        env=env,
        timeout=30,
    )
    identity_row = json.loads(identity.strip().splitlines()[-1])
    if (
        identity_row.get("version") != [3, 11, 18]
        or identity_row.get("machine") != "arm64"
        or not identity_row.get("openssl", "").startswith("OpenSSL 3.5.9")
    ):
        raise ValueError(
            "The built isolated runtime does not match the exact qualification target."
        )
    import_inventory = _import_custody_inventory(venv_python, prefix)
    if import_inventory["status"] != "within_limits":
        raise ImportInventoryLimitError(import_inventory)
    audit = _audit_dynamic_links(prefix)
    reports = {
        "schema_version": "bluefire.macos-protected-python-build.v1",
        "status": "built",
        "run_identity": args.run_identity,
        "source_manifest_sha256": manifest_sha256,
        "python_source_sha256": PYTHON_SHA256,
        "openssl_source_sha256": OPENSSL_SHA256,
        "wheel": manifest.get("wheel"),
        "wheelhouse": wheels,
        "interpreter": identity_row,
        "interpreter_sha256": _hash(venv_python.resolve(strict=True), 256 * 1024 * 1024)[0],
        "prefix": str(prefix),
        "dynamic_link_audit": audit,
        "import_custody_inventory": import_inventory,
        "build_commands": [
            {
                "name": "openssl-configure",
                "status": "passed",
                "output_sha256": hashlib.sha256(configure_out.encode()).hexdigest(),
            },
            {
                "name": "openssl-build",
                "status": "passed",
                "output_sha256": hashlib.sha256(openssl_build.encode()).hexdigest(),
            },
            {
                "name": "openssl-install",
                "status": "passed",
                "output_sha256": hashlib.sha256(openssl_install.encode()).hexdigest(),
            },
            {
                "name": "cpython-configure",
                "status": "passed",
                "output_sha256": hashlib.sha256(python_configure.encode()).hexdigest(),
            },
            {
                "name": "cpython-build",
                "status": "passed",
                "output_sha256": hashlib.sha256(python_build.encode()).hexdigest(),
            },
            {
                "name": "cpython-install",
                "status": "passed",
                "output_sha256": hashlib.sha256(python_install.encode()).hexdigest(),
            },
            {
                "name": "wheel-install",
                "status": "passed",
                "output_sha256": hashlib.sha256(install_output.encode()).hexdigest(),
            },
        ],
    }
    receipt_path = Path(args.report)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(reports, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o644)
    print(
        json.dumps(
            {
                "status": "built",
                "interpreter_sha256": reports["interpreter_sha256"],
                "wheel_count": len(wheels),
            }
        )
    )


def _wheel_rows_by_name(wheels: list[object]) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for row in wheels:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("name"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))
            or not isinstance(row.get("bytes"), int)
            or row["bytes"] <= 0
            or row["name"] in rows
        ):
            raise ValueError("The staged dependency manifest contains ambiguous wheel identities.")
        rows[row["name"]] = row
    return rows


def _promote_wheels(
    staged_entries: list[Path],
    rows_by_name: dict[str, dict[str, object]],
    protected_wheels: Path,
) -> None:
    if {path.name for path in staged_entries} != set(rows_by_name):
        raise ValueError("The wheelhouse differs from its pinned pre-promotion manifest.")
    for path in staged_entries:
        row = rows_by_name[path.name]
        destination = protected_wheels / path.name
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o400)
        os.chown(destination, 0, 0)
        if _hash(destination, MAX_WHEEL_BYTES) != (row["sha256"], row["bytes"]):
            raise ValueError("A dependency changed during protected promotion.")


def _first_rpath_candidate(
    rpaths: list[str], suffix: str, loader_file: Path, executable_dir: Path
) -> Path | None:
    return _resolve_rpath_candidate(
        rpaths,
        suffix,
        loader_file,
        executable_dir,
        protected_prefix=loader_file.parent.parent.parent,
    )[0]


def _resolve_rpath_candidate(
    rpaths: list[str],
    suffix: str,
    loader_file: Path,
    executable_dir: Path,
    *,
    protected_prefix: Path,
) -> tuple[Path | None, list[dict[str, object]], int | None]:
    diagnostics: list[dict[str, object]] = []
    for index, rpath in enumerate(rpaths):
        if rpath.startswith("@loader_path/"):
            root = (loader_file.parent / rpath.removeprefix("@loader_path/")).resolve()
            origin = "loader_path"
        elif rpath.startswith("@executable_path/"):
            root = (executable_dir / rpath.removeprefix("@executable_path/")).resolve()
            origin = "executable_path"
        else:
            root = Path(rpath).resolve()
            origin = "absolute" if Path(rpath).is_absolute() else "relative"
        candidate = (root / suffix).resolve()
        exists = candidate.exists()
        if len(diagnostics) < MAX_RPATH_CANDIDATES:
            diagnostics.append(
                {
                    "index": index,
                    "origin": origin,
                    "candidate": _diagnostic_path_label(candidate, protected_prefix),
                    "exists": exists,
                }
            )
        # Only a real filesystem candidate establishes @rpath ordering. A
        # system-looking but absent path cannot prove what dyld will resolve.
        if exists:
            return candidate, diagnostics, index
    return None, diagnostics, None


def _audit_dynamic_links(prefix: Path) -> dict[str, object]:
    candidates = [prefix / "cpython" / "bin" / "python3.11"]
    for root in (prefix / "venv" / "lib", prefix / "cpython" / "lib"):
        if root.exists():
            candidates.extend(
                path
                for path in root.rglob("*")
                if path.suffix in {".so", ".dylib", ".bundle"} and path.is_file()
            )
    if not candidates:
        raise ValueError("No protected Python runtime files were found for dynamic-link review.")
    reviewed = 0
    link_diagnostics: list[dict[str, object]] = []
    link_violation_count = 0
    for path in candidates:
        if not path.is_file():
            continue
        details = path.stat()
        if details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError(
                "A protected runtime library is not root-owned and immutable to ordinary users."
            )
        resolved_file = path.resolve(strict=True)
        if not resolved_file.is_relative_to(prefix):
            raise ValueError("A protected runtime library resolves outside its isolated prefix.")
        load_commands = subprocess.run(
            ["/usr/bin/otool", "-l", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=True,
        ).stdout
        rpaths = _parse_lc_rpaths(load_commands)
        for dependency in _parse_lc_dylib_dependencies(load_commands):
            if dependency.startswith("/") and _is_sip_system_path(dependency):
                # Dyld shared-cache libraries need not have on-disk files.
                continue
            choices: list[Path] = []
            rpath_candidates: list[dict[str, object]] = []
            selected_rpath_index: int | None = None
            if dependency.startswith("@loader_path/"):
                choices = [
                    (resolved_file.parent / dependency.removeprefix("@loader_path/")).resolve()
                ]
            elif dependency.startswith("@executable_path/"):
                choices = [
                    (
                        (prefix / "cpython" / "bin") / dependency.removeprefix("@executable_path/")
                    ).resolve()
                ]
            elif dependency.startswith("@rpath/"):
                suffix = dependency.removeprefix("@rpath/")
                candidate, rpath_candidates, selected_rpath_index = _resolve_rpath_candidate(
                    rpaths,
                    suffix,
                    resolved_file,
                    prefix / "cpython" / "bin",
                    protected_prefix=prefix,
                )
                if candidate is not None:
                    choices = [candidate]
            else:
                choices = [Path(dependency).resolve()]
            if len(choices) != 1:
                link_violation_count += 1
                if len(link_diagnostics) < MAX_LINK_DIAGNOSTICS:
                    link_diagnostics.append(
                        _link_diagnostic(
                            path,
                            dependency,
                            "unresolved_dependency",
                            prefix,
                            rpath_candidates=rpath_candidates,
                            selected_rpath_index=selected_rpath_index,
                        )
                    )
                continue
            choice = choices[0]
            # System dylibs are often present only in the dyld shared cache,
            # so an approved absolute SIP install name need not exist as a file.
            if _is_sip_system_path(choice.as_posix()):
                continue
            if not choice.exists() or not choice.is_file():
                link_violation_count += 1
                if len(link_diagnostics) < MAX_LINK_DIAGNOSTICS:
                    link_diagnostics.append(
                        _link_diagnostic(
                            path,
                            dependency,
                            "missing_dependency",
                            prefix,
                            candidate=choice,
                            rpath_candidates=rpath_candidates,
                            selected_rpath_index=selected_rpath_index,
                        )
                    )
                continue
            resolved_choice = choice.resolve(strict=True)
            if resolved_choice.is_relative_to(prefix):
                dependency_stat = resolved_choice.stat()
                if dependency_stat.st_uid != 0 or dependency_stat.st_mode & 0o022:
                    link_violation_count += 1
                    if len(link_diagnostics) < MAX_LINK_DIAGNOSTICS:
                        link_diagnostics.append(
                            _link_diagnostic(
                                path,
                                dependency,
                                "protected_dependency_mutable",
                                prefix,
                                candidate=resolved_choice,
                                rpath_candidates=rpath_candidates,
                                selected_rpath_index=selected_rpath_index,
                            )
                        )
            elif not str(resolved_choice).startswith(("/usr/lib/", "/System/Library/")):
                # For @rpath, this is the first existing loader candidate; a
                # later safe rpath cannot mask an earlier unprotected file.
                link_violation_count += 1
                if len(link_diagnostics) < MAX_LINK_DIAGNOSTICS:
                    link_diagnostics.append(
                        _link_diagnostic(
                            path,
                            dependency,
                            "outside_prefix_and_sip",
                            prefix,
                            candidate=resolved_choice,
                            rpath_candidates=rpath_candidates,
                            selected_rpath_index=selected_rpath_index,
                        )
                    )
        reviewed += 1
    if link_violation_count:
        raise DynamicLinkAuditError(
            link_diagnostics,
            truncated=link_violation_count > len(link_diagnostics),
        )
    return {"status": "closed", "files_reviewed": reviewed, "external_dependencies": []}


def _parse_lc_rpaths(output: str) -> list[str]:
    rpaths: list[str] = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for candidate in lines[index + 1 : index + 5]:
                pieces = candidate.strip().split()
                if pieces and pieces[0] == "path" and len(pieces) > 1:
                    rpaths.append(pieces[1])
                    break
    return rpaths


_DYLIB_DEPENDENCY_COMMANDS = frozenset(
    {
        "cmd LC_LOAD_DYLIB",
        "cmd LC_LOAD_WEAK_DYLIB",
        "cmd LC_REEXPORT_DYLIB",
        "cmd LC_LOAD_UPWARD_DYLIB",
        "cmd LC_LAZY_LOAD_DYLIB",
    }
)


def _parse_lc_dylib_dependencies(output: str) -> list[str]:
    """Read dependent install names, excluding LC_ID_DYLIB by command role."""
    dependencies: list[str] = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() not in _DYLIB_DEPENDENCY_COMMANDS:
            continue
        dependency = None
        for candidate in lines[index + 1 :]:
            value = candidate.strip()
            if (
                value.startswith("Load command ")
                or value.startswith("cmd ")
                or re.search(r"\(architecture [^)]+\):$", value)
            ):
                break
            if value.startswith("name "):
                dependency = value[len("name ") :]
                offset = re.search(r"\s+\(offset [0-9]+\)$", dependency)
                if offset is not None:
                    dependency = dependency[: offset.start()]
                dependency = dependency.strip()
                break
        if not dependency:
            raise ValueError("A Mach-O dynamic-library load command has no install name.")
        dependencies.append(dependency)
    return dependencies


def _diagnostic_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", value)[:MAX_DIAGNOSTIC_LABEL]


def _diagnostic_path_label(path: Path, prefix: Path) -> str:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved.is_relative_to(prefix):
        return "prefix/" + _diagnostic_component(resolved.relative_to(prefix).as_posix())
    if _is_sip_system_path(path.as_posix()) or _is_sip_system_path(resolved.as_posix()):
        return "sip/" + _diagnostic_component(path.name)
    category = "external" if path.exists() else "missing"
    return category + "/" + _diagnostic_component(path.name)


def _diagnostic_dependency_label(dependency: str, prefix: Path) -> str:
    for kind in ("@rpath/", "@loader_path/", "@executable_path/"):
        if dependency.startswith(kind):
            return kind + _diagnostic_component(Path(dependency).name)
    if dependency.startswith("/"):
        return _diagnostic_path_label(Path(dependency), prefix)
    return "relative/" + _diagnostic_component(Path(dependency).name)


def _link_diagnostic(
    image: Path,
    dependency: str,
    reason: str,
    prefix: Path,
    *,
    candidate: Path | None = None,
    rpath_candidates: list[dict[str, object]] | None = None,
    selected_rpath_index: int | None = None,
) -> dict[str, object]:
    candidates = rpath_candidates or []
    return {
        "image": _diagnostic_component(image.name),
        "dependency": _diagnostic_dependency_label(dependency, prefix),
        "reason": reason,
        "candidate": _diagnostic_path_label(candidate, prefix) if candidate is not None else None,
        "selected_rpath_index": selected_rpath_index,
        "rpath_candidates": candidates[:MAX_RPATH_CANDIDATES],
        "rpath_candidates_limit_reached": len(candidates) >= MAX_RPATH_CANDIDATES,
    }


def _failure_document(error: BaseException) -> dict[str, object]:
    failure: dict[str, object] = {
        "schema_version": "bluefire.macos-protected-python-build.v1",
        "status": "failed",
        "error_type": type(error).__name__,
        "message": str(error)[:1200],
    }
    if isinstance(error, DynamicLinkAuditError):
        failure["dynamic_link_diagnostics"] = {
            "schema_version": "bluefire.macos-dynamic-link-diagnostic.v1",
            "violations": error.diagnostics,
            "truncated": error.truncated,
        }
    if isinstance(error, ImportInventoryLimitError):
        failure["import_custody_inventory"] = error.inventory
    return failure


def _is_sip_system_path(path: str) -> bool:
    value = path
    if not value.startswith("/") or posixpath.normpath(value) != value:
        return False
    return value.startswith(("/usr/lib/", "/System/Library/"))


def _make_runtime_readable(prefix: Path, roots: tuple[Path, ...]) -> None:
    runtime_roots = tuple(root.resolve(strict=True) for root in roots)
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("A protected runtime root is missing or indirect.")
        for directory, children, leaves in os.walk(root, followlinks=False):
            base = Path(directory)
            details = base.lstat()
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0:
                raise ValueError("A protected runtime directory is not root-owned.")
            os.chmod(base, 0o755)
            children[:] = sorted(children)
            for name in children + leaves:
                path = base / name
                if path.is_symlink():
                    resolved = path.resolve(strict=True)
                    if not any(
                        resolved.is_relative_to(runtime_root) for runtime_root in runtime_roots
                    ):
                        raise ValueError(
                            "A protected runtime link resolves outside its installed interpreter or venv."
                        )
                    continue
                details = path.lstat()
                if not stat.S_ISREG(details.st_mode) and not stat.S_ISDIR(details.st_mode):
                    raise ValueError(
                        "A protected runtime contains an unsupported filesystem object."
                    )
                if details.st_uid != 0 or details.st_mode & 0o022:
                    raise ValueError(
                        "A protected runtime file is not root-owned and non-writable to ordinary users."
                    )
                if stat.S_ISREG(details.st_mode):
                    mode = stat.S_IMODE(details.st_mode) | 0o044
                    if mode & 0o100:
                        mode |= 0o011
                    os.chmod(path, mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--stage-root", required=True)
    stage_parser.add_argument("--wheel", required=True)
    stage_parser.add_argument("--inspection", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--stage-root", required=True)
    install_parser.add_argument("--prefix", required=True)
    install_parser.add_argument("--run-identity", required=True)
    install_parser.add_argument("--report", required=True)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            stage(args)
        else:
            install(args)
    except (
        OSError,
        ValueError,
        RuntimeError,
        TypeError,
        subprocess.SubprocessError,
        tarfile.TarError,
        json.JSONDecodeError,
    ) as error:
        failure = _failure_document(error)
        if args.command == "install":
            try:
                report = Path(args.report)
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(
                    json.dumps(failure, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                )
                os.chmod(report, 0o644)
            except OSError:
                pass
        print(json.dumps(failure), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
