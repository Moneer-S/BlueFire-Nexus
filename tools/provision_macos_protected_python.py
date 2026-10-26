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
        [
            "./configure",
            f"--prefix={python_prefix}",
            f"--with-openssl={openssl_prefix}",
            "--with-openssl-rpath=no",
        ],
        cwd=python_tree,
        env=env,
        timeout=240,
    )
    python_build = _run(["make", "-j2"], cwd=python_tree, env=env, timeout=1200)
    python_install = _run(["make", "altinstall"], cwd=python_tree, env=env, timeout=300)
    interpreter = python_prefix / "bin" / "python3.11"
    venv_python = prefix / "venv" / "bin" / "python"
    _run([str(interpreter), "-m", "venv", str(prefix / "venv")], cwd=prefix, env=env, timeout=120)
    install_output = _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--find-links",
            str(protected_wheels),
            "--disable-pip-version-check",
            str(
                protected_wheels
                / next(row["name"] for row in wheels if row["name"].startswith("bluefire_nexus-"))
            ),
        ],
        cwd=prefix,
        env=env,
        timeout=300,
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
    for rpath in rpaths:
        if rpath.startswith("@loader_path/"):
            root = (loader_file.parent / rpath.removeprefix("@loader_path/")).resolve()
        elif rpath.startswith("@executable_path/"):
            root = (executable_dir / rpath.removeprefix("@executable_path/")).resolve()
        else:
            root = Path(rpath).resolve()
        candidate = (root / suffix).resolve()
        # Only a real filesystem candidate establishes @rpath ordering. A
        # system-looking but absent path cannot prove what dyld will resolve.
        if candidate.exists():
            return candidate
    return None


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
    external: list[str] = []
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
        rpaths: list[str] = []
        lines = load_commands.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == "cmd LC_RPATH":
                for candidate in lines[index + 1 : index + 5]:
                    pieces = candidate.strip().split()
                    if pieces and pieces[0] == "path" and len(pieces) > 1:
                        rpaths.append(pieces[1])
                        break
        result = subprocess.run(
            ["/usr/bin/otool", "-L", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=True,
        )
        for line in result.stdout.splitlines()[1:]:
            if line.strip().endswith(":") and "(architecture " in line:
                continue
            dependency = line.strip().split(" ", 1)[0]
            if not dependency:
                continue
            if dependency.startswith("/") and _is_sip_system_path(dependency):
                # Dyld shared-cache libraries need not have on-disk files.
                continue
            choices: list[Path] = []
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
                candidate = _first_rpath_candidate(
                    rpaths,
                    suffix,
                    resolved_file,
                    prefix / "cpython" / "bin",
                )
                if candidate is not None:
                    choices = [candidate]
            else:
                choices = [Path(dependency).resolve()]
            if len(choices) != 1:
                external.append(dependency)
                continue
            choice = choices[0]
            # System dylibs are often present only in the dyld shared cache,
            # so an approved absolute SIP install name need not exist as a file.
            if _is_sip_system_path(choice.as_posix()):
                continue
            if not choice.exists() or not choice.is_file():
                external.append(dependency)
                continue
            resolved_choice = choice.resolve(strict=True)
            if resolved_choice.is_relative_to(prefix):
                dependency_stat = resolved_choice.stat()
                if dependency_stat.st_uid != 0 or dependency_stat.st_mode & 0o022:
                    external.append(dependency)
            elif not str(resolved_choice).startswith(("/usr/lib/", "/System/Library/")):
                # For @rpath, this is the first existing loader candidate; a
                # later safe rpath cannot mask an earlier unprotected file.
                external.append(dependency)
        reviewed += 1
    if external:
        raise ValueError(
            "A protected Python dynamic dependency is outside its prefix and SIP paths."
        )
    return {"status": "closed", "files_reviewed": reviewed, "external_dependencies": []}


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
        failure = {
            "schema_version": "bluefire.macos-protected-python-build.v1",
            "status": "failed",
            "error_type": type(error).__name__,
            "message": str(error)[:1200],
        }
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
