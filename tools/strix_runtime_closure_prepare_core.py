"""Orchestration for deterministic Strix Linux runtime closure preparation."""

from __future__ import annotations

import argparse
import os
import platform
import re
import secrets
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from bluefire import strix_worker_fixed_bootstrap as bootstrap_contract
from bluefire import strix_worker_seccomp_bootstrap as lockdown_contract
from tools import build_strix_engine_candidate as candidate
from tools import qualify_strix_runtime_candidate as qualification
from tools.strix_runtime_closure_common import (
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    StrixRuntimeClosurePreparationError,
    _canonical_json,
    _copy_payload,
    _digest_bytes,
    _document_bytes,
    _is_reparse,
    _read_regular,
    _sha256_hex,
    _write_exclusive,
)
from tools.strix_runtime_closure_elf import (
    ELF_SCHEMA,
    LOADER_DESTINATION,
    ElfIdentity,
    _close_elf_dependencies,
    _elf_identity,
)
from tools.strix_runtime_closure_qualification import _load_qualification
from tools.strix_runtime_closure_wheel import (
    WheelEntry,
    WheelPlan,
    _install_wheel,
    _plan_wheel,
)
from tools.strix_runtime_closure_worker import (
    _installed_distributions_ref,
    _require_exact_worker_dependencies,
    _worker_manifest,
)

PREPARATION_SCHEMA = "bluefire.strix-linux-runtime-closure-preparation.v1"
CPYTHON_SOURCE_SCHEMA = "bluefire.strix-cpython-source-closure.v1"
INVENTORY_SCHEMA = "bluefire.strix-linux-runtime-inventory.v1"
SBOM_SCHEMA = "bluefire.strix-linux-runtime-sbom.v1"
TOOL_VERSION = 1
ROOT_NAME = "strix-linux-runtime-root"
PYTHON_VERSION = "3.12.14"
MACHINE = "x86_64"
SETUP_PYTHON_ACTION = "ece7cb06caefa5fff74198d8649806c4678c61a1"
BOOTSTRAP_DESTINATION = "bootstrap/worker.py"
LOCKDOWN_DESTINATION = "bootstrap/worker_lockdown.py"
PREPARATION_NAME = "strix-linux-runtime-preparation-manifest.json"
ELF_NAME = "strix-linux-runtime-elf-dependencies.json"
MAX_FILES = 65_536
MAX_DIRECTORIES = 16_384
MAX_JSON_BYTES = 128 * 1024 * 1024

PRIVATE_DIRECTORIES = (
    "bootstrap",
    "config",
    "dev",
    "etc",
    "home",
    "home/worker",
    "inputs",
    "lib",
    "lib64",
    "run",
    "run/bluefire",
    "runtime",
    "runtime/bin",
    "runtime/lib",
    "runtime/lib/python3.12",
    "runtime/lib/python3.12/lib-dynload",
    "runtime/lib/python3.12/site-packages",
    "tmp",
    "workspace",
)
PRIVATE_MOUNTPOINTS = (
    "config",
    "dev",
    "etc",
    "home/worker",
    "inputs",
    "run/bluefire",
    "tmp",
    "workspace",
)
FORBIDDEN_NAMES = {"sitecustomize.py", "usercustomize.py"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
def _copy_source_file(
    source: Path,
    root: Path,
    relative: str,
    *,
    destinations: dict[str, str],
    mode: int = 0o444,
    allow_symlink: bool = False,
    allowed_roots: Iterable[Path] = (),
) -> dict[str, Any]:
    payload = _read_regular(
        source, allow_symlink=allow_symlink, allowed_roots=allowed_roots
    )
    return _copy_payload(root, relative, payload, mode=mode, destinations=destinations)


def _copy_stdlib(
    source: Path,
    root: Path,
    *,
    destinations: dict[str, str],
    allowed_root: Path,
) -> list[dict[str, Any]]:
    if not source.is_dir() or source.is_symlink():
        raise StrixRuntimeClosurePreparationError("CPython stdlib root is invalid")
    copied: list[dict[str, Any]] = []
    for current, directories, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            item for item in directories if item not in {"site-packages", "__pycache__"}
        )
        for directory in directories:
            details = (current_path / directory).lstat()
            if stat.S_ISLNK(details.st_mode) or _is_reparse(details):
                raise StrixRuntimeClosurePreparationError(
                    "stdlib contains a linked directory"
                )
        for filename in sorted(files):
            if filename.endswith((".pyc", ".pyo", ".pth")) or filename in FORBIDDEN_NAMES:
                if filename.endswith(".pth") or filename in FORBIDDEN_NAMES:
                    raise StrixRuntimeClosurePreparationError(
                        "stdlib contains a startup hook"
                    )
                continue
            source_file = current_path / filename
            relative = (
                "runtime/lib/python3.12/"
                + source_file.relative_to(source).as_posix()
            )
            copied.append(
                _copy_source_file(
                    source_file,
                    root,
                    relative,
                    destinations=destinations,
                    allow_symlink=True,
                    allowed_roots=(allowed_root,),
                )
            )
    return copied


def _inventory(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    directories: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    inodes: set[tuple[int, int]] = set()
    total = 0
    for current, children, names in os.walk(root, followlinks=False):
        parent = Path(current)
        children.sort()
        names.sort()
        for name in children:
            path = parent / name
            details = path.lstat()
            if (
                path.is_symlink()
                or _is_reparse(details)
                or not stat.S_ISDIR(details.st_mode)
            ):
                raise StrixRuntimeClosurePreparationError(
                    "closure contains a linked directory"
                )
            if stat.S_IMODE(details.st_mode) != 0o555:
                raise StrixRuntimeClosurePreparationError(
                    "closure directory is mutable"
                )
            directories.append(
                {"path": path.relative_to(root).as_posix(), "mode": 0o555}
            )
        for name in names:
            path = parent / name
            details = path.lstat()
            if (
                path.is_symlink()
                or _is_reparse(details)
                or not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
            ):
                raise StrixRuntimeClosurePreparationError(
                    "closure contains a linked or special file"
                )
            inode = (details.st_dev, details.st_ino)
            if inode in inodes:
                raise StrixRuntimeClosurePreparationError(
                    "closure contains a hardlink"
                )
            inodes.add(inode)
            relative = path.relative_to(root).as_posix()
            payload = _read_regular(path)
            mode = stat.S_IMODE(details.st_mode)
            expected_mode = (
                0o555
                if relative in {"runtime/bin/python", LOADER_DESTINATION}
                else 0o444
            )
            if mode != expected_mode:
                raise StrixRuntimeClosurePreparationError(
                    "closure file mode is invalid"
                )
            total += len(payload)
            if total > MAX_TOTAL_BYTES:
                raise StrixRuntimeClosurePreparationError(
                    "closure exceeds its aggregate byte bound"
                )
            files.append(
                {
                    "path": relative,
                    "mode": mode,
                    "size": len(payload),
                    "content_digest": _digest_bytes(payload),
                }
            )
    if len(directories) > MAX_DIRECTORIES or len(files) > MAX_FILES:
        raise StrixRuntimeClosurePreparationError(
            "closure member count exceeds its bound"
        )
    return sorted(directories, key=lambda row: row["path"]), sorted(
        files, key=lambda row: row["path"]
    )


def _inventory_document(root: Path) -> dict[str, Any]:
    """Read one bounded inventory for both manifest content and its digest."""
    directories, files = _inventory(root)
    return {
        "schema_version": INVENTORY_SCHEMA,
        "directories": directories,
        "files": files,
        "total_bytes": sum(int(row["size"]) for row in files),
    }


def runtime_inventory_digest(root: Path) -> str:
    """Return the exact canonical inventory digest for a prepared runtime root."""
    return _digest_bytes(_document_bytes(_inventory_document(root)))


def _freeze_directories(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555)
    root.chmod(0o555)


def _wheelhouse(
    qualification_root: Path, receipt: dict[str, Any]
) -> tuple[list[WheelPlan], str]:
    rows = receipt.get("wheelhouse", {}).get("wheels")
    if not isinstance(rows, list) or not rows:
        raise StrixRuntimeClosurePreparationError("wheelhouse receipt is empty")
    root = qualification_root.resolve(strict=True) / qualification.WHEELHOUSE_NAME
    plans: list[WheelPlan] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("filename"), str):
            raise StrixRuntimeClosurePreparationError(
                "wheelhouse receipt row is invalid"
            )
        plan = _plan_wheel(root / row["filename"], str(row.get("sha256", "")))
        if (
            plan.name != row.get("name")
            or plan.version != row.get("version")
            or plan.normalized_name != row.get("normalized_name")
        ):
            raise StrixRuntimeClosurePreparationError("wheelhouse metadata drifted")
        plans.append(plan)
    if len({plan.normalized_name for plan in plans}) != len(plans):
        raise StrixRuntimeClosurePreparationError(
            "wheelhouse has duplicate distributions"
        )
    document = {
        "schema_version": "bluefire.strix-wheelhouse-inventory.v1",
        "wheels": [
            {
                "name": plan.name,
                "version": plan.version,
                "wheel_digest": plan.wheel_digest,
                            "metadata_digest": plan.metadata_digest,
                "record_digest": plan.record_digest,
            }
            for plan in sorted(plans, key=lambda item: item.normalized_name)
        ],
    }
    return plans, _digest_bytes(_document_bytes(document))


def prepare_strix_linux_runtime_closure(
    *,
    qualification_root: Path,
    runtime_root: Path,
    strix_wheel: Path,
    worker_artifact: Path,
    worker_artifact_sha256: str,
    base_python: Path,
    output_root: Path,
    bootstrap_worker: Path = Path(bootstrap_contract.__file__),
    bootstrap_lockdown: Path = Path(lockdown_contract.__file__),
    loader_source: Path = Path("/lib64/ld-linux-x86-64.so.2"),
    system_library_roots: Sequence[Path] = (
        Path("/lib/x86_64-linux-gnu"),
        Path("/usr/lib/x86_64-linux-gnu"),
    ),
) -> dict[str, Any]:
    """Build one new immutable closure bundle and return its canonical refs."""

    if sys.platform != "linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise StrixRuntimeClosurePreparationError(
            "closure assembly requires Linux x86-64"
        )
    output = output_root.resolve(strict=False)
    if output.exists():
        raise StrixRuntimeClosurePreparationError(
            "output root must not already exist"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = (
        output.parent
        / f".{output.name}.staging-{os.getpid()}-{secrets.token_hex(8)}"
    )
    staging.mkdir(mode=0o700)
    try:
        manifest, receipt, refs = _load_qualification(qualification_root)
        runtime = runtime_root.resolve(strict=True)
        python = base_python.resolve(strict=True)
        if not runtime.is_dir() or runtime.is_symlink():
            raise StrixRuntimeClosurePreparationError(
                "qualified runtime root is invalid"
            )
        base = python.parent.parent
        stdlib = base / "lib/python3.12"
        base_library = base / "lib"
        runtime_python = runtime / "bin/python"
        if runtime_python.resolve(strict=True) != python:
            raise StrixRuntimeClosurePreparationError(
                "venv interpreter is not the supplied setup-python interpreter"
            )
        interpreter_payload = _read_regular(
            python, MAX_FILE_BYTES, allow_empty=False
        )
        interpreter_sha256 = _sha256_hex(interpreter_payload)
        python_receipt = receipt.get("python", {})
        if (
            python_receipt.get("build_executable_sha256") != interpreter_sha256
            or python_receipt.get("runtime_interpreter", {}).get("sha256")
            != interpreter_sha256
        ):
            raise StrixRuntimeClosurePreparationError(
                "CPython interpreter differs from qualification"
            )
        strix_expected = str(
            manifest.get("candidate", {}).get("wheel", {}).get("sha256", "")
        )
        strix_plan = _plan_wheel(strix_wheel, strix_expected)
        if strix_plan.normalized_name != "strix-agent":
            raise StrixRuntimeClosurePreparationError(
                "candidate wheel is not Strix"
            )
        worker_plan = _plan_wheel(worker_artifact, worker_artifact_sha256)
        worker_manifest, worker_manifest_digest = _worker_manifest(worker_plan)
        dependency_plans, wheelhouse_ref = _wheelhouse(
            qualification_root, receipt
        )
        _require_exact_worker_dependencies(dependency_plans, strix_plan)
        installed_distributions_ref = _installed_distributions_ref(
            (*dependency_plans, strix_plan, worker_plan)
        )

        bootstrap_payload = _read_regular(
            bootstrap_worker, MAX_FILE_BYTES, allow_empty=False
        )
        lockdown_payload = _read_regular(
            bootstrap_lockdown, MAX_FILE_BYTES, allow_empty=False
        )
        if (
            _digest_bytes(lockdown_payload)
            != bootstrap_contract.LOCKDOWN_SOURCE_DIGEST
            or bootstrap_contract.POLICY_DIGEST
            != lockdown_contract.POLICY_DIGEST
            or bootstrap_contract.LOCKDOWN_PATH
            != "/bootstrap/worker_lockdown.py"
            or bootstrap_contract.RUNTIME_SITE_PACKAGES
            != "/runtime/lib/python3.12/site-packages"
            or bootstrap_contract.CONTROLLED_WORKER_MODULE
            != "bluefire.strix_controlled_installed_worker"
        ):
            raise StrixRuntimeClosurePreparationError(
                "worker bootstrap does not bind the exact lockdown policy"
            )

        root = staging / ROOT_NAME
        root.mkdir(mode=0o700)
        for relative in PRIVATE_DIRECTORIES:
            root.joinpath(*PurePosixPath(relative).parts).mkdir(
                mode=0o700, parents=True, exist_ok=True
            )
        destinations: dict[str, str] = {}
        bootstrap_row = _copy_payload(
            root,
            BOOTSTRAP_DESTINATION,
            bootstrap_payload,
            destinations=destinations,
        )
        lockdown_row = _copy_payload(
            root,
            LOCKDOWN_DESTINATION,
            lockdown_payload,
            destinations=destinations,
        )
        cpython_rows = [
            _copy_payload(
                root,
                "runtime/bin/python",
                interpreter_payload,
                mode=0o555,
                destinations=destinations,
            ),
            _copy_source_file(
                base_library / "libpython3.12.so.1.0",
                root,
                "runtime/lib/libpython3.12.so.1.0",
                destinations=destinations,
                allow_symlink=True,
                allowed_roots=(base,),
            ),
        ]
        cpython_rows.extend(
            _copy_stdlib(
                stdlib, root, destinations=destinations, allowed_root=base
            )
        )
        sha2_rows = [
            row
            for row in cpython_rows
            if "/lib-dynload/_sha2." in row["path"]
        ]
        ctypes_rows = [
            row
            for row in cpython_rows
            if "/lib-dynload/_ctypes." in row["path"]
        ]
        if len(sha2_rows) != 1 or len(ctypes_rows) != 1:
            raise StrixRuntimeClosurePreparationError(
                "CPython closure lacks exact _sha2 or _ctypes extension identity"
            )

        qualified_cli_payload = _read_regular(
            runtime / "bin/strix", 8 * 1024 * 1024, allow_empty=False
        )
        qualified_cli_receipt = receipt.get("strix", {}).get("cli", {})
        if (
            qualified_cli_receipt.get("path") != "bin/strix"
            or qualified_cli_receipt.get("sha256")
            != _sha256_hex(qualified_cli_payload)
            or qualified_cli_receipt.get("size") != len(qualified_cli_payload)
        ):
            raise StrixRuntimeClosurePreparationError(
                "qualified Strix console script differs from its receipt"
            )
        cli_lines = qualified_cli_payload.splitlines(keepends=True)
        if (
            not cli_lines
            or cli_lines[0] != f"#!{runtime_python}\n".encode()
            or b"from strix.interface.main import main"
            not in qualified_cli_payload
        ):
            raise StrixRuntimeClosurePreparationError(
                "qualified Strix console script is not the reviewed entry point"
            )
        cli_row = _copy_payload(
            root,
            "runtime/bin/strix",
            b"#!/runtime/bin/python\n" + b"".join(cli_lines[1:]),
            destinations=destinations,
        )

        source_site_packages = runtime / "lib/python3.12/site-packages"
        site_packages = root / "runtime/lib/python3.12/site-packages"
        sbom_distributions: list[dict[str, Any]] = []
        for plan in sorted(
            dependency_plans, key=lambda item: item.normalized_name
        ):
            installed = _install_wheel(
                plan,
                site_packages,
                destinations=destinations,
                source_site_packages=source_site_packages,
            )
            sbom_distributions.append(_sbom_row(plan, len(installed)))
        strix_installed = _install_wheel(
            strix_plan,
            site_packages,
            destinations=destinations,
            source_site_packages=source_site_packages,
        )
        worker_installed = _install_wheel(
            worker_plan,
            site_packages,
            destinations=destinations,
            source_site_packages=None,
        )
        sbom_distributions.extend(
            (
                _sbom_row(strix_plan, len(strix_installed)),
                _sbom_row(worker_plan, len(worker_installed)),
            )
        )

        elf_document = _close_elf_dependencies(
            root,
            base_library_root=base_library,
            system_library_roots=system_library_roots,
            loader_source=loader_source,
            destinations=destinations,
        )
        elf_payload = _document_bytes(elf_document)
        elf_ref = _digest_bytes(elf_payload)
        _write_exclusive(staging / ELF_NAME, elf_payload)
        _freeze_directories(root)
        inventory_document = _inventory_document(root)
        directories = inventory_document["directories"]
        files = inventory_document["files"]
        inventory_digest = _digest_bytes(_document_bytes(inventory_document))
        cpython_document = {
            "schema_version": CPYTHON_SOURCE_SCHEMA,
            "python_version": PYTHON_VERSION,
            "machine": MACHINE,
            "setup_python_action": SETUP_PYTHON_ACTION,
            "files": sorted(cpython_rows, key=lambda row: row["path"]),
            "sha2_extension": sha2_rows[0],
            "ctypes_extension": ctypes_rows[0],
            "setup_python_archive_identity_available": False,
            "source_paths_redacted": True,
        }
        cpython_source_closure_ref = _digest_bytes(
            _document_bytes(cpython_document)
        )
        qualified_record = str(
            receipt.get("strix", {})
            .get("package_record", {})
            .get("record_sha256", "")
        )
        if _SHA256.fullmatch(qualified_record) is None:
            raise StrixRuntimeClosurePreparationError(
                "qualified Strix RECORD digest is invalid"
            )
        manifest_document = _preparation_document(
            qualification_manifest=manifest,
            refs=refs,
            wheelhouse_ref=wheelhouse_ref,
            strix_plan=strix_plan,
            qualified_record=qualified_record,
            worker_plan=worker_plan,
            worker_manifest=worker_manifest,
            worker_manifest_digest=worker_manifest_digest,
            installed_distributions_ref=installed_distributions_ref,
            cpython_source_closure_ref=cpython_source_closure_ref,
            bootstrap_row=bootstrap_row,
            lockdown_row=lockdown_row,
            cli_row=cli_row,
            qualified_cli_payload=qualified_cli_payload,
            elf_ref=elf_ref,
            directories=directories,
            files=files,
            inventory_digest=inventory_digest,
            sbom_distributions=sbom_distributions,
            total_bytes=inventory_document["total_bytes"],
        )
        manifest_payload = _document_bytes(manifest_document)
        preparation_ref = _digest_bytes(manifest_payload)
        _write_exclusive(staging / PREPARATION_NAME, manifest_payload)
        staging.chmod(0o555)
        os.replace(staging, output)
        return {
            "schema_version": (
                "bluefire.strix-linux-runtime-closure-preparation-result.v1"
            ),
            "closure_root": str(output / ROOT_NAME),
            "preparation_manifest": str(output / PREPARATION_NAME),
            "preparation_manifest_ref": preparation_ref,
            "elf_dependency_manifest": str(output / ELF_NAME),
            "elf_dependency_manifest_ref": elf_ref,
            "inventory_digest": inventory_digest,
            "cpython_source_closure_ref": cpython_source_closure_ref,
            "runtime_qualification_ref": refs["runtime_qualification_ref"],
            "wheelhouse_ref": wheelhouse_ref,
            "production_ready": False,
        }
    except BaseException:
        _remove_staging(staging)
        raise


def _sbom_row(plan: WheelPlan, installed_files: int) -> dict[str, Any]:
    return {
        "name": plan.name,
        "normalized_name": plan.normalized_name,
        "version": plan.version,
        "wheel_digest": plan.wheel_digest,
        "metadata_digest": plan.metadata_digest,
        "record_digest": plan.record_digest,
        "installed_files": installed_files,
    }


def _preparation_document(**values: Any) -> dict[str, Any]:
    strix_plan: WheelPlan = values["strix_plan"]
    worker_plan: WheelPlan = values["worker_plan"]
    files = values["files"]
    return {
        "schema_version": PREPARATION_SCHEMA,
        "status": "prepared-not-startup-qualified",
        "production_ready": False,
        "source_revision": candidate.UPSTREAM_COMMIT,
        "worker_source_revision": values["worker_manifest"][
            "worker_source_revision"
        ],
        "platform": {"system": "linux", "machine": MACHINE},
        "python_version": PYTHON_VERSION,
        "tool": {
            "name": "prepare_strix_linux_runtime_closure",
            "version": TOOL_VERSION,
            "network_used": False,
            "target_runtime_executed": False,
            "ldd_used": False,
        },
        "qualification": {
            **values["refs"],
            "wheelhouse_ref": values["wheelhouse_ref"],
            "prepared_not_runtime_qualified": True,
        },
        "components": {
            "strix_wheel_digest": strix_plan.wheel_digest,
            "strix_record_digest": strix_plan.record_digest,
            "qualified_installed_strix_record_digest": (
                "sha256:" + values["qualified_record"]
            ),
            "worker_artifact_digest": worker_plan.wheel_digest,
            "worker_record_digest": worker_plan.record_digest,
            "worker_artifact_manifest_digest": values[
                "worker_manifest_digest"
            ],
            "installed_distributions_ref": values[
                "installed_distributions_ref"
            ],
            "worker_source_revision": values["worker_manifest"][
                "worker_source_revision"
            ],
            "cpython_artifact_digest": None,
            "cpython_artifact_identity_available": False,
            "cpython_source_closure_ref": values[
                "cpython_source_closure_ref"
            ],
            "bootstrap_digest": values["bootstrap_row"]["content_digest"],
            "lockdown_source_digest": values["lockdown_row"][
                "content_digest"
            ],
            "seccomp_profile_digest": lockdown_contract.POLICY_DIGEST,
            "strix_entrypoint_digest": values["cli_row"]["content_digest"],
            "guest_executable_sha256": values["cli_row"][
                "content_digest"
            ],
            "strix_console_script": {
                "qualified_source_digest": _digest_bytes(
                    values["qualified_cli_payload"]
                ),
                "closure_digest": values["cli_row"]["content_digest"],
                "fixed_shebang": "#!/runtime/bin/python",
                "entry_point": "strix.interface.main:main",
                "mode": 0o444,
                "execve_admitted": False,
            },
        },
        "elf_dependency_manifest_ref": values["elf_ref"],
        "closure": {
            "root_name": ROOT_NAME,
            "fixed_argv": [
                "/runtime/bin/python",
                "-I",
                "-S",
                "-B",
                "-X",
                "utf8",
                "/bootstrap/worker.py",
            ],
            "expected_python_prefix": "/runtime",
            "pyvenv_cfg_absent": True,
            "private_mountpoints": list(PRIVATE_MOUNTPOINTS),
            "workspace_launch_mode": 0o700,
            "directory_inventory": values["directories"],
            "file_inventory": files,
            "inventory_digest": values["inventory_digest"],
            "external_symlinks_absent": True,
            "hardlinks_absent": True,
            "special_files_absent": True,
            "host_credentials_absent": True,
            "docker_sockets_absent": True,
            "proc_and_sys_absent": True,
        },
        "sbom": {
            "schema_version": SBOM_SCHEMA,
            "distributions": sorted(
                values["sbom_distributions"],
                key=lambda row: (row["normalized_name"], row["version"]),
            ),
            "file_count": len(files),
            "total_bytes": values["total_bytes"],
        },
        "source_paths_redacted": True,
        "reconstruction": {
            "dependency_packages_from_exact_wheels": True,
            "strix_from_exact_candidate_wheel": True,
            "worker_from_exact_minimal_artifact": True,
            "full_bluefire_wheel_refused": True,
            "pip_generated_metadata_excluded": True,
        },
    }


def _remove_staging(staging: Path) -> None:
    if not staging.exists():
        return
    for path in sorted(
        staging.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass
    try:
        staging.chmod(0o700)
    except OSError:
        pass
    shutil.rmtree(staging, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--strix-wheel", type=Path, required=True)
    parser.add_argument("--worker-artifact", type=Path, required=True)
    parser.add_argument("--worker-artifact-sha256", required=True)
    parser.add_argument("--base-python", type=Path, required=True)
    parser.add_argument(
        "--bootstrap-worker",
        type=Path,
        default=Path(bootstrap_contract.__file__),
    )
    parser.add_argument(
        "--bootstrap-lockdown",
        type=Path,
        default=Path(lockdown_contract.__file__),
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = prepare_strix_linux_runtime_closure(
            qualification_root=arguments.qualification_root,
            runtime_root=arguments.runtime_root,
            strix_wheel=arguments.strix_wheel,
            worker_artifact=arguments.worker_artifact,
            worker_artifact_sha256=arguments.worker_artifact_sha256,
            base_python=arguments.base_python,
            output_root=arguments.output_root,
            bootstrap_worker=arguments.bootstrap_worker,
            bootstrap_lockdown=arguments.bootstrap_lockdown,
        )
    except StrixRuntimeClosurePreparationError as exc:
        print(
            f"Strix Linux runtime closure preparation refused: {exc}",
            file=sys.stderr,
        )
        return 1
    print(_canonical_json(result).decode("ascii"))
    return 0


__all__ = [
    "BOOTSTRAP_DESTINATION",
    "CPYTHON_SOURCE_SCHEMA",
    "ELF_NAME",
    "ELF_SCHEMA",
    "ElfIdentity",
    "INVENTORY_SCHEMA",
    "LOADER_DESTINATION",
    "LOCKDOWN_DESTINATION",
    "PREPARATION_NAME",
    "PREPARATION_SCHEMA",
    "PRIVATE_DIRECTORIES",
    "PRIVATE_MOUNTPOINTS",
    "ROOT_NAME",
    "SBOM_SCHEMA",
    "StrixRuntimeClosurePreparationError",
    "WheelEntry",
    "WheelPlan",
    "_canonical_json",
    "_copy_payload",
    "_digest_bytes",
    "_document_bytes",
    "_elf_identity",
    "_plan_wheel",
    "main",
    "prepare_strix_linux_runtime_closure",
    "runtime_inventory_digest",
]
