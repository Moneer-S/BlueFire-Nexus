"""Fixed WSL2 Linux runtime boundary for the Gate 11 product journey."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess  # nosec B404 - only fixed WSL/test command grammars are used
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, cast

from .cross_platform_committed_linux_artifact import (
    LINUX_ARTIFACT_SOURCE,
    CommittedLinuxArtifact,
    CommittedLinuxArtifactError,
    load_committed_linux_artifact,
)
from .cross_platform_linux_bundle_validation import (
    LINUX_SCENARIO_VARIANTS,
    PRIMARY_SCENARIO_VARIANT,
    validate_linux_bundle,
)
from .cross_platform_linux_distribution import (
    DisposableWslDistributionError,
    create_disposable_wsl_distribution,
)
from .cross_platform_process_proof import (
    ProcessProofError,
    validate_posix_watchdog_containment_proof,
)
from .cross_platform_readiness import WSL_DISTRIBUTION_ID, _trusted_wsl_executable
from .run_store import RunStore

LINUX_SCHEMA = "bluefire.cross-platform-linux-execute.v1"
LINUX_ENVIRONMENT = "disposable-wsl2-distribution"
LINUX_WORKER_SCHEMA = "bluefire.cross-platform-linux-worker.v3"
LINUX_WORKER = "tools/run_cross_platform_linux_worker.py"
LINUX_CLEANUP = "tools/run_cross_platform_linux_cleanup.py"
LINUX_VERIFIER = "tools/run_cross_platform_linux_verify_cleanup.py"
LINUX_WHEELHOUSE_ENV = "BLUEFIRE_GATE11_LINUX_WHEELHOUSE"
LINUX_WHEELHOUSE_LOCK = "bluefire/data/gate11_linux_wheelhouse.json"

_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")
_ACCEPTANCE_ENV = {
    "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
    "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
}
_MAX_WORKER_OUTPUT = 256 * 1024


class LinuxJourneyError(ValueError):
    """Raised when the fixed Linux boundary is absent, ambiguous, or invalid."""


class LinuxDependenciesUnavailableError(LinuxJourneyError):
    """Raised when the fixed offline Linux dependency set is absent or mismatched."""


Require = Callable[[bool, str], None]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LinuxJourneyError(message)


def linux_unavailable_report(wsl: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the only two positively diagnosed WSL absence reports."""

    state = wsl.get("probe_state")
    _require(state in {"absent", "incompatible"}, "WSL absence is not positively known")
    code = "wsl_distribution_absent" if state == "absent" else "wsl_distribution_not_v2"
    return {
        "schema_version": LINUX_SCHEMA,
        "passed": False,
        "proof_kind": "dynamic",
        "platform": "linux",
        "environment_type": LINUX_ENVIRONMENT,
        "availability": {"state": "unavailable", "code": code},
        "boundary": {
            "provider": "wsl2",
            "distribution_id": WSL_DISTRIBUTION_ID,
            "probe_state": state,
            "configured": wsl.get("configured"),
            "version": wsl.get("version"),
            "facts_digest": wsl.get("facts_digest"),
            "source_distribution_persistent": wsl.get("configured") is True,
            "execution_distribution_disposable": True,
            "execution_distribution_created": False,
        },
        "runner": None,
        "watchdog_containment": None,
        "execution": None,
        "receiver": None,
        "run_bundle": None,
    }


def linux_dependencies_unavailable_report(wsl: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a deterministic dependency blocker without persisting a local path."""

    _require(
        wsl.get("probe_state") == "ready"
        and wsl.get("configured") is True
        and wsl.get("version") == "2",
        "dependency unavailability requires a ready fixed WSL2 boundary",
    )
    dependencies = [
        {"distribution": "cffi", "required": "==2.1.1", "observed_version": None},
        {
            "distribution": "cryptography",
            "required": ">=50,<51",
            "observed_version": None,
        },
        {"distribution": "pycparser", "required": "==3.0", "observed_version": None},
        {"distribution": "PyNaCl", "required": ">=1.5,<2", "observed_version": None},
        {"distribution": "PyYAML", "required": ">=6.0.1,<7", "observed_version": None},
    ]
    return {
        "schema_version": LINUX_SCHEMA,
        "passed": False,
        "proof_kind": "dynamic",
        "platform": "linux",
        "environment_type": LINUX_ENVIRONMENT,
        "availability": {"state": "unavailable", "code": "linux_dependencies_unavailable"},
        "boundary": {
            "provider": "wsl2",
            "distribution_id": WSL_DISTRIBUTION_ID,
            "probe_state": "ready",
            "configured": True,
            "version": "2",
            "facts_digest": wsl.get("facts_digest"),
            "source_distribution_persistent": True,
            "execution_distribution_disposable": True,
            "execution_distribution_created": False,
        },
        "dependencies": dependencies,
        "runner": None,
        "watchdog_containment": None,
        "execution": None,
        "receiver": None,
        "run_bundle": None,
    }


def _safe_regular_payload(path: Path, maximum: int) -> tuple[bytes, tuple[int, str]]:
    details = path.lstat()
    reparse = bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    _require(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not reparse
        and details.st_nlink == 1
        and 1 <= details.st_size <= maximum,
        "the Linux release artifact is not a safe bounded regular file",
    )
    before = (details.st_dev, details.st_ino, details.st_size)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size) == before,
            "the Linux release artifact identity changed",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        current_reparse = bool(
            int(getattr(current, "st_file_attributes", 0))
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        _require(
            len(payload) == opened.st_size
            and len(payload) <= maximum
            and (after.st_dev, after.st_ino, after.st_size) == before
            and (current.st_dev, current.st_ino, current.st_size) == before
            and not stat.S_ISLNK(current.st_mode)
            and not current_reparse,
            "the Linux release artifact changed during validation",
        )
        return payload, (len(payload), "sha256:" + hashlib.sha256(payload).hexdigest())
    finally:
        os.close(descriptor)


def _safe_regular(path: Path, maximum: int) -> tuple[int, str]:
    return _safe_regular_payload(path, maximum)[1]


def _write_staged_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a staged Linux file write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_linux_release_artifact(
    repository: Path, acceptance_binding: Mapping[str, str]
) -> CommittedLinuxArtifact:
    try:
        return load_committed_linux_artifact(
            repository,
            repository_commit=str(acceptance_binding.get("repository_commit", "")),
            repository_tree=str(acceptance_binding.get("repository_tree", "")),
        )
    except (OSError, CommittedLinuxArtifactError) as exc:
        raise LinuxJourneyError("the commit-bound Linux release artifact is invalid") from exc


def validate_linux_release_artifact(
    repository: Path, *, acceptance_binding: Mapping[str, str] | None = None
) -> Mapping[str, Any]:
    """Independently bind the exact acceptance commit's Linux runner objects."""

    binding = acceptance_binding or _acceptance_binding()
    return dict(_load_linux_release_artifact(repository, binding).record)


def _wsl_path(path: Path) -> str:
    resolved = path.resolve(strict=True)
    drive = resolved.drive.rstrip(":").casefold()
    _require(len(drive) == 1 and drive.isascii() and drive.isalpha(), "WSL path is unsupported")
    return str(PurePosixPath("/mnt", drive, *resolved.parts[1:]))


def _acceptance_binding() -> Mapping[str, str]:
    values = {key: os.environ.get(name) for key, name in _ACCEPTANCE_ENV.items()}
    _require(
        all(isinstance(value, str) and 1 <= len(value) <= 512 for value in values.values()),
        "the Linux worker acceptance binding is incomplete",
    )
    return {key: str(value) for key, value in values.items()}


def _stage_product(repository: Path, staging: Path, artifact: CommittedLinuxArtifact) -> None:
    product = staging / "product"
    product.mkdir()

    def ignored(source: str, names: list[str]) -> set[str]:
        values = set(shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")(source, names))
        if Path(source).name == "native" and "linux-x86_64" in names:
            values.add("linux-x86_64")
        return values

    shutil.copytree(
        repository / "bluefire",
        product / "bluefire",
        ignore=ignored,
    )
    native = product / "bluefire" / "native" / "linux-x86_64"
    native.mkdir()
    _write_staged_file(native / "runner-manifest.json", artifact.manifest)
    _write_staged_file(native / "bluefire-runner", artifact.binary)
    _require(
        _safe_regular(native / "runner-manifest.json", 64 * 1024)
        == (artifact.record["manifest_size"], artifact.record["manifest_sha256"])
        and _safe_regular(native / "bluefire-runner", 128 * 1024 * 1024)
        == (artifact.record["binary_size"], artifact.record["binary_sha256"]),
        "the staged commit-bound Linux release artifact changed",
    )
    project_payload, (project_size, project_digest) = _safe_regular_payload(
        repository / "pyproject.toml", 256 * 1024
    )
    _write_staged_file(product / "pyproject.toml", project_payload)
    _require(
        _safe_regular(product / "pyproject.toml", 256 * 1024) == (project_size, project_digest),
        "the staged Linux dependency contract changed",
    )


def _stage_wheelhouse(repository: Path, staging: Path) -> Mapping[str, Any]:
    lock_path = repository / LINUX_WHEELHOUSE_LOCK
    try:
        lock_payload, (lock_size, lock_digest) = _safe_regular_payload(lock_path, 64 * 1024)
        lock = json.loads(lock_payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise LinuxJourneyError("the committed Linux wheelhouse lock is invalid") from exc
    wheels = lock.get("wheels") if isinstance(lock, Mapping) else None
    expected_versions = {
        "cffi": "2.1.1",
        "cryptography": "50.0.0",
        "pycparser": "3.0",
        "PyNaCl": "1.6.2",
        "PyYAML": "6.0.3",
    }
    _require(
        isinstance(lock, Mapping)
        and set(lock) == {"schema_version", "platform", "architecture", "python", "wheels"}
        and lock.get("schema_version") == "bluefire.linux-wheelhouse.v1"
        and lock.get("platform") == "linux"
        and lock.get("architecture") == "x86_64"
        and lock.get("python") == {"implementation": "cpython", "major": 3, "minor": 12}
        and isinstance(wheels, list)
        and len(wheels) == 5,
        "the Linux wheelhouse lock is invalid",
    )
    wheel_rows = cast(list[Mapping[str, Any]], wheels)
    observed_names: list[str] = []
    filenames: list[str] = []
    for row in wheel_rows:
        _require(
            isinstance(row, Mapping)
            and set(row) == {"distribution", "version", "filename", "size", "sha256"}
            and isinstance(row.get("distribution"), str)
            and row.get("version") == expected_versions.get(str(row["distribution"]))
            and isinstance(row.get("filename"), str)
            and Path(str(row["filename"])).name == row["filename"]
            and str(row["filename"]).endswith(".whl")
            and type(row.get("size")) is int
            and 1 <= int(row["size"]) <= 32 * 1024 * 1024
            and isinstance(row.get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", str(row["sha256"])) is not None,
            "the Linux wheelhouse lock row is invalid",
        )
        observed_names.append(str(row["distribution"]))
        filenames.append(str(row["filename"]))
    _require(
        observed_names == list(expected_versions) and len(filenames) == len(set(filenames)),
        "the Linux wheelhouse lock inventory is invalid",
    )
    try:
        raw_root = os.environ.get(LINUX_WHEELHOUSE_ENV)
        if not isinstance(raw_root, str) or not 1 <= len(raw_root) <= 4096:
            raise LinuxJourneyError("wheelhouse missing")
        supplied = Path(raw_root)
        supplied_details = supplied.lstat()
        reparse = bool(
            int(getattr(supplied_details, "st_file_attributes", 0))
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        _require(
            supplied.is_absolute()
            and stat.S_ISDIR(supplied_details.st_mode)
            and not stat.S_ISLNK(supplied_details.st_mode)
            and not reparse,
            "wheelhouse root unsafe",
        )
        supplied = supplied.resolve(strict=True)
        entries = tuple(supplied.iterdir())
        _require(
            len(entries) == 5 and {item.name for item in entries} == set(filenames),
            "wheelhouse inventory mismatch",
        )
    except (OSError, LinuxJourneyError, ValueError) as exc:
        raise LinuxDependenciesUnavailableError(
            "the fixed offline Linux dependency wheelhouse is unavailable"
        ) from exc
    target = staging / "wheelhouse"
    target.mkdir()
    for row in wheel_rows:
        try:
            source = supplied / str(row["filename"])
            expected = (int(row["size"]), "sha256:" + str(row["sha256"]))
            payload, observed = _safe_regular_payload(source, 32 * 1024 * 1024)
            _require(observed == expected, "wheel mismatch")
        except (OSError, LinuxJourneyError, ValueError) as exc:
            raise LinuxDependenciesUnavailableError(
                "the fixed offline Linux dependency wheelhouse is unavailable"
            ) from exc
        staged = target / source.name
        _write_staged_file(staged, payload)
        _require(
            _safe_regular(staged, 32 * 1024 * 1024) == expected,
            "the staged Linux wheel changed",
        )
    staged_lock = staging / "wheelhouse.json"
    _write_staged_file(staged_lock, lock_payload)
    _require(
        _safe_regular(staged_lock, 64 * 1024) == (lock_size, lock_digest),
        "the staged Linux wheelhouse lock changed",
    )
    return {
        "manifest_sha256": lock_digest,
        "manifest_size": lock_size,
        "wheel_count": 5,
    }


def _worker_environment() -> Mapping[str, str]:
    allowed = ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
    return {name: os.environ[name] for name in allowed if os.environ.get(name)}


def _run_fixed(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        completed = subprocess.run(  # nosec B603 - caller supplies one internally fixed grammar
            command,
            cwd=cwd,
            env=_worker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            check=False,
            shell=False,
        )
        stdout.seek(0)
        output = stdout.read(_MAX_WORKER_OUTPUT + 1)
        stderr.seek(0)
        error = stderr.read(64 * 1024 + 1)
    _require(
        len(output) <= _MAX_WORKER_OUTPUT and len(error) <= 64 * 1024,
        "a fixed WSL command stream exceeded its bound",
    )
    return subprocess.CompletedProcess(command, completed.returncode, output, error)


def _control_json(path: Path, maximum: int) -> Mapping[str, Any]:
    _safe_regular(path, maximum)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise LinuxJourneyError("a Linux control record is invalid") from exc
    if not isinstance(value, Mapping):
        raise LinuxJourneyError("a Linux control record is not an object")
    return value


def _bounded_output(path: Path, maximum: int) -> bytes:
    details = path.lstat()
    _require(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and details.st_nlink == 1
        and 0 <= details.st_size <= maximum,
        "a Linux worker stream exceeded its bound",
    )
    payload = path.read_bytes()
    _require(len(payload) == details.st_size, "a Linux worker stream changed during reading")
    return payload


def _stop_wsl_client(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    _require(process.poll() is not None, "the WSL client process survived cleanup")


def _supervised_worker(
    staging: Path,
    worker_command: list[str],
    cleanup_command: list[str],
    verifier_command: list[str],
    workspace_name: str,
    verifier_digest: str,
) -> tuple[int, bytes, bytes, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    options: dict[str, Any] = {
        "cwd": staging,
        "env": _worker_environment(),
        "stdin": subprocess.DEVNULL,
        "shell": False,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    stdout_path = staging / "worker.stdout"
    stderr_path = staging / "worker.stderr"
    stdout_handle = stdout_path.open("xb")
    stderr_handle = stderr_path.open("xb")
    try:
        process = subprocess.Popen(  # nosec B603 - fixed grammar
            worker_command,
            stdout=stdout_handle,
            stderr=stderr_handle,
            **options,
        )
    finally:
        stdout_handle.close()
        stderr_handle.close()
    supervisor: Mapping[str, Any] | None = None
    stdout = b""
    stderr = b""
    returncode = -1
    primary: BaseException | None = None
    cleanup: subprocess.CompletedProcess[bytes] | None = None
    cleanup_error: BaseException | None = None
    stop_error: BaseException | None = None
    try:
        deadline = time.monotonic() + 20
        supervisor_path = staging / "supervisor.json"
        while time.monotonic() < deadline:
            if supervisor_path.is_file():
                supervisor = _control_json(supervisor_path, 4096)
                break
            if process.poll() is not None:
                break
            time.sleep(0.025)
        _require(
            isinstance(supervisor, Mapping)
            and supervisor.get("schema_version") == "bluefire.cross-platform-linux-supervisor.v1"
            and supervisor.get("workspace_name") == workspace_name
            and type(supervisor.get("process_id")) is int
            and supervisor.get("process_id") == supervisor.get("process_group_id")
            and supervisor.get("process_id") == supervisor.get("session_id")
            and type(supervisor.get("start_time_ticks")) is int,
            "the Linux worker did not publish a valid supervisor identity",
        )
        deadline = time.monotonic() + 180
        while process.poll() is None and time.monotonic() < deadline:
            if (
                stdout_path.stat().st_size > _MAX_WORKER_OUTPUT
                or stderr_path.stat().st_size > 64 * 1024
            ):
                primary = LinuxJourneyError(
                    "the fixed Linux product worker stream exceeded its bound"
                )
                break
            time.sleep(0.025)
        if process.poll() is None:
            primary = LinuxJourneyError("the fixed Linux product worker timed out")
        else:
            returncode = int(process.wait(timeout=5))
    except BaseException as exc:
        if primary is None:
            primary = exc
    finally:
        # Preserve the live in-distro lineage while the cleanup helper obtains
        # pidfds for the exact supervisor, descendants, and fixed worker path.
        try:
            cleanup = _run_fixed(cleanup_command, cwd=staging, timeout=30)
        except BaseException as exc:
            cleanup_error = exc
        try:
            _stop_wsl_client(process)
            if process.poll() is not None:
                returncode = int(process.wait(timeout=5))
        except BaseException as exc:
            stop_error = exc
        try:
            stdout = _bounded_output(stdout_path, _MAX_WORKER_OUTPUT)
            stderr = _bounded_output(stderr_path, 64 * 1024)
        except BaseException as exc:
            if primary is None:
                primary = exc
    if cleanup_error is not None:
        raise LinuxJourneyError("the Linux supervisor cleanup did not run") from cleanup_error
    if cleanup is None:
        raise LinuxJourneyError("the Linux supervisor cleanup did not return")
    _require(
        cleanup.returncode == 0 and cleanup.stderr == b"",
        "the Linux supervisor cleanup could not prove absence",
    )
    cleanup_summary = _worker_summary(cleanup.stdout)
    identities = cleanup_summary.get("process_identities")
    _require(
        set(cleanup_summary)
        == {
            "schema_version",
            "workspace_name",
            "process_absent",
            "workspace_absent",
            "process_identities",
            "survivor_probes",
        }
        and cleanup_summary.get("schema_version") == "bluefire.cross-platform-linux-cleanup.v1"
        and cleanup_summary.get("workspace_name") == workspace_name
        and cleanup_summary.get("process_absent") is True
        and cleanup_summary.get("workspace_absent") is True
        and isinstance(identities, list)
        and 1 <= len(identities) <= 65536
        and cleanup_summary.get("survivor_probes")
        == [{"delay_ms": delay, "running": False} for delay in (0, 100, 250)],
        "the Linux supervisor cleanup proof is invalid",
    )
    identity_rows = cast(list[Any], identities)
    proof_payload = (
        json.dumps(
            cleanup_summary,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    _write_staged_file(staging / "cleanup-proof.json", proof_payload)
    verified = _run_fixed(verifier_command, cwd=staging, timeout=30)
    _require(
        verified.returncode == 0 and verified.stderr == b"",
        "the independent Linux cleanup verifier failed",
    )
    verification = _worker_summary(verified.stdout)
    identity_material = {
        "schema_version": "bluefire.cross-platform-linux-cleanup-identities.v1",
        "workspace_name": workspace_name,
        "process_identities": identity_rows,
    }
    identity_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                identity_material,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )
    _require(
        verification
        == {
            "schema_version": "bluefire.cross-platform-linux-cleanup-verification.v1",
            "workspace_name": workspace_name,
            "workspace_absent": True,
            "process_identities_absent": True,
            "process_identity_count": len(identity_rows),
            "identity_material_sha256": identity_digest,
            "verifier_sha256": verifier_digest,
            "probe_delays_ms": [0, 100, 250],
        },
        "the independent Linux cleanup verification is invalid",
    )
    verification = {**verification, "identity_material": identity_material}
    if stop_error is not None and primary is None:
        primary = stop_error
    if primary is not None:
        raise primary
    if supervisor is None:
        raise LinuxJourneyError("the Linux supervisor identity is unavailable")
    return returncode, stdout, stderr, supervisor, cleanup_summary, verification


def _worker_summary(payload: bytes) -> Mapping[str, Any]:
    _require(0 < len(payload) <= _MAX_WORKER_OUTPUT, "the Linux worker output is unbounded")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise LinuxJourneyError("the Linux worker output is not strict JSON") from exc
    if not isinstance(value, Mapping):
        raise LinuxJourneyError("the Linux worker output is not an object")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def run_linux_journey(
    repository: Path,
    evidence_dir: Path,
    runtime: Path,
    wsl: Mapping[str, Any],
    *,
    scenario_variant: str = PRIMARY_SCENARIO_VARIANT,
) -> Mapping[str, Any]:
    """Execute one fixed Linux scenario variant in a fresh WSL-local workspace."""

    _require(
        wsl.get("probe_state") == "ready"
        and wsl.get("configured") is True
        and wsl.get("version") == "2",
        "the fixed WSL2 boundary is not ready",
    )
    _require(scenario_variant in LINUX_SCENARIO_VARIANTS, "invalid Linux scenario variant")
    acceptance_binding = _acceptance_binding()
    artifact = _load_linux_release_artifact(repository, acceptance_binding)
    runner = dict(artifact.record)
    staging = runtime / (
        "linux-stage" if scenario_variant == PRIMARY_SCENARIO_VARIANT else "linux-alternate-stage"
    )
    staging.mkdir()
    _stage_product(repository, staging, artifact)
    wheelhouse = _stage_wheelhouse(repository, staging)
    _write_staged_file(staging / "runner", artifact.binary)
    _require(
        _safe_regular(staging / "runner", 128 * 1024 * 1024)
        == (runner["binary_size"], runner["binary_sha256"]),
        "the staged commit-bound Linux runner changed",
    )
    worker_source = repository / LINUX_WORKER
    worker_payload, (worker_size, worker_digest) = _safe_regular_payload(worker_source, 512 * 1024)
    _write_staged_file(staging / "worker.py", worker_payload)
    staged_worker_size, staged_worker_digest = _safe_regular(staging / "worker.py", 512 * 1024)
    _require(
        (staged_worker_size, staged_worker_digest) == (worker_size, worker_digest),
        "the staged Linux worker changed",
    )
    cleanup_source = repository / LINUX_CLEANUP
    cleanup_payload, (cleanup_size, cleanup_digest) = _safe_regular_payload(
        cleanup_source, 256 * 1024
    )
    _write_staged_file(staging / "cleanup.py", cleanup_payload)
    staged_cleanup_size, staged_cleanup_digest = _safe_regular(staging / "cleanup.py", 256 * 1024)
    _require(
        (staged_cleanup_size, staged_cleanup_digest) == (cleanup_size, cleanup_digest),
        "the staged Linux cleanup worker changed",
    )
    verifier_payload, (verifier_size, verifier_digest) = _safe_regular_payload(
        repository / LINUX_VERIFIER, 256 * 1024
    )
    _write_staged_file(staging / "verify-cleanup.py", verifier_payload)
    _require(
        _safe_regular(staging / "verify-cleanup.py", 256 * 1024)
        == (verifier_size, verifier_digest),
        "the staged Linux cleanup verifier changed",
    )
    workspace_name = "bluefire-gate11-" + secrets.token_hex(8)
    executable = _trusted_wsl_executable()
    if executable is None or not executable.is_file():
        raise LinuxJourneyError("the trusted WSL executable changed")
    try:
        distribution = create_disposable_wsl_distribution(executable, runtime)
    except DisposableWslDistributionError as exc:
        raise LinuxJourneyError("the disposable WSL2 execution distribution failed") from exc
    worker_result: (
        tuple[int, bytes, bytes, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]] | None
    ) = None
    primary: BaseException | None = None
    distribution_cleanup: Mapping[str, Any] | None = None
    cleanup_error: BaseException | None = None
    try:
        request = {
            "schema_version": "bluefire.cross-platform-linux-request.v2",
            "source_distribution_id": WSL_DISTRIBUTION_ID,
            "execution_distribution_id": distribution.distribution_name,
            "workspace_name": workspace_name,
            "scenario_variant": scenario_variant,
            "acceptance_binding": acceptance_binding,
            "release_artifact": {key: value for key, value in runner.items() if key != "source"},
            "wheelhouse": wheelhouse,
        }
        (staging / "request.json").write_text(
            json.dumps(request, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        command = distribution.isolated_python_command(
            _wsl_path(staging / "worker.py"),
            new_session=True,
        )
        cleanup_command = distribution.isolated_python_command(
            _wsl_path(staging / "cleanup.py"),
        )
        verifier_command = distribution.isolated_python_command(
            _wsl_path(staging / "verify-cleanup.py"),
        )
        worker_result = _supervised_worker(
            staging,
            command,
            cleanup_command,
            verifier_command,
            workspace_name,
            verifier_digest,
        )
    except BaseException as exc:
        primary = exc
    finally:
        try:
            distribution_cleanup = distribution.cleanup()
        except BaseException as exc:
            cleanup_error = exc
    if cleanup_error is not None:
        raise LinuxJourneyError(
            "the disposable WSL2 execution distribution survived cleanup"
        ) from cleanup_error
    if primary is not None:
        raise primary
    if worker_result is None or distribution_cleanup is None:
        raise LinuxJourneyError("the disposable Linux execution result is unavailable")
    returncode, worker_stdout, worker_stderr, supervisor, cleanup_summary, verification = (
        worker_result
    )
    if returncode != 0:
        if worker_stderr == b"":
            failure = _worker_summary(worker_stdout) if worker_stdout else {}
            if (
                set(failure) == {"schema_version", "code", "dependencies"}
                and failure.get("schema_version") == "bluefire.cross-platform-linux-worker-error.v1"
                and failure.get("code") == "linux_dependencies_unavailable"
                and isinstance(failure.get("dependencies"), Mapping)
            ):
                raise LinuxDependenciesUnavailableError(
                    "the fixed Linux product dependencies are unavailable"
                )
        raise LinuxJourneyError("the fixed Linux product worker failed")
    _require(worker_stderr == b"", "the fixed Linux product worker emitted diagnostics")
    summary = _worker_summary(worker_stdout)
    _require(
        set(summary)
        == {
            "schema_version",
            "passed",
            "run_id",
            "runner",
            "watchdog_containment",
            "receiver",
            "scenario_variant",
            "workspace_name",
            "workspace_removed",
        }
        and summary.get("schema_version") == LINUX_WORKER_SCHEMA
        and summary.get("passed") is True
        and summary.get("scenario_variant") == scenario_variant
        and summary.get("workspace_name") == workspace_name
        and summary.get("runner")
        == {key: value for key, value in runner.items() if key != "source"}
        and summary.get("workspace_removed") is True,
        "the Linux product worker summary is invalid",
    )
    try:
        watchdog_containment = dict(
            validate_posix_watchdog_containment_proof(summary["watchdog_containment"])
        )
    except ProcessProofError as exc:
        raise LinuxJourneyError("the Linux watchdog containment proof is invalid") from exc
    run_id = str(summary["run_id"])
    execution = validate_linux_bundle(
        staging / "runs" / run_id,
        summary,
        scenario_variant=scenario_variant,
        require=_require,
    )
    destination_runs = evidence_dir / "runs"
    destination_runs.mkdir(exist_ok=True)
    target = destination_runs / run_id
    _require(not target.exists(), "the Linux run destination is stale")
    shutil.copytree(staging / "runs" / run_id, target)
    _require(
        RunStore(destination_runs).validate_bundle(run_id).get("valid") is True,
        "the copied Linux bundle changed",
    )
    return {
        "schema_version": LINUX_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "platform": "linux",
        "environment_type": LINUX_ENVIRONMENT,
        "availability": {"state": "ready", "code": None},
        "boundary": {
            "provider": "wsl2",
            "distribution_id": WSL_DISTRIBUTION_ID,
            "probe_state": "ready",
            "configured": True,
            "version": "2",
            "facts_digest": wsl.get("facts_digest"),
            "source_distribution_persistent": True,
            **distribution_cleanup,
            "workspace_disposable": True,
            "workspace_removed": True,
            "workspace_name": workspace_name,
            "worker_process_exited": True,
            "worker_process_id": supervisor["process_id"],
            "process_group_id": supervisor["process_group_id"],
            "session_id": supervisor["session_id"],
            "worker_start_time_ticks": supervisor["start_time_ticks"],
            "survivor_probes": cleanup_summary["survivor_probes"],
            "cleanup_verification": verification,
        },
        "runner": runner,
        "watchdog_containment": watchdog_containment,
        "execution": execution,
        "receiver": summary["receiver"],
        "run_bundle": {"run_id": run_id, "path": f"runs/{run_id}"},
    }


__all__ = [
    "LINUX_ARTIFACT_SOURCE",
    "LINUX_ENVIRONMENT",
    "LINUX_SCHEMA",
    "LINUX_WORKER_SCHEMA",
    "LinuxJourneyError",
    "linux_unavailable_report",
    "run_linux_journey",
    "validate_linux_release_artifact",
]
