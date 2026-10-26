"""Explicit root-owned macOS workspace supervisor for the fixed file-access lab.

The command creates only the product's fixed generated namespace and an isolated
normal service workspace. It does not create OS accounts or delete the retained
resource when the UI stops.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import signal
import stat
import subprocess
import sys
import threading
from importlib import resources
from pathlib import Path
from typing import Any, Callable, cast

from .config import BlueFireConfig
from .macos_file_access_workspace import WORKSPACE_PARENT

_IDENTITY_MIN = 60_000
_IDENTITY_MAX = 65_000
_MAX_IMPORT_FILES = 1024
_MAX_IMPORT_BYTES = 256 * 1024 * 1024
_SETUP_LOCK_NAME = ".macos-file-access-setup.lock"
_SUPPORTED_METHODS = (
    "macos.file_access.probe.v1",
    "macos.file_access.verify_owner.v1",
    "macos.file_access.close_attempt.v1",
)

MACOS_SETUP_DIAGNOSTIC_STAGES = frozenset(
    {
        "platform_runtime_gate",
        "request_validation",
        "package_import_custody",
        "interpreter_custody",
        "runtime_import_custody",
        "runner_manifest",
        "workspace_parent_reservation",
        "protected_setup_lifecycle",
        "local_account_inventory",
        "active_process_inventory",
        "temporary_identity_selection",
        "native_resource_validation",
        "native_runner_initialization",
        "namespace_creation",
        "resource_baseline_review",
        "workspace_directory_creation",
        "owner_service_prepare",
        "service_startup",
        "ui_readiness",
    }
)


class MacOSSetupFailure(RuntimeError):
    """A setup error annotated with one fixed, non-sensitive operation stage."""

    def __init__(self, stage: str, message: str) -> None:
        if stage not in MACOS_SETUP_DIAGNOSTIC_STAGES:
            raise ValueError("unknown macOS setup diagnostic stage")
        super().__init__(message)
        self.safe_setup_stage = stage


def _at_setup_stage(stage: str, operation: Callable[[], Any]) -> Any:
    """Tag expected setup failures without retaining their underlying details."""
    if stage not in MACOS_SETUP_DIAGNOSTIC_STAGES:
        raise ValueError("unknown macOS setup diagnostic stage")
    try:
        return operation()
    except MacOSSetupFailure:
        raise
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        raise MacOSSetupFailure(stage, str(exc)) from None


def _require(condition: bool, message: str = "The protected macOS setup is unavailable.") -> None:
    if not condition:
        raise RuntimeError(message)


def _platform_gate() -> None:
    from .macos_file_access_peer import _supported_runtime

    _require(
        sys.platform == "darwin"
        and platform.machine() == "arm64"
        and sys.implementation.name == "cpython"
        and sys.version_info[:3] in ((3, 10, 16), (3, 11, 18))
        and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
        and _supported_runtime(),
        "Use a root-owned CPython 3.10.16 legacy or 3.11.18 qualification session on macOS arm64.",
    )


def _credential_rows(uid: int, gid: int) -> dict[str, Any]:
    return {
        "real_uid": uid,
        "effective_uid": uid,
        "saved_uid": uid,
        "real_gid": gid,
        "effective_gid": gid,
        "saved_gid": gid,
        "groups": [gid],
    }


def _registered_ids() -> tuple[set[int], set[int]]:
    """Read the local directory node only; never enumerate network domains."""
    executable = Path("/usr/bin/dscl")
    _require(executable.is_file() and not executable.is_symlink())
    try:
        users = subprocess.run(
            [str(executable), ".", "-list", "/Users", "UniqueID"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        groups = subprocess.run(
            [str(executable), ".", "-list", "/Groups", "PrimaryGroupID"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("The local identity inventory is unavailable.") from exc
    _require(
        users.returncode == groups.returncode == 0
        and not users.stderr
        and not groups.stderr
        and len(users.stdout) <= 1024 * 1024
        and len(groups.stdout) <= 1024 * 1024
    )

    def ids(payload: bytes) -> set[int]:
        try:
            rows = payload.decode("ascii", "strict").splitlines()
            _require(len(rows) <= 100_000)
            values = set()
            for row in rows:
                fields = row.split()
                _require(len(fields) == 2 and bool(fields[0]))
                values.add(int(fields[1], 10))
            return values
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("The local identity inventory is invalid.") from exc

    user_ids, group_ids = ids(users.stdout), ids(groups.stdout)
    _require(0 in user_ids and 0 in group_ids)
    return user_ids, group_ids


def _active_ids() -> tuple[set[int], set[int]]:
    """Observe only numeric process identities; never retain command output."""
    executable = Path("/bin/ps")
    _require(executable.is_file() and not executable.is_symlink())
    try:
        result = subprocess.run(
            [str(executable), "-axo", "uid=,gid="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("The temporary identity inventory is unavailable.") from exc
    _require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 2 * 1024 * 1024)
    try:
        text = result.stdout.decode("ascii", "strict")
        rows = [line.split() for line in text.splitlines() if line.strip()]
        _require(len(rows) <= 100_000 and all(len(row) == 2 for row in rows))
        pairs = [(int(row[0], 10), int(row[1], 10)) for row in rows]
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("The temporary identity inventory is invalid.") from exc
    user_ids, group_ids = {uid for uid, _ in pairs}, {gid for _, gid in pairs}
    _require(0 in user_ids and 0 in group_ids)
    return user_ids, group_ids


def temporary_credentials() -> tuple[dict[str, Any], dict[str, Any]]:
    """Select two unassigned numeric UIDs and one unassigned shared GID.

    No local users or groups are created. The IDs must be absent from both the
    host account databases and the live process table before any resource is made.
    """
    used_uids, used_gids = _at_setup_stage("local_account_inventory", _registered_ids)
    used_uids.add(0)
    used_gids.add(0)
    process_uids, process_gids = _at_setup_stage("active_process_inventory", _active_ids)
    used_uids.update(process_uids)
    used_gids.update(process_gids)
    available = [
        value
        for value in range(_IDENTITY_MIN, _IDENTITY_MAX + 1)
        if value not in used_uids and value not in used_gids
    ]
    _require(len(available) >= 3, "No unused temporary numeric identities are available.")
    # Randomize choices within the reviewed, non-system range while retaining a
    # deterministic uniqueness check against accounts and live processes.
    offset = secrets.randbelow(len(available) - 2)
    owner_uid, reader_uid, group_id = available[offset : offset + 3]
    _require(owner_uid != reader_uid and group_id not in used_gids)
    return _credential_rows(owner_uid, group_id), _credential_rows(reader_uid, group_id)


def _fixed_config() -> BlueFireConfig:
    """Build a no-model, approval-required config for the original Mac methods."""
    base = BlueFireConfig.from_mapping(
        {
            "schema_version": "bluefire.config.v1",
            "mode": "execute",
            "ai": {"enabled": False},
            "active_profile": "macos-file-access.v1",
            "runner_profiles": [
                {
                    "id": "macos-file-access.v1",
                    "mode": "execute",
                    "environment_type": "disposable",
                    "platforms": ["macos"],
                    "runner_binary": {"env": "BLUEFIRE_MACOS_RUNNER"},
                    "sandbox_root": {"env": "BLUEFIRE_MACOS_SANDBOX"},
                    "scope": ["sandbox.workspace"],
                    "network_allowlist": [],
                    "capabilities": ["filesystem.read", "filesystem.write", "cleanup"],
                    "safety_tiers": ["controlled"],
                    "approval_required": True,
                    "enabled_actions": list(_SUPPORTED_METHODS),
                    "blocked_actions": [],
                    "cleanup_policy": "always",
                    "budgets": {
                        "max_steps": 3,
                        "max_seconds": 30,
                        "max_artifacts": 16,
                        "max_bytes": 1_048_576,
                    },
                }
            ],
        }
    )
    _require(
        not base.ai.enabled
        and base.ai.autonomy.value == "off"
        and base.active_profile == "macos-file-access.v1"
        and len(base.runner_profiles) == 1
        and base.runner_profiles[0].enabled_actions == _SUPPORTED_METHODS
        and base.runner_profiles[0].approval_required
        and not base.runner_profiles[0].network_allowlist
        and not base.runner_profiles[0].secrets
        and not base.runner_profiles[0].native_tool_installations
    )
    return base


def _hash_file(path: Path) -> str:
    from .macos_file_access_workspace_validation import _descriptor_security

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and not before.st_mode & 0o6022
            and before.st_nlink == 1
            and before.st_size <= _MAX_IMPORT_BYTES
            and os.path.samestat(before, path.lstat())
        )
        _descriptor_security(descriptor)
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            count += len(chunk)
            _require(count <= before.st_size)
            digest.update(chunk)
        after = os.fstat(descriptor)
        _require(
            count == before.st_size
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _walk_imports(root: Path, *, limit: int) -> dict[str, str]:
    from .macos_file_access_workspace_validation import _directory

    _require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    rows: dict[str, str] = {}
    total = 0

    def failed(error: OSError) -> None:
        raise error

    for directory, children, leaves in os.walk(root, followlinks=False, onerror=failed):
        base = Path(directory)
        details = base.lstat()
        _require(
            stat.S_ISDIR(details.st_mode) and details.st_uid == 0 and not details.st_mode & 0o022
        )
        _directory(base)
        for child in children:
            path = base / child
            _require(path.is_dir() and not path.is_symlink())
        for leaf in leaves:
            path = base / leaf
            if path.suffix not in {".py", ".pyc", ".so", ".zip"}:
                continue
            relative = path.relative_to(root).as_posix()
            _require(relative not in rows and len(rows) < limit)
            rows[relative] = _hash_file(path)
            total += path.stat().st_size
            _require(total <= _MAX_IMPORT_BYTES)
    _require(bool(rows))
    return rows


def _isolated_runtime_roots(python: Path) -> list[str]:
    source = "import json,sys; print(json.dumps(sys.path, separators=(',', ':')))"
    try:
        result = subprocess.run(
            [str(python), "-I", "-S", "-B", "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("The isolated Python search path is unavailable.") from exc
    _require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 16 * 1024)
    try:
        paths = json.loads(result.stdout.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("The isolated Python search path is invalid.") from exc
    _require(
        type(paths) is list
        and 0 < len(paths) <= 8
        and all(type(path) is str and Path(path).is_absolute() for path in paths)
        and len(paths) == len(set(paths))
    )
    return cast(list[str], paths)


def _make_directory(path: Path, *, mode: int, owner: int = 0, group: int = 0) -> None:
    path.mkdir(mode=mode, parents=False, exist_ok=False)
    os.chown(path, owner, group, follow_symlinks=False)  # type: ignore[attr-defined]
    os.chmod(path, mode, follow_symlinks=False)
    _validate_directory(path, owner=owner)


def _validate_directory(path: Path, *, owner: int = 0) -> None:
    from .macos_file_access_workspace_validation import _directory

    _directory(path, owner=owner)


def _ensure_workspace_parent() -> None:
    from . import macos_file_access_workspace_validation as validation

    parent = WORKSPACE_PARENT.parent
    validation._parents(parent)
    if WORKSPACE_PARENT.exists() or WORKSPACE_PARENT.is_symlink():
        _validate_directory(WORKSPACE_PARENT)
        details = WORKSPACE_PARENT.lstat()
        _require(stat.S_IMODE(details.st_mode) == 0o711)
    else:
        _make_directory(WORKSPACE_PARENT, mode=0o711)


def _acquire_setup_reservation() -> int:
    """Hold one root-owned lock and refuse to reuse any retained setup state."""
    import fcntl

    from . import macos_file_access_workspace_validation as validation

    lock_path = WORKSPACE_PARENT / _SETUP_LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError("The protected macOS setup reservation is unavailable.") from exc
    try:
        details = os.fstat(descriptor)
        _require(_reservation_file_matches(details, lock_path.lstat()))
        validation._descriptor_security(descriptor)
        try:
            fcntl.flock(  # type: ignore[attr-defined]
                descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB  # type: ignore[attr-defined]
            )
        except (BlockingIOError, OSError) as exc:
            raise RuntimeError("Another protected macOS setup session is active.") from exc
        _require(
            _setup_state_reusable(os.listdir(WORKSPACE_PARENT)),
            "A retained macOS workspace already exists; refusing identity reuse.",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _reservation_file_matches(details: os.stat_result, path_details: os.stat_result) -> bool:
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_uid == 0
        and stat.S_IMODE(details.st_mode) == 0o600
        and details.st_nlink == 1
        and details.st_size == 0
        and os.path.samestat(details, path_details)
    )


def _setup_state_reusable(entries: list[str]) -> bool:
    return type(entries) is list and set(entries) == {_SETUP_LOCK_NAME}


def _release_setup_reservation(descriptor: int) -> None:
    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
    finally:
        os.close(descriptor)


def _verified_interpreter(python: Path, validation: Any) -> str:
    """Validate executable ancestors and ACL before hashing or executing Python."""
    validation._parents(python.parent)
    digest = _hash_file(python)
    validation._protected_file(python, digest)
    return digest


def _with_setup_reservation(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    descriptor = _at_setup_stage("workspace_parent_reservation", _acquire_setup_reservation)
    try:
        return operation()
    finally:
        _at_setup_stage(
            "workspace_parent_reservation", lambda: _release_setup_reservation(descriptor)
        )


def _fresh_shutdown_binding(creator: Any) -> dict[str, Any] | None:
    if creator is None:
        return None
    try:
        binding = creator.review_context("baseline")["binding"]
    except BaseException:
        return None
    return binding if type(binding) is dict else None


def _shutdown_projection(
    owner_result: Any, creator_result: Any, binding: dict[str, Any]
) -> dict[str, Any]:
    host_clean = (
        type(owner_result) is dict
        and owner_result.get("host_closed") is True
        and owner_result.get("descriptor_cleanup_unknown") is False
        and owner_result.get("creation_unknown") is False
    )
    components_closed = (
        type(creator_result) is dict
        and creator_result.get("workers_closed") is True
        and creator_result.get("namespace_handles_closed") is True
    )
    return {
        "schema_version": "bluefire.macos-file-access-local-supervisor-result.v1",
        "status": "stopped_cleanly" if host_clean and components_closed else "cleanup_unknown",
        "host": owner_result,
        "components": creator_result,
        "generated_resource": {
            "generation": binding["generation"],
            "mode_at_shutdown": binding["mode"],
            "state_at_shutdown": (
                "owner_only_hardened" if binding["mode"] == "0600" else "group_readable_baseline"
            ),
            "resource_retained": True,
            "fixture_removed": False,
            "whole_setup_cleanup_proven": False,
        },
        "workspace_retained": True,
        "identity_accounts_created": False,
    }


def run_local_supervisor(*, port: int = 0, no_browser: bool = False) -> dict[str, Any]:
    """Run the original root custodian and stop only on explicit process exit."""
    _at_setup_stage("platform_runtime_gate", _platform_gate)
    _at_setup_stage(
        "request_validation",
        lambda: _require(type(port) is int and 0 <= port <= 65535 and type(no_browser) is bool),
    )
    from . import macos_file_access_workspace
    from .api import browser_console_url
    from .macos_file_access_peer import _supported_runtime
    from .runner_bootstrap import load_runner_manifest

    _at_setup_stage("platform_runtime_gate", lambda: _require(_supported_runtime()))
    package_module = sys.modules.get("bluefire")
    _at_setup_stage("package_import_custody", lambda: _require(package_module is not None))
    package_file = getattr(package_module, "__file__", None)
    _at_setup_stage(
        "package_import_custody", lambda: _require(type(package_file) is str and bool(package_file))
    )
    package_root = _at_setup_stage(
        "package_import_custody",
        lambda: Path(cast(str, package_file)).resolve(strict=True).parent.parent,
    )
    _at_setup_stage(
        "package_import_custody",
        lambda: _require(package_root.name in {"site-packages", "dist-packages"}),
    )
    validation = macos_file_access_workspace.validation

    def inventory_package_imports() -> dict[str, str]:
        validation._parents(package_root)
        return _walk_imports(package_root, limit=_MAX_IMPORT_FILES)

    source_sha256 = _at_setup_stage("package_import_custody", inventory_package_imports)
    _at_setup_stage(
        "package_import_custody",
        lambda: validation._import_inventory(
            [str(package_root)],
            {str(package_root / name): digest for name, digest in source_sha256.items()},
        ),
    )
    python = _at_setup_stage(
        "interpreter_custody", lambda: Path(sys.executable).resolve(strict=True)
    )
    python_sha256 = _at_setup_stage(
        "interpreter_custody", lambda: _verified_interpreter(python, validation)
    )
    # This executes the pinned interpreter as root. Its parent chain and file
    # custody are verified before the first subprocess probe.
    runtime_import_roots = _at_setup_stage(
        "runtime_import_custody", lambda: _isolated_runtime_roots(python)
    )
    runtime_sha256: dict[str, str] = {}
    runtime_bytes = 0

    def inventory_runtime_imports() -> None:
        nonlocal runtime_bytes
        for raw_root in runtime_import_roots:
            root = Path(raw_root)
            if not root.exists():
                _require(root.suffix == ".zip")
                continue
            if root.is_file():
                runtime_sha256[str(root)] = _hash_file(root)
                runtime_bytes += root.stat().st_size
            else:
                for relative, digest in _walk_imports(root, limit=4096).items():
                    path = root / relative
                    runtime_sha256[str(path)] = digest
                    runtime_bytes += path.stat().st_size
            _require(len(runtime_sha256) <= 4096 and runtime_bytes <= _MAX_IMPORT_BYTES)
        validation._import_inventory(runtime_import_roots, runtime_sha256)

    _at_setup_stage("runtime_import_custody", inventory_runtime_imports)
    native_resources = _at_setup_stage(
        "runner_manifest", lambda: resources.files("bluefire.native")
    )
    manifest = _at_setup_stage(
        "runner_manifest", lambda: load_runner_manifest(resource_root=native_resources)
    )
    native_resource = _at_setup_stage(
        "runner_manifest", lambda: native_resources.joinpath(manifest.filename)
    )
    _at_setup_stage("workspace_parent_reservation", _ensure_workspace_parent)
    return _at_setup_stage(
        "protected_setup_lifecycle",
        lambda: _with_setup_reservation(
            lambda: _run_reserved_workspace(
                port=port,
                no_browser=no_browser,
                python=python,
                python_sha256=python_sha256,
                package_root=package_root,
                source_sha256=source_sha256,
                runtime_import_roots=runtime_import_roots,
                runtime_sha256=runtime_sha256,
                manifest=manifest,
                native_resource=native_resource,
                browser_console_url=browser_console_url,
                macos_file_access_workspace=macos_file_access_workspace,
            )
        ),
    )


def _run_reserved_workspace(
    *,
    port: int,
    no_browser: bool,
    python: Path,
    python_sha256: str,
    package_root: Path,
    source_sha256: dict[str, str],
    runtime_import_roots: list[str],
    runtime_sha256: dict[str, str],
    manifest: Any,
    native_resource: Any,
    browser_console_url: Any,
    macos_file_access_workspace: Any,
) -> dict[str, Any]:
    from . import macos_file_access_bridge, macos_file_access_creator
    from .runner_client import SubprocessRustRunner

    owner_credential, reader_credential = _at_setup_stage(
        "temporary_identity_selection", temporary_credentials
    )
    runtime_root = WORKSPACE_PARENT / ("runner-runtime-" + secrets.token_hex(16))
    _at_setup_stage(
        "workspace_directory_creation", lambda: _make_directory(runtime_root, mode=0o700)
    )

    with resources.as_file(native_resource) as native_path:
        native = Path(native_path).resolve(strict=True)
        _at_setup_stage(
            "native_resource_validation", lambda: _require(_hash_file(native) == manifest.sha256)
        )
        _at_setup_stage(
            "native_resource_validation",
            lambda: macos_file_access_workspace.validation._protected_file(native, manifest.sha256),
        )
        runtime = _at_setup_stage(
            "native_runner_initialization", lambda: SubprocessRustRunner(native, runtime_root)
        )
        retained_creators: list[Any] = []
        retained_owners: list[Any] = []
        creator = owner = None
        binding = None
        shutdown_result = None
        stopped = threading.Event()
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def stop_on_sigterm(_signum, _frame):
            stopped.set()

        signal.signal(signal.SIGTERM, stop_on_sigterm)
        try:
            creator = _at_setup_stage(
                "namespace_creation",
                lambda: macos_file_access_creator.MacOSFileAccessCreator.create(
                    runtime,
                    owner=owner_credential,
                    reader=reader_credential,
                    retained=retained_creators,
                ),
            )
            binding = _at_setup_stage(
                "resource_baseline_review", lambda: creator.review_context("baseline")["binding"]
            )
            generation = binding["generation"]
            workspace_root = WORKSPACE_PARENT / generation

            def create_workspace_directories() -> None:
                _require(not workspace_root.exists() and not workspace_root.is_symlink())
                _make_directory(
                    workspace_root,
                    mode=0o700,
                    owner=owner_credential["effective_uid"],
                    group=owner_credential["effective_gid"],
                )
                _make_directory(
                    workspace_root / "runs",
                    mode=0o700,
                    owner=owner_credential["effective_uid"],
                    group=owner_credential["effective_gid"],
                )
                cache_parent = WORKSPACE_PARENT / "runtime-cache"
                if cache_parent.exists() or cache_parent.is_symlink():
                    macos_file_access_workspace.validation._directory(cache_parent)
                    _require(stat.S_IMODE(cache_parent.lstat().st_mode) == 0o711)
                else:
                    _make_directory(cache_parent, mode=0o711)
                pycache_root = cache_parent / generation
                _make_directory(pycache_root, mode=0o755)

            _at_setup_stage("workspace_directory_creation", create_workspace_directories)
            owner = _at_setup_stage(
                "owner_service_prepare",
                lambda: macos_file_access_workspace.MacOSWorkspaceOwner.prepare(
                    creator,
                    python=python,
                    python_sha256=python_sha256,
                    package_root=package_root,
                    source_sha256=source_sha256,
                    runtime_import_roots=runtime_import_roots,
                    runtime_sha256=runtime_sha256,
                    workspace_root=workspace_root,
                    config=_fixed_config(),
                    retained=retained_owners,
                    port=port,
                ),
            )
            _at_setup_stage(
                "service_startup", lambda: macos_file_access_bridge.start_workspace(owner)
            )
            ready = _at_setup_stage("ui_readiness", owner.ui_readiness)
            url = browser_console_url(
                ready["host"], ready["port"], ready["browser_bootstrap_capability"]
            )
            print(
                f"BlueFire original macOS file-access workspace: {url if no_browser else url.split('#', 1)[0]}",
                file=sys.stderr,
            )
            print(
                f"One-time connection code: {ready['browser_bootstrap_capability']}",
                file=sys.stderr,
            )
            sys.stderr.flush()
            if not no_browser:
                from .browser_launch import open_console_url

                try:
                    open_console_url(url.split("#", 1)[0])
                except (OSError, RuntimeError):
                    print(
                        "The local console is ready; open the printed address manually.",
                        file=sys.stderr,
                    )
            stopped.wait()
        except KeyboardInterrupt:
            pass
        finally:
            if creator is None and retained_creators:
                creator = retained_creators[0]
            if owner is None and retained_owners:
                owner = retained_owners[0]
            current_binding = _fresh_shutdown_binding(creator)
            owner_result: Any = {"host_closed": True, "scope": "not_started"}
            creator_result: Any = {
                "workers_closed": True,
                "namespace_handles_closed": True,
                "fixture_removed": False,
                "scope": "not_started",
            }
            if owner is not None and getattr(owner, "_state", None) != "preparing":
                try:
                    owner_result = owner.close()
                except BaseException:
                    owner_result = {
                        "host_closed": False,
                        "scope": "original_workspace_host_only",
                        "cleanup_error": "unknown",
                    }
            if creator is not None and getattr(creator, "_state", None) != "creating":
                try:
                    creator_result = creator.close()
                except BaseException:
                    creator_result = {
                        "workers_closed": False,
                        "namespace_handles_closed": False,
                        "fixture_removed": False,
                        "scope": "original_component_retirement_only",
                        "cleanup_error": "unknown",
                    }
            if current_binding is not None:
                shutdown_result = _shutdown_projection(
                    owner_result, creator_result, current_binding
                )
            else:
                shutdown_result = {
                    "schema_version": "bluefire.macos-file-access-local-supervisor-result.v1",
                    "status": "cleanup_unknown",
                    "host": owner_result,
                    "components": creator_result,
                    "generated_resource": {
                        "resource_retained": True,
                        "fixture_removed": False,
                        "whole_setup_cleanup_proven": False,
                        "state_at_shutdown": "unknown",
                    },
                    "workspace_retained": True,
                    "identity_accounts_created": False,
                }
            signal.signal(signal.SIGTERM, previous_sigterm)
        return shutdown_result
