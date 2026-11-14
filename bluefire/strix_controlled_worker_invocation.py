"""Digest-bound projection of one reviewed Strix launch plan.

The installed worker derives the fixed upstream CLI invocation from this
projection.  It never executes a caller-selected program or accepts arbitrary
arguments, environment names, provider credentials, or host paths.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping

from . import strix_adapter as adapter
from . import strix_controlled_backend as backend
from . import strix_startup_overlay as startup_overlay
from .util import canonical_json_bytes, content_hash, file_hash

SCHEMA_VERSION = "bluefire.strix-controlled-worker-invocation.v1"
PROC_MEMFD_INPUT_MODE = "proc_memfd"
DESCRIPTOR_BIND_INPUT_MODE = "descriptor_bind_files"
DESCRIPTOR_BIND_GUEST_CWD = Path("/workspace")
DESCRIPTOR_BIND_GUEST_EXECUTABLE = Path("/runtime/bin/strix")
DESCRIPTOR_BIND_GUEST_EXECUTABLE_MODE = 0o444
DESCRIPTOR_BIND_GUEST_RUNTIME_UID = 0
DESCRIPTOR_BIND_GUEST_HOME = Path("/home/worker")
DESCRIPTOR_BIND_GUEST_PATH = "/runtime/bin"
DESCRIPTOR_BIND_GUEST_TMP = Path("/tmp")
_DESCRIPTOR_BIND_PATHS = (
    Path("/inputs/objective.json"),
    Path("/inputs/config.json"),
    Path("/inputs/mcp.json"),
)
_PROJECTION_SCHEMA = "bluefire.strix-controlled-worker-installed-projection.v1"
PROC_MEMFD_PROJECTION_REF: str = content_hash(
    {
        "schema_version": _PROJECTION_SCHEMA,
        "mode": PROC_MEMFD_INPUT_MODE,
        "projection": "validated-launch-intent-paths",
    }
)
DESCRIPTOR_BIND_PROJECTION_REF: str = content_hash(
    {
        "schema_version": _PROJECTION_SCHEMA,
        "mode": DESCRIPTOR_BIND_INPUT_MODE,
        "argv0": str(DESCRIPTOR_BIND_GUEST_EXECUTABLE),
        "argv0_mode": DESCRIPTOR_BIND_GUEST_EXECUTABLE_MODE,
        "argv0_uid": DESCRIPTOR_BIND_GUEST_RUNTIME_UID,
        "cwd": str(DESCRIPTOR_BIND_GUEST_CWD),
        "home": str(DESCRIPTOR_BIND_GUEST_HOME),
        "path": DESCRIPTOR_BIND_GUEST_PATH,
        "tmpdir": str(DESCRIPTOR_BIND_GUEST_TMP),
        "inputs": [str(path) for path in _DESCRIPTOR_BIND_PATHS],
    }
)


def installed_projection_ref(mode: str) -> str:
    if mode == PROC_MEMFD_INPUT_MODE:
        return PROC_MEMFD_PROJECTION_REF
    if mode == DESCRIPTOR_BIND_INPUT_MODE:
        return DESCRIPTOR_BIND_PROJECTION_REF
    raise _refuse()


def fixed_guest_console_script(source: bytes) -> bytes:
    """Rewrite only the admitted console-script shebang for the pivot runtime."""
    if (
        type(source) is not bytes
        or not 0 < len(source) <= 32 * 1024
        or b"\x00" in source
        or not source.startswith(b"#!")
        or b"\n" not in source
    ):
        raise _refuse()
    _shebang, body = source.split(b"\n", 1)
    if b"from strix.interface.main import main" not in body:
        raise _refuse()
    return b"#!/runtime/bin/python\n" + body


def guest_console_script_sha256(path: Path) -> str:
    try:
        source = path.read_bytes()
    except OSError:
        raise _refuse() from None
    return "sha256:" + hashlib.sha256(fixed_guest_console_script(source)).hexdigest()


_ENVIRONMENT_NAMES = frozenset(
    {
        "HOME",
        "PATH",
        "TMPDIR",
        "STRIX_LLM",
        "STRIX_API_TYPE",
        "LLM_API_BASE",
        "STRIX_IMAGE",
        "STRIX_RUNTIME_BACKEND",
        "STRIX_DOCKER_SANDBOX_NETWORK",
        "STRIX_RUN_ID",
        "STRIX_RUN_TYPE",
        "STRIX_TELEMETRY",
        "STRIX_NO_UPDATE_CHECK",
        "STRIX_RUN_RECORD_TIMINGS",
        "STRIX_SANDBOX_MEM_LIMIT",
        "STRIX_SANDBOX_CPUS",
        "STRIX_SANDBOX_PIDS_LIMIT",
        "STRIX_SANDBOX_LOG_MAX_SIZE",
        "STRIX_SANDBOX_LOG_MAX_FILE",
    }
)


class ControlledWorkerInvocationError(RuntimeError):
    """The reviewed plan cannot be represented by the fixed worker entrypoint."""


def _refuse() -> ControlledWorkerInvocationError:
    return ControlledWorkerInvocationError("controlled worker invocation refused")


def _adapter_attempt(profile_attempt_id: str) -> str:
    if not isinstance(profile_attempt_id, str) or not profile_attempt_id.startswith(
        "engine-attempt-"
    ):
        raise _refuse()
    value = "attempt-" + profile_attempt_id.removeprefix("engine-attempt-")
    if adapter._ATTEMPT_ID.fullmatch(value) is None:
        raise _refuse()
    return value


def _pairs(value: Mapping[str, str] | tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    try:
        pairs = tuple(sorted(dict(value).items()))
    except (TypeError, ValueError):
        raise _refuse() from None
    if any(type(name) is not str or type(item) is not str for name, item in pairs):
        raise _refuse()
    return pairs


def _strict_json(payload: bytes) -> Any:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in rows:
            if name in result:
                raise ValueError("duplicate")
            result[name] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
        if canonical_json_bytes(value) + b"\n" != payload:
            raise ValueError("noncanonical")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise _refuse() from None


def _regular_bytes(path: Path, *, maximum: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise _refuse()
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= maximum
        ):
            raise _refuse()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(maximum + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or path.is_symlink()
        ):
            raise _refuse()
        return payload
    except OSError:
        raise _refuse() from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sealed_memfd(name: str, payload: bytes) -> int:
    try:
        import fcntl

        required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        descriptor = os.memfd_create(
            f"bluefire-strix-{name}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        os.set_inheritable(descriptor, False)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required != required:
            raise OSError("missing seal")
        return descriptor
    except (AttributeError, ImportError, OSError):
        if "descriptor" in locals():
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise _refuse() from None


def _sealed_bind_bytes(path: Path, *, maximum: int) -> bytes:
    """Read one helper-published sealed memfd through its fixed bind mount."""
    descriptor = -1
    try:
        import fcntl

        if not path.is_absolute() or path.is_symlink():
            raise _refuse()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) & 0o222
            or not 0 < before.st_size <= maximum
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required != required
        ):
            raise _refuse()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(maximum + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or path.is_symlink()
        ):
            raise _refuse()
        return payload
    except (AttributeError, ImportError, OSError):
        raise _refuse() from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


class PinnedWorkerInputs:
    """Sealed exact input bytes and their derived upstream argv."""

    __slots__ = ("argv", "cwd", "_descriptors", "_environment_overrides")

    def __init__(
        self,
        argv: tuple[str, ...],
        payloads: tuple[bytes, bytes, bytes],
        *,
        cwd: str,
    ) -> None:
        descriptors: list[int] = []
        try:
            for name, payload in zip(("objective", "config", "mcp"), payloads, strict=True):
                descriptors.append(_sealed_memfd(name, payload))
        except BaseException:
            for descriptor in descriptors:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        selected = list(argv)
        for index, descriptor in zip((9, 11, 13), descriptors, strict=True):
            selected[index] = f"/proc/self/fd/{descriptor}"
        self.argv = tuple(selected)
        self.cwd = cwd
        self._environment_overrides: tuple[tuple[str, str], ...] = ()
        self._descriptors = tuple(descriptors)

    @classmethod
    def descriptor_bind_files(cls, argv: tuple[str, ...]) -> "PinnedWorkerInputs":
        selected = list(argv)
        for index, path in zip((9, 11, 13), _DESCRIPTOR_BIND_PATHS, strict=True):
            selected[index] = str(path)
        selected[0] = str(DESCRIPTOR_BIND_GUEST_EXECUTABLE)
        value = cls.__new__(cls)
        value.argv = tuple(selected)
        value.cwd = str(DESCRIPTOR_BIND_GUEST_CWD)
        value._environment_overrides = (
            ("HOME", str(DESCRIPTOR_BIND_GUEST_HOME)),
            ("PATH", DESCRIPTOR_BIND_GUEST_PATH),
            ("TMPDIR", str(DESCRIPTOR_BIND_GUEST_TMP)),
        )
        value._descriptors = ()
        return value

    def runtime_environment(self, base: Mapping[str, str]) -> dict[str, str]:
        environment = dict(base)
        environment.update(self._environment_overrides)
        return environment

    def close(self) -> None:
        descriptors = getattr(self, "_descriptors", ())
        self._descriptors = ()
        for descriptor in descriptors:
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> "PinnedWorkerInputs":
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class ControlledWorkerInvocation:
    schema_version: str
    profile_attempt_id: str
    adapter_attempt_id: str
    intent_digest: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: str
    wall_seconds: int
    target: str
    target_origin: str
    resolved_addresses: tuple[str, ...]
    target_snapshot_digest: str
    scope_digest: str
    network_policy_digest: str
    engine: tuple[tuple[str, str], ...]
    model: str
    model_authorization_digest: str
    startup_overlay_receipt: tuple[tuple[str, str], ...]
    startup_overlay_ref: str
    guest_executable_sha256: str
    objective_sha256: str
    config_sha256: str
    mcp_sha256: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != SCHEMA_VERSION
            or self.adapter_attempt_id != _adapter_attempt(self.profile_attempt_id)
            or adapter._SHA256.fullmatch(self.intent_digest) is None
            or adapter._SHA256.fullmatch(self.objective_sha256) is None
            or adapter._SHA256.fullmatch(self.config_sha256) is None
            or adapter._SHA256.fullmatch(self.mcp_sha256) is None
            or adapter._SHA256.fullmatch(self.startup_overlay_ref) is None
            or adapter._SHA256.fullmatch(self.guest_executable_sha256) is None
            or type(self.wall_seconds) is not int
            or not 30 <= self.wall_seconds <= 3600
            or type(self.argv) is not tuple
            or len(self.argv) != 20
            or type(self.environment) is not tuple
            or _pairs(self.environment) != self.environment
            or set(dict(self.environment)) != _ENVIRONMENT_NAMES
            or type(self.engine) is not tuple
            or _pairs(self.engine) != self.engine
            or _pairs(self.startup_overlay_receipt) != self.startup_overlay_receipt
        ):
            raise _refuse()
        startup_receipt = startup_overlay.reviewed_startup_overlay_receipt().to_dict()
        if (
            dict(self.startup_overlay_receipt) != startup_receipt
            or self.startup_overlay_ref != startup_overlay.STARTUP_OVERLAY_RECEIPT_REF
        ):
            raise _refuse()
        environment = dict(self.environment)
        argv = self.argv
        cwd = Path(self.cwd)
        objective = cwd / "objective.txt"
        config = cwd / "config" / "cli-config.json"
        mcp = cwd / "config" / "mcp-servers.json"
        if (
            not cwd.is_absolute()
            or argv[1:]
            != (
                "-n",
                "--target",
                self.target,
                "--scan-mode",
                "quick",
                "--scope-mode",
                "full",
                "--instruction-file",
                str(objective),
                "--config",
                str(config),
                "--mcp-config",
                str(mcp),
                "--max-turns",
                argv[15],
                "--max-budget",
                argv[17],
                "--fail-on",
                "info",
            )
            or not argv[15].isascii()
            or not argv[15].isdigit()
            or not 1 <= int(argv[15]) <= 100
            or environment["HOME"] != str(cwd / "home")
            or environment["TMPDIR"] != str(cwd / "tmp")
            or environment["STRIX_LLM"] != self.model
            or environment["STRIX_API_TYPE"] != adapter.STRIX_API_TYPE
            or environment["STRIX_IMAGE"] != dict(self.engine).get("image_reference")
            or environment["STRIX_RUNTIME_BACKEND"] != backend.BACKEND_NAME
            or environment["STRIX_RUN_ID"] != self.adapter_attempt_id
            or environment["STRIX_RUN_TYPE"] != "bluefire"
            or environment["STRIX_TELEMETRY"] != "false"
            or environment["STRIX_NO_UPDATE_CHECK"] != "1"
            or environment["STRIX_RUN_RECORD_TIMINGS"] != "true"
            or self.target_origin
            != adapter.StrixScope(
                target=self.target,
                resolved_addresses=self.resolved_addresses,
                target_snapshot_digest=self.target_snapshot_digest,
                scope_digest=self.scope_digest,
                network_policy_digest=self.network_policy_digest,
                network_name=environment["STRIX_DOCKER_SANDBOX_NETWORK"],
            ).origin
        ):
            raise _refuse()
        adapter.StrixModelGateway(
            model=self.model,
            base_url=environment["LLM_API_BASE"],
            authorization_digest=self.model_authorization_digest,
        )
        adapter.StrixBudgets(
            wall_seconds=self.wall_seconds,
            max_turns_per_agent=int(argv[15]),
            max_model_cost_usd=argv[17],
        )
        body = {
            "schema_version": "bluefire.strix-launch-intent.v1",
            "attempt_id": self.adapter_attempt_id,
            "argv": list(argv),
            "environment": environment,
            "required_secret_environment": ["LLM_API_KEY"],
            "cwd": self.cwd,
            "wall_seconds": self.wall_seconds,
            "target": self.target,
            "target_origin": self.target_origin,
            "resolved_addresses": list(self.resolved_addresses),
            "target_snapshot_digest": self.target_snapshot_digest,
            "scope_digest": self.scope_digest,
            "network_policy_digest": self.network_policy_digest,
            "engine": dict(self.engine),
            "model": self.model,
            "model_authorization_digest": self.model_authorization_digest,
            "objective_sha256": self.objective_sha256,
        }
        if content_hash(body) != self.intent_digest:
            raise _refuse()

    @classmethod
    def from_plan(
        cls, plan: adapter.StrixLaunchPlan, *, profile_attempt_id: str
    ) -> "ControlledWorkerInvocation":
        if type(plan) is not adapter.StrixLaunchPlan:
            raise _refuse()
        cwd = Path(plan.cwd)
        objective = cwd / "objective.txt"
        config = cwd / "config" / "cli-config.json"
        mcp = cwd / "config" / "mcp-servers.json"
        value = cls(
            schema_version=SCHEMA_VERSION,
            profile_attempt_id=profile_attempt_id,
            adapter_attempt_id=plan.attempt_id,
            intent_digest=plan.intent_digest,
            argv=plan.argv,
            environment=plan.environment,
            cwd=str(cwd),
            wall_seconds=plan.wall_seconds,
            target=plan.target,
            target_origin=plan.target_origin,
            resolved_addresses=plan.resolved_addresses,
            target_snapshot_digest=plan.target_snapshot_digest,
            scope_digest=plan.scope_digest,
            network_policy_digest=plan.network_policy_digest,
            engine=_pairs(plan.engine),
            model=plan.model,
            model_authorization_digest=plan.model_authorization_digest,
            startup_overlay_receipt=_pairs(
                startup_overlay.reviewed_startup_overlay_receipt().to_dict()
            ),
            startup_overlay_ref=startup_overlay.STARTUP_OVERLAY_RECEIPT_REF,
            guest_executable_sha256=guest_console_script_sha256(Path(plan.argv[0])),
            objective_sha256=file_hash(objective),
            config_sha256=file_hash(config),
            mcp_sha256=file_hash(mcp),
        )
        if sys.platform == "linux":
            value.validate_installed_files()
        return value

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "ControlledWorkerInvocation":
        if type(value) is not dict or set(value) != {item.name for item in fields(cls)}:
            raise _refuse()
        try:
            return cls(
                **dict(
                    value,
                    argv=tuple(value["argv"]),
                    environment=tuple(tuple(pair) for pair in value["environment"]),
                    resolved_addresses=tuple(value["resolved_addresses"]),
                    engine=tuple(tuple(pair) for pair in value["engine"]),
                    startup_overlay_receipt=tuple(
                        tuple(pair) for pair in value["startup_overlay_receipt"]
                    ),
                )
            )
        except (TypeError, ValueError, KeyError):
            raise _refuse() from None

    def wire(self) -> dict[str, Any]:
        return asdict(self)

    def _validate_installed_paths(self) -> Path:
        cwd = Path(self.cwd)
        try:
            info = cwd.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or cwd.is_symlink()
                or cwd.resolve(strict=True) != cwd
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise _refuse()
            executable = Path(self.argv[0])
            engine = dict(self.engine)
            executable_info = executable.lstat()
            if (
                not executable.is_absolute()
                or executable.is_symlink()
                or not stat.S_ISREG(executable_info.st_mode)
                or file_hash(executable) != engine.get("executable_sha256")
            ):
                raise _refuse()
            for directory in (cwd / "home", cwd / "tmp", cwd / "config"):
                directory_info = directory.lstat()
                if (
                    directory.is_symlink()
                    or not stat.S_ISDIR(directory_info.st_mode)
                    or directory_info.st_uid != os.geteuid()
                    or stat.S_IMODE(directory_info.st_mode) != 0o700
                ):
                    raise _refuse()
            return cwd
        except (OSError, adapter.StrixAdapterError):
            raise _refuse() from None

    def _validated_installed_input_bytes(self) -> tuple[bytes, bytes, bytes]:
        cwd = self._validate_installed_paths()
        try:
            objective = _regular_bytes(cwd / "objective.txt", maximum=32 * 1024)
            config = _regular_bytes(cwd / "config" / "cli-config.json", maximum=4096)
            mcp = _regular_bytes(cwd / "config" / "mcp-servers.json", maximum=4096)
            if (
                "sha256:" + hashlib.sha256(objective).hexdigest() != self.objective_sha256
                or "sha256:" + hashlib.sha256(config).hexdigest() != self.config_sha256
                or "sha256:" + hashlib.sha256(mcp).hexdigest() != self.mcp_sha256
                or _strict_json(config) != {"env": {}}
                or _strict_json(mcp) != []
                or not objective.strip()
            ):
                raise _refuse()
            return objective, config, mcp
        except (OSError, adapter.StrixAdapterError):
            raise _refuse() from None

    def validate_installed_files(self) -> None:
        self._validated_installed_input_bytes()

    def pin_installed_inputs(self, *, mode: str = PROC_MEMFD_INPUT_MODE) -> PinnedWorkerInputs:
        if sys.platform != "linux":
            raise _refuse()
        if mode == PROC_MEMFD_INPUT_MODE:
            return PinnedWorkerInputs(
                self.argv, self._validated_installed_input_bytes(), cwd=self.cwd
            )
        if mode != DESCRIPTOR_BIND_INPUT_MODE:
            raise _refuse()
        self._validate_descriptor_bind_guest()
        objective = _sealed_bind_bytes(_DESCRIPTOR_BIND_PATHS[0], maximum=32 * 1024)
        config = _sealed_bind_bytes(_DESCRIPTOR_BIND_PATHS[1], maximum=4096)
        mcp = _sealed_bind_bytes(_DESCRIPTOR_BIND_PATHS[2], maximum=4096)
        if (
            "sha256:" + hashlib.sha256(objective).hexdigest() != self.objective_sha256
            or "sha256:" + hashlib.sha256(config).hexdigest() != self.config_sha256
            or "sha256:" + hashlib.sha256(mcp).hexdigest() != self.mcp_sha256
            or _strict_json(config) != {"env": {}}
            or _strict_json(mcp) != []
            or not objective.strip()
        ):
            raise _refuse()
        return PinnedWorkerInputs.descriptor_bind_files(self.argv)

    def _validate_descriptor_bind_guest(self) -> None:
        try:
            executable = DESCRIPTOR_BIND_GUEST_EXECUTABLE
            info = executable.lstat()
            if (
                executable.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != DESCRIPTOR_BIND_GUEST_EXECUTABLE_MODE
                or info.st_uid != DESCRIPTOR_BIND_GUEST_RUNTIME_UID
                or info.st_nlink != 1
                or file_hash(executable) != self.guest_executable_sha256
            ):
                raise _refuse()
            for directory in (
                DESCRIPTOR_BIND_GUEST_CWD,
                DESCRIPTOR_BIND_GUEST_HOME,
                DESCRIPTOR_BIND_GUEST_TMP,
            ):
                directory_info = directory.lstat()
                if (
                    directory.is_symlink()
                    or not stat.S_ISDIR(directory_info.st_mode)
                    or directory_info.st_uid != os.geteuid()
                    or stat.S_IMODE(directory_info.st_mode) != 0o700
                ):
                    raise _refuse()
        except (OSError, adapter.StrixAdapterError):
            raise _refuse() from None

    def runtime_environment(self, bootstrap_environment: Mapping[str, str]) -> dict[str, str]:
        if "LLM_API_KEY" in bootstrap_environment or "LLM_API_KEY" in dict(self.environment):
            raise _refuse()
        return dict(self.environment)


__all__ = [
    "ControlledWorkerInvocation",
    "ControlledWorkerInvocationError",
    "DESCRIPTOR_BIND_GUEST_CWD",
    "DESCRIPTOR_BIND_GUEST_EXECUTABLE",
    "DESCRIPTOR_BIND_GUEST_EXECUTABLE_MODE",
    "DESCRIPTOR_BIND_GUEST_RUNTIME_UID",
    "DESCRIPTOR_BIND_GUEST_HOME",
    "DESCRIPTOR_BIND_GUEST_PATH",
    "DESCRIPTOR_BIND_GUEST_TMP",
    "DESCRIPTOR_BIND_INPUT_MODE",
    "DESCRIPTOR_BIND_PROJECTION_REF",
    "PinnedWorkerInputs",
    "PROC_MEMFD_INPUT_MODE",
    "PROC_MEMFD_PROJECTION_REF",
    "fixed_guest_console_script",
    "guest_console_script_sha256",
    "installed_projection_ref",
]
