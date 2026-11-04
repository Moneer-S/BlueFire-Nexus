"""Pure admission, launch-plan, and result-projection mechanics for Strix.

This module never starts a process, opens a network connection, or grants
authority. The runtime supervisor must inject the one model-gateway secret,
enforce the recorded network policy, own the process/container descendants,
and verify cessation independently.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from .util import canonical_json_bytes, content_hash, file_hash

STRIX_PACKAGE_VERSION = "1.7.0"
STRIX_API_TYPE = "chat_completions"
STRIX_REQUIRED_SECRET_ENV = ("LLM_API_KEY",)
STRIX_SUPPORTED_STATUSES = frozenset({"running", "stopped", "interrupted", "failed", "completed"})
_ATTEMPT_ID = re.compile(r"^attempt-[0-9a-f]{32}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NETWORK = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")
_MEMORY = re.compile(r"^[1-9][0-9]{0,5}(?:[kKmMgG])?$|^[1-9][0-9]{0,12}$")
_CPUS = re.compile(r"^(?:0\.[1-9][0-9]?|[1-9][0-9]?(?:\.[0-9]{1,2})?)$")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_COVERAGE_BYTES = 4 * 1024 * 1024


class StrixAdapterError(ValueError):
    """A Strix candidate or attempt crossed its reviewed contract."""


def _require_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StrixAdapterError(f"{label} must be a sha256 digest")
    return value


def _require_text(value: str, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise StrixAdapterError(f"{label} is invalid")
    return value


def _canonical_url(value: str, label: str, *, allow_path: bool) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise StrixAdapterError(f"{label} is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise StrixAdapterError(f"{label} must be an exact HTTP(S) URL without credentials")
    try:
        hostname = parsed.hostname.encode("ascii").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError):
        raise StrixAdapterError(f"{label} host or port is invalid") from None
    if not allow_path and parsed.path not in {"", "/", "/v1"}:
        raise StrixAdapterError(f"{label} path is outside the supported gateway boundary")
    if any(char.isspace() for char in hostname):
        raise StrixAdapterError(f"{label} host is invalid")
    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None or default_port else f"{host}:{port}"
    canonical = urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    if canonical != value:
        raise StrixAdapterError(f"{label} must use its canonical URL form")
    return canonical


@dataclass(frozen=True, slots=True)
class StrixBuildIdentity:
    source_revision: str
    source_tree_sha256: str
    package_sha256: str
    executable_sha256: str
    image_reference: str
    image_inventory_sha256: str
    prompt_upstream_sha256: str
    prompt_overlay_sha256: str
    prompt_patched_sha256: str
    package_version: str = STRIX_PACKAGE_VERSION

    def __post_init__(self) -> None:
        if self.source_revision != REVIEWED_SOURCE_REVISION:
            raise StrixAdapterError("Strix source revision is not the reviewed pin")
        if self.package_version != STRIX_PACKAGE_VERSION:
            raise StrixAdapterError("Strix package version is not the reviewed declaration")
        for name in (
            "source_tree_sha256",
            "package_sha256",
            "executable_sha256",
            "image_inventory_sha256",
        ):
            _require_digest(getattr(self, name), name)
        if _IMAGE.fullmatch(self.image_reference) is None:
            raise StrixAdapterError("Strix image must be an exact sha256 reference")
        if self.prompt_upstream_sha256 != f"sha256:{REVIEWED_PROMPT_SHA256}":
            raise StrixAdapterError("Strix prompt preimage is not the reviewed source")
        if self.prompt_overlay_sha256 != f"sha256:{OVERLAY_SHA256}":
            raise StrixAdapterError("Strix prompt overlay is not the reviewed correction")
        if self.prompt_patched_sha256 != f"sha256:{PATCHED_PROMPT_SHA256}":
            raise StrixAdapterError("Strix patched prompt is not the reviewed result")

    def to_dict(self) -> dict[str, str]:
        return {
            "engine": "strix",
            "package_version": self.package_version,
            "source_revision": self.source_revision,
            "source_tree_sha256": self.source_tree_sha256,
            "package_sha256": self.package_sha256,
            "executable_sha256": self.executable_sha256,
            "image_reference": self.image_reference,
            "image_inventory_sha256": self.image_inventory_sha256,
            "prompt_upstream_sha256": self.prompt_upstream_sha256,
            "prompt_overlay_sha256": self.prompt_overlay_sha256,
            "prompt_patched_sha256": self.prompt_patched_sha256,
        }


@dataclass(frozen=True, slots=True)
class StrixScope:
    target: str
    resolved_addresses: tuple[str, ...]
    target_snapshot_digest: str
    scope_digest: str
    network_policy_digest: str
    network_name: str

    def __post_init__(self) -> None:
        _canonical_url(self.target, "Strix target", allow_path=True)
        for name in ("target_snapshot_digest", "scope_digest", "network_policy_digest"):
            _require_digest(getattr(self, name), name)
        if _NETWORK.fullmatch(self.network_name) is None:
            raise StrixAdapterError("Strix owned network name is invalid")
        if not self.resolved_addresses or len(self.resolved_addresses) > 16:
            raise StrixAdapterError("Strix target requires bounded resolved addresses")
        seen: set[str] = set()
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for value in self.resolved_addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                raise StrixAdapterError("Strix target address is invalid") from None
            canonical = str(address)
            if canonical != value or canonical in seen:
                raise StrixAdapterError("Strix target addresses must be unique and canonical")
            if (
                not (address.is_private or address.is_loopback)
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
            ):
                raise StrixAdapterError("Strix first milestone permits only isolated lab addresses")
            seen.add(canonical)
            parsed_addresses.append(address)
        expected_order = tuple(
            str(address)
            for address in sorted(parsed_addresses, key=lambda item: (item.version, int(item)))
        )
        if expected_order != self.resolved_addresses:
            raise StrixAdapterError("Strix target addresses must use canonical sorted order")

    @property
    def origin(self) -> str:
        parsed = urlsplit(self.target)
        return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


@dataclass(frozen=True, slots=True)
class StrixModelGateway:
    model: str
    base_url: str
    authorization_digest: str

    def __post_init__(self) -> None:
        _require_text(self.model, "Strix model identity", maximum=200)
        _canonical_url(self.base_url, "Strix model gateway", allow_path=False)
        _require_digest(self.authorization_digest, "Strix model authorization")


@dataclass(frozen=True, slots=True)
class StrixBudgets:
    wall_seconds: int
    max_turns_per_agent: int
    max_model_cost_usd: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.wall_seconds, bool)
            or not 30 <= self.wall_seconds <= 3600
            or isinstance(self.max_turns_per_agent, bool)
            or not 1 <= self.max_turns_per_agent <= 100
        ):
            raise StrixAdapterError("Strix wall or turn budget is outside the reviewed bound")
        try:
            cost = Decimal(self.max_model_cost_usd)
        except (InvalidOperation, TypeError):
            raise StrixAdapterError("Strix model budget is invalid") from None
        if not cost.is_finite() or cost <= 0 or cost > Decimal("100"):
            raise StrixAdapterError("Strix model budget is outside the reviewed bound")
        canonical = format(cost.normalize(), "f")
        if canonical != self.max_model_cost_usd or len(canonical) > 12:
            raise StrixAdapterError("Strix model budget must use canonical decimal text")


@dataclass(frozen=True, slots=True)
class StrixRuntimeLimits:
    memory: str = "2g"
    cpus: str = "2"
    pids: int = 512
    log_size: str = "20m"
    log_files: int = 2

    def __post_init__(self) -> None:
        if _MEMORY.fullmatch(self.memory) is None or _MEMORY.fullmatch(self.log_size) is None:
            raise StrixAdapterError("Strix memory or log bound is invalid")
        if _CPUS.fullmatch(self.cpus) is None:
            raise StrixAdapterError("Strix CPU bound is invalid")
        if (
            isinstance(self.pids, bool)
            or not 32 <= self.pids <= 4096
            or isinstance(self.log_files, bool)
            or not 1 <= self.log_files <= 8
        ):
            raise StrixAdapterError("Strix process or log-file bound is invalid")


@dataclass(frozen=True, slots=True)
class StrixAttemptWorkspace:
    attempt_id: str
    cwd: Path
    home: Path
    temporary: Path
    objective_file: Path
    config_file: Path
    mcp_file: Path
    objective_sha256: str


@dataclass(frozen=True, slots=True)
class StrixLaunchPlan:
    attempt_id: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    required_secret_environment: tuple[str, ...]
    cwd: Path
    wall_seconds: int
    target: str
    target_origin: str
    resolved_addresses: tuple[str, ...]
    target_snapshot_digest: str
    scope_digest: str
    network_policy_digest: str
    engine: Mapping[str, str]
    model: str
    model_authorization_digest: str
    intent_digest: str

    def environment_dict(self) -> dict[str, str]:
        return dict(self.environment)

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.strix-launch-plan.v1",
            "attempt_id": self.attempt_id,
            "argv": list(self.argv),
            "environment": self.environment_dict(),
            "required_secret_environment": list(self.required_secret_environment),
            "cwd": str(self.cwd),
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
            "intent_digest": self.intent_digest,
        }


@dataclass(frozen=True, slots=True)
class StrixRunSnapshot:
    upstream_run_id: str
    run_directory: Path
    engine_status: str
    attempt_state: str
    completeness: str
    exit_reason: str | None
    process_exit_code: int | None
    process_classification: str
    engine_reported_findings: bool | None
    security_outcome: str
    caveats: tuple[str, ...]
    run_record_sha256: str
    coverage_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.strix-run-snapshot.v1",
            "upstream_run_id": self.upstream_run_id,
            "engine_status": self.engine_status,
            "attempt_state": self.attempt_state,
            "completeness": self.completeness,
            "exit_reason": self.exit_reason,
            "process_exit_code": self.process_exit_code,
            "process_classification": self.process_classification,
            "engine_reported_findings": self.engine_reported_findings,
            "security_outcome": self.security_outcome,
            "caveats": list(self.caveats),
            "run_record_sha256": self.run_record_sha256,
            "coverage_sha256": self.coverage_sha256,
        }


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def prepare_attempt_workspace(
    root: str | Path,
    *,
    attempt_id: str,
    objective: str,
) -> StrixAttemptWorkspace:
    """Create one exclusive, controller-owned attempt directory."""

    if _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise StrixAdapterError("Strix attempt identity is invalid")
    if not isinstance(objective, str):
        raise StrixAdapterError("Strix objective must be text")
    normalized = objective.replace("\r\n", "\n").replace("\r", "\n").strip()
    encoded = (normalized + "\n").encode("utf-8")
    if not normalized or len(encoded) > 32 * 1024 or b"\x00" in encoded:
        raise StrixAdapterError("Strix objective is empty or exceeds its byte bound")
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        raise StrixAdapterError("Strix workspace root must be an existing ordinary directory")
    base = base.resolve(strict=True)
    cwd = base / attempt_id
    try:
        cwd.mkdir(mode=0o700, exist_ok=False)
        home = cwd / "home"
        temporary = cwd / "tmp"
        config = cwd / "config"
        for directory in (home, temporary, config):
            directory.mkdir(mode=0o700, exist_ok=False)
        objective_file = cwd / "objective.txt"
        config_file = config / "cli-config.json"
        mcp_file = config / "mcp-servers.json"
        _write_exclusive(objective_file, encoded)
        _write_exclusive(config_file, canonical_json_bytes({"env": {}}) + b"\n")
        _write_exclusive(mcp_file, b"[]\n")
    except OSError as error:
        raise StrixAdapterError(
            "Strix attempt workspace could not be created exclusively"
        ) from error
    return StrixAttemptWorkspace(
        attempt_id=attempt_id,
        cwd=cwd,
        home=home,
        temporary=temporary,
        objective_file=objective_file,
        config_file=config_file,
        mcp_file=mcp_file,
        objective_sha256="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )


def _read_bounded_regular(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink():
        raise StrixAdapterError(f"Strix artifact {path.name} is not an ordinary file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StrixAdapterError(f"Strix artifact {path.name} is unreadable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StrixAdapterError(f"Strix artifact {path.name} is not an ordinary file")
        size = before.st_size
        if size < 1 or size > maximum:
            raise StrixAdapterError(f"Strix artifact {path.name} exceeds its byte bound")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        if (
            len(payload) != size
            or len(payload) > maximum
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or path.is_symlink()
        ):
            raise StrixAdapterError(f"Strix artifact {path.name} changed while read")
        return payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _strict_json_snapshot(path: Path, *, maximum: int) -> tuple[Any, str]:
    payload = _read_bounded_regular(path, maximum=maximum)

    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise StrixAdapterError(f"Strix artifact {path.name} repeats a JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                StrixAdapterError(f"Strix artifact {path.name} has a non-finite value")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StrixAdapterError(f"Strix artifact {path.name} is unreadable") from error
    return document, "sha256:" + hashlib.sha256(payload).hexdigest()


def _strict_json(path: Path, *, maximum: int) -> Any:
    return _strict_json_snapshot(path, maximum=maximum)[0]


def _validate_workspace(workspace: StrixAttemptWorkspace) -> None:
    if _ATTEMPT_ID.fullmatch(workspace.attempt_id) is None:
        raise StrixAdapterError("Strix attempt identity is invalid")
    if workspace.cwd.name != workspace.attempt_id:
        raise StrixAdapterError("Strix attempt identity does not match its workspace")
    fixed = {
        workspace.home: workspace.cwd / "home",
        workspace.temporary: workspace.cwd / "tmp",
        workspace.objective_file: workspace.cwd / "objective.txt",
        workspace.config_file: workspace.cwd / "config" / "cli-config.json",
        workspace.mcp_file: workspace.cwd / "config" / "mcp-servers.json",
    }
    if workspace.cwd.is_symlink() or not workspace.cwd.is_dir():
        raise StrixAdapterError("Strix attempt directory changed after preparation")
    cwd = workspace.cwd.resolve(strict=True)
    for path, expected in fixed.items():
        if path != expected or path.is_symlink():
            raise StrixAdapterError("Strix fixed workspace path changed after preparation")
        resolved = path.resolve(strict=True)
        if cwd not in resolved.parents:
            raise StrixAdapterError("Strix workspace child escaped its attempt directory")
    if not workspace.home.is_dir() or not workspace.temporary.is_dir():
        raise StrixAdapterError("Strix workspace directory changed after preparation")
    if any(
        not path.is_file()
        for path in (workspace.objective_file, workspace.config_file, workspace.mcp_file)
    ):
        raise StrixAdapterError("Strix workspace file changed after preparation")
    if _strict_json(workspace.config_file, maximum=4096) != {"env": {}}:
        raise StrixAdapterError("Strix config must be the empty reviewed environment")
    if _strict_json(workspace.mcp_file, maximum=4096) != []:
        raise StrixAdapterError("Strix MCP configuration must be an empty JSON list")
    if file_hash(workspace.objective_file) != workspace.objective_sha256:
        raise StrixAdapterError("Strix objective changed after workspace preparation")


def build_launch_plan(
    *,
    build: StrixBuildIdentity,
    scope: StrixScope,
    gateway: StrixModelGateway,
    budgets: StrixBudgets,
    limits: StrixRuntimeLimits,
    workspace: StrixAttemptWorkspace,
    executable: str | Path,
    path_environment: str,
) -> StrixLaunchPlan:
    """Build a secret-free argv/environment plan for trusted supervision."""

    _validate_workspace(workspace)
    binary = Path(executable)
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise StrixAdapterError("Strix executable must be an absolute reviewed file")
    if file_hash(binary) != build.executable_sha256:
        raise StrixAdapterError("Strix executable bytes do not match the reviewed build")
    if (
        not isinstance(path_environment, str)
        or not path_environment
        or len(path_environment) > 4096
        or "\x00" in path_environment
        or "\n" in path_environment
        or "\r" in path_environment
    ):
        raise StrixAdapterError("Strix PATH must be supplied explicitly")
    environment = {
        "HOME": str(workspace.home),
        "PATH": path_environment,
        "TMPDIR": str(workspace.temporary),
        "STRIX_LLM": gateway.model,
        "STRIX_API_TYPE": STRIX_API_TYPE,
        "LLM_API_BASE": gateway.base_url,
        "STRIX_IMAGE": build.image_reference,
        "STRIX_RUNTIME_BACKEND": "docker",
        "STRIX_DOCKER_SANDBOX_NETWORK": scope.network_name,
        "STRIX_RUN_ID": workspace.attempt_id,
        "STRIX_RUN_TYPE": "bluefire",
        "STRIX_TELEMETRY": "false",
        "STRIX_NO_UPDATE_CHECK": "1",
        "STRIX_RUN_RECORD_TIMINGS": "true",
        "STRIX_SANDBOX_MEM_LIMIT": limits.memory,
        "STRIX_SANDBOX_CPUS": limits.cpus,
        "STRIX_SANDBOX_PIDS_LIMIT": str(limits.pids),
        "STRIX_SANDBOX_LOG_MAX_SIZE": limits.log_size,
        "STRIX_SANDBOX_LOG_MAX_FILE": str(limits.log_files),
    }
    if "LLM_API_KEY" in environment:
        raise StrixAdapterError("Strix launch plan must not persist its gateway secret")
    argv = (
        str(binary),
        "-n",
        "--target",
        scope.target,
        "--scan-mode",
        "quick",
        "--scope-mode",
        "full",
        "--instruction-file",
        str(workspace.objective_file),
        "--config",
        str(workspace.config_file),
        "--mcp-config",
        str(workspace.mcp_file),
        "--max-turns",
        str(budgets.max_turns_per_agent),
        "--max-budget",
        budgets.max_model_cost_usd,
        "--fail-on",
        "info",
    )
    body = {
        "schema_version": "bluefire.strix-launch-intent.v1",
        "attempt_id": workspace.attempt_id,
        "argv": list(argv),
        "environment": environment,
        "required_secret_environment": list(STRIX_REQUIRED_SECRET_ENV),
        "cwd": str(workspace.cwd),
        "wall_seconds": budgets.wall_seconds,
        "target": scope.target,
        "target_origin": scope.origin,
        "resolved_addresses": list(scope.resolved_addresses),
        "target_snapshot_digest": scope.target_snapshot_digest,
        "scope_digest": scope.scope_digest,
        "network_policy_digest": scope.network_policy_digest,
        "engine": build.to_dict(),
        "model": gateway.model,
        "model_authorization_digest": gateway.authorization_digest,
        "objective_sha256": workspace.objective_sha256,
    }
    return StrixLaunchPlan(
        attempt_id=workspace.attempt_id,
        argv=argv,
        environment=tuple(sorted(environment.items())),
        required_secret_environment=STRIX_REQUIRED_SECRET_ENV,
        cwd=workspace.cwd,
        wall_seconds=budgets.wall_seconds,
        target=scope.target,
        target_origin=scope.origin,
        resolved_addresses=scope.resolved_addresses,
        target_snapshot_digest=scope.target_snapshot_digest,
        scope_digest=scope.scope_digest,
        network_policy_digest=scope.network_policy_digest,
        engine=build.to_dict(),
        model=gateway.model,
        model_authorization_digest=gateway.authorization_digest,
        intent_digest=content_hash(body),
    )


def _coverage_projection(
    document: Any, upstream_run_id: str
) -> tuple[bool, str | None, tuple[str, ...]]:
    if not isinstance(document, Mapping):
        raise StrixAdapterError("Strix coverage artifact must be an object")
    if document.get("run_id") != upstream_run_id or document.get("run_name") != upstream_run_id:
        raise StrixAdapterError("Strix coverage artifact names another run")
    completeness = document.get("completeness")
    if not isinstance(completeness, Mapping):
        raise StrixAdapterError("Strix coverage artifact has no completeness record")
    complete = completeness.get("complete")
    scan_status = completeness.get("scan_status")
    exit_reason = completeness.get("exit_reason")
    caveats = completeness.get("caveats")
    if (
        type(complete) is not bool
        or scan_status not in STRIX_SUPPORTED_STATUSES
        or (
            exit_reason is not None and (not isinstance(exit_reason, str) or len(exit_reason) > 100)
        )
        or not isinstance(caveats, list)
        or len(caveats) > 64
        or any(not isinstance(item, str) or len(item) > 2048 for item in caveats)
    ):
        raise StrixAdapterError("Strix coverage completeness is invalid")
    return complete, exit_reason, tuple(caveats)


def discover_run_snapshot(
    attempt_cwd: str | Path,
    *,
    expected_target: str,
    expected_instruction_sha256: str,
    process_exit_code: int | None,
    cancellation_requested: bool = False,
    cessation_verified: bool = False,
) -> StrixRunSnapshot:
    """Bind one fixed Strix run record and project it without security claims."""

    _canonical_url(expected_target, "Strix expected target", allow_path=True)
    _require_digest(expected_instruction_sha256, "Strix expected instruction")
    if process_exit_code is not None and (
        isinstance(process_exit_code, bool) or not -255 <= process_exit_code <= 255
    ):
        raise StrixAdapterError("Strix process exit code is invalid")
    cwd = Path(attempt_cwd)
    if cwd.is_symlink() or not cwd.is_dir():
        raise StrixAdapterError("Strix attempt directory is unavailable")
    cwd = cwd.resolve(strict=True)
    runs_root = cwd / "strix_runs"
    if runs_root.is_symlink() or not runs_root.is_dir():
        raise StrixAdapterError("Strix run directory is unavailable")
    entries = list(runs_root.iterdir())
    if len(entries) != 1:
        raise StrixAdapterError("Strix attempt must contain exactly one upstream run")
    run_directory = entries[0]
    if (
        run_directory.is_symlink()
        or not run_directory.is_dir()
        or _LABEL.fullmatch(run_directory.name) is None
    ):
        raise StrixAdapterError("Strix upstream run directory is invalid")
    run_record_path = run_directory / "run.json"
    record, run_record_hash = _strict_json_snapshot(run_record_path, maximum=_MAX_JSON_BYTES)
    if not isinstance(record, Mapping):
        raise StrixAdapterError("Strix run artifact must be an object")
    upstream_run_id = record.get("run_id")
    status = record.get("status")
    targets = record.get("targets_info")
    instruction = record.get("instruction")
    if (
        upstream_run_id != run_directory.name
        or record.get("run_name") != upstream_run_id
        or status not in STRIX_SUPPORTED_STATUSES
        or record.get("non_interactive") is not True
        or record.get("scan_mode") != "quick"
        or record.get("scope_mode") != "full"
        or not isinstance(targets, list)
        or len(targets) != 1
        or not isinstance(targets[0], Mapping)
        or targets[0].get("type") != "web_application"
        or targets[0].get("original") != expected_target
        or not isinstance(targets[0].get("details"), Mapping)
        or targets[0]["details"].get("target_url") != expected_target
        or not isinstance(instruction, str)
    ):
        raise StrixAdapterError("Strix run record does not match the admitted attempt")
    instruction_hash = (
        "sha256:" + hashlib.sha256(instruction.strip().encode("utf-8") + b"\n").hexdigest()
    )
    if instruction_hash != expected_instruction_sha256:
        raise StrixAdapterError("Strix run record objective changed after admission")

    coverage_path = run_directory / "coverage.json"
    coverage_hash: str | None = None
    complete = False
    exit_reason: str | None = None
    caveats: tuple[str, ...] = ("Strix coverage artifact is unavailable.",)
    coverage_scan_status: str | None = None
    if coverage_path.exists():
        coverage, coverage_hash = _strict_json_snapshot(coverage_path, maximum=_MAX_COVERAGE_BYTES)
        complete, exit_reason, caveats = _coverage_projection(coverage, upstream_run_id)
        coverage_scan_status = str(coverage["completeness"]["scan_status"])
        if coverage_scan_status != status:
            raise StrixAdapterError("Strix run and coverage status disagree")

    if process_exit_code is None:
        process_classification = "running_or_exit_unobserved"
        findings: bool | None = None
    elif process_exit_code == 2:
        process_classification = "findings_threshold"
        findings = True
    elif process_exit_code == 0:
        process_classification = "zero_exit"
        findings = None
    else:
        process_classification = "error_or_interruption"
        findings = None

    projected_caveats = list(caveats)
    if status == "running" and process_exit_code is None:
        attempt_state = "running"
        completeness = "unknown"
    elif status == "running":
        attempt_state = "unknown"
        completeness = "unknown"
        projected_caveats.append("The process exited but the persisted run still reports running.")
    elif cancellation_requested and cessation_verified and status in {"stopped", "interrupted"}:
        attempt_state = "cancelled"
        completeness = "partial"
    elif exit_reason in {"budget_exceeded", "max_budget_exceeded", "max_turns_exceeded"}:
        attempt_state = "budget_exhausted"
        completeness = "partial"
    elif status == "failed":
        attempt_state = "failed"
        completeness = "partial"
    elif status in {"stopped", "interrupted"}:
        attempt_state = "partial"
        completeness = "partial"
    elif status == "completed" and complete and process_exit_code in {0, 2}:
        attempt_state = "completed"
        completeness = "complete"
    else:
        attempt_state = "unknown"
        completeness = "unknown"
    if cancellation_requested and not cessation_verified:
        projected_caveats.append(
            "Cancellation was requested, but owned-work cessation is unverified."
        )

    return StrixRunSnapshot(
        upstream_run_id=upstream_run_id,
        run_directory=run_directory,
        engine_status=status,
        attempt_state=attempt_state,
        completeness=completeness,
        exit_reason=exit_reason,
        process_exit_code=process_exit_code,
        process_classification=process_classification,
        engine_reported_findings=findings,
        security_outcome="not_independently_established",
        caveats=tuple(projected_caveats),
        run_record_sha256=run_record_hash,
        coverage_sha256=coverage_hash,
    )
