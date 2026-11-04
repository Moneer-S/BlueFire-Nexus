"""Fixed local process lifecycle for the generated tenant-record lab.

This module is a controller boundary, not a general process launcher.  It can
prepare and supervise only the package-owned tenant target and controlled test
provider.  Commands, modules, paths, URLs, and environment variables are not
caller supplied.  A trusted backend provides the platform-specific POSIX
session or Windows Job implementation and returns independently checkable
custody receipts.

The boundary is intentionally separate from Strix containment.  Proving these
two local fixture processes stopped does not prove an engine container, model
gateway, or hosted network policy was contained.

The module-file seals are controller preflight evidence. Exact installed
qualification must additionally establish that ``python -I -B -m`` resolved
each fixed module to the sealed file; readiness receipts do not currently
attest the imported ``__file__``. This module therefore does not claim that
source identity proof by itself.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess  # nosec B404 - fixed package entrypoints only
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from importlib.util import find_spec
from pathlib import Path
from typing import IO, Any, Callable, Mapping, Protocol, TypeVar, cast

from .util import content_hash, parse_iso8601_datetime

PLAN_SCHEMA = "bluefire.tenant-lab-launch-plan.v1"
RECORD_SCHEMA = "bluefire.tenant-lab-lifecycle.v1"
TARGET_MODULE = "bluefire.tenant_record_target_child"
PROVIDER_MODULE = "bluefire.controlled_strix_provider"
MAX_PACKET_BYTES = 128 * 1024
MAX_LOG_BYTES = 256 * 1024

_RUN_ID = re.compile(r"^engine-lab-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_EnumT = TypeVar("_EnumT", bound=Enum)


class TenantLabLaunchError(RuntimeError):
    """Raised when the fixed lab lifecycle cannot be established truthfully."""


class TenantLabStartFailure(TenantLabLaunchError):
    """A start failed after durable reservation and best-effort settlement."""

    def __init__(self, message: str, record: "TenantLabLifecycleRecord") -> None:
        super().__init__(message)
        self.record = record


class TenantLabPreparationFailure(TenantLabLaunchError):
    """Preparation failed and scratch absence could not be proven."""


class ServiceRole(str, Enum):
    TARGET = "target"
    TEST_PROVIDER = "test_provider"


class LifecycleState(str, Enum):
    PREPARED = "prepared"
    LAUNCH_RESERVED = "launch_reserved"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    CLEANED = "cleaned"
    UNKNOWN = "unknown"


class Presence(str, Enum):
    RUNNING = "running"
    ABSENT = "verified_absent"
    UNKNOWN = "unknown"


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantLabLaunchError(f"{label} digest is invalid")
    return value


def _timestamp(value: str, label: str) -> str:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise TenantLabLaunchError(f"{label} timestamp is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise TenantLabLaunchError(f"{label} timestamp is invalid") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise TenantLabLaunchError(f"{label} timestamp is invalid")
    return value


def _at_or_after(value: str, prior: str, label: str) -> None:
    if parse_iso8601_datetime(value) < parse_iso8601_datetime(prior):
        raise TenantLabLaunchError(f"{label} timestamp is out of order")


def _bounded_bytes(value: bytes, label: str, maximum: int = MAX_PACKET_BYTES) -> bytes:
    if type(value) is not bytes or not 0 < len(value) <= maximum:
        raise TenantLabLaunchError(f"{label} is empty or oversized")
    return value


def _sha256_bytes(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def _provider_manifest_semantic_digest(value: bytes) -> str:
    """Match the controlled provider's canonical parsed-manifest digest."""

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, item in pairs:
            if name in result:
                raise ValueError("duplicate provider manifest field")
            result[name] = item
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite provider manifest value")

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
        if not isinstance(parsed, Mapping):
            raise ValueError("provider manifest is not an object")
        canonical = json.dumps(
            parsed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise TenantLabLaunchError("provider manifest is invalid") from exc
    return _sha256_bytes(canonical)


def _is_link_or_reparse(path: Path, details: os.stat_result | None = None) -> bool:
    observed = path.lstat() if details is None else details
    return path.is_symlink() or bool(getattr(observed, "st_file_attributes", 0) & _REPARSE_POINT)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TenantLabLaunchError(f"{label} must be text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TenantLabLaunchError(f"{label} must be an integer")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TenantLabLaunchError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str, maximum: int) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TenantLabLaunchError(f"{label} must be a bounded array")
    return tuple(_mapping(item, label) for item in value)


def _enum(enum_type: type[_EnumT], value: object, label: str) -> _EnumT:
    if not isinstance(value, str):
        raise TenantLabLaunchError(f"{label} is invalid")
    try:
        return cast(_EnumT, enum_type(value))
    except ValueError as exc:
        raise TenantLabLaunchError(f"{label} is invalid") from exc


def _exact(value: Mapping[str, object], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise TenantLabLaunchError(f"{label} fields are invalid")


def _endpoint_from_mapping(value: object, label: str) -> "LoopbackEndpoint":
    row = _mapping(value, f"{label} endpoint")
    _exact(row, {"host", "port"}, f"{label} endpoint")
    return LoopbackEndpoint(
        host=_text(row["host"], f"{label} host"),
        port=_integer(row["port"], f"{label} port"),
    )


@dataclass(frozen=True, slots=True)
class LoopbackEndpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        if self.host not in {"127.0.0.1", "::1"}:
            raise TenantLabLaunchError("lab endpoint must be numeric loopback")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise TenantLabLaunchError("lab endpoint port is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True, slots=True)
class SealedFile:
    """Identity of one controller-selected regular file, including its bytes."""

    path: Path
    path_digest: str
    sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise TenantLabLaunchError("sealed file path is invalid")
        _digest(self.path_digest, "sealed file path")
        _digest(self.sha256, "sealed file")
        for value in (self.device, self.inode, self.size, self.mtime_ns):
            if type(value) is not int or value < 0:
                raise TenantLabLaunchError("sealed file identity is invalid")

    @property
    def digest(self) -> str:
        return content_hash(
            {
                "path_digest": self.path_digest,
                "sha256": self.sha256,
                "device": self.device,
                "inode": self.inode,
                "size": self.size,
                "mtime_ns": self.mtime_ns,
            }
        )


def _seal_file(path: Path) -> SealedFile:
    """Hash one regular file through its descriptor and reject identity drift."""

    import hashlib

    try:
        candidate = path.resolve(strict=True)
        before_path = candidate.lstat()
        if _is_link_or_reparse(candidate, before_path) or not stat.S_ISREG(before_path.st_mode):
            raise TenantLabLaunchError("fixed source is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise TenantLabLaunchError("fixed source is not a regular file")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)

        def identity(value: os.stat_result) -> tuple[int, int, int, int]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
            )

        if identity(before_path) != identity(before) or identity(before) != identity(after):
            raise TenantLabLaunchError("fixed source changed while it was inspected")
    except TenantLabLaunchError:
        raise
    except OSError as exc:
        raise TenantLabLaunchError("fixed source could not be inspected") from exc
    return SealedFile(
        path=candidate,
        path_digest=_sha256_bytes(os.fsencode(candidate)),
        sha256="sha256:" + digest.hexdigest(),
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        mtime_ns=after.st_mtime_ns,
    )


@dataclass(frozen=True, slots=True)
class RuntimeBinding:
    """Trusted preflight configuration; no path enters the launch plan.

    The seals bind intended installed files. An installed qualification must
    separately prove that isolated ``-m`` resolution imported those files.
    """

    python_path: Path
    target_path: Path
    provider_path: Path
    python_seal: SealedFile
    target_seal: SealedFile
    provider_seal: SealedFile

    @classmethod
    def current(cls) -> "RuntimeBinding":
        """Resolve only the installed package's fixed interpreter and modules."""

        target_spec = find_spec(TARGET_MODULE)
        provider_spec = find_spec(PROVIDER_MODULE)
        package_root = Path(__file__).resolve(strict=True).parent
        if target_spec is None or target_spec.origin is None:
            raise TenantLabLaunchError("packaged tenant target is unavailable")
        if provider_spec is None or provider_spec.origin is None:
            raise TenantLabLaunchError("packaged controlled provider is unavailable")
        target = Path(target_spec.origin).resolve(strict=True)
        provider = Path(provider_spec.origin).resolve(strict=True)
        if target.parent != package_root or target.name != "tenant_record_target_child.py":
            raise TenantLabLaunchError("tenant target is not package owned")
        if provider.parent != package_root or provider.name != "controlled_strix_provider.py":
            raise TenantLabLaunchError("controlled provider is not package owned")
        return cls._inspect(
            python_path=Path(sys.executable),
            target_path=target,
            provider_path=provider,
        )

    @classmethod
    def inspect_for_test(
        cls, *, python_path: Path, target_path: Path, provider_path: Path
    ) -> "RuntimeBinding":
        """Inject fixed files for unit qualification; production uses ``current``."""

        return cls._inspect(
            python_path=python_path,
            target_path=target_path,
            provider_path=provider_path,
        )

    @classmethod
    def _inspect(
        cls, *, python_path: Path, target_path: Path, provider_path: Path
    ) -> "RuntimeBinding":

        python = python_path.resolve(strict=True)
        target = target_path.resolve(strict=True)
        provider = provider_path.resolve(strict=True)
        if not python.is_file() or not target.is_file() or not provider.is_file():
            raise TenantLabLaunchError("fixed package runtime is unavailable")
        return cls(
            python_path=python,
            target_path=target,
            provider_path=provider,
            python_seal=_seal_file(python),
            target_seal=_seal_file(target),
            provider_seal=_seal_file(provider),
        )

    def __post_init__(self) -> None:
        expected = (
            (self.python_path, self.python_seal),
            (self.target_path, self.target_seal),
            (self.provider_path, self.provider_seal),
        )
        for path, seal in expected:
            if not isinstance(path, Path) or not path.is_absolute() or path != seal.path:
                raise TenantLabLaunchError("fixed package runtime path is invalid")
            if _seal_file(path) != seal:
                raise TenantLabLaunchError("fixed package runtime changed")

    @property
    def python_digest(self) -> str:
        return self.python_seal.sha256

    @property
    def target_digest(self) -> str:
        return self.target_seal.sha256

    @property
    def provider_digest(self) -> str:
        return self.provider_seal.sha256

    @property
    def digest(self) -> str:
        return content_hash(
            {
                "python_digest": self.python_digest,
                "target_digest": self.target_digest,
                "provider_digest": self.provider_digest,
                "target_module": TARGET_MODULE,
                "provider_module": PROVIDER_MODULE,
            }
        )

    def revalidate(self) -> None:
        """Rehash the exact interpreter and modules immediately before effects."""

        for path, seal in (
            (self.python_path, self.python_seal),
            (self.target_path, self.target_seal),
            (self.provider_path, self.provider_seal),
        ):
            if _seal_file(path) != seal:
                raise TenantLabLaunchError("fixed package runtime changed")


@dataclass(frozen=True, slots=True)
class TenantLabPackets:
    target_packet: bytes
    provider_manifest: bytes
    provider_token: bytes

    def __post_init__(self) -> None:
        _bounded_bytes(self.target_packet, "target packet")
        _bounded_bytes(self.provider_manifest, "provider manifest")
        token = _bounded_bytes(self.provider_token, "provider token", 512)
        if len(token) < 32 or any(byte < 33 or byte > 126 for byte in token):
            raise TenantLabLaunchError("provider token must be bounded printable ASCII")

    @property
    def target_digest(self) -> str:
        return _sha256_bytes(self.target_packet)

    @property
    def provider_manifest_digest(self) -> str:
        return _sha256_bytes(self.provider_manifest)

    @property
    def provider_token_digest(self) -> str:
        return _sha256_bytes(self.provider_token)


@dataclass(frozen=True, slots=True)
class TenantLabLaunchPlan:
    run_id: str
    attempt_id: str
    runtime_digest: str
    target_packet_digest: str
    provider_manifest_digest: str
    provider_token_digest: str
    target_endpoint: LoopbackEndpoint
    provider_endpoint: LoopbackEndpoint
    custody_mode: str
    max_runtime_seconds: int
    max_log_bytes: int
    created_at: str

    def __post_init__(self) -> None:
        if _RUN_ID.fullmatch(self.run_id) is None:
            raise TenantLabLaunchError("lab run identity is invalid")
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise TenantLabLaunchError("engine attempt identity is invalid")
        for label, value in (
            ("runtime", self.runtime_digest),
            ("target packet", self.target_packet_digest),
            ("provider manifest", self.provider_manifest_digest),
            ("provider token", self.provider_token_digest),
        ):
            _digest(value, label)
        if self.custody_mode not in {"posix_session", "windows_job_object"}:
            raise TenantLabLaunchError("lab custody mode is invalid")
        if self.provider_endpoint.host != "127.0.0.1":
            raise TenantLabLaunchError("controlled provider supports IPv4 loopback only")
        if type(self.max_runtime_seconds) is not int or not 1 <= self.max_runtime_seconds <= 900:
            raise TenantLabLaunchError("lab runtime limit is invalid")
        if type(self.max_log_bytes) is not int or not 1 <= self.max_log_bytes <= MAX_LOG_BYTES:
            raise TenantLabLaunchError("lab log limit is invalid")
        _timestamp(self.created_at, "plan creation")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PLAN_SCHEMA,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "runtime_digest": self.runtime_digest,
            "target_packet_digest": self.target_packet_digest,
            "provider_manifest_digest": self.provider_manifest_digest,
            "provider_token_digest": self.provider_token_digest,
            "target_endpoint": self.target_endpoint.to_dict(),
            "provider_endpoint": self.provider_endpoint.to_dict(),
            "custody_mode": self.custody_mode,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_log_bytes": self.max_log_bytes,
            "created_at": self.created_at,
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "TenantLabLaunchPlan":
        expected = {
            "schema_version",
            "run_id",
            "attempt_id",
            "runtime_digest",
            "target_packet_digest",
            "provider_manifest_digest",
            "provider_token_digest",
            "target_endpoint",
            "provider_endpoint",
            "custody_mode",
            "max_runtime_seconds",
            "max_log_bytes",
            "created_at",
        }
        if set(value) != expected or value.get("schema_version") != PLAN_SCHEMA:
            raise TenantLabLaunchError("lab launch plan fields are invalid")
        target = _endpoint_from_mapping(value["target_endpoint"], "target")
        provider = _endpoint_from_mapping(value["provider_endpoint"], "provider")
        return cls(
            run_id=_text(value["run_id"], "run identity"),
            attempt_id=_text(value["attempt_id"], "attempt identity"),
            runtime_digest=_text(value["runtime_digest"], "runtime digest"),
            target_packet_digest=_text(value["target_packet_digest"], "target packet digest"),
            provider_manifest_digest=_text(
                value["provider_manifest_digest"], "provider manifest digest"
            ),
            provider_token_digest=_text(value["provider_token_digest"], "provider token digest"),
            target_endpoint=target,
            provider_endpoint=provider,
            custody_mode=_text(value["custody_mode"], "custody mode"),
            max_runtime_seconds=_integer(value["max_runtime_seconds"], "runtime limit"),
            max_log_bytes=_integer(value["max_log_bytes"], "log limit"),
            created_at=_text(value["created_at"], "creation timestamp"),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceLayout:
    root: Path
    run_root: Path
    target_packet: Path
    target_audit: Path
    target_ready: Path
    provider_manifest: Path
    provider_token: Path
    provider_audit: Path
    provider_ready: Path

    @classmethod
    def for_run(cls, root: Path, run_id: str) -> "WorkspaceLayout":
        if _RUN_ID.fullmatch(run_id) is None:
            raise TenantLabLaunchError("lab run identity is invalid")
        base = root.resolve(strict=True)
        run_root = base / run_id
        return cls(
            root=base,
            run_root=run_root,
            target_packet=run_root / "target" / "packet.json",
            target_audit=run_root / "target" / "audit.jsonl",
            target_ready=run_root / "target" / "ready.json",
            provider_manifest=run_root / "provider" / "manifest.json",
            provider_token=run_root / "provider" / "token.txt",
            provider_audit=run_root / "provider" / "audit.jsonl",
            provider_ready=run_root / "provider" / "ready.json",
        )

    def __post_init__(self) -> None:
        if not self.root.is_absolute() or self.run_root.parent != self.root:
            raise TenantLabLaunchError("lab workspace is not contained")
        expected = {
            self.target_packet: ("target", "packet.json"),
            self.target_audit: ("target", "audit.jsonl"),
            self.target_ready: ("target", "ready.json"),
            self.provider_manifest: ("provider", "manifest.json"),
            self.provider_token: ("provider", "token.txt"),
            self.provider_audit: ("provider", "audit.jsonl"),
            self.provider_ready: ("provider", "ready.json"),
        }
        if any(
            path.parent != self.run_root / parts[0] or path.name != parts[1]
            for path, parts in expected.items()
        ):
            raise TenantLabLaunchError("lab workspace path grammar is invalid")


@dataclass(frozen=True, slots=True)
class FixedChildSpec:
    role: ServiceRole
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    endpoint: LoopbackEndpoint
    run_id: str
    attempt_id: str
    plan_digest: str
    packet_digest: str
    runtime_digest: str
    python_digest: str
    module_digest: str
    secondary_secret_digest: str | None
    python_source: SealedFile
    module_source: SealedFile
    packet_source: SealedFile
    secondary_secret_source: SealedFile | None
    custody_mode: str
    max_runtime_seconds: int
    max_log_bytes: int

    def __post_init__(self) -> None:
        if _RUN_ID.fullmatch(self.run_id) is None or _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise TenantLabLaunchError("child launch identity is invalid")
        _digest(self.plan_digest, "launch plan")
        _digest(self.packet_digest, "child packet")
        _digest(self.runtime_digest, "runtime")
        _digest(self.python_digest, "Python interpreter")
        _digest(self.module_digest, "child module")
        if self.secondary_secret_digest is not None:
            _digest(self.secondary_secret_digest, "secondary secret")
        if self.role is ServiceRole.TARGET and self.secondary_secret_digest is not None:
            raise TenantLabLaunchError("target command cannot receive provider secret material")
        if self.role is ServiceRole.TEST_PROVIDER and self.secondary_secret_digest is None:
            raise TenantLabLaunchError("provider command lacks its token binding")
        if self.role is ServiceRole.TEST_PROVIDER and self.endpoint.host != "127.0.0.1":
            raise TenantLabLaunchError("controlled provider supports IPv4 loopback only")
        if self.python_source.sha256 != self.python_digest:
            raise TenantLabLaunchError("child interpreter seal does not match its identity")
        if self.module_source.sha256 != self.module_digest:
            raise TenantLabLaunchError("child module seal does not match its identity")
        if self.packet_source.sha256 != self.packet_digest:
            raise TenantLabLaunchError("child packet seal does not match its identity")
        if self.secondary_secret_source is None:
            if self.secondary_secret_digest is not None:
                raise TenantLabLaunchError("child secret seal is missing")
        elif self.secondary_secret_source.sha256 != self.secondary_secret_digest:
            raise TenantLabLaunchError("child secret seal does not match its identity")
        if self.custody_mode not in {"posix_session", "windows_job_object"}:
            raise TenantLabLaunchError("child custody mode is invalid")
        if self.environment != (
            ("PYTHONDONTWRITEBYTECODE", "1"),
            ("PYTHONHASHSEED", "0"),
            ("PYTHONNOUSERSITE", "1"),
        ):
            raise TenantLabLaunchError("child environment is not the fixed allowlist")
        if not self.argv or any(not isinstance(value, str) or not value for value in self.argv):
            raise TenantLabLaunchError("child command is invalid")
        if not Path(self.argv[0]).is_absolute() or self.argv[1:4] != ("-I", "-B", "-m"):
            raise TenantLabLaunchError("child command is not the isolated package grammar")
        if Path(self.argv[0]) != self.python_source.path:
            raise TenantLabLaunchError("child command changed the sealed interpreter")
        if self.role is ServiceRole.TARGET:
            if (
                len(self.argv) != 16
                or self.argv[4:7] != (TARGET_MODULE, "--fixed-target", "--packet")
                or self.argv[8] != "--audit"
                or self.argv[10] != "--ready-file"
                or self.argv[12] != "--host"
                or self.argv[14] != "--port"
            ):
                raise TenantLabLaunchError("target command is not the fixed grammar")
            path_indexes: tuple[int, ...] = (7, 9, 11)
            if Path(self.argv[7]) != self.packet_source.path:
                raise TenantLabLaunchError("target command changed the sealed packet")
            run_root = self.packet_source.path.parent.parent
            if (
                run_root.name != self.run_id
                or self.packet_source.path != run_root / "target" / "packet.json"
                or Path(self.argv[9]) != run_root / "target" / "audit.jsonl"
                or Path(self.argv[11]) != run_root / "target" / "ready.json"
            ):
                raise TenantLabLaunchError("target command left its fixed run workspace")
        else:
            if (
                len(self.argv) != 17
                or self.argv[4:6] != (PROVIDER_MODULE, "--manifest")
                or self.argv[7] != "--token-file"
                or self.argv[9] != "--audit"
                or self.argv[11] != "--ready-file"
                or self.argv[13] != "--host"
                or self.argv[15] != "--port"
            ):
                raise TenantLabLaunchError("provider command is not the fixed grammar")
            path_indexes = (6, 8, 10, 12)
            if (
                Path(self.argv[6]) != self.packet_source.path
                or self.secondary_secret_source is None
                or Path(self.argv[8]) != self.secondary_secret_source.path
            ):
                raise TenantLabLaunchError("provider command changed its sealed inputs")
            run_root = self.packet_source.path.parent.parent
            if (
                run_root.name != self.run_id
                or self.packet_source.path != run_root / "provider" / "manifest.json"
                or self.secondary_secret_source.path != run_root / "provider" / "token.txt"
                or Path(self.argv[10]) != run_root / "provider" / "audit.jsonl"
                or Path(self.argv[12]) != run_root / "provider" / "ready.json"
            ):
                raise TenantLabLaunchError("provider command left its fixed run workspace")
        if any(not Path(self.argv[index]).is_absolute() for index in path_indexes):
            raise TenantLabLaunchError("child workspace path is not absolute")
        if self.argv[-3] != self.endpoint.host or self.argv[-1] != str(self.endpoint.port):
            raise TenantLabLaunchError("child endpoint changed after planning")
        if not 1 <= self.max_runtime_seconds <= 900 or not 1 <= self.max_log_bytes <= MAX_LOG_BYTES:
            raise TenantLabLaunchError("child resource limit is invalid")

    @property
    def digest(self) -> str:
        # Persist only identities and argument grammar. Raw local paths stay in
        # the process adapter and never enter product evidence.
        if self.role is ServiceRole.TARGET:
            argv_shape = [
                Path(self.argv[0]).name,
                *self.argv[1:7],
                Path(self.argv[7]).name,
                self.argv[8],
                Path(self.argv[9]).name,
                self.argv[10],
                Path(self.argv[11]).name,
                *self.argv[12:],
            ]
        else:
            argv_shape = [
                Path(self.argv[0]).name,
                *self.argv[1:6],
                Path(self.argv[6]).name,
                self.argv[7],
                Path(self.argv[8]).name,
                self.argv[9],
                Path(self.argv[10]).name,
                self.argv[11],
                Path(self.argv[12]).name,
                *self.argv[13:],
            ]
        return content_hash(
            {
                "role": self.role.value,
                "argv_shape": argv_shape,
                "endpoint": self.endpoint.to_dict(),
                "run_id": self.run_id,
                "attempt_id": self.attempt_id,
                "plan_digest": self.plan_digest,
                "packet_digest": self.packet_digest,
                "runtime_digest": self.runtime_digest,
                "python_digest": self.python_digest,
                "module_digest": self.module_digest,
                "secondary_secret_digest": self.secondary_secret_digest,
                "python_source_digest": self.python_source.digest,
                "module_source_digest": self.module_source.digest,
                "packet_source_digest": self.packet_source.digest,
                "secondary_secret_source_digest": (
                    None
                    if self.secondary_secret_source is None
                    else self.secondary_secret_source.digest
                ),
                "custody_mode": self.custody_mode,
                "max_runtime_seconds": self.max_runtime_seconds,
                "max_log_bytes": self.max_log_bytes,
            }
        )


@dataclass(frozen=True, slots=True)
class OwnedChild:
    role: ServiceRole
    pid: int
    process_identity_digest: str
    plan_digest: str
    custody_mode: str
    custody_snapshot_digest: str
    custody_receipt_digest: str
    spec_digest: str
    endpoint: LoopbackEndpoint
    started_at: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise TenantLabLaunchError("owned child PID is invalid")
        for label, value in (
            ("process identity", self.process_identity_digest),
            ("launch plan", self.plan_digest),
            ("custody snapshot", self.custody_snapshot_digest),
            ("custody receipt", self.custody_receipt_digest),
            ("launch specification", self.spec_digest),
        ):
            _digest(value, label)
        if self.custody_mode not in {"posix_session", "windows_job_object"}:
            raise TenantLabLaunchError("owned child custody mode is invalid")
        expected_receipt = content_hash(
            {
                "role": self.role.value,
                "process_identity_digest": self.process_identity_digest,
                "plan_digest": self.plan_digest,
                "spec_digest": self.spec_digest,
                "custody_mode": self.custody_mode,
                "custody_snapshot_digest": self.custody_snapshot_digest,
            }
        )
        if self.custody_receipt_digest != expected_receipt:
            raise TenantLabLaunchError("owned child custody receipt is not canonical")
        _timestamp(self.started_at, "child start")


@dataclass(frozen=True, slots=True)
class ReadinessReceipt:
    role: ServiceRole
    process_identity_digest: str
    spec_digest: str
    endpoint: LoopbackEndpoint
    binding_digest: str
    observed_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.endpoint.port == 0:
            raise TenantLabLaunchError("readiness endpoint is unresolved")
        for label, value in (
            ("process identity", self.process_identity_digest),
            ("launch specification", self.spec_digest),
            ("readiness binding", self.binding_digest),
            ("readiness receipt", self.receipt_digest),
        ):
            _digest(value, label)
        _timestamp(self.observed_at, "readiness")
        if self.receipt_digest != content_hash(
            {"binding_digest": self.binding_digest, "observed_at": self.observed_at}
        ):
            raise TenantLabLaunchError("readiness receipt is not canonical")


@dataclass(frozen=True, slots=True)
class LogSummary:
    byte_count: int
    sha256: str
    truncated: bool

    def __post_init__(self) -> None:
        if type(self.byte_count) is not int or self.byte_count < 0:
            raise TenantLabLaunchError("log byte count is invalid")
        _digest(self.sha256, "log")
        if type(self.truncated) is not bool:
            raise TenantLabLaunchError("log truncation marker is invalid")


@dataclass(frozen=True, slots=True)
class ProcessSettlement:
    role: ServiceRole
    process_identity_digest: str | None
    plan_digest: str
    custody_mode: str
    custody_snapshot_digest: str
    presence: Presence
    observed_at: str
    custody_receipt_digest: str
    stdout: LogSummary
    stderr: LogSummary

    def __post_init__(self) -> None:
        if self.process_identity_digest is not None:
            _digest(self.process_identity_digest, "process identity")
        _digest(self.plan_digest, "settlement plan")
        _digest(self.custody_snapshot_digest, "settlement custody snapshot")
        _digest(self.custody_receipt_digest, "custody settlement")
        _timestamp(self.observed_at, "process settlement")
        if self.custody_mode not in {"posix_session", "windows_job_object"}:
            raise TenantLabLaunchError("settlement custody mode is invalid")
        if self.custody_receipt_digest != content_hash(
            {
                "role": self.role.value,
                "process_identity_digest": self.process_identity_digest,
                "plan_digest": self.plan_digest,
                "custody_mode": self.custody_mode,
                "custody_snapshot_digest": self.custody_snapshot_digest,
                "presence": self.presence.value,
                "observed_at": self.observed_at,
                "stdout": {
                    "byte_count": self.stdout.byte_count,
                    "sha256": self.stdout.sha256,
                    "truncated": self.stdout.truncated,
                },
                "stderr": {
                    "byte_count": self.stderr.byte_count,
                    "sha256": self.stderr.sha256,
                    "truncated": self.stderr.truncated,
                },
            }
        ):
            raise TenantLabLaunchError("process settlement receipt is not canonical")


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    state: Presence
    plan_digest: str
    workspace_digest: str
    observed_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.state is Presence.RUNNING:
            raise TenantLabLaunchError("scratch cleanup cannot report running")
        _digest(self.plan_digest, "cleanup plan")
        _digest(self.workspace_digest, "cleanup workspace")
        _timestamp(self.observed_at, "cleanup")
        _digest(self.receipt_digest, "cleanup receipt")
        if self.receipt_digest != content_hash(
            {
                "state": self.state.value,
                "plan_digest": self.plan_digest,
                "workspace_digest": self.workspace_digest,
                "observed_at": self.observed_at,
            }
        ):
            raise TenantLabLaunchError("cleanup receipt is not canonical")


@dataclass(frozen=True, slots=True)
class LifecycleCommit:
    plan_digest: str
    prior_record_digest: str | None
    record_digest: str
    phase: str
    committed_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _digest(self.plan_digest, "commit plan")
        if self.prior_record_digest is not None:
            _digest(self.prior_record_digest, "prior record")
        _digest(self.record_digest, "committed record")
        if (
            not isinstance(self.phase, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.phase) is None
        ):
            raise TenantLabLaunchError("lifecycle commit phase is invalid")
        _timestamp(self.committed_at, "lifecycle commit")
        _digest(self.receipt_digest, "lifecycle commit receipt")
        if self.receipt_digest != content_hash(
            {
                "plan_digest": self.plan_digest,
                "prior_record_digest": self.prior_record_digest,
                "record_digest": self.record_digest,
                "phase": self.phase,
                "committed_at": self.committed_at,
            }
        ):
            raise TenantLabLaunchError("lifecycle commit receipt is not canonical")


def _child_from_mapping(value: Mapping[str, object]) -> OwnedChild:
    _exact(
        value,
        {
            "role",
            "pid",
            "process_identity_digest",
            "plan_digest",
            "custody_mode",
            "custody_snapshot_digest",
            "custody_receipt_digest",
            "spec_digest",
            "endpoint",
            "started_at",
        },
        "owned child",
    )
    return OwnedChild(
        role=_enum(ServiceRole, value["role"], "child role"),
        pid=_integer(value["pid"], "child PID"),
        process_identity_digest=_text(value["process_identity_digest"], "process identity digest"),
        plan_digest=_text(value["plan_digest"], "child plan digest"),
        custody_mode=_text(value["custody_mode"], "child custody mode"),
        custody_snapshot_digest=_text(value["custody_snapshot_digest"], "child custody snapshot"),
        custody_receipt_digest=_text(value["custody_receipt_digest"], "custody receipt digest"),
        spec_digest=_text(value["spec_digest"], "launch specification digest"),
        endpoint=_endpoint_from_mapping(value["endpoint"], "child"),
        started_at=_text(value["started_at"], "child start timestamp"),
    )


def _readiness_from_mapping(value: Mapping[str, object]) -> ReadinessReceipt:
    _exact(
        value,
        {
            "role",
            "process_identity_digest",
            "spec_digest",
            "endpoint",
            "binding_digest",
            "observed_at",
            "receipt_digest",
        },
        "readiness receipt",
    )
    return ReadinessReceipt(
        role=_enum(ServiceRole, value["role"], "readiness role"),
        process_identity_digest=_text(
            value["process_identity_digest"], "readiness process identity"
        ),
        spec_digest=_text(value["spec_digest"], "readiness specification"),
        endpoint=_endpoint_from_mapping(value["endpoint"], "readiness"),
        binding_digest=_text(value["binding_digest"], "readiness binding"),
        observed_at=_text(value["observed_at"], "readiness timestamp"),
        receipt_digest=_text(value["receipt_digest"], "readiness receipt"),
    )


def _log_from_mapping(value: object, label: str) -> LogSummary:
    row = _mapping(value, label)
    _exact(row, {"byte_count", "sha256", "truncated"}, label)
    truncated = row["truncated"]
    if type(truncated) is not bool:
        raise TenantLabLaunchError(f"{label} truncation marker is invalid")
    return LogSummary(
        byte_count=_integer(row["byte_count"], f"{label} byte count"),
        sha256=_text(row["sha256"], f"{label} digest"),
        truncated=truncated,
    )


def _settlement_from_mapping(value: Mapping[str, object]) -> ProcessSettlement:
    _exact(
        value,
        {
            "role",
            "process_identity_digest",
            "plan_digest",
            "custody_mode",
            "custody_snapshot_digest",
            "presence",
            "observed_at",
            "custody_receipt_digest",
            "stdout",
            "stderr",
        },
        "process settlement",
    )
    return ProcessSettlement(
        role=_enum(ServiceRole, value["role"], "settlement role"),
        process_identity_digest=_optional_text(
            value["process_identity_digest"], "settlement process identity"
        ),
        plan_digest=_text(value["plan_digest"], "settlement plan"),
        custody_mode=_text(value["custody_mode"], "settlement custody mode"),
        custody_snapshot_digest=_text(
            value["custody_snapshot_digest"], "settlement custody snapshot"
        ),
        presence=_enum(Presence, value["presence"], "settlement presence"),
        observed_at=_text(value["observed_at"], "settlement timestamp"),
        custody_receipt_digest=_text(value["custody_receipt_digest"], "settlement receipt"),
        stdout=_log_from_mapping(value["stdout"], "stdout summary"),
        stderr=_log_from_mapping(value["stderr"], "stderr summary"),
    )


def _cleanup_from_mapping(value: object) -> CleanupReceipt:
    row = _mapping(value, "cleanup receipt")
    _exact(
        row,
        {"state", "plan_digest", "workspace_digest", "observed_at", "receipt_digest"},
        "cleanup receipt",
    )
    return CleanupReceipt(
        state=_enum(Presence, row["state"], "cleanup state"),
        plan_digest=_text(row["plan_digest"], "cleanup plan"),
        workspace_digest=_text(row["workspace_digest"], "cleanup workspace"),
        observed_at=_text(row["observed_at"], "cleanup timestamp"),
        receipt_digest=_text(row["receipt_digest"], "cleanup receipt"),
    )


@dataclass(frozen=True, slots=True)
class TenantLabLifecycleRecord:
    plan: TenantLabLaunchPlan
    revision: int
    state: LifecycleState
    prepared_at: str
    reserved_at: str | None
    running_at: str | None
    ended_at: str | None
    children: tuple[OwnedChild, ...]
    readiness: tuple[ReadinessReceipt, ...]
    settlements: tuple[ProcessSettlement, ...]
    cleanup_receipt: CleanupReceipt | None

    def __post_init__(self) -> None:
        if type(self.revision) is not int or not 1 <= self.revision <= 100:
            raise TenantLabLaunchError("lab lifecycle revision is invalid")
        _timestamp(self.prepared_at, "preparation")
        _at_or_after(self.prepared_at, self.plan.created_at, "preparation")
        for value, label in (
            (self.reserved_at, "reservation"),
            (self.running_at, "running"),
            (self.ended_at, "ending"),
        ):
            if value is not None:
                _timestamp(value, label)
                _at_or_after(value, self.prepared_at, label)
        if self.reserved_at is not None and self.running_at is not None:
            _at_or_after(self.running_at, self.reserved_at, "running")
        if self.running_at is not None and self.ended_at is not None:
            _at_or_after(self.ended_at, self.running_at, "ending")
        if len(self.children) > 2 or len({item.role for item in self.children}) != len(
            self.children
        ):
            raise TenantLabLaunchError("lab child ownership is invalid")
        if len(self.readiness) > 2 or len({item.role for item in self.readiness}) != len(
            self.readiness
        ):
            raise TenantLabLaunchError("lab readiness ownership is invalid")
        if len(self.settlements) > 2 or len({item.role for item in self.settlements}) != len(
            self.settlements
        ):
            raise TenantLabLaunchError("lab process settlement is invalid")
        plan_digest = self.plan.digest
        children = {item.role: item for item in self.children}
        for child in self.children:
            if child.plan_digest != plan_digest or child.custody_mode != self.plan.custody_mode:
                raise TenantLabLaunchError("lab child belongs to another launch plan")
            if self.reserved_at is not None:
                _at_or_after(child.started_at, self.reserved_at, "child start")
        for ready in self.readiness:
            ready_child = children.get(ready.role)
            if (
                ready_child is None
                or ready.process_identity_digest != ready_child.process_identity_digest
                or ready.spec_digest != ready_child.spec_digest
                or ready.endpoint.host != ready_child.endpoint.host
                or (ready_child.endpoint.port != 0 and ready.endpoint != ready_child.endpoint)
            ):
                raise TenantLabLaunchError("lab readiness does not match its owned child")
            packet_digest = (
                self.plan.target_packet_digest
                if ready.role is ServiceRole.TARGET
                else self.plan.provider_manifest_digest
            )
            if ready.binding_digest != content_hash(
                {
                    "role": ready.role.value,
                    "process": ready_child.process_identity_digest,
                    "endpoint": ready.endpoint.to_dict(),
                    "packet": packet_digest,
                    "plan": plan_digest,
                }
            ):
                raise TenantLabLaunchError("lab readiness binding is invalid")
            _at_or_after(ready.observed_at, ready_child.started_at, "readiness")
            if self.running_at is not None:
                _at_or_after(self.running_at, ready.observed_at, "running")
        for settlement in self.settlements:
            if (
                settlement.plan_digest != plan_digest
                or settlement.custody_mode != self.plan.custody_mode
            ):
                raise TenantLabLaunchError("lab settlement belongs to another launch plan")
            settled_child = children.get(settlement.role)
            if settled_child is not None and (
                settlement.process_identity_digest != settled_child.process_identity_digest
                or settlement.custody_snapshot_digest != settled_child.custody_snapshot_digest
            ):
                raise TenantLabLaunchError("lab settlement changed the owned custody identity")
            if settled_child is None and settlement.process_identity_digest is not None:
                raise TenantLabLaunchError("lab settlement invented an unowned process identity")
            prior = settled_child.started_at if settled_child is not None else self.reserved_at
            if prior is not None:
                _at_or_after(settlement.observed_at, prior, "process settlement")
            if self.ended_at is not None:
                _at_or_after(self.ended_at, settlement.observed_at, "ending")
        if self.cleanup_receipt is not None:
            if self.cleanup_receipt.plan_digest != plan_digest:
                raise TenantLabLaunchError("cleanup receipt belongs to another launch plan")
            if self.ended_at is None:
                raise TenantLabLaunchError("cleanup receipt predates process settlement")
            _at_or_after(self.cleanup_receipt.observed_at, self.ended_at, "cleanup")
        if self.state is LifecycleState.PREPARED:
            if (
                any(
                    value is not None
                    for value in (self.reserved_at, self.running_at, self.ended_at)
                )
                or self.children
                or self.readiness
                or self.settlements
                or self.cleanup_receipt
            ):
                raise TenantLabLaunchError("prepared lab contains lifecycle claims")
        elif self.reserved_at is None:
            raise TenantLabLaunchError("reserved lab timestamp is missing")
        if self.state is LifecycleState.LAUNCH_RESERVED:
            if (
                self.running_at is not None
                or self.ended_at is not None
                or self.settlements
                or self.cleanup_receipt is not None
            ):
                raise TenantLabLaunchError("launch-reserved lab contains later lifecycle claims")
        elif self.state is LifecycleState.RUNNING:
            if (
                self.running_at is None
                or self.ended_at is not None
                or self.settlements
                or self.cleanup_receipt is not None
                or {item.role for item in self.children} != set(ServiceRole)
                or {item.role for item in self.readiness} != set(ServiceRole)
            ):
                raise TenantLabLaunchError("running lab is incomplete")
        elif self.state is LifecycleState.STOPPING:
            if self.ended_at is not None or self.cleanup_receipt is not None:
                raise TenantLabLaunchError("stopping lab contains completed lifecycle claims")
        elif self.state in {LifecycleState.STOPPED, LifecycleState.CLEANED}:
            if (
                self.ended_at is None
                or {item.role for item in self.settlements} != set(ServiceRole)
                or any(item.presence is not Presence.ABSENT for item in self.settlements)
            ):
                raise TenantLabLaunchError("stopped lab lacks verified process absence")
            if self.state is LifecycleState.STOPPED and self.cleanup_receipt is not None:
                raise TenantLabLaunchError("stopped lab contains a cleanup lifecycle claim")
        elif self.state is LifecycleState.UNKNOWN:
            if self.ended_at is None or {item.role for item in self.settlements} != set(
                ServiceRole
            ):
                raise TenantLabLaunchError("unknown lab lacks complete settlement evidence")
            if self.cleanup_receipt is not None and any(
                item.presence is not Presence.ABSENT for item in self.settlements
            ):
                raise TenantLabLaunchError("cleanup uncertainty lacks verified process absence")
        if self.state is LifecycleState.CLEANED:
            if self.cleanup_receipt is None or self.cleanup_receipt.state is not Presence.ABSENT:
                raise TenantLabLaunchError("cleaned lab lacks verified scratch absence")
        if self.cleanup_receipt is not None and self.state not in {
            LifecycleState.CLEANED,
            LifecycleState.UNKNOWN,
        }:
            raise TenantLabLaunchError("cleanup receipt is out of lifecycle order")

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        def child(value: OwnedChild) -> dict[str, object]:
            return {
                "role": value.role.value,
                "pid": value.pid,
                "process_identity_digest": value.process_identity_digest,
                "plan_digest": value.plan_digest,
                "custody_mode": value.custody_mode,
                "custody_snapshot_digest": value.custody_snapshot_digest,
                "custody_receipt_digest": value.custody_receipt_digest,
                "spec_digest": value.spec_digest,
                "endpoint": value.endpoint.to_dict(),
                "started_at": value.started_at,
            }

        def ready(value: ReadinessReceipt) -> dict[str, object]:
            return {
                "role": value.role.value,
                "process_identity_digest": value.process_identity_digest,
                "spec_digest": value.spec_digest,
                "endpoint": value.endpoint.to_dict(),
                "binding_digest": value.binding_digest,
                "observed_at": value.observed_at,
                "receipt_digest": value.receipt_digest,
            }

        def settlement(value: ProcessSettlement) -> dict[str, object]:
            return {
                "role": value.role.value,
                "process_identity_digest": value.process_identity_digest,
                "plan_digest": value.plan_digest,
                "custody_mode": value.custody_mode,
                "custody_snapshot_digest": value.custody_snapshot_digest,
                "presence": value.presence.value,
                "observed_at": value.observed_at,
                "custody_receipt_digest": value.custody_receipt_digest,
                "stdout": {
                    "byte_count": value.stdout.byte_count,
                    "sha256": value.stdout.sha256,
                    "truncated": value.stdout.truncated,
                },
                "stderr": {
                    "byte_count": value.stderr.byte_count,
                    "sha256": value.stderr.sha256,
                    "truncated": value.stderr.truncated,
                },
            }

        cleanup = self.cleanup_receipt
        return {
            "schema_version": RECORD_SCHEMA,
            "plan": self.plan.to_dict(),
            "revision": self.revision,
            "state": self.state.value,
            "prepared_at": self.prepared_at,
            "reserved_at": self.reserved_at,
            "running_at": self.running_at,
            "ended_at": self.ended_at,
            "children": [child(value) for value in self.children],
            "readiness": [ready(value) for value in self.readiness],
            "settlements": [settlement(value) for value in self.settlements],
            "cleanup_receipt": (
                None
                if cleanup is None
                else {
                    "state": cleanup.state.value,
                    "plan_digest": cleanup.plan_digest,
                    "workspace_digest": cleanup.workspace_digest,
                    "observed_at": cleanup.observed_at,
                    "receipt_digest": cleanup.receipt_digest,
                }
            ),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "TenantLabLifecycleRecord":
        expected = {
            "schema_version",
            "plan",
            "revision",
            "state",
            "prepared_at",
            "reserved_at",
            "running_at",
            "ended_at",
            "children",
            "readiness",
            "settlements",
            "cleanup_receipt",
        }
        if set(value) != expected or value.get("schema_version") != RECORD_SCHEMA:
            raise TenantLabLaunchError("lab lifecycle fields are invalid")
        plan = TenantLabLaunchPlan.from_mapping(_mapping(value["plan"], "launch plan"))
        children = tuple(
            _child_from_mapping(item) for item in _sequence(value["children"], "children", 2)
        )
        readiness = tuple(
            _readiness_from_mapping(item) for item in _sequence(value["readiness"], "readiness", 2)
        )
        settlements = tuple(
            _settlement_from_mapping(item)
            for item in _sequence(value["settlements"], "settlements", 2)
        )
        raw_cleanup = value["cleanup_receipt"]
        cleanup = None if raw_cleanup is None else _cleanup_from_mapping(raw_cleanup)
        return cls(
            plan=plan,
            revision=_integer(value["revision"], "revision"),
            state=_enum(LifecycleState, value["state"], "lifecycle state"),
            prepared_at=_text(value["prepared_at"], "preparation timestamp"),
            reserved_at=_optional_text(value["reserved_at"], "reservation timestamp"),
            running_at=_optional_text(value["running_at"], "running timestamp"),
            ended_at=_optional_text(value["ended_at"], "ending timestamp"),
            children=children,
            readiness=readiness,
            settlements=settlements,
            cleanup_receipt=cleanup,
        )


class FixedProcessBackend(Protocol):
    """Trusted platform adapter for fixed argv, Job/session custody and logs.

    ``launch`` must rehash/open the bound interpreter, module, and packet files
    without following a replacement and must attach the suspended child to the
    requested Job/session custody before it can consume the packet.  The
    launcher validates the returned identities but cannot manufacture that OS
    enforcement itself.
    """

    def launch(self, spec: FixedChildSpec) -> OwnedChild: ...

    def verify_ready(self, spec: FixedChildSpec, child: OwnedChild) -> ReadinessReceipt: ...

    def verify_all_running(
        self, plan: TenantLabLaunchPlan, children: tuple[OwnedChild, ...]
    ) -> bool: ...

    def stop(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement: ...

    def reconcile(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement: ...

    def cleanup(self, plan: TenantLabLaunchPlan, layout: WorkspaceLayout) -> CleanupReceipt: ...


class _ProcessLike(Protocol):
    pid: int
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None
    returncode: int | None

    def poll(self) -> int | None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(slots=True)
class _NativeLaunch:
    process: _ProcessLike
    custody: object
    custody_handle: int | None
    process_identity_digest: str
    custody_snapshot_digest: str
    activated: bool


class _NativeSupervisor(Protocol):
    def launch(self, spec: FixedChildSpec) -> _NativeLaunch: ...

    def activate(self, launch: _NativeLaunch) -> None: ...

    def running(self, launch: _NativeLaunch) -> Presence: ...

    def bind_ready_pid(self, launch: _NativeLaunch, process_id: int) -> bool: ...

    def stop(self, launch: _NativeLaunch) -> Presence: ...


class _SystemNativeSupervisor:
    """Reviewed Windows Job/Linux pidfd custody for fixed child specs only."""

    def __init__(
        self,
        *,
        popen_factory: Callable[..., _ProcessLike] = subprocess.Popen,
        platform_name: str = sys.platform,
        windows_factory: Callable[[], object] | None = None,
        linux_factory: Callable[[], object] | None = None,
        windows_identity: Callable[[int], Mapping[str, int]] | None = None,
    ) -> None:
        self._popen = popen_factory
        self._platform = platform_name
        self._windows_factory = windows_factory
        self._linux_factory = linux_factory
        self._windows_identity = windows_identity

    @staticmethod
    def _require_sources(spec: FixedChildSpec) -> None:
        expected = (
            spec.python_source,
            spec.module_source,
            spec.packet_source,
            *((spec.secondary_secret_source,) if spec.secondary_secret_source else ()),
        )
        if any(_seal_file(value.path) != value for value in expected):
            raise TenantLabLaunchError("fixed launch source changed")

    def launch(self, spec: FixedChildSpec) -> _NativeLaunch:
        if not isinstance(spec, FixedChildSpec):
            raise TenantLabLaunchError("native supervisor accepts only a fixed child spec")
        self._require_sources(spec)
        if self._platform != "win32" and not self._platform.startswith("linux"):
            raise TenantLabLaunchError("fixed child custody is not qualified on this platform")
        expected_custody = "windows_job_object" if self._platform == "win32" else "posix_session"
        if spec.custody_mode != expected_custody:
            raise TenantLabLaunchError("fixed child custody does not match the platform")

        environment = dict(spec.environment)
        options: dict[str, Any] = {
            "cwd": spec.packet_source.path.parent.parent,
            "env": environment,
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "close_fds": True,
            "bufsize": 0,
        }
        process: _ProcessLike | None = None
        containment: object | None = None
        job: int | None = None
        job_assigned = False
        try:
            if self._platform == "win32":
                from .runner_windows_containment import WindowsJobContainment

                containment = (
                    self._windows_factory()
                    if self._windows_factory is not None
                    else WindowsJobContainment(kill_on_close=True)
                )
                job = int(cast(Any, containment).create_job())
                system_root = Path(cast(Any, containment).system_directory()).parent
                environment.update(
                    {
                        "SYSTEMROOT": os.fspath(system_root),
                        "WINDIR": os.fspath(system_root),
                        "TEMP": os.fspath(spec.packet_source.path.parent),
                        "TMP": os.fspath(spec.packet_source.path.parent),
                    }
                )
                options["creationflags"] = getattr(
                    subprocess, "CREATE_NO_WINDOW", 0x0800_0000
                ) | getattr(subprocess, "CREATE_SUSPENDED", 0x0000_0004)
            else:
                from .runner_linux_containment import LinuxPrivateProcessContainment

                if self._linux_factory is None and not LinuxPrivateProcessContainment.available():
                    raise TenantLabLaunchError("Linux private-session custody is unavailable")
                containment = (
                    self._linux_factory()
                    if self._linux_factory is not None
                    else LinuxPrivateProcessContainment()
                )
                environment.update({"LANG": "C", "LC_ALL": "C"})
                options["start_new_session"] = True
                options["umask"] = 0o077

            process = self._popen(spec.argv, **options)  # nosec B603 - fixed grammar above
            if process.stdout is None or process.stderr is None or process.pid <= 0:
                raise TenantLabLaunchError("fixed child process handles are unavailable")

            if self._platform == "win32":
                assert job is not None
                cast(Any, containment).assign(job, cast(subprocess.Popen[bytes], process))
                job_assigned = True
                if self._windows_identity is None:
                    from .cross_platform_recovery_witness import (
                        capture_process_identity,
                    )

                    identity: object = dict(capture_process_identity(process.pid))
                else:
                    identity = dict(self._windows_identity(process.pid))
                activated = False
            else:
                from .runner_linux_containment import LinuxPrivateProcessContainment

                cast(Any, containment).register(cast(subprocess.Popen[bytes], process))
                identity = list(cast(Any, containment).process_identity(process.pid))
                activated = True
            process_digest = content_hash({"platform": self._platform, "identity": identity})
            custody_digest = content_hash(
                {
                    "mode": spec.custody_mode,
                    "process_identity_digest": process_digest,
                    "spec_digest": spec.digest,
                    "private_tree": True,
                }
            )
            return _NativeLaunch(
                process=process,
                custody=containment,
                custody_handle=job,
                process_identity_digest=process_digest,
                custody_snapshot_digest=custody_digest,
                activated=activated,
            )
        except BaseException:
            cleaned = process is None
            job_released = False
            if process is not None:
                try:
                    if self._platform == "win32" and containment is not None and job_assigned:
                        cleaned = bool(
                            cast(Any, containment).terminate(cast(subprocess.Popen[bytes], process))
                        )
                        job_released = cleaned
                    elif self._platform.startswith("linux") and containment is not None:
                        cleaned = bool(
                            cast(Any, containment).release(
                                cast(subprocess.Popen[bytes], process), terminate=True
                            )
                        )
                except BaseException:
                    cleaned = False
                if not cleaned:
                    try:
                        process.kill()
                        process.wait(timeout=5.0)
                        leader_absent = process.returncode is not None
                        cleaned = leader_absent and not (self._platform == "win32" and job_assigned)
                    except BaseException:
                        cleaned = False
            if job is not None and not job_released and containment is not None:
                try:
                    handle_closed = bool(cast(Any, containment).close_handle(job))
                    cleaned = handle_closed and cleaned
                except BaseException:
                    cleaned = False
            if not cleaned:
                raise TenantLabLaunchError("fixed child launch cleanup is unknown") from None
            raise

    def activate(self, launch: _NativeLaunch) -> None:
        if launch.activated:
            return
        if self._platform != "win32":
            raise TenantLabLaunchError("fixed child activation state is invalid")
        try:
            cast(Any, launch.custody).resume_suspended(
                cast(subprocess.Popen[bytes], launch.process)
            )
            launch.activated = True
        except BaseException:
            self.stop(launch)
            raise TenantLabLaunchError("fixed child could not be activated") from None

    def running(self, launch: _NativeLaunch) -> Presence:
        try:
            if self._platform == "win32":
                return Presence.RUNNING if launch.process.poll() is None else Presence.ABSENT
            from .runner_linux_containment import LinuxPrivateProcessContainment

            containment = cast(LinuxPrivateProcessContainment, launch.custody)
            return (
                Presence.ABSENT
                if containment.exited_without_reap(cast(subprocess.Popen[bytes], launch.process))
                else Presence.RUNNING
            )
        except BaseException:
            return Presence.UNKNOWN

    def bind_ready_pid(self, launch: _NativeLaunch, process_id: int) -> bool:
        if process_id == launch.process.pid:
            return True
        if self._platform != "win32" or launch.custody_handle is None:
            return False
        from .runner_lifecycle import (
            _windows_close_handle,
            _windows_open_process,
            _windows_process_in_job,
            _windows_process_running,
        )

        handle = 0
        try:
            handle = _windows_open_process(process_id)
            return _windows_process_running(handle) and _windows_process_in_job(
                handle, launch.custody_handle
            )
        except OSError:
            return False
        finally:
            if handle:
                _windows_close_handle(handle)

    def stop(self, launch: _NativeLaunch) -> Presence:
        try:
            if self._platform == "win32":
                cleaned = cast(Any, launch.custody).finish(
                    cast(subprocess.Popen[bytes], launch.process)
                )
            else:
                cleaned = cast(Any, launch.custody).release(
                    cast(subprocess.Popen[bytes], launch.process), terminate=True
                )
            return Presence.ABSENT if cleaned else Presence.UNKNOWN
        except BaseException:
            return Presence.UNKNOWN


@dataclass(slots=True)
class _BoundedDrain:
    stream: IO[bytes]
    maximum: int
    overflow: threading.Event
    truncated: bool = False
    error: bool = False
    retained: int = 0
    _hasher: Any = field(init=False, repr=False)
    thread: threading.Thread = field(init=False, repr=False)

    def __post_init__(self) -> None:
        import hashlib

        self._hasher = hashlib.sha256()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    return
                remaining = max(0, self.maximum - self.retained)
                if remaining:
                    retained = chunk[:remaining]
                    self._hasher.update(retained)
                    self.retained += len(retained)
                if len(chunk) > remaining:
                    self.truncated = True
                    self.overflow.set()
        except (OSError, RuntimeError, ValueError):
            self.error = True
            self.overflow.set()

    def finish(self, timeout_seconds: float) -> LogSummary | None:
        self.thread.join(timeout=timeout_seconds)
        if self.thread.is_alive():
            try:
                self.stream.close()
            except OSError:
                pass
            self.thread.join(timeout=timeout_seconds)
        try:
            self.stream.close()
        except OSError:
            self.error = True
        if self.thread.is_alive() or self.error:
            return None
        return LogSummary(
            byte_count=self.retained,
            sha256="sha256:" + self._hasher.hexdigest(),
            truncated=self.truncated,
        )


@dataclass(slots=True)
class _ManagedChild:
    spec: FixedChildSpec
    native: _NativeLaunch
    stdout: _BoundedDrain
    stderr: _BoundedDrain
    stop_event: threading.Event
    lock: threading.Lock = field(default_factory=threading.Lock)
    settled_presence: Presence | None = None
    stdout_summary: LogSummary | None = None
    stderr_summary: LogSummary | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _probe_loopback(endpoint: LoopbackEndpoint, timeout_seconds: float) -> None:
    with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout_seconds):
        return


class ControllerOwnedFixedProcessBackend:
    """Concrete supervisor for the two fixed package-owned mechanics children.

    Custody is intentionally process-local. A fresh backend never signals a PID
    from persisted data and reports UNKNOWN unless this instance retained the
    exact Job/session object. This is local deterministic fixture supervision,
    not Strix containment or hosted external-network enforcement.
    """

    def __init__(
        self,
        *,
        scratch_root: Path,
        runtime: RuntimeBinding,
        native: _NativeSupervisor | None = None,
        clock: Clock = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        socket_probe: Callable[[LoopbackEndpoint, float], None] = _probe_loopback,
    ) -> None:
        root = scratch_root.resolve(strict=True)
        if not root.is_dir() or _is_link_or_reparse(root):
            raise TenantLabLaunchError("backend scratch root is invalid")
        runtime.revalidate()
        self._root = root
        self._runtime = runtime
        self._native = native or _SystemNativeSupervisor()
        self._clock = clock
        self._monotonic = monotonic
        self._sleep = sleep
        self._socket_probe = socket_probe
        self._lock = threading.RLock()
        self._live: dict[tuple[str, ServiceRole], _ManagedChild] = {}
        self._attempted: set[tuple[str, ServiceRole]] = set()
        self._known_plans: set[str] = set()
        self._settled: dict[tuple[str, ServiceRole], Presence] = {}

    @staticmethod
    def _key(plan_digest: str, role: ServiceRole) -> tuple[str, ServiceRole]:
        return (plan_digest, role)

    @staticmethod
    def _require_sources(spec: FixedChildSpec) -> None:
        sources = (
            spec.python_source,
            spec.module_source,
            spec.packet_source,
            *((spec.secondary_secret_source,) if spec.secondary_secret_source else ()),
        )
        if any(_seal_file(item.path) != item for item in sources):
            raise TenantLabLaunchError("fixed child source changed")

    @staticmethod
    def _require_fresh_outputs(spec: FixedChildSpec) -> None:
        indexes = (9, 11) if spec.role is ServiceRole.TARGET else (10, 12)
        for index in indexes:
            try:
                Path(spec.argv[index]).lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise TenantLabLaunchError("fixed child output absence is unknown") from exc
            raise TenantLabLaunchError("fixed child output already exists")

    def launch(self, spec: FixedChildSpec) -> OwnedChild:
        if not isinstance(spec, FixedChildSpec):
            raise TenantLabLaunchError("backend accepts only fixed child specifications")
        self._runtime.revalidate()
        expected_module = (
            self._runtime.target_seal
            if spec.role is ServiceRole.TARGET
            else self._runtime.provider_seal
        )
        if (
            spec.runtime_digest != self._runtime.digest
            or spec.python_source != self._runtime.python_seal
            or spec.module_source != expected_module
            or spec.packet_source.path.parent.parent.parent != self._root
        ):
            raise TenantLabLaunchError("fixed child does not belong to this backend")
        self._require_sources(spec)
        self._require_fresh_outputs(spec)
        key = self._key(spec.plan_digest, spec.role)
        with self._lock:
            if key in self._attempted:
                raise TenantLabLaunchError("fixed child launch identity was already attempted")
            self._known_plans.add(spec.plan_digest)
            self._attempted.add(key)
            self._settled[key] = Presence.UNKNOWN
        native: _NativeLaunch | None = None
        managed: _ManagedChild | None = None
        try:
            native = self._native.launch(spec)
            if native.process.stdout is None or native.process.stderr is None:
                raise TenantLabLaunchError("fixed child output pipes are unavailable")
            stop_event = threading.Event()
            stdout = _BoundedDrain(native.process.stdout, spec.max_log_bytes, stop_event)
            stderr = _BoundedDrain(native.process.stderr, spec.max_log_bytes, stop_event)
            managed = _ManagedChild(spec, native, stdout, stderr, stop_event)
            with self._lock:
                self._live[key] = managed
            stdout.start()
            stderr.start()
            self._native.activate(native)
            self._require_sources(spec)
            thread = threading.Thread(
                target=self._watchdog,
                args=(key, managed),
                name=f"bluefire-{spec.role.value}-deadline",
                daemon=True,
            )
            thread.start()
            custody_fields = {
                "role": spec.role.value,
                "process_identity_digest": native.process_identity_digest,
                "plan_digest": spec.plan_digest,
                "spec_digest": spec.digest,
                "custody_mode": spec.custody_mode,
                "custody_snapshot_digest": native.custody_snapshot_digest,
            }
            return OwnedChild(
                role=spec.role,
                pid=native.process.pid,
                process_identity_digest=native.process_identity_digest,
                plan_digest=spec.plan_digest,
                custody_mode=spec.custody_mode,
                custody_snapshot_digest=native.custody_snapshot_digest,
                custody_receipt_digest=content_hash(custody_fields),
                spec_digest=spec.digest,
                endpoint=spec.endpoint,
                started_at=_timestamp(self._clock(), "child start"),
            )
        except BaseException:
            if managed is not None:
                presence, _stdout, _stderr = self._stop_managed(managed)
            elif native is not None:
                presence = self._native.stop(native)
            else:
                presence = Presence.UNKNOWN
            with self._lock:
                self._settled[key] = presence
            raise

    def _watchdog(self, key: tuple[str, ServiceRole], managed: _ManagedChild) -> None:
        managed.stop_event.wait(timeout=managed.spec.max_runtime_seconds)
        presence, _stdout, _stderr = self._stop_managed(managed)
        with self._lock:
            self._settled[key] = presence

    def _stop_managed(
        self, managed: _ManagedChild
    ) -> tuple[Presence, LogSummary | None, LogSummary | None]:
        with managed.lock:
            if managed.settled_presence is not None:
                return (
                    managed.settled_presence,
                    managed.stdout_summary,
                    managed.stderr_summary,
                )
            managed.stop_event.set()
            presence = self._native.stop(managed.native)
            stdout = managed.stdout.finish(5.0)
            stderr = managed.stderr.finish(5.0)
            if stdout is None or stderr is None:
                presence = Presence.UNKNOWN
            managed.settled_presence = presence
            managed.stdout_summary = stdout
            managed.stderr_summary = stderr
            return presence, stdout, stderr

    @staticmethod
    def _ready_path(spec: FixedChildSpec) -> Path:
        return Path(spec.argv[11] if spec.role is ServiceRole.TARGET else spec.argv[12])

    @staticmethod
    def _read_ready(path: Path) -> tuple[bytes, Mapping[str, object]]:
        details = path.lstat()
        if (
            _is_link_or_reparse(path, details)
            or not stat.S_ISREG(details.st_mode)
            or details.st_size > 32 * 1024
        ):
            raise TenantLabLaunchError("fixed child readiness file is invalid")
        if os.name != "nt" and stat.S_IMODE(details.st_mode) & 0o077:
            raise TenantLabLaunchError("fixed child readiness file is not private")
        payload = path.read_bytes()
        sealed = _seal_file(path)
        initial_identity = (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
        )
        sealed_identity = (sealed.device, sealed.inode, sealed.size, sealed.mtime_ns)
        if (
            not payload
            or len(payload) > 32 * 1024
            or _sha256_bytes(payload) != sealed.sha256
            or initial_identity != sealed_identity
        ):
            raise TenantLabLaunchError("fixed child readiness file changed")

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate readiness field")
                result[name] = value
            return result

        try:
            value = json.loads(payload, object_pairs_hook=unique)
        except (UnicodeError, ValueError) as exc:
            raise TenantLabLaunchError("fixed child readiness is invalid") from exc
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise TenantLabLaunchError("fixed child readiness is invalid")
        canonical = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
        if payload != canonical:
            raise TenantLabLaunchError("fixed child readiness is not canonical")
        return payload, cast(Mapping[str, object], value)

    def verify_ready(self, spec: FixedChildSpec, child: OwnedChild) -> ReadinessReceipt:
        key = self._key(spec.plan_digest, spec.role)
        with self._lock:
            managed = self._live.get(key)
        if (
            managed is None
            or child.process_identity_digest != managed.native.process_identity_digest
            or child.spec_digest != spec.digest
        ):
            raise TenantLabLaunchError("fixed child readiness has no retained custody")
        path = self._ready_path(spec)
        deadline = self._monotonic() + min(15.0, float(spec.max_runtime_seconds))
        while True:
            state = self._native.running(managed.native)
            if state is not Presence.RUNNING:
                raise TenantLabLaunchError("fixed child exited before readiness")
            try:
                payload, value = self._read_ready(path)
                break
            except FileNotFoundError:
                if self._monotonic() >= deadline:
                    raise TenantLabLaunchError("fixed child readiness timed out") from None
                self._sleep(0.025)
        schema = value.get("schema_version")
        if spec.role is ServiceRole.TARGET:
            from .tenant_record_target_child import (
                READY_SCHEMA,
                TargetReadyReceipt,
                TenantTargetChildError,
            )

            try:
                target_ready = TargetReadyReceipt.from_bytes(payload)
            except TenantTargetChildError as exc:
                raise TenantLabLaunchError("tenant target readiness is invalid") from exc
            if (
                schema != READY_SCHEMA
                or not self._native.bind_ready_pid(managed.native, target_ready.pid)
                or target_ready.packet_digest != spec.packet_digest
                or target_ready.max_runtime_seconds > spec.max_runtime_seconds
            ):
                raise TenantLabLaunchError("tenant target readiness binding is invalid")
        else:
            manifest_payload = spec.packet_source.path.read_bytes()
            if _seal_file(spec.packet_source.path) != spec.packet_source:
                raise TenantLabLaunchError("controlled provider manifest changed")
            manifest_digest = _provider_manifest_semantic_digest(manifest_payload)
            expected = {
                "schema_version",
                "provider_id",
                "provider_label",
                "attempt_id",
                "model_id",
                "host",
                "port",
                "manifest_digest",
                "live_model_proof",
            }
            if (
                set(value) != expected
                or schema != "bluefire.controlled-provider-ready.v1"
                or value.get("provider_id") != "controlled-strix-mechanics.v1"
                or value.get("provider_label") != "Test provider"
                or value.get("attempt_id") != spec.attempt_id
                or value.get("manifest_digest") != manifest_digest
                or value.get("live_model_proof") is not False
            ):
                raise TenantLabLaunchError("controlled provider readiness is invalid")
        endpoint = LoopbackEndpoint(
            _text(value.get("host"), "readiness host"),
            _integer(value.get("port"), "readiness port"),
        )
        if endpoint.port == 0 or endpoint.host != spec.endpoint.host:
            raise TenantLabLaunchError("fixed child readiness endpoint is invalid")
        if spec.endpoint.port != 0 and endpoint != spec.endpoint:
            raise TenantLabLaunchError("fixed child readiness changed the planned endpoint")
        self._socket_probe(endpoint, 1.0)
        if self._native.running(managed.native) is not Presence.RUNNING:
            raise TenantLabLaunchError("fixed child lost custody after readiness")
        self._require_sources(spec)
        binding = content_hash(
            {
                "role": spec.role.value,
                "process": child.process_identity_digest,
                "endpoint": endpoint.to_dict(),
                "packet": spec.packet_digest,
                "plan": spec.plan_digest,
            }
        )
        observed_at = _timestamp(self._clock(), "readiness")
        return ReadinessReceipt(
            role=spec.role,
            process_identity_digest=child.process_identity_digest,
            spec_digest=spec.digest,
            endpoint=endpoint,
            binding_digest=binding,
            observed_at=observed_at,
            receipt_digest=content_hash({"binding_digest": binding, "observed_at": observed_at}),
        )

    def verify_all_running(
        self, plan: TenantLabLaunchPlan, children: tuple[OwnedChild, ...]
    ) -> bool:
        """Take one bounded, process-local custody observation of both roles."""

        indexed = {child.role: child for child in children}
        if len(indexed) != len(children) or set(indexed) != set(ServiceRole):
            return False
        managed_children: list[tuple[OwnedChild, _ManagedChild]] = []
        with self._lock:
            for role in (ServiceRole.TARGET, ServiceRole.TEST_PROVIDER):
                child = indexed[role]
                key = self._key(plan.digest, role)
                managed = self._live.get(key)
                if (
                    managed is None
                    or self._settled.get(key) is not Presence.UNKNOWN
                    or child.process_identity_digest != managed.native.process_identity_digest
                    or child.spec_digest != managed.spec.digest
                ):
                    return False
                managed_children.append((child, managed))
        locks = [managed.lock for _child, managed in managed_children]
        for lock in locks:
            lock.acquire()
        try:
            return all(
                managed.settled_presence is None
                and self._native.running(managed.native) is Presence.RUNNING
                for _child, managed in managed_children
            )
        finally:
            for lock in reversed(locks):
                lock.release()

    def stop(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        return self._settle(plan, role, child)

    def reconcile(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        return self._settle(plan, role, child)

    def _settle(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        key = self._key(plan.digest, role)
        with self._lock:
            managed = self._live.get(key)
            known = plan.digest in self._known_plans
            attempted = key in self._attempted
            retained_presence = self._settled.get(key)
        stdout: LogSummary | None = None
        stderr: LogSummary | None = None
        if managed is not None:
            presence, stdout, stderr = self._stop_managed(managed)
            if (
                child is not None
                and child.process_identity_digest != managed.native.process_identity_digest
            ):
                presence = Presence.UNKNOWN
            with self._lock:
                self._settled[key] = presence
        elif retained_presence is not None:
            presence = retained_presence
        elif known and not attempted and child is None:
            presence = Presence.ABSENT
        else:
            presence = Presence.UNKNOWN
        unknown_log = LogSummary(0, _sha256_bytes(b""), presence is Presence.UNKNOWN)
        stdout = stdout or unknown_log
        stderr = stderr or unknown_log
        observed_at = _timestamp(self._clock(), "process settlement")
        process_identity = None if child is None else child.process_identity_digest
        custody_snapshot = (
            child.custody_snapshot_digest
            if child is not None
            else (
                managed.native.custody_snapshot_digest
                if managed is not None
                else content_hash(
                    {
                        "role": role.value,
                        "plan_digest": plan.digest,
                        "attempted": attempted,
                        "retained_custody": False,
                    }
                )
            )
        )
        fields = {
            "role": role.value,
            "process_identity_digest": process_identity,
            "plan_digest": plan.digest,
            "custody_mode": plan.custody_mode,
            "custody_snapshot_digest": custody_snapshot,
            "presence": presence.value,
            "observed_at": observed_at,
            "stdout": {
                "byte_count": stdout.byte_count,
                "sha256": stdout.sha256,
                "truncated": stdout.truncated,
            },
            "stderr": {
                "byte_count": stderr.byte_count,
                "sha256": stderr.sha256,
                "truncated": stderr.truncated,
            },
        }
        return ProcessSettlement(
            role=role,
            process_identity_digest=process_identity,
            plan_digest=plan.digest,
            custody_mode=plan.custody_mode,
            custody_snapshot_digest=custody_snapshot,
            presence=presence,
            observed_at=observed_at,
            custody_receipt_digest=content_hash(fields),
            stdout=stdout,
            stderr=stderr,
        )

    def _release_settled_custody(self, plan: TenantLabLaunchPlan) -> None:
        """Reap and drop heavy process custody after verified settlement."""

        retained: list[tuple[tuple[str, ServiceRole], _ManagedChild]] = []
        with self._lock:
            for role in (ServiceRole.TARGET, ServiceRole.TEST_PROVIDER):
                key = self._key(plan.digest, role)
                managed = self._live.get(key)
                if managed is not None:
                    retained.append((key, managed))
        for key, managed in retained:
            with managed.lock:
                if managed.settled_presence is not Presence.ABSENT:
                    raise TenantLabLaunchError("fixed child custody is not verified absent")
                try:
                    managed.native.process.wait(timeout=5.0)
                except BaseException as exc:
                    raise TenantLabLaunchError(
                        "fixed child process handle could not be reaped"
                    ) from exc
                if managed.native.process.returncode is None:
                    raise TenantLabLaunchError("fixed child process handle remains live")
            with self._lock:
                if self._live.get(key) is not managed:
                    raise TenantLabLaunchError("fixed child custody changed during release")
                if self._settled.get(key) is not Presence.ABSENT:
                    raise TenantLabLaunchError("fixed child settlement changed during release")
                del self._live[key]

    def cleanup(self, plan: TenantLabLaunchPlan, layout: WorkspaceLayout) -> CleanupReceipt:
        if (
            layout.root != self._root
            or layout.run_root.parent != layout.root
            or layout.run_root.name != plan.run_id
        ):
            raise TenantLabLaunchError("cleanup workspace is not the fixed run identity")
        self._release_settled_custody(plan)
        if _is_link_or_reparse(layout.run_root):
            raise TenantLabLaunchError("cleanup workspace is linked")
        try:
            shutil.rmtree(layout.run_root)
        except FileNotFoundError:
            pass
        try:
            layout.run_root.lstat()
        except FileNotFoundError:
            state = Presence.ABSENT
        except OSError as exc:
            raise TenantLabLaunchError("cleanup workspace absence is unknown") from exc
        else:
            raise TenantLabLaunchError("cleanup workspace remains present")
        details = layout.root.stat()
        root_identity = content_hash(
            {
                "resolved_path_digest": _sha256_bytes(os.fsencode(layout.root)),
                "device": details.st_dev,
                "inode": details.st_ino,
            }
        )
        workspace_digest = content_hash(
            {
                "root_identity_digest": root_identity,
                "plan_digest": plan.digest,
                "run_id": plan.run_id,
                "relative_entries": [
                    "target/packet.json",
                    "target/audit.jsonl",
                    "target/ready.json",
                    "provider/manifest.json",
                    "provider/token.txt",
                    "provider/audit.jsonl",
                    "provider/ready.json",
                ],
                "run_root_name": layout.run_root.name,
            }
        )
        observed_at = _timestamp(self._clock(), "cleanup")
        fields = {
            "state": state.value,
            "plan_digest": plan.digest,
            "workspace_digest": workspace_digest,
            "observed_at": observed_at,
        }
        return CleanupReceipt(
            state=state,
            plan_digest=plan.digest,
            workspace_digest=workspace_digest,
            observed_at=observed_at,
            receipt_digest=content_hash(fields),
        )


LifecycleSink = Callable[
    [TenantLabLifecycleRecord, str, str | None],
    LifecycleCommit,
]
RootProtectionCheck = Callable[[Path], bool]
Clock = Callable[[], str]


class TenantRecordLabLauncher:
    """Prepare and supervise the two fixed local mechanics-fixture processes."""

    def __init__(
        self,
        *,
        scratch_root: Path,
        runtime: RuntimeBinding,
        backend: FixedProcessBackend,
        root_is_protected: RootProtectionCheck,
        clock: Clock,
    ) -> None:
        root = scratch_root.resolve(strict=True)
        if not root.is_dir() or not root_is_protected(root):
            raise TenantLabLaunchError("lab scratch root is not controller protected")
        if runtime.digest != content_hash(
            {
                "python_digest": runtime.python_digest,
                "target_digest": runtime.target_digest,
                "provider_digest": runtime.provider_digest,
                "target_module": TARGET_MODULE,
                "provider_module": PROVIDER_MODULE,
            }
        ):
            raise TenantLabLaunchError("fixed runtime binding is invalid")
        self._root = root
        details = root.stat()
        self._root_identity = (details.st_dev, details.st_ino)
        self._root_identity_digest = content_hash(
            {
                "resolved_path_digest": _sha256_bytes(os.fsencode(root)),
                "device": details.st_dev,
                "inode": details.st_ino,
            }
        )
        self._runtime = runtime
        self._backend = backend
        self._root_is_protected = root_is_protected
        self._clock = clock

    def plan(
        self,
        *,
        run_id: str,
        attempt_id: str,
        packets: TenantLabPackets,
        target_endpoint: LoopbackEndpoint | None = None,
        provider_endpoint: LoopbackEndpoint | None = None,
        max_runtime_seconds: int = 780,
        max_log_bytes: int = 64 * 1024,
    ) -> TenantLabLaunchPlan:
        custody = "windows_job_object" if os.name == "nt" else "posix_session"
        return TenantLabLaunchPlan(
            run_id=run_id,
            attempt_id=attempt_id,
            runtime_digest=self._runtime.digest,
            target_packet_digest=packets.target_digest,
            provider_manifest_digest=packets.provider_manifest_digest,
            provider_token_digest=packets.provider_token_digest,
            target_endpoint=target_endpoint or LoopbackEndpoint("127.0.0.1", 0),
            provider_endpoint=provider_endpoint or LoopbackEndpoint("127.0.0.1", 0),
            custody_mode=custody,
            max_runtime_seconds=max_runtime_seconds,
            max_log_bytes=max_log_bytes,
            created_at=self._now(),
        )

    def prepare(
        self,
        plan: TenantLabLaunchPlan,
        packets: TenantLabPackets,
        sink: LifecycleSink,
    ) -> TenantLabLifecycleRecord:
        self._validate_plan(plan)
        self._require_protected_root()
        if (
            packets.target_digest != plan.target_packet_digest
            or packets.provider_manifest_digest != plan.provider_manifest_digest
            or packets.provider_token_digest != plan.provider_token_digest
        ):
            raise TenantLabLaunchError("lab packets changed after planning")
        layout = WorkspaceLayout.for_run(self._root, plan.run_id)
        try:
            layout.run_root.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise TenantLabLaunchError("lab run workspace absence is unknown") from exc
        else:
            raise TenantLabLaunchError("lab run workspace already exists")
        created = False
        try:
            layout.run_root.mkdir(mode=0o700)
            created = True
            (layout.run_root / "target").mkdir(mode=0o700)
            (layout.run_root / "provider").mkdir(mode=0o700)
            for directory in (
                layout.run_root,
                layout.run_root / "target",
                layout.run_root / "provider",
            ):
                self._harden_workspace_path(directory, directory=True)
            self._validate_layout_identity(layout)
            self._write_exclusive(layout.target_packet, packets.target_packet)
            self._write_exclusive(layout.provider_manifest, packets.provider_manifest)
            self._write_exclusive(layout.provider_token, packets.provider_token)
            for source in (
                layout.target_packet,
                layout.provider_manifest,
                layout.provider_token,
            ):
                self._harden_workspace_path(source, directory=False)
            self._sync_workspace(layout)
            record = TenantLabLifecycleRecord(
                plan=plan,
                revision=1,
                state=LifecycleState.PREPARED,
                prepared_at=self._now(),
                reserved_at=None,
                running_at=None,
                ended_at=None,
                children=(),
                readiness=(),
                settlements=(),
                cleanup_receipt=None,
            )
            self._commit(sink, record, "prepared", None)
            return record
        except BaseException:
            if created and not self._remove_unstarted_workspace(layout):
                raise TenantLabPreparationFailure(
                    "lab preparation failed and scratch absence is unknown"
                ) from None
            raise

    def start(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord:
        self._validate_record(record)
        if record.state is not LifecycleState.PREPARED:
            raise TenantLabLaunchError("a prepared lab identity can be launched only once")
        layout = self._layout_and_verify_packets(record.plan)
        reserved = replace(
            record,
            revision=record.revision + 1,
            state=LifecycleState.LAUNCH_RESERVED,
            reserved_at=self._now(),
        )
        self._commit(sink, reserved, "launch_reserved", record.digest)
        current = reserved
        try:
            for role in (ServiceRole.TARGET, ServiceRole.TEST_PROVIDER):
                spec = self._spec(current.plan, layout, role)
                child = self._backend.launch(spec)
                self._validate_child(spec, child)
                prior_digest = current.digest
                current = replace(
                    current,
                    revision=current.revision + 1,
                    children=(*current.children, child),
                )
                self._commit(sink, current, f"{role.value}_launched", prior_digest)
                readiness = self._backend.verify_ready(spec, child)
                self._validate_readiness(spec, child, readiness)
                prior_digest = current.digest
                current = replace(
                    current,
                    revision=current.revision + 1,
                    readiness=(*current.readiness, readiness),
                )
                self._commit(sink, current, f"{role.value}_ready", prior_digest)
            if not self._backend.verify_all_running(current.plan, current.children):
                raise TenantLabLaunchError("fixed lab lost joint custody before running")
            prior_digest = current.digest
            running = replace(
                current,
                revision=current.revision + 1,
                state=LifecycleState.RUNNING,
                running_at=self._now(),
            )
            self._commit(sink, running, "running", prior_digest)
            return running
        except BaseException as exc:
            settled = self._best_effort_reconcile(current, sink)
            raise TenantLabStartFailure("fixed lab launch failed", settled) from exc

    def check_running(self, record: TenantLabLifecycleRecord) -> str:
        """Freshly verify exact retained custody/readiness without changing it."""

        self._validate_record(record)
        if record.state is not LifecycleState.RUNNING:
            raise TenantLabLaunchError("fresh custody requires a running lab")
        layout = self._layout_and_verify_packets(record.plan)
        if not self._backend.verify_all_running(record.plan, record.children):
            raise TenantLabLaunchError("fixed lab has no exact joint custody")
        retained = {item.role: item for item in record.readiness}
        observations: list[str] = []
        for child in record.children:
            spec = self._spec(record.plan, layout, child.role)
            observed = self._backend.verify_ready(spec, child)
            self._validate_readiness(spec, child, observed)
            prior = retained[child.role]
            if (
                observed.role is not prior.role
                or observed.process_identity_digest != prior.process_identity_digest
                or observed.spec_digest != prior.spec_digest
                or observed.endpoint != prior.endpoint
                or observed.binding_digest != prior.binding_digest
            ):
                raise TenantLabLaunchError("fixed lab readiness identity changed")
            _at_or_after(observed.observed_at, prior.observed_at, "fresh readiness")
            _at_or_after(observed.observed_at, cast(str, record.running_at), "fresh readiness")
            observations.append(observed.receipt_digest)
        if not self._backend.verify_all_running(record.plan, record.children):
            raise TenantLabLaunchError("fixed lab lost joint custody during readiness")
        observed_at = self._now()
        return content_hash(
            {
                "schema_version": "bluefire.tenant-record-live-custody.v1",
                "plan_digest": record.plan.digest,
                "lifecycle_digest": record.digest,
                "readiness_receipt_digests": observations,
                "observed_at": observed_at,
            }
        )

    def stop(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord:
        self._validate_record(record)
        if record.state in {LifecycleState.STOPPED, LifecycleState.CLEANED}:
            return record
        if record.cleanup_receipt is not None:
            return self.cleanup(record, sink)
        if record.state not in {
            LifecycleState.LAUNCH_RESERVED,
            LifecycleState.RUNNING,
            LifecycleState.STOPPING,
            LifecycleState.UNKNOWN,
        }:
            raise TenantLabLaunchError("lab state cannot be stopped")
        current = record
        if record.state is not LifecycleState.STOPPING:
            prior_digest = record.digest
            current = replace(
                record,
                revision=record.revision + 1,
                state=LifecycleState.STOPPING,
                ended_at=None,
                settlements=(),
                cleanup_receipt=None,
            )
            self._commit(sink, current, "stopping", prior_digest)
        children = {child.role: child for child in current.children}
        settlements = {item.role: item for item in current.settlements}
        for role in (ServiceRole.TEST_PROVIDER, ServiceRole.TARGET):
            retained = settlements.get(role)
            if retained is not None and retained.presence is Presence.ABSENT:
                continue
            try:
                settlement = self._backend.stop(current.plan, role, children.get(role))
                self._validate_settlement(current.plan, role, children.get(role), settlement)
            except BaseException:
                settlement = self._unknown_settlement(current.plan, role, children.get(role))
            settlements[role] = settlement
            prior_digest = current.digest
            current = replace(
                current,
                revision=current.revision + 1,
                settlements=tuple(sorted(settlements.values(), key=lambda value: value.role.value)),
            )
            self._commit(sink, current, f"{role.value}_stopped", prior_digest)
        return self._settled(current, tuple(settlements.values()), sink, "stopped")

    def reconcile(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord:
        """Stop/discover exact owned children after interruption; never relaunch."""

        self._validate_record(record)
        if record.state in {LifecycleState.STOPPED, LifecycleState.CLEANED}:
            return record
        if record.cleanup_receipt is not None:
            return self.cleanup(record, sink)
        if record.state is LifecycleState.PREPARED:
            raise TenantLabLaunchError("unreserved lab has no process custody to reconcile")
        prior_digest = record.digest
        current = replace(
            record,
            revision=record.revision + 1,
            state=LifecycleState.STOPPING,
            ended_at=None,
            settlements=(record.settlements if record.state is LifecycleState.STOPPING else ()),
            cleanup_receipt=None,
        )
        self._commit(sink, current, "reconcile_reserved", prior_digest)
        children = {child.role: child for child in current.children}
        settlements = {item.role: item for item in current.settlements}
        for role in (ServiceRole.TEST_PROVIDER, ServiceRole.TARGET):
            retained = settlements.get(role)
            if retained is not None and retained.presence is Presence.ABSENT:
                continue
            try:
                settlement = self._backend.reconcile(current.plan, role, children.get(role))
                self._validate_settlement(current.plan, role, children.get(role), settlement)
            except BaseException:
                settlement = self._unknown_settlement(current.plan, role, children.get(role))
            settlements[role] = settlement
            prior_digest = current.digest
            current = replace(
                current,
                revision=current.revision + 1,
                settlements=tuple(sorted(settlements.values(), key=lambda value: value.role.value)),
            )
            self._commit(sink, current, f"{role.value}_reconciled", prior_digest)
        return self._settled(current, tuple(settlements.values()), sink, "reconciled")

    def cleanup(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord:
        self._validate_record(record)
        if record.state is LifecycleState.CLEANED:
            return record
        retrying_unknown = (
            record.state is LifecycleState.UNKNOWN
            and record.cleanup_receipt is not None
            and {item.role for item in record.settlements} == set(ServiceRole)
            and all(item.presence is Presence.ABSENT for item in record.settlements)
        )
        if record.state is not LifecycleState.STOPPED and not retrying_unknown:
            raise TenantLabLaunchError("lab scratch cleanup requires verified process absence")
        self._require_protected_root()
        layout = WorkspaceLayout.for_run(self._root, record.plan.run_id)
        if record.cleanup_receipt is not None:
            self._validate_cleanup_receipt(record.plan, layout, record.cleanup_receipt)
        workspace_digest = self._workspace_digest(record.plan, layout)
        try:
            receipt = self._backend.cleanup(record.plan, layout)
            self._validate_cleanup_receipt(record.plan, layout, receipt)
        except BaseException:
            observed_at = self._now()
            receipt = CleanupReceipt(
                state=Presence.UNKNOWN,
                plan_digest=record.plan.digest,
                workspace_digest=workspace_digest,
                observed_at=observed_at,
                receipt_digest=content_hash(
                    {
                        "state": Presence.UNKNOWN.value,
                        "plan_digest": record.plan.digest,
                        "workspace_digest": workspace_digest,
                        "observed_at": observed_at,
                    }
                ),
            )
        state = (
            LifecycleState.CLEANED if receipt.state is Presence.ABSENT else LifecycleState.UNKNOWN
        )
        prior_digest = record.digest
        updated = replace(
            record,
            revision=record.revision + 1,
            state=state,
            cleanup_receipt=receipt,
        )
        self._commit(
            sink,
            updated,
            "cleaned" if state is LifecycleState.CLEANED else "cleanup_unknown",
            prior_digest,
        )
        return updated

    def _now(self) -> str:
        return _timestamp(self._clock(), "controller clock")

    def _commit(
        self,
        sink: LifecycleSink,
        record: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        receipt = sink(record, phase, prior_record_digest)
        if not isinstance(receipt, LifecycleCommit):
            raise TenantLabLaunchError("lifecycle persistence did not acknowledge the commit")
        if (
            receipt.plan_digest != record.plan.digest
            or receipt.prior_record_digest != prior_record_digest
            or receipt.record_digest != record.digest
            or receipt.phase != phase
        ):
            raise TenantLabLaunchError("lifecycle persistence acknowledged a different transition")
        latest = max(
            (
                record.plan.created_at,
                record.prepared_at,
                *(
                    value
                    for value in (
                        record.reserved_at,
                        record.running_at,
                        record.ended_at,
                    )
                    if value
                ),
                *(value.started_at for value in record.children),
                *(value.observed_at for value in record.readiness),
                *(value.observed_at for value in record.settlements),
                *(() if record.cleanup_receipt is None else (record.cleanup_receipt.observed_at,)),
            ),
            key=parse_iso8601_datetime,
        )
        _at_or_after(receipt.committed_at, latest, "lifecycle commit")
        return receipt

    def _validate_plan(self, plan: TenantLabLaunchPlan) -> None:
        self._runtime.revalidate()
        if not isinstance(plan, TenantLabLaunchPlan) or plan.runtime_digest != self._runtime.digest:
            raise TenantLabLaunchError("lab plan does not bind the configured runtime")
        expected = "windows_job_object" if os.name == "nt" else "posix_session"
        if plan.custody_mode != expected:
            raise TenantLabLaunchError("lab plan does not bind the host custody mode")

    def _require_protected_root(self) -> None:
        try:
            details = self._root.stat()
        except OSError as exc:
            raise TenantLabLaunchError("lab scratch root identity changed") from exc
        if (
            (details.st_dev, details.st_ino) != self._root_identity
            or self._root.resolve(strict=True) != self._root
            or not self._root_is_protected(self._root)
        ):
            raise TenantLabLaunchError("lab scratch root protection changed")

    def _workspace_digest(self, plan: TenantLabLaunchPlan, layout: WorkspaceLayout) -> str:
        return content_hash(
            {
                "root_identity_digest": self._root_identity_digest,
                "plan_digest": plan.digest,
                "run_id": plan.run_id,
                "relative_entries": [
                    "target/packet.json",
                    "target/audit.jsonl",
                    "target/ready.json",
                    "provider/manifest.json",
                    "provider/token.txt",
                    "provider/audit.jsonl",
                    "provider/ready.json",
                ],
                "run_root_name": layout.run_root.name,
            }
        )

    def _validate_cleanup_receipt(
        self,
        plan: TenantLabLaunchPlan,
        layout: WorkspaceLayout,
        receipt: CleanupReceipt,
    ) -> None:
        if (
            not isinstance(receipt, CleanupReceipt)
            or receipt.plan_digest != plan.digest
            or receipt.workspace_digest != self._workspace_digest(plan, layout)
        ):
            raise TenantLabLaunchError("cleanup receipt belongs to another lab workspace")
        if receipt.state is Presence.ABSENT:
            try:
                layout.run_root.lstat()
            except FileNotFoundError:
                return
            except OSError as exc:
                raise TenantLabLaunchError("lab scratch absence is unknown") from exc
            raise TenantLabLaunchError("cleanup receipt conflicts with retained scratch state")

    def _validate_record(self, record: TenantLabLifecycleRecord) -> None:
        if not isinstance(record, TenantLabLifecycleRecord):
            raise TenantLabLaunchError("lab lifecycle record is invalid")
        self._validate_plan(record.plan)
        # Re-run canonical validation in case a trusted caller retained a
        # mutated nested object through an unsafe persistence adapter.
        TenantLabLifecycleRecord(
            plan=record.plan,
            revision=record.revision,
            state=record.state,
            prepared_at=record.prepared_at,
            reserved_at=record.reserved_at,
            running_at=record.running_at,
            ended_at=record.ended_at,
            children=tuple(record.children),
            readiness=tuple(record.readiness),
            settlements=tuple(record.settlements),
            cleanup_receipt=record.cleanup_receipt,
        )

    @staticmethod
    def _write_exclusive(path: Path, payload: bytes) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _harden_workspace_path(path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            from .windows_owner_acl import (
                WindowsOwnerAclError,
                apply_owner_private_acl_path,
            )

            try:
                apply_owner_private_acl_path(path, directory=directory)
            except WindowsOwnerAclError as exc:
                raise TenantLabLaunchError(
                    "lab workspace owner-private ACL is unavailable"
                ) from exc
            return
        mode = 0o700 if directory else 0o600
        try:
            os.chmod(path, mode, follow_symlinks=False)
            details = path.lstat()
        except OSError as exc:
            raise TenantLabLaunchError("lab workspace private permissions are unavailable") from exc
        getuid = getattr(os, "getuid", None)
        if (
            _is_link_or_reparse(path, details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or stat.S_IMODE(details.st_mode) != mode
            or (callable(getuid) and details.st_uid != getuid())
        ):
            raise TenantLabLaunchError("lab workspace private permissions are invalid")

    def _remove_unstarted_workspace(self, layout: WorkspaceLayout) -> bool:
        try:
            self._require_protected_root()
        except TenantLabLaunchError:
            return False
        for path in (
            layout.provider_token,
            layout.provider_manifest,
            layout.target_packet,
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                return False
        for path in (
            layout.run_root / "provider",
            layout.run_root / "target",
            layout.run_root,
        ):
            try:
                path.rmdir()
            except OSError:
                return False
        try:
            self._sync_directory(self._root)
        except OSError:
            return False
        try:
            layout.run_root.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name == "nt":
            # File bytes are flushed and all later use revalidates the exact
            # workspace. Windows directory-entry durability belongs to the
            # ProductStore/installed-host qualification boundary.
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _sync_workspace(self, layout: WorkspaceLayout) -> None:
        for path in (
            layout.run_root / "target",
            layout.run_root / "provider",
            layout.run_root,
            self._root,
        ):
            self._sync_directory(path)

    def _layout_and_verify_packets(self, plan: TenantLabLaunchPlan) -> WorkspaceLayout:
        self._require_protected_root()
        layout = WorkspaceLayout.for_run(self._root, plan.run_id)
        self._validate_layout_identity(layout)
        expected = (
            (layout.target_packet, plan.target_packet_digest, MAX_PACKET_BYTES),
            (layout.provider_manifest, plan.provider_manifest_digest, MAX_PACKET_BYTES),
            (layout.provider_token, plan.provider_token_digest, 512),
        )
        for path, digest, maximum in expected:
            if not path.is_file() or _is_link_or_reparse(path) or path.stat().st_size > maximum:
                raise TenantLabLaunchError("lab packet workspace is unavailable")
            if _seal_file(path).sha256 != digest:
                raise TenantLabLaunchError("lab packet changed after preparation")
        return layout

    @staticmethod
    def _validate_layout_identity(layout: WorkspaceLayout) -> None:
        expected = (
            layout.run_root,
            layout.run_root / "target",
            layout.run_root / "provider",
        )
        for path in expected:
            if not path.is_dir() or _is_link_or_reparse(path) or path.resolve(strict=True) != path:
                raise TenantLabLaunchError("lab workspace directory identity changed")

    def _spec(
        self, plan: TenantLabLaunchPlan, layout: WorkspaceLayout, role: ServiceRole
    ) -> FixedChildSpec:
        self._runtime.revalidate()
        python = os.fspath(self._runtime.python_path)
        endpoint = plan.target_endpoint if role is ServiceRole.TARGET else plan.provider_endpoint
        common = (
            "--host",
            endpoint.host,
            "--port",
            str(endpoint.port),
        )
        argv: tuple[str, ...]
        if role is ServiceRole.TARGET:
            argv = (
                python,
                "-I",
                "-B",
                "-m",
                TARGET_MODULE,
                "--fixed-target",
                "--packet",
                os.fspath(layout.target_packet),
                "--audit",
                os.fspath(layout.target_audit),
                "--ready-file",
                os.fspath(layout.target_ready),
                *common,
            )
            packet_digest = plan.target_packet_digest
            packet_source = _seal_file(layout.target_packet)
            module_source = self._runtime.target_seal
            secret_source = None
        else:
            argv = (
                python,
                "-I",
                "-B",
                "-m",
                PROVIDER_MODULE,
                "--manifest",
                os.fspath(layout.provider_manifest),
                "--token-file",
                os.fspath(layout.provider_token),
                "--audit",
                os.fspath(layout.provider_audit),
                "--ready-file",
                os.fspath(layout.provider_ready),
                *common,
            )
            packet_digest = plan.provider_manifest_digest
            packet_source = _seal_file(layout.provider_manifest)
            module_source = self._runtime.provider_seal
            secret_source = _seal_file(layout.provider_token)
        return FixedChildSpec(
            role=role,
            argv=argv,
            environment=(
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("PYTHONHASHSEED", "0"),
                ("PYTHONNOUSERSITE", "1"),
            ),
            endpoint=endpoint,
            run_id=plan.run_id,
            attempt_id=plan.attempt_id,
            plan_digest=plan.digest,
            packet_digest=packet_digest,
            runtime_digest=plan.runtime_digest,
            python_digest=self._runtime.python_digest,
            module_digest=module_source.sha256,
            secondary_secret_digest=(
                None if role is ServiceRole.TARGET else plan.provider_token_digest
            ),
            python_source=self._runtime.python_seal,
            module_source=module_source,
            packet_source=packet_source,
            secondary_secret_source=secret_source,
            custody_mode=plan.custody_mode,
            max_runtime_seconds=plan.max_runtime_seconds,
            max_log_bytes=plan.max_log_bytes,
        )

    @staticmethod
    def _validate_child(spec: FixedChildSpec, child: OwnedChild) -> None:
        if (
            not isinstance(child, OwnedChild)
            or child.role is not spec.role
            or child.plan_digest != spec.plan_digest
            or child.custody_mode != spec.custody_mode
            or child.spec_digest != spec.digest
            or child.endpoint != spec.endpoint
        ):
            raise TenantLabLaunchError("fixed child identity does not match its launch")

    @staticmethod
    def _validate_readiness(
        spec: FixedChildSpec, child: OwnedChild, receipt: ReadinessReceipt
    ) -> None:
        if (
            not isinstance(receipt, ReadinessReceipt)
            or receipt.role is not child.role
            or receipt.process_identity_digest != child.process_identity_digest
            or receipt.spec_digest != spec.digest
            or receipt.endpoint.host != child.endpoint.host
            or (child.endpoint.port != 0 and receipt.endpoint != child.endpoint)
        ):
            raise TenantLabLaunchError("fixed child readiness does not match its process")
        expected_binding = content_hash(
            {
                "role": spec.role.value,
                "process": child.process_identity_digest,
                "endpoint": receipt.endpoint.to_dict(),
                "packet": spec.packet_digest,
                "plan": spec.plan_digest,
            }
        )
        if receipt.binding_digest != expected_binding:
            raise TenantLabLaunchError("fixed child readiness did not bind the launch plan")
        _at_or_after(receipt.observed_at, child.started_at, "readiness")

    @staticmethod
    def _validate_settlement(
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
        settlement: ProcessSettlement,
    ) -> None:
        if not isinstance(settlement, ProcessSettlement) or settlement.role is not role:
            raise TenantLabLaunchError("process settlement role is invalid")
        if settlement.plan_digest != plan.digest or settlement.custody_mode != plan.custody_mode:
            raise TenantLabLaunchError("process settlement belongs to another custody plan")
        if (
            child is not None
            and settlement.process_identity_digest != child.process_identity_digest
        ):
            raise TenantLabLaunchError("process settlement identity changed")
        if (
            child is not None
            and settlement.custody_snapshot_digest != child.custody_snapshot_digest
        ):
            raise TenantLabLaunchError("process settlement changed the custody identity")
        if child is None and settlement.process_identity_digest is not None:
            raise TenantLabLaunchError("process settlement invented an unowned identity")
        if (
            settlement.stdout.byte_count > plan.max_log_bytes
            or settlement.stderr.byte_count > plan.max_log_bytes
        ):
            raise TenantLabLaunchError("process settlement exceeded its log bound")

    def _unknown_settlement(
        self,
        plan: TenantLabLaunchPlan,
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        empty = LogSummary(0, _sha256_bytes(b""), False)
        observed_at = self._now()
        process_identity = None if child is None else child.process_identity_digest
        custody_snapshot = (
            content_hash({"role": role.value, "discovery": "unknown"})
            if child is None
            else child.custody_snapshot_digest
        )
        fields = {
            "role": role.value,
            "process_identity_digest": process_identity,
            "plan_digest": plan.digest,
            "custody_mode": plan.custody_mode,
            "custody_snapshot_digest": custody_snapshot,
            "presence": Presence.UNKNOWN.value,
            "observed_at": observed_at,
            "stdout": {"byte_count": 0, "sha256": empty.sha256, "truncated": False},
            "stderr": {"byte_count": 0, "sha256": empty.sha256, "truncated": False},
        }
        # Unknown discovery without a retained child still binds the active
        # plan and its requested custody mode below.
        plan_digest = plan.digest
        custody_mode = plan.custody_mode
        fields["plan_digest"] = plan_digest
        fields["custody_mode"] = custody_mode
        return ProcessSettlement(
            role=role,
            process_identity_digest=process_identity,
            plan_digest=plan_digest,
            custody_mode=custody_mode,
            custody_snapshot_digest=custody_snapshot,
            presence=Presence.UNKNOWN,
            observed_at=observed_at,
            custody_receipt_digest=content_hash(fields),
            stdout=empty,
            stderr=empty,
        )

    def _settled(
        self,
        record: TenantLabLifecycleRecord,
        settlements: tuple[ProcessSettlement, ...],
        sink: LifecycleSink,
        phase: str,
    ) -> TenantLabLifecycleRecord:
        roles = {item.role for item in settlements}
        all_absent = roles == set(ServiceRole) and all(
            item.presence is Presence.ABSENT for item in settlements
        )
        prior_digest = record.digest
        updated = replace(
            record,
            revision=record.revision + 1,
            state=LifecycleState.STOPPED if all_absent else LifecycleState.UNKNOWN,
            ended_at=self._now(),
            settlements=tuple(sorted(settlements, key=lambda value: value.role.value)),
        )
        self._commit(
            sink,
            updated,
            phase if all_absent else f"{phase}_unknown",
            prior_digest,
        )
        return updated

    def _best_effort_reconcile(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord:
        children = {child.role: child for child in record.children}
        settlements: list[ProcessSettlement] = []
        for role in (ServiceRole.TEST_PROVIDER, ServiceRole.TARGET):
            try:
                settlement = self._backend.reconcile(record.plan, role, children.get(role))
                self._validate_settlement(record.plan, role, children.get(role), settlement)
            except BaseException:
                settlement = self._unknown_settlement(record.plan, role, children.get(role))
            settlements.append(settlement)
        try:
            return self._settled(record, tuple(settlements), sink, "launch_failed")
        except BaseException:
            # The caller receives an explicit UNKNOWN record even if persistence
            # itself failed while the launcher was attempting to retain it.
            return replace(
                record,
                revision=record.revision + 1,
                state=LifecycleState.UNKNOWN,
                ended_at=self._now(),
                settlements=tuple(sorted(settlements, key=lambda value: value.role.value)),
            )
