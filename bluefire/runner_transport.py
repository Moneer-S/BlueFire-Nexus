"""Authenticated loopback transport for the separately hosted Rust runner.

The wire protocol intentionally has one request and one response per TLS
connection.  That keeps framing and failure recovery small enough to audit:
mutual TLS authenticates the enrolled processes, an independent HMAC binds the
complete canonical request/response, and SQLite records each nonce and task
before an effect may be dispatched.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import struct
import threading
import time
from contextlib import closing, contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Iterator, Mapping, cast

from cryptography import x509
from cryptography.x509.oid import NameOID

from .runner_client import (
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
    RunnerTransport,
    RunnerTransportError,
    SubprocessRustRunner,
    _PinnedPrivateDirectory,
    _windows_open_descriptor,
    canonical_runner_inventory,
    cleanup_runner_watchdog_terminal_state,
    request_runner_task_cancel,
    runner_pending_result_path,
    runner_watchdog_control_root,
)
from .runner_trust import (
    RunnerEnrollment,
    RunnerTrustError,
    _is_link_or_reparse,
    _owner_private,
    certificate_fingerprint,
    load_local_enrollment,
)
from .secret_store import SecretProvider
from .util import canonical_json_bytes, content_hash, file_hash

TRANSPORT_SCHEMA_VERSION = "bluefire.runner-transport.v1"
LEDGER_SCHEMA_VERSION = 4
DEFAULT_MAX_FRAME_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_WORKERS = 16
DEFAULT_CONTROL_WORKER_RESERVE = 4
DEFAULT_MAX_TERMINAL_ROWS = 256
DEFAULT_MAX_LEDGER_ROWS = 10_000
DEFAULT_MAX_LEDGER_BYTES = 512 * 1024 * 1024
DEFAULT_CONTROL_RESERVE_ROWS = 64
DEFAULT_TERMINAL_RETENTION_SECONDS = 7 * 24 * 60 * 60
_MAX_RECOVERY_RECEIPTS = 512
_MAX_RECEIPT_BYTES = 256 * 1024
_EXECUTE_RECOVERY_RESERVE_BYTES = _MAX_RECOVERY_RECEIPTS * 68 + 128
_SQLITE_OVERHEAD_BYTES = 2 * 1024 * 1024
_FRAME_HEADER = struct.Struct("!I")
_OPERATIONS = frozenset({"health", "inventory", "execute", "recover", "cancel", "shutdown"})
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "operation",
        "runner_id",
        "client_id",
        "profile_id",
        "task_id",
        "nonce",
        "request_hash",
        "payload",
        "authentication",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "operation",
        "runner_id",
        "client_id",
        "profile_id",
        "task_id",
        "nonce",
        "request_hash",
        "ok",
        "status",
        "payload",
        "response_hash",
        "error_code",
        "authentication",
    }
)
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_NONCE = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_GENERATION = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "run_id",
        "step_id",
        "behavior_id",
        "action_id",
        "status",
        "runner_id",
        "runner_profile_id",
        "platform",
        "request_hash",
        "policy_digest",
        "started_at",
        "finished_at",
        "output",
        "stdout",
        "stderr",
        "receipt_ids",
        "cleanup",
        "evidence",
        "error",
        "limitations",
    }
)
_RESULT_STATUSES = frozenset(
    {
        "success",
        "failed",
        "partial",
        "refused",
        "control_blocked",
        "timed_out",
        "cleanup_failed",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "request_hash",
        "action_id",
        "runner_profile_id",
        "workspace_id",
        "created_at",
        "paths",
    }
)
_RECEIPT_COMMIT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "runner_profile_id",
        "workspace_id",
        "committed_at",
    }
)
_OWNED_PATH_FIELDS = frozenset({"relative_path", "kind", "sha256", "size"})
_REMOTE_ERROR_MESSAGES = {
    "authentication_failed": "Runner request authentication failed.",
    "profile_not_allowed": "Runner profile is not enrolled for this transport.",
    "request_invalid": "Runner request is invalid or unsupported.",
    "replay_detected": "Runner refused a replayed request.",
    "duplicate_request": "Runner task was already recorded.",
    "task_conflict": "Runner task identity conflicts with an existing request.",
    "task_not_found": "Runner task was not found.",
    "task_identity_mismatch": "Runner task recovery identity does not match.",
    "runner_failure": "Runner could not complete the requested operation.",
    "ledger_unavailable": "Runner recovery state is unavailable.",
    "ledger_capacity": "Runner recovery ledger has reached its safe capacity.",
    "runner_busy": "Runner request capacity is temporarily unavailable.",
    "runner_draining": "Runner is draining and is not accepting new execution tasks.",
    "active_tasks": "Runner shutdown is waiting for active execution tasks to finish.",
    "outcome_indeterminate": "Runner outcome is indeterminate and requires recovery.",
    "recovery_required": "Runner effects require receipt-based cleanup recovery.",
    "task_cancelled": "Runner task was cancelled after its process tree stopped.",
    "task_timed_out": "Runner task timed out after its process tree stopped.",
}
_LEDGER_PROCESS_LOCK = threading.Lock()
_LOCKED_LEDGERS: set[str] = set()
_LEDGER_METADATA_SCHEMA = "bluefire.runner-ledger-metadata.v1"
_LEDGER_METADATA_SQL = """
CREATE TABLE runner_ledger_metadata (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL CHECK (
        schema_version = 'bluefire.runner-ledger-metadata.v1'
    ),
    ledger_generation TEXT NOT NULL UNIQUE CHECK (
        length(ledger_generation) = 64
        AND ledger_generation NOT GLOB '*[^0-9a-f]*'
    )
) WITHOUT ROWID
"""
_LEDGER_METADATA_COLUMNS = (
    ("singleton", "INTEGER", 1, 1),
    ("schema_version", "TEXT", 1, 0),
    ("ledger_generation", "TEXT", 1, 0),
)
_TRANSPORT_TASKS_SQL = """
CREATE TABLE transport_tasks (
    task_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    runner_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    peer_fingerprint TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL,
    server_fingerprint TEXT NOT NULL,
    client_fingerprint TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    execute_payload_json BLOB,
    result_json BLOB,
    recovery_receipts_json BLOB,
    cleanup_required INTEGER NOT NULL DEFAULT 0,
    effect_dispatched INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    executor_instance TEXT NOT NULL,
    cancellation_requested INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
)
"""
_TRANSPORT_TASKS_NONCE_INDEX_SQL = "CREATE INDEX transport_tasks_nonce ON transport_tasks(nonce)"
_LEDGER_APPLICATION_OBJECTS = frozenset(
    {
        ("table", "runner_ledger_metadata"),
        ("table", "transport_tasks"),
        ("index", "transport_tasks_nonce"),
    }
)
_MAX_LEDGER_INSPECTION_BYTES = DEFAULT_MAX_LEDGER_BYTES + _SQLITE_OVERHEAD_BYTES
_MAX_LEDGER_SQL_VALUE_BYTES = 256 * 1024
_MAX_LEDGER_VALUE_BYTES = DEFAULT_MAX_FRAME_BYTES + 1024 * 1024
_LEDGER_STATES = frozenset(
    {
        "running",
        "completed",
        "failed",
        "indeterminate",
        "recovery_required",
        "cancelled",
        "timed_out",
    }
)
_LEDGER_UNRESOLVED_STATES = frozenset({"running", "indeterminate", "recovery_required"})
_LEDGER_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class AuthenticatedRunnerTransportError(RunnerTransportError):
    """A secret- and path-safe authenticated transport failure."""


class RunnerConnectionError(AuthenticatedRunnerTransportError):
    """The loopback transport could not complete an exchange."""


class RunnerAuthenticationError(AuthenticatedRunnerTransportError):
    """TLS, enrollment, framing, or message authentication failed."""


class RunnerRemoteError(AuthenticatedRunnerTransportError):
    """An authenticated refusal returned by the runner service."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _REMOTE_ERROR_MESSAGES else "request_invalid"
        super().__init__(_REMOTE_ERROR_MESSAGES[self.code])


class _RequestRefusal(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _EnrollmentCache:
    """Reuse validated material until the public trust document changes."""

    def __init__(self, root: Path, *, secret_provider: SecretProvider | None = None) -> None:
        self.root = root
        self.secret_provider = secret_provider
        self._lock = threading.Lock()
        self._enrollment, self._marker = self._load_stable()

    def active(self) -> RunnerEnrollment:
        try:
            marker = self._trust_marker()
        except OSError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None
        with self._lock:
            if marker != self._marker:
                self._enrollment, self._marker = self._load_stable()
            if self._enrollment.status != "active":
                raise RunnerAuthenticationError("Runner enrollment is unavailable or inactive.")
            return self._enrollment

    def _load_stable(self) -> tuple[RunnerEnrollment, tuple[int, int, int, int]]:
        try:
            for _attempt in range(2):
                before = self._trust_marker()
                enrollment = self._load()
                after = self._trust_marker()
                if before == after:
                    return enrollment, after
        except OSError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None
        raise RunnerAuthenticationError("Runner enrollment changed while it was validated.")

    def _load(self) -> RunnerEnrollment:
        try:
            return load_local_enrollment(self.root, secret_provider=self.secret_provider)
        except RunnerTrustError:
            raise RunnerAuthenticationError(
                "Runner enrollment is unavailable or inactive."
            ) from None

    def _trust_marker(self) -> tuple[int, int, int, int]:
        status = (self.root / "trust.json").stat()
        return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _loopback_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AuthenticatedRunnerTransportError(
            "Runner address must be literal loopback."
        ) from None
    if not address.is_loopback:
        raise AuthenticatedRunnerTransportError("Runner address must be literal loopback.")
    return address.compressed


def _port(value: int, *, allow_zero: bool) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 65535:
        raise AuthenticatedRunnerTransportError("Runner port is invalid.")
    return value


def _token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise RunnerAuthenticationError("Runner message identity is invalid.")
    return value


def _execute_task_id(request_hash: str) -> str:
    if _DIGEST.fullmatch(request_hash) is None:
        raise RunnerAuthenticationError("Runner execution identity is invalid.")
    return "execute-" + request_hash.removeprefix("sha256:")


def _enrollment_binding(enrollment: RunnerEnrollment, peer_fingerprint: str) -> dict[str, str]:
    public_identity = {
        "runner_id": enrollment.runner_id,
        "client_id": enrollment.client_id,
        "ca_fingerprint": str(enrollment.metadata["ca_fingerprint"]),
        "server_fingerprint": str(enrollment.metadata["server_fingerprint"]),
        "client_fingerprint": str(enrollment.metadata["client_fingerprint"]),
    }
    return {
        **public_identity,
        "peer_fingerprint": peer_fingerprint,
        "enrollment_generation": content_hash(public_identity),
    }


def _normalized_sql(value: Any) -> str:
    return " ".join(str(value).split())


def _limit_sqlite_connection(connection: sqlite3.Connection) -> None:
    setlimit = getattr(connection, "setlimit", None)
    if callable(setlimit):
        setlimit(int(getattr(sqlite3, "SQLITE_LIMIT_LENGTH", 0)), _MAX_LEDGER_VALUE_BYTES)
        setlimit(
            int(getattr(sqlite3, "SQLITE_LIMIT_SQL_LENGTH", 1)),
            _MAX_LEDGER_SQL_VALUE_BYTES,
        )
        setlimit(int(getattr(sqlite3, "SQLITE_LIMIT_COLUMN", 2)), 128)
        setlimit(int(getattr(sqlite3, "SQLITE_LIMIT_COMPOUND_SELECT", 4)), 16)
        setlimit(int(getattr(sqlite3, "SQLITE_LIMIT_EXPR_DEPTH", 3)), 64)


def _ledger_application_objects(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, str | None], ...]:
    return tuple(
        (str(row[0]), str(row[1]), str(row[2]), None if row[3] is None else str(row[3]))
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
    )


def _validated_index_shapes(
    connection: sqlite3.Connection,
    table: str,
) -> tuple[tuple[int, str, int, tuple[str, ...]], ...]:
    shapes: list[tuple[int, str, int, tuple[str, ...]]] = []
    for row in connection.execute(f"PRAGMA index_list({table})").fetchall():
        name = str(row[1])
        columns = tuple(
            str(item[2]) for item in connection.execute(f"PRAGMA index_info({name})").fetchall()
        )
        shapes.append((int(row[2]), str(row[3]), int(row[4]), columns))
    return tuple(sorted(shapes))


def _validated_ledger_schema(connection: sqlite3.Connection) -> None:
    objects = _ledger_application_objects(connection)
    identities = frozenset((kind, name) for kind, name, _table, _sql in objects)
    if identities != _LEDGER_APPLICATION_OBJECTS or len(objects) != len(
        _LEDGER_APPLICATION_OBJECTS
    ):
        raise sqlite3.DatabaseError("invalid ledger application schema")
    definitions = {(kind, name): sql for kind, name, _table, sql in objects}
    if (
        _normalized_sql(definitions.get(("table", "runner_ledger_metadata")))
        != _normalized_sql(_LEDGER_METADATA_SQL)
        or _normalized_sql(definitions.get(("table", "transport_tasks")))
        != _normalized_sql(_TRANSPORT_TASKS_SQL)
        or _normalized_sql(definitions.get(("index", "transport_tasks_nonce")))
        != _normalized_sql(_TRANSPORT_TASKS_NONCE_INDEX_SQL)
    ):
        raise sqlite3.DatabaseError("invalid ledger schema definition")
    if _validated_index_shapes(connection, "transport_tasks") != (
        (0, "c", 0, ("nonce",)),
        (1, "pk", 0, ("task_id",)),
        (1, "u", 0, ("nonce",)),
    ):
        raise sqlite3.DatabaseError("invalid task ledger indexes")
    if _validated_index_shapes(connection, "runner_ledger_metadata") != (
        (1, "pk", 0, ("singleton",)),
        (1, "u", 0, ("ledger_generation",)),
    ):
        raise sqlite3.DatabaseError("invalid metadata indexes")
    if connection.execute("PRAGMA foreign_key_list(transport_tasks)").fetchall():
        raise sqlite3.DatabaseError("unexpected task ledger foreign keys")


def _validated_ledger_generation(connection: sqlite3.Connection) -> str:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != LEDGER_SCHEMA_VERSION:
        raise sqlite3.DatabaseError("unsupported ledger schema")
    _validated_ledger_schema(connection)
    definition = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = 'runner_ledger_metadata'"
    ).fetchall()
    if (
        len(definition) != 1
        or str(definition[0][0]) != "table"
        or _normalized_sql(definition[0][1]) != _normalized_sql(_LEDGER_METADATA_SQL)
    ):
        raise sqlite3.DatabaseError("invalid ledger metadata table")
    columns = tuple(
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(runner_ledger_metadata)").fetchall()
    )
    if columns != _LEDGER_METADATA_COLUMNS:
        raise sqlite3.DatabaseError("invalid ledger metadata columns")
    rows = connection.execute(
        """
        SELECT singleton, schema_version, ledger_generation
        FROM runner_ledger_metadata ORDER BY singleton LIMIT 2
        """
    ).fetchall()
    if len(rows) != 1:
        raise sqlite3.DatabaseError("invalid ledger metadata cardinality")
    singleton, schema_version, ledger_generation = rows[0]
    if (
        singleton != 1
        or schema_version != _LEDGER_METADATA_SCHEMA
        or not isinstance(ledger_generation, str)
        or _LEDGER_GENERATION.fullmatch(ledger_generation) is None
    ):
        raise sqlite3.DatabaseError("invalid ledger generation")
    return ledger_generation


@contextmanager
def _pinned_ledger_inspection(
    state_path: str | Path,
    *,
    maximum_bytes: int = _MAX_LEDGER_INSPECTION_BYTES,
) -> Iterator[sqlite3.Connection | None]:
    candidate = Path(state_path).expanduser()
    if (
        not candidate.is_absolute()
        or candidate.name in {"", ".", ".."}
        or isinstance(maximum_bytes, bool)
        or not 4096 <= maximum_bytes <= _MAX_LEDGER_INSPECTION_BYTES
    ):
        raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.")
    parent_descriptor: int | None = None
    guard: BinaryIO | None = None
    connection: sqlite3.Connection | None = None
    try:
        if _is_link_or_reparse(candidate.parent):
            raise OSError("linked recovery parent")
        parent = candidate.parent.resolve(strict=True)
        if os.path.normcase(str(parent / candidate.name)) != os.path.normcase(
            str(candidate.absolute())
        ):
            raise OSError("recovery path aliases another location")
        for suffix in _LEDGER_SIDECAR_SUFFIXES:
            sidecar = candidate.with_name(candidate.name + suffix)
            if sidecar.exists() or _is_link_or_reparse(sidecar):
                raise OSError("unexpected recovery ledger sidecar")
        if os.name == "nt":
            try:
                parent_descriptor = _windows_open_descriptor(parent, directory=True)
                parent_identity = os.fstat(parent_descriptor)
                descriptor = _windows_open_descriptor(candidate, directory=False)
            except FileNotFoundError:
                if parent_descriptor is None:
                    raise OSError("recovery parent disappeared") from None
                current_parent = parent.stat(follow_symlinks=False)
                if (
                    (current_parent.st_dev, current_parent.st_ino)
                    != (parent_identity.st_dev, parent_identity.st_ino)
                    or candidate.exists()
                    or _is_link_or_reparse(candidate)
                    or any(
                        candidate.with_name(candidate.name + suffix).exists()
                        or _is_link_or_reparse(candidate.with_name(candidate.name + suffix))
                        for suffix in _LEDGER_SIDECAR_SUFFIXES
                    )
                ):
                    raise OSError("recovery ledger absence changed") from None
                yield None
                return
            guard = os.fdopen(descriptor, "rb", buffering=0)
            database_uri = candidate.as_uri() + "?mode=ro&immutable=1"
        else:
            parent_descriptor = os.open(
                parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                descriptor = os.open(
                    candidate.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                yield None
                return
            guard = os.fdopen(descriptor, "rb", buffering=0)
            proc_descriptor = Path("/proc/self/fd")
            dev_descriptor = Path("/dev/fd")
            if proc_descriptor.is_dir():
                descriptor_path = proc_descriptor / str(descriptor)
            elif dev_descriptor.is_dir():
                descriptor_path = dev_descriptor / str(descriptor)
            else:
                raise OSError("descriptor-backed SQLite inspection is unavailable")
            database_uri = descriptor_path.as_uri() + "?mode=ro&immutable=1"
        pinned = os.fstat(guard.fileno())
        current = candidate.stat(follow_symlinks=False)
        if (
            _is_link_or_reparse(candidate)
            or not stat.S_ISREG(pinned.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or pinned.st_nlink != 1
            or current.st_nlink != 1
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
            or not 0 < pinned.st_size <= maximum_bytes
        ):
            raise OSError("unsafe recovery ledger")
        connection = sqlite3.connect(database_uri, uri=True, timeout=2.0)
        connection.row_factory = sqlite3.Row
        _limit_sqlite_connection(connection)
        connection.execute("PRAGMA query_only = ON")
        yield connection
        after = candidate.stat(follow_symlinks=False)
        final = os.fstat(guard.fileno())
        if (
            _is_link_or_reparse(candidate)
            or after.st_nlink != 1
            or final.st_nlink != 1
            or (after.st_dev, after.st_ino) != (pinned.st_dev, pinned.st_ino)
            or (final.st_dev, final.st_ino) != (pinned.st_dev, pinned.st_ino)
            or final.st_size > maximum_bytes
        ):
            raise OSError("recovery ledger identity changed")
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise AuthenticatedRunnerTransportError(
            "Runner recovery ledger could not be inspected safely."
        ) from None
    finally:
        if connection is not None:
            connection.close()
        if guard is not None:
            guard.close()
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def read_runner_ledger_generation(state_path: str | Path) -> str | None:
    """Read one exact ledger generation without creating or modifying the ledger.

    A cleanly absent path returns ``None``. Unsafe, malformed, legacy, or raced
    paths are refused so lifecycle code cannot derive a recovery namespace from
    anything except the strict singleton metadata record.
    """

    with _pinned_ledger_inspection(state_path) as connection:
        if connection is None:
            return None
        try:
            return _validated_ledger_generation(connection)
        except sqlite3.Error:
            raise AuthenticatedRunnerTransportError(
                "Runner recovery ledger generation could not be verified."
            ) from None


def audit_runner_ledger(
    state_path: str | Path,
    enrollment: RunnerEnrollment,
    *,
    maximum_bytes: int = _MAX_LEDGER_INSPECTION_BYTES,
) -> Mapping[str, Any] | None:
    """Strictly audit one stopped runner ledger without exposing task material."""

    if not isinstance(enrollment, RunnerEnrollment):
        raise AuthenticatedRunnerTransportError("Runner enrollment identity is invalid.")
    client_fingerprint = str(enrollment.metadata["client_fingerprint"])
    binding = _enrollment_binding(enrollment, client_fingerprint)
    allowed_profiles = frozenset(enrollment.allowed_profile_ids)
    with _pinned_ledger_inspection(state_path, maximum_bytes=maximum_bytes) as connection:
        if connection is None:
            return None
        try:
            generation = _validated_ledger_generation(connection)
            integrity = connection.execute("PRAGMA quick_check(1)").fetchall()
            if len(integrity) != 1 or str(integrity[0][0]) != "ok":
                raise sqlite3.DatabaseError("ledger integrity check failed")
            total = execute = unresolved = active = cleanup_required = 0
            rows = connection.execute(
                """
                SELECT task_id, operation, profile_id, request_hash, runner_id, client_id,
                       peer_fingerprint, ca_fingerprint, server_fingerprint,
                       client_fingerprint, enrollment_generation, nonce, state,
                       execute_payload_json, result_json, recovery_receipts_json,
                       cleanup_required, effect_dispatched, error_code, executor_instance,
                       cancellation_requested, created_at, updated_at
                FROM transport_tasks ORDER BY task_id
                """
            )
            for row in rows:
                total += 1
                if total > 1_000_000:
                    raise sqlite3.DatabaseError("ledger row bound exceeded")
                operation = row["operation"]
                state_value = row["state"]
                is_execute = operation == "execute"
                if is_execute:
                    execute += 1
                if state_value in _LEDGER_UNRESOLVED_STATES:
                    unresolved += 1
                if state_value == "running":
                    active += 1
                cleanup_required += int(row["cleanup_required"] == 1)
                blobs = (
                    row["execute_payload_json"],
                    row["result_json"],
                    row["recovery_receipts_json"],
                )
                if (
                    operation not in _OPERATIONS
                    or state_value not in _LEDGER_STATES
                    or row["profile_id"] not in allowed_profiles
                    or any(row[field] != value for field, value in binding.items())
                    or _TOKEN.fullmatch(str(row["task_id"])) is None
                    or _TOKEN.fullmatch(str(row["executor_instance"])) is None
                    or _DIGEST.fullmatch(str(row["request_hash"])) is None
                    or _NONCE.fullmatch(str(row["nonce"])) is None
                    or row["cleanup_required"] not in {0, 1}
                    or row["effect_dispatched"] not in {0, 1}
                    or row["cancellation_requested"] not in {0, 1}
                    or not isinstance(row["created_at"], int)
                    or not isinstance(row["updated_at"], int)
                    or row["created_at"] < 0
                    or row["updated_at"] < row["created_at"]
                    or any(
                        blob is not None
                        and (not isinstance(blob, bytes) or len(blob) > _MAX_LEDGER_VALUE_BYTES)
                        for blob in blobs
                    )
                    or (is_execute and row["task_id"] != _execute_task_id(row["request_hash"]))
                    or (is_execute and row["execute_payload_json"] is None)
                    or (not is_execute and row["execute_payload_json"] is not None)
                    or (not is_execute and row["effect_dispatched"] != 0)
                    or (state_value == "completed" and row["result_json"] is None)
                    or (state_value != "completed" and row["result_json"] is not None)
                    or (
                        state_value == "recovery_required"
                        and (row["cleanup_required"] != 1 or row["recovery_receipts_json"] is None)
                    )
                    or (
                        state_value != "recovery_required"
                        and (
                            row["cleanup_required"] != 0
                            or row["recovery_receipts_json"] is not None
                        )
                    )
                    or (row["error_code"] is not None and not isinstance(row["error_code"], str))
                ):
                    raise sqlite3.DatabaseError("ledger row identity is invalid")
            return {
                "schema_version": "bluefire.runner-ledger-audit.v1",
                "ledger_generation": generation,
                "total_rows": total,
                "execute_rows": execute,
                "unresolved_rows": unresolved,
                "active_rows": active,
                "cleanup_required_rows": cleanup_required,
            }
        except (RunnerAuthenticationError, sqlite3.Error, TypeError, ValueError):
            raise AuthenticatedRunnerTransportError(
                "Runner recovery ledger audit could not be verified."
            ) from None


def runner_result_namespace_id(
    state_path: str | Path,
    enrollment: RunnerEnrollment | str,
    *,
    ledger_generation: str,
) -> str:
    """Derive the stable secret-free result namespace for one ledger generation."""

    candidate = Path(state_path).expanduser()
    if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
        raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.") from None
    if isinstance(enrollment, RunnerEnrollment):
        generation = _enrollment_binding(
            enrollment, str(enrollment.metadata["client_fingerprint"])
        )["enrollment_generation"]
    else:
        generation = enrollment
    if not isinstance(generation, str) or _DIGEST.fullmatch(generation) is None:
        raise AuthenticatedRunnerTransportError("Runner enrollment generation is invalid.")
    if (
        not isinstance(ledger_generation, str)
        or _LEDGER_GENERATION.fullmatch(ledger_generation) is None
    ):
        raise AuthenticatedRunnerTransportError("Runner ledger generation is invalid.")
    identity = {
        "schema_version": "bluefire.runner-result-namespace.v2",
        "ledger_path": os.path.normcase(str(resolved)),
        "ledger_generation": ledger_generation,
        "enrollment_generation": generation,
    }
    # 160 bits keeps Windows recovery/control paths below legacy MAX_PATH in
    # ordinary temporary roots while retaining collision-resistant identities.
    return content_hash(identity).removeprefix("sha256:")[:40]


def runner_result_namespace_path(
    state_path: str | Path,
    enrollment: RunnerEnrollment | str,
    *,
    ledger_generation: str,
) -> Path:
    """Return the exact namespace path without creating or modifying it."""

    candidate = Path(state_path).expanduser()
    if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
        raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.")
    try:
        candidate = candidate.resolve(strict=False)
    except OSError:
        raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.") from None
    return (
        candidate.parent
        / ".bluefire-runner-results"
        / runner_result_namespace_id(
            candidate,
            enrollment,
            ledger_generation=ledger_generation,
        )
    )


def _request_mac(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> str:
    digest = hmac.new(
        enrollment.hmac_key(), canonical_json_bytes(dict(unsigned)), hashlib.sha256
    ).hexdigest()
    return "sha256:" + digest


def _sign_request(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(unsigned), "authentication": _request_mac(enrollment, unsigned)}


def _sign_response(enrollment: RunnerEnrollment, unsigned: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(unsigned), "authentication": _request_mac(enrollment, unsigned)}


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _decode_json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicates_rejected,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise RunnerAuthenticationError("Runner message is not valid canonical JSON.") from None
    if not isinstance(value, dict):
        raise RunnerAuthenticationError("Runner message must be a JSON object.")
    try:
        if canonical_json_bytes(value) != payload:
            raise RunnerAuthenticationError("Runner message is not canonical JSON.")
    except (RecursionError, TypeError, ValueError):
        raise RunnerAuthenticationError("Runner message contains unsupported JSON.") from None
    return value


def _decode_durable_json_object(payload: bytes) -> dict[str, Any]:
    """Decode runner-owned JSON without requiring a whitespace representation.

    Rust deliberately emits pretty JSON for results and receipts.  The decoded
    value is still required to be finite, duplicate-free, and canonically
    serializable before any identity comparison is made.
    """

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicates_rejected,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("document is not an object")
        canonical_json_bytes(value)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise RunnerTransportError("runner durable artifact is invalid") from None
    return value


def _safe_relative_receipt_path(value: Any) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return None
    if "\\" in value or ":" in value or any(ord(character) < 32 for character in value):
        return None
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    normalized = candidate.as_posix()
    return normalized if normalized == value else None


def _receive_exact(
    connection: ssl.SSLSocket,
    length: int,
    *,
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> bytes:
    result = bytearray()
    while len(result) < length:
        if abort_event is not None and abort_event.is_set():
            raise RunnerConnectionError("Runner message wait was cancelled.")
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunnerConnectionError("Runner message deadline expired.")
            connection.settimeout(min(remaining, 0.1) if abort_event is not None else remaining)
        try:
            chunk = connection.recv(length - len(result))
        except TimeoutError:
            if abort_event is not None:
                continue
            raise
        if not chunk:
            raise RunnerConnectionError("Runner connection closed before the message completed.")
        result.extend(chunk)
    return bytes(result)


def _receive_frame(
    connection: ssl.SSLSocket,
    maximum: int,
    *,
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> dict[str, Any]:
    header = _receive_exact(
        connection,
        _FRAME_HEADER.size,
        deadline=deadline,
        abort_event=abort_event,
    )
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > maximum:
        raise RunnerAuthenticationError("Runner message exceeds the framing limit.")
    return _decode_json_object(
        _receive_exact(
            connection,
            length,
            deadline=deadline,
            abort_event=abort_event,
        )
    )


def _send_frame(connection: ssl.SSLSocket, value: Mapping[str, Any], maximum: int) -> None:
    try:
        payload = canonical_json_bytes(dict(value))
    except (RecursionError, TypeError, ValueError):
        raise RunnerAuthenticationError("Runner message contains unsupported JSON.") from None
    if not payload or len(payload) > maximum:
        raise RunnerAuthenticationError("Runner message exceeds the framing limit.")
    connection.sendall(_FRAME_HEADER.pack(len(payload)) + payload)


def _certificate_common_name(certificate_bytes: bytes) -> str:
    try:
        certificate = x509.load_der_x509_certificate(certificate_bytes)
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except (TypeError, ValueError):
        raise RunnerAuthenticationError("Runner peer certificate is invalid.") from None
    if len(names) != 1 or not isinstance(names[0].value, str):
        raise RunnerAuthenticationError("Runner peer certificate identity is invalid.")
    return names[0].value


def _verify_peer(
    connection: ssl.SSLSocket,
    *,
    expected_fingerprint: str,
    expected_common_name: str,
) -> str:
    certificate = connection.getpeercert(binary_form=True)
    if not certificate:
        raise RunnerAuthenticationError("Runner peer did not present a certificate.")
    fingerprint = certificate_fingerprint(certificate)
    if not hmac.compare_digest(fingerprint, expected_fingerprint):
        raise RunnerAuthenticationError("Runner peer certificate identity does not match.")
    if not hmac.compare_digest(_certificate_common_name(certificate), expected_common_name):
        raise RunnerAuthenticationError("Runner peer certificate identity does not match.")
    if connection.version() != "TLSv1.3":
        raise RunnerAuthenticationError("Runner transport did not negotiate TLS 1.3.")
    return fingerprint


def _server_context(enrollment: RunnerEnrollment) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=str(enrollment.ca_certificate))
        context.load_cert_chain(
            certfile=str(enrollment.server_certificate),
            keyfile=str(enrollment.server_private_key),
            password=enrollment.server_key_password(),
        )
    except (OSError, ssl.SSLError):
        raise RunnerAuthenticationError("Runner server identity could not be loaded.") from None
    return context


def _client_context(enrollment: RunnerEnrollment) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    try:
        context.load_verify_locations(cafile=str(enrollment.ca_certificate))
        context.load_cert_chain(
            certfile=str(enrollment.client_certificate),
            keyfile=str(enrollment.client_private_key),
            password=enrollment.client_key_password(),
        )
    except (OSError, ssl.SSLError):
        raise RunnerAuthenticationError("Runner client identity could not be loaded.") from None
    return context


class AuthenticatedRunnerServer:
    """Mutually authenticated, durable loopback host for a runner transport."""

    def __init__(
        self,
        enrollment_root: str | Path,
        runner: RunnerTransport,
        state_path: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        socket_timeout_seconds: float = 10.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_workers: int = DEFAULT_MAX_WORKERS,
        control_worker_reserve: int = DEFAULT_CONTROL_WORKER_RESERVE,
        max_terminal_rows: int = DEFAULT_MAX_TERMINAL_ROWS,
        max_ledger_rows: int = DEFAULT_MAX_LEDGER_ROWS,
        max_ledger_bytes: int = DEFAULT_MAX_LEDGER_BYTES,
        control_reserve_rows: int = DEFAULT_CONTROL_RESERVE_ROWS,
        terminal_retention_seconds: int = DEFAULT_TERMINAL_RETENTION_SECONDS,
        cancel_confirmation_seconds: float = 5.0,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        if (
            socket_timeout_seconds <= 0
            or not 4096 <= max_frame_bytes <= DEFAULT_MAX_FRAME_BYTES
            or isinstance(max_workers, bool)
            or not 2 <= max_workers <= 128
            or isinstance(control_worker_reserve, bool)
            or not 1 <= control_worker_reserve < max_workers
            or isinstance(max_terminal_rows, bool)
            or not 1 <= max_terminal_rows <= 100_000
            or isinstance(max_ledger_rows, bool)
            or not 1 <= max_ledger_rows <= 1_000_000
            or isinstance(control_reserve_rows, bool)
            or not 3 <= control_reserve_rows < max_ledger_rows
            or isinstance(max_ledger_bytes, bool)
            or not (
                (control_reserve_rows + 1) * max_frame_bytes + _EXECUTE_RECOVERY_RESERVE_BYTES
                <= max_ledger_bytes
                <= 64 * 1024 * 1024 * 1024
            )
            or isinstance(terminal_retention_seconds, bool)
            or not 60 <= terminal_retention_seconds <= 365 * 24 * 60 * 60
            or not 0.1 <= cancel_confirmation_seconds <= 30
        ):
            raise AuthenticatedRunnerTransportError("Runner transport bounds are invalid.")
        self.enrollment_root = Path(enrollment_root).expanduser()
        self._enrollments = _EnrollmentCache(self.enrollment_root, secret_provider=secret_provider)
        enrollment = self._enrollments.active()
        self.runner = runner
        self.host = _loopback_host(host)
        self.port = _port(port, allow_zero=True)
        self.socket_timeout_seconds = float(socket_timeout_seconds)
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_workers = int(max_workers)
        self.control_worker_reserve = int(control_worker_reserve)
        self.max_terminal_rows = int(max_terminal_rows)
        self.max_ledger_rows = int(max_ledger_rows)
        self.max_ledger_bytes = int(max_ledger_bytes)
        self.control_reserve_rows = int(control_reserve_rows)
        self.control_reserve_bytes = self.control_reserve_rows * self.max_frame_bytes
        self.terminal_retention_ns = int(terminal_retention_seconds * 1_000_000_000)
        self.cancel_confirmation_seconds = float(cancel_confirmation_seconds)
        self.instance_id = secrets.token_hex(16)
        self.state_path = self._prepare_state_path(state_path)
        self._runner_binary, self._runner_binary_digest = self._bind_runner_binary()
        self._server_context = _server_context(enrollment)
        self._stop = threading.Event()
        self._serve_thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._ingress_slots = threading.BoundedSemaphore(max_workers)
        self._execute_slots = threading.BoundedSemaphore(max_workers - control_worker_reserve)
        self._control_slots = threading.BoundedSemaphore(control_worker_reserve)
        self._task_cancellations: dict[str, threading.Event] = {}
        self._task_cancellations_lock = threading.Lock()
        self._dispatch_state_lock = threading.Lock()
        self._accepting_execute = True
        self._ledger_release_lock = threading.Lock()
        self._database_lock = threading.RLock()
        self._database_connection: sqlite3.Connection | None = None
        self._ledger_file_guard: BinaryIO | None = None
        self._ledger_parent_descriptor: int | None = None
        self._ledger_file_identity: tuple[int, int] | None = None
        self._ledger_parent_identity: tuple[int, int] | None = None
        self._result_root_guards: list[_PinnedPrivateDirectory] = []
        self.ledger_generation = ""
        self._ledger_lock: BinaryIO | None = self._acquire_ledger_lock()
        try:
            self.ledger_generation = self._initialize_ledger()
            shared_result_root, shared_result_guard = self._prepare_result_root(
                self.state_path.parent / ".bluefire-runner-results"
            )
            self._result_root_guards.append(shared_result_guard)
            namespace_path = runner_result_namespace_path(
                self.state_path,
                enrollment,
                ledger_generation=self.ledger_generation,
            )
            if namespace_path.parent != shared_result_root:
                raise AuthenticatedRunnerTransportError(
                    "Runner recovery result namespace is invalid."
                )
            self.result_namespace_id = namespace_path.name
            self.result_root, result_root_guard = self._prepare_result_root(namespace_path)
            self._result_root_guards.append(result_root_guard)
            self._reconcile_interrupted_tasks()
            self._prune_ledger()
            self._listener = self._bind_listener()
        except Exception:
            self._release_ledger_lock()
            raise

    @property
    def server_address(self) -> tuple[str, int]:
        address = self._listener.getsockname()
        return str(address[0]), int(address[1])

    def _bind_listener(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(64)
            listener.settimeout(0.2)
        except OSError:
            listener.close()
            raise RunnerConnectionError("Runner loopback listener could not be started.") from None
        return listener

    @staticmethod
    def _prepare_state_path(value: str | Path) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
            raise AuthenticatedRunnerTransportError("Runner recovery path is invalid.")
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            if _is_link_or_reparse(candidate.parent) or not candidate.parent.is_dir():
                raise RunnerTrustError("unsafe state parent")
            parent = candidate.parent.resolve(strict=True)
            _owner_private(parent, directory=True)
            state_path = parent / candidate.name
            if _is_link_or_reparse(state_path):
                raise RunnerTrustError("unsafe state file")
            if state_path.exists():
                status = state_path.stat()
                if not state_path.is_file() or status.st_nlink != 1:
                    raise RunnerTrustError("unsafe state file")
                _owner_private(state_path, directory=False)
            return state_path
        except (OSError, RunnerTrustError):
            raise AuthenticatedRunnerTransportError(
                "Runner recovery path is unavailable or unsafe."
            ) from None

    @staticmethod
    def _prepare_result_root(value: Path) -> tuple[Path, _PinnedPrivateDirectory]:
        guard: _PinnedPrivateDirectory | None = None
        try:
            if _is_link_or_reparse(value):
                raise RunnerTrustError("unsafe result directory")
            value.mkdir(mode=0o700, parents=False, exist_ok=True)
            metadata = value.stat(follow_symlinks=False)
            root = value.resolve(strict=True)
            if _is_link_or_reparse(root) or not stat.S_ISDIR(metadata.st_mode) or not root.is_dir():
                raise RunnerTrustError("unsafe result directory")
            guard = _PinnedPrivateDirectory(
                root,
                expected_identity=(metadata.st_dev, metadata.st_ino),
            )
            guard.__enter__()
            return root, guard
        except (OSError, RunnerTrustError, RunnerTransportError):
            if guard is not None:
                guard.close()
            raise AuthenticatedRunnerTransportError(
                "Runner recovery result storage is unavailable or unsafe."
            ) from None

    def _durable_result_path(self, task_id: str) -> Path:
        _token(task_id)
        identity = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:40]
        return self.result_root / f"{identity}.json"

    def durable_result_path(self, task_id: str) -> Path:
        """Return the exact private recovery path in this ledger/enrollment namespace."""

        return self._durable_result_path(task_id)

    def _validated_inventory(
        self, enrollment: RunnerEnrollment
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        # The guard verifies before the inventory subprocess is allowed to
        # launch and again after it returns. On Windows it also holds an open
        # handle that denies write/delete sharing for the whole call.
        with self._verified_runner_binary_guard():
            inventory = self.runner.inventory()
        canonical = canonical_runner_inventory(inventory)
        if canonical.get("runner_id") != enrollment.runner_id:
            raise _RequestRefusal("authentication_failed")
        return inventory, canonical

    @staticmethod
    def _validated_execute_documents(
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        inventory: Mapping[str, Any],
    ) -> None:
        profile_id = str(request["profile_id"])
        if profile.get("profile_id") != profile_id:
            raise _RequestRefusal("profile_not_allowed")
        if (
            profile.get("runner_id") != enrollment.runner_id
            or manifest.get("runner_id") != enrollment.runner_id
            or manifest.get("runner_profile_id") != profile_id
        ):
            raise _RequestRefusal("profile_not_allowed")
        if (
            inventory.get("runner_id") != enrollment.runner_id
            or manifest.get("platform") != profile.get("platform")
            or inventory.get("platform") != profile.get("platform")
            or manifest.get("policy_digest") != profile.get("policy_digest")
            or not isinstance(profile.get("policy_digest"), str)
            or _DIGEST.fullmatch(str(profile.get("policy_digest"))) is None
        ):
            raise _RequestRefusal("request_invalid")

    def _validated_execute_result(
        self,
        result: Mapping[str, Any],
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> dict[str, Any]:
        checked = dict(result)
        expected = {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest.get("request_id"),
            "run_id": manifest.get("run_id"),
            "step_id": manifest.get("step_id"),
            "behavior_id": manifest.get("behavior_id"),
            "action_id": manifest.get("action_id"),
            "runner_id": manifest.get("runner_id"),
            "runner_profile_id": manifest.get("runner_profile_id"),
            "platform": manifest.get("platform"),
            "request_hash": manifest.get("request_hash"),
            "policy_digest": profile.get("policy_digest"),
        }
        if set(checked) != _RESULT_FIELDS or any(
            checked.get(field) != value for field, value in expected.items()
        ):
            raise RunnerTransportError("runner result identity does not match the request")
        if checked.get("status") not in _RESULT_STATUSES:
            raise RunnerTransportError("runner result status is invalid")
        for field in ("started_at", "finished_at"):
            value = checked.get(field)
            if not isinstance(value, str) or not 1 <= len(value) <= 128:
                raise RunnerTransportError("runner result timestamp is invalid")
        for field in ("stdout", "stderr"):
            value = checked.get(field)
            if (
                not isinstance(value, dict)
                or set(value) != {"text", "total_bytes", "truncated"}
                or not isinstance(value.get("text"), str)
                or isinstance(value.get("total_bytes"), bool)
                or not isinstance(value.get("total_bytes"), int)
                or not 0 <= int(value["total_bytes"]) <= self.max_frame_bytes
                or not isinstance(value.get("truncated"), bool)
            ):
                raise RunnerTransportError("runner result output metadata is invalid")
        receipts = checked.get("receipt_ids")
        if (
            not isinstance(receipts, list)
            or len(receipts) > _MAX_RECOVERY_RECEIPTS
            or len(receipts) != len(set(receipts))
            or any(
                not isinstance(item, str) or _HEX_DIGEST.fullmatch(item) is None
                for item in receipts
            )
        ):
            raise RunnerTransportError("runner result receipt identity is invalid")
        evidence = checked.get("evidence")
        limitations = checked.get("limitations")
        if (
            not isinstance(evidence, list)
            or len(evidence) > 4096
            or not isinstance(limitations, list)
            or len(limitations) > 4096
            or any(not isinstance(item, str) or len(item) > 4096 for item in limitations)
            or (checked.get("cleanup") is not None and not isinstance(checked["cleanup"], dict))
            or (checked.get("error") is not None and not isinstance(checked["error"], dict))
        ):
            raise RunnerTransportError("runner result schema is invalid")
        try:
            encoded = canonical_json_bytes({"result": checked})
        except (RecursionError, TypeError, ValueError):
            raise RunnerTransportError("runner result contains unsupported JSON") from None
        if len(encoded) > self.max_frame_bytes:
            raise RunnerTransportError("runner result exceeds the transport limit")
        return checked

    def _read_private_result_entry(
        self,
        path: Path,
    ) -> tuple[bytes, tuple[int, int]] | None:
        if path.parent != self.result_root:
            raise RunnerTransportError("runner durable result path is invalid")
        try:
            with _PinnedPrivateDirectory(self.result_root) as pinned:
                return pinned.read_with_identity(
                    path.name,
                    maximum=self.max_frame_bytes,
                )
        except FileNotFoundError:
            return None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable or unsafe") from None

    def _read_private_result_payload(self, path: Path) -> bytes | None:
        entry = self._read_private_result_entry(path)
        return None if entry is None else entry[0]

    def _read_private_result(self, path: Path) -> dict[str, Any] | None:
        payload = self._read_private_result_payload(path)
        return None if payload is None else _decode_durable_json_object(payload)

    def _persist_durable_result(self, task_id: str, result: Mapping[str, Any]) -> None:
        destination = self._durable_result_path(task_id)
        encoded = canonical_json_bytes(dict(result))
        if len(encoded) > self.max_frame_bytes:
            raise RunnerTransportError("runner durable result exceeds the transport limit")
        try:
            with _PinnedPrivateDirectory(self.result_root) as pinned:
                try:
                    pinned.create(
                        destination.name,
                        encoded,
                        maximum=self.max_frame_bytes,
                    )
                except FileExistsError:
                    existing = pinned.read(
                        destination.name,
                        maximum=self.max_frame_bytes,
                    )
                    if existing != encoded:
                        raise OSError("durable result identity conflicts") from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result could not be committed") from None

    def _promote_pending_result(
        self,
        pending: Path,
        destination: Path,
        *,
        expected: bytes,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            if pending.parent != self.result_root or destination.parent != self.result_root:
                raise OSError("durable result directories differ")
            with _PinnedPrivateDirectory(self.result_root) as pinned:
                pinned.promote(
                    pending.name,
                    destination.name,
                    maximum=self.max_frame_bytes,
                    expected=expected,
                    expected_identity=expected_identity,
                )
        except FileExistsError:
            return
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner pending result could not be reconciled") from None

    def _recover_durable_result(
        self,
        task_id: str,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        destination = self._durable_result_path(task_id)
        final = self._read_private_result(destination)
        if final is not None:
            return self._validated_execute_result(final, manifest, profile)
        pending = runner_pending_result_path(destination, task_id)
        pending_entry = self._read_private_result_entry(pending)
        if pending_entry is None:
            return None
        pending_payload, pending_identity = pending_entry
        candidate = _decode_durable_json_object(pending_payload)
        self._validated_execute_result(candidate, manifest, profile)
        self._promote_pending_result(
            pending,
            destination,
            expected=pending_payload,
            expected_identity=pending_identity,
        )
        committed = self._read_private_result(destination)
        if committed is None:
            raise RunnerTransportError("runner pending result was not committed")
        return self._validated_execute_result(committed, manifest, profile)

    @staticmethod
    def _read_bounded_artifact(path: Path, maximum: int) -> dict[str, Any]:
        try:
            if _is_link_or_reparse(path):
                raise OSError("linked artifact")
            before = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > maximum
            ):
                raise OSError("unsafe artifact")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise OSError("artifact identity changed")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read(maximum + 1)
            finally:
                os.close(descriptor)
            after = path.stat(follow_symlinks=False)
            if (
                _is_link_or_reparse(path)
                or after.st_nlink != 1
                or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns)
                or len(payload) > maximum
            ):
                raise OSError("artifact identity changed")
            return _decode_durable_json_object(payload)
        except OSError:
            raise RunnerTransportError(
                "runner recovery artifact is unavailable or unsafe"
            ) from None

    @staticmethod
    def _receipt_roots(profile: Mapping[str, Any]) -> tuple[Path, Path, str] | None:
        raw_root = profile.get("sandbox_root")
        if not isinstance(raw_root, str):
            return None
        requested = Path(raw_root).expanduser()
        if not requested.is_absolute():
            return None
        try:
            if _is_link_or_reparse(requested):
                return None
            root = requested.resolve(strict=True)
            if (
                not root.is_dir()
                or _is_link_or_reparse(root)
                or os.path.normcase(os.path.normpath(str(requested)))
                != os.path.normcase(os.path.normpath(str(root)))
            ):
                return None
            state_root = root / ".bluefire"
            receipts = state_root / "receipts"
            commits = state_root / "receipt-commits"
            if not receipts.exists() or not commits.exists():
                return None
            for directory in (state_root, receipts, commits):
                metadata = directory.stat(follow_symlinks=False)
                if _is_link_or_reparse(directory) or not stat.S_ISDIR(metadata.st_mode):
                    return None
            workspace_id = hashlib.sha256(str(root).replace("\\", "/").encode("utf-8")).hexdigest()
            return receipts, commits, workspace_id
        except OSError:
            return None

    @staticmethod
    def _receipt_limits(
        manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> tuple[int, int] | None:
        manifest_limits = manifest.get("limits")
        profile_limits = profile.get("limits")
        if not isinstance(manifest_limits, Mapping) or not isinstance(profile_limits, Mapping):
            return None
        max_files = manifest_limits.get("max_files")
        max_bytes = manifest_limits.get("max_artifact_bytes")
        profile_files = profile_limits.get("max_files")
        profile_bytes = profile_limits.get("max_artifact_bytes")
        if (
            isinstance(max_files, bool)
            or not isinstance(max_files, int)
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or isinstance(profile_files, bool)
            or not isinstance(profile_files, int)
            or isinstance(profile_bytes, bool)
            or not isinstance(profile_bytes, int)
            or not 1 <= max_files <= min(profile_files, _MAX_RECOVERY_RECEIPTS)
            or not 1 <= max_bytes <= profile_bytes
            or max_bytes > 1024 * 1024 * 1024 * 1024
        ):
            return None
        return max_files, max_bytes

    @staticmethod
    def _valid_owned_paths(paths: Any, *, max_files: int, max_bytes: int) -> bool:
        if not isinstance(paths, list) or not paths or len(paths) > min(max_files * 8, 4096):
            return False
        seen: set[str] = set()
        files: list[str] = []
        directories: list[str] = []
        total_size = 0
        for raw in paths:
            if not isinstance(raw, dict) or set(raw) != _OWNED_PATH_FIELDS:
                return False
            relative = _safe_relative_receipt_path(raw.get("relative_path"))
            kind = raw.get("kind")
            if relative is None or relative in seen or kind not in {"file", "directory"}:
                return False
            seen.add(relative)
            if kind == "file":
                digest = raw.get("sha256")
                size = raw.get("size")
                if (
                    not isinstance(digest, str)
                    or _HEX_DIGEST.fullmatch(digest) is None
                    or isinstance(size, bool)
                    or not isinstance(size, int)
                    or not 0 <= size <= max_bytes
                ):
                    return False
                files.append(relative)
                total_size += size
            else:
                if raw.get("sha256") is not None or raw.get("size") is not None:
                    return False
                directories.append(relative)
        if not files or len(files) > max_files or total_size > max_files * max_bytes:
            return False
        return all(
            any(file.startswith(directory + "/") for file in files) for directory in directories
        )

    def _validated_receipt_id(
        self,
        receipt_id: str,
        receipt_path: Path,
        commit_path: Path,
        *,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        workspace_id: str,
        max_files: int,
        max_bytes: int,
    ) -> str | None:
        try:
            receipt = self._read_bounded_artifact(receipt_path, _MAX_RECEIPT_BYTES)
            commit = self._read_bounded_artifact(commit_path, _MAX_RECEIPT_BYTES)
        except RunnerTransportError:
            return None
        if (
            set(receipt) != _RECEIPT_FIELDS
            or receipt.get("schema_version") != "bluefire.receipt/v1"
            or receipt.get("receipt_id") != receipt_id
            or receipt.get("request_hash") != manifest.get("request_hash")
            or receipt.get("action_id") != manifest.get("action_id")
            or receipt.get("runner_profile_id") != profile.get("profile_id")
            or receipt.get("workspace_id") != workspace_id
            or not isinstance(receipt.get("created_at"), str)
            or not 1 <= len(str(receipt.get("created_at"))) <= 128
            or not self._valid_owned_paths(
                receipt.get("paths"), max_files=max_files, max_bytes=max_bytes
            )
        ):
            return None
        identity = {
            "schema_version": "bluefire.receipt/v1",
            "request_hash": receipt["request_hash"],
            "action_id": receipt["action_id"],
            "runner_profile_id": receipt["runner_profile_id"],
            "workspace_id": receipt["workspace_id"],
            "created_at": receipt["created_at"],
            "paths": receipt["paths"],
        }
        if hashlib.sha256(canonical_json_bytes(identity)).hexdigest() != receipt_id:
            return None
        if (
            set(commit) != _RECEIPT_COMMIT_FIELDS
            or commit.get("schema_version") != "bluefire.receipt-commit/v1"
            or commit.get("receipt_id") != receipt_id
            or commit.get("runner_profile_id") != profile.get("profile_id")
            or commit.get("workspace_id") != workspace_id
            or not isinstance(commit.get("committed_at"), str)
            or not 1 <= len(str(commit.get("committed_at"))) <= 128
        ):
            return None
        return receipt_id

    def _discover_recovery_receipts(
        self, manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> list[str]:
        roots = self._receipt_roots(profile)
        limits = self._receipt_limits(manifest, profile)
        if roots is None or limits is None:
            return []
        receipts, commits, workspace_id = roots
        max_files, max_bytes = limits
        names: list[str] = []
        try:
            with os.scandir(receipts) as entries:
                for index, entry in enumerate(entries):
                    if index >= _MAX_RECOVERY_RECEIPTS * 4:
                        return []
                    name = entry.name
                    if (
                        len(name) == 69
                        and name.endswith(".json")
                        and _HEX_DIGEST.fullmatch(name[:-5]) is not None
                    ):
                        names.append(name[:-5])
                        if len(names) > _MAX_RECOVERY_RECEIPTS:
                            return []
        except OSError:
            return []
        valid: list[str] = []
        for receipt_id in sorted(set(names)):
            checked = self._validated_receipt_id(
                receipt_id,
                receipts / f"{receipt_id}.json",
                commits / f"{receipt_id}.json",
                manifest=manifest,
                profile=profile,
                workspace_id=workspace_id,
                max_files=max_files,
                max_bytes=max_bytes,
            )
            if checked is not None:
                valid.append(checked)
        return valid

    def _acquire_ledger_lock(self) -> BinaryIO:
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        key = os.path.normcase(str(self.state_path))
        with _LEDGER_PROCESS_LOCK:
            if key in _LOCKED_LEDGERS:
                raise AuthenticatedRunnerTransportError(
                    "Runner recovery ledger is already owned by a live server."
                )
            _LOCKED_LEDGERS.add(key)
        handle: BinaryIO | None = None
        try:
            if _is_link_or_reparse(lock_path):
                raise OSError("unsafe ledger lock")
            if lock_path.exists() and (not lock_path.is_file() or lock_path.stat().st_nlink != 1):
                raise OSError("unsafe ledger lock")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            handle = os.fdopen(descriptor, "r+b", buffering=0)
            if os.fstat(descriptor).st_nlink != 1 or _is_link_or_reparse(lock_path):
                raise OSError("unsafe ledger lock")
            if os.fstat(descriptor).st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
            _owner_private(lock_path, directory=False)
            self._ledger_lock_key = key
            return handle
        except (OSError, RunnerTrustError):
            if handle is not None:
                handle.close()
            with _LEDGER_PROCESS_LOCK:
                _LOCKED_LEDGERS.discard(key)
            raise AuthenticatedRunnerTransportError(
                "Runner recovery ledger is already owned or unavailable."
            ) from None

    def _release_ledger_lock(self) -> None:
        with self._ledger_release_lock:
            self._close_database_resources()
            while self._result_root_guards:
                self._result_root_guards.pop().close()
            handle = self._ledger_lock
            if handle is None:
                return
            self._ledger_lock = None
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(  # type: ignore[attr-defined]
                        handle.fileno(),
                        fcntl.LOCK_UN,  # type: ignore[attr-defined]
                    )
            except OSError:
                pass
            finally:
                handle.close()
                with _LEDGER_PROCESS_LOCK:
                    _LOCKED_LEDGERS.discard(self._ledger_lock_key)

    def _bind_runner_binary(self) -> tuple[Path | None, str | None]:
        raw_binary = getattr(self.runner, "runner_binary", None)
        if raw_binary is None:
            return None, None
        if not isinstance(raw_binary, Path):
            raise AuthenticatedRunnerTransportError("Runner binary identity is invalid.")
        try:
            binary = raw_binary.resolve(strict=True)
            if not binary.is_file() or _is_link_or_reparse(binary):
                raise OSError("unsafe runner binary")
            digest = file_hash(binary)
        except OSError:
            raise AuthenticatedRunnerTransportError(
                "Runner binary identity could not be verified."
            ) from None
        construction_digest = getattr(self.runner, "runner_binary_digest", None)
        if construction_digest is not None and (
            not isinstance(construction_digest, str)
            or _DIGEST.fullmatch(construction_digest) is None
            or not hmac.compare_digest(construction_digest, digest)
        ):
            raise AuthenticatedRunnerTransportError(
                "Runner binary identity changed after runner construction."
            )
        return binary, digest

    def _verified_runner_binary_digest(self) -> str | None:
        if self._runner_binary is None:
            return None
        try:
            current = getattr(self.runner, "runner_binary", None)
            if (
                not isinstance(current, Path)
                or current.resolve(strict=True) != self._runner_binary
                or self._runner_binary.resolve(strict=True) != self._runner_binary
                or not self._runner_binary.is_file()
                or _is_link_or_reparse(self._runner_binary)
            ):
                raise OSError("runner binary changed")
            digest = file_hash(self._runner_binary)
        except OSError:
            raise RunnerTransportError("runner binary identity could not be verified") from None
        if not hmac.compare_digest(digest, str(self._runner_binary_digest)):
            raise RunnerTransportError("runner binary identity changed")
        return digest

    @staticmethod
    def _open_handle_digest(handle: BinaryIO) -> str:
        digest = hashlib.sha256()
        handle.seek(0)
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
        handle.seek(0)
        return f"sha256:{digest.hexdigest()}"

    @contextmanager
    def _windows_runner_binary_handle(self) -> Iterator[BinaryIO]:
        """Open the bound binary while denying Windows write/delete sharing."""

        if self._runner_binary is None:
            raise RunnerTransportError("runner binary identity could not be verified")
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(self._runner_binary),
                0x80000000,  # GENERIC_READ
                0x00000001,  # FILE_SHARE_READ: deliberately no write/delete sharing
                None,
                3,  # OPEN_EXISTING
                0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
                None,
            )
            invalid = wintypes.HANDLE(-1).value
            if handle == invalid:
                raise OSError(ctypes.get_last_error(), "CreateFileW failed")
            descriptor = msvcrt.open_osfhandle(
                int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            with os.fdopen(descriptor, "rb") as opened:
                yield cast(BinaryIO, opened)
        except OSError:
            raise RunnerTransportError("runner binary identity could not be verified") from None

    @contextmanager
    def _verified_runner_binary_guard(self) -> Iterator[str | None]:
        """Pin the approved binary identity around one inventory/effect call.

        POSIX path-based subprocess APIs do not let this transport hand the
        already-open descriptor to every RunnerTransport implementation. The
        before/after hashes therefore detect a replacement, but cannot undo an
        effect if a path is replaced in the narrow interval before exec.
        """

        if self._runner_binary is None:
            yield None
            return
        if os.name == "nt":
            with self._windows_runner_binary_handle() as handle:
                before = self._open_handle_digest(handle)
                if not hmac.compare_digest(before, str(self._runner_binary_digest)):
                    raise RunnerTransportError("runner binary identity changed")
                # Re-check the pathname while the guarded handle prevents the
                # underlying file from being written, renamed, or deleted.
                self._verified_runner_binary_digest()
                try:
                    yield before
                finally:
                    after = self._open_handle_digest(handle)
                    self._verified_runner_binary_digest()
                    if not hmac.compare_digest(before, after):
                        raise RunnerTransportError("runner binary identity changed")
            return
        posix_before = self._verified_runner_binary_digest()
        if posix_before is None:
            raise RunnerTransportError("runner binary identity could not be verified")
        try:
            yield posix_before
        finally:
            posix_after = self._verified_runner_binary_digest()
            if posix_after is None or not hmac.compare_digest(posix_before, posix_after):
                raise RunnerTransportError("runner binary identity changed")

    def _initialize_ledger(self) -> str:
        connection: sqlite3.Connection | None = None
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self._validate_initial_ledger_sidecars()
            self._pin_ledger_path()
            connection = sqlite3.connect(
                self.state_path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            _limit_sqlite_connection(connection)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(f"PRAGMA journal_size_limit = {self.max_ledger_bytes}")
            connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version not in {0, LEDGER_SCHEMA_VERSION}:
                    raise sqlite3.DatabaseError("unsupported ledger schema")
                if version == 0:
                    if _ledger_application_objects(connection):
                        raise sqlite3.DatabaseError("foreign objects in fresh ledger")
                    connection.execute(_TRANSPORT_TASKS_SQL)
                    connection.execute(_TRANSPORT_TASKS_NONCE_INDEX_SQL)
                    connection.execute(_LEDGER_METADATA_SQL)
                    connection.execute(
                        """
                        INSERT INTO runner_ledger_metadata
                            (singleton, schema_version, ledger_generation)
                        VALUES (1, ?, ?)
                        """,
                        (_LEDGER_METADATA_SCHEMA, secrets.token_hex(32)),
                    )
                    connection.execute(f"PRAGMA user_version = {LEDGER_SCHEMA_VERSION}")
                ledger_generation = _validated_ledger_generation(connection)
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                maximum_pages = (
                    self.max_ledger_bytes + _SQLITE_OVERHEAD_BYTES + page_size - 1
                ) // page_size
                if page_count > maximum_pages:
                    raise sqlite3.DatabaseError("ledger database exceeds its byte capacity")
                connection.execute(f"PRAGMA max_page_count = {maximum_pages}")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            self._database_connection = connection
            connection = None
            self.ledger_generation = ledger_generation
            self._assert_ledger_identity(validate_schema=True)
            return ledger_generation
        except (OSError, RunnerTrustError, RunnerTransportError, sqlite3.Error):
            if connection is not None:
                connection.close()
            self._close_database_resources()
            raise AuthenticatedRunnerTransportError(
                "Runner recovery ledger could not be initialized."
            ) from None

    def _validate_initial_ledger_sidecars(self) -> None:
        for suffix in _LEDGER_SIDECAR_SUFFIXES:
            path = self.state_path.with_name(self.state_path.name + suffix)
            if not path.exists():
                if _is_link_or_reparse(path):
                    raise OSError("linked recovery ledger sidecar")
                continue
            details = path.stat(follow_symlinks=False)
            if (
                _is_link_or_reparse(path)
                or not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_size > self.max_ledger_bytes + _SQLITE_OVERHEAD_BYTES
                or suffix in {"-wal", "-shm"}
            ):
                raise OSError("unsafe recovery ledger sidecar")

    def _pin_ledger_path(self) -> None:
        parent_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if os.name != "nt":
            self._ledger_parent_descriptor = os.open(self.state_path.parent, parent_flags)
            parent = os.fstat(self._ledger_parent_descriptor)
            if not stat.S_ISDIR(parent.st_mode):
                raise OSError("unsafe recovery ledger parent")
            getattr(os, "fchmod")(  # noqa: B009 - absent on Windows
                self._ledger_parent_descriptor, 0o700
            )
            descriptor = os.open(
                self.state_path.name,
                os.O_RDONLY
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._ledger_parent_descriptor,
            )
            self._ledger_file_guard = os.fdopen(descriptor, "rb", buffering=0)
        else:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(self.state_path),
                0x80000000,  # GENERIC_READ
                0x00000001 | 0x00000002,  # share read/write, deliberately no delete
                None,
                4,  # OPEN_ALWAYS
                0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
                None,
            )
            invalid = wintypes.HANDLE(-1).value
            if handle == invalid:
                raise OSError(ctypes.get_last_error(), "CreateFileW failed")
            try:
                descriptor = msvcrt.open_osfhandle(
                    int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
                )
            except BaseException:
                ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
                raise
            self._ledger_file_guard = os.fdopen(descriptor, "rb", buffering=0)

        if self._ledger_file_guard is None:
            raise OSError("recovery ledger guard unavailable")
        pinned = os.fstat(self._ledger_file_guard.fileno())
        parent = self.state_path.parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(pinned.st_mode)
            or pinned.st_nlink != 1
            or _is_link_or_reparse(self.state_path)
            or _is_link_or_reparse(self.state_path.parent)
            or not stat.S_ISDIR(parent.st_mode)
        ):
            raise OSError("unsafe recovery ledger identity")
        if os.name == "nt":
            _owner_private(self.state_path, directory=False)
        else:
            getattr(os, "fchmod")(  # noqa: B009 - absent on Windows
                self._ledger_file_guard.fileno(), 0o600
            )
        current = self.state_path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise OSError("recovery ledger identity changed")
        self._ledger_file_identity = pinned.st_dev, pinned.st_ino
        self._ledger_parent_identity = parent.st_dev, parent.st_ino

    def _assert_ledger_identity(self, *, validate_schema: bool) -> None:
        guard = self._ledger_file_guard
        connection = self._database_connection
        if (
            guard is None
            or connection is None
            or self._ledger_file_identity is None
            or self._ledger_parent_identity is None
        ):
            raise sqlite3.DatabaseError("recovery ledger is closed")
        pinned = os.fstat(guard.fileno())
        current = self.state_path.stat(follow_symlinks=False)
        parent = self.state_path.parent.stat(follow_symlinks=False)
        if (
            _is_link_or_reparse(self.state_path)
            or _is_link_or_reparse(self.state_path.parent)
            or not stat.S_ISREG(pinned.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or pinned.st_nlink != 1
            or current.st_nlink != 1
            or (pinned.st_dev, pinned.st_ino) != self._ledger_file_identity
            or (current.st_dev, current.st_ino) != self._ledger_file_identity
            or (parent.st_dev, parent.st_ino) != self._ledger_parent_identity
            or current.st_size > self.max_ledger_bytes + _SQLITE_OVERHEAD_BYTES
        ):
            raise sqlite3.DatabaseError("recovery ledger identity changed")
        for suffix in _LEDGER_SIDECAR_SUFFIXES:
            sidecar = self.state_path.with_name(self.state_path.name + suffix)
            if sidecar.exists() or _is_link_or_reparse(sidecar):
                raise sqlite3.DatabaseError("unexpected recovery ledger sidecar")
        if validate_schema:
            generation = _validated_ledger_generation(connection)
            if not hmac.compare_digest(generation, self.ledger_generation):
                raise sqlite3.DatabaseError("recovery ledger generation changed")

    @contextmanager
    def _database(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        del write  # The lifetime connection is always safely write-capable.
        with self._database_lock:
            connection = self._database_connection
            if connection is None:
                raise sqlite3.DatabaseError("recovery ledger is closed")
            self._assert_ledger_identity(validate_schema=True)
            try:
                yield connection
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                self._assert_ledger_identity(validate_schema=True)

    def _close_database_resources(self) -> None:
        with self._database_lock:
            connection = self._database_connection
            self._database_connection = None
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                    connection.close()
                except sqlite3.Error:
                    pass
            guard = self._ledger_file_guard
            self._ledger_file_guard = None
            if guard is not None:
                guard.close()
            parent_descriptor = self._ledger_parent_descriptor
            self._ledger_parent_descriptor = None
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    @staticmethod
    def _stored_execute_payload(row: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        raw = row.get("execute_payload_json")
        if not isinstance(raw, bytes):
            raise RunnerTransportError("runner execution manifest is unavailable")
        decoded = _decode_json_object(raw)
        if set(decoded) != {"manifest", "profile"}:
            raise RunnerTransportError("runner execution manifest is invalid")
        manifest = decoded.get("manifest")
        profile = decoded.get("profile")
        if not isinstance(manifest, dict) or not isinstance(profile, dict):
            raise RunnerTransportError("runner execution manifest is invalid")
        if (
            content_hash(decoded) != row.get("request_hash")
            or row.get("task_id") != _execute_task_id(str(row.get("request_hash")))
            or profile.get("profile_id") != row.get("profile_id")
            or profile.get("runner_id") != row.get("runner_id")
            or manifest.get("runner_id") != row.get("runner_id")
            or manifest.get("runner_profile_id") != row.get("profile_id")
            or manifest.get("platform") != profile.get("platform")
            or manifest.get("policy_digest") != profile.get("policy_digest")
        ):
            raise RunnerTransportError("runner execution manifest identity is invalid")
        return manifest, profile

    def _execute_row(self, task_id: str) -> sqlite3.Row | None:
        with self._database() as connection:
            return cast(
                sqlite3.Row | None,
                connection.execute(
                    """
                    SELECT task_id, operation, profile_id, request_hash, runner_id,
                           state, execute_payload_json, result_json,
                           recovery_receipts_json, cleanup_required, effect_dispatched,
                           error_code, executor_instance, cancellation_requested
                    FROM transport_tasks WHERE task_id = ?
                    """,
                    (task_id,),
                ).fetchone(),
            )

    def _set_reconciled_completion(self, task_id: str, result: Mapping[str, Any]) -> None:
        encoded = canonical_json_bytes({"result": dict(result)})
        if len(encoded) > self.max_frame_bytes:
            raise RunnerTransportError("runner result exceeds the transport limit")
        with self._database(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE transport_tasks
                SET state = 'completed', result_json = ?, recovery_receipts_json = NULL,
                    cleanup_required = 0, error_code = NULL, updated_at = ?
                WHERE task_id = ? AND operation = 'execute' AND effect_dispatched = 1
                """,
                (encoded, time.time_ns(), task_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise sqlite3.DatabaseError("execute task changed during reconciliation")
            connection.commit()

    def _set_execute_recovery_state(self, task_id: str, *, receipt_ids: list[str]) -> str:
        state = "recovery_required" if receipt_ids else "indeterminate"
        error_code = "recovery_required" if receipt_ids else "outcome_indeterminate"
        encoded = canonical_json_bytes({"receipt_ids": receipt_ids}) if receipt_ids else None
        with self._database(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE transport_tasks
                SET state = ?, result_json = NULL, recovery_receipts_json = ?,
                    cleanup_required = ?, error_code = ?, updated_at = ?
                WHERE task_id = ? AND operation = 'execute' AND effect_dispatched = 1
                """,
                (
                    state,
                    encoded,
                    int(bool(receipt_ids)),
                    error_code,
                    time.time_ns(),
                    task_id,
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise sqlite3.DatabaseError("execute task changed during reconciliation")
            connection.commit()
        return state

    def _cleanup_reconciled_watchdog(self, task_id: str) -> None:
        destination = self._durable_result_path(task_id)
        try:
            cleanup_runner_watchdog_terminal_state(destination, task_id)
        except RunnerTransportError:
            control_root = runner_watchdog_control_root(destination, task_id)
            try:
                with _PinnedPrivateDirectory(control_root):
                    pass
            except FileNotFoundError:
                return
            raise

    def _read_watchdog_status(self, task_id: str) -> dict[str, Any] | None:
        destination = self._durable_result_path(task_id)
        control_root = runner_watchdog_control_root(destination, task_id)
        try:
            with _PinnedPrivateDirectory(control_root) as pinned:
                entries = pinned.names()
                if entries != ("status.json",):
                    return None
                payload = pinned.read("status.json", maximum=4096)
            status = _decode_durable_json_object(payload)
        except FileNotFoundError:
            return None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner watchdog status is unavailable or unsafe") from None
        if not isinstance(status, dict):
            raise RunnerTransportError("runner watchdog status is invalid")
        common = {
            "schema_version",
            "task_id",
            "state",
            "error_code",
            "watchdog_pid",
        }
        state = status.get("state")
        error_code = status.get("error_code")
        watchdog_pid = status.get("watchdog_pid")
        if (
            status.get("schema_version") != "bluefire.runner-watchdog-status.v1"
            or status.get("task_id") != task_id
            or state not in {"succeeded", "failed", "cancelled"}
            or isinstance(watchdog_pid, bool)
            or not isinstance(watchdog_pid, int)
            or not 1 <= watchdog_pid <= 2**31 - 1
        ):
            raise RunnerTransportError("runner watchdog status is invalid")
        if state == "succeeded":
            result_digest = status.get("result_digest")
            if (
                set(status) != common | {"result_digest"}
                or error_code is not None
                or not isinstance(result_digest, str)
                or _DIGEST.fullmatch(result_digest) is None
            ):
                raise RunnerTransportError("runner watchdog status is invalid")
        elif (
            set(status) != common
            or not isinstance(error_code, str)
            or not 1 <= len(error_code) <= 64
            or (state == "cancelled" and error_code != "cancelled")
            or (state == "failed" and error_code == "cancelled")
        ):
            raise RunnerTransportError("runner watchdog status is invalid")
        return status

    def _set_confirmed_execute_terminal(self, task_id: str, *, state: str, error_code: str) -> None:
        if state not in {"cancelled", "timed_out"}:
            raise sqlite3.DatabaseError("invalid confirmed execute terminal state")
        with self._database(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE transport_tasks
                SET state = ?, result_json = NULL, recovery_receipts_json = NULL,
                    cleanup_required = 0, cancellation_requested = CASE
                        WHEN ? = 'cancelled' THEN 1 ELSE cancellation_requested END,
                    error_code = ?, updated_at = ?
                WHERE task_id = ? AND operation = 'execute' AND effect_dispatched = 1
                  AND state IN ('running', 'indeterminate', 'recovery_required')
                """,
                (state, state, error_code, time.time_ns(), task_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise sqlite3.DatabaseError("execute terminal state changed")
            connection.commit()

    def _reconcile_execute_task(self, task_id: str) -> dict[str, Any]:
        row = self._execute_row(task_id)
        if row is None or row["operation"] != "execute":
            return {"state": "not_found", "result": None, "receipt_ids": []}
        if not bool(row["effect_dispatched"]):
            with self._database(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if bool(row["cancellation_requested"]):
                    state = "cancelled"
                    connection.execute(
                        """
                        UPDATE transport_tasks
                        SET state = 'cancelled', error_code = 'task_cancelled', updated_at = ?
                        WHERE task_id = ? AND operation = 'execute' AND effect_dispatched = 0
                          AND state = 'running'
                        """,
                        (time.time_ns(), task_id),
                    )
                else:
                    state = "failed"
                    connection.execute(
                        """
                        UPDATE transport_tasks
                        SET state = 'failed', error_code = 'runner_failure', updated_at = ?
                        WHERE task_id = ? AND operation = 'execute' AND effect_dispatched = 0
                          AND state = 'running'
                        """,
                        (time.time_ns(), task_id),
                    )
                connection.commit()
            return {"state": state, "result": None, "receipt_ids": []}
        try:
            manifest, profile = self._stored_execute_payload(dict(row))
        except (RunnerTransportError, RunnerAuthenticationError):
            self._set_execute_recovery_state(task_id, receipt_ids=[])
            return {"state": "indeterminate", "result": None, "receipt_ids": []}
        invalid_watchdog_status = False
        try:
            watchdog_status = self._read_watchdog_status(task_id)
        except RunnerTransportError:
            watchdog_status = None
            invalid_watchdog_status = True
        try:
            result = self._recover_durable_result(task_id, manifest, profile)
        except RunnerTransportError:
            result = None
        if result is not None and not invalid_watchdog_status:
            if watchdog_status is not None:
                destination = self._durable_result_path(task_id)
                if watchdog_status.get("state") != "succeeded" or watchdog_status.get(
                    "result_digest"
                ) != file_hash(destination):
                    result = None
        if result is not None:
            self._set_reconciled_completion(task_id, result)
            try:
                self._cleanup_reconciled_watchdog(task_id)
            except RunnerTransportError:
                # The exact durable outcome is authoritative. Auxiliary
                # watchdog hygiene must never erase it or masquerade as action
                # cleanup; a later host lifecycle pass may retry removal.
                pass
            return {"state": "completed", "result": result, "receipt_ids": []}
        receipts = self._discover_recovery_receipts(manifest, profile)
        terminal_state: str | None = None
        terminal_error: str | None = None
        if watchdog_status is not None:
            if (
                watchdog_status.get("state") == "cancelled"
                and watchdog_status.get("error_code") == "cancelled"
            ):
                terminal_state, terminal_error = "cancelled", "task_cancelled"
            elif (
                watchdog_status.get("state") == "failed"
                and watchdog_status.get("error_code") == "timed_out"
            ):
                terminal_state, terminal_error = "timed_out", "task_timed_out"
        if terminal_state is not None and terminal_error is not None and not receipts:
            self._set_confirmed_execute_terminal(
                task_id, state=terminal_state, error_code=terminal_error
            )
            try:
                self._cleanup_reconciled_watchdog(task_id)
            except RunnerTransportError:
                pass
            return {"state": terminal_state, "result": None, "receipt_ids": []}
        state = self._set_execute_recovery_state(task_id, receipt_ids=receipts)
        if watchdog_status is not None:
            try:
                self._cleanup_reconciled_watchdog(task_id)
            except RunnerTransportError:
                pass
        return {"state": state, "result": None, "receipt_ids": receipts}

    def _reconcile_interrupted_tasks(self) -> None:
        with self._database() as connection:
            rows = connection.execute(
                """
                SELECT task_id, operation, effect_dispatched
                FROM transport_tasks WHERE state = 'running'
                ORDER BY created_at ASC, task_id ASC
                """
            ).fetchall()
        for row in rows:
            task_id = str(row["task_id"])
            if row["operation"] == "execute" and bool(row["effect_dispatched"]):
                self._reconcile_execute_task(task_id)
                continue
            with self._database(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE transport_tasks
                    SET state = 'failed', error_code = 'runner_failure', updated_at = ?
                    WHERE task_id = ? AND state = 'running'
                    """,
                    (time.time_ns(), task_id),
                )
                connection.commit()

    def _enter_effect_dispatch(self, task_id: str, cancellation: threading.Event | None) -> bool:
        """Atomically register cancellation delivery and cross the effect edge."""

        with self._task_cancellations_lock:
            if cancellation is not None:
                if task_id in self._task_cancellations:
                    raise sqlite3.DatabaseError("execute cancellation identity is already active")
                self._task_cancellations[task_id] = cancellation
            try:
                with self._database(write=True) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        """
                        SELECT state, effect_dispatched, cancellation_requested
                        FROM transport_tasks
                        WHERE task_id = ? AND operation = 'execute'
                        """,
                        (task_id,),
                    ).fetchone()
                    if (
                        row is not None
                        and row["state"] == "cancelled"
                        and not bool(row["effect_dispatched"])
                        and bool(row["cancellation_requested"])
                    ):
                        connection.commit()
                        if cancellation is not None:
                            cancellation.set()
                        return False
                    if row is None or row["state"] != "running" or bool(row["effect_dispatched"]):
                        connection.rollback()
                        raise sqlite3.DatabaseError("execute task could not enter dispatch")
                    if bool(row["cancellation_requested"]):
                        connection.execute(
                            """
                            UPDATE transport_tasks
                            SET state = 'cancelled', result_json = NULL,
                                recovery_receipts_json = NULL, cleanup_required = 0,
                                error_code = 'task_cancelled', updated_at = ?
                            WHERE task_id = ? AND state = 'running'
                              AND effect_dispatched = 0 AND cancellation_requested = 1
                            """,
                            (time.time_ns(), task_id),
                        )
                        connection.commit()
                        if cancellation is not None:
                            cancellation.set()
                        return False
                    cursor = connection.execute(
                        """
                        UPDATE transport_tasks
                        SET effect_dispatched = 1, updated_at = ?
                        WHERE task_id = ? AND operation = 'execute' AND state = 'running'
                          AND effect_dispatched = 0 AND cancellation_requested = 0
                        """,
                        (time.time_ns(), task_id),
                    )
                    if cursor.rowcount != 1:
                        connection.rollback()
                        raise sqlite3.DatabaseError("execute task could not enter dispatch")
                    connection.commit()
                    return True
            except BaseException:
                if (
                    cancellation is not None
                    and self._task_cancellations.get(task_id) is cancellation
                ):
                    del self._task_cancellations[task_id]
                raise

    def _mark_effect_dispatched(self, task_id: str) -> None:
        if not self._enter_effect_dispatch(task_id, None):
            raise _RequestRefusal("task_cancelled")

    def _mark_task_cancelled(self, task_id: str) -> None:
        with self._database(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE transport_tasks
                SET state = 'cancelled', result_json = NULL,
                    recovery_receipts_json = NULL, cleanup_required = 0,
                    cancellation_requested = 1, error_code = 'task_cancelled',
                    updated_at = ?
                WHERE task_id = ? AND operation = 'execute' AND state = 'running'
                  AND effect_dispatched = 1
                """,
                (time.time_ns(), task_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise sqlite3.DatabaseError("execute cancellation state changed")
            connection.commit()

    def start(self) -> AuthenticatedRunnerServer:
        if self._serve_thread is not None:
            raise AuthenticatedRunnerTransportError("Runner server is already started.")
        self._serve_thread = threading.Thread(
            target=self.serve_forever,
            name="bluefire-runner-transport",
            daemon=True,
        )
        self._serve_thread.start()
        return self

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if not self._ingress_slots.acquire(blocking=False):
                connection.close()
                continue
            worker = threading.Thread(
                target=self._serve_connection,
                args=(connection,),
                name="bluefire-runner-request",
                daemon=True,
            )
            with self._workers_lock:
                self._workers.add(worker)
            try:
                worker.start()
            except RuntimeError:
                with self._workers_lock:
                    self._workers.discard(worker)
                self._ingress_slots.release()
                connection.close()

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        if self._serve_thread is not None and self._serve_thread is not threading.current_thread():
            self._serve_thread.join(timeout=2.0)
        with self._workers_lock:
            workers = tuple(self._workers)
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=self.socket_timeout_seconds + 1.0)
        with self._workers_lock:
            release_lock = not self._workers
        if release_lock:
            self._release_ledger_lock()

    close = shutdown

    def __enter__(self) -> AuthenticatedRunnerServer:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.shutdown()

    def _serve_connection(self, raw_connection: socket.socket) -> None:
        current = threading.current_thread()
        managed_shutdown = False
        checked: Mapping[str, Any] = {}
        ingress_held = True
        operation_slot: threading.BoundedSemaphore | None = None
        try:
            ingress_deadline = time.monotonic() + self.socket_timeout_seconds
            raw_connection.settimeout(self.socket_timeout_seconds)
            with closing(raw_connection):
                with self._server_context.wrap_socket(
                    raw_connection, server_side=True, do_handshake_on_connect=False
                ) as connection:
                    connection.settimeout(max(ingress_deadline - time.monotonic(), 0.001))
                    connection.do_handshake()
                    enrollment = self._active_enrollment()
                    peer_fingerprint = _verify_peer(
                        connection,
                        expected_fingerprint=str(enrollment.metadata["client_fingerprint"]),
                        expected_common_name=enrollment.client_id,
                    )
                    request = _receive_frame(
                        connection, self.max_frame_bytes, deadline=ingress_deadline
                    )
                    connection.settimeout(self.socket_timeout_seconds)
                    try:
                        checked = self._validated_request(request, enrollment)
                    except _RequestRefusal as exc:
                        response = self._error_response(request, enrollment, exc.code)
                    else:
                        # Authentication/framing has its own bounded ingress
                        # pool. Long Executes move to a smaller pool, leaving
                        # authenticated control capacity available.
                        self._ingress_slots.release()
                        ingress_held = False
                        operation_slot = (
                            self._execute_slots
                            if checked["operation"] == "execute"
                            else self._control_slots
                        )
                        with self._dispatch_state_lock:
                            draining = (
                                checked["operation"] == "execute" and not self._accepting_execute
                            )
                        if draining:
                            operation_slot = None
                            response = self._error_response(request, enrollment, "runner_draining")
                        elif not operation_slot.acquire(blocking=False):
                            operation_slot = None
                            response = self._error_response(request, enrollment, "runner_busy")
                        else:
                            try:
                                response = self._dispatch(checked, enrollment, peer_fingerprint)
                            except _RequestRefusal as exc:
                                response = self._error_response(request, enrollment, exc.code)
                    managed_shutdown = (
                        checked.get("operation") == "shutdown" and response.get("ok") is True
                    )
                    _send_frame(connection, response, self.max_frame_bytes)
                    if managed_shutdown:
                        # The authenticated acknowledgement is queued on the TLS
                        # connection before the listener begins shutting down.
                        self._stop.set()
                        self._listener.close()
        except (
            AuthenticatedRunnerTransportError,
            OSError,
            RunnerTrustError,
            ssl.SSLError,
            sqlite3.Error,
        ):
            # Deliberately silent: no path, certificate, or runner diagnostics cross the wire.
            return
        finally:
            with self._workers_lock:
                self._workers.discard(current)
                release_lock = self._stop.is_set() and not self._workers
            if operation_slot is not None:
                operation_slot.release()
            if ingress_held:
                self._ingress_slots.release()
            if release_lock:
                self._release_ledger_lock()

    def _active_enrollment(self) -> RunnerEnrollment:
        return self._enrollments.active()

    def _validated_request(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment
    ) -> dict[str, Any]:
        if set(request) != _REQUEST_FIELDS:
            raise RunnerAuthenticationError("Runner request has an unsupported shape.")
        if (
            request.get("schema_version") != TRANSPORT_SCHEMA_VERSION
            or request.get("kind") != "request"
        ):
            raise RunnerAuthenticationError("Runner request schema is unsupported.")
        operation = request.get("operation")
        if not isinstance(operation, str) or operation not in _OPERATIONS:
            raise RunnerAuthenticationError("Runner request operation is unsupported.")
        runner_id = _token(request.get("runner_id"))
        client_id = _token(request.get("client_id"))
        profile_id = _token(request.get("profile_id"))
        task_id = _token(request.get("task_id"))
        nonce = request.get("nonce")
        request_hash = request.get("request_hash")
        authentication = request.get("authentication")
        payload = request.get("payload")
        if (
            not isinstance(nonce, str)
            or _NONCE.fullmatch(nonce) is None
            or not isinstance(request_hash, str)
            or _DIGEST.fullmatch(request_hash) is None
            or not isinstance(authentication, str)
            or _DIGEST.fullmatch(authentication) is None
            or not isinstance(payload, dict)
        ):
            raise RunnerAuthenticationError("Runner request authentication fields are invalid.")
        if runner_id != enrollment.runner_id or client_id != enrollment.client_id:
            raise _RequestRefusal("authentication_failed")
        if content_hash(payload) != request_hash:
            raise _RequestRefusal("authentication_failed")
        unsigned = {key: request[key] for key in request if key != "authentication"}
        expected = _request_mac(enrollment, unsigned)
        if not hmac.compare_digest(authentication, expected):
            raise _RequestRefusal("authentication_failed")
        if operation == "execute" and task_id != _execute_task_id(request_hash):
            raise _RequestRefusal("request_invalid")
        if profile_id not in enrollment.allowed_profile_ids:
            raise _RequestRefusal("profile_not_allowed")
        return dict(request)

    def _dispatch(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        peer_fingerprint: str,
    ) -> Mapping[str, Any]:
        binding = _enrollment_binding(enrollment, peer_fingerprint)
        operation = str(request["operation"])
        already_completed = False
        shutdown_request: dict[str, Any] | None = None
        if operation == "shutdown":
            shutdown_request = self._require_payload(request, frozenset({"server_instance_id"}))
            if shutdown_request.get("server_instance_id") != self.instance_id:
                raise _RequestRefusal("task_identity_mismatch")
        try:
            self._begin_request(request, binding)
        except sqlite3.Error:
            raise _RequestRefusal("ledger_unavailable") from None
        try:
            if operation == "health":
                self._require_payload(request, frozenset())
                # Inventory is deliberately probed so health cannot claim a ready
                # transport while the execution boundary is unavailable.
                runner_binary_digest = self._verified_runner_binary_digest()
                _inventory, canonical_inventory = self._validated_inventory(enrollment)
                payload: Mapping[str, Any] = {
                    "schema_version": "bluefire.runner-health.v1",
                    "status": "ready",
                    "runner_id": enrollment.runner_id,
                    "client_id": enrollment.client_id,
                    "server_instance_id": self.instance_id,
                    "profile_id": request["profile_id"],
                    "transport": "mutual-tls-loopback",
                    "tls": "TLSv1.3",
                    "server_fingerprint": enrollment.metadata["server_fingerprint"],
                    "client_fingerprint": enrollment.metadata["client_fingerprint"],
                    "authenticated_peer_fingerprint": peer_fingerprint,
                    "enrollment_generation": binding["enrollment_generation"],
                    "runner_binary_digest": runner_binary_digest,
                    "inventory_digest": content_hash(canonical_inventory),
                    "ledger": self._ledger_capacity_status(),
                }
            elif operation == "inventory":
                self._require_payload(request, frozenset())
                self._verified_runner_binary_digest()
                inventory, _canonical = self._validated_inventory(enrollment)
                payload = {"inventory": dict(inventory)}
            elif operation == "execute":
                supplied = self._require_payload(request, frozenset({"manifest", "profile"}))
                manifest = supplied["manifest"]
                profile = supplied["profile"]
                if not isinstance(manifest, dict) or not isinstance(profile, dict):
                    raise _RequestRefusal("request_invalid")
                payload, already_completed = self._execute_payload(
                    request, enrollment, manifest, profile
                )
            elif operation == "recover":
                supplied = self._require_payload(
                    request, frozenset({"original_task_id", "original_request_hash"})
                )
                payload = self._recover_payload(request, supplied, binding)
            elif operation == "cancel":
                supplied = self._require_payload(
                    request, frozenset({"original_task_id", "original_request_hash"})
                )
                payload = self._cancel_payload(request, supplied, binding)
            else:
                if shutdown_request is None:
                    raise _RequestRefusal("request_invalid")
                with self._database() as connection:
                    active_execute = int(
                        connection.execute(
                            """
                            SELECT COUNT(*) FROM transport_tasks
                            WHERE operation = 'execute' AND state = 'running'
                            """
                        ).fetchone()[0]
                    )
                if active_execute:
                    raise _RequestRefusal("active_tasks")
                payload = {
                    "schema_version": "bluefire.runner-lifecycle.v1",
                    "status": "shutdown_acknowledged",
                    "runner_id": enrollment.runner_id,
                    "client_id": enrollment.client_id,
                    "server_instance_id": self.instance_id,
                }
            if not already_completed:
                try:
                    self._complete_request(str(request["task_id"]), payload)
                except BaseException:
                    if operation != "execute":
                        raise
                    payload, already_completed = self._post_dispatch_resolution(
                        str(request["task_id"])
                    )
                if operation == "execute":
                    try:
                        self._cleanup_reconciled_watchdog(str(request["task_id"]))
                    except RunnerTransportError:
                        pass
            return self._success_response(request, enrollment, payload)
        except _RequestRefusal as exc:
            self._fail_request(str(request["task_id"]), exc.code)
            raise
        except sqlite3.Error:
            self._fail_request(str(request["task_id"]), "ledger_unavailable")
            raise _RequestRefusal("ledger_unavailable") from None
        except Exception:
            self._fail_request(str(request["task_id"]), "runner_failure")
            raise _RequestRefusal("runner_failure") from None

    def _recheck_effect_trust(
        self, request: Mapping[str, Any], connection_enrollment: RunnerEnrollment
    ) -> None:
        try:
            current = self._active_enrollment()
        except RunnerAuthenticationError:
            raise _RequestRefusal("authentication_failed") from None
        for field in (
            "runner_id",
            "client_id",
            "ca_fingerprint",
            "server_fingerprint",
            "client_fingerprint",
        ):
            if current.metadata[field] != connection_enrollment.metadata[field]:
                raise _RequestRefusal("authentication_failed")
        if request["profile_id"] not in current.allowed_profile_ids:
            raise _RequestRefusal("profile_not_allowed")

    @staticmethod
    def _require_payload(request: Mapping[str, Any], fields: frozenset[str]) -> dict[str, Any]:
        payload = request.get("payload")
        if not isinstance(payload, dict) or set(payload) != fields:
            raise _RequestRefusal("request_invalid")
        return payload

    def _post_dispatch_resolution(self, task_id: str) -> tuple[Mapping[str, Any], bool]:
        try:
            outcome = self._reconcile_execute_task(task_id)
        except BaseException:
            self._fail_request(task_id, "outcome_indeterminate")
            raise _RequestRefusal("outcome_indeterminate") from None
        if outcome["state"] == "completed" and isinstance(outcome.get("result"), dict):
            return {"result": dict(outcome["result"])}, True
        code = {
            "recovery_required": "recovery_required",
            "cancelled": "task_cancelled",
            "timed_out": "task_timed_out",
        }.get(str(outcome["state"]), "outcome_indeterminate")
        raise _RequestRefusal(code)

    def _execute_payload(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], bool]:
        _inventory, canonical_inventory = self._validated_inventory(enrollment)
        self._validated_execute_documents(
            request, enrollment, manifest, profile, canonical_inventory
        )

        task_id = str(request["task_id"])
        self._recheck_effect_trust(request, enrollment)
        existing = self._recover_durable_result(task_id, manifest, profile)
        if existing is not None:
            # A safely archived ledger row may be reconstructed from the exact
            # immutable result. Mark the historical effect edge so a failed
            # ledger completion is itself reconciled without replay.
            self._mark_effect_dispatched(task_id)
            return {"result": existing}, False
        raw_execute_task = getattr(self.runner, "execute_task", None)
        execute_task = cast(Callable[..., Mapping[str, Any]], raw_execute_task)
        task_aware = callable(raw_execute_task)
        cancellation = threading.Event()
        try:
            try:
                # Inventory was verified on both sides of its own launch. Pin
                # and verify once more across the actual effect launch. The
                # trust recheck and cancellation registration happen before the
                # atomic ledger effect edge while this guard is held.
                with self._verified_runner_binary_guard():
                    self._recheck_effect_trust(request, enrollment)
                    entered = self._enter_effect_dispatch(
                        task_id, cancellation if task_aware else None
                    )
                    if not entered:
                        raise _RequestRefusal("task_cancelled")
                    if task_aware:
                        result = execute_task(
                            manifest,
                            profile,
                            task_id=task_id,
                            cancel_event=cancellation,
                            durable_result_path=self._durable_result_path(task_id),
                        )
                    else:
                        result = self.runner.execute(manifest, profile)
                if not isinstance(result, Mapping):
                    raise RunnerTransportError("runner result is not an object")
                checked = self._validated_execute_result(result, manifest, profile)
                durable = self._recover_durable_result(task_id, manifest, profile)
                if durable is None:
                    self._persist_durable_result(task_id, checked)
                elif canonical_json_bytes(durable) != canonical_json_bytes(checked):
                    raise RunnerTransportError("runner durable result identity conflicts")
            except _RequestRefusal:
                raise
            except RunnerTaskTimedOut:
                try:
                    receipts = self._discover_recovery_receipts(manifest, profile)
                    if receipts:
                        self._set_execute_recovery_state(task_id, receipt_ids=receipts)
                        raise _RequestRefusal("recovery_required")
                    self._set_confirmed_execute_terminal(
                        task_id, state="timed_out", error_code="task_timed_out"
                    )
                    try:
                        self._cleanup_reconciled_watchdog(task_id)
                    except RunnerTransportError:
                        pass
                except _RequestRefusal:
                    raise
                except BaseException:
                    return self._post_dispatch_resolution(task_id)
                raise _RequestRefusal("task_timed_out") from None
            except RunnerTaskCancelled:
                try:
                    receipts = self._discover_recovery_receipts(manifest, profile)
                    if receipts:
                        self._set_execute_recovery_state(task_id, receipt_ids=receipts)
                        raise _RequestRefusal("recovery_required")
                    self._mark_task_cancelled(task_id)
                    try:
                        self._cleanup_reconciled_watchdog(task_id)
                    except RunnerTransportError:
                        pass
                except _RequestRefusal:
                    raise
                except BaseException:
                    return self._post_dispatch_resolution(task_id)
                raise _RequestRefusal("task_cancelled") from None
            except BaseException:
                return self._post_dispatch_resolution(task_id)
        finally:
            if task_aware:
                with self._task_cancellations_lock:
                    if self._task_cancellations.get(task_id) is cancellation:
                        del self._task_cancellations[task_id]
        return {"result": checked}, False

    def _ledger_byte_usage(self, connection: sqlite3.Connection) -> tuple[int, int]:
        row = connection.execute(
            """
            SELECT
                COALESCE(SUM(
                    COALESCE(length(execute_payload_json), 0)
                    + COALESCE(length(result_json), 0)
                    + COALESCE(length(recovery_receipts_json), 0)
                ), 0) AS blob_bytes,
                COALESCE(SUM(
                    COALESCE(length(execute_payload_json), 0)
                    + COALESCE(length(result_json), 0)
                    + COALESCE(length(recovery_receipts_json), 0)
                    + CASE
                        WHEN operation = 'execute' AND result_json IS NULL
                             AND state IN ('running', 'indeterminate', 'recovery_required')
                        THEN ? + MAX(? - COALESCE(length(recovery_receipts_json), 0), 0)
                        WHEN operation != 'execute' AND state = 'running'
                        THEN ?
                        ELSE 0
                    END
                ), 0) AS committed_bytes
            FROM transport_tasks
            """,
            (
                self.max_frame_bytes,
                _EXECUTE_RECOVERY_RESERVE_BYTES,
                self.max_frame_bytes,
            ),
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("ledger byte usage is unavailable")
        return int(row["blob_bytes"]), int(row["committed_bytes"])

    @staticmethod
    def _reclaim_oldest_terminal_control(connection: sqlite3.Connection) -> bool:
        cursor = connection.execute(
            """
            DELETE FROM transport_tasks WHERE task_id = (
                SELECT task_id FROM transport_tasks
                WHERE operation != 'execute'
                  AND state NOT IN ('running', 'indeterminate', 'recovery_required')
                ORDER BY updated_at ASC, task_id ASC
                LIMIT 1
            )
            """
        )
        return cursor.rowcount == 1

    def _begin_request(self, request: Mapping[str, Any], binding: Mapping[str, str]) -> None:
        # Polling rows are disposable, but Execute identities are replay guards.
        # Prune only the former, then fail closed at a hard global bound.
        self._prune_ledger()
        now = time.time_ns()
        execute_payload = (
            canonical_json_bytes(request["payload"]) if request["operation"] == "execute" else None
        )
        with self._dispatch_state_lock, self._database(write=True) as connection:
            if request["operation"] == "execute" and not self._accepting_execute:
                raise _RequestRefusal("runner_draining")
            connection.execute("BEGIN IMMEDIATE")
            nonce_row = connection.execute(
                "SELECT 1 FROM transport_tasks WHERE nonce = ?", (request["nonce"],)
            ).fetchone()
            if nonce_row is not None:
                connection.rollback()
                raise _RequestRefusal("replay_detected")
            task_row = connection.execute(
                """
                SELECT operation, profile_id, request_hash, runner_id, client_id,
                       peer_fingerprint, ca_fingerprint, server_fingerprint,
                       client_fingerprint, enrollment_generation
                FROM transport_tasks WHERE task_id = ?
                """,
                (request["task_id"],),
            ).fetchone()
            if task_row is not None:
                connection.rollback()
                same = (
                    task_row["operation"] == request["operation"]
                    and task_row["profile_id"] == request["profile_id"]
                    and task_row["request_hash"] == request["request_hash"]
                    and all(task_row[field] == value for field, value in binding.items())
                )
                raise _RequestRefusal("duplicate_request" if same else "task_conflict")
            row_count = int(
                connection.execute("SELECT COUNT(*) FROM transport_tasks").fetchone()[0]
            )
            execute_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM transport_tasks WHERE operation = 'execute'"
                ).fetchone()[0]
            )
            execute_capacity = self.max_ledger_rows - self.control_reserve_rows
            execute_payload_size = len(execute_payload) if execute_payload is not None else 0
            request_reservation = self.max_frame_bytes + execute_payload_size
            if request["operation"] == "execute":
                request_reservation += _EXECUTE_RECOVERY_RESERVE_BYTES
                byte_capacity = self.max_ledger_bytes - self.control_reserve_bytes
            else:
                byte_capacity = self.max_ledger_bytes
            _blob_bytes, committed_bytes = self._ledger_byte_usage(connection)
            while (
                row_count >= self.max_ledger_rows
                or committed_bytes + request_reservation > byte_capacity
            ) and self._reclaim_oldest_terminal_control(connection):
                row_count -= 1
                _blob_bytes, committed_bytes = self._ledger_byte_usage(connection)
            if (
                row_count >= self.max_ledger_rows
                or committed_bytes + request_reservation > byte_capacity
                or (request["operation"] == "execute" and execute_count >= execute_capacity)
            ):
                connection.rollback()
                raise _RequestRefusal("ledger_capacity")
            connection.execute(
                """
                INSERT INTO transport_tasks (
                    task_id, operation, profile_id, request_hash,
                    runner_id, client_id, peer_fingerprint, ca_fingerprint,
                    server_fingerprint, client_fingerprint, enrollment_generation,
                    nonce, state,
                    execute_payload_json, result_json, recovery_receipts_json,
                    cleanup_required, effect_dispatched, error_code, executor_instance,
                    cancellation_requested, created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'running', ?, NULL, NULL, 0, 0, NULL, ?, 0, ?, ?
                )
                """,
                (
                    request["task_id"],
                    request["operation"],
                    request["profile_id"],
                    request["request_hash"],
                    binding["runner_id"],
                    binding["client_id"],
                    binding["peer_fingerprint"],
                    binding["ca_fingerprint"],
                    binding["server_fingerprint"],
                    binding["client_fingerprint"],
                    binding["enrollment_generation"],
                    request["nonce"],
                    execute_payload,
                    self.instance_id,
                    now,
                    now,
                ),
            )
            if request["operation"] == "shutdown":
                # The admission gate and durable shutdown record change under
                # the same lock as Execute admission, so no new effect can pass
                # a check-then-begin race once draining starts.
                self._accepting_execute = False
            connection.commit()

    def _ledger_capacity_status(self) -> Mapping[str, Any]:
        with self._database() as connection:
            rows = int(connection.execute("SELECT COUNT(*) FROM transport_tasks").fetchone()[0])
            execute_rows = int(
                connection.execute(
                    "SELECT COUNT(*) FROM transport_tasks WHERE operation = 'execute'"
                ).fetchone()[0]
            )
            blob_bytes, committed_bytes = self._ledger_byte_usage(connection)
        execute_capacity = self.max_ledger_rows - self.control_reserve_rows
        execute_byte_capacity = self.max_ledger_bytes - self.control_reserve_bytes
        with self._dispatch_state_lock:
            admission_open = self._accepting_execute
        return {
            "rows": rows,
            "capacity": self.max_ledger_rows,
            "execute_rows": execute_rows,
            "execute_capacity": execute_capacity,
            "control_reserve": self.control_reserve_rows,
            "blob_bytes": blob_bytes,
            "committed_bytes": committed_bytes,
            "byte_capacity": self.max_ledger_bytes,
            "execute_byte_capacity": execute_byte_capacity,
            "control_reserve_bytes": self.control_reserve_bytes,
            "accepting_execute": (
                admission_open
                and rows < self.max_ledger_rows
                and execute_rows < execute_capacity
                and committed_bytes + self.max_frame_bytes + _EXECUTE_RECOVERY_RESERVE_BYTES
                <= execute_byte_capacity
            ),
        }

    def _complete_request(self, task_id: str, payload: Mapping[str, Any]) -> None:
        encoded = canonical_json_bytes(dict(payload))
        if len(encoded) > self.max_frame_bytes:
            raise RunnerTransportError("runner result exceeds the transport limit")
        with self._database(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE transport_tasks
                SET state = 'completed', result_json = ?, recovery_receipts_json = NULL,
                    cleanup_required = 0, error_code = NULL, updated_at = ?
                WHERE task_id = ? AND state = 'running'
                """,
                (encoded, time.time_ns(), task_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise sqlite3.DatabaseError("task state changed before completion")
            connection.commit()
        self._prune_ledger()

    def _fail_request(self, task_id: str, code: str) -> None:
        try:
            with self._database(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE transport_tasks
                    SET state = CASE
                            WHEN operation = 'execute' AND effect_dispatched = 1
                            THEN 'indeterminate'
                            ELSE 'failed'
                        END,
                        error_code = CASE
                            WHEN operation = 'execute' AND effect_dispatched = 1
                            THEN 'outcome_indeterminate'
                            ELSE ?
                        END,
                        updated_at = ?
                    WHERE task_id = ? AND state = 'running'
                    """,
                    (code, time.time_ns(), task_id),
                )
                connection.commit()
        except sqlite3.Error:
            return
        self._prune_ledger()

    def _prune_ledger(self) -> None:
        cutoff = time.time_ns() - self.terminal_retention_ns
        polling_limit = min(self.max_terminal_rows, self.control_reserve_rows - 2)
        try:
            with self._database(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    DELETE FROM transport_tasks
                    WHERE operation != 'execute'
                      AND state NOT IN ('running', 'indeterminate', 'recovery_required')
                      AND updated_at < ?
                    """,
                    (cutoff,),
                )
                count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM transport_tasks
                        WHERE operation != 'execute'
                          AND state NOT IN ('running', 'indeterminate', 'recovery_required')
                        """
                    ).fetchone()[0]
                )
                excess = max(count - polling_limit, 0)
                if excess:
                    connection.execute(
                        """
                        DELETE FROM transport_tasks WHERE task_id IN (
                            SELECT task_id FROM transport_tasks
                            WHERE operation != 'execute'
                              AND state NOT IN ('running', 'indeterminate', 'recovery_required')
                            ORDER BY updated_at ASC, task_id ASC
                            LIMIT ?
                        )
                        """,
                        (excess,),
                    )
                connection.commit()
        except sqlite3.Error:
            return

    def _recover_payload(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        binding: Mapping[str, str],
    ) -> Mapping[str, Any]:
        original_task = _token(payload.get("original_task_id"))
        original_hash = payload.get("original_request_hash")
        if not isinstance(original_hash, str) or _DIGEST.fullmatch(original_hash) is None:
            raise _RequestRefusal("request_invalid")

        def fetch() -> sqlite3.Row | None:
            with self._database() as connection:
                return cast(
                    sqlite3.Row | None,
                    connection.execute(
                        """
                        SELECT task_id, operation, profile_id, request_hash, state,
                               execute_payload_json, result_json, recovery_receipts_json,
                               cleanup_required, effect_dispatched, error_code,
                               executor_instance, cancellation_requested,
                               runner_id, client_id, peer_fingerprint, ca_fingerprint,
                               server_fingerprint, client_fingerprint, enrollment_generation
                        FROM transport_tasks WHERE task_id = ?
                        """,
                        (original_task,),
                    ).fetchone(),
                )

        row = fetch()
        if row is None:
            return {
                "original_task_id": original_task,
                "original_request_hash": original_hash,
                "state": "not_found",
                "result": None,
                "error_code": None,
                "cancellation_requested": False,
                "receipt_ids": [],
                "cleanup_required": False,
            }
        if (
            row["operation"] != "execute"
            or row["profile_id"] != request["profile_id"]
            or row["request_hash"] != original_hash
            or any(row[field] != value for field, value in binding.items())
        ):
            raise _RequestRefusal("task_identity_mismatch")
        state = str(row["state"])
        needs_reconciliation = state in {"indeterminate", "recovery_required"} or (
            state == "running" and row["executor_instance"] != self.instance_id
        )
        if state == "completed":
            try:
                manifest, profile = self._stored_execute_payload(dict(row))
                raw_stored = row["result_json"]
                if not isinstance(raw_stored, bytes):
                    raise RunnerTransportError("completed task has no result")
                stored = _decode_json_object(raw_stored)
                candidate = stored.get("result")
                if not isinstance(candidate, dict) or set(stored) != {"result"}:
                    raise RunnerTransportError("completed task result is invalid")
                self._validated_execute_result(candidate, manifest, profile)
            except (RunnerTransportError, RunnerAuthenticationError):
                needs_reconciliation = True
        if needs_reconciliation:
            self._reconcile_execute_task(original_task)
            refreshed = fetch()
            if refreshed is None:
                raise sqlite3.DatabaseError("execute task disappeared during recovery")
            row = refreshed
            state = str(row["state"])
        result: Any = None
        if state == "completed":
            raw_result = row["result_json"]
            if not isinstance(raw_result, bytes):
                raise sqlite3.DatabaseError("completed task has no result")
            stored = _decode_json_object(raw_result)
            result = stored.get("result")
            if not isinstance(result, dict) or set(stored) != {"result"}:
                raise sqlite3.DatabaseError("completed task result is invalid")
            manifest, profile = self._stored_execute_payload(dict(row))
            result = self._validated_execute_result(result, manifest, profile)
        receipt_ids: list[str] = []
        raw_receipts = row["recovery_receipts_json"]
        if state == "recovery_required":
            if not isinstance(raw_receipts, bytes):
                raise sqlite3.DatabaseError("recovery receipt state is invalid")
            stored_receipts = _decode_json_object(raw_receipts)
            candidate_ids = stored_receipts.get("receipt_ids")
            if (
                set(stored_receipts) != {"receipt_ids"}
                or not isinstance(candidate_ids, list)
                or any(
                    not isinstance(item, str) or _HEX_DIGEST.fullmatch(item) is None
                    for item in candidate_ids
                )
            ):
                raise sqlite3.DatabaseError("recovery receipt state is invalid")
            receipt_ids = list(candidate_ids)
        return {
            "original_task_id": original_task,
            "original_request_hash": original_hash,
            "state": state,
            "result": result,
            "error_code": (
                row["error_code"]
                if state
                in {"failed", "indeterminate", "recovery_required", "cancelled", "timed_out"}
                else None
            ),
            "cancellation_requested": bool(row["cancellation_requested"]),
            "receipt_ids": receipt_ids,
            "cleanup_required": bool(row["cleanup_required"]),
        }

    def _cancel_payload(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        binding: Mapping[str, str],
    ) -> Mapping[str, Any]:
        original_task = _token(payload.get("original_task_id"))
        original_hash = payload.get("original_request_hash")
        if not isinstance(original_hash, str) or _DIGEST.fullmatch(original_hash) is None:
            raise _RequestRefusal("request_invalid")
        cancellation: threading.Event | None = None
        effect_dispatched = False
        with self._task_cancellations_lock:
            with self._database(write=True) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT operation, profile_id, request_hash, state, effect_dispatched,
                           runner_id, client_id, peer_fingerprint, ca_fingerprint,
                           server_fingerprint, client_fingerprint, enrollment_generation
                    FROM transport_tasks WHERE task_id = ?
                    """,
                    (original_task,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    raise _RequestRefusal("task_not_found")
                if (
                    row["operation"] != "execute"
                    or row["profile_id"] != request["profile_id"]
                    or row["request_hash"] != original_hash
                    or any(row[field] != value for field, value in binding.items())
                ):
                    connection.rollback()
                    raise _RequestRefusal("task_identity_mismatch")
                state = str(row["state"])
                effect_dispatched = bool(row["effect_dispatched"])
                requested = state == "running" or (state == "indeterminate" and effect_dispatched)
                if requested and not effect_dispatched:
                    # This transaction and the effect-dispatch gate share the
                    # cancellation lock. No process can be launched after this
                    # confirmed pre-effect terminal transition.
                    cursor = connection.execute(
                        """
                        UPDATE transport_tasks
                        SET state = 'cancelled', cancellation_requested = 1,
                            error_code = 'task_cancelled', updated_at = ?
                        WHERE task_id = ? AND state = 'running' AND effect_dispatched = 0
                        """,
                        (time.time_ns(), original_task),
                    )
                    if cursor.rowcount != 1:
                        connection.rollback()
                        raise sqlite3.DatabaseError("execute cancellation state changed")
                    state = "cancelled"
                elif requested:
                    connection.execute(
                        """
                        UPDATE transport_tasks SET cancellation_requested = 1, updated_at = ?
                        WHERE task_id = ? AND state IN ('running', 'indeterminate')
                          AND effect_dispatched = 1
                        """,
                        (time.time_ns(), original_task),
                    )
                    cancellation = self._task_cancellations.get(original_task)
                connection.commit()
            if requested and cancellation is not None:
                cancellation.set()

        durable_signal = False
        if requested and effect_dispatched and cancellation is None:
            try:
                request_runner_task_cancel(self._durable_result_path(original_task), original_task)
                durable_signal = True
            except RunnerTransportError:
                # Generic in-process transports have no watchdog marker. Their
                # recorded intent remains truthful but is not terminal proof.
                durable_signal = False
        if requested and (cancellation is not None or durable_signal):
            deadline = time.monotonic() + self.cancel_confirmation_seconds
            while time.monotonic() < deadline:
                if durable_signal:
                    try:
                        status = self._read_watchdog_status(original_task)
                    except RunnerTransportError:
                        status = None
                    if status is not None:
                        self._reconcile_execute_task(original_task)
                with self._database() as connection:
                    current = connection.execute(
                        """
                        SELECT state, cancellation_requested
                        FROM transport_tasks WHERE task_id = ?
                        """,
                        (original_task,),
                    ).fetchone()
                if current is None:
                    raise sqlite3.DatabaseError("execute task disappeared during cancellation")
                state = str(current["state"])
                if state not in {"running", "indeterminate"}:
                    requested = bool(current["cancellation_requested"])
                    break
                time.sleep(0.01)
        if durable_signal:
            try:
                status = self._read_watchdog_status(original_task)
            except RunnerTransportError:
                status = None
            if status is not None:
                self._reconcile_execute_task(original_task)
        with self._database() as connection:
            current = connection.execute(
                """
                SELECT state, cancellation_requested
                FROM transport_tasks WHERE task_id = ?
                """,
                (original_task,),
            ).fetchone()
        if current is None:
            raise sqlite3.DatabaseError("execute task disappeared during cancellation")
        state = str(current["state"])
        requested = bool(current["cancellation_requested"])
        cancelled = state == "cancelled"
        return {
            "original_task_id": original_task,
            "original_request_hash": original_hash,
            "state": (
                "cancellation_requested"
                if state in {"running", "indeterminate"} and requested
                else state
            ),
            "cancellation_requested": requested,
            "cancelled": cancelled,
        }

    def _response_base(
        self,
        request: Mapping[str, Any],
        *,
        ok: bool,
        status: str,
        payload: Mapping[str, Any],
        error_code: str | None,
    ) -> dict[str, Any]:
        return {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "kind": "response",
            "operation": request.get("operation"),
            "runner_id": request.get("runner_id"),
            "client_id": request.get("client_id"),
            "profile_id": request.get("profile_id"),
            "task_id": request.get("task_id"),
            "nonce": request.get("nonce"),
            "request_hash": request.get("request_hash"),
            "ok": ok,
            "status": status,
            "payload": dict(payload),
            "response_hash": content_hash(dict(payload)),
            "error_code": error_code,
        }

    def _success_response(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return _sign_response(
            enrollment,
            self._response_base(
                request, ok=True, status="completed", payload=payload, error_code=None
            ),
        )

    def _error_response(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment, code: str
    ) -> Mapping[str, Any]:
        # A response can only be formed after the strict outer request shape was
        # decoded. Unknown fields are normalized to harmless placeholders rather
        # than echoed from local exception text.
        safe_request = {
            "operation": (
                request.get("operation") if request.get("operation") in _OPERATIONS else "health"
            ),
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "profile_id": (
                request.get("profile_id")
                if isinstance(request.get("profile_id"), str)
                else "invalid"
            ),
            "task_id": (
                request.get("task_id") if isinstance(request.get("task_id"), str) else "invalid"
            ),
            "nonce": request.get("nonce") if isinstance(request.get("nonce"), str) else "0" * 64,
            "request_hash": (
                request.get("request_hash")
                if isinstance(request.get("request_hash"), str)
                else content_hash({})
            ),
        }
        return _sign_response(
            enrollment,
            self._response_base(
                safe_request,
                ok=False,
                status="refused",
                payload={},
                error_code=code if code in _REMOTE_ERROR_MESSAGES else "request_invalid",
            ),
        )


class AuthenticatedRunnerClient:
    """RunnerTransport client with exact-task reconnect recovery semantics."""

    def __init__(
        self,
        enrollment_root: str | Path,
        *,
        profile_id: str,
        host: str = "127.0.0.1",
        port: int,
        socket_timeout_seconds: float = 10.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        recovery_attempts: int = 3,
        recovery_delay_seconds: float = 0.05,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        if (
            socket_timeout_seconds <= 0
            or max_frame_bytes < 4096
            or isinstance(recovery_attempts, bool)
            or not 1 <= recovery_attempts <= 20
            or not 0 <= recovery_delay_seconds <= 5
        ):
            raise AuthenticatedRunnerTransportError("Runner transport bounds are invalid.")
        self.enrollment_root = Path(enrollment_root).expanduser()
        self._enrollments = _EnrollmentCache(self.enrollment_root, secret_provider=secret_provider)
        self.profile_id = _token(profile_id)
        self.host = _loopback_host(host)
        self.port = _port(port, allow_zero=False)
        self.socket_timeout_seconds = float(socket_timeout_seconds)
        self.max_frame_bytes = int(max_frame_bytes)
        self.recovery_attempts = int(recovery_attempts)
        self.recovery_delay_seconds = float(recovery_delay_seconds)
        self._last_execution: tuple[str, str] | None = None

    @property
    def last_execution_identity(self) -> tuple[str, str] | None:
        return self._last_execution

    def health(self) -> Mapping[str, Any]:
        return self._call("health", {}, task_id=self._random_task("health"))

    def inventory(self) -> Mapping[str, Any]:
        payload = self._call("inventory", {}, task_id=self._random_task("inventory"))
        inventory = payload.get("inventory")
        if not isinstance(inventory, dict) or set(payload) != {"inventory"}:
            raise RunnerAuthenticationError("Runner inventory response is invalid.")
        canonical_runner_inventory(inventory)
        return inventory

    def transport_identity(self) -> Mapping[str, Any]:
        """Return the validated, secret-free identity of the authenticated host."""

        health = self.health()
        enrollment = self._active_enrollment()
        client_fingerprint = str(enrollment.metadata["client_fingerprint"])
        expected_generation = _enrollment_binding(enrollment, client_fingerprint)[
            "enrollment_generation"
        ]
        binary_digest = health.get("runner_binary_digest")
        inventory_digest = health.get("inventory_digest")
        expected = {
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
            "server_fingerprint": enrollment.metadata["server_fingerprint"],
            "client_fingerprint": client_fingerprint,
            "authenticated_peer_fingerprint": client_fingerprint,
            "enrollment_generation": expected_generation,
        }
        if (
            any(health.get(field) != value for field, value in expected.items())
            or not isinstance(inventory_digest, str)
            or _DIGEST.fullmatch(inventory_digest) is None
            or (
                binary_digest is not None
                and (not isinstance(binary_digest, str) or _DIGEST.fullmatch(binary_digest) is None)
            )
        ):
            raise RunnerAuthenticationError("Runner transport identity is invalid.")
        return {
            "schema_version": "bluefire.runner-transport-identity.v1",
            **expected,
            "runner_binary_digest": binary_digest,
            "inventory_digest": inventory_digest,
        }

    @staticmethod
    def execution_identity(
        manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> tuple[str, str]:
        payload = {"manifest": dict(manifest), "profile": dict(profile)}
        request_hash = content_hash(payload)
        return _execute_task_id(request_hash), request_hash

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        if profile.get("profile_id") != self.profile_id:
            raise RunnerAuthenticationError("Runner profile does not match the enrolled client.")
        manifest_profile = manifest.get("runner_profile_id")
        if manifest_profile is not None and manifest_profile != self.profile_id:
            raise RunnerAuthenticationError("Runner profile does not match the execution request.")
        payload = {"manifest": dict(manifest), "profile": dict(profile)}
        task_id, request_hash = self.execution_identity(manifest, profile)
        self._last_execution = (task_id, request_hash)
        try:
            response = self._call("execute", payload, task_id=task_id, request_hash=request_hash)
            return self._execution_result(response)
        except RunnerRemoteError as exc:
            if exc.code == "task_cancelled":
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped."
                ) from None
            if exc.code == "task_timed_out":
                raise RunnerTaskTimedOut(
                    "Runner task timed out after its process tree stopped."
                ) from None
            if exc.code != "duplicate_request":
                raise
            return self._recovered_execution(task_id, request_hash)
        except RunnerConnectionError:
            return self._recover_after_connection_loss(payload, task_id, request_hash)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Execute and cancel one exact remote task through separate mTLS requests.

        The durable path belongs to the local orchestration interface only. It
        is validated but never read, written, or sent to the runner host; the
        authenticated server derives its own ledger-bound result namespace.
        """

        expected_task_id, request_hash = self.execution_identity(manifest, profile)
        checked_task_id = _token(task_id)
        if not hmac.compare_digest(checked_task_id, expected_task_id):
            raise RunnerAuthenticationError("Runner execution identity is invalid.")
        if not callable(getattr(cancel_event, "is_set", None)) or not callable(
            getattr(cancel_event, "wait", None)
        ):
            raise RunnerAuthenticationError("Runner cancellation signal is invalid.")
        caller_path = Path(durable_result_path).expanduser()
        if not caller_path.is_absolute() or caller_path.name in {"", ".", ".."}:
            raise RunnerAuthenticationError("Runner durable result identity is invalid.")

        monitor_stop = threading.Event()
        monitor_payload: list[Mapping[str, Any]] = []
        monitor_error: list[BaseException] = []

        def monitor_cancellation() -> None:
            not_found_attempts = 0
            connection_attempts = 0
            while not monitor_stop.wait(0.01):
                if not cancel_event.is_set():
                    continue
                while not monitor_stop.is_set():
                    try:
                        monitor_payload.append(
                            self._cancel_for_execute_task(
                                checked_task_id,
                                request_hash,
                                abort_event=monitor_stop,
                            )
                        )
                        return
                    except RunnerRemoteError as exc:
                        if exc.code != "task_not_found" or not_found_attempts >= 20:
                            monitor_error.append(exc)
                            return
                        not_found_attempts += 1
                    except RunnerConnectionError as exc:
                        connection_attempts += 1
                        if connection_attempts >= self.recovery_attempts:
                            monitor_error.append(exc)
                            return
                    except BaseException as exc:
                        monitor_error.append(exc)
                        return
                    if monitor_stop.wait(max(self.recovery_delay_seconds, 0.01)):
                        return

        monitor = threading.Thread(
            target=monitor_cancellation,
            name=f"bluefire-runner-cancel-{checked_task_id[-12:]}",
            daemon=True,
        )
        monitor.start()
        execution_result: Mapping[str, Any] | None = None
        execution_error: BaseException | None = None
        try:
            execution_result = self.execute(manifest, profile)
        except BaseException as exc:
            execution_error = exc
        finally:
            monitor_stop.set()
            monitor.join(timeout=max(self.socket_timeout_seconds + 1.0, 2.0))
        if monitor.is_alive():
            raise RunnerConnectionError(
                "Runner cancellation request did not stop within its transport deadline."
            )
        if execution_result is not None:
            return execution_result
        assert execution_error is not None
        if not isinstance(execution_error, RunnerConnectionError):
            raise execution_error

        terminal = monitor_payload[-1] if monitor_payload else None
        if terminal is not None and terminal.get("state") == "cancelled":
            raise RunnerTaskCancelled("Runner task was cancelled after its process tree stopped.")
        if cancel_event.is_set() or terminal is not None or monitor_error:
            recovered_error: RunnerConnectionError | None = None
            for attempt in range(self.recovery_attempts):
                if attempt and self.recovery_delay_seconds:
                    time.sleep(self.recovery_delay_seconds)
                try:
                    recovered = self.recover(checked_task_id, request_hash)
                except RunnerConnectionError as exc:
                    recovered_error = exc
                    continue
                state = recovered.get("state")
                if state == "completed":
                    return self._recovered_result_payload(recovered)
                if state == "cancelled":
                    raise RunnerTaskCancelled(
                        "Runner task was cancelled after its process tree stopped."
                    )
                if state == "timed_out":
                    raise RunnerTaskTimedOut(
                        "Runner task timed out after its process tree stopped."
                    )
                if state == "recovery_required":
                    raise RunnerRemoteError("recovery_required")
                if state == "failed" and isinstance(recovered.get("error_code"), str):
                    raise RunnerRemoteError(str(recovered["error_code"]))
            if monitor_error and isinstance(monitor_error[-1], RunnerAuthenticationError):
                raise monitor_error[-1]
            if recovered_error is not None:
                raise recovered_error
        raise execution_error

    def recover(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        _token(task_id)
        if _DIGEST.fullmatch(request_hash) is None:
            raise RunnerAuthenticationError("Runner recovery identity is invalid.")
        return self._call(
            "recover",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("recover"),
        )

    def cancel(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        _token(task_id)
        if _DIGEST.fullmatch(request_hash) is None:
            raise RunnerAuthenticationError("Runner cancellation identity is invalid.")
        payload = self._call(
            "cancel",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("cancel"),
        )
        return self._validated_cancellation_payload(payload, task_id, request_hash)

    def _cancel_for_execute_task(
        self,
        task_id: str,
        request_hash: str,
        *,
        abort_event: threading.Event,
    ) -> Mapping[str, Any]:
        payload = self._call(
            "cancel",
            {"original_task_id": task_id, "original_request_hash": request_hash},
            task_id=self._random_task("cancel"),
            abort_event=abort_event,
        )
        return self._validated_cancellation_payload(payload, task_id, request_hash)

    @staticmethod
    def _validated_cancellation_payload(
        payload: Mapping[str, Any],
        task_id: str,
        request_hash: str,
    ) -> Mapping[str, Any]:
        if (
            set(payload)
            != {
                "original_task_id",
                "original_request_hash",
                "state",
                "cancellation_requested",
                "cancelled",
            }
            or payload.get("original_task_id") != task_id
            or payload.get("original_request_hash") != request_hash
            or not isinstance(payload.get("state"), str)
            or not isinstance(payload.get("cancellation_requested"), bool)
            or not isinstance(payload.get("cancelled"), bool)
            or (payload.get("cancelled") is True and payload.get("state") != "cancelled")
        ):
            raise RunnerAuthenticationError("Runner cancellation response is invalid.")
        return payload

    def shutdown(self, server_instance_id: str | None = None) -> Mapping[str, Any]:
        """Request an authenticated managed-host shutdown acknowledgement.

        Lifecycle callers may supply the instance identity from the authenticated
        process record so shutdown remains available when runner inventory health
        is quarantined. Callers without that record retain health discovery.
        """

        instance_id = (
            _token(self.health().get("server_instance_id"))
            if server_instance_id is None
            else _token(server_instance_id)
        )
        payload = self._call(
            "shutdown",
            {"server_instance_id": instance_id},
            task_id=self._random_task("shutdown"),
        )
        enrollment = self._active_enrollment()
        if payload != {
            "schema_version": "bluefire.runner-lifecycle.v1",
            "status": "shutdown_acknowledged",
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "server_instance_id": instance_id,
        }:
            raise RunnerAuthenticationError("Runner lifecycle response is invalid.")
        return payload

    def _recover_after_connection_loss(
        self, payload: Mapping[str, Any], task_id: str, request_hash: str
    ) -> Mapping[str, Any]:
        resent = False
        for attempt in range(self.recovery_attempts):
            if attempt and self.recovery_delay_seconds:
                time.sleep(self.recovery_delay_seconds)
            try:
                recovered = self.recover(task_id, request_hash)
            except RunnerConnectionError:
                continue
            state = recovered.get("state")
            if state == "completed":
                return self._recovered_result_payload(recovered)
            if state == "cancelled":
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped."
                )
            if state == "timed_out":
                raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
            if state == "not_found" and not resent:
                resent = True
                try:
                    response = self._call(
                        "execute", payload, task_id=task_id, request_hash=request_hash
                    )
                    return self._execution_result(response)
                except RunnerRemoteError as exc:
                    if exc.code != "duplicate_request":
                        raise
                except RunnerConnectionError:
                    continue
            if state in {
                "failed",
                "indeterminate",
                "recovery_required",
                "cancelled",
                "timed_out",
            }:
                break
        raise RunnerConnectionError(
            "Runner outcome could not be recovered; inspect the recorded task before retrying."
        )

    def _recovered_execution(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        recovered = self.recover(task_id, request_hash)
        if recovered.get("state") == "cancelled":
            raise RunnerTaskCancelled("Runner task was cancelled after its process tree stopped.")
        if recovered.get("state") == "timed_out":
            raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
        if recovered.get("state") != "completed":
            raise RunnerConnectionError(
                "Runner task exists but has no completed result; inspect recovery state."
            )
        return self._recovered_result_payload(recovered)

    @staticmethod
    def _recovered_result_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RunnerAuthenticationError("Runner recovery result is invalid.")
        return result

    @staticmethod
    def _execution_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = payload.get("result")
        if not isinstance(result, dict) or set(payload) != {"result"}:
            raise RunnerAuthenticationError("Runner execution response is invalid.")
        return result

    @staticmethod
    def _random_task(prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(24)}"

    def _active_enrollment(self) -> RunnerEnrollment:
        enrollment = self._enrollments.active()
        if self.profile_id not in enrollment.allowed_profile_ids:
            raise RunnerAuthenticationError("Runner profile is not enrolled for this transport.")
        return enrollment

    def _call(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        request_hash: str | None = None,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        enrollment = self._active_enrollment()
        checked_hash = request_hash or content_hash(dict(payload))
        unsigned = {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "kind": "request",
            "operation": operation,
            "runner_id": enrollment.runner_id,
            "client_id": enrollment.client_id,
            "profile_id": self.profile_id,
            "task_id": task_id,
            "nonce": secrets.token_hex(32),
            "request_hash": checked_hash,
            "payload": dict(payload),
        }
        request = _sign_request(enrollment, unsigned)
        response = self._exchange(request, enrollment, abort_event=abort_event)
        return self._validated_response(response, request, enrollment)

    def _exchange(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        *,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        context = _client_context(enrollment)
        deadline = time.monotonic() + self.socket_timeout_seconds
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.socket_timeout_seconds
            ) as raw_connection:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerConnectionError("Runner connection deadline expired.")
                raw_connection.settimeout(remaining)
                with context.wrap_socket(
                    raw_connection,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                ) as connection:
                    connection.settimeout(max(deadline - time.monotonic(), 0.001))
                    connection.do_handshake()
                    _verify_peer(
                        connection,
                        expected_fingerprint=str(enrollment.metadata["server_fingerprint"]),
                        expected_common_name=enrollment.runner_id,
                    )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RunnerConnectionError("Runner connection deadline expired.")
                    connection.settimeout(remaining)
                    _send_frame(connection, request, self.max_frame_bytes)
                    return _receive_frame(
                        connection,
                        self.max_frame_bytes,
                        deadline=deadline,
                        abort_event=abort_event,
                    )
        except RunnerAuthenticationError:
            raise
        except ssl.SSLError:
            raise RunnerAuthenticationError(
                "Runner TLS authentication could not be completed."
            ) from None
        except (OSError, RunnerConnectionError):
            raise RunnerConnectionError("Runner loopback service is unavailable.") from None

    @staticmethod
    def _validated_response(
        response: Mapping[str, Any],
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
    ) -> Mapping[str, Any]:
        if set(response) != _RESPONSE_FIELDS:
            raise RunnerAuthenticationError("Runner response has an unsupported shape.")
        if (
            response.get("schema_version") != TRANSPORT_SCHEMA_VERSION
            or response.get("kind") != "response"
        ):
            raise RunnerAuthenticationError("Runner response schema is unsupported.")
        for field in (
            "operation",
            "runner_id",
            "client_id",
            "profile_id",
            "task_id",
            "nonce",
            "request_hash",
        ):
            actual = response.get(field)
            expected = request.get(field)
            if (
                not isinstance(actual, str)
                or not isinstance(expected, str)
                or not hmac.compare_digest(actual, expected)
            ):
                raise RunnerAuthenticationError(
                    "Runner response identity does not match its request."
                )
        payload = response.get("payload")
        authentication = response.get("authentication")
        response_hash = response.get("response_hash")
        if (
            not isinstance(payload, dict)
            or not isinstance(authentication, str)
            or _DIGEST.fullmatch(authentication) is None
            or not isinstance(response_hash, str)
            or _DIGEST.fullmatch(response_hash) is None
            or content_hash(payload) != response_hash
        ):
            raise RunnerAuthenticationError("Runner response authentication is invalid.")
        unsigned = {key: response[key] for key in response if key != "authentication"}
        if not hmac.compare_digest(authentication, _request_mac(enrollment, unsigned)):
            raise RunnerAuthenticationError("Runner response authentication is invalid.")
        ok = response.get("ok")
        status = response.get("status")
        error_code = response.get("error_code")
        if ok is True and status == "completed" and error_code is None:
            return payload
        if ok is False and status == "refused" and isinstance(error_code, str):
            raise RunnerRemoteError(error_code)
        raise RunnerAuthenticationError("Runner response status is invalid.")


def run_authenticated_runner_server(
    *,
    enrollment_root: str | Path,
    runner_binary: str | Path,
    work_root: str | Path,
    state_path: str | Path,
    host: str = "127.0.0.1",
    port: int,
    runner_timeout_seconds: float = 35.0,
) -> None:
    """Start a blocking server suitable as a ``multiprocessing`` target."""

    runner = SubprocessRustRunner(
        runner_binary,
        work_root,
        timeout_seconds=runner_timeout_seconds,
    )
    server = AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        state_path,
        host=host,
        port=port,
        socket_timeout_seconds=max(runner_timeout_seconds + 5.0, 10.0),
    )
    try:
        server.serve_forever()
    finally:
        server.shutdown()


__all__ = [
    "AuthenticatedRunnerClient",
    "AuthenticatedRunnerServer",
    "AuthenticatedRunnerTransportError",
    "DEFAULT_CONTROL_WORKER_RESERVE",
    "DEFAULT_CONTROL_RESERVE_ROWS",
    "DEFAULT_MAX_FRAME_BYTES",
    "DEFAULT_MAX_LEDGER_BYTES",
    "DEFAULT_MAX_LEDGER_ROWS",
    "DEFAULT_MAX_WORKERS",
    "LEDGER_SCHEMA_VERSION",
    "RunnerAuthenticationError",
    "RunnerConnectionError",
    "RunnerRemoteError",
    "TRANSPORT_SCHEMA_VERSION",
    "audit_runner_ledger",
    "read_runner_ledger_generation",
    "run_authenticated_runner_server",
    "runner_result_namespace_id",
    "runner_result_namespace_path",
]
