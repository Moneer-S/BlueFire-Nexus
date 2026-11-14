"""Bounded durable state for the external Linux exec lifetime supervisor.

The journal stores identity and evidence only. It opens no Docker socket and
does not grant execution authority. A supervisor process uses it to retain an
operation before effects, reconcile interrupted cleanup, replay the last
bounded RPC results, and keep terminal evidence pending until a controller
explicitly acknowledges the exact event and receipt.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, cast

from .util import content_hash, json_clone


class LinuxExecSupervisorJournalError(RuntimeError):
    """The private journal is invalid, full, changed, or not durable."""


_SCHEMA_VERSION = 1
_DB_NAME = "exec-supervisor-v2.sqlite3"
_LOCK_NAME = "exec-supervisor-v2.lock"
_MAX_DB_BYTES = 8 * 1024 * 1024
_MAX_DOCUMENT_BYTES = 12 * 1024
_MAX_RPC_RESPONSE_BYTES = 8 * 1024
_MAX_OPERATIONS = 128
_MAX_RPC_ROWS = 128
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "admission_digest",
        "attempt_id",
        "operation_id",
        "container_id",
        "claim_ref",
        "controller_fence",
        "custody_plan_digest",
        "network_policy_digest",
        "operation_deadline_monotonic_ns",
        "controller_instance_ref",
        "supervisor_instance_ref",
    }
)
_PROOF_FIELDS = _REQUEST_FIELDS | frozenset(
    {
        "lease_ref",
        "lease_generation",
        "deadline_stop_enforced",
        "controller_loss_stop_enforced",
    }
)
_TERMINAL_FIELDS = frozenset(
    {
        "schema_version",
        "request_ref",
        "lease_ref",
        "lease_generation",
        "outcome",
        "completion_qualification_ref",
        "final_inventory_digest",
        "clock_epoch_ref",
        "observed_monotonic_ns",
        "background_work_absent",
        "container_absent",
    }
)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LinuxExecSupervisorJournalError(f"{label} is invalid")
    return value


def _operation(value: object) -> str:
    if not isinstance(value, str) or _OPERATION.fullmatch(value) is None:
        raise LinuxExecSupervisorJournalError("supervisor operation identity is invalid")
    return value


def _positive(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value < 2**63:
        raise LinuxExecSupervisorJournalError(f"{label} is invalid")
    return value


def _current_euid() -> int:
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise LinuxExecSupervisorJournalError("supervisor journal owner is unavailable")
    value = getter()
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LinuxExecSupervisorJournalError("supervisor journal owner is invalid")
    return cast(int, value)


def _canonical_document(value: Mapping[str, Any], label: str) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise LinuxExecSupervisorJournalError(f"{label} is invalid")
    try:
        cloned = json_clone(dict(value))
        encoded = json.dumps(cloned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise LinuxExecSupervisorJournalError(f"{label} is invalid") from exc
    if not encoded or len(encoded.encode("ascii")) > _MAX_DOCUMENT_BYTES:
        raise LinuxExecSupervisorJournalError(f"{label} exceeds its bound")
    return encoded, content_hash(cloned)


def _decode_document(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise LinuxExecSupervisorJournalError(f"{label} is invalid")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise LinuxExecSupervisorJournalError(f"{label} is invalid") from exc
    if not isinstance(decoded, dict):
        raise LinuxExecSupervisorJournalError(f"{label} is invalid")
    canonical, _ = _canonical_document(decoded, label)
    if canonical != value:
        raise LinuxExecSupervisorJournalError(f"{label} is not canonical")
    return decoded


@dataclass(frozen=True, slots=True)
class ExecSupervisorJournalIdentityV2:
    binding_ref: str
    attempt_id: str
    claim_ref: str
    controller_fence: str
    custody_plan_digest: str
    network_policy_digest: str
    controller_instance_ref: str
    daemon_instance_digest: str
    docker_endpoint_ref: str
    supervisor_instance_ref: str
    supervisor_session_ref: str
    clock_epoch_ref: str
    supervisor_qualification_ref: str

    def __post_init__(self) -> None:
        if _ATTEMPT.fullmatch(self.attempt_id) is None:
            raise LinuxExecSupervisorJournalError("supervisor journal attempt is invalid")
        for name in set(self.__dataclass_fields__) - {"attempt_id"}:
            _digest(getattr(self, name), f"supervisor journal {name}")

    @property
    def identity_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.linux-exec-supervisor-journal-identity.v2",
                **asdict(self),
            }
        )

    def document(self) -> dict[str, str]:
        return {
            "schema_version": "bluefire.linux-exec-supervisor-journal-identity.v2",
            **asdict(self),
        }


@dataclass(frozen=True, slots=True)
class SupervisorRpcReservationV2:
    disposition: Literal["new", "pending", "replay"]
    cursor: int
    request_digest: str
    response: bytes | None

    def __post_init__(self) -> None:
        if self.disposition not in {"new", "pending", "replay"}:
            raise LinuxExecSupervisorJournalError("supervisor RPC disposition is invalid")
        _positive(self.cursor, "supervisor RPC cursor")
        _digest(self.request_digest, "supervisor RPC request")
        if self.disposition == "replay":
            if not isinstance(self.response, bytes) or len(self.response) > _MAX_RPC_RESPONSE_BYTES:
                raise LinuxExecSupervisorJournalError("supervisor RPC replay is invalid")
        elif self.response is not None:
            raise LinuxExecSupervisorJournalError("supervisor RPC reservation is invalid")


@dataclass(frozen=True, slots=True)
class SupervisorOperationRecordV2:
    operation_id: str
    request_ref: str
    request: dict[str, Any]
    proof_ref: str
    proof: dict[str, Any]
    phase: Literal["active", "cleanup_pending", "terminal"]
    cleanup_reason: str | None
    terminal_cursor: int | None
    terminal_receipt_ref: str | None
    terminal_receipt: dict[str, Any] | None

    def __post_init__(self) -> None:
        _operation(self.operation_id)
        _digest(self.request_ref, "supervisor operation request")
        _digest(self.proof_ref, "supervisor operation proof")
        if self.phase not in {"active", "cleanup_pending", "terminal"}:
            raise LinuxExecSupervisorJournalError("supervisor operation phase is invalid")
        if self.phase == "active":
            if any(
                value is not None
                for value in (
                    self.cleanup_reason,
                    self.terminal_cursor,
                    self.terminal_receipt_ref,
                    self.terminal_receipt,
                )
            ):
                raise LinuxExecSupervisorJournalError("active supervisor operation is inconsistent")
        elif self.phase == "cleanup_pending":
            if (
                not isinstance(self.cleanup_reason, str)
                or _REASON.fullmatch(self.cleanup_reason) is None
                or any(
                    value is not None
                    for value in (
                        self.terminal_cursor,
                        self.terminal_receipt_ref,
                        self.terminal_receipt,
                    )
                )
            ):
                raise LinuxExecSupervisorJournalError("pending supervisor cleanup is inconsistent")
        elif (
            self.cleanup_reason is None
            or _REASON.fullmatch(self.cleanup_reason) is None
            or self.terminal_cursor is None
            or self.terminal_receipt_ref is None
            or self.terminal_receipt is None
        ):
            raise LinuxExecSupervisorJournalError("terminal supervisor operation is inconsistent")


@dataclass(frozen=True, slots=True)
class SupervisorTerminalEventV2:
    cursor: int
    operation_id: str
    request_ref: str
    receipt_ref: str
    receipt: dict[str, Any]
    acknowledged: bool

    def __post_init__(self) -> None:
        _positive(self.cursor, "supervisor terminal cursor")
        _operation(self.operation_id)
        _digest(self.request_ref, "supervisor terminal request")
        _digest(self.receipt_ref, "supervisor terminal receipt")
        if type(self.acknowledged) is not bool:
            raise LinuxExecSupervisorJournalError("supervisor terminal acknowledgement is invalid")


class SQLiteLinuxExecSupervisorJournalV2:
    """One private durable journal owned by the external supervisor process."""

    def __init__(
        self,
        directory: Path,
        *,
        identity: ExecSupervisorJournalIdentityV2,
        create: bool,
    ) -> None:
        if type(identity) is not ExecSupervisorJournalIdentityV2 or type(create) is not bool:
            raise LinuxExecSupervisorJournalError("supervisor journal construction is invalid")
        self._directory = self._prepare_directory(Path(directory), create=create)
        self._lock_fd = self._acquire_process_lock(self._directory / _LOCK_NAME)
        try:
            self._path = self._directory / _DB_NAME
            if not create and not self._path.exists():
                raise LinuxExecSupervisorJournalError("supervisor journal does not exist")
            self._check_database_path(self._path, may_be_missing=create)
            self._connection = sqlite3.connect(
                str(self._path),
                timeout=1.0,
                isolation_level=None,
                check_same_thread=False,
            )
        except Exception:
            os.close(self._lock_fd)
            raise
        self._lock = threading.RLock()
        self._poisoned = False
        self._closed = False
        self._identity = identity
        try:
            if os.name == "posix":
                os.chmod(self._path, 0o600)
            self._configure()
            if create:
                self._create(identity)
            else:
                self._reopen(identity)
            self._check_size()
        except Exception:
            self._connection.close()
            os.close(self._lock_fd)
            raise

    @classmethod
    def create(
        cls, directory: Path, identity: ExecSupervisorJournalIdentityV2
    ) -> SQLiteLinuxExecSupervisorJournalV2:
        return cls(directory, identity=identity, create=True)

    @classmethod
    def reopen(
        cls, directory: Path, identity: ExecSupervisorJournalIdentityV2
    ) -> SQLiteLinuxExecSupervisorJournalV2:
        return cls(directory, identity=identity, create=False)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def identity(self) -> ExecSupervisorJournalIdentityV2:
        return self._identity

    @staticmethod
    def _prepare_directory(path: Path, *, create: bool) -> Path:
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise LinuxExecSupervisorJournalError("supervisor journal path is invalid")
        if create and not path.exists():
            try:
                path.mkdir(mode=0o700, parents=False)
            except OSError as exc:
                raise LinuxExecSupervisorJournalError(
                    "supervisor journal directory cannot be created"
                ) from exc
        try:
            row = path.lstat()
        except OSError as exc:
            raise LinuxExecSupervisorJournalError(
                "supervisor journal directory is unavailable"
            ) from exc
        if not stat.S_ISDIR(row.st_mode) or path.is_symlink():
            raise LinuxExecSupervisorJournalError("supervisor journal directory is not private")
        if os.name == "posix":
            if row.st_uid != _current_euid() or row.st_mode & 0o077:
                raise LinuxExecSupervisorJournalError("supervisor journal directory is not private")
        return path.resolve(strict=True)

    @staticmethod
    def _check_database_path(path: Path, *, may_be_missing: bool) -> None:
        try:
            row = path.lstat()
        except FileNotFoundError:
            if may_be_missing:
                return
            raise LinuxExecSupervisorJournalError("supervisor journal is unavailable") from None
        except OSError as exc:
            raise LinuxExecSupervisorJournalError("supervisor journal is unavailable") from exc
        if path.is_symlink() or not stat.S_ISREG(row.st_mode):
            raise LinuxExecSupervisorJournalError("supervisor journal file is unsafe")
        if os.name == "posix" and (row.st_uid != _current_euid() or row.st_mode & 0o077):
            raise LinuxExecSupervisorJournalError("supervisor journal file is not private")

    @staticmethod
    def _acquire_process_lock(path: Path) -> int:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
            if os.name == "posix":
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
                row = os.fstat(descriptor)
                if not stat.S_ISREG(row.st_mode) or row.st_uid != _current_euid():
                    raise OSError("unsafe lock")
                os.fchmod(descriptor, 0o600)  # type: ignore[attr-defined]
            else:
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return descriptor
        except (OSError, ImportError) as exc:
            try:
                os.close(descriptor)
            except (OSError, UnboundLocalError):
                pass
            raise LinuxExecSupervisorJournalError(
                "another exec supervisor owns the journal"
            ) from exc

    def _configure(self) -> None:
        mode = self._connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise LinuxExecSupervisorJournalError("supervisor journal rollback is unavailable")
        self._connection.execute("PRAGMA synchronous=FULL")
        if self._connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise LinuxExecSupervisorJournalError("supervisor journal durability is unavailable")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA temp_store=MEMORY")
        self._connection.execute("PRAGMA secure_delete=ON")
        page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
        if not isinstance(page_size, int) or page_size <= 0 or _MAX_DB_BYTES % page_size:
            raise LinuxExecSupervisorJournalError("supervisor journal page size is unsupported")
        self._connection.execute(f"PRAGMA max_page_count={_MAX_DB_BYTES // page_size}")

    def _create(self, identity: ExecSupervisorJournalIdentityV2) -> None:
        if self._path.stat().st_size != 0:
            raise LinuxExecSupervisorJournalError("supervisor journal already exists")
        identity_json, identity_ref = _canonical_document(identity.document(), "journal identity")
        if identity_ref != identity.identity_ref:
            raise LinuxExecSupervisorJournalError("supervisor journal identity changed")
        with self._transaction():
            self._connection.execute(
                """CREATE TABLE supervisor_meta_v2 (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL,
                    identity_ref TEXT NOT NULL,
                    identity_json TEXT NOT NULL,
                    next_terminal_cursor INTEGER NOT NULL CHECK(next_terminal_cursor >= 1),
                    acked_terminal_cursor INTEGER NOT NULL CHECK(acked_terminal_cursor >= 0),
                    acked_rpc_cursor INTEGER NOT NULL CHECK(acked_rpc_cursor >= 0)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE supervisor_operations_v2 (
                    operation_id TEXT PRIMARY KEY,
                    request_ref TEXT NOT NULL UNIQUE,
                    request_json TEXT NOT NULL,
                    proof_ref TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK(phase IN ('active','cleanup_pending','terminal')),
                    cleanup_reason TEXT,
                    terminal_cursor INTEGER UNIQUE,
                    terminal_receipt_ref TEXT UNIQUE,
                    terminal_json TEXT
                )"""
            )
            self._connection.execute(
                """CREATE TABLE supervisor_rpc_v2 (
                    cursor INTEGER PRIMARY KEY CHECK(cursor >= 1),
                    request_digest TEXT NOT NULL,
                    response BLOB,
                    CHECK(response IS NULL OR length(response) <= 8192)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE supervisor_terminal_acks_v2 (
                    cursor INTEGER PRIMARY KEY CHECK(cursor >= 1),
                    receipt_ref TEXT NOT NULL,
                    prior_ack_ref TEXT,
                    ack_ref TEXT NOT NULL UNIQUE
                )"""
            )
            self._connection.execute(
                "INSERT INTO supervisor_meta_v2 VALUES (1,?,?,?,?,?,?)",
                (_SCHEMA_VERSION, identity_ref, identity_json, 1, 0, 0),
            )
            self._connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _reopen(self, identity: ExecSupervisorJournalIdentityV2) -> None:
        try:
            integrity = self._connection.execute("PRAGMA quick_check(1)").fetchone()[0]
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            row = self._connection.execute(
                "SELECT schema_version,identity_ref,identity_json,next_terminal_cursor,"
                "acked_terminal_cursor,acked_rpc_cursor FROM supervisor_meta_v2 WHERE singleton=1"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise LinuxExecSupervisorJournalError("supervisor journal is unreadable") from exc
        if integrity != "ok" or version != _SCHEMA_VERSION or row is None or len(row) != 6:
            raise LinuxExecSupervisorJournalError("supervisor journal schema is invalid")
        identity_json, identity_ref = _canonical_document(identity.document(), "journal identity")
        if row[0] != _SCHEMA_VERSION or row[1] != identity_ref or row[2] != identity_json:
            raise LinuxExecSupervisorJournalError("supervisor journal identity changed")
        _positive(row[3], "supervisor terminal cursor")
        _positive(row[4], "supervisor terminal acknowledgement", allow_zero=True)
        _positive(row[5], "supervisor RPC acknowledgement", allow_zero=True)
        self._validate_all_rows(
            next_terminal_cursor=row[3],
            acked_terminal_cursor=row[4],
            acked_rpc_cursor=row[5],
        )

    class _Transaction:
        def __init__(self, owner: SQLiteLinuxExecSupervisorJournalV2) -> None:
            self.owner = owner

        def __enter__(self) -> None:
            self.owner._require_usable()
            try:
                self.owner._connection.execute("BEGIN IMMEDIATE")
            except sqlite3.DatabaseError as exc:
                raise LinuxExecSupervisorJournalError(
                    "supervisor journal transaction failed"
                ) from exc

        def __exit__(self, kind, value, traceback) -> Literal[False]:
            try:
                self.owner._connection.execute("ROLLBACK" if kind else "COMMIT")
            except sqlite3.DatabaseError as exc:
                self.owner._poisoned = True
                raise LinuxExecSupervisorJournalError("supervisor journal commit failed") from exc
            if kind is None:
                try:
                    self.owner._check_size()
                except Exception:
                    self.owner._poisoned = True
                    raise
            return False

    def _transaction(self) -> _Transaction:
        return self._Transaction(self)

    def _check_size(self) -> None:
        try:
            if self._path.stat().st_size > _MAX_DB_BYTES:
                raise LinuxExecSupervisorJournalError("supervisor journal exceeds its bound")
        except OSError as exc:
            raise LinuxExecSupervisorJournalError("supervisor journal size is unavailable") from exc

    def _require_usable(self) -> None:
        if self._closed or self._poisoned:
            raise LinuxExecSupervisorJournalError("supervisor journal is unavailable")

    def _validate_all_rows(
        self,
        *,
        next_terminal_cursor: int,
        acked_terminal_cursor: int,
        acked_rpc_cursor: int,
    ) -> None:
        rows = self._connection.execute(
            "SELECT operation_id,request_ref,request_json,proof_ref,proof_json,phase,"
            "cleanup_reason,terminal_cursor,terminal_receipt_ref,terminal_json "
            "FROM supervisor_operations_v2 ORDER BY operation_id"
        ).fetchall()
        if len(rows) > _MAX_OPERATIONS:
            raise LinuxExecSupervisorJournalError("supervisor operation bound changed")
        records = tuple(self._operation_from_row(row) for row in rows)
        terminal_cursors = sorted(
            cast(int, item.terminal_cursor) for item in records if item.phase == "terminal"
        )
        if (
            terminal_cursors != list(range(1, next_terminal_cursor))
            or acked_terminal_cursor >= next_terminal_cursor
        ):
            raise LinuxExecSupervisorJournalError(
                "supervisor terminal acknowledgement state changed"
            )
        terminal_receipts = {
            cast(int, item.terminal_cursor): cast(str, item.terminal_receipt_ref)
            for item in records
            if item.phase == "terminal"
        }
        acknowledgements = self._connection.execute(
            "SELECT cursor,receipt_ref,prior_ack_ref,ack_ref "
            "FROM supervisor_terminal_acks_v2 ORDER BY cursor"
        ).fetchall()
        if len(acknowledgements) != acked_terminal_cursor:
            raise LinuxExecSupervisorJournalError(
                "supervisor terminal acknowledgement state changed"
            )
        prior_ack_ref: str | None = None
        for expected_cursor, row in enumerate(acknowledgements, start=1):
            cursor, receipt_ref, observed_prior, ack_ref = row
            if (
                cursor != expected_cursor
                or receipt_ref != terminal_receipts.get(cursor)
                or observed_prior != prior_ack_ref
                or ack_ref
                != self._terminal_ack_ref(
                    cursor=cursor,
                    receipt_ref=receipt_ref,
                    prior_ack_ref=prior_ack_ref,
                )
            ):
                raise LinuxExecSupervisorJournalError(
                    "supervisor terminal acknowledgement state changed"
                )
            prior_ack_ref = ack_ref
        rpc = self._connection.execute(
            "SELECT cursor,request_digest,response FROM supervisor_rpc_v2 ORDER BY cursor"
        ).fetchall()
        if len(rpc) > _MAX_RPC_ROWS:
            raise LinuxExecSupervisorJournalError("supervisor RPC bound changed")
        if not rpc and acked_rpc_cursor != 0:
            raise LinuxExecSupervisorJournalError("supervisor RPC acknowledgement changed")
        previous = (acked_rpc_cursor - 1) if acked_rpc_cursor else 0
        pending = 0
        for cursor, request_digest, response in rpc:
            _positive(cursor, "supervisor RPC cursor")
            _digest(request_digest, "supervisor RPC request")
            if cursor != previous + 1:
                raise LinuxExecSupervisorJournalError("supervisor RPC sequence changed")
            previous = cursor
            if response is None:
                pending += 1
            elif not isinstance(response, bytes) or len(response) > _MAX_RPC_RESPONSE_BYTES:
                raise LinuxExecSupervisorJournalError("supervisor RPC response changed")
        if pending > 1 or pending and rpc[-1][2] is not None:
            raise LinuxExecSupervisorJournalError("supervisor RPC pending state changed")
        if rpc and (
            rpc[0][0] != (acked_rpc_cursor if acked_rpc_cursor else 1)
            or (acked_rpc_cursor and rpc[0][2] is None)
        ):
            raise LinuxExecSupervisorJournalError("supervisor RPC acknowledgement changed")

    def reserve_rpc(self, cursor: int, request_digest: str) -> SupervisorRpcReservationV2:
        cursor = _positive(cursor, "supervisor RPC cursor")
        request_digest = _digest(request_digest, "supervisor RPC request")
        with self._lock, self._transaction():
            existing = self._connection.execute(
                "SELECT request_digest,response FROM supervisor_rpc_v2 WHERE cursor=?", (cursor,)
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise LinuxExecSupervisorJournalError(
                        "supervisor RPC cursor was replayed differently"
                    )
                response = existing[1]
                return SupervisorRpcReservationV2(
                    disposition="pending" if response is None else "replay",
                    cursor=cursor,
                    request_digest=request_digest,
                    response=None if response is None else bytes(response),
                )
            row = self._connection.execute(
                "SELECT COALESCE(MAX(cursor),(SELECT acked_rpc_cursor FROM supervisor_meta_v2 "
                "WHERE singleton=1)),COUNT(*),SUM(response IS NULL) FROM supervisor_rpc_v2"
            ).fetchone()
            if row[2] not in (None, 0):
                raise LinuxExecSupervisorJournalError("supervisor RPC reconciliation is pending")
            if cursor != row[0] + 1:
                raise LinuxExecSupervisorJournalError("supervisor RPC cursor is not current")
            if row[1] >= _MAX_RPC_ROWS:
                raise LinuxExecSupervisorJournalError("supervisor RPC journal is full")
            self._connection.execute(
                "INSERT INTO supervisor_rpc_v2(cursor,request_digest,response) VALUES (?,?,NULL)",
                (cursor, request_digest),
            )
            return SupervisorRpcReservationV2("new", cursor, request_digest, None)

    @property
    def last_rpc_cursor(self) -> int:
        """Last durably reserved cursor, including an unfinished request."""

        with self._lock:
            self._require_usable()
            value = self._connection.execute(
                "SELECT COALESCE(MAX(cursor),(SELECT acked_rpc_cursor FROM supervisor_meta_v2 "
                "WHERE singleton=1)) FROM supervisor_rpc_v2"
            ).fetchone()[0]
            return _positive(value, "supervisor RPC cursor", allow_zero=True)

    @property
    def pending_rpc(self) -> tuple[int, str] | None:
        """Unfinished cursor that must be reconciled before another request."""

        with self._lock:
            self._require_usable()
            row = self._connection.execute(
                "SELECT cursor,request_digest FROM supervisor_rpc_v2 "
                "WHERE response IS NULL ORDER BY cursor"
            ).fetchone()
            if row is None:
                return None
            return (
                _positive(row[0], "supervisor RPC cursor"),
                _digest(row[1], "supervisor RPC request"),
            )

    def complete_rpc(self, cursor: int, request_digest: str, response: bytes) -> bytes:
        cursor = _positive(cursor, "supervisor RPC cursor")
        request_digest = _digest(request_digest, "supervisor RPC request")
        if not isinstance(response, bytes) or len(response) > _MAX_RPC_RESPONSE_BYTES:
            raise LinuxExecSupervisorJournalError("supervisor RPC response exceeds its bound")
        with self._lock, self._transaction():
            row = self._connection.execute(
                "SELECT request_digest,response FROM supervisor_rpc_v2 WHERE cursor=?", (cursor,)
            ).fetchone()
            if row is None or row[0] != request_digest:
                raise LinuxExecSupervisorJournalError("supervisor RPC reservation is unavailable")
            if row[1] is not None:
                if row[1] != response:
                    raise LinuxExecSupervisorJournalError("supervisor RPC response changed")
                return bytes(row[1])
            self._connection.execute(
                "UPDATE supervisor_rpc_v2 SET response=? WHERE cursor=?", (response, cursor)
            )
            return response

    def acknowledge_rpc(self, cursor: int) -> None:
        cursor = _positive(cursor, "supervisor RPC acknowledgement")
        with self._lock, self._transaction():
            row = self._connection.execute(
                "SELECT acked_rpc_cursor FROM supervisor_meta_v2 WHERE singleton=1"
            ).fetchone()
            acknowledged = row[0]
            if cursor < acknowledged:
                raise LinuxExecSupervisorJournalError("supervisor RPC acknowledgement regressed")
            newest = self._connection.execute(
                "SELECT COALESCE(MAX(cursor),0) FROM supervisor_rpc_v2 WHERE response IS NOT NULL"
            ).fetchone()[0]
            if cursor > newest:
                raise LinuxExecSupervisorJournalError(
                    "supervisor RPC acknowledgement is unretained"
                )
            self._connection.execute(
                "UPDATE supervisor_meta_v2 SET acked_rpc_cursor=? WHERE singleton=1", (cursor,)
            )
            self._connection.execute("DELETE FROM supervisor_rpc_v2 WHERE cursor < ?", (cursor,))

    def record_active(
        self,
        *,
        operation_id: str,
        request_ref: str,
        request: Mapping[str, Any],
        proof_ref: str,
        proof: Mapping[str, Any],
    ) -> SupervisorOperationRecordV2:
        operation_id = _operation(operation_id)
        request_ref = _digest(request_ref, "supervisor operation request")
        proof_ref = _digest(proof_ref, "supervisor operation proof")
        request_json, computed_request = _canonical_document(request, "supervisor request")
        proof_json, computed_proof = _canonical_document(proof, "supervisor proof")
        if computed_request != request_ref or computed_proof != proof_ref:
            raise LinuxExecSupervisorJournalError("supervisor operation document changed")
        self._validate_operation_documents(operation_id, request_ref, request, proof_ref, proof)
        with self._lock, self._transaction():
            row = self._connection.execute(
                "SELECT operation_id,request_ref,request_json,proof_ref,proof_json,phase,"
                "cleanup_reason,terminal_cursor,terminal_receipt_ref,terminal_json "
                "FROM supervisor_operations_v2 WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is not None:
                record = self._operation_from_row(row)
                if (
                    record.request_ref != request_ref
                    or record.request != dict(request)
                    or record.proof_ref != proof_ref
                    or record.proof != dict(proof)
                ):
                    raise LinuxExecSupervisorJournalError("supervisor operation was rebound")
                return record
            count = self._connection.execute(
                "SELECT COUNT(*) FROM supervisor_operations_v2"
            ).fetchone()[0]
            if count >= _MAX_OPERATIONS:
                raise LinuxExecSupervisorJournalError("supervisor operation journal is full")
            self._connection.execute(
                "INSERT INTO supervisor_operations_v2 VALUES (?,?,?,?,?,'active',NULL,NULL,NULL,NULL)",
                (operation_id, request_ref, request_json, proof_ref, proof_json),
            )
            return SupervisorOperationRecordV2(
                operation_id,
                request_ref,
                dict(request),
                proof_ref,
                dict(proof),
                "active",
                None,
                None,
                None,
                None,
            )

    def update_live_proof(
        self,
        *,
        operation_id: str,
        request_ref: str,
        proof_ref: str,
        proof: Mapping[str, Any],
    ) -> SupervisorOperationRecordV2:
        operation_id = _operation(operation_id)
        request_ref = _digest(request_ref, "supervisor operation request")
        proof_ref = _digest(proof_ref, "supervisor operation proof")
        proof_json, computed = _canonical_document(proof, "supervisor proof")
        if computed != proof_ref:
            raise LinuxExecSupervisorJournalError("supervisor operation proof changed")
        with self._lock, self._transaction():
            current = self._require_operation(operation_id)
            if current.phase != "active" or current.request_ref != request_ref:
                raise LinuxExecSupervisorJournalError("supervisor operation is not live")
            self._validate_operation_documents(
                current.operation_id,
                current.request_ref,
                current.request,
                proof_ref,
                proof,
            )
            self._validate_proof_progression(current.proof, proof)
            self._connection.execute(
                "UPDATE supervisor_operations_v2 SET proof_ref=?,proof_json=? WHERE operation_id=?",
                (proof_ref, proof_json, operation_id),
            )
            return SupervisorOperationRecordV2(
                current.operation_id,
                current.request_ref,
                current.request,
                proof_ref,
                dict(proof),
                current.phase,
                current.cleanup_reason,
                current.terminal_cursor,
                current.terminal_receipt_ref,
                current.terminal_receipt,
            )

    def mark_cleanup_pending(
        self, *, operation_id: str, request_ref: str, reason: str
    ) -> SupervisorOperationRecordV2:
        operation_id = _operation(operation_id)
        request_ref = _digest(request_ref, "supervisor operation request")
        if not isinstance(reason, str) or _REASON.fullmatch(reason) is None:
            raise LinuxExecSupervisorJournalError("supervisor cleanup reason is invalid")
        with self._lock, self._transaction():
            current = self._require_operation(operation_id)
            if current.request_ref != request_ref:
                raise LinuxExecSupervisorJournalError("supervisor cleanup request changed")
            if current.phase == "terminal":
                if current.cleanup_reason != reason:
                    raise LinuxExecSupervisorJournalError("supervisor cleanup reason changed")
                return current
            if current.phase == "cleanup_pending" and current.cleanup_reason != reason:
                raise LinuxExecSupervisorJournalError("supervisor cleanup reason changed")
            self._connection.execute(
                "UPDATE supervisor_operations_v2 SET phase='cleanup_pending',cleanup_reason=? "
                "WHERE operation_id=?",
                (reason, operation_id),
            )
            return SupervisorOperationRecordV2(
                current.operation_id,
                current.request_ref,
                current.request,
                current.proof_ref,
                current.proof,
                "cleanup_pending",
                reason,
                None,
                None,
                None,
            )

    def record_terminal(
        self,
        *,
        operation_id: str,
        request_ref: str,
        reason: str,
        receipt_ref: str,
        receipt: Mapping[str, Any],
    ) -> SupervisorTerminalEventV2:
        operation_id = _operation(operation_id)
        request_ref = _digest(request_ref, "supervisor operation request")
        receipt_ref = _digest(receipt_ref, "supervisor terminal receipt")
        if not isinstance(reason, str) or _REASON.fullmatch(reason) is None:
            raise LinuxExecSupervisorJournalError("supervisor cleanup reason is invalid")
        receipt_json, computed = _canonical_document(receipt, "supervisor terminal receipt")
        if computed != receipt_ref or receipt.get("request_ref") != request_ref:
            raise LinuxExecSupervisorJournalError("supervisor terminal receipt changed")
        with self._lock, self._transaction():
            current = self._require_operation(operation_id)
            if current.request_ref != request_ref:
                raise LinuxExecSupervisorJournalError("supervisor terminal request changed")
            self._validate_terminal_document(receipt, current.request_ref, current.proof)
            if current.phase == "terminal":
                if current.terminal_receipt_ref != receipt_ref or current.terminal_receipt != dict(
                    receipt
                ):
                    raise LinuxExecSupervisorJournalError("supervisor terminal outcome changed")
                terminal_cursor = current.terminal_cursor
                terminal_receipt = current.terminal_receipt
                if terminal_cursor is None or terminal_receipt is None:
                    raise LinuxExecSupervisorJournalError(
                        "supervisor terminal outcome is incomplete"
                    )
                return SupervisorTerminalEventV2(
                    terminal_cursor,
                    operation_id,
                    request_ref,
                    receipt_ref,
                    terminal_receipt,
                    self._is_terminal_acknowledged(terminal_cursor),
                )
            if current.phase != "cleanup_pending":
                raise LinuxExecSupervisorJournalError(
                    "supervisor cleanup was not retained before terminal evidence"
                )
            if current.phase == "cleanup_pending" and current.cleanup_reason != reason:
                raise LinuxExecSupervisorJournalError("supervisor terminal reason changed")
            next_cursor = self._connection.execute(
                "SELECT next_terminal_cursor FROM supervisor_meta_v2 WHERE singleton=1"
            ).fetchone()[0]
            _positive(next_cursor, "supervisor terminal cursor")
            self._connection.execute(
                "UPDATE supervisor_operations_v2 SET phase='terminal',cleanup_reason=?,"
                "terminal_cursor=?,terminal_receipt_ref=?,terminal_json=? WHERE operation_id=?",
                (reason, next_cursor, receipt_ref, receipt_json, operation_id),
            )
            self._connection.execute(
                "UPDATE supervisor_meta_v2 SET next_terminal_cursor=? WHERE singleton=1",
                (next_cursor + 1,),
            )
            return SupervisorTerminalEventV2(
                next_cursor, operation_id, request_ref, receipt_ref, dict(receipt), False
            )

    def pending_terminal_events(self) -> tuple[SupervisorTerminalEventV2, ...]:
        with self._lock:
            self._require_usable()
            acknowledged = self._connection.execute(
                "SELECT acked_terminal_cursor FROM supervisor_meta_v2 WHERE singleton=1"
            ).fetchone()[0]
            records = sorted(
                self.operations(phases=("terminal",)),
                key=lambda item: cast(int, item.terminal_cursor),
            )
            events: list[SupervisorTerminalEventV2] = []
            for item in records:
                cursor = item.terminal_cursor
                receipt_ref = item.terminal_receipt_ref
                receipt = item.terminal_receipt
                if cursor is None or receipt_ref is None or receipt is None:
                    raise LinuxExecSupervisorJournalError(
                        "supervisor terminal evidence is incomplete"
                    )
                if cursor > acknowledged:
                    events.append(
                        SupervisorTerminalEventV2(
                            cursor,
                            item.operation_id,
                            item.request_ref,
                            receipt_ref,
                            receipt,
                            False,
                        )
                    )
            return tuple(events)

    def acknowledge_terminal(self, *, cursor: int, receipt_ref: str) -> None:
        cursor = _positive(cursor, "supervisor terminal acknowledgement")
        receipt_ref = _digest(receipt_ref, "supervisor terminal receipt")
        with self._lock, self._transaction():
            acknowledged = self._connection.execute(
                "SELECT acked_terminal_cursor FROM supervisor_meta_v2 WHERE singleton=1"
            ).fetchone()[0]
            row = self._connection.execute(
                "SELECT terminal_receipt_ref FROM supervisor_operations_v2 "
                "WHERE phase='terminal' AND terminal_cursor=?",
                (cursor,),
            ).fetchone()
            if row is None or row[0] != receipt_ref:
                raise LinuxExecSupervisorJournalError("supervisor terminal acknowledgement changed")
            if cursor <= acknowledged:
                return
            if cursor != acknowledged + 1:
                raise LinuxExecSupervisorJournalError(
                    "supervisor terminal acknowledgement is not current"
                )
            prior_ack_ref = None
            if acknowledged:
                prior_row = self._connection.execute(
                    "SELECT ack_ref FROM supervisor_terminal_acks_v2 WHERE cursor=?",
                    (acknowledged,),
                ).fetchone()
                if prior_row is None:
                    raise LinuxExecSupervisorJournalError(
                        "supervisor terminal acknowledgement state changed"
                    )
                prior_ack_ref = _digest(prior_row[0], "supervisor prior terminal acknowledgement")
            ack_ref = self._terminal_ack_ref(
                cursor=cursor,
                receipt_ref=receipt_ref,
                prior_ack_ref=prior_ack_ref,
            )
            self._connection.execute(
                "INSERT INTO supervisor_terminal_acks_v2 VALUES (?,?,?,?)",
                (cursor, receipt_ref, prior_ack_ref, ack_ref),
            )
            self._connection.execute(
                "UPDATE supervisor_meta_v2 SET acked_terminal_cursor=? WHERE singleton=1",
                (cursor,),
            )

    def _terminal_ack_ref(self, *, cursor: int, receipt_ref: str, prior_ack_ref: str | None) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.exec-supervisor-terminal-ack.v2",
                "identity_ref": self._identity.identity_ref,
                "cursor": cursor,
                "receipt_ref": receipt_ref,
                "prior_ack_ref": prior_ack_ref,
            }
        )

    def operations(
        self, *, phases: tuple[str, ...] = ("active", "cleanup_pending", "terminal")
    ) -> tuple[SupervisorOperationRecordV2, ...]:
        if (
            not isinstance(phases, tuple)
            or not phases
            or len(set(phases)) != len(phases)
            or any(item not in {"active", "cleanup_pending", "terminal"} for item in phases)
        ):
            raise LinuxExecSupervisorJournalError("supervisor operation phase filter is invalid")
        placeholders = ",".join("?" for _ in phases)
        with self._lock:
            self._require_usable()
            rows = self._connection.execute(
                "SELECT operation_id,request_ref,request_json,proof_ref,proof_json,phase,"
                "cleanup_reason,terminal_cursor,terminal_receipt_ref,terminal_json "
                f"FROM supervisor_operations_v2 WHERE phase IN ({placeholders}) ORDER BY operation_id",
                phases,
            ).fetchall()
            return tuple(self._operation_from_row(row) for row in rows)

    def _require_operation(self, operation_id: str) -> SupervisorOperationRecordV2:
        row = self._connection.execute(
            "SELECT operation_id,request_ref,request_json,proof_ref,proof_json,phase,"
            "cleanup_reason,terminal_cursor,terminal_receipt_ref,terminal_json "
            "FROM supervisor_operations_v2 WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise LinuxExecSupervisorJournalError("supervisor operation is unavailable")
        return self._operation_from_row(row)

    def _operation_from_row(self, row: tuple[object, ...]) -> SupervisorOperationRecordV2:
        if len(row) != 10:
            raise LinuxExecSupervisorJournalError("supervisor operation row is invalid")
        (
            operation_id,
            request_ref,
            request_json,
            proof_ref,
            proof_json,
            phase,
            cleanup_reason,
            terminal_cursor,
            terminal_receipt_ref,
            terminal_json,
        ) = row
        request = _decode_document(request_json, "supervisor request")
        proof = _decode_document(proof_json, "supervisor proof")
        if content_hash(request) != request_ref or content_hash(proof) != proof_ref:
            raise LinuxExecSupervisorJournalError("supervisor operation evidence changed")
        terminal = (
            None
            if terminal_json is None
            else _decode_document(terminal_json, "supervisor terminal receipt")
        )
        if terminal is not None and content_hash(terminal) != terminal_receipt_ref:
            raise LinuxExecSupervisorJournalError("supervisor terminal evidence changed")
        record = SupervisorOperationRecordV2(
            cast(str, operation_id),
            cast(str, request_ref),
            request,
            cast(str, proof_ref),
            proof,
            cast(Literal["active", "cleanup_pending", "terminal"], phase),
            cast(str | None, cleanup_reason),
            cast(int | None, terminal_cursor),
            cast(str | None, terminal_receipt_ref),
            terminal,
        )
        self._validate_operation_documents(
            record.operation_id,
            record.request_ref,
            record.request,
            record.proof_ref,
            record.proof,
        )
        if record.terminal_receipt is not None:
            self._validate_terminal_document(
                record.terminal_receipt,
                record.request_ref,
                record.proof,
            )
        return record

    def _validate_terminal_document(
        self,
        receipt: Mapping[str, Any],
        request_ref: str,
        proof: Mapping[str, Any],
    ) -> None:
        generation = receipt.get("lease_generation")
        if (
            set(receipt) != _TERMINAL_FIELDS
            or receipt.get("schema_version") != "bluefire.exec-lifetime-terminal-receipt.v2"
            or receipt.get("request_ref") != request_ref
            or receipt.get("lease_ref") != proof.get("lease_ref")
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < proof.get("lease_generation", 1)
            or receipt.get("outcome") != "verified_absent"
            or receipt.get("completion_qualification_ref") is not None
            or receipt.get("background_work_absent") is not True
            or receipt.get("container_absent") is not True
            or receipt.get("clock_epoch_ref") != self._identity.clock_epoch_ref
        ):
            raise LinuxExecSupervisorJournalError("supervisor terminal receipt is unqualified")
        _digest(
            receipt.get("final_inventory_digest"),
            "supervisor terminal final inventory",
        )
        _positive(
            receipt.get("observed_monotonic_ns"),
            "supervisor terminal observation",
        )

    def _validate_operation_documents(
        self,
        operation_id: str,
        request_ref: str,
        request: Mapping[str, Any],
        proof_ref: str,
        proof: Mapping[str, Any],
    ) -> None:
        if (
            set(request) != _REQUEST_FIELDS
            or set(proof) != _PROOF_FIELDS
            or request.get("schema_version") != "bluefire.exec-lifetime-operation-request.v2"
            or proof.get("schema_version") != "bluefire.verified-exec-lifetime-custody.v2"
            or request.get("operation_id") != operation_id
            or proof.get("operation_id") != operation_id
            or any(
                proof.get(name) != request.get(name)
                for name in _REQUEST_FIELDS - {"schema_version"}
            )
            or proof.get("deadline_stop_enforced") is not True
            or proof.get("controller_loss_stop_enforced") is not True
            or request.get("attempt_id") != self._identity.attempt_id
            or request.get("claim_ref") != self._identity.claim_ref
            or request.get("controller_fence") != self._identity.controller_fence
            or request.get("custody_plan_digest") != self._identity.custody_plan_digest
            or request.get("network_policy_digest") != self._identity.network_policy_digest
            or request.get("controller_instance_ref") != self._identity.controller_instance_ref
            or request.get("supervisor_instance_ref") != self._identity.supervisor_instance_ref
        ):
            raise LinuxExecSupervisorJournalError("supervisor operation binding changed")
        for name in (
            "admission_digest",
            "claim_ref",
            "controller_fence",
            "custody_plan_digest",
            "network_policy_digest",
            "controller_instance_ref",
            "supervisor_instance_ref",
        ):
            _digest(request.get(name), f"supervisor operation {name}")
        _positive(
            request.get("operation_deadline_monotonic_ns"),
            "supervisor operation deadline",
        )
        attempt_id = request.get("attempt_id")
        container_id = request.get("container_id")
        if (
            not isinstance(attempt_id, str)
            or _ATTEMPT.fullmatch(attempt_id) is None
            or not isinstance(container_id, str)
            or _CONTAINER.fullmatch(container_id) is None
        ):
            raise LinuxExecSupervisorJournalError("supervisor operation binding changed")
        _digest(request_ref, "supervisor operation request")
        _digest(proof_ref, "supervisor operation proof")
        _digest(proof.get("lease_ref"), "supervisor operation lease")
        _positive(proof.get("lease_generation"), "supervisor operation lease generation")

    @staticmethod
    def _validate_proof_progression(
        previous: Mapping[str, Any], candidate: Mapping[str, Any]
    ) -> None:
        fixed = (
            "admission_digest",
            "attempt_id",
            "operation_id",
            "container_id",
            "claim_ref",
            "controller_fence",
            "custody_plan_digest",
            "network_policy_digest",
            "operation_deadline_monotonic_ns",
            "controller_instance_ref",
            "supervisor_instance_ref",
            "lease_ref",
        )
        if any(previous.get(name) != candidate.get(name) for name in fixed):
            raise LinuxExecSupervisorJournalError("supervisor operation proof was rebound")
        old = _positive(previous.get("lease_generation"), "supervisor operation lease generation")
        new = _positive(candidate.get("lease_generation"), "supervisor operation lease generation")
        if new < old:
            raise LinuxExecSupervisorJournalError("supervisor operation proof regressed")

    def _is_terminal_acknowledged(self, cursor: int | None) -> bool:
        if cursor is None:
            return False
        acknowledged = self._connection.execute(
            "SELECT acked_terminal_cursor FROM supervisor_meta_v2 WHERE singleton=1"
        ).fetchone()[0]
        return bool(cursor <= acknowledged)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._connection.close()
            finally:
                os.close(self._lock_fd)


__all__ = [
    "ExecSupervisorJournalIdentityV2",
    "LinuxExecSupervisorJournalError",
    "SQLiteLinuxExecSupervisorJournalV2",
    "SupervisorOperationRecordV2",
    "SupervisorRpcReservationV2",
    "SupervisorTerminalEventV2",
]
