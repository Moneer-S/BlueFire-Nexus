"""Independent live-state witness for the Gate 11 recovery journey.

The recovery producer owns orchestration.  This module separately reads the
live effect and receipt state, queries the authenticated recovery ledger, and
checks exact Windows process creation identities.  Private filesystem paths
remain in memory and are never returned by the public witness document.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, cast

from .util import canonical_json_bytes, content_hash

WITNESS_SCHEMA = "bluefire.cross-platform-recovery-live-witness.v1"
_PROFILE_ID = "sandbox-endpoint-deep-lab.v1"
_EFFECT_DIRECTORY = "gate11-recovery"
_EFFECT_PATH = f"{_EFFECT_DIRECTORY}/transport-recovery.jsonl"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TASK_ID = re.compile(r"^execute-[0-9a-f]{64}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_EFFECT_BYTES = 64 * 1024


class RecoveryWitnessError(ValueError):
    """Raised when live recovery state cannot support the serialized claim."""


class RecoveryClient(Protocol):
    def health(self) -> Mapping[str, Any]: ...

    def recover(self, task_id: str, request_hash: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class LiveRecoveryInspection:
    """Private-path-free values copied from independently inspected live state."""

    result: Mapping[str, Any]
    receipt_body: Mapping[str, Any]
    receipt_commit_body: Mapping[str, Any]
    facts: Mapping[str, Any]
    client_process_identity: Mapping[str, int]
    host_process_identity: Mapping[str, int]


@dataclass(frozen=True)
class CleanedRecoveryInspection:
    """Independent state observed after receipt-driven cleanup."""

    result: Mapping[str, Any]
    facts: Mapping[str, Any]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryWitnessError(message)


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields, f"{label} is invalid")
    return cast(Mapping[str, Any], value)


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").tzinfo == timezone.utc
    except ValueError:
        return False


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "live witness JSON contains duplicate keys")
        value[key] = item
    return value


def _is_link_or_reparse(path: Path) -> bool:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_size),
        int(details.st_mtime_ns),
        int(details.st_nlink),
    )


def _safe_directory(path: Path, label: str) -> Path:
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RecoveryWitnessError(f"{label} is unavailable") from exc
    _require(
        stat.S_ISDIR(details.st_mode)
        and not _is_link_or_reparse(path)
        and resolved == path.resolve(),
        f"{label} is unsafe",
    )
    return resolved


def _safe_file(path: Path, maximum: int, label: str) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not _is_link_or_reparse(path)
            and before.st_nlink == 1
            and 1 <= before.st_size <= maximum,
            f"{label} is unsafe",
        )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        _require(_identity(opened) == _identity(before), f"{label} changed before inspection")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        _require(
            len(payload) == before.st_size
            and len(payload) <= maximum
            and _identity(after) == _identity(before) == _identity(current),
            f"{label} changed during inspection",
        )
        return payload
    except RecoveryWitnessError:
        raise
    except OSError as exc:
        raise RecoveryWitnessError(f"{label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _json_file(path: Path, maximum: int, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            _safe_file(path, maximum, label).decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RecoveryWitnessError(f"{label} is not strict JSON") from exc
    return _exact(value, set(value) if isinstance(value, Mapping) else set(), label)


def _directory_ids(root: Path, label: str) -> list[str]:
    checked = _safe_directory(root, label)
    values: list[str] = []
    try:
        entries = list(checked.iterdir())
    except OSError as exc:
        raise RecoveryWitnessError(f"{label} cannot be inventoried") from exc
    _require(len(entries) <= 1024, f"{label} exceeds its entry bound")
    for entry in entries:
        details = entry.lstat()
        _require(
            stat.S_ISREG(details.st_mode)
            and not _is_link_or_reparse(entry)
            and details.st_nlink == 1
            and entry.name.endswith(".json")
            and _RAW_DIGEST.fullmatch(entry.name[:-5]) is not None,
            f"{label} contains an unsafe entry",
        )
        values.append(entry.name[:-5])
    return sorted(values)


def _filetime_value(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _open_process(process_id: int, *, absent_ok: bool) -> int | None:
    _require(os.name == "nt", "Windows process identity proof is unavailable")
    _require(type(process_id) is int and process_id > 0, "process identity is invalid")
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    handle = open_process(
        _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE,
        0,
        process_id,
    )
    if handle:
        return int(handle)
    error = cast(Any, ctypes).get_last_error()
    if absent_ok and error in {87, 1168}:
        return None
    raise RecoveryWitnessError(f"Windows process identity cannot be opened ({error})")


def _close_handle(handle: int) -> None:
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        raise RecoveryWitnessError("Windows process identity handle could not be closed")


def _process_creation_time(handle: int) -> int:
    from ctypes import wintypes

    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    get_times = kernel32.GetProcessTimes
    get_times.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    get_times.restype = ctypes.c_int
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not get_times(
        ctypes.c_void_p(handle),
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise RecoveryWitnessError("Windows process creation identity is unavailable")
    value = _filetime_value(created)
    _require(value > 0, "Windows process creation identity is invalid")
    return value


def _process_handle_running(handle: int) -> bool:
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    wait = kernel32.WaitForSingleObject
    wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    wait.restype = ctypes.c_uint32
    result = int(wait(ctypes.c_void_p(handle), 0))
    if result == _WAIT_TIMEOUT:
        return True
    if result == _WAIT_OBJECT_0:
        return False
    raise RecoveryWitnessError("Windows process liveness probe failed")


def capture_process_identity(process_id: int) -> Mapping[str, int]:
    handle = _open_process(process_id, absent_ok=False)
    assert handle is not None
    try:
        identity = {
            "process_id": process_id,
            "creation_time_100ns": _process_creation_time(handle),
        }
        _require(_process_handle_running(handle), "Windows process is not running")
        return identity
    finally:
        _close_handle(handle)


def process_identity_running(identity: Mapping[str, Any]) -> bool:
    row = _exact(identity, {"process_id", "creation_time_100ns"}, "process identity")
    process_id = row.get("process_id")
    created = row.get("creation_time_100ns")
    _require(
        type(process_id) is int and process_id > 0 and type(created) is int and created > 0,
        "process identity is invalid",
    )
    handle = _open_process(cast(int, process_id), absent_ok=True)
    if handle is None:
        return False
    try:
        if _process_creation_time(handle) != created:
            return False
        return _process_handle_running(handle)
    finally:
        _close_handle(handle)


def require_process_absent(identity: Mapping[str, Any], label: str) -> None:
    _require(not process_identity_running(identity), f"{label} process identity is still running")


def _health_facts(client: RecoveryClient) -> Mapping[str, Any]:
    health = client.health()
    ledger = health.get("ledger") if isinstance(health, Mapping) else None
    _require(
        isinstance(ledger, Mapping)
        and health.get("schema_version") == "bluefire.runner-health.v1"
        and health.get("status") == "ready"
        and health.get("transport") == "mutual-tls-loopback"
        and health.get("tls") == "TLSv1.3"
        and isinstance(ledger.get("generation"), str)
        and _DIGEST.fullmatch(str(ledger["generation"])) is not None
        and type(ledger.get("rows")) is int
        and type(ledger.get("execute_rows")) is int
        and 0 <= ledger["execute_rows"] <= ledger["rows"]
        and ledger.get("accepting_execute") is True,
        "authenticated recovery ledger health is invalid",
    )
    ledger_row = cast(Mapping[str, Any], ledger)
    return {
        "ledger_generation": str(ledger_row["generation"]),
        "ledger_row_count": int(ledger_row["rows"]),
        "ledger_execute_count": int(ledger_row["execute_rows"]),
    }


def _recover_result(
    client: RecoveryClient,
    task_id: str,
    request_hash: str,
    expected_result: Mapping[str, Any],
) -> Mapping[str, Any]:
    recovered = _exact(
        client.recover(task_id, request_hash),
        {
            "original_task_id",
            "original_request_hash",
            "state",
            "result",
            "error_code",
            "cancellation_requested",
            "receipt_ids",
            "cleanup_required",
        },
        "authenticated recovery response",
    )
    result = recovered.get("result")
    _require(
        recovered.get("original_task_id") == task_id
        and recovered.get("original_request_hash") == request_hash
        and recovered.get("state") == "completed"
        and isinstance(result, Mapping)
        and canonical_json_bytes(result) == canonical_json_bytes(expected_result)
        and recovered.get("error_code") is None
        and recovered.get("cancellation_requested") is False
        and recovered.get("receipt_ids") == []
        and recovered.get("cleanup_required") is False,
        "authenticated ledger did not return the exact committed result",
    )
    return dict(cast(Mapping[str, Any], result))


def _result_output(result: Mapping[str, Any], receipt_id: str) -> Mapping[str, Any]:
    output = _exact(
        result.get("output"),
        {"artifact", "sha256", "size", "template", "record_count", "format"},
        "live recovery output",
    )
    _require(
        result.get("schema_version") == "bluefire.runner-result.v1"
        and result.get("status") == "success"
        and result.get("action_id") == "sandbox.fixture.create.v1"
        and result.get("runner_profile_id") == _PROFILE_ID
        and result.get("platform") == "windows"
        and isinstance(result.get("request_hash"), str)
        and _DIGEST.fullmatch(str(result["request_hash"])) is not None
        and result.get("receipt_ids") == [receipt_id]
        and output.get("artifact") == _EFFECT_PATH
        and isinstance(output.get("sha256"), str)
        and _RAW_DIGEST.fullmatch(str(output["sha256"])) is not None
        and type(output.get("size")) is int
        and 0 < output["size"] <= _MAX_EFFECT_BYTES
        and output.get("template") == "telemetry-seed"
        and output.get("record_count") == 1
        and output.get("format") == "jsonl",
        "live recovery result is invalid",
    )
    return output


def _validate_receipt(
    receipt: Mapping[str, Any],
    commit: Mapping[str, Any],
    receipt_id: str,
    result: Mapping[str, Any],
    output: Mapping[str, Any],
) -> None:
    _exact(
        receipt,
        {
            "schema_version",
            "receipt_id",
            "request_hash",
            "action_id",
            "runner_profile_id",
            "workspace_id",
            "created_at",
            "paths",
        },
        "live receipt",
    )
    identity = {key: value for key, value in receipt.items() if key != "receipt_id"}
    expected_paths = [
        {
            "relative_path": _EFFECT_PATH,
            "kind": "file",
            "sha256": output.get("sha256"),
            "size": output.get("size"),
        },
        {
            "relative_path": _EFFECT_DIRECTORY,
            "kind": "directory",
            "sha256": None,
            "size": None,
        },
    ]
    _require(
        receipt.get("schema_version") == "bluefire.receipt/v1"
        and receipt.get("receipt_id")
        == receipt_id
        == hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        and receipt.get("request_hash") == result.get("request_hash")
        and receipt.get("action_id") == "sandbox.fixture.create.v1"
        and receipt.get("runner_profile_id") == _PROFILE_ID
        and isinstance(receipt.get("workspace_id"), str)
        and _RAW_DIGEST.fullmatch(str(receipt["workspace_id"])) is not None
        and _timestamp(receipt.get("created_at"))
        and receipt.get("paths") == expected_paths,
        "live receipt is not bound to the effect",
    )
    _exact(
        commit,
        {"schema_version", "receipt_id", "runner_profile_id", "workspace_id", "committed_at"},
        "live receipt commit",
    )
    _require(
        commit.get("schema_version") == "bluefire.receipt-commit/v1"
        and commit.get("receipt_id") == receipt_id
        and commit.get("runner_profile_id") == receipt.get("runner_profile_id")
        and commit.get("workspace_id") == receipt.get("workspace_id")
        and _timestamp(commit.get("committed_at")),
        "live receipt commit is invalid",
    )


def _effect_facts(path: Path, output: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = _safe_file(path, _MAX_EFFECT_BYTES, "live recovery effect")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    line_count = len(payload.splitlines())
    _require(
        payload.endswith(b"\n")
        and digest == "sha256:" + str(output.get("sha256"))
        and len(payload) == output.get("size")
        and line_count == 1,
        "live recovery effect does not match the authenticated result",
    )
    return {"effect_digest": digest, "effect_size": len(payload), "effect_count": line_count}


def _stage_facts(value: Mapping[str, Any]) -> Mapping[str, Any]:
    body = dict(value)
    _require("stage_digest" not in body, "live witness stage digest is duplicated")
    return {**body, "stage_digest": content_hash(body)}


def inspect_live_recovery(
    *,
    client: RecoveryClient,
    sandbox: Path,
    task_id: str,
    request_hash: str,
    receipt_id: str,
    expected_result: Mapping[str, Any],
    expected_generation: str,
    client_process_id: int,
    host_process_id: int,
    stage: str,
) -> LiveRecoveryInspection:
    """Inspect one active authenticated result plus its live filesystem effects."""

    _require(
        stage in {"before_interruption", "after_recovery"},
        "live witness stage is invalid",
    )
    _require(_TASK_ID.fullmatch(task_id) is not None, "live witness task identity is invalid")
    _require(_DIGEST.fullmatch(request_hash) is not None, "live witness request hash is invalid")
    _require(_RAW_DIGEST.fullmatch(receipt_id) is not None, "live witness receipt is invalid")
    checked_sandbox = _safe_directory(sandbox, "live recovery sandbox")
    receipt_root = _safe_directory(checked_sandbox / ".bluefire" / "receipts", "live receipt root")
    commit_root = _safe_directory(
        checked_sandbox / ".bluefire" / "receipt-commits", "live commit root"
    )
    result = _recover_result(client, task_id, request_hash, expected_result)
    output = _result_output(result, receipt_id)
    receipt_ids = _directory_ids(receipt_root, "live receipt root")
    commit_ids = _directory_ids(commit_root, "live commit root")
    _require(
        receipt_ids == commit_ids == [receipt_id],
        "live recovery does not own exactly one receipt and commit",
    )
    receipt = _json_file(receipt_root / f"{receipt_id}.json", _MAX_RECEIPT_BYTES, "live receipt")
    commit = _json_file(
        commit_root / f"{receipt_id}.json", _MAX_RECEIPT_BYTES, "live receipt commit"
    )
    _validate_receipt(receipt, commit, receipt_id, result, output)
    effect = _effect_facts(checked_sandbox / _EFFECT_PATH, output)
    health = _health_facts(client)
    _require(
        health["ledger_generation"] == expected_generation and health["ledger_execute_count"] >= 1,
        "live authenticated ledger generation changed",
    )
    client_identity = capture_process_identity(client_process_id)
    host_identity = capture_process_identity(host_process_id)
    _require(
        client_identity["process_id"] != host_identity["process_id"],
        "live witness client and host are not distinct processes",
    )
    facts = _stage_facts(
        {
            "stage": stage,
            **health,
            "result_digest": content_hash(result),
            "receipt_body_digest": content_hash(receipt),
            "receipt_commit_digest": content_hash(commit),
            "receipt_count": len(receipt_ids),
            "receipt_commit_count": len(commit_ids),
            **effect,
        }
    )
    return LiveRecoveryInspection(
        result=result,
        receipt_body=receipt,
        receipt_commit_body=commit,
        facts=facts,
        client_process_identity=client_identity,
        host_process_identity=host_identity,
    )


def _validate_cleanup_result(value: Mapping[str, Any], receipt_id: str) -> None:
    cleanup = _exact(
        value.get("cleanup"),
        {
            "requested_receipts",
            "removed_paths",
            "already_absent_receipts",
            "retained_paths",
            "errors",
            "verification_performed",
            "verified_removed_paths",
            "verified_absent_paths",
            "verified_receipts",
        },
        "live cleanup result",
    )
    _require(
        value.get("schema_version") == "bluefire.runner-result.v1"
        and value.get("status") == "success"
        and value.get("action_id") == "sandbox.cleanup.v1"
        and value.get("runner_profile_id") == _PROFILE_ID
        and value.get("platform") == "windows"
        and value.get("receipt_ids") == []
        and cleanup
        == {
            "requested_receipts": 1,
            "removed_paths": [_EFFECT_PATH, _EFFECT_DIRECTORY],
            "already_absent_receipts": [],
            "retained_paths": [],
            "errors": [],
            "verification_performed": True,
            "verified_removed_paths": 2,
            "verified_absent_paths": 0,
            "verified_receipts": 1,
        }
        and _RAW_DIGEST.fullmatch(receipt_id) is not None,
        "live cleanup result did not reconcile the exact receipt",
    )


def _require_absent(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RecoveryWitnessError(f"{label} could not be inspected") from exc
    raise RecoveryWitnessError(f"{label} still exists")


def inspect_cleaned_recovery(
    *,
    client: RecoveryClient,
    sandbox: Path,
    task_id: str,
    request_hash: str,
    receipt_id: str,
    expected_result: Mapping[str, Any],
    expected_generation: str,
    cleanup_result: Mapping[str, Any],
    client_process_identity: Mapping[str, Any],
    host_before_identity: Mapping[str, Any],
    host_after_identity: Mapping[str, Any],
) -> CleanedRecoveryInspection:
    """Re-query the active ledger and independently verify receipt/effect absence."""

    checked_sandbox = _safe_directory(sandbox, "cleaned recovery sandbox")
    result = _recover_result(client, task_id, request_hash, expected_result)
    health = _health_facts(client)
    _require(
        health["ledger_generation"] == expected_generation and health["ledger_execute_count"] >= 2,
        "cleanup changed the authenticated ledger generation",
    )
    receipt_root = checked_sandbox / ".bluefire" / "receipts"
    commit_root = checked_sandbox / ".bluefire" / "receipt-commits"
    receipt_count = len(_directory_ids(receipt_root, "cleaned receipt root"))
    commit_count = len(_directory_ids(commit_root, "cleaned commit root"))
    _require(receipt_count == commit_count == 0, "cleanup retained receipt state")
    _require_absent(checked_sandbox / _EFFECT_PATH, "cleaned recovery effect")
    _require_absent(checked_sandbox / _EFFECT_DIRECTORY, "cleaned recovery directory")
    _validate_cleanup_result(cleanup_result, receipt_id)
    require_process_absent(host_before_identity, "interrupted host")
    _require(
        process_identity_running(client_process_identity)
        and process_identity_running(host_after_identity),
        "cleanup escaped the expected client or recovered host process identity",
    )
    facts = _stage_facts(
        {
            "stage": "after_cleanup",
            **health,
            "result_digest": content_hash(result),
            "cleanup_result_digest": content_hash(cleanup_result),
            "receipt_count": receipt_count,
            "receipt_commit_count": commit_count,
            "effect_exists": False,
            "effect_directory_exists": False,
            "host_before_absent": True,
            "host_after_running": True,
        }
    )
    return CleanedRecoveryInspection(result=result, facts=facts)


def stopped_process_facts(
    *,
    client_process_identity: Mapping[str, Any],
    host_before_identity: Mapping[str, Any],
    host_after_identity: Mapping[str, Any],
) -> Mapping[str, Any]:
    require_process_absent(host_before_identity, "interrupted host")
    require_process_absent(host_after_identity, "recovered host")
    _require(
        process_identity_running(client_process_identity),
        "recovery client process identity was lost",
    )
    return _stage_facts(
        {
            "stage": "after_recovered_host_stop",
            "host_before_absent": True,
            "host_after_absent": True,
            "client_running": True,
        }
    )


def inspect_continuation(
    *,
    client: RecoveryClient,
    sandbox: Path,
    task_id: str,
    request_hash: str,
    expected_result: Mapping[str, Any],
    expected_generation: str,
    client_process_identity: Mapping[str, Any],
    host_process_id: int,
) -> tuple[Mapping[str, Any], Mapping[str, int]]:
    """Prove a fresh host can continue with the same cleaned recovery ledger."""

    checked_sandbox = _safe_directory(sandbox, "continuation recovery sandbox")
    result = _recover_result(client, task_id, request_hash, expected_result)
    health = _health_facts(client)
    _require(
        health["ledger_generation"] == expected_generation and health["ledger_execute_count"] >= 2,
        "continuation host changed the authenticated recovery ledger",
    )
    _require(
        _directory_ids(checked_sandbox / ".bluefire" / "receipts", "continuation receipt root")
        == []
        and _directory_ids(
            checked_sandbox / ".bluefire" / "receipt-commits",
            "continuation commit root",
        )
        == [],
        "continuation host restored cleaned receipt state",
    )
    _require_absent(checked_sandbox / _EFFECT_PATH, "continuation recovery effect")
    _require_absent(checked_sandbox / _EFFECT_DIRECTORY, "continuation recovery directory")
    host_identity = capture_process_identity(host_process_id)
    _require(
        process_identity_running(client_process_identity)
        and host_identity["process_id"] != client_process_identity["process_id"],
        "continuation process boundary is invalid",
    )
    facts = _stage_facts(
        {
            "stage": "continuation",
            **health,
            "result_digest": content_hash(result),
            "receipt_count": 0,
            "receipt_commit_count": 0,
            "effect_exists": False,
            "effect_directory_exists": False,
            "host_running": True,
        }
    )
    return facts, host_identity


def build_witness_validation(
    *,
    before: LiveRecoveryInspection,
    recovered: LiveRecoveryInspection,
    cleaned: CleanedRecoveryInspection,
    stopped: Mapping[str, Any],
    continuation: Mapping[str, Any],
    continuation_host_identity: Mapping[str, int],
) -> Mapping[str, Any]:
    """Build the exact path-free witness subdocument from live inspections only."""

    _require(
        before.facts.get("stage") == "before_interruption"
        and recovered.facts.get("stage") == "after_recovery"
        and cleaned.facts.get("stage") == "after_cleanup"
        and stopped.get("stage") == "after_recovered_host_stop"
        and continuation.get("stage") == "continuation",
        "live recovery witness stages are incomplete",
    )
    result_digest = content_hash(before.result)
    generation = before.facts.get("ledger_generation")
    _require(
        canonical_json_bytes(before.result)
        == canonical_json_bytes(recovered.result)
        == canonical_json_bytes(cleaned.result)
        and before.receipt_body == recovered.receipt_body
        and before.receipt_commit_body == recovered.receipt_commit_body
        and all(
            stage.get("result_digest") == result_digest
            for stage in (before.facts, recovered.facts, cleaned.facts, continuation)
        )
        and all(
            stage.get("ledger_generation") == generation
            for stage in (before.facts, recovered.facts, cleaned.facts, continuation)
        )
        and before.client_process_identity == recovered.client_process_identity,
        "live recovery witness facts are not stable",
    )
    identities = {
        "client": dict(before.client_process_identity),
        "host_before": dict(before.host_process_identity),
        "host_after": dict(recovered.host_process_identity),
        "continuation_host": dict(continuation_host_identity),
    }
    process_identities = [
        (row["process_id"], row["creation_time_100ns"]) for row in identities.values()
    ]
    _require(
        len(process_identities) == len(set(process_identities))
        and all(
            row["process_id"] != identities["client"]["process_id"]
            for name, row in identities.items()
            if name != "client"
        ),
        "live recovery witness process identities are not distinct",
    )
    body = {
        "schema_version": WITNESS_SCHEMA,
        "stages": {
            "before_interruption": dict(before.facts),
            "after_recovery": dict(recovered.facts),
            "after_cleanup": dict(cleaned.facts),
            "after_recovered_host_stop": dict(stopped),
            "continuation": dict(continuation),
        },
        "os_process_identities": identities,
        "result_stable": True,
        "ledger_generation_stable": True,
        "live_receipt_binding_stable": True,
        "cleanup_reconciled": True,
    }
    value = {**body, "witness_digest": content_hash(body)}
    validate_witness_validation(value)
    return value


def _path_free(value: Any) -> bool:
    if isinstance(value, Mapping):
        return all(_path_free(key) and _path_free(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return all(_path_free(item) for item in value)
    if not isinstance(value, str):
        return True
    return not (
        re.search(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\|/[^\s])", value)
        or "file://" in value.lower()
    )


def validate_witness_validation(value: Any) -> None:
    """Validate exact shape and all recomputable path-free witness relations."""

    row = _exact(
        value,
        {
            "schema_version",
            "stages",
            "os_process_identities",
            "result_stable",
            "ledger_generation_stable",
            "live_receipt_binding_stable",
            "cleanup_reconciled",
            "witness_digest",
        },
        "recovery witness validation",
    )
    stages = _exact(
        row.get("stages"),
        {
            "before_interruption",
            "after_recovery",
            "after_cleanup",
            "after_recovered_host_stop",
            "continuation",
        },
        "recovery witness stages",
    )
    live_fields = set(
        "stage ledger_generation ledger_row_count ledger_execute_count result_digest "
        "receipt_body_digest receipt_commit_digest receipt_count receipt_commit_count "
        "effect_digest effect_size effect_count stage_digest".split()
    )
    cleanup_fields = set(
        "stage ledger_generation ledger_row_count ledger_execute_count result_digest "
        "cleanup_result_digest receipt_count receipt_commit_count effect_exists "
        "effect_directory_exists host_before_absent host_after_running stage_digest".split()
    )
    stopped_fields = set(
        "stage host_before_absent host_after_absent client_running stage_digest".split()
    )
    continuation_fields = set(
        "stage ledger_generation ledger_row_count ledger_execute_count result_digest "
        "receipt_count receipt_commit_count effect_exists effect_directory_exists "
        "host_running stage_digest".split()
    )
    stage_fields = {
        "before_interruption": live_fields,
        "after_recovery": live_fields,
        "after_cleanup": cleanup_fields,
        "after_recovered_host_stop": stopped_fields,
        "continuation": continuation_fields,
    }
    for name, fields in stage_fields.items():
        stage = _exact(stages.get(name), fields, "recovery witness stage")
        body = {key: item for key, item in stage.items() if key != "stage_digest"}
        _require(
            stage.get("stage") == name and stage.get("stage_digest") == content_hash(body),
            "recovery witness stage digest is invalid",
        )
    identities = _exact(
        row.get("os_process_identities"),
        {"client", "host_before", "host_after", "continuation_host"},
        "recovery witness process identities",
    )
    process_identities: list[tuple[int, int]] = []
    for identity in identities.values():
        item = _exact(
            identity,
            {"process_id", "creation_time_100ns"},
            "recovery witness process identity",
        )
        _require(
            type(item.get("process_id")) is int
            and item["process_id"] > 0
            and type(item.get("creation_time_100ns")) is int
            and item["creation_time_100ns"] > 0,
            "recovery witness process identity is invalid",
        )
        process_identities.append((int(item["process_id"]), int(item["creation_time_100ns"])))
    client_process_id = int(identities["client"]["process_id"])
    before = stages["before_interruption"]
    recovered = stages["after_recovery"]
    cleaned = stages["after_cleanup"]
    stopped = stages["after_recovered_host_stop"]
    continued = stages["continuation"]
    generation = before["ledger_generation"]
    result_digest = before["result_digest"]
    body = {key: item for key, item in row.items() if key != "witness_digest"}
    _require(
        row.get("schema_version") == WITNESS_SCHEMA
        and all(
            _DIGEST.fullmatch(str(item)) is not None
            for item in (
                generation,
                result_digest,
                before["receipt_body_digest"],
                before["receipt_commit_digest"],
                before["effect_digest"],
                cleaned["cleanup_result_digest"],
            )
        )
        and all(
            stage["ledger_generation"] == generation and stage["result_digest"] == result_digest
            for stage in (recovered, cleaned, continued)
        )
        and before["receipt_count"] == before["receipt_commit_count"] == 1
        and recovered["receipt_count"] == recovered["receipt_commit_count"] == 1
        and before["effect_count"] == recovered["effect_count"] == 1
        and before["effect_digest"] == recovered["effect_digest"]
        and before["effect_size"] == recovered["effect_size"]
        and cleaned["receipt_count"] == cleaned["receipt_commit_count"] == 0
        and continued["receipt_count"] == continued["receipt_commit_count"] == 0
        and all(
            item is False
            for item in (
                cleaned["effect_exists"],
                cleaned["effect_directory_exists"],
                continued["effect_exists"],
                continued["effect_directory_exists"],
            )
        )
        and all(
            item is True
            for item in (
                cleaned["host_before_absent"],
                cleaned["host_after_running"],
                stopped["host_before_absent"],
                stopped["host_after_absent"],
                stopped["client_running"],
                continued["host_running"],
            )
        )
        and all(
            row.get(key) is True
            for key in (
                "result_stable",
                "ledger_generation_stable",
                "live_receipt_binding_stable",
                "cleanup_reconciled",
            )
        )
        and len(process_identities) == len(set(process_identities))
        and all(
            int(identity["process_id"]) != client_process_id
            for name, identity in identities.items()
            if name != "client"
        )
        and row.get("witness_digest") == content_hash(body)
        and _path_free(row),
        "recovery witness validation is inconsistent",
    )


__all__ = [
    "CleanedRecoveryInspection",
    "LiveRecoveryInspection",
    "RecoveryWitnessError",
    "WITNESS_SCHEMA",
    "build_witness_validation",
    "capture_process_identity",
    "inspect_cleaned_recovery",
    "inspect_continuation",
    "inspect_live_recovery",
    "process_identity_running",
    "require_process_absent",
    "stopped_process_facts",
    "validate_witness_validation",
]
