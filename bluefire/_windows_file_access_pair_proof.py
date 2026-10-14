"""Pure phase proof checks; phases have no independently observed process exit.

Only the outer terminal has the actual child return code. No proof establishes
authenticated admission, independent observation, or owned Job closure.
"""

from __future__ import annotations

from typing import Any, cast

from ._windows_file_access_native_contract import (
    _PAIR,
    ISSUES,
    PROOF_SCHEMA,
    STAGES,
    _digest,
    _exact,
    _int,
    _require,
)

PAIR_ISSUES = ISSUES | frozenset(
    "pair_resource_or_credential_invalid phase_snapshot_missing resource_pair_drift owner_phase_unsupported owner_phase_not_ready".split()
)
PAIR_STAGES = STAGES | frozenset(
    "pair_boundary pair_recheck owner_context owner_metadata owner_read owner_recheck".split()
)


def _cleanup(value: Any) -> bool:
    row = _exact(
        value,
        "handles_released impersonation_reverted controller_restored owned_process_exit_required",
    )
    _require(all(type(v) is bool for v in row.values()))
    clean = all(
        row[key] for key in ("handles_released", "impersonation_reverted", "controller_restored")
    )
    _require(row["owned_process_exit_required"] == (not clean))
    return clean


def _failure(row: dict[str, Any], clean: bool, *, paired: bool) -> None:
    _require(type(row["issue"]) is str and row["issue"] in (PAIR_ISSUES if paired else ISSUES))
    _require(
        type(row["failed_stage"]) is str
        and row["failed_stage"] in (PAIR_STAGES if paired else STAGES)
    )
    _require((row["issue"] == "cleanup_unknown") == (not clean))
    _require(clean or row["failed_stage"] == "cleanup")


def reader_phase(row: Any, request: dict[str, Any], *, paired: bool = False) -> tuple[str, bool]:
    row = _exact(
        row,
        "schema_version request_id outcome issue failed_stage data_open_attempted bytes_read observed_sha256 effective_reader_verified resource_rechecked independent_observation cleanup",
    )
    _require(row["schema_version"] == PROOF_SCHEMA and row["request_id"] == request["request_id"])
    for key in (
        "data_open_attempted",
        "effective_reader_verified",
        "resource_rechecked",
        "independent_observation",
    ):
        _require(type(row[key]) is bool)
    _require(row["independent_observation"] is False)
    clean = _cleanup(row["cleanup"])
    size = request["resource"]["size_bytes"]
    count = _int(row["bytes_read"], 0, size)
    digest = row["observed_sha256"]
    if digest is not None:
        _digest(digest)
        _require(count == size and row["data_open_attempted"] and row["effective_reader_verified"])
    _require(
        not row["resource_rechecked"]
        or (row["data_open_attempted"] and row["effective_reader_verified"])
    )
    _require(not count or (row["data_open_attempted"] and row["effective_reader_verified"]))
    outcome = row["outcome"]
    _require(outcome in ("allowed", "data_access_denied", "unknown"))
    if outcome == "unknown":
        _failure(row, clean, paired=paired)
    else:
        _require(
            row["issue"] is None
            and row["failed_stage"] is None
            and clean
            and row["data_open_attempted"]
            and row["effective_reader_verified"]
            and row["resource_rechecked"]
        )
        _require(
            (count == size and digest == request["resource"]["sha256"])
            if outcome == "allowed"
            else (count == 0 and digest is None)
        )
    return cast(str, outcome), clean


def _owner_phase(row: Any, request: dict[str, Any]) -> str:
    row = _exact(
        row,
        "schema_version outcome issue failed_stage data_open_attempted bytes_read observed_sha256 original_owner_verified no_thread_token_verified resource_rechecked",
    )
    _require(row["schema_version"] == "bluefire.windows-fixed-owner-read.v2")
    for key in (
        "data_open_attempted",
        "original_owner_verified",
        "no_thread_token_verified",
        "resource_rechecked",
    ):
        _require(type(row[key]) is bool)
    count = _int(row["bytes_read"], 0, request["resource"]["size_bytes"])
    identity = row["original_owner_verified"] and row["no_thread_token_verified"]
    _require(not row["data_open_attempted"] or identity)
    _require(not count or row["data_open_attempted"])
    _require(not row["resource_rechecked"] or row["data_open_attempted"])
    if row["observed_sha256"] is not None:
        _digest(row["observed_sha256"])
        _require(count == request["resource"]["size_bytes"] and row["data_open_attempted"])
    _require(row["outcome"] in ("allowed", "unknown"))
    if row["outcome"] == "allowed":
        _require(
            row["issue"] is None
            and row["failed_stage"] is None
            and identity
            and row["data_open_attempted"]
            and row["resource_rechecked"]
            and count == request["resource"]["size_bytes"]
            and row["observed_sha256"] == request["resource"]["sha256"]
        )
    else:
        if row["issue"] is None or row["failed_stage"] is None:
            _require(
                row["issue"] is None
                and row["failed_stage"] is None
                and not row["data_open_attempted"]
                and count == 0
                and row["observed_sha256"] is None
                and not row["original_owner_verified"]
                and not row["no_thread_token_verified"]
                and not row["resource_rechecked"]
            )
        else:
            _require(
                type(row["issue"]) is str
                and row["issue"] in PAIR_ISSUES
                and type(row["failed_stage"]) is str
                and row["failed_stage"] in PAIR_STAGES
            )
    return cast(str, row["outcome"])


def pair_proof(
    row: Any, request: dict[str, Any], returncode: int
) -> tuple[str, bool, str, str, str]:
    row = _exact(
        row,
        "schema_version request_id outcome issue failed_stage reader owner resource_pair_rechecked independent_observation cleanup",
    )
    _require(row["schema_version"] == _PAIR.proof and row["request_id"] == request["request_id"])
    _require(
        type(row["resource_pair_rechecked"]) is bool and row["independent_observation"] is False
    )
    clean = _cleanup(row["cleanup"])
    reader, reader_clean = reader_phase(row["reader"], request, paired=True)
    owner = _owner_phase(row["owner"], request)
    _require(reader_clean or not clean)
    _require(row["owner"]["issue"] != "cleanup_unknown" or not clean)
    _int(row["reader"]["bytes_read"] + row["owner"]["bytes_read"], 0, 2097152)
    if reader == "unknown" or not reader_clean:
        _require(owner == "unknown" and row["owner"]["data_open_attempted"] is False)
    if row["resource_pair_rechecked"]:
        _require(reader != "unknown" and reader_clean and owner == "allowed")
    outcome = row["outcome"]
    _require(outcome in ("allowed", "data_access_denied", "unknown"))
    if outcome == "unknown":
        _require(returncode == 4)
        _failure(row, clean, paired=True)
    else:
        _require(
            returncode == 0
            and row["issue"] is None
            and row["failed_stage"] is None
            and clean
            and reader_clean
            and row["resource_pair_rechecked"]
            and owner == "allowed"
            and outcome == reader
        )
    return (
        cast(str, outcome),
        outcome != "unknown",
        "verified" if clean else "unknown",
        reader,
        owner,
    )
