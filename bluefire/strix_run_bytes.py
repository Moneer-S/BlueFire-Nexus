"""Pure bounded projection of Strix run and coverage artifact bytes.

The same function consumes bytes returned by the verified artifact store in
live settlement and claimed recovery. No source path or engine supplied text
is trusted as a controller observation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .strix_adapter import (
    STRIX_SUPPORTED_STATUSES,
    StrixAdapterError,
    _canonical_target_origin,
    _require_digest,
)

MAX_RUN_BYTES = 2 * 1024 * 1024
MAX_COVERAGE_BYTES = 4 * 1024 * 1024
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PUBLIC_EXIT_REASONS = frozenset(
    {
        "completed",
        "stopped",
        "interrupted",
        "failed",
        "budget_exceeded",
        "max_budget_exceeded",
        "max_turns_exceeded",
    }
)


@dataclass(frozen=True, slots=True)
class StrixRunByteSnapshot:
    upstream_run_id: str
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


def _json_bytes(payload: bytes, *, maximum: int, label: str) -> tuple[Any, str]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= maximum:
        raise StrixAdapterError(f"Strix {label} artifact exceeds its byte limit")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise StrixAdapterError(f"Strix {label} artifact repeats a JSON key")
            document[key] = value
        return document

    def invalid_constant(_value: str) -> None:
        raise StrixAdapterError(f"Strix {label} artifact has a non-finite value")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise StrixAdapterError(f"Strix {label} artifact has a non-finite value")
        return parsed

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=invalid_constant,
            parse_float=finite_float,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise StrixAdapterError(f"Strix {label} artifact is unreadable") from None
    return document, "sha256:" + hashlib.sha256(payload).hexdigest()


def parse_strix_run_bytes(
    run_bytes: bytes,
    coverage_bytes: bytes | None,
    *,
    upstream_run_id: str,
    expected_target: str,
    expected_instruction_sha256: str,
    process_exit_code: int | None,
    cancellation_requested: bool = False,
    cessation_verified: bool = False,
) -> StrixRunByteSnapshot:
    """Project one exact run from verified payloads without filesystem access."""

    if not isinstance(upstream_run_id, str) or _RUN_ID.fullmatch(upstream_run_id) is None:
        raise StrixAdapterError("Strix upstream run identity is invalid")
    _canonical_target_origin(expected_target, "Strix expected target")
    _require_digest(expected_instruction_sha256, "Strix expected instruction")
    if process_exit_code is not None and (
        isinstance(process_exit_code, bool)
        or not isinstance(process_exit_code, int)
        or not -255 <= process_exit_code <= 255
    ):
        raise StrixAdapterError("Strix process exit code is invalid")
    record, run_digest = _json_bytes(run_bytes, maximum=MAX_RUN_BYTES, label="run")
    if not isinstance(record, Mapping):
        raise StrixAdapterError("Strix run artifact must be an object")
    status = record.get("status")
    targets = record.get("targets_info")
    instruction = record.get("instruction")
    if (
        record.get("run_id") != upstream_run_id
        or record.get("run_name") != upstream_run_id
        or not isinstance(status, str)
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

    coverage_digest: str | None = None
    complete = False
    exit_reason: str | None = None
    caveats: list[str] = []
    if coverage_bytes is None:
        caveats.append("Strix coverage artifact is unavailable.")
    else:
        coverage, coverage_digest = _json_bytes(
            coverage_bytes, maximum=MAX_COVERAGE_BYTES, label="coverage"
        )
        if not isinstance(coverage, Mapping):
            raise StrixAdapterError("Strix coverage artifact must be an object")
        if coverage.get("run_id") != upstream_run_id or coverage.get("run_name") != upstream_run_id:
            raise StrixAdapterError("Strix coverage artifact names another run")
        completeness_record = coverage.get("completeness")
        if not isinstance(completeness_record, Mapping):
            raise StrixAdapterError("Strix coverage artifact has no completeness record")
        raw_complete = completeness_record.get("complete")
        scan_status = completeness_record.get("scan_status")
        raw_exit_reason = completeness_record.get("exit_reason")
        raw_caveats = completeness_record.get("caveats")
        if (
            type(raw_complete) is not bool
            or not isinstance(scan_status, str)
            or scan_status not in STRIX_SUPPORTED_STATUSES
            or scan_status != status
            or (
                raw_exit_reason is not None
                and (not isinstance(raw_exit_reason, str) or len(raw_exit_reason) > 100)
            )
            or not isinstance(raw_caveats, list)
            or len(raw_caveats) > 64
            or any(not isinstance(item, str) or len(item) > 2048 for item in raw_caveats)
        ):
            raise StrixAdapterError("Strix coverage completeness is invalid")
        complete = raw_complete
        exit_reason = (
            raw_exit_reason
            if raw_exit_reason in _PUBLIC_EXIT_REASONS
            else "engine_reported_other"
            if raw_exit_reason is not None
            else None
        )
        if raw_caveats:
            caveats.append("Strix reported scan coverage caveats.")

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

    if status == "running" and process_exit_code is None:
        attempt_state, completeness = "running", "unknown"
    elif status == "running":
        attempt_state, completeness = "unknown", "unknown"
        caveats.append("The process exited but the persisted run still reports running.")
    elif cancellation_requested and cessation_verified and status in {"stopped", "interrupted"}:
        attempt_state, completeness = "cancelled", "partial"
    elif exit_reason in {"budget_exceeded", "max_budget_exceeded", "max_turns_exceeded"}:
        attempt_state, completeness = "budget_exhausted", "partial"
    elif status == "failed":
        attempt_state, completeness = "failed", "partial"
    elif status in {"stopped", "interrupted"}:
        attempt_state, completeness = "partial", "partial"
    elif status == "completed" and complete and process_exit_code in {0, 2}:
        attempt_state, completeness = "completed", "complete"
    else:
        attempt_state, completeness = "unknown", "unknown"
    if cancellation_requested and not cessation_verified:
        caveats.append("Cancellation was requested, but owned-work cessation is unverified.")

    return StrixRunByteSnapshot(
        upstream_run_id=upstream_run_id,
        engine_status=status,
        attempt_state=attempt_state,
        completeness=completeness,
        exit_reason=exit_reason,
        process_exit_code=process_exit_code,
        process_classification=process_classification,
        engine_reported_findings=findings,
        security_outcome="not_independently_established",
        caveats=tuple(caveats),
        run_record_sha256=run_digest,
        coverage_sha256=coverage_digest,
    )
