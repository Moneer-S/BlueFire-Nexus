from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from bluefire.strix_adapter import StrixAdapterError
from bluefire.strix_run_bytes import MAX_COVERAGE_BYTES, MAX_RUN_BYTES, parse_strix_run_bytes

TARGET = "https://lab.example.test"
INSTRUCTION = "Assess only the admitted lab."
INSTRUCTION_DIGEST = "sha256:" + hashlib.sha256((INSTRUCTION + "\n").encode()).hexdigest()


def _run(**changes: Any) -> bytes:
    record: dict[str, Any] = {
        "run_id": "upstream-run-1",
        "run_name": "upstream-run-1",
        "status": "completed",
        "non_interactive": True,
        "scan_mode": "quick",
        "scope_mode": "full",
        "targets_info": [
            {
                "type": "web_application",
                "original": TARGET,
                "details": {"target_url": TARGET},
            }
        ],
        "instruction": INSTRUCTION,
    }
    record.update(changes)
    return json.dumps(record).encode()


def _coverage(**changes: Any) -> bytes:
    completeness: dict[str, Any] = {
        "complete": True,
        "scan_status": "completed",
        "exit_reason": "completed",
        "caveats": [],
    }
    completeness.update(changes)
    return json.dumps(
        {
            "run_id": "upstream-run-1",
            "run_name": "upstream-run-1",
            "completeness": completeness,
        }
    ).encode()


def _parse(run_bytes: bytes, coverage_bytes: bytes | None):
    return parse_strix_run_bytes(
        run_bytes,
        coverage_bytes,
        upstream_run_id="upstream-run-1",
        expected_target=TARGET,
        expected_instruction_sha256=INSTRUCTION_DIGEST,
        process_exit_code=0,
        cessation_verified=True,
    )


def test_projection_uses_exact_bytes_and_sanitizes_engine_text() -> None:
    run_bytes = _run()
    coverage_bytes = _coverage(
        caveats=["token=secret-url-and-credential"], exit_reason="token=secret"
    )
    snapshot = _parse(run_bytes, coverage_bytes)

    assert snapshot.attempt_state == "completed"
    assert snapshot.run_record_sha256 == "sha256:" + hashlib.sha256(run_bytes).hexdigest()
    assert snapshot.coverage_sha256 == "sha256:" + hashlib.sha256(coverage_bytes).hexdigest()
    assert snapshot.exit_reason == "engine_reported_other"
    assert snapshot.caveats == ("Strix reported scan coverage caveats.",)
    assert "secret" not in json.dumps(snapshot.to_dict())


@pytest.mark.parametrize(
    ("run_bytes", "coverage_bytes"),
    [
        (_run(status=[]), _coverage()),
        (_run(), _coverage(scan_status=[])),
        (b'{"run_id":"a","run_id":"b"}', _coverage()),
        (_run(), b'{"run_id":"a","run_id":"b"}'),
        (_run(status=float("nan")), _coverage()),
        (_run()[:-1] + b',"ignored":1e999}', _coverage()),
        (_run(), _coverage()[:-1] + b',"ignored":1e999}'),
        (_run(), _coverage(caveats=["x"] * 65)),
        (_run(instruction="another objective"), _coverage()),
        (_run() + b" " * MAX_RUN_BYTES, _coverage()),
        (_run(), _coverage() + b" " * MAX_COVERAGE_BYTES),
    ],
    ids=(
        "run-status-type",
        "coverage-status-type",
        "duplicate-run-key",
        "duplicate-coverage-key",
        "nan",
        "nonfinite-run-float",
        "nonfinite-coverage-float",
        "too-many-caveats",
        "objective-drift",
        "run-size",
        "coverage-size",
    ),
)
def test_rejects_invalid_or_unbounded_untrusted_bytes(
    run_bytes: bytes, coverage_bytes: bytes
) -> None:
    with pytest.raises(StrixAdapterError):
        _parse(run_bytes, coverage_bytes)
