"""Fixed one-shot correction child; no setup, credential or rollback entry."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import time
from pathlib import Path
from typing import BinaryIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent.parent))

import bluefire._windows_file_access_native_contract as contract
import bluefire._windows_file_access_setup_binding as supervision
import bluefire.windows_file_access_correction_admission as admission
import bluefire.windows_file_access_enrollment as enrollment
import bluefire.windows_file_access_enrollment_native as native
import bluefire.windows_file_access_enrollment_setup as setup
import bluefire.windows_file_access_pair_admission as pair
import bluefire.windows_session_facts as session
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_file_access_control import (
    WindowsControlRequest,
    transition_windows_file_access,
)
from bluefire.windows_file_access_correction_capability import held_correction_capability
from bluefire.windows_file_access_correction_contract import (
    OUTPUT_MAX as OUTPUT_MAX,
)
from bluefire.windows_file_access_correction_contract import (
    RESULT_SCHEMA as RESULT_SCHEMA,
)
from bluefire.windows_file_access_correction_contract import (
    validate_terminal as validate_terminal,
)
from bluefire.windows_file_access_policy import WindowsFileAccessPolicy
from bluefire.windows_file_access_read import WindowsResourceExpectation
from bluefire.windows_file_access_setup_child import _read

REQUEST_SCHEMA = "bluefire.windows-file-correction-child-request.v1"
INPUT_MAX = 65536


def _current(binding: dict, deadline_ns: int) -> int:
    now = time.time_ns() // 1_000_000
    contract._require(
        binding["issued_at_ms"] <= now < binding["expires_at_ms"]
        and time.monotonic_ns() < deadline_ns
    )
    return now


def _request(raw: bytes) -> dict:
    row = contract._exact(
        contract._document(raw, INPUT_MAX),
        "schema_version original_record original_receipt binding original_deadline_ns supervision",
    )
    contract._require(row["schema_version"] == REQUEST_SCHEMA)
    pair._document(row["original_record"])
    contract._document(row["original_receipt"], 16384)
    binding = contract._document(row["binding"])
    deadline = contract._int(row["original_deadline_ns"], 1, 2**63 - 1)
    remaining = deadline - time.monotonic_ns()
    contract._require(0 < remaining <= admission.OPERATION_MS * 1_000_000)
    _current(binding, deadline)
    supervision._document(row["supervision"])
    return row


def _identity(value: dict) -> tuple[int, int]:
    return int(value["volume_serial"], 16), int.from_bytes(
        bytes.fromhex(value["file_id"]), "little"
    )


def _derive(row: dict) -> dict:
    deadline = row["original_deadline_ns"]
    checked = enrollment.read_windows_file_pair_enrollment(
        now_ms=_current(row["binding"], deadline),
        deadline=deadline / 1_000_000_000,
        cancelled=lambda: False,
    )
    contract._require(
        checked._raw == canonical_json_bytes(row["original_record"])
        and checked._receipt == canonical_json_bytes(row["original_receipt"])
    )
    record, _ = pair.checked_provenance(checked)
    binding = admission.validate_correction_binding(row["binding"], checked)
    resource = record["resource"]
    contract._require(
        resource["size_bytes"] == len(setup._CONTENT)
        and resource["sha256"] == "sha256:" + hashlib.sha256(setup._CONTENT).hexdigest()
    )
    owner = session.current_process_principal()
    owner.validate()
    expectation = WindowsResourceExpectation(
        record["generation"],
        WindowsFileAccessPolicy(resource["owner_sid"], resource["reader_sid"]),
        tuple(_identity(value) for value in resource["ancestors"]),
        _identity(resource["file_identity"]),
        resource["size_bytes"],
        resource["sha256"],
        setup._CONTENT.count(b"\n"),
        "readable",
    )
    request = WindowsControlRequest(
        expectation, owner, binding["previous_descriptor_sha256"], "metadata_only"
    )
    admitted = False

    def original_guard() -> None:
        _current(binding, deadline)
        contract._require(session.current_process_principal() == owner)
        contract._require(admission.validate_correction_binding(row["binding"], checked) == binding)
        capability_current()
        _current(binding, deadline)

    def admit() -> None:
        nonlocal admitted
        contract._require(not admitted)
        original_guard()
        admitted = True

    # The parent's retained Job enforces the original hard deadline around the
    # primitive's at-most-five-second cooperative setter interval.
    with held_correction_capability(
        checked,
        original_deadline=deadline / 1_000_000_000,
        expires_at_ms=binding["expires_at_ms"],
        cancelled=lambda: False,
    ) as capability_current:
        observed = transition_windows_file_access(request, admit=admit, before_apply=original_guard)
    _current(binding, deadline)
    contract._require(admitted and session.current_process_principal() == owner)
    volume, file_id = native.file_identity_wire(*observed.file_identity)
    return {
        "before_descriptor_sha256": observed.before_descriptor_sha256,
        "after_descriptor_sha256": observed.after_descriptor_sha256,
        "target": observed.target,
        "file_identity": {"volume_serial": volume, "file_id": file_id},
        "preserved_sha256": observed.preserved_sha256,
        "fresh_owner_read": observed.fresh_owner_read,
        "read_handles_closed": observed.read_handles_closed,
    }


def _run(stdin: BinaryIO, stdout: BinaryIO) -> int:
    binding_digest = None
    result = None
    try:
        size = struct.unpack("<I", _read(stdin, 4))[0]
        contract._require(0 < size <= INPUT_MAX)
        raw = _read(stdin, size)
        contract._require(stdin.read(1) == b"")
        row = _request(raw)
        binding_digest = content_hash(row["binding"])
        with supervision.require_child_handoff(row["supervision"]):
            result = _derive(_request(raw))
        terminal = validate_terminal(
            {"schema_version": RESULT_SCHEMA, "binding_digest": binding_digest, "result": result},
            row["binding"],
            0,
        )
        code = 0
    except Exception:
        terminal = {
            "schema_version": RESULT_SCHEMA,
            "binding_digest": binding_digest,
            "result": None,
        }
        code = 4
    payload = canonical_json_bytes(terminal)
    contract._require(len(payload) <= OUTPUT_MAX)
    data = memoryview(struct.pack("<I", len(payload)) + payload)
    while data:
        written = stdout.write(data)
        contract._require(type(written) is int and 0 < written <= len(data))
        data = data[written:]
    stdout.flush()
    return code


def main() -> int:
    if (
        sys.platform != "win32"
        or not sys.flags.isolated
        or __package__ not in {None, ""}
        or len(sys.argv) != 1
        or not Path(sys.argv[0]).is_absolute()
        or os.path.normcase(sys.argv[0]) != os.path.normcase(__file__)
    ):
        return 4
    try:
        return _run(sys.stdin.buffer, sys.stdout.buffer)
    except Exception:
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
