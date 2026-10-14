"""Fixed packaged setup entry; clocks constrain work and never confer authority."""

from __future__ import annotations

import math
import os
import struct
import sys
import time
from pathlib import Path
from typing import BinaryIO

# Match the existing packaged watchdog's isolated sibling bootstrap. The
# installed application/import closure is trusted, never a caller module path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent.parent))

import bluefire._windows_file_access_native_contract as contract
import bluefire._windows_file_access_setup_binding as binding
import bluefire.windows_file_access_admission as admission
from bluefire.util import canonical_json_bytes

REQUEST_SCHEMA = "bluefire.windows-file-setup-child-request.v1"
RESULT_SCHEMA = "bluefire.windows-file-setup-child-result.v1"
INPUT_MAX = 1024
OUTPUT_MAX = 8192
INTERVAL_MS = 5000


def _managed_root() -> Path:
    from bluefire.runner_bootstrap import managed_product_root
    from bluefire.runtime_paths import runtime_temp_parent

    # This existing OS-token query is independent of LOCALAPPDATA/USERPROFILE.
    return managed_product_root(
        environ={"LOCALAPPDATA": str(runtime_temp_parent().parent)}, platform_name="windows"
    )


def _request(raw: bytes) -> dict:
    return _request_for(raw, admission._READER_SETUP)


def _request_for(raw: bytes, protocol: admission._SetupProtocol) -> dict:
    admission._setup_protocol(protocol)
    row = contract._document(raw, INPUT_MAX)
    contract._exact(
        row,
        "schema_version profile_id confirm_create original_issued_at_ms original_deadline_ns supervision",
    )
    contract._require(
        row["schema_version"] == protocol.schema("setup-child-request")
        and row["confirm_create"] is True
    )
    contract._identifier(row["profile_id"])
    issued = contract._int(row["original_issued_at_ms"], 1, 2**63 - 1 - INTERVAL_MS)
    deadline = contract._int(row["original_deadline_ns"], 1, 2**63 - 1)
    remaining = deadline - time.monotonic_ns()
    contract._require(0 < remaining <= INTERVAL_MS * 1_000_000)
    contract._require(issued <= time.time_ns() // 1_000_000 < issued + INTERVAL_MS)
    contract._require(math.isfinite(deadline / 1_000_000_000))
    binding._document(row["supervision"])
    return row


def _read(stream: BinaryIO, count: int) -> bytes:
    value = bytearray()
    while len(value) < count:
        part = stream.read(count - len(value))
        contract._require(type(part) is bytes and 0 < len(part) <= count - len(value))
        value.extend(part)
    return bytes(value)


def _derive(row: dict) -> dict:
    return _derive_for(row, admission._READER_SETUP)


def _derive_for(row: dict, protocol: admission._SetupProtocol) -> dict:
    from bluefire.runner_lifecycle import ManagedRunnerLifecycle
    from bluefire.windows_file_access_enrollment_setup import (
        _run_local_pair_setup_child,
        _run_local_setup_child,
    )

    admission._setup_protocol(protocol)
    producer = (
        _run_local_setup_child
        if protocol is admission._READER_SETUP
        else _run_local_pair_setup_child
    )
    return producer(
        row["profile_id"],
        lifecycle=ManagedRunnerLifecycle(_managed_root()),
        original_issued_at_ms=row["original_issued_at_ms"],
        original_deadline=row["original_deadline_ns"] / 1_000_000_000,
    )


def _run(stdin: BinaryIO, stdout: BinaryIO) -> int:
    return _run_for(stdin, stdout, admission._READER_SETUP)


def _run_for(stdin: BinaryIO, stdout: BinaryIO, protocol: admission._SetupProtocol) -> int:
    from bluefire.windows_file_access_enrollment_setup import WindowsFileSetupError

    admission._setup_protocol(protocol)
    try:
        size = struct.unpack("<I", _read(stdin, 4))[0]
        contract._require(0 < size <= INPUT_MAX)
        raw = _read(stdin, size)
        contract._require(stdin.read(1) == b"")
        row = _request_for(raw, protocol)
        with binding.require_child_handoff(row["supervision"]):
            # OS observation/closure may consume time; never reset the interval.
            current = _request_for(raw, protocol)
            result = (
                _derive(current)
                if protocol is admission._READER_SETUP
                else _derive_for(current, protocol)
            )
        response = {
            "schema_version": protocol.schema("setup-child-result"),
            "result": result,
            "error": None,
        }
        code = 0
    except WindowsFileSetupError as exc:
        response = {
            "schema_version": protocol.schema("setup-child-result"),
            "result": None,
            "error": {
                "stage": exc.stage,
                "bootstrap_mutated": exc.bootstrap_mutated,
                "intent_persisted": exc.intent_persisted,
            },
        }
        code = 4
    except Exception:
        # Unknown exceptions cannot establish absence of privileged effects.
        response = {
            "schema_version": protocol.schema("setup-child-result"),
            "result": None,
            "error": None,
        }
        code = 4
    payload = canonical_json_bytes(response)
    contract._require(len(payload) <= OUTPUT_MAX)
    framed = memoryview(struct.pack("<I", len(payload)) + payload)
    while framed:
        written = stdout.write(framed)
        contract._require(type(written) is int and 0 < written <= len(framed))
        framed = framed[written:]
    stdout.flush()
    return code


def main() -> int:
    # Filename/isolated-mode checks constrain the entry, not its authority. _run
    # still requires the actual Job, creator generation and retained pipe objects.
    if (
        sys.platform != "win32"
        or not sys.flags.isolated
        or __package__ not in {None, ""}
        or not (len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == "--pair-baseline-v2"))
        or not Path(sys.argv[0]).is_absolute()
        or os.path.normcase(sys.argv[0]) != os.path.normcase(__file__)
    ):
        return 4
    try:
        if len(sys.argv) == 1:
            return _run(sys.stdin.buffer, sys.stdout.buffer)
        return _run_for(sys.stdin.buffer, sys.stdout.buffer, admission._PAIR_SETUP)
    except Exception:
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
