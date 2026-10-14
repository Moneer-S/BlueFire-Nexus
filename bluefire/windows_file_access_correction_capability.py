"""Held-image v3 protocol query inside the already-owned correction child's Job.

Temporary streams bound decoding, not subprocess disk writes. The original
whole-Job supervisor is the only hard deadline and descendant cleanup authority.
Compiled protocol support never establishes effective access or correction proof.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - fixed pinned image and no-argument capability command
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from . import _windows_file_access_enrollment_observe as observe
from . import _windows_file_access_native_contract as contract
from . import _windows_file_access_setup_binding as supervision
from . import windows_file_access_admission as original
from . import windows_file_access_correction_admission as correction
from . import windows_file_access_enrollment_native as native
from . import windows_file_access_handles as handles
from . import windows_file_access_pair_admission as pair
from . import windows_session_facts as session

_COMMAND = "windows-file-correction-worker-capability"
_MAX_OUTPUT = 1024


class WindowsCorrectionCapabilityError(RuntimeError):
    """Path-free failure; unsupported or uncertain never permits the setter."""


def _capability(raw: bytes, version: str) -> dict:
    protocol = contract._CORRECTION
    expected = {
        "schema_version": "bluefire.windows-file-worker-capability.v3",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": version,
        "platform": "windows",
        "architecture": "x86_64",
        "supported": True,
        "worker_command": "windows-file-correction-worker",
        "worker_schema": protocol.schema("request"),
        "read_schema": protocol.proof,
        "scope": "protocol_support_only",
        "action_id": protocol.action,
        "capability": protocol.capability,
        "max_data_opens": 2,
        "max_bytes_per_read": 1048576,
        "max_total_read_bytes": 2097152,
        "max_execution_ms": 5000,
    }
    row = contract._exact(contract._document(raw, _MAX_OUTPUT), " ".join(expected))
    contract._require(row == expected and type(row["supported"]) is bool)
    for name in (
        "max_data_opens",
        "max_bytes_per_read",
        "max_total_read_bytes",
        "max_execution_ms",
    ):
        contract._require(type(row[name]) is int)
    return row


class _ImagePins:
    """Read-only adapter for the established image/hash/channel join."""

    def __init__(self, current: Callable[[], None]) -> None:
        self.current = current
        self.held: list[int] = []
        self.observed: dict[str, tuple[object, bool]] = {}

    def observe(self, path: str, *, directory: bool, protected: bool = False) -> dict:
        contract._require(protected is False and len(self.held) < 96)
        self.current()
        descriptor = handles.open_observation(Path(path), directory=directory, data=not directory)
        self.held.append(descriptor)
        facts = handles.inspect_observation(descriptor, directory=directory)
        contract._require(facts.final_path == "\\\\?\\" + path)
        previous = self.observed.get(path)
        if previous is not None:
            contract._require(previous == (facts, directory))
        self.observed[path] = (facts, directory)
        volume, file_id = native.file_identity_wire(*facts.identity)
        self.current()
        return {"identity": {"volume_serial": volume, "file_id": file_id}, "size": facts.size}

    def verify_all(self) -> None:
        for path, (_, directory) in list(self.observed.items()):
            self.observe(path, directory=directory)
        self.current()

    def close(self) -> None:
        failed = False
        for descriptor in reversed(self.held):
            try:
                os.close(descriptor)
            except Exception:
                failed = True
        self.held.clear()
        contract._require(not failed)


def _query(path: Path, version: str, deadline: float) -> dict:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        remaining = deadline - time.monotonic()
        contract._require(0 < remaining <= 5)
        supervision._Api().current_job()
        result = subprocess.run(  # nosec B603 - exact held source image, fixed private query
            [os.fspath(path), _COMMAND],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            timeout=remaining,
            check=False,
            shell=False,
            close_fds=True,
            creationflags=0x08000000,
        )
        contract._require(time.monotonic() < deadline)
        supervision._Api().current_job()
        output.seek(0)
        errors.seek(0)
        contract._require(result.returncode == 0 and errors.read(1) == b"")
        return _capability(output.read(_MAX_OUTPUT + 1), version)


@contextmanager
def held_correction_capability(
    checked: pair.VerifiedWindowsPairSetup,
    *,
    original_deadline: float,
    expires_at_ms: int,
    cancelled: Callable[[], bool],
) -> Iterator[Callable[[], None]]:
    """Hold original image/ancestry through setter; rechecks never query again.

    Only the fixed child, after its actual creator/Job/pipe handoff, calls this
    private boundary. Job membership alone is not original dispatch authority.
    """
    backend = None
    try:
        record, receipt = pair.checked_provenance(checked)
        contract._mono(original_deadline)
        now = time.time_ns() // 1_000_000
        contract._require(
            0 < original_deadline - time.monotonic() <= correction.OPERATION_MS / 1000
        )
        contract._int(
            expires_at_ms, now + 1, min(record["expires_at_ms"], now + correction.OPERATION_MS)
        )
        owner = session.current_process_principal()
        owner.validate()
        contract._require(
            owner.elevated is False and owner.user_sid == record["resource"]["owner_sid"]
        )
        gate = native._Gate(min(original_deadline, time.monotonic() + 5.0), cancelled)

        def current() -> None:
            stopped = cancelled()
            contract._require(
                type(stopped) is bool
                and not stopped
                and record["issued_at_ms"] <= time.time_ns() // 1_000_000 < expires_at_ms
                and session.current_process_principal() == owner
                and time.monotonic() < original_deadline
            )

        current()
        supervision._Api().current_job()
        lifecycle = observe.ManagedRunnerLifecycle(observe._managed_root())
        bootstrap = lifecycle._load_bootstrap(lifecycle._load_active_enrollment())
        path = Path(bootstrap.binary_path)
        contract._require(
            path.is_absolute()
            and path.name == "bluefire-runner.exe"
            and 1 <= len(path.parents) <= 16
        )
        backend = _ImagePins(current)
        for ancestor in reversed(path.parents):
            backend.observe(os.fspath(ancestor), directory=True)
        joined_lifecycle, client = observe._image_and_channel(
            backend, receipt, gate, original._PAIR_SETUP
        )
        source = receipt["source"]
        contract._require(
            backend.observe(os.fspath(path), directory=False)
            == {
                "identity": source["native_image"]["identity"],
                "size": source["native_image"]["size_bytes"],
            }
        )
        query_deadline = min(original_deadline, time.monotonic() + 5.0)
        _query(path, source["capability"]["runner_version"], query_deadline)

        def recheck() -> None:
            current()
            backend.verify_all()
            fresh = joined_lifecycle._load_bootstrap(joined_lifecycle._load_active_enrollment())
            contract._require(
                Path(fresh.binary_path) == path
                and fresh.source == "packaged"
                and fresh.managed_binary
                and fresh.binary_digest == source["native_image"]["sha256"]
                and fresh.runner_version == source["capability"]["runner_version"]
            )
            again, _ = joined_lifecycle.client_for_profile(source["source_profile_id"])
            contract._require(
                dict(again.transport_identity())
                == dict(client.transport_identity())
                == source["transport"]
            )
            supervision._Api().current_job()
            current()

        recheck()
        yield recheck
        recheck()
    except Exception:
        raise WindowsCorrectionCapabilityError(
            "Windows correction protocol support is unavailable."
        ) from None
    finally:
        if backend is not None:
            try:
                backend.close()
            except Exception:
                raise WindowsCorrectionCapabilityError(
                    "Windows correction image cleanup is unknown."
                ) from None
