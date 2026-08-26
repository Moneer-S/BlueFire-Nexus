"""Process-boundary fixture for managed-runner lifecycle tests only."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from bluefire.runner_host import serve_managed_runner
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.secret_store import SecretStoreError

_PREFIX = b"bluefire-process-test-only-v1\0"


class ProcessTestSecretProvider:
    """Stateless cross-process provider that is intentionally test-only."""

    @property
    def provider_id(self) -> str:
        return "process-test-only.v1"

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise SecretStoreError("Test secret is invalid.")
        digest = hashlib.sha256(purpose.encode("utf-8")).digest()
        return _PREFIX + digest + plaintext

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        digest = hashlib.sha256(purpose.encode("utf-8")).digest()
        prefix = _PREFIX + digest
        if not isinstance(opaque, bytes) or not hmac.compare_digest(opaque[: len(prefix)], prefix):
            raise SecretStoreError("Test secret is invalid.")
        return opaque[len(prefix) :]


class ProcessFixtureRunner:
    def __init__(self, binary: Path, platform_name: str) -> None:
        self.runner_binary = binary
        self.platform_name = platform_name

    def inventory(self) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": "0.1.0",
            "action_sdk_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "platform": self.platform_name,
            "actions": [
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": "sandbox.fixture.create.v1",
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS["sandbox.fixture.create.v1"],
                    "readiness": "ready",
                }
            ],
        }

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        raise RuntimeError("The lifecycle process fixture does not execute effects.")


def main(argv: Sequence[str] | None = None) -> int:
    values = tuple(sys.argv[1:] if argv is None else argv)
    if len(values) == 3 and values[0] == "descendant-hang":
        gate = Path(values[1])
        pid_path = Path(values[2])
        deadline = time.monotonic() + 30.0
        while gate.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        child = subprocess.Popen(  # nosec B603
            [str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(120)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        pid_path.write_text(str(child.pid), encoding="ascii")
        while True:
            time.sleep(1.0)
    if len(values) != 9:
        return 2
    enrollment, binary, work, state, record, gate, launch_id, platform_name, timeout = values
    provider = ProcessTestSecretProvider()
    binary_path = Path(binary).resolve(strict=True)
    serve_managed_runner(
        enrollment_root=enrollment,
        runner_binary=binary_path,
        work_root=work,
        state_path=state,
        process_record_path=record,
        start_gate_path=gate,
        launch_id=launch_id,
        runner_timeout_seconds=float(timeout),
        secret_provider=provider,
        runner=ProcessFixtureRunner(binary_path, platform_name),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ProcessFixtureRunner", "ProcessTestSecretProvider", "main"]
