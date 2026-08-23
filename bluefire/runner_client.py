"""The only maintained Python transport allowed to launch the Rust runner."""

from __future__ import annotations

import json
import os

# Only the fixed, absolute Rust runner boundary uses subprocess.
import subprocess  # nosec B404
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .util import canonical_json_bytes

FORBIDDEN_EXECUTION_KEYS = frozenset(
    {
        "command",
        "cmd",
        "shell",
        "script",
        "script_body",
        "payload",
        "binary",
        "shellcode",
        "interpreter",
        "executable",
    }
)


class RunnerTransportError(RuntimeError):
    pass


@runtime_checkable
class RunnerTransport(Protocol):
    def inventory(self) -> Mapping[str, Any]: ...

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def reject_forbidden_execution_keys(value: Any, *, path: str = "$") -> None:
    """Recursively reject free-form executable content at the transport edge."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in FORBIDDEN_EXECUTION_KEYS:
                raise RunnerTransportError(f"forbidden execution field at {path}.{key}")
            reject_forbidden_execution_keys(child, path=f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            reject_forbidden_execution_keys(child, path=f"{path}[{index}]")


class SubprocessRustRunner:
    """Invoke one preconfigured runner binary with a fixed argument grammar."""

    def __init__(
        self,
        runner_binary: str | Path,
        work_root: str | Path,
        *,
        timeout_seconds: float = 35.0,
        output_limit_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        binary = Path(runner_binary).expanduser()
        if not binary.is_absolute() or not binary.is_file():
            raise RunnerTransportError("runner binary must be an existing absolute file")
        root = Path(work_root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        self.runner_binary = binary.resolve(strict=True)
        self.work_root = root.resolve(strict=True)
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        if timeout_seconds <= 0 or output_limit_bytes < 4096:
            raise RunnerTransportError("runner transport bounds are invalid")

    def inventory(self) -> Mapping[str, Any]:
        output = self._invoke([str(self.runner_binary), "inventory", "--json"])
        return self._decode_json(output, "runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
            request_root = Path(directory)
            manifest_path = request_root / "manifest.json"
            profile_path = request_root / "profile.json"
            manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
            output = self._invoke(
                [
                    str(self.runner_binary),
                    "execute",
                    "--manifest",
                    str(manifest_path),
                    "--profile",
                    str(profile_path),
                    "--json",
                ]
            )
        result = self._decode_json(output, "runner result")
        if result.get("schema_version") != "bluefire.runner-result.v1":
            raise RunnerTransportError("runner returned an unsupported result schema")
        if result.get("run_id") != manifest.get("run_id"):
            raise RunnerTransportError("runner result run_id does not match the request")
        if result.get("step_id") != manifest.get("step_id"):
            raise RunnerTransportError("runner result step_id does not match the request")
        if result.get("action_id") != manifest.get("action_id"):
            raise RunnerTransportError("runner result action_id does not match the request")
        return result

    def _invoke(self, argv: list[str]) -> bytes:
        explicit_environment: dict[str, str] = {"LC_ALL": "C", "LANG": "C"}
        if os.name == "nt":
            for name in ("SYSTEMROOT", "WINDIR"):
                value = os.environ.get(name)
                if value:
                    explicit_environment[name] = value
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        # argv[0] is the validated absolute runner path and the grammar is fixed.
        process = subprocess.Popen(  # nosec B603
            argv,
            cwd=self.work_root,
            env=explicit_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=creationflags,
        )
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()

        def drain(stream, destination: bytearray) -> None:
            if stream is None:
                return
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = self.output_limit_bytes - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            return_code = process.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            raise RunnerTransportError("Rust runner transport timed out") from exc
        finally:
            for reader in readers:
                reader.join(timeout=5)

        if overflow.is_set():
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        # The runner deliberately uses 3 for policy refusal/control blocking
        # and 4 for an action-level failed/partial result. Both still carry a
        # valid, signed-by-content JSON TaskResult on stdout and must reach the
        # evidence layer intact. Exit code 2 (or anything unexpected) is a
        # transport/CLI failure.
        if return_code not in {0, 3, 4}:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise RunnerTransportError(
                f"Rust runner exited with code {return_code}: {message[:1000]}"
            )
        return bytes(stdout)

    @staticmethod
    def _decode_json(payload: bytes, label: str) -> Mapping[str, Any]:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerTransportError(f"{label} is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise RunnerTransportError(f"{label} must be a JSON object")
        return value


__all__ = [
    "RunnerTransport",
    "RunnerTransportError",
    "SubprocessRustRunner",
    "reject_forbidden_execution_keys",
]
