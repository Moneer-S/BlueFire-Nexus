"""The only maintained Python transport allowed to launch the Rust runner."""

from __future__ import annotations

import json
import os
import re

# Only the fixed, absolute Rust runner boundary uses subprocess.
import subprocess  # nosec B404
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .util import canonical_json_bytes, content_hash, file_hash

_INVENTORY_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_INVENTORY_MAX_ACTIONS = 512
_INVENTORY_MAX_BYTES = 2 * 1024 * 1024
_INVENTORY_PLATFORMS = frozenset({"linux", "macos", "windows"})
_ACTION_READINESS = frozenset({"ready", "structural", "unavailable"})

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


class RunnerReadinessError(RunnerTransportError):
    """A sanitized refusal raised before an Execute effect can be dispatched."""


@runtime_checkable
class RunnerTransport(Protocol):
    def inventory(self) -> Mapping[str, Any]: ...

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def canonical_runner_inventory(inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and normalize the stable identity-bearing runner inventory.

    The returned document deliberately contains only bounded, non-secret fields.
    Its digest is therefore safe to surface and stable across JSON key ordering.
    """

    if not isinstance(inventory, Mapping):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
    runner_id = _inventory_token(inventory.get("runner_id"), maximum=128)
    runner_version = _inventory_token(inventory.get("runner_version"), maximum=128)
    action_sdk_version = _inventory_token(inventory.get("action_sdk_version"), maximum=128)
    receipt_protocol = _inventory_token(inventory.get("receipt_protocol"), maximum=128)
    platform = inventory.get("platform")
    raw_actions = inventory.get("actions")
    if (
        runner_id is None
        or runner_version is None
        or action_sdk_version is None
        or receipt_protocol is None
        or not isinstance(platform, str)
        or platform not in _INVENTORY_PLATFORMS
        or not isinstance(raw_actions, list)
        or len(raw_actions) > _INVENTORY_MAX_ACTIONS
    ):
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.")

    try:
        source_bytes = canonical_json_bytes(dict(inventory))
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(source_bytes) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")

    actions: list[dict[str, str]] = []
    action_ids: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_id = _inventory_token(raw_action.get("action_id"), maximum=200)
        action_version = _inventory_token(raw_action.get("action_version"), maximum=64)
        readiness = raw_action.get("readiness")
        if (
            action_id is None
            or not _INVENTORY_IDENTIFIER.fullmatch(action_id)
            or action_version is None
            or not isinstance(readiness, str)
            or readiness not in _ACTION_READINESS
            or action_id in action_ids
        ):
            raise RunnerReadinessError("Runner inventory is invalid or unsupported.")
        action_ids.add(action_id)
        actions.append(
            {
                "action_id": action_id,
                "action_version": action_version,
                "readiness": readiness,
                "contract_digest": content_hash(dict(raw_action)),
            }
        )
    actions.sort(key=lambda item: item["action_id"])
    canonical = {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": runner_id,
        "runner_version": runner_version,
        "action_sdk_version": action_sdk_version,
        "receipt_protocol": receipt_protocol,
        "platform": platform,
        "source_digest": content_hash(dict(inventory)),
        "actions": actions,
    }
    try:
        encoded = canonical_json_bytes(canonical)
    except (TypeError, ValueError) as exc:
        raise RunnerReadinessError("Runner inventory is invalid or unsupported.") from exc
    if len(encoded) > _INVENTORY_MAX_BYTES:
        raise RunnerReadinessError("Runner inventory exceeds the readiness size limit.")
    return canonical


def runner_inventory_digest(inventory: Mapping[str, Any]) -> str:
    """Return the canonical digest used by the approval and dispatch gates."""

    return content_hash(canonical_runner_inventory(inventory))


def runner_transport_identity(
    runner: RunnerTransport,
    inventory: Mapping[str, Any],
) -> Mapping[str, str]:
    """Build a secret-safe identity for the exact transport and runner binary."""

    canonical = canonical_runner_inventory(inventory)
    identity = {
        "transport": f"{type(runner).__module__}.{type(runner).__qualname__}",
        "runner_id": str(canonical["runner_id"]),
        "runner_version": str(canonical["runner_version"]),
        "platform": str(canonical["platform"]),
    }
    raw_binary = getattr(runner, "runner_binary", None)
    if isinstance(raw_binary, Path):
        try:
            binary = raw_binary.resolve(strict=True)
            if not binary.is_file():
                raise OSError("runner binary is not a file")
            identity["runner_binary_digest"] = file_hash(binary)
        except OSError as exc:
            raise RunnerReadinessError("Runner identity could not be verified.") from exc
    return identity


class InventoryBoundRunner:
    """Fail closed if the approved runner identity or inventory changes.

    Inventory is checked when orchestration claims the approval and again
    immediately before every action dispatch. The underlying transport error is
    never exposed because it may contain local paths or process diagnostics.
    """

    def __init__(
        self,
        runner: RunnerTransport,
        *,
        expected_inventory_digest: str,
        expected_identity_digest: str,
        recovery_identity: Mapping[str, Any],
    ) -> None:
        self.runner = runner
        self.expected_inventory_digest = expected_inventory_digest
        self.expected_identity_digest = expected_identity_digest
        self.recovery_identity = dict(recovery_identity)

    @property
    def runner_binary(self) -> Any:
        return getattr(self.runner, "runner_binary", None)

    def inventory(self) -> Mapping[str, Any]:
        try:
            inventory = self.runner.inventory()
            canonical = canonical_runner_inventory(inventory)
            identity = runner_transport_identity(self.runner, inventory)
        except (AttributeError, OSError, RunnerTransportError, TypeError, ValueError) as exc:
            raise RunnerReadinessError(
                "Runner became unavailable after approval; no action was dispatched."
            ) from exc
        if content_hash(canonical) != self.expected_inventory_digest:
            raise RunnerReadinessError(
                "Runner inventory changed after approval; submit a new Execute request."
            )
        if content_hash(identity) != self.expected_identity_digest:
            raise RunnerReadinessError(
                "Runner identity changed after approval; submit a new Execute request."
            )
        return inventory

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.inventory()
        return self.runner.execute(manifest, profile)


def _inventory_token(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not 1 <= len(token) <= maximum or any(ord(character) < 32 for character in token):
        return None
    return token


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
    "InventoryBoundRunner",
    "RunnerTransport",
    "RunnerTransportError",
    "RunnerReadinessError",
    "SubprocessRustRunner",
    "canonical_runner_inventory",
    "reject_forbidden_execution_keys",
    "runner_inventory_digest",
    "runner_transport_identity",
]
