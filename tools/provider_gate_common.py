"""Shared constants and fail-closed helpers for GATE-02 provider evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

STRUCTURAL_SCHEMA = "bluefire.provider-structural-evidence.v1"
JOURNEY_SCHEMA = "bluefire.provider-journey-evidence.v1"
FIXTURE_SCHEMA = "bluefire.provider-upgrade-fixture-set.v1"
PACKAGE_ID = "fixture.provider-upgrade-pack"
BEHAVIOR_ID = "fixture.provider-upgrade.behavior.v1"
ACTION_ID = "fixture.provider-upgrade.action.v1"
PROVIDER_ID = "fixture.provider-upgrade.runtime.v1"
PUBLISHER_ID = "bluefire.fixture.provider-upgrade"
SUCCESS_VERSIONS = ("1.0.0", "2.0.0")
LIMIT_VERSION = "3.0.0"
ALL_VERSIONS = (*SUCCESS_VERSIONS, LIMIT_VERSION)
EXPECTED_COMPATIBILITY = {
    "minimum_bluefire_version": "3.0.0",
    "maximum_bluefire_version_exclusive": "4.0.0",
}
EXPECTED_LICENSE = {
    "spdx_id": "MIT",
    "notice": "Copyright 2026 BlueFire fixture authors; MIT licensed.",
}
FIXTURE_SOURCE = (
    "Deterministically assembled no-import WebAssembly fixture committed with BlueFire Nexus"
)
DEFINITION_SOURCE = "BlueFire committed deterministic no-import WebAssembly provider fixture"
DEFINITION_NOTES = "Guest output attests the exact canonical message and repeat_count input."
EXPECTED_PARAMETERS = [
    {
        "name": "message",
        "type": "string",
        "required": False,
        "default": "probe",
        "enum": ["probe", "verify"],
        "minimum": None,
        "maximum": None,
    },
    {
        "name": "repeat_count",
        "type": "integer",
        "required": False,
        "default": 1,
        "enum": [1, 2],
        "minimum": 1.0,
        "maximum": 2.0,
    },
]
EXPECTED_OUTPUTS = [
    {
        "name": "result",
        "type": "artifact.fixture.provider-upgrade-result.v1",
        "required": True,
        "multiple": False,
    }
]
PRIVATE_FIELDS = frozenset(
    {
        "artifact_hex",
        "canonical_content_bytes",
        "canonical_envelope_bytes",
        "private_key",
        "seed",
        "signing_key",
    }
)
FORBIDDEN_PACKAGE_EXECUTION_FIELDS = frozenset(
    {
        "args",
        "argv",
        "binary",
        "cmd",
        "command",
        "commands",
        "dll",
        "entry_point",
        "executable",
        "library",
        "module_path",
        "powershell",
        "script",
        "shell",
        "subprocess",
    }
)
STRICT_SOURCE_AUDIT_PATHS = (
    "bluefire/action_packages.py",
    "bluefire/action_provider_packages.py",
    "bluefire/action_catalog.py",
    "bluefire/provider_runner_contracts.py",
    "bluefire/runner_adapter.py",
    "bluefire/orchestrator.py",
    "bluefire/service.py",
    "bluefire/ai.py",
    "bluefire/ai_drafts.py",
    "bluefire/planner.py",
    "bluefire/api.py",
    "bluefire/cli.py",
    "bluefire/job_runtime.py",
    "bluefire/runner_host.py",
    "runner/src/providers.rs",
    "runner/src/provider_action.rs",
    "runner/src/runner.rs",
)
TRUSTED_PROCESS_BOUNDARY_PATHS = (
    "bluefire/runner_client.py",
    "bluefire/runner_bootstrap.py",
    "bluefire/runner_lifecycle.py",
    "bluefire/runner_trust.py",
    "bluefire/runner_watchdog.py",
    "runner/src/process.rs",
)
SOURCE_AUDIT_PATHS = (*STRICT_SOURCE_AUDIT_PATHS, *TRUSTED_PROCESS_BOUNDARY_PATHS)
PYTHON_SHELL_MODULES = frozenset({"asyncio.subprocess", "commands", "shlex", "subprocess"})
PYTHON_SHELL_CALLS = frozenset(
    {
        "call",
        "check_call",
        "check_output",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "exec",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "eval",
        "getoutput",
        "getstatusoutput",
        "popen",
        "Popen",
        "posix_spawn",
        "posix_spawnp",
        "run",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "startfile",
        "system",
    }
)
PYTHON_DYNAMIC_IMPORT_CALLS = frozenset(
    {"__import__", "builtins.__import__", "importlib.import_module"}
)
PYTHON_DYNAMIC_NAMESPACE_CALLS = frozenset(
    {"globals", "locals", "vars", "builtins.globals", "builtins.locals", "builtins.vars"}
)
RUST_SHELL_TOKENS = (
    "std::process::Command",
    "process::Command",
    "Command::new(",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
)


class ProviderGateError(RuntimeError):
    """Fail-closed provider acceptance error."""

    def __init__(self, message: str, *, code: str = "provider_gate_failed") -> None:
        super().__init__(message)
        self.code = code


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProviderGateError(f"{label} fields are invalid")
    return value


def _contained_file(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or len(name) > 160 or Path(name).name != name:
        raise ProviderGateError("fixture file name is invalid")
    candidate = (root / name).resolve(strict=True)
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        raise ProviderGateError("fixture file escapes its committed directory")
    return candidate


def _load_document(path: Path) -> dict[str, Any]:
    if path.stat().st_size < 1 or path.stat().st_size > 256 * 1024:
        raise ProviderGateError("fixture document size is invalid")
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        value = json.loads(raw)
    elif path.suffix in {".yaml", ".yml"}:
        value = yaml.safe_load(raw)
    else:
        raise ProviderGateError("fixture document format is invalid")
    if not isinstance(value, dict):
        raise ProviderGateError("fixture document must be an object")
    return value


def _walk_fields(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            fields.add(str(key).casefold().replace("-", "_"))
            fields.update(_walk_fields(child))
    elif isinstance(value, list):
        for child in value:
            fields.update(_walk_fields(child))
    return fields


def _decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 43:
        raise ProviderGateError("fixture public key is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise ProviderGateError("fixture public key cannot be decoded") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ProviderGateError("fixture public key is not canonical base64url")
    return decoded


def _read_uleb(value: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(value) and shift < 64:
        byte = value[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, offset
        shift += 7
    raise ProviderGateError("provider WASM contains invalid LEB128")


def _wasm_sections(artifact: bytes) -> dict[int, bytes]:
    if not artifact.startswith(b"\x00asm\x01\x00\x00\x00"):
        raise ProviderGateError("provider artifact is not WASM v1")
    sections: dict[int, bytes] = {}
    offset = 8
    previous = 0
    while offset < len(artifact):
        section_id = artifact[offset]
        offset += 1
        size, offset = _read_uleb(artifact, offset)
        end = offset + size
        if section_id <= previous or section_id in sections or end > len(artifact):
            raise ProviderGateError("provider WASM section table is invalid")
        sections[section_id] = artifact[offset:end]
        previous = section_id
        offset = end
    if offset != len(artifact):
        raise ProviderGateError("provider WASM is truncated")
    return sections


def _assert_public(value: Any) -> None:
    if isinstance(value, bytes):
        raise ProviderGateError("public provider response exposed bytes")
    if isinstance(value, Mapping):
        normalized = {str(key).casefold().replace("-", "_") for key in value}
        if normalized & PRIVATE_FIELDS:
            raise ProviderGateError("public provider response exposed private fields")
        for child in value.values():
            _assert_public(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_public(child)


def _contains_literal(value: Any, literals: Sequence[str]) -> bool:
    if isinstance(value, str):
        return any(literal in value for literal in literals)
    if isinstance(value, Mapping):
        return any(
            _contains_literal(key, literals) or _contains_literal(child, literals)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_literal(child, literals) for child in value)
    return False


def _assert_public_report(
    value: Mapping[str, Any], artifact_hex_values: Sequence[str], label: str
) -> None:
    _assert_public(value)
    if _contains_literal(value, artifact_hex_values):
        raise ProviderGateError(f"{label} exposed private provider bytes")
