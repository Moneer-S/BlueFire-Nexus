"""Strict historical native document shapes, without executing or renewing them."""

from __future__ import annotations

import os
import re
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .runner_contracts import (
    EFFECT_CAPABILITIES,
    seal_manifest,
    seal_profile,
    validate_reviewed_manifest,
)
from .runner_descriptor_io import _descriptor_mount_identity, descriptor_identity, identity_format
from .util import canonical_json_bytes, parse_iso8601_datetime
from .windows_owner_acl import _windows_open_descriptor

_MANIFEST_REQUIRED = frozenset(
    {
        "schema_version",
        "request_id",
        "run_id",
        "step_id",
        "behavior_id",
        "action_id",
        "mode",
        "runner_id",
        "runner_profile_id",
        "platform",
        "requested_at",
        "expires_at",
        "params",
        "target_scope",
        "required_capabilities",
        "safety_tier",
        "limits",
        "cleanup_action_id",
        "policy_digest",
        "request_hash",
    }
)
_MANIFEST_OPTIONAL = frozenset(
    {"execution_binding", "provider_binding", "reviewed_operation", "approval", "evidence_refs"}
)
_PROFILE_REQUIRED = frozenset(
    {
        "schema_version",
        "profile_id",
        "runner_id",
        "platform",
        "sandbox_root",
        "allowed_actions",
        "capabilities",
        "max_safety_tier",
        "target_scope",
        "limits",
        "policy_digest",
    }
)
_PROFILE_OPTIONAL = frozenset(
    {
        "reviewed_execution",
        "control_blocked_actions",
        "action_bindings",
        "provider_bindings",
        "provider_artifacts",
        "approval_required_at_or_above",
    }
)
_LIMIT_FIELDS = frozenset(
    {"timeout_ms", "max_stdout_bytes", "max_stderr_bytes", "max_artifact_bytes", "max_files"}
)
_TIERS = {"safe", "controlled", "restricted"}
_APPROVAL_WORKSPACE = re.compile(r"approval-[0-9a-f]{32}\Z")
_DirectoryState = tuple[int, int, int | None, int, int, int, int, int]
_WorkspaceState = tuple[
    tuple[_DirectoryState, ...],
    tuple[tuple[str, _DirectoryState | None, bool | None], ...],
]


@dataclass(frozen=True)
class HistoricalWorkspace:
    """Private review evidence only; this record grants no execution authority."""

    path: Path
    _sandbox: Path
    _state: _WorkspaceState

    def binding(self) -> dict[str, Any]:
        """Return fresh private digest input; paths must not enter public review output."""
        return {
            "path": str(self.path),
            "sandbox": str(self._sandbox),
            "identity_format": identity_format(),
            "directories": [list(row) for row in self._state[0]],
            "receipt_namespaces": [
                {
                    "name": name,
                    "directory": list(row) if row is not None else None,
                    "occupied": occupied,
                }
                for name, row, occupied in self._state[1]
            ],
        }

    def recheck(self) -> None:
        _require(_workspace_snapshot(self.path, self._sandbox) == self._state)


def _open_history_directory(path: Path, parent: int | None) -> int:
    if sys.platform == "win32":
        return _windows_open_descriptor(path, directory=True, write_dac=False, share_write=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    return os.open(path if parent is None else path.name, flags, dir_fd=parent)


def _directory_state(descriptor: int, *, metadata: bool = True) -> _DirectoryState:
    identity = descriptor_identity(descriptor, directory=True)
    mount = _descriptor_mount_identity(descriptor)
    details = os.fstat(descriptor)
    return (
        *identity,
        mount,
        details.st_mode if metadata else 0,
        details.st_uid if metadata else 0,
        details.st_gid if metadata else 0,
        details.st_mtime_ns if metadata else 0,
        details.st_ctime_ns if metadata else 0,
    )


def _workspace_snapshot(workspace: Path, sandbox: Path) -> _WorkspaceState:
    """Pin the exact canonical chain and fixed receipt namespaces without changing permissions."""
    _require(workspace.is_absolute() and sandbox.is_absolute())
    _require(str(workspace.resolve(strict=True)) == str(workspace))
    _require(str(sandbox.resolve(strict=True)) == str(sandbox))
    paths = (*reversed(workspace.parents), workspace)
    _require(sandbox in paths)
    root_index = paths.index(sandbox)
    captured: list[tuple[Path, int, int | None, bool, _DirectoryState]] = []
    namespaces: list[tuple[str, _DirectoryState | None, bool | None]] = []
    with ExitStack() as stack:

        def pin(
            path: Path, parent: int | None, *, metadata: bool = True
        ) -> tuple[int, _DirectoryState]:
            descriptor = _open_history_directory(path, parent)
            stack.callback(os.close, descriptor)
            state = _directory_state(descriptor, metadata=metadata)
            captured.append((path, descriptor, parent, metadata, state))
            return descriptor, state

        parent = None
        chain = []
        for index, path in enumerate(paths):
            parent, state = pin(path, parent, metadata=index >= root_index)
            chain.append(state)
        if parent is None:
            raise ValueError("historical workspace directory identity is unavailable")
        root_state = chain[root_index]
        _require(
            all(row[0] == root_state[0] and row[2] == root_state[2] for row in chain[root_index:])
        )

        def optional(path: Path, parent_descriptor: int) -> tuple[int, _DirectoryState] | None:
            try:
                return pin(path, parent_descriptor)
            except FileNotFoundError:
                return None

        bluefire = optional(workspace / ".bluefire", parent)
        namespaces.append((".bluefire", bluefire[1] if bluefire else None, None))
        for name in ("receipts", "receipt-commits"):
            path = workspace / ".bluefire" / name
            entry = optional(path, bluefire[0]) if bluefire else None
            occupied = None
            if entry:
                _require(entry[1][0] == root_state[0] and entry[1][2] == root_state[2])
                with os.scandir(path if sys.platform == "win32" else entry[0]) as names:
                    occupied = next(names, None) is not None
            namespaces.append((f".bluefire/{name}", entry[1] if entry else None, occupied))
        if bluefire:
            _require(bluefire[1][0] == root_state[0] and bluefire[1][2] == root_state[2])
        for path, descriptor, parent_descriptor, metadata, state in reversed(captured):
            _require(_directory_state(descriptor, metadata=metadata) == state)
            current = _open_history_directory(path, parent_descriptor)
            try:
                _require(_directory_state(current, metadata=metadata) == state)
            finally:
                os.close(current)
        _require(str(workspace.resolve(strict=True)) == str(workspace))
    return tuple(chain), tuple(namespaces)


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("historical native document schema is invalid")


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and bool(item) for item in value)


def _scope(value: Any) -> None:
    _require(isinstance(value, dict) and not set(value) - {"filesystem", "network"})
    _require(_strings(value.get("filesystem", [])))
    network = value.get("network", [])
    _require(isinstance(network, list))
    for destination in network:
        _require(isinstance(destination, dict) and set(destination) == {"host", "port"})
        _require(isinstance(destination["host"], str) and bool(destination["host"]))
        _require(type(destination["port"]) is int and 0 <= destination["port"] <= 65535)


def _common(
    document: Mapping[str, Any], required: frozenset[str], optional: frozenset[str]
) -> None:
    _require(required <= document.keys() and not document.keys() - required - optional)
    structured = {
        "params",
        "target_scope",
        "limits",
        "required_capabilities",
        "capabilities",
        "allowed_actions",
    }
    for field in required - structured:
        _require(isinstance(document[field], str) and bool(document[field]))
    limits = document["limits"]
    _require(isinstance(limits, dict) and set(limits) == _LIMIT_FIELDS)
    _require(all(type(value) is int and 0 <= value <= (2**64 - 1) for value in limits.values()))
    _scope(document["target_scope"])


def validate_history_documents(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    platform: str,
    sandbox: Path,
) -> HistoricalWorkspace:
    """Validate retained seals and exact supported workspace; never refresh expiry.

    Native v1 carries no separate approval ID. For service-created workspaces, the
    authenticated ledger payload binds the approval-named path through the sealed
    profile, request and result identities; the directory name is not a new grant.
    """
    _common(manifest, _MANIFEST_REQUIRED, _MANIFEST_OPTIONAL)
    _common(profile, _PROFILE_REQUIRED, _PROFILE_OPTIONAL)
    _require(
        manifest["mode"] == "execute" and manifest["platform"] == profile["platform"] == platform
    )
    stored_sandbox = Path(profile["sandbox_root"])
    _require(stored_sandbox.is_absolute() and str(stored_sandbox) == profile["sandbox_root"])
    isolated = stored_sandbox != sandbox
    if isolated:
        _require(
            stored_sandbox.parent == sandbox / ".bluefire-executions"
            and _APPROVAL_WORKSPACE.fullmatch(stored_sandbox.name) is not None
        )
    _require(
        manifest["runner_id"] == profile["runner_id"]
        and manifest["runner_profile_id"] == profile["profile_id"]
        and manifest["policy_digest"] == profile["policy_digest"]
    )
    _require(isinstance(manifest["params"], dict))
    for document, field in ((manifest, "required_capabilities"), (profile, "capabilities")):
        _require(_strings(document[field]))
        _require(set(document[field]) <= set(EFFECT_CAPABILITIES.values()))
    _require(_strings(profile["allowed_actions"]))
    _require(_strings(profile.get("control_blocked_actions", [])))
    _require(_strings(manifest.get("evidence_refs", [])))
    _require(manifest["safety_tier"] in _TIERS and profile["max_safety_tier"] in _TIERS)
    _require(profile.get("approval_required_at_or_above") in _TIERS | {None})
    requested = parse_iso8601_datetime(manifest["requested_at"])
    expires = parse_iso8601_datetime(manifest["expires_at"])
    _require(requested.tzinfo is not None and expires.tzinfo is not None and requested <= expires)
    approval = manifest.get("approval")
    _require(not isolated or isinstance(approval, dict))
    if approval is not None:
        _require(
            isinstance(approval, dict)
            and set(approval) == {"approved_by", "approved_at", "expires_at", "request_hash"}
        )
        _require(all(isinstance(value, str) and bool(value) for value in approval.values()))
        approved_at = parse_iso8601_datetime(approval["approved_at"])
        approval_expiry = parse_iso8601_datetime(approval["expires_at"])
        _require(
            approved_at.tzinfo is not None
            and approval_expiry.tzinfo is not None
            and approved_at <= approval_expiry
        )
        _require(approval["request_hash"] == manifest["request_hash"])
    _require(canonical_json_bytes(seal_profile(profile)) == canonical_json_bytes(profile))
    _require(canonical_json_bytes(seal_manifest(manifest)) == canonical_json_bytes(manifest))
    validate_reviewed_manifest(manifest, profile)
    return HistoricalWorkspace(
        stored_sandbox, sandbox, _workspace_snapshot(stored_sandbox, sandbox)
    )
