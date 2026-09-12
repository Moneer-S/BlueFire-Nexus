"""Private retained-object evidence, separate from a review's live mount snapshot."""

from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .runner_history_documents import (
    HistoricalWorkspace,
    _directory_state,
    _open_history_directory,
    _workspace_snapshot,
)
from .runner_history_identity import DurableIdentityUnavailable, durable_descriptor_identity


def enrolled_sandbox_snapshot(sandbox: Path) -> HistoricalWorkspace:
    """The authenticated bootstrap already binds this exact root, even with no history."""
    return HistoricalWorkspace(sandbox, sandbox, _workspace_snapshot(sandbox, sandbox))


def optional_durable_identity(descriptor: int, *, directory: bool = False) -> dict[str, Any] | None:
    """Unsupported storage retains exact-session review, never durable continuation."""
    try:
        return durable_descriptor_identity(descriptor, directory=directory)
    except DurableIdentityUnavailable:
        return None


def durable_file_snapshot(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    identity = snapshot.get("durable_identity")
    if identity is None:
        return None
    return {key: value for key, value in snapshot.items() if key != "identity"}


def durable_workspace_snapshot(workspace: HistoricalWorkspace) -> dict[str, Any] | None:
    """Capture only the accepted chain and fixed namespaces; no permission changes."""
    workspace.recheck()
    exact = workspace.binding()
    paths = (*reversed(workspace.path.parents), workspace.path)
    sandbox_index = paths.index(Path(exact["sandbox"]))
    captured = []
    directories = []
    namespaces = []
    supported = True
    with ExitStack() as stack:

        def pin(path: Path, parent: int | None, expected: list[Any], *, metadata: bool = True):
            nonlocal supported
            descriptor = _open_history_directory(path, parent)
            stack.callback(os.close, descriptor)
            if list(_directory_state(descriptor, metadata=metadata)) != expected:
                raise ValueError("historical workspace changed during preservation review")
            durable = optional_durable_identity(descriptor, directory=True)
            supported = supported and durable is not None
            captured.append((descriptor, metadata, expected, durable))
            return descriptor, {"object": durable, "metadata": expected[3:]}

        parent = None
        for index, path in enumerate(paths):
            parent, evidence = pin(
                path, parent, exact["directories"][index], metadata=index >= sandbox_index
            )
            directories.append(evidence)
        bluefire_descriptor = None
        for entry in exact["receipt_namespaces"]:
            evidence = None
            if entry["directory"] is not None:
                descriptor, evidence = pin(
                    workspace.path / entry["name"],
                    parent if entry["name"] == ".bluefire" else bluefire_descriptor,
                    entry["directory"],
                )
                if entry["name"] == ".bluefire":
                    bluefire_descriptor = descriptor
            namespaces.append({**entry, "directory": evidence})
        workspace.recheck()
        for descriptor, metadata, expected, durable in captured:
            if (
                list(_directory_state(descriptor, metadata=metadata)) != expected
                or optional_durable_identity(descriptor, directory=True) != durable
            ):
                raise ValueError("historical object changed during preservation review")
    if not supported:
        return None
    return {
        "path": str(workspace.path),
        "sandbox": exact["sandbox"],
        "directories": directories,
        "receipt_namespaces": namespaces,
    }
