"""Opt-in local-only retention of bounded original gate diagnostic bytes."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .runner_private_files import _PinnedPrivateDirectory

PRIVATE_DIAGNOSTICS_ENV = "BLUEFIRE_ACCEPTANCE_PRIVATE_DIAGNOSTICS"
PRIVATE_OUTPUT_LIMIT = 8192
_MARKER_NAME = ".bluefire-private-diagnostics.json"
_MARKER = b'{"schema_version":"bluefire.private-gate-diagnostics.v1"}\n'
_CAPTURE_NAME = re.compile(r"^capture-[a-f0-9]{32}$")


def private_capture_root(repository: Path, evidence_dir: Path) -> Path | None:
    """Validate an explicitly configured, dedicated root before executing a helper."""
    raw = os.environ.get(PRIVATE_DIAGNOSTICS_ENV)
    if not raw:
        return None
    if any(
        os.environ.get(key, "").lower() not in {"", "0", "false"}
        for key in ("CI", "GITHUB_ACTIONS")
    ):
        raise ValueError("private gate diagnostics are unavailable in CI")
    root = Path(raw)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("private gate diagnostics require a regular absolute directory")
    repository = repository.resolve(strict=True)
    evidence_dir = evidence_dir.resolve(strict=True)
    if (
        root == repository
        or repository in root.parents
        or root == evidence_dir
        or evidence_dir in root.parents
        or root == evidence_dir.parent
        or evidence_dir.parent in root.parents
        or any((parent / ".git").exists() for parent in (root, *root.parents))
    ):
        raise ValueError("private diagnostics must stay outside source and acceptance bundles")
    details = root.lstat()
    entries = {entry.name for entry in root.iterdir()}
    if entries and (
        _MARKER_NAME not in entries
        or any(name != _MARKER_NAME and not _CAPTURE_NAME.fullmatch(name) for name in entries)
    ):
        raise ValueError(
            "private diagnostics require an empty or previously owned capture directory"
        )
    with _PinnedPrivateDirectory(
        root, expected_identity=(details.st_dev, details.st_ino)
    ) as pinned:
        if set(pinned.names()) != entries:
            raise ValueError("private diagnostics directory changed during validation")
        if _MARKER_NAME in entries:
            if pinned.read(_MARKER_NAME, maximum=len(_MARKER)) != _MARKER:
                raise ValueError("private diagnostics ownership marker is invalid")
        else:
            pinned.create(_MARKER_NAME, _MARKER, maximum=len(_MARKER))
    return root


def retain_private_output(
    *,
    repository: Path,
    evidence_dir: Path,
    stdout: bytes,
    stderr: bytes,
    source: Mapping[str, Any],
) -> Mapping[str, Any]:
    root = private_capture_root(repository, evidence_dir)
    if root is None:
        return {"status": "not_configured"}
    capture_id = "capture-" + uuid.uuid4().hex
    stdout_capture, stderr_capture = stdout[:PRIVATE_OUTPUT_LIMIT], stderr[:PRIVATE_OUTPUT_LIMIT]
    record = {
        "schema_version": "bluefire.private-gate-capture.v1",
        "capture_id": capture_id,
        "private_only": True,
        "publication": "never commit or upload as CI/release evidence",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "capturing_process_id": os.getpid(),
        "repository": str(repository),
        "evidence_dir": str(evidence_dir),
        "acceptance_id": os.environ.get("BLUEFIRE_ACCEPTANCE_ID"),
        "repository_commit": os.environ.get("BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
        "source": dict(source),
        "stdout_truncated": len(stdout) > PRIVATE_OUTPUT_LIMIT,
        "stderr_truncated": len(stderr) > PRIVATE_OUTPUT_LIMIT,
        "stdout_bytes": len(stdout_capture),
        "stderr_bytes": len(stderr_capture),
    }
    payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    with _PinnedPrivateDirectory(root) as parent:
        if parent.read(_MARKER_NAME, maximum=len(_MARKER)) != _MARKER:
            raise ValueError("private diagnostics ownership marker changed")
        identity, mount = parent.create_directory(capture_id)
        with _PinnedPrivateDirectory(
            root / capture_id,
            parent=parent,
            expected_identity=identity,
            expected_mount_identity=mount,
        ) as capture:
            capture.create("stdout.bin", stdout_capture, maximum=PRIVATE_OUTPUT_LIMIT)
            capture.create("stderr.bin", stderr_capture, maximum=PRIVATE_OUTPUT_LIMIT)
            capture.create("source.json", payload, maximum=64 * 1024)
    return {
        "status": "retained",
        "capture_id": capture_id,
        "stdout_truncated": record["stdout_truncated"],
        "stderr_truncated": record["stderr_truncated"],
        "stdout_bytes": len(stdout_capture),
        "stderr_bytes": len(stderr_capture),
    }
