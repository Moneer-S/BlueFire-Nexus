"""Read-only, bounded display snapshots of manifestless run observations.

These snapshots deliberately confer no bundle, approval, or replay authority.
Canonical readers remain responsible for sealed records, including corrupt ones.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .detections import DetectionCandidate
from .evidence import EvidenceGraph, EvidenceRecord
from .product_store_contracts import safe_document
from .replay_checkpoint_values import bounded_json_copy
from .run_bundle_export import MAX_FILE_BYTES, MAX_TOTAL_BYTES
from .run_store import RUN_ID_RE, RunStore, RunStoreError
from .runner_descriptor_io import descriptor_identity
from .util import content_hash
from .windows_owner_acl import _windows_open_descriptor

_NAMES = (
    "result.json",
    "scenario.json",
    "plan.json",
    "policy.json",
    "profile.json",
    "evidence.json",
    "detections.json",
    "events.jsonl",
)


def _require(condition: bool) -> None:
    if not condition:
        raise RunStoreError("Retained observations failed display validation.")


def _open(path: Path, parent: int | None, *, directory: bool) -> int:
    if sys.platform == "win32":
        return _windows_open_descriptor(path, directory=directory)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    else:
        # Reject FIFOs/devices after open without waiting for a peer writer.
        flags |= os.O_NONBLOCK
    return os.open(path if parent is None else path.name, flags, dir_fd=parent)


def _state(descriptor: int, *, directory: bool) -> tuple[int, ...]:
    identity = descriptor_identity(descriptor, directory=directory)
    details = os.fstat(descriptor)
    return (*identity, details.st_size, details.st_mtime_ns, details.st_ctime_ns, details.st_nlink)


def _manifest_absent(path: Path, parent: int) -> None:
    try:
        if sys.platform == "win32":
            (path / "manifest.json").lstat()
        else:
            os.stat("manifest.json", dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RunStoreError("Sealed or damaged manifests require canonical run inspection.")


def _capture(store: RunStore, run_id: str) -> dict[str, bytes]:
    _require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None)
    root = store.root / run_id
    # Pin the literal chain, never resolve a substituted run directory first.
    chain = (*reversed(root.parents), root)
    captured: dict[str, bytes] = {}
    total = 0
    with ExitStack() as stack:
        pinned: list[tuple[Path, int | None, int, bool, tuple[int, ...]]] = []

        def pin(path: Path, parent: int | None, *, directory: bool) -> int:
            descriptor = _open(path, parent, directory=directory)
            stack.callback(os.close, descriptor)
            pinned.append(
                (path, parent, descriptor, directory, _state(descriptor, directory=directory))
            )
            return descriptor

        parent = None
        for path in chain:
            parent = pin(path, parent, directory=True)
        assert parent is not None
        _manifest_absent(root, parent)
        for name in _NAMES:
            descriptor = pin(root / name, parent, directory=False)
            size = os.fstat(descriptor).st_size
            _require(0 <= size <= MAX_FILE_BYTES)
            total += size
            _require(total <= MAX_TOTAL_BYTES)
            payload = bytearray()
            while len(payload) <= size:
                block = os.read(descriptor, min(65536, size + 1 - len(payload)))
                if not block:
                    break
                payload.extend(block)
            _require(len(payload) == size)
            captured[name] = bytes(payload)
        _manifest_absent(root, parent)
        for path, ancestor, descriptor, directory, before in pinned:
            _require(_state(descriptor, directory=directory) == before)
            reopened = _open(path, ancestor, directory=directory)
            try:
                _require(_state(reopened, directory=directory) == before)
            finally:
                os.close(reopened)
    return captured


def _object(payload: bytes) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            _require(key not in result)
            result[key] = value
        return result

    value = bounded_json_copy(json.loads(payload, object_pairs_hook=pairs), "retained observation")
    if not isinstance(value, dict):
        raise RunStoreError("Retained JSON must be an object.")
    return value


def _events(store: RunStore, payload: bytes, run_id: str) -> tuple[list[Any], bool]:
    rows: list[Any] = []
    previous = None
    lines = payload.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        # A failed append may leave one torn last row. Withhold that row only;
        # any earlier corruption, or a fully written invalid row, still refuses.
        if index == len(lines) - 1 and not line.endswith(b"\n"):
            return rows, False
        _object(line)
        row = store._validated_event_row(
            line.decode("utf-8"), expected_sequence=len(rows) + 1, previous_hash=previous
        )
        row = bounded_json_copy(row, "retained event")
        data = row.get("data")
        _require(isinstance(data, dict) and data.get("run_id", run_id) == run_id)
        rows.append(row)
        _require(len(rows) <= 2048)
        previous = str(row["event_hash"])
    return rows, True


def retained_observations(store: RunStore, run_id: str) -> dict[str, Any]:
    """Capture unchanged ordinary files; verify observations without finalizing."""
    try:
        captured = _capture(store, run_id)
        documents = {
            name[:-5]: _object(captured[name]) for name in _NAMES if name.endswith(".json")
        }
        result = documents.pop("result")
        scenario, plan = documents["scenario"], documents["plan"]
        _require(result.get("run_id") == run_id and isinstance(result.get("status"), str))
        _require(
            plan.get("scenario_id") == scenario.get("id") and isinstance(scenario.get("id"), str)
        )
        _require(plan.get("scenario_digest") == content_hash(scenario))
        _require(plan.get("mode") in {"execute", "simulate"})
        _require(result.get("mode", plan["mode"]) == plan["mode"])
        _require(not (set(result) & (set(documents) | {"events", "manifest", "bundle_digest"})))
        steps = result.get("steps", [])
        _require(isinstance(steps, list) and isinstance(plan.get("steps"), list))
        for step in steps:
            _require(
                isinstance(step, dict)
                and isinstance(step.get("step_id"), str)
                and isinstance(step.get("status"), str)
            )
        records = documents["evidence"].get("records")
        candidates = documents["detections"].get("candidates")
        if not isinstance(records, list) or not isinstance(candidates, list):
            raise RunStoreError("Retained evidence and detections must be lists.")
        graph = EvidenceGraph()
        evidence_ids: set[str] = set()
        for row in records:
            record = EvidenceRecord.from_mapping(row)
            _require(record.run_id == run_id and record.evidence_id not in evidence_ids)
            graph.add(record)
            evidence_ids.add(record.evidence_id)
        for row in candidates:
            candidate = DetectionCandidate.from_mapping(row)
            _require(set(candidate.observed_evidence_ids) <= evidence_ids)
        events, complete = _events(store, captured["events.jsonl"], run_id)
        observations = {
            **result,
            "mode": plan["mode"],
            "steps": steps,
            **documents,
            "events": events,
        }
        # Reuse the product's credential policy. No raw reader errors or paths
        # enter the public response, and unreviewed plaintext is never returned.
        safe_document(observations, context="retained observations")
        return {
            "schema_version": "bluefire.retained-run-observations.v1",
            "run_id": run_id,
            "record_state": "unsealed",
            "display_only": True,
            "canonical": False,
            "replay_available": False,
            "events_complete": complete,
            "observations": observations,
        }
    except (OSError, ValueError, TypeError, RecursionError, KeyError) as exc:
        raise RunStoreError(
            "Retained observations are unavailable or failed safe display validation."
        ) from exc
