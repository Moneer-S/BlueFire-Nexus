"""Harness-owned postflight integrity bindings for product acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .product_acceptance_artifacts import inspect_regular_file
from .product_acceptance_process import _write_gate_assessment
from .product_acceptance_schema import result_postflight_assessment

_UNSAFE_CONTENT_ATTRIBUTES = ("filter", "working-tree-encoding", "ident")
_INACTIVE_ATTRIBUTE_VALUES = {b"unspecified", b"unset"}


def _nul_records(payload: bytes) -> list[bytes]:
    if not payload:
        return []
    if not payload.endswith(b"\0"):
        raise ValueError("Git emitted a non-terminated record stream")
    return payload[:-1].split(b"\0")


def _display_git_path(path: bytes) -> str:
    return json.dumps(path.decode("utf-8", "backslashreplace"), ensure_ascii=True)


def _worktree_path(repository: Path, git_path: bytes) -> tuple[Path, str]:
    relative_text = git_path.decode("utf-8", "surrogateescape")
    relative = PurePosixPath(relative_text)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe tracked path {_display_git_path(git_path)}")
    return repository.joinpath(*relative.parts), relative_text


def _parse_index(payload: bytes) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for record in _nul_records(payload):
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ")
        except ValueError as exc:
            raise ValueError("Git emitted malformed index metadata") from exc
        if not path or stage != b"0" or path in entries:
            raise ValueError("Git index is unmerged or contains duplicate paths")
        entries[path] = (mode, object_id)
    return entries


def _parse_head_tree(payload: bytes) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for record in _nul_records(payload):
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ")
        except ValueError as exc:
            raise ValueError("Git emitted malformed HEAD tree metadata") from exc
        expected_type = b"commit" if mode == b"160000" else b"blob"
        if not path or object_type != expected_type or path in entries:
            raise ValueError("Git HEAD tree contains unsupported entries")
        entries[path] = (mode, object_id)
    return entries


def _index_flag_failures(payload: bytes, expected_paths: set[bytes]) -> list[str]:
    failures: list[str] = []
    observed_paths: set[bytes] = set()
    for record in _nul_records(payload):
        if len(record) < 3 or record[1:2] != b" ":
            raise ValueError("Git emitted malformed index flags")
        tag = record[:1]
        path = record[2:]
        if not path or path in observed_paths:
            raise ValueError("Git emitted duplicate index flags")
        observed_paths.add(path)
        if tag != b"H":
            failures.append(
                "repository integrity: tracked path "
                f"{_display_git_path(path)} has forbidden Git index flag "
                f"{tag.decode('ascii', 'backslashreplace')}"
            )
    if observed_paths != expected_paths:
        raise ValueError("Git index flag inventory does not match its tracked-file inventory")
    return failures


def _unsafe_attribute_failures(payload: bytes, expected_paths: set[bytes]) -> list[str]:
    fields = _nul_records(payload)
    if len(fields) % 3:
        raise ValueError("Git emitted malformed attribute metadata")
    observed: set[tuple[bytes, bytes]] = set()
    failures: list[str] = []
    allowed_attributes = {item.encode("ascii") for item in _UNSAFE_CONTENT_ATTRIBUTES}
    for offset in range(0, len(fields), 3):
        path, attribute, value = fields[offset : offset + 3]
        key = (path, attribute)
        if path not in expected_paths or attribute not in allowed_attributes or key in observed:
            raise ValueError("Git emitted inconsistent attribute metadata")
        observed.add(key)
        if value not in _INACTIVE_ATTRIBUTE_VALUES:
            failures.append(
                "repository integrity: tracked path "
                f"{_display_git_path(path)} has forbidden {attribute.decode('ascii')} attribute"
            )
    expected = {(path, attribute) for path in expected_paths for attribute in allowed_attributes}
    if observed != expected:
        raise ValueError("Git attribute inventory is incomplete")
    return failures


def _stable_stat(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns)


def repository_state(repository: Path) -> dict[str, Any]:
    """Return the commit, tree, and worktree state without raising on non-Git roots."""

    def git(
        *arguments: str, input_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            input=input_bytes,
        )

    head = git("rev-parse", "--verify", "HEAD")
    commit = head.stdout.decode("ascii", "replace").strip() if head.returncode == 0 else None
    tree = git("rev-parse", "--verify", f"{commit}^{{tree}}") if commit else head
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    index = git("ls-files", "--stage", "-z", "--full-name")
    flags = git("ls-files", "-v", "-z", "--full-name")
    head_tree = git("ls-tree", "-r", "-z", "--full-tree", commit) if commit else head
    available = all(
        result.returncode == 0 for result in (head, tree, status, index, flags, head_tree)
    )
    integrity_failures: list[str] = []
    if available:
        try:
            index_entries = _parse_index(index.stdout)
            head_entries = _parse_head_tree(head_tree.stdout)
            integrity_failures.extend(_index_flag_failures(flags.stdout, set(index_entries)))
            if index_entries != head_entries:
                integrity_failures.append("repository integrity: Git index differs from HEAD")

            attribute_input = b"".join(path + b"\0" for path in index_entries)
            attributes = git(
                "check-attr",
                "-z",
                "--stdin",
                *_UNSAFE_CONTENT_ATTRIBUTES,
                input_bytes=attribute_input,
            )
            if attributes.returncode != 0:
                raise ValueError("Git attribute inspection failed")
            attribute_failures = _unsafe_attribute_failures(attributes.stdout, set(index_entries))
            integrity_failures.extend(attribute_failures)

            if not attribute_failures:
                batch_entries: list[tuple[bytes, Path, os.stat_result, bytes]] = []
                individual_entries: list[tuple[bytes, Path, str, os.stat_result, bytes]] = []
                for git_path, (mode, expected_object_id) in index_entries.items():
                    path, relative_text = _worktree_path(repository, git_path)
                    try:
                        before = path.lstat()
                        if mode in {b"100644", b"100755"}:
                            if not stat.S_ISREG(before.st_mode):
                                raise OSError(
                                    "tracked regular file has a different filesystem type"
                                )
                            entry = (git_path, path, relative_text, before, expected_object_id)
                            if b"\n" in git_path or b"\r" in git_path:
                                individual_entries.append(entry)
                            else:
                                batch_entries.append((git_path, path, before, expected_object_id))
                            continue
                        if mode == b"120000":
                            if stat.S_ISLNK(before.st_mode):
                                link_bytes = os.fsencode(os.readlink(path))
                            elif stat.S_ISREG(before.st_mode):
                                link_bytes = path.read_bytes()
                            else:
                                raise OSError(
                                    "tracked symbolic link has a different filesystem type"
                                )
                            hashed = git("hash-object", "--stdin", input_bytes=link_bytes)
                        elif mode == b"160000":
                            raise OSError(
                                "tracked Git submodules are not supported by release acceptance"
                            )
                        else:
                            raise OSError("tracked path has an unsupported Git mode")
                        after = path.lstat()
                    except OSError as exc:
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} could not be verified ({exc})"
                        )
                        continue
                    if hashed.returncode != 0:
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} could not be hashed"
                        )
                    elif hashed.stdout.strip() != expected_object_id:
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} content differs from the Git index"
                        )
                    if _stable_stat(after) != _stable_stat(before):
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} changed during verification"
                        )

                if batch_entries:
                    hashes = git(
                        "hash-object",
                        "--stdin-paths",
                        input_bytes=b"".join(item[0] + b"\n" for item in batch_entries),
                    )
                    object_ids = hashes.stdout.splitlines() if hashes.returncode == 0 else []
                    if len(object_ids) != len(batch_entries):
                        object_ids = [b""] * len(batch_entries)
                    for (git_path, path, before, expected_object_id), object_id in zip(
                        batch_entries, object_ids, strict=True
                    ):
                        if object_id != expected_object_id:
                            integrity_failures.append(
                                "repository integrity: tracked path "
                                f"{_display_git_path(git_path)} content differs from the Git index"
                            )
                        try:
                            after = path.lstat()
                        except OSError as exc:
                            integrity_failures.append(
                                "repository integrity: tracked path "
                                f"{_display_git_path(git_path)} could not be verified ({exc})"
                            )
                        else:
                            if _stable_stat(after) != _stable_stat(before):
                                integrity_failures.append(
                                    "repository integrity: tracked path "
                                    f"{_display_git_path(git_path)} changed during verification"
                                )

                for git_path, path, relative_text, before, expected_object_id in individual_entries:
                    try:
                        with path.open("rb") as source:
                            opened = os.fstat(source.fileno())
                            if _stable_stat(opened) != _stable_stat(before):
                                raise OSError("tracked file changed while it was opened")
                            hashed = subprocess.run(
                                [
                                    "git",
                                    "-C",
                                    str(repository),
                                    "hash-object",
                                    "--stdin",
                                    f"--path={relative_text}",
                                ],
                                check=False,
                                stdin=source,
                                capture_output=True,
                            )
                        after = path.lstat()
                    except OSError as exc:
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} could not be verified ({exc})"
                        )
                        continue
                    if hashed.returncode != 0 or hashed.stdout.strip() != expected_object_id:
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} content differs from the Git index"
                        )
                    if _stable_stat(after) != _stable_stat(before):
                        integrity_failures.append(
                            "repository integrity: tracked path "
                            f"{_display_git_path(git_path)} changed during verification"
                        )
        except (OSError, UnicodeError, ValueError) as exc:
            available = False
            integrity_failures.append(f"repository integrity inspection failed: {exc}")

    status_lines = (
        status.stdout.decode("utf-8", "replace").splitlines() if status.returncode == 0 else []
    )
    status_lines.extend(integrity_failures)
    return {
        "available": available,
        "commit": commit,
        "tree": tree.stdout.decode("utf-8", "replace").strip() if tree.returncode == 0 else None,
        "clean": available and not status.stdout.strip() and not integrity_failures,
        "status": status_lines,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def final_artifact_failures(
    run_dir: Path, gates: Sequence[Mapping[str, Any]]
) -> dict[str, list[str]]:
    """Find evidence changed after its owning gate was assessed."""

    failures: dict[str, list[str]] = {}
    for gate in gates:
        for artifact in gate.get("evidence_artifacts", []):
            try:
                inspection = inspect_regular_file(
                    run_dir,
                    artifact["path"],
                    label=f"{gate['gate_id']} evidence",
                )
            except (OSError, ValueError) as exc:
                failures.setdefault(gate["gate_id"], []).append(
                    f"{gate['gate_id']} evidence became unsafe after validation: "
                    f"{artifact['path']} ({exc})"
                )
                continue
            if inspection.contains_private_path:
                failures.setdefault(gate["gate_id"], []).append(
                    f"{gate['gate_id']} evidence discloses a local absolute path: "
                    f"{artifact['path']}"
                )
            if (
                inspection.sha256 != artifact["sha256"]
                or inspection.size_bytes != artifact["size_bytes"]
            ):
                failures.setdefault(gate["gate_id"], []).append(
                    f"{gate['gate_id']} evidence changed after validation: {artifact['path']}"
                )
    return failures


def _refresh_gate_artifacts(run_dir: Path, gates: Sequence[dict[str, Any]]) -> None:
    root = run_dir.resolve()
    for gate in gates:
        for artifact in gate["evidence_artifacts"]:
            try:
                inspection = inspect_regular_file(
                    root,
                    artifact["path"],
                    label=f"{gate['gate_id']} evidence",
                )
            except (OSError, ValueError):
                continue
            if inspection.contains_private_path:
                continue
            artifact["sha256"] = inspection.sha256
            artifact["size_bytes"] = inspection.size_bytes
        gate["hashes"] = {
            artifact["path"]: artifact["sha256"] for artifact in gate["evidence_artifacts"]
        }


def _assessment(gate: Mapping[str, Any], *, postflight: Mapping[str, Any] | None) -> dict:
    return {
        "schema_version": "bluefire.product-gate-assessment.v1",
        "status": gate["status"],
        "failure_reason": gate["failure_reason"],
        "workflow_exit_code": gate["workflow"]["exit_code"],
        "proof_sha256": _canonical_digest(gate["proofs"]),
        "postflight": dict(postflight) if postflight is not None else None,
    }


def apply_gate_failures(
    run_dir: Path,
    gates: Sequence[dict[str, Any]],
    failures: Mapping[str, Sequence[str]],
) -> None:
    """Bind postflight integrity failures into harness-owned gate assessments."""

    root = run_dir.resolve()
    for gate in gates:
        gate_failures = list(failures.get(gate["gate_id"], ()))
        if not gate_failures:
            continue
        prior_reason = gate.get("failure_reason")
        reasons = ([prior_reason] if isinstance(prior_reason, str) else []) + gate_failures
        gate["failure_reason"] = "; ".join(dict.fromkeys(reasons))
        gate["status"] = "failed"
        receipt_relative = gate["workflow"].get("receipt_path")
        if not isinstance(receipt_relative, str):
            continue
        receipt_path = (root / receipt_relative).resolve()
        if not receipt_path.is_relative_to(root) or not receipt_path.is_file():
            continue
        try:
            _write_gate_assessment(receipt_path, _assessment(gate, postflight=None))
        except (OSError, ValueError):
            gate["failure_reason"] += "; gate assessment could not be finalized"

    _refresh_gate_artifacts(root, gates)


def bind_gate_12_assessment(
    run_dir: Path,
    gates: Sequence[dict[str, Any]],
    *,
    repository: Mapping[str, Any],
    status: str,
    failure_reason: str | None,
) -> None:
    """Add final repository and verdict facts to the canonical GATE-12 receipt."""

    gate = next(item for item in gates if item["gate_id"] == "GATE-12")
    receipt_relative = gate["workflow"].get("receipt_path")
    if not isinstance(receipt_relative, str):
        return
    root = run_dir.resolve()
    receipt_path = (root / receipt_relative).resolve()
    if not receipt_path.is_relative_to(root) or not receipt_path.is_file():
        return
    postflight = {
        "schema_version": "bluefire.product-postflight-assessment.v1",
        "repository": dict(repository),
        "status": status,
        "failure_reason": failure_reason,
    }
    _write_gate_assessment(receipt_path, _assessment(gate, postflight=postflight))
    _refresh_gate_artifacts(root, [gate])


def persist_result_assessment(run_dir: Path, result: dict[str, Any]) -> None:
    """Persist and index the mandatory whole-result postflight assessment."""

    evidence = result["evidence"]
    path = run_dir / "postflight.json"
    path.write_text(
        json.dumps(
            result_postflight_assessment(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    evidence["postflight_file_sha256"] = _sha256_file(path)


__all__ = [
    "apply_gate_failures",
    "bind_gate_12_assessment",
    "final_artifact_failures",
    "persist_result_assessment",
    "repository_state",
]
