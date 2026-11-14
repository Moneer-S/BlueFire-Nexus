"""Capture bounded, privacy-safe evidence about the pinned uv build identity."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Any, Sequence

SCHEMA_VERSION = "bluefire.uv-version-evidence.v1"
OUTPUT_NAME = "bluefire-uv-version-evidence.json"
MAX_COMMAND_BYTES = 4096
MAX_RECEIPT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 15

_SAFE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.+:-]{0,160}$")
_SAFE_HUMAN = re.compile(r"^[A-Za-z0-9_.+() -]{1,256}$")
_ROOT_FIELDS = ("package_name", "version", "commit_info", "target_triple")
_COMMIT_FIELDS = (
    "short_commit_hash",
    "commit_hash",
    "commit_date",
    "last_tag",
    "commits_since_last_tag",
)


class UvVersionEvidenceError(ValueError):
    """Raised when bounded diagnostic evidence cannot be captured safely."""


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _run_uv(arguments: Sequence[str]) -> str:
    try:
        # The executable and arguments are fixed local build-tool interrogation.
        completed = subprocess.run(  # nosec B603
            ["uv", *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise UvVersionEvidenceError("pinned uv version evidence command failed") from exc
    value = completed.stdout.strip()
    if not value or len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise UvVersionEvidenceError("pinned uv version evidence output is not bounded")
    return value


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return "unknown"


def _safe_scalar(value: Any) -> dict[str, Any]:
    kind = _type_name(value)
    result: dict[str, Any] = {"type": kind}
    if value is None or isinstance(value, (bool, int)):
        result["value"] = value
    elif isinstance(value, float):
        result["value"] = value if value == value and abs(value) != float("inf") else None
    elif isinstance(value, str):
        if _SAFE_VALUE.fullmatch(value):
            result["value"] = value
        else:
            result.update({"value_omitted": True, "length": len(value)})
    return result


def _safe_keys(value: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    keys = sorted(key if _SAFE_KEY.fullmatch(key) else "<unsafe-key>" for key in value)
    types = {
        (key if _SAFE_KEY.fullmatch(key) else "<unsafe-key>"): _type_name(item)
        for key, item in value.items()
    }
    return keys, dict(sorted(types.items()))


def _structured_evidence(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except _DuplicateKeyError as exc:
        key = exc.key if _SAFE_KEY.fullmatch(exc.key) else "<unsafe-key>"
        return {"status": "duplicate-key", "key": key, "size_bytes": len(raw.encode("utf-8"))}
    except json.JSONDecodeError:
        return {"status": "invalid-json", "size_bytes": len(raw.encode("utf-8"))}
    if not isinstance(value, dict):
        return {"status": "non-object", "type": _type_name(value)}

    root_keys, root_types = _safe_keys(value)
    evidence: dict[str, Any] = {
        "status": "parsed",
        "root_keys": root_keys,
        "root_types": root_types,
        "known_fields": {
            name: _safe_scalar(value[name])
            for name in _ROOT_FIELDS
            if name != "commit_info" and name in value
        },
    }
    commit = value.get("commit_info")
    if isinstance(commit, dict):
        commit_keys, commit_types = _safe_keys(commit)
        evidence["commit_info"] = {
            "type": "object",
            "keys": commit_keys,
            "types": commit_types,
            "known_fields": {
                name: _safe_scalar(commit[name]) for name in _COMMIT_FIELDS if name in commit
            },
        }
    else:
        evidence["commit_info"] = _safe_scalar(commit)
    return evidence


def capture_uv_version_evidence(output: Path) -> dict[str, Any]:
    if (
        output.name != OUTPUT_NAME
        or output.exists()
        or output.is_symlink()
        or not output.parent.is_dir()
    ):
        raise UvVersionEvidenceError("uv version evidence destination is invalid")
    human = _run_uv(("-V",))
    structured = _run_uv(("self", "version", "--output-format", "json"))
    if any(len(value.encode("utf-8")) > MAX_COMMAND_BYTES for value in (human, structured)):
        raise UvVersionEvidenceError("pinned uv version evidence output is oversized")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "human_output": (
            {"status": "captured", "value": human}
            if _SAFE_HUMAN.fullmatch(human)
            else {"status": "omitted", "size_bytes": len(human.encode("utf-8"))}
        ),
        "structured_output": _structured_evidence(structured),
    }
    payload = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise UvVersionEvidenceError("uv version evidence receipt is oversized")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        capture_uv_version_evidence(arguments.output)
    except UvVersionEvidenceError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
