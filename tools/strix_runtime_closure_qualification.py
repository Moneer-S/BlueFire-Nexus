"""Revalidation of the exact upstream Strix qualification output."""

from __future__ import annotations

import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from tools import build_strix_engine_candidate as candidate
from tools import qualify_strix_runtime_candidate as qualification
from tools.strix_runtime_closure_common import (
    MAX_FILE_BYTES,
    StrixRuntimeClosurePreparationError,
    _digest_bytes,
    _is_reparse,
    _read_regular,
    _safe_relative,
    _sha256_hex,
    _strict_json,
)

PYTHON_VERSION = "3.12.14"
SETUP_PYTHON_ACTION = "ece7cb06caefa5fff74198d8649806c4678c61a1"
MAX_JSON_BYTES = 128 * 1024 * 1024
_REVISION = re.compile(r"^[0-9a-f]{40}$")


def _parse_checksums(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise StrixRuntimeClosurePreparationError(
            "qualification checksums are not ASCII"
        ) from exc
    result: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+/-]{0,500})", line
        )
        if match is None:
            raise StrixRuntimeClosurePreparationError(
                "qualification checksum syntax is invalid"
            )
        relative = _safe_relative(match.group(2), "qualification checksum").as_posix()
        if relative in result:
            raise StrixRuntimeClosurePreparationError(
                "qualification checksum is duplicated"
            )
        result[relative] = match.group(1)
    if not result:
        raise StrixRuntimeClosurePreparationError(
            "qualification checksum set is empty"
        )
    return result


def _load_qualification(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise StrixRuntimeClosurePreparationError(
            "qualification root is not a real directory"
        )
    checksum_payload = _read_regular(
        root / qualification.CHECKSUMS_NAME, MAX_JSON_BYTES, allow_empty=False
    )
    checksums = _parse_checksums(checksum_payload)
    observed: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        details = path.lstat()
        if path.is_symlink() or _is_reparse(details):
            raise StrixRuntimeClosurePreparationError(
                "qualification output contains a link"
            )
        if stat.S_ISDIR(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode):
            raise StrixRuntimeClosurePreparationError(
                "qualification output contains a special file"
            )
        observed.add(relative)
    if observed != set(checksums) | {qualification.CHECKSUMS_NAME}:
        raise StrixRuntimeClosurePreparationError(
            "qualification output inventory drifted"
        )
    for relative, expected in checksums.items():
        payload = _read_regular(
            root.joinpath(*PurePosixPath(relative).parts), MAX_FILE_BYTES
        )
        if _sha256_hex(payload) != expected:
            raise StrixRuntimeClosurePreparationError(
                "qualification artifact digest drifted"
            )
    manifest_payload = _read_regular(
        root / qualification.QUALIFICATION_MANIFEST_NAME,
        MAX_JSON_BYTES,
        allow_empty=False,
    )
    receipt_payload = _read_regular(
        root / qualification.RUNTIME_RECEIPT_NAME,
        MAX_JSON_BYTES,
        allow_empty=False,
    )
    manifest = _strict_json(manifest_payload, "qualification manifest")
    receipt = _strict_json(receipt_payload, "runtime receipt")
    if not isinstance(manifest, dict) or not isinstance(receipt, dict):
        raise StrixRuntimeClosurePreparationError(
            "qualification documents are not objects"
        )
    if (
        manifest.get("schema")
        != "bluefire.strix-runtime-qualification-preparation.v1"
        or manifest.get("status") != "prepared-not-runtime-qualified"
        or manifest.get("python_runtime") != receipt
        or manifest.get("actions", {}).get("setup_python")
        != SETUP_PYTHON_ACTION
        or manifest.get("candidate", {}).get("upstream_commit")
        != candidate.UPSTREAM_COMMIT
        or not isinstance(manifest.get("bluefire_source_revision"), str)
        or _REVISION.fullmatch(str(manifest["bluefire_source_revision"])) is None
    ):
        raise StrixRuntimeClosurePreparationError(
            "qualification identity is unsupported"
        )
    execution = manifest.get("execution")
    if not isinstance(execution, dict) or not execution or any(execution.values()):
        raise StrixRuntimeClosurePreparationError(
            "qualification unexpectedly records execution"
        )
    if (
        receipt.get("platform", {}).get("system") != "Linux"
        or str(receipt.get("platform", {}).get("machine", "")).lower()
        not in {"x86_64", "amd64"}
        or receipt.get("python", {}).get("version") != PYTHON_VERSION
        or receipt.get("network_resolution_during_install") is not False
        or receipt.get("all_dependency_payloads_are_wheels") is not True
        or receipt.get("engine_imported") is not False
        or receipt.get("engine_executed") is not False
    ):
        raise StrixRuntimeClosurePreparationError(
            "qualified runtime receipt is incompatible"
        )
    return manifest, receipt, {
        "runtime_qualification_ref": _digest_bytes(manifest_payload),
        "runtime_receipt_ref": _digest_bytes(receipt_payload),
        "qualification_checksums_ref": _digest_bytes(checksum_payload),
    }
