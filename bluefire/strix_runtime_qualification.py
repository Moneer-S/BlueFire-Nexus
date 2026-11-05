"""Load one exact Strix CLI-startup qualification for runtime admission.

This module does not qualify a target, model, container, containment control,
or security outcome. It validates the immutable runtime identity produced by
the separately reviewed qualification tool. A per-attempt admission resolver
must still bind scope, authorization, network, custody, protected roots, and
cleanup before :class:`bluefire.strix_engine_runtime.StrixEngineRuntime` can
launch anything. No production resolver currently consumes this receipt, so
loading it does not admit a live runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, cast

from .strix_adapter import StrixBuildIdentity
from .strix_redistribution_review import (
    is_blocked_strix_redistribution_review,
    strix_redistribution_review,
)
from .util import canonical_json_bytes, json_clone


class StrixRuntimeQualificationError(ValueError):
    """Raised when a runtime-qualification manifest cannot be admitted."""


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "bluefire_source_revision",
        "inputs",
        "runner",
        "build_identity",
        "probe",
        "execution",
        "qualification",
    }
)
_INPUT_FIELDS = frozenset(
    {
        "candidate_manifest_ref",
        "candidate_checksums_ref",
        "preparation_manifest_ref",
        "preparation_checksums_ref",
        "runtime_receipt_ref",
        "oci_inventory_ref",
        "transfer_bundle_ref",
        "threat_review_ref",
    }
)
_RUNNER_FIELDS = frozenset({"system", "release", "machine", "image_os", "image_version"})
_BUILD_FIELDS = frozenset(
    {
        "engine",
        "package_version",
        "source_revision",
        "source_tree_sha256",
        "package_sha256",
        "executable_sha256",
        "image_reference",
        "image_inventory_sha256",
        "prompt_upstream_sha256",
        "prompt_overlay_sha256",
        "prompt_patched_sha256",
    }
)
_PROBE_FIELDS = frozenset(
    {
        "argv",
        "exit_code",
        "stdout",
        "stderr",
        "elapsed_milliseconds",
        "network_namespace",
        "process_namespace",
        "mount_namespace",
        "probe_uid",
        "probe_gid",
        "credential_environment",
        "help_tokens_verified",
        "runtime_unchanged",
        "owned_work_absent",
    }
)
_STREAM_FIELDS = frozenset({"bytes", "sha256"})
_EXECUTION_FIELDS = frozenset(
    {
        "strix_imported",
        "strix_cli",
        "argv",
        "sidecar",
        "sandbox_container",
        "target",
        "model",
        "network",
    }
)
_QUALIFICATION_FIELDS = frozenset(
    {
        "runtime_qualified",
        "production_runtime_admitted",
        "scope",
        "reproducibility_proven",
        "containment_proven",
        "lifecycle_proven",
        "target_execution_proven",
        "model_execution_proven",
        "effectiveness_proven",
        "license_review_complete",
        "redistribution_authorized",
        "redistribution_review",
        "limitations",
    }
)
RUNTIME_QUALIFICATION_LIMITATIONS = (
    "Qualification covers one exact Linux x86-64 installed CLI startup only.",
    "No sandbox container, target, model, sidecar, or network operation was exercised.",
    "Attempt containment, cancellation, cleanup, and evidence admission require separate proof.",
    "A second clean build has not established artifact reproducibility.",
    "Go TUI, bundled viewer assets, complete runtime wheels, and OCI notices/rights remain unresolved.",
    "No production resolver currently admits this receipt into a live engine attempt.",
)


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StrixRuntimeQualificationError(f"{label} fields are invalid")
    return dict(cast(Mapping[str, Any], value))


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixRuntimeQualificationError(f"{label} digest is invalid")
    return value


def _text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise StrixRuntimeQualificationError(f"{label} is invalid")
    return value


def _stream(value: Any, label: str) -> None:
    row = _exact(value, _STREAM_FIELDS, label)
    size = row["bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= 1024 * 1024:
        raise StrixRuntimeQualificationError(f"{label} size is invalid")
    _digest(row["sha256"], label)


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise StrixRuntimeQualificationError("runtime qualification is unavailable") from exc
    if (
        not stat.S_ISREG(path_metadata.st_mode)
        or path.is_symlink()
        or path_metadata.st_size < 0
        or path_metadata.st_size > _MAX_MANIFEST_BYTES
    ):
        raise StrixRuntimeQualificationError("runtime qualification is not a bounded regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StrixRuntimeQualificationError(
            "runtime qualification is not a bounded regular file"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size < 0
            or opened.st_size > _MAX_MANIFEST_BYTES
            or (path_metadata.st_dev, path_metadata.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise StrixRuntimeQualificationError(
                "runtime qualification is not a bounded regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, _MAX_MANIFEST_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_MANIFEST_BYTES:
                raise StrixRuntimeQualificationError(
                    "runtime qualification is not a bounded regular file"
                )
        finished = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        finished_identity = (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
        )
        if total != opened.st_size or opened_identity != finished_identity:
            raise StrixRuntimeQualificationError("runtime qualification changed while being read")
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrixRuntimeQualificationError("runtime qualification is not canonical JSON") from exc
    if not isinstance(value, dict) or payload != canonical_json_bytes(value) + b"\n":
        raise StrixRuntimeQualificationError("runtime qualification is not canonical JSON")
    return cast(dict[str, Any], json_clone(value)), payload


@dataclass(frozen=True, slots=True)
class QualifiedStrixRuntime:
    """Immutable compatibility evidence a future trusted resolver may admit."""

    runtime_qualification_ref: str
    runtime_qualified: bool
    production_runtime_admitted: bool
    bluefire_source_revision: str
    threat_review_ref: str
    build: StrixBuildIdentity

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_qualification_ref": self.runtime_qualification_ref,
            "runtime_qualified": self.runtime_qualified,
            "production_runtime_admitted": self.production_runtime_admitted,
            "bluefire_source_revision": self.bluefire_source_revision,
            "threat_review_ref": self.threat_review_ref,
            "build": self.build.to_dict(),
        }


def load_strix_runtime_qualification(path: Path, *, expected_ref: str) -> QualifiedStrixRuntime:
    """Load one canonical manifest only when its controller-held ref matches."""

    manifest, payload = _read_manifest(path)
    expected = _digest(expected_ref, "expected runtime qualification")
    actual = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    if actual != expected:
        raise StrixRuntimeQualificationError("runtime qualification reference changed")
    row = _exact(manifest, _MANIFEST_FIELDS, "runtime qualification")
    if (
        row["schema_version"] != "bluefire.strix-runtime-admission.v1"
        or row["status"] != "qualified-installed-cli-startup-only"
    ):
        raise StrixRuntimeQualificationError("runtime qualification schema is unsupported")
    revision = row["bluefire_source_revision"]
    if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
        raise StrixRuntimeQualificationError("BlueFire source revision is invalid")

    inputs = _exact(row["inputs"], _INPUT_FIELDS, "runtime qualification inputs")
    for name, value in inputs.items():
        _digest(value, name.replace("_", " "))

    runner = _exact(row["runner"], _RUNNER_FIELDS, "runtime qualification runner")
    if runner["system"] != "Linux" or str(runner["machine"]).lower() not in {"x86_64", "amd64"}:
        raise StrixRuntimeQualificationError("runtime qualification platform is unsupported")
    for name, value in runner.items():
        _text(value, f"runner {name}")

    build_row = _exact(row["build_identity"], _BUILD_FIELDS, "Strix build identity")
    if build_row.pop("engine") != "strix":
        raise StrixRuntimeQualificationError("runtime qualification engine is unsupported")
    try:
        build = StrixBuildIdentity(**cast(dict[str, str], build_row))
    except (TypeError, ValueError) as exc:
        raise StrixRuntimeQualificationError("Strix build identity is invalid") from exc
    if inputs["oci_inventory_ref"] != build.image_inventory_sha256:
        raise StrixRuntimeQualificationError("OCI inventory identity is contradictory")

    probe = _exact(row["probe"], _PROBE_FIELDS, "runtime qualification probe")
    if (
        probe["argv"] != ["--help"]
        or probe["exit_code"] != 0
        or probe["network_namespace"] != "isolated-empty"
        or probe["process_namespace"] != "isolated"
        or probe["mount_namespace"] != "isolated"
        or probe["probe_uid"] != 65534
        or probe["probe_gid"] != 65534
        or probe["credential_environment"] is not False
        or probe["help_tokens_verified"] is not True
        or probe["runtime_unchanged"] is not True
        or probe["owned_work_absent"] is not True
    ):
        raise StrixRuntimeQualificationError("runtime qualification probe is not admissible")
    elapsed = probe["elapsed_milliseconds"]
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or not 0 <= elapsed <= 30_000:
        raise StrixRuntimeQualificationError("runtime qualification duration is invalid")
    _stream(probe["stdout"], "probe stdout")
    _stream(probe["stderr"], "probe stderr")

    execution = _exact(row["execution"], _EXECUTION_FIELDS, "runtime execution claims")
    if execution != {
        "strix_imported": True,
        "strix_cli": True,
        "argv": ["--help"],
        "sidecar": False,
        "sandbox_container": False,
        "target": False,
        "model": False,
        "network": False,
    }:
        raise StrixRuntimeQualificationError("runtime execution claims are invalid")

    qualification = _exact(
        row["qualification"], _QUALIFICATION_FIELDS, "runtime qualification claims"
    )
    if not is_blocked_strix_redistribution_review(qualification["redistribution_review"]):
        raise StrixRuntimeQualificationError("runtime redistribution review must remain blocked")
    if qualification != {
        "runtime_qualified": True,
        "production_runtime_admitted": False,
        "scope": "exact-installed-cli-startup-only",
        "reproducibility_proven": False,
        "containment_proven": False,
        "lifecycle_proven": False,
        "target_execution_proven": False,
        "model_execution_proven": False,
        "effectiveness_proven": False,
        "license_review_complete": False,
        "redistribution_authorized": False,
        "redistribution_review": strix_redistribution_review(),
        "limitations": list(RUNTIME_QUALIFICATION_LIMITATIONS),
    }:
        raise StrixRuntimeQualificationError("runtime qualification claims are invalid")

    return QualifiedStrixRuntime(
        runtime_qualification_ref=actual,
        runtime_qualified=True,
        production_runtime_admitted=False,
        bluefire_source_revision=revision,
        threat_review_ref=inputs["threat_review_ref"],
        build=build,
    )
