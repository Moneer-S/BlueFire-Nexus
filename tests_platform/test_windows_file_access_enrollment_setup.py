"""Closed synthetic setup/anchor recipe only; no provisioning or trust claims."""

from __future__ import annotations

import copy

import pytest

from bluefire import windows_file_access_enrollment_setup as module
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_enrollment import declared_candidate

RECORD_IDENTITY = (0xFEDCBA9876543210, (1 << 127) | 5)


def declared_anchor(record_raw: bytes, identity: tuple[int, int] = RECORD_IDENTITY):
    row = module.enrollment._document(record_raw)
    volume, file_id = module.file_identity_wire(*identity)
    return {
        "schema_version": module.ANCHOR_SCHEMA,
        "enrollment_id": row["enrollment_id"],
        "generation": row["generation"],
        "host_id": row["host"]["host_id"],
        "record_identity": {"volume_serial": volume, "file_id": file_id},
        "enrollment_digest": content_hash(row),
        "setup_receipt_digest": row["setup_receipt_digest"],
        "image_sha256": row["native_image"]["sha256"],
        "credential_binding_digest": content_hash(row["credential_reference"]),
    }


def test_anchor_recipe_is_separate_fixed_generation_tree_and_exact_nine_fields():
    raw = canonical_json_bytes(declared_candidate())
    anchor = declared_anchor(raw)
    assert len(anchor) == len(module._ANCHOR_FIELDS.split()) == 9
    paths = module._anchor_paths(anchor["generation"])
    assert paths == (
        "C:\\",
        r"C:\ProgramData",
        r"C:\ProgramData\BlueFire",
        r"C:\ProgramData\BlueFire\EndpointAccessAnchors",
        r"C:\ProgramData\BlueFire\EndpointAccessAnchors\0123456789abcdef0123456789abcdef",
        r"C:\ProgramData\BlueFire\EndpointAccessAnchors\0123456789abcdef0123456789abcdef\setup.json",
    )
    assert paths[-1] != module.enrollment.ANCHOR_PATH
    assert module._match_anchor_record(canonical_json_bytes(anchor), raw, RECORD_IDENTITY) is None
    assert anchor["record_identity"] == {
        "volume_serial": "fedcba9876543210",
        "file_id": "05000000000000000000000000000080",
    }


@pytest.mark.parametrize("generation", ["0" * 31, "A" * 32, "../" + "0" * 29, True, 123])
def test_anchor_paths_refuse_aliases_traversal_and_unbounded_generation(generation):
    with pytest.raises(module.contract.NativeWireError):
        module._anchor_paths(generation)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "schema",
        "enrollment",
        "generation",
        "host",
        "volume_high",
        "file_high",
        "numeric_volume",
        "numeric_file",
        "zero_file",
        "enrollment_digest",
        "receipt",
        "image",
        "credential",
        "float",
    ],
)
def test_anchor_closed_geometry_and_all_record_bindings_are_checked(fault):
    raw = canonical_json_bytes(declared_candidate())
    row = copy.deepcopy(declared_anchor(raw))
    if fault == "unknown":
        row["verified"] = True
    elif fault == "schema":
        row["schema_version"] = "caller"
    elif fault == "enrollment":
        row["enrollment_id"] = "win-file-enrollment-" + "f" * 32
    elif fault == "generation":
        row["generation"] = "f" * 32
        row["enrollment_id"] = "win-file-enrollment-" + "f" * 32
    elif fault == "host":
        row["host_id"] = "sha256:" + "f" * 64
    elif fault == "volume_high":
        row["record_identity"]["volume_serial"] = "7edcba9876543210"
    elif fault == "file_high":
        row["record_identity"]["file_id"] = "05000000000000000000000000000000"
    elif fault == "numeric_volume":
        row["record_identity"]["volume_serial"] = RECORD_IDENTITY[0]
    elif fault == "numeric_file":
        row["record_identity"]["file_id"] = RECORD_IDENTITY[1]
    elif fault == "zero_file":
        row["record_identity"]["file_id"] = "0" * 32
    elif fault == "enrollment_digest":
        row["enrollment_digest"] = "sha256:" + "f" * 64
    elif fault == "receipt":
        row["setup_receipt_digest"] = "sha256:" + "f" * 64
    elif fault == "image":
        row["image_sha256"] = "sha256:" + "f" * 64
    elif fault == "credential":
        row["credential_binding_digest"] = "sha256:" + "f" * 64
    else:
        row["generation"] = 1.5
    with pytest.raises(module.contract.NativeWireError):
        module._match_anchor_record(canonical_json_bytes(row), raw, RECORD_IDENTITY)


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"\xef\xbb\xbf{}",
        "{}".encode("utf-16"),
        b'{"generation":1,"generation":2}',
        b" " * 4097,
    ],
)
def test_anchor_bytes_are_strict_utf8_duplicate_free_and_bounded(raw):
    with pytest.raises(module.contract.NativeWireError):
        module._anchor_document(raw)


def test_publication_requires_missing_original_reviewed_lifecycle_not_hash_consistency():
    with pytest.raises(module.enrollment.WindowsEnrollmentUnavailable):
        module.publish_windows_file_access_setup()
    for field in (
        "candidate",
        "host",
        "setup_receipt_digest",
        "native_image",
        "verified",
        "backend",
    ):
        with pytest.raises(TypeError):
            module.publish_windows_file_access_setup(**{field: "synthetic assertion"})
