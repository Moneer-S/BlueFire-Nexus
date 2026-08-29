from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire import source_intake_run_validation
from bluefire.action_packages import verify_action_package
from bluefire.source_intake import perform_source_intake
from bluefire.source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    KEY_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    LICENSE_SHA256,
    LICENSE_SIZE_BYTES,
    PACKAGE_ID,
    PACKAGE_VERSION,
    PUBLISHER_ID,
    REQUIRED_NOTICE,
    REVIEWED_OPCODE,
    SOURCE_ASSET,
    SOURCE_COMMIT,
    SOURCE_SHA256,
    SOURCE_SIZE_BYTES,
    SourceIntakePackageError,
    build_gate09_action_package,
    gate09_intake_request,
    gate09_package_components,
    validate_gate09_intake_envelope,
)
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "bluefire" / "data"


def _intake(tmp_path: Path):
    destination = tmp_path / "intake"
    destination.mkdir()
    return perform_source_intake(DATA, destination, gate09_intake_request())


def test_pinned_assets_transform_and_build_one_verified_package(tmp_path: Path) -> None:
    source = (DATA / SOURCE_ASSET).read_bytes()
    license_payload = (DATA / LICENSE_ASSET).read_bytes()
    assert len(source) == SOURCE_SIZE_BYTES
    assert "sha256:" + hashlib.sha256(source).hexdigest() == SOURCE_SHA256
    assert len(license_payload) == LICENSE_SIZE_BYTES
    assert "sha256:" + hashlib.sha256(license_payload).hexdigest() == LICENSE_SHA256
    assert REQUIRED_NOTICE.encode("utf-8") in license_payload

    intake = _intake(tmp_path)
    validated = validate_gate09_intake_envelope(intake.envelope)
    key = Ed25519PrivateKey.generate()
    package = build_gate09_action_package(validated, private_key=key)
    verified = verify_action_package(
        package,
        trusted_signers={(PUBLISHER_ID, KEY_ID): key.public_key()},
        bluefire_version="0.1.0",
        platform="windows",
    )

    assert verified.manifest.package_id == PACKAGE_ID
    assert verified.manifest.version == PACKAGE_VERSION
    assert verified.manifest.license.spdx_id == LICENSE_ID
    assert verified.manifest.license.notice == REQUIRED_NOTICE
    assert verified.manifest.provenance.revision == SOURCE_COMMIT
    assert verified.manifest.behavior_ids == (BEHAVIOR_ID,)
    assert verified.manifest.action_ids == (ACTION_ID,)
    assert verified.behaviors[0].techniques == ("T1082",)
    assert verified.behaviors[0].execution_state.value == "action"
    assert verified.actions[0].program.steps[0].opcode == REVIEWED_OPCODE
    assert REVIEWED_OPCODE == "endpoint.discovery.windows-version.v1"
    assert verified.manifest.platforms == ("windows",)
    assert verified.manifest.capabilities == ("system.discovery",)
    assert verified.behaviors[0].outputs[0].name == "windows_version"
    assert verified.behaviors[0].outputs[0].type == "artifact.endpoint.windows-version.v1"
    assert verified.actions[0].definition.outputs == verified.behaviors[0].outputs
    assert verified.actions[0].definition.provenance.derived is False
    assert verified.behaviors[0].provenance.derived is True


def test_package_recipe_is_deterministic_for_one_key_and_intake(tmp_path: Path) -> None:
    intake = _intake(tmp_path)
    key = Ed25519PrivateKey.generate()

    first = build_gate09_action_package(intake.envelope, private_key=key)
    second = build_gate09_action_package(intake.envelope, private_key=key)

    assert first == second
    assert json.loads(first)["integrity"]["content_digest"].startswith("sha256:")


def test_self_consistent_unreviewed_projection_cannot_expand_catalog(tmp_path: Path) -> None:
    intake = _intake(tmp_path)
    forged = copy.deepcopy(intake.envelope)
    forged["record"]["output"]["technique_id"] = "T1016"
    forged["record"]["transformation_history"][0]["output_sha256"] = content_hash(
        forged["record"]["output"]
    )
    forged["record_sha256"] = content_hash(forged["record"])

    with pytest.raises(SourceIntakePackageError, match="reviewed T1082 projection"):
        gate09_package_components(forged)


def test_record_digest_and_review_metadata_are_recomputed(tmp_path: Path) -> None:
    intake = _intake(tmp_path)
    bad_digest = copy.deepcopy(intake.envelope)
    bad_digest["record_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(SourceIntakePackageError, match="record digest"):
        validate_gate09_intake_envelope(bad_digest)

    changed_review = copy.deepcopy(intake.envelope)
    changed_review["record"]["review"]["license_review"] = "conditional"
    changed_review["record_sha256"] = content_hash(changed_review["record"])
    with pytest.raises(SourceIntakePackageError, match="review is not reviewed"):
        validate_gate09_intake_envelope(changed_review)


def test_recipe_contains_no_upstream_description_or_execution_material(tmp_path: Path) -> None:
    intake = _intake(tmp_path)
    manifest, payload = gate09_package_components(intake.envelope)
    serialized = json.dumps({"manifest": manifest, "payload": payload}, sort_keys=True)

    assert "kill_chain_phases" not in serialized
    assert "external_references" not in serialized
    assert "system hostname get" not in serialized
    assert "description" in serialized  # authored output-contract descriptions remain explicit
    assert payload["actions"][0]["program"]["steps"] == [
        {
            "opcode": REVIEWED_OPCODE,
            "adapter": "bluefire.builtin-runner-adapter.v1",
            "constants": {},
        }
    ]


def test_package_recipe_rejects_extra_or_forged_transformation_audit(tmp_path: Path) -> None:
    intake = _intake(tmp_path)
    forged_records = []

    extra_record = copy.deepcopy(intake.envelope)
    extra_record["record"]["unreviewed"] = "payload"
    forged_records.append(extra_record)

    extra_event = copy.deepcopy(intake.envelope)
    extra_event["record"]["transformation_history"][0]["unreviewed"] = True
    forged_records.append(extra_event)

    false_canonical_input = copy.deepcopy(intake.envelope)
    false_canonical_input["record"]["transformation_history"][0]["canonical_input_sha256"] = (
        "sha256:" + "0" * 64
    )
    forged_records.append(false_canonical_input)

    incomplete_disposition = copy.deepcopy(intake.envelope)
    incomplete_disposition["record"]["transformation_history"][0]["source_field_disposition"][
        "discarded"
    ].pop()
    forged_records.append(incomplete_disposition)

    for forged in forged_records:
        forged["record_sha256"] = content_hash(forged["record"])
        with pytest.raises(SourceIntakePackageError):
            gate09_package_components(forged)


def test_native_windows_version_validation_accepts_only_the_exact_result() -> None:
    valid = {
        "operating_system": "windows",
        "major_version": 10,
        "minor_version": 0,
        "build_number": 26100,
    }
    assert dict(source_intake_run_validation._windows_version_output(valid)) == valid

    malformed = [
        {**valid, "major_version": True},
        {**valid, "minor_version": False},
        {**valid, "build_number": True},
        {**valid, "architecture": "x86_64"},
        {key: value for key, value in valid.items() if key != "build_number"},
        {**valid, "operating_system": "linux"},
    ]
    for output in malformed:
        with pytest.raises(ValueError, match="native Windows version output is invalid"):
            source_intake_run_validation._windows_version_output(output)


def test_native_runner_evidence_id_uses_the_rust_blank_field_contract() -> None:
    evidence = {
        "schema_version": "bluefire.runner-evidence.v1",
        "evidence_id": "sha256:" + "0" * 64,
        "output": {"operating_system": "windows"},
    }
    expected_body = {**evidence, "evidence_id": ""}

    assert source_intake_run_validation._runner_evidence_id(evidence) == content_hash(expected_body)
    without_id = dict(evidence)
    without_id.pop("evidence_id")
    assert source_intake_run_validation._runner_evidence_id(evidence) != content_hash(without_id)
