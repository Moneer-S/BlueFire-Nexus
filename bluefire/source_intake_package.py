"""Gate 09 recipe binding reviewed ATT&CK metadata to a BlueFire action.

The imported source contributes only a neutral technique identifier and title.
Execution remains an alias to BlueFire's independently implemented, compiled,
Windows-only, fixed-FFI ``endpoint.discovery.windows-version.v1`` operation.
"""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .action_packages import (
    ACTION_PACKAGE_PAYLOAD_SCHEMA,
    ACTION_PROGRAM_ADAPTER,
    ACTION_PROGRAM_SCHEMA,
    build_signed_action_package,
)
from .util import content_hash

SOURCE_ID = "research.mitre-attack-enterprise.v1"
SOURCE_PROJECT = "mitre/cti"
SOURCE_VERSION = "ATT&CK-v19.2"
SOURCE_COMMIT = (
    "8543c5b05bd9bbcace9fc37f30bba96b675b6f33"  # pragma: allowlist secret -- public Git object
)
SOURCE_TAG_OBJECT = (
    "8378689cbd8cf6ad7d566d3924c3c9755417cf43"  # pragma: allowlist secret -- public Git object
)
SOURCE_BLOB = (
    "456248b9947555603bfe2981ae8d931cb2ba88a7"  # pragma: allowlist secret -- public Git object
)
SOURCE_SHA256 = "sha256:dd2e50ceef844302a690a1debac8336864e93ebd19da526eefac3072f5ee9a02"
SOURCE_SIZE_BYTES = 6_617
SOURCE_ASSET = "mitre_attack_t1082_v19_2.json"
LICENSE_ASSET = "mitre_attack_v19_2_LICENSE.txt"
LICENSE_ID = "LicenseRef-MITRE-ATTACK-2026"
LICENSE_SHA256 = "sha256:4de9222b0d5bc69b758f9cf0afdaea48fdcbfe7d33c7481973a6aa07d6cbea9d"
LICENSE_SIZE_BYTES = 2_311
REQUIRED_NOTICE = (
    "© 2026 The MITRE Corporation. This work is reproduced and distributed "
    "with the permission of The MITRE Corporation."
)

SOURCE_PATH = (
    "enterprise-attack/attack-pattern/attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1.json"
)
SOURCE_REFERENCE = f"https://github.com/mitre/cti/blob/{SOURCE_COMMIT}/{SOURCE_PATH}"
LICENSE_REFERENCE = f"https://github.com/mitre/cti/blob/{SOURCE_COMMIT}/LICENSE.txt"
INTAKE_ID = "intake.mitre-t1082.v1"
TRANSFORMER_NAME = "mitre-attack-technique-v1"
TRANSFORMER_VERSION = "1.0.0"

PUBLISHER_ID = "bluefire.source-intake"
KEY_ID = "local-reviewed-t1082-v1"
PACKAGE_ID = "bluefire-research.attack-system-information"
PACKAGE_VERSION = "19.2.0"
BEHAVIOR_ID = "research.attack.system-information-discovery.v1"
ACTION_ID = "research.attack.system-information-discovery-action.v1"
REVIEWED_OPCODE = "endpoint.discovery.windows-version.v1"

_EXPECTED_OUTPUT: Mapping[str, Any] = {
    "created": "2017-05-31T21:31:04.307Z",
    "deprecated": False,
    "modified": "2026-05-12T15:12:00.625Z",
    "name": "System Information Discovery",
    "reference_url": "https://attack.mitre.org/techniques/T1082",
    "revoked": False,
    "schema_version": "bluefire.mitre-attack-technique-metadata.v1",
    "source_object_id": "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1",
    "technique_id": "T1082",
    "x_mitre_version": "3.0",
}
_EXPECTED_CANONICAL_INPUT_SHA256 = (
    "sha256:2f40458d19cf6192add68bca1247e68b8f38999672414c34e3bfb6e6744844d6"
)
_EXPECTED_CANONICAL_INPUT_SIZE_BYTES = 5_060
_EXPECTED_OUTPUT_SIZE_BYTES = 393
_EXPECTED_DISPOSITION_SHA256 = (
    "sha256:dcb38e27612c127a9b54ba9fd4872b4ead1fc394cc5c7276e61c07e74b0ccd1a"
)

_FILE_REVIEW = (
    "The pinned STIX 2.0 bundle contains exactly one declarative T1082 "
    "attack-pattern. BlueFire projects only neutral identity, version, status, "
    "and timestamp fields; descriptions, citations, procedures, command examples, "
    "and unrelated references are discarded and never executed."
)
_ATTRIBUTION = "MITRE ATT&CK® T1082 metadata. " + REQUIRED_NOTICE


class SourceIntakePackageError(ValueError):
    """Raised when the source record cannot authorize the fixed package recipe."""


def gate09_intake_request() -> dict[str, Any]:
    """Return the exact reviewed request for the vendored v19.2 T1082 file."""

    return {
        "schema_version": "bluefire.source-intake-request.v1",
        "intake_id": INTAKE_ID,
        "source": {
            "path": SOURCE_ASSET,
            "sha256": SOURCE_SHA256,
            "size_bytes": SOURCE_SIZE_BYTES,
            "media_type": "application/json",
        },
        "provenance": {
            "research_source_id": SOURCE_ID,
            "project": SOURCE_PROJECT,
            "exact_ref": SOURCE_COMMIT,
            "version": SOURCE_VERSION,
            "retrieved_at": "2026-08-29",
            "reference_url": SOURCE_REFERENCE,
        },
        "review": {
            "license": LICENSE_ID,
            "license_url": LICENSE_REFERENCE,
            "license_review": "reviewed",
            "file_review": _FILE_REVIEW,
            "file_disposition": "declarative_metadata",
            "use_classification": "metadata_import",
            "attribution": _ATTRIBUTION,
        },
        "transformer": {
            "name": TRANSFORMER_NAME,
            "version": TRANSFORMER_VERSION,
        },
    }


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceIntakePackageError(f"{context} must be an object")
    return value


def validate_gate09_intake_envelope(value: Any) -> Mapping[str, Any]:
    """Recompute the record binding before it can expand the action catalog."""

    envelope = _mapping(value, "source intake envelope")
    if set(envelope) != {"schema_version", "record", "record_sha256"}:
        raise SourceIntakePackageError("source intake envelope fields are not exact")
    if envelope.get("schema_version") != "bluefire.source-intake-envelope.v1":
        raise SourceIntakePackageError("source intake envelope schema is unsupported")
    record = _mapping(envelope.get("record"), "source intake record")
    if set(record) != {
        "intake_id",
        "output",
        "provenance",
        "review",
        "schema_version",
        "source",
        "transformation_history",
        "transformer",
    }:
        raise SourceIntakePackageError("source intake record fields are not exact")
    record_sha256 = envelope.get("record_sha256")
    if not isinstance(record_sha256, str) or content_hash(record) != record_sha256:
        raise SourceIntakePackageError("source intake record digest is invalid")

    expected = gate09_intake_request()
    exact_fields = {
        "intake_id": expected["intake_id"],
        "provenance": expected["provenance"],
        "review": expected["review"],
        "source": expected["source"],
        "transformer": expected["transformer"],
    }
    for name, expected_value in exact_fields.items():
        if record.get(name) != expected_value:
            raise SourceIntakePackageError(f"source intake record {name} is not reviewed")
    if record.get("schema_version") != "bluefire.source-intake-record.v1":
        raise SourceIntakePackageError("source intake record schema is unsupported")
    output = _mapping(record.get("output"), "source intake output")
    if dict(output) != dict(_EXPECTED_OUTPUT):
        raise SourceIntakePackageError("source intake output is not the reviewed T1082 projection")

    history = record.get("transformation_history")
    if not isinstance(history, list) or len(history) != 1:
        raise SourceIntakePackageError("source intake transformation history is not exact")
    event = _mapping(history[0], "source intake transformation event")
    if (
        set(event)
        != {
            "canonical_input_sha256",
            "canonical_input_size_bytes",
            "input_sha256",
            "input_size_bytes",
            "operation",
            "output_sha256",
            "output_size_bytes",
            "sequence",
            "source_field_disposition",
            "transformer",
        }
        or event.get("sequence") != 1
        or event.get("operation") != "declarative_metadata_projection"
        or event.get("canonical_input_sha256") != _EXPECTED_CANONICAL_INPUT_SHA256
        or event.get("canonical_input_size_bytes") != _EXPECTED_CANONICAL_INPUT_SIZE_BYTES
        or event.get("input_sha256") != SOURCE_SHA256
        or event.get("input_size_bytes") != SOURCE_SIZE_BYTES
        or event.get("output_sha256") != content_hash(output)
        or event.get("output_size_bytes") != _EXPECTED_OUTPUT_SIZE_BYTES
        or event.get("transformer") != expected["transformer"]
    ):
        raise SourceIntakePackageError("source intake transformation binding is invalid")
    disposition = _mapping(event.get("source_field_disposition"), "field disposition")
    projected = disposition.get("projected_or_validated")
    discarded = disposition.get("discarded")
    if (
        set(disposition) != {"discarded", "projected_or_validated"}
        or not isinstance(projected, list)
        or not isinstance(discarded, list)
        or projected != sorted(set(projected))
        or discarded != sorted(set(discarded))
        or len(projected) != 16
        or len(discarded) != 36
        or content_hash(disposition) != _EXPECTED_DISPOSITION_SHA256
    ):
        raise SourceIntakePackageError("source field disposition is incomplete")
    return envelope


def _definition_provenance(record_sha256: str, *, action: bool) -> dict[str, Any]:
    relationship = (
        "Independent BlueFire compiled RtlGetVersion operation; no upstream executable "
        "content was copied."
        if action
        else "Neutral metadata projection; upstream descriptions and procedures were discarded."
    )
    return {
        "source": "Reviewed MITRE ATT&CK® v19.2 T1082 intake",
        "reference": f"urn:bluefire:source-intake:{INTAKE_ID}:sha256:{record_sha256.removeprefix('sha256:')}",
        "license": LICENSE_ID,
        "derived": not action,
        "notes": relationship + " " + REQUIRED_NOTICE,
    }


def gate09_package_components(intake_envelope: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create the fixed manifest and payload after authoritative intake validation."""

    envelope = validate_gate09_intake_envelope(intake_envelope)
    record_sha256 = str(envelope["record_sha256"])
    behavior_provenance = _definition_provenance(record_sha256, action=False)
    action_provenance = _definition_provenance(record_sha256, action=True)
    output = {
        "name": "windows_version",
        "type": "artifact.endpoint.windows-version.v1",
        "description": "Windows major, minor, and build numbers from the fixed RtlGetVersion API.",
    }
    capabilities = ["system.discovery"]
    platforms = ["windows"]
    manifest = {
        "package_id": PACKAGE_ID,
        "version": PACKAGE_VERSION,
        "compatibility": {
            "minimum_bluefire_version": "0.1.0",
            "maximum_bluefire_version_exclusive": "1.0.0",
        },
        "license": {
            "spdx_id": LICENSE_ID,
            "notice": REQUIRED_NOTICE,
        },
        "provenance": {
            "publisher_id": PUBLISHER_ID,
            "source": "BlueFire reviewed T1082 metadata package recipe",
            "reference": SOURCE_REFERENCE,
            "revision": SOURCE_COMMIT,
        },
        "platforms": platforms,
        "capabilities": capabilities,
        "safety_tiers": ["safe"],
        "behavior_ids": [BEHAVIOR_ID],
        "action_ids": [ACTION_ID],
    }
    behavior = {
        "schema_version": "bluefire.behavior.v1",
        "id": BEHAVIOR_ID,
        "title": _EXPECTED_OUTPUT["name"],
        "purpose": (
            "Observe the Windows major, minor, and build version through BlueFire's "
            "independently compiled, fixed RtlGetVersion operation."
        ),
        "execution_state": "action",
        "safety_tier": "safe",
        "platforms": platforms,
        "techniques": ["T1082"],
        "capabilities": capabilities,
        "inputs": [],
        "outputs": [output],
        "parameters": [],
        "action_ids": [ACTION_ID],
        "telemetry": ["endpoint.discovery.windows_version_observed"],
        "detection_hints": [
            "Compare the observed Windows build number with an independently maintained host "
            "inventory."
        ],
        "provenance": behavior_provenance,
        "limitations": [
            "Reports only Windows major, minor, and build numbers; it does not collect accounts, "
            "architecture, network configuration, or host file content."
        ],
    }
    action = {
        "schema_version": "bluefire.action.v1",
        "id": ACTION_ID,
        "title": "Observe the Windows version",
        "purpose": "Dispatch the reviewed compiled BlueFire RtlGetVersion operation.",
        "safety_tier": "safe",
        "capabilities": capabilities,
        "platforms": platforms,
        "inputs": [],
        "outputs": [output],
        "parameters": [],
        "mutates": False,
        "cleanup_action_id": None,
        "provenance": action_provenance,
    }
    payload = {
        "schema_version": ACTION_PACKAGE_PAYLOAD_SCHEMA,
        "behaviors": [behavior],
        "actions": [
            {
                "definition": action,
                "program": {
                    "schema_version": ACTION_PROGRAM_SCHEMA,
                    "steps": [
                        {
                            "opcode": REVIEWED_OPCODE,
                            "adapter": ACTION_PROGRAM_ADAPTER,
                            "constants": {},
                        }
                    ],
                },
            }
        ],
    }
    return manifest, payload


def build_gate09_action_package(
    intake_envelope: Any,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str = KEY_ID,
) -> bytes:
    """Build a signed package; the signing key remains caller-owned and ephemeral."""

    manifest, payload = gate09_package_components(intake_envelope)
    return build_signed_action_package(
        manifest=manifest,
        payload=payload,
        key_id=key_id,
        private_key=private_key,
    )


__all__ = [
    "ACTION_ID",
    "BEHAVIOR_ID",
    "INTAKE_ID",
    "KEY_ID",
    "LICENSE_ASSET",
    "LICENSE_ID",
    "LICENSE_REFERENCE",
    "LICENSE_SHA256",
    "LICENSE_SIZE_BYTES",
    "PACKAGE_ID",
    "PACKAGE_VERSION",
    "PUBLISHER_ID",
    "REQUIRED_NOTICE",
    "REVIEWED_OPCODE",
    "SOURCE_ASSET",
    "SOURCE_BLOB",
    "SOURCE_COMMIT",
    "SOURCE_ID",
    "SOURCE_REFERENCE",
    "SOURCE_SHA256",
    "SOURCE_SIZE_BYTES",
    "SOURCE_TAG_OBJECT",
    "SOURCE_VERSION",
    "SourceIntakePackageError",
    "build_gate09_action_package",
    "gate09_intake_request",
    "gate09_package_components",
    "validate_gate09_intake_envelope",
]
