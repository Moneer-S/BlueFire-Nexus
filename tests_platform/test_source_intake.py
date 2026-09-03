from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

import bluefire.source_intake as source_intake
from bluefire.source_intake import (
    BUILTIN_SOURCE_TRANSFORMERS,
    MAX_CONTAINER_ITEMS,
    MAX_JSON_DEPTH,
    MAX_SOURCE_BYTES,
    SourceIntakeError,
    SourceTransformation,
    SourceTransformer,
    SourceTransformerRegistry,
    perform_source_intake,
)
from bluefire.util import canonical_json_bytes, content_hash

PIN = "8543c5b05bd9bbcace9fc37f30bba96b675b6f33"  # pragma: allowlist secret
ROOT = Path(__file__).resolve().parents[1]


def _attack_pattern(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1",
        "created": "2017-05-31T21:30:27.342Z",
        "modified": "2025-10-24T17:48:19.158Z",
        "created_by_ref": "identity--c78cb6f5-95a1-4a3d-a1b5-3f82e6d12427",
        "name": "System Information Discovery",
        "description": (
            "Adversaries may look for details about network configuration.\n\n"
            "This prose may say command, payload, or input without materializing any field."
        ),
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1082",
                "url": "https://attack.mitre.org/techniques/T1082",
            },
            {"source_name": "example-citation", "description": "Citation only."},
        ],
        "object_marking_refs": ["marking-definition--00000000-0000-0000-0000-000000000000"],
        "revoked": False,
        "x_mitre_attack_spec_version": "3.3.0",
        "x_mitre_deprecated": False,
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_is_subtechnique": False,
        "x_mitre_platforms": ["Linux", "Windows", "macOS"],
        "x_mitre_version": "1.7",
    }
    value.update(overrides)
    return value


def _technique(**overrides: Any) -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--4b868c14-1f22-47cd-9227-9b8ec5bf42c0",
        "spec_version": "2.0",
        "objects": [_attack_pattern(**overrides)],
    }


def _request(payload: bytes, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "bluefire.source-intake-request.v1",
        "intake_id": "intake.mitre-system-information.v1",
        "source": {
            "path": (
                "enterprise-attack/attack-pattern/"
                "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1.json"
            ),
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "media_type": "application/json",
        },
        "provenance": {
            "research_source_id": "research.mitre-attack-enterprise.v1",
            "project": "MITRE CTI",
            "exact_ref": PIN,
            "version": "ATT&CK-v19.2",
            "retrieved_at": "2026-08-29",
            "reference_url": f"https://github.com/mitre-attack/attack-stix-data/tree/{PIN}",
        },
        "review": {
            "license": "LicenseRef-ATTACK-Terms",
            "license_url": "https://attack.mitre.org/resources/terms-of-use/",
            "license_review": "reviewed",
            "file_review": "One declarative STIX attack-pattern file was reviewed field by field.",
            "file_disposition": "declarative_metadata",
            "use_classification": "metadata_import",
            "attribution": "MITRE ATT&CK; ATT&CK is a registered trademark of The MITRE Corporation.",
        },
        "transformer": {"name": "mitre-attack-technique-v1", "version": "1.0.0"},
    }
    value.update(overrides)
    return value


def _write_source(root: Path, value: Any, *, pretty: bool = True) -> bytes:
    path = (
        root
        / "enterprise-attack"
        / "attack-pattern"
        / "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if pretty:
        payload = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    else:
        payload = canonical_json_bytes(value)
    path.write_bytes(payload)
    return payload


def _assert_empty(path: Path) -> None:
    assert list(path.iterdir()) == []


def test_official_style_attack_metadata_is_projected_deterministically(tmp_path: Path) -> None:
    source = tmp_path / "source"
    first_destination = tmp_path / "first"
    second_destination = tmp_path / "second"
    source.mkdir()
    first_destination.mkdir()
    second_destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(payload)

    first = perform_source_intake(source, first_destination, request)
    second = perform_source_intake(source, second_destination, request)

    target_name = "intake.mitre-system-information.v1.json"
    padding = max(1, 228 - len(os.fspath(tmp_path)) - len(target_name) - 2)
    long_destination = tmp_path / ("d" * padding)
    long_destination.mkdir()
    assert 220 <= len(os.fspath(long_destination / target_name)) < 248
    long_path_result = perform_source_intake(source, long_destination, request)

    assert first.path.name == "intake.mitre-system-information.v1.json"
    assert first.path.read_bytes() == second.path.read_bytes()
    assert long_path_result.path.read_bytes() == first.path.read_bytes()
    assert first.path.read_bytes() == canonical_json_bytes(first.envelope)
    assert first.record_sha256 == content_hash(first.envelope["record"])
    output = first.envelope["record"]["output"]
    assert first.output_sha256 == content_hash(output)
    assert output == {
        "created": "2017-05-31T21:30:27.342Z",
        "deprecated": False,
        "modified": "2025-10-24T17:48:19.158Z",
        "name": "System Information Discovery",
        "reference_url": "https://attack.mitre.org/techniques/T1082",
        "revoked": False,
        "schema_version": "bluefire.mitre-attack-technique-metadata.v1",
        "source_object_id": "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1",
        "technique_id": "T1082",
        "x_mitre_version": "1.7",
    }
    history = first.envelope["record"]["transformation_history"]
    assert history[0]["input_sha256"] == request["source"]["sha256"]
    assert history[0]["output_sha256"] == content_hash(output)
    disposition = history[0]["source_field_disposition"]
    assert "/objects/0/description" in disposition["discarded"]
    assert "/objects/0/kill_chain_phases/0/phase_name" in disposition["discarded"]
    assert "/objects/0/name" in disposition["projected_or_validated"]
    assert "/objects/0/external_references/0/url" in disposition["projected_or_validated"]
    assert set(disposition["discarded"]).isdisjoint(disposition["projected_or_validated"])
    assert set(disposition["discarded"]) | set(disposition["projected_or_validated"]) == set(
        source_intake._json_field_paths(_technique())
    )
    serialized = first.path.read_text(encoding="utf-8")
    assert "description" not in output
    assert "kill_chain_phases" not in output
    assert str(source) not in serialized


def test_transformer_inventory_is_an_exact_static_allowlist() -> None:
    assert BUILTIN_SOURCE_TRANSFORMERS.inventory() == (
        {
            "name": "mitre-attack-technique-v1",
            "output_schema": "bluefire.mitre-attack-technique-metadata.v1",
            "version": "1.0.0",
        },
    )


def test_exact_pinned_t1082_bundle_passes_the_core_intake(tmp_path: Path) -> None:
    asset = ROOT / "bluefire" / "data" / "mitre_attack_t1082_v19_2.json"
    destination = tmp_path / "destination"
    destination.mkdir()
    payload = asset.read_bytes()
    assert len(payload) == 6_617
    assert hashlib.sha256(payload).hexdigest() == (
        "dd2e50ceef844302a690a1debac8336864e93ebd19da526eefac3072f5ee9a02"  # pragma: allowlist secret -- public source digest
    )
    request = _request(payload)
    request["source"]["path"] = asset.name

    result = perform_source_intake(asset.parent, destination, request)

    assert result.envelope["record"]["output"]["technique_id"] == "T1082"
    assert result.envelope["record"]["output"]["x_mitre_version"] == "3.0"


@pytest.mark.parametrize(
    ("source_change", "error"),
    [
        ({"sha256": "sha256:" + "0" * 64}, "SHA-256"),
        ({"size_bytes": 1}, "identity or size"),
    ],
)
def test_exact_source_identity_is_required_without_state_delta(
    tmp_path: Path, source_change: dict[str, Any], error: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(payload)
    request["source"].update(source_change)

    with pytest.raises(SourceIntakeError, match=error):
        perform_source_intake(source, destination, request)

    _assert_empty(destination)


@pytest.mark.parametrize(
    "field",
    [
        "command",
        "command_line",
        "executor",
        "dependencies",
        "input-arguments",
        "payloads",
        "install_script",
        "source_code",
        "command-template",
        "executor_name",
        "dependency_source",
        "input_file",
        "payload_url",
    ],
)
def test_recursive_materialization_fields_are_rejected_before_output(
    tmp_path: Path, field: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    technique = _technique(x_extension={"nested": [{field: "must never materialize"}]})
    payload = _write_source(source, technique, pretty=False)

    with pytest.raises(SourceIntakeError, match="forbidden materialization field"):
        perform_source_intake(source, destination, _request(payload))

    _assert_empty(destination)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b'{"a":1,"a":2}', "duplicate"),
        (b'{"number":1.5}', "floating-point"),
        (b'{"number":9223372036854775808}', "signed 64-bit"),
        (b'{"value":NaN}', "floating-point"),
    ],
)
def test_ambiguous_or_nonfinite_json_is_rejected(
    tmp_path: Path, payload: bytes, error: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    path = source / _request(payload)["source"]["path"]
    path.parent.mkdir(parents=True)
    path.write_bytes(payload)

    with pytest.raises(SourceIntakeError, match=error):
        perform_source_intake(source, destination, _request(payload))

    _assert_empty(destination)


def test_json_depth_and_container_limits_are_enforced(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    deep: Any = "leaf"
    for _ in range(MAX_JSON_DEPTH + 1):
        deep = {"safe": deep}
    payload = _write_source(source, deep, pretty=False)
    with pytest.raises(SourceIntakeError, match="depth limit"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)

    wide = {f"safe_{index}": index for index in range(MAX_CONTAINER_ITEMS + 1)}
    payload = _write_source(source, wide, pretty=False)
    with pytest.raises(SourceIntakeError, match="object field limit"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)


@pytest.mark.parametrize(
    ("section", "field", "value", "error"),
    [
        ("review", "license_review", "conditional", "must be reviewed"),
        ("review", "file_disposition", "executable", "declarative_metadata"),
        ("review", "use_classification", "external_adapter", "metadata_import"),
        ("review", "license", "not an SPDX id!", "SPDX-shaped"),
        ("transformer", "name", "unreviewed-transformer", "not allowlisted"),
        ("transformer", "version", "2.0.0", "not allowlisted"),
    ],
)
def test_review_and_transformer_must_be_exactly_allowlisted(
    tmp_path: Path, section: str, field: str, value: str, error: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(payload)
    request[section][field] = value

    with pytest.raises(SourceIntakeError, match=error):
        perform_source_intake(source, destination, request)

    _assert_empty(destination)


def test_unknown_request_fields_and_mutable_reference_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    unknown = _request(payload)
    unknown["execute"] = False
    with pytest.raises(SourceIntakeError, match="unknown fields"):
        perform_source_intake(source, destination, unknown)
    _assert_empty(destination)

    unbound = _request(payload)
    unbound["provenance"]["reference_url"] = "https://github.com/mitre-attack/attack-stix-data"
    with pytest.raises(SourceIntakeError, match="exact immutable source ref"):
        perform_source_intake(source, destination, unbound)
    _assert_empty(destination)

    mutable = _request(payload)
    mutable["provenance"]["exact_ref"] = "main"
    mutable["provenance"][
        "reference_url"
    ] = "https://github.com/mitre-attack/attack-stix-data/tree/main"
    with pytest.raises(SourceIntakeError, match="immutable commit"):
        perform_source_intake(source, destination, mutable)
    _assert_empty(destination)

    mutable_version = _request(payload)
    mutable_version["provenance"]["version"] = "latest"
    with pytest.raises(SourceIntakeError, match="mutable label"):
        perform_source_intake(source, destination, mutable_version)
    _assert_empty(destination)


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"type": "malware"}, "type must be attack-pattern"),
        ({"revoked": "false"}, "must be booleans"),
        ({"modified": "2016-01-01T00:00:00Z"}, "must not precede"),
        ({"x_mitre_version": "latest"}, "major.minor"),
        ({"external_references": []}, "bounded non-empty"),
    ],
)
def test_attack_transformer_rejects_invalid_semantics(
    tmp_path: Path, change: dict[str, Any], error: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique(**change))

    with pytest.raises(SourceIntakeError, match=error):
        perform_source_intake(source, destination, _request(payload))

    _assert_empty(destination)


def test_attack_reference_id_and_url_must_be_uniquely_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    references = copy.deepcopy(_attack_pattern()["external_references"])
    references[0]["url"] = "https://attack.mitre.org/techniques/T1016"
    payload = _write_source(source, _technique(external_references=references))
    with pytest.raises(SourceIntakeError, match="exactly match"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)

    references[0]["url"] = "https://attack.mitre.org/techniques/T1082/"
    payload = _write_source(source, _technique(external_references=references))
    with pytest.raises(SourceIntakeError, match="exactly match"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)

    references[0]["url"] = "https://attack.mitre.org/techniques/T1082"
    references.append(copy.deepcopy(references[0]))
    payload = _write_source(source, _technique(external_references=references))
    with pytest.raises(SourceIntakeError, match="exactly one"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)


def test_bundle_refuses_zero_or_multiple_objects(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    for objects in ([], [_attack_pattern(), _attack_pattern()]):
        bundle = _technique()
        bundle["objects"] = objects
        payload = _write_source(source, bundle)
        with pytest.raises(SourceIntakeError, match="exactly one object"):
            perform_source_intake(source, destination, _request(payload))
        _assert_empty(destination)


@pytest.mark.parametrize(
    "unsafe_path",
    ["../T1016.json", "/absolute/T1016.json", "attack-patterns\\T1016.json", "C:T1016.json"],
    ids=("parent-traversal", "posix-absolute", "windows-separated", "drive-relative"),
)
def test_source_path_traversal_and_alternate_syntax_are_rejected(
    tmp_path: Path, unsafe_path: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(payload)
    request["source"]["path"] = unsafe_path
    with pytest.raises(SourceIntakeError, match="path|unsafe"):
        perform_source_intake(source, destination, request)
    _assert_empty(destination)


def test_source_symlink_and_hardlink_are_refused(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = canonical_json_bytes(_technique())
    actual = tmp_path / "actual.json"
    actual.write_bytes(payload)
    link = source / _request(payload)["source"]["path"]
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(actual)
    except OSError:
        pytest.skip("symbolic-link creation is unavailable on this host")
    with pytest.raises(SourceIntakeError, match="symbolic links|reparse"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)

    link.unlink()
    os.link(actual, link)
    with pytest.raises(SourceIntakeError, match="singly-linked"):
        perform_source_intake(source, destination, _request(payload))
    _assert_empty(destination)


def test_destination_symlink_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "source"
    real_destination = tmp_path / "real-destination"
    linked_destination = tmp_path / "linked-destination"
    source.mkdir()
    real_destination.mkdir()
    payload = _write_source(source, _technique())
    try:
        linked_destination.symlink_to(real_destination, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic-link creation is unavailable on this host")
    with pytest.raises(SourceIntakeError, match="symbolic link|reparse"):
        perform_source_intake(source, linked_destination, _request(payload))
    _assert_empty(real_destination)


def test_stale_output_is_preserved_and_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    stale = destination / "intake.mitre-system-information.v1.json"
    stale.write_bytes(b"operator-owned")

    with pytest.raises(SourceIntakeError, match="already exists"):
        perform_source_intake(source, destination, _request(payload))

    assert stale.read_bytes() == b"operator-owned"
    assert list(destination.iterdir()) == [stale]

    temporary_destination = tmp_path / "temporary-destination"
    temporary_destination.mkdir()
    monkeypatch.setattr(source_intake.secrets, "token_hex", lambda _size: "f" * 12)
    stale_temporary = temporary_destination / (source_intake._TEMPORARY_OUTPUT_PREFIX + "f" * 12)
    stale_temporary.write_bytes(b"operator-owned-temporary")
    with pytest.raises(SourceIntakeError, match="atomically published"):
        perform_source_intake(source, temporary_destination, _request(payload))
    assert stale_temporary.read_bytes() == b"operator-owned-temporary"
    assert list(temporary_destination.iterdir()) == [stale_temporary]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-relative publication regression")
def test_windows_publication_preserves_a_rebound_temporary_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    token = "a" * 12
    temporary = destination / (source_intake._TEMPORARY_OUTPUT_PREFIX + token)
    target = destination / "intake.mitre-system-information.v1.json"
    real_rename = source_intake._windows_rename_descriptor

    monkeypatch.setattr(source_intake.secrets, "token_hex", lambda _size: token)

    def rename_then_rebind(descriptor: int, root_descriptor: int, target_name: str) -> None:
        real_rename(descriptor, root_descriptor, target_name)
        temporary.write_bytes(b"operator-owned-temporary")

    monkeypatch.setattr(source_intake, "_windows_rename_descriptor", rename_then_rebind)

    with pytest.raises(SourceIntakeError, match="temporary output changed"):
        perform_source_intake(source, destination, _request(payload))

    assert temporary.read_bytes() == b"operator-owned-temporary"
    assert not target.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows handle cleanup regression")
def test_windows_failed_handle_cleanup_retains_every_named_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    token = "b" * 12
    temporary = destination / (source_intake._TEMPORARY_OUTPUT_PREFIX + token)
    target = destination / "intake.mitre-system-information.v1.json"
    real_rename = source_intake._windows_rename_descriptor

    monkeypatch.setattr(source_intake.secrets, "token_hex", lambda _size: token)

    def rename_then_rebind(descriptor: int, root_descriptor: int, target_name: str) -> None:
        real_rename(descriptor, root_descriptor, target_name)
        temporary.write_bytes(b"operator-owned-temporary")

    def refuse_handle_cleanup(_descriptor: int) -> None:
        raise OSError("simulated handle cleanup refusal")

    def refuse_path_cleanup(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("failed handle cleanup must never fall back to pathname deletion")

    monkeypatch.setattr(source_intake, "_windows_rename_descriptor", rename_then_rebind)
    monkeypatch.setattr(source_intake, "_windows_mark_delete_descriptor", refuse_handle_cleanup)
    monkeypatch.setattr(Path, "unlink", refuse_path_cleanup)

    with pytest.raises(SourceIntakeError, match="exact cleanup could not be guaranteed"):
        perform_source_intake(source, destination, _request(payload))

    assert temporary.read_bytes() == b"operator-owned-temporary"
    assert target.is_file()


def test_publication_failure_removes_only_its_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())

    def refuse_publication(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("simulated publication refusal")

    if os.name == "nt":
        monkeypatch.setattr(source_intake, "_windows_rename_descriptor", refuse_publication)
    else:
        monkeypatch.setattr(source_intake, "_posix_rename_no_replace", refuse_publication)
    with pytest.raises(SourceIntakeError, match="atomically published"):
        perform_source_intake(source, destination, _request(payload))
    if os.name == "nt":
        _assert_empty(destination)
    else:
        retained = list(destination.iterdir())
        assert len(retained) == 1
        assert retained[0].name.startswith(source_intake._TEMPORARY_OUTPUT_PREFIX)


def test_missing_destination_during_publication_is_a_typed_failure(tmp_path: Path) -> None:
    destination = tmp_path / "missing"

    with pytest.raises(SourceIntakeError, match="destination is unavailable"):
        source_intake._publish_new_file(destination, "output.json", b"{}")


def test_descriptor_close_failure_preserves_error_and_closes_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    real_close = source_intake.os.close
    closed: list[int] = []

    def refuse_publication(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("simulated publication refusal")

    def close_then_report(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)
        if len(closed) == 1:
            raise OSError("simulated descriptor close failure")

    if os.name == "nt":
        monkeypatch.setattr(source_intake, "_windows_rename_descriptor", refuse_publication)
    else:
        monkeypatch.setattr(source_intake, "_posix_rename_no_replace", refuse_publication)
    monkeypatch.setattr(source_intake.os, "close", close_then_report)

    with pytest.raises(SourceIntakeError, match="atomically published"):
        source_intake._publish_new_file(destination, "output.json", b"{}")

    assert len(closed) == 2
    assert closed[0] != closed[1]


def test_source_close_failure_does_not_mask_verification_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    payload = _write_source(source, _technique())
    request = _request(payload)
    request["source"]["size_bytes"] += 1
    parsed = source_intake.SourceIntakeRequest.from_mapping(request)
    real_close = source_intake.os.close

    def close_then_report(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("simulated descriptor close failure")

    monkeypatch.setattr(source_intake.os, "close", close_then_report)

    with pytest.raises(SourceIntakeError, match="identity or size"):
        source_intake._read_verified_source(source, parsed.source)


def test_post_publication_identity_failure_uses_only_exact_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    target = destination / "intake.mitre-system-information.v1.json"
    original_lstat = Path.lstat
    target_calls = 0

    def fail_first_post_link_lstat(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal target_calls
        if path == target:
            target_calls += 1
            if target_calls == 2:
                raise PermissionError("simulated post-link identity refusal")
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fail_first_post_link_lstat)
    with pytest.raises(SourceIntakeError, match="atomically published"):
        perform_source_intake(source, destination, _request(payload))

    assert target_calls == 2
    if os.name == "nt":
        _assert_empty(destination)
    else:
        assert list(destination.iterdir()) == [target]


def test_custom_transformers_cannot_emit_materialization_fields(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(
        payload,
        transformer={"name": "unsafe-test-v1", "version": "1.0.0"},
    )
    fields = source_intake._json_field_paths(_technique())
    registry = SourceTransformerRegistry(
        (
            SourceTransformer(
                "unsafe-test-v1",
                "1.0.0",
                "bluefire.test-metadata.v1",
                lambda _value: SourceTransformation(
                    metadata={
                        "schema_version": "bluefire.test-metadata.v1",
                        "nested": {"payload": "blocked"},
                    },
                    projected_fields=fields,
                    discarded_fields=(),
                ),
            ),
        )
    )
    with pytest.raises(SourceIntakeError, match="forbidden materialization field"):
        perform_source_intake(source, destination, request, registry=registry)
    _assert_empty(destination)


def test_transformer_must_dispose_every_source_field(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    payload = _write_source(source, _technique())
    request = _request(
        payload,
        transformer={"name": "incomplete-test-v1", "version": "1.0.0"},
    )
    registry = SourceTransformerRegistry(
        (
            SourceTransformer(
                "incomplete-test-v1",
                "1.0.0",
                "bluefire.test-metadata.v1",
                lambda _value: SourceTransformation(
                    metadata={"schema_version": "bluefire.test-metadata.v1"},
                    projected_fields=("type",),
                    discarded_fields=(),
                ),
            ),
        )
    )
    with pytest.raises(SourceIntakeError, match="incomplete field disposition"):
        perform_source_intake(source, destination, request, registry=registry)
    _assert_empty(destination)


def test_nondeterministic_transformer_is_rejected_without_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    document = _technique()
    payload = _write_source(source, document)
    request = _request(
        payload,
        transformer={"name": "stateful-test-v1", "version": "1.0.0"},
    )
    calls = 0

    def stateful(_value: Any) -> SourceTransformation:
        nonlocal calls
        calls += 1
        return SourceTransformation(
            metadata={"schema_version": "bluefire.test-metadata.v1", "sequence": calls},
            projected_fields=source_intake._json_field_paths(document),
            discarded_fields=(),
        )

    registry = SourceTransformerRegistry(
        (SourceTransformer("stateful-test-v1", "1.0.0", "bluefire.test-metadata.v1", stateful),)
    )
    with pytest.raises(SourceIntakeError, match="not deterministic"):
        perform_source_intake(source, destination, request, registry=registry)
    _assert_empty(destination)


def test_oversized_source_is_rejected_before_filesystem_access(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    request = _request(canonical_json_bytes(_technique()))
    request["source"]["size_bytes"] = MAX_SOURCE_BYTES + 1

    with pytest.raises(SourceIntakeError, match="between 1"):
        perform_source_intake(source, destination, request)

    _assert_empty(destination)
