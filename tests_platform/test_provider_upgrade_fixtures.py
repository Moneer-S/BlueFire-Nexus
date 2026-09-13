from __future__ import annotations

import base64
import copy
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import bluefire.cli as cli
import tools.run_provider_gate_journey as provider_gate_helper
from bluefire import __version__
from bluefire.action_packages import verify_action_package
from bluefire.api import APIError
from bluefire.cli import _execute, _parser
from bluefire.config import RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_api import json_body, request, running_server
from tests_platform.test_service import EXECUTE_PROFILE_ACTIONS, _ready_inventory

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "provider_upgrade"
PACKAGE_ID = "fixture.provider-upgrade-pack"
BEHAVIOR_ID = "fixture.provider-upgrade.behavior.v1"
ACTION_ID = "fixture.provider-upgrade.action.v1"
PROVIDER_ID = "fixture.provider-upgrade.runtime.v1"
VERSIONS = ("1.0.0", "2.0.0", "3.0.0")
PRIVATE_RESPONSE_FIELDS = {
    "artifact_hex",
    "canonical_envelope_bytes",
    "canonical_content_bytes",
}


def _load_document(path: Path) -> dict[str, Any]:
    serialized = path.read_text(encoding="utf-8")
    value = json.loads(serialized) if path.suffix == ".json" else yaml.safe_load(serialized)
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _fixture_index() -> dict[str, Any]:
    return _load_document(FIXTURE_ROOT / "fixture-index.json")


def _trust_request(version: str = "1.0.0") -> dict[str, Any]:
    return _load_document(FIXTURE_ROOT / str(_fixture_row(version)["publisher_trust_file"]))


def _fixture_row(version: str) -> Mapping[str, Any]:
    rows = _fixture_index()["packages"]
    assert isinstance(rows, list)
    return next(row for row in rows if row["version"] == version)


def _fixture_envelope(version: str) -> dict[str, Any]:
    return _load_document(FIXTURE_ROOT / str(_fixture_row(version)["file"]))


def _public_key(version: str) -> Ed25519PublicKey:
    encoded = str(_trust_request(version)["public_key"])
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(encoded + "="))


def _verified_fixture(version: str) -> Any:
    trust = _trust_request(version)
    return verify_action_package(
        canonical_json_bytes(_fixture_envelope(version)),
        trusted_signers={(trust["publisher_id"], trust["key_id"]): _public_key(version)},
        bluefire_version=__version__,
        platform="windows",
    )


def _read_uleb(value: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(value):
        byte = value[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        assert shift < 64
    raise AssertionError("truncated unsigned LEB128 value")


def _wasm_sections(artifact: bytes) -> dict[int, bytes]:
    assert artifact[:8] == b"\x00asm\x01\x00\x00\x00"
    sections: dict[int, bytes] = {}
    offset = 8
    previous = 0
    while offset < len(artifact):
        section_id = artifact[offset]
        offset += 1
        size, offset = _read_uleb(artifact, offset)
        end = offset + size
        assert end <= len(artifact)
        assert section_id > previous
        assert section_id not in sections
        sections[section_id] = artifact[offset:end]
        previous = section_id
        offset = end
    assert offset == len(artifact)
    return sections


def _wasm_exports(payload: bytes) -> dict[str, tuple[int, int]]:
    count, offset = _read_uleb(payload, 0)
    exports: dict[str, tuple[int, int]] = {}
    for _ in range(count):
        size, offset = _read_uleb(payload, offset)
        end = offset + size
        assert end <= len(payload)
        name = payload[offset:end].decode("utf-8")
        offset = end
        assert offset < len(payload)
        kind = payload[offset]
        offset += 1
        index, offset = _read_uleb(payload, offset)
        exports[name] = (kind, index)
    assert offset == len(payload)
    return exports


def _embedded_provider_outputs(artifact: bytes) -> tuple[bytes, ...]:
    data_section = _wasm_sections(artifact)[11]
    start_marker = b'{"outputs"'
    end_marker = b'"schema_version":"bluefire.provider-action-output.v1"}'
    outputs: list[bytes] = []
    offset = 0
    while True:
        start = data_section.find(start_marker, offset)
        if start < 0:
            break
        end = data_section.index(end_marker, start) + len(end_marker)
        output = data_section[start:end]
        assert canonical_json_bytes(json.loads(output)) == output
        outputs.append(output)
        offset = end
    assert len(outputs) == 2
    return tuple(outputs)


def _assert_no_private_key_material(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            assert "private_key" not in normalized
            assert normalized not in {"secret", "seed", "signing_key"}
            _assert_no_private_key_material(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_private_key_material(child)


def _assert_public_response(value: Any) -> None:
    assert not isinstance(value, bytes)
    if isinstance(value, Mapping):
        assert PRIVATE_RESPONSE_FIELDS.isdisjoint(value)
        for child in value.values():
            _assert_public_response(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_public_response(child)


class ProviderUpgradeInventoryRunner:
    def __init__(self) -> None:
        inventory = dict(_ready_inventory(actions=EXECUTE_PROFILE_ACTIONS))
        inventory["platform"] = "windows"
        runtime_contract = {
            "kind": "wasm",
            "abi_version": "bluefire.provider-abi.v1",
            "runtime_version": "wasmi-1.1.0",
            "readiness": "ready",
            "no_host_imports": True,
            "hard_limits": {
                "max_module_bytes": 128 * 1024,
                "max_memory_bytes": 2 * 1024 * 1024,
                "max_input_bytes": 16 * 1024,
                "max_output_bytes": 16 * 1024,
                "fuel": 200_000,
            },
        }
        inventory["provider_runtimes"] = [
            {**runtime_contract, "contract_digest": content_hash(runtime_contract)}
        ]
        self.document = inventory

    def inventory(self) -> Mapping[str, Any]:
        return copy.deepcopy(self.document)

    def execute(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:  # pragma: no cover - lifecycle never dispatches
        raise AssertionError("provider upgrade lifecycle fixture must not dispatch")


@pytest.fixture
def provider_upgrade_service(
    tmp_path: Path,
) -> Iterator[BlueFireService]:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ProviderUpgradeInventoryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        yield service
    finally:
        service.close()


def _execute_profile(service: BlueFireService) -> RunnerProfile:
    return next(
        profile for profile in service._runner_profiles() if profile.mode is ExecutionMode.EXECUTE
    )


def _install(service: BlueFireService, version: str) -> Mapping[str, Any]:
    return service.install_action_package(
        {
            "envelope": _fixture_envelope(version),
            "installed_by": "provider-fixture-installer",
        }
    )


def _activate(service: BlueFireService, version: str) -> Mapping[str, Any]:
    return service.activate_action_package(
        PACKAGE_ID,
        version,
        {
            "runner_profile_id": _execute_profile(service).id,
            "activated_by": "provider-fixture-operator",
            "reason": f"activate independently signed provider fixture {version}",
        },
    )


def _readiness_row(service: BlueFireService) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    profile = service._profile(_execute_profile(service).id, ExecutionMode.EXECUTE)
    assert profile is not None
    _runner, _sandbox, readiness = service._execute_readiness_boundary(profile)
    row = next(item for item in readiness["enabled_actions"] if item["action_id"] == ACTION_ID)
    return readiness, row


def test_committed_provider_upgrade_fixtures_are_signed_real_no_import_wasm() -> None:
    index = _fixture_index()
    assert {path.name for path in FIXTURE_ROOT.iterdir() if path.is_file()} == {
        "fixture-index.json",
        "provider-1.0.0.signed.json",
        "provider-2.0.0.signed.json",
        "provider-3.0.0-output-limit.signed.json",
        "publisher-limit-trust.yaml",
        "publisher-trust.yaml",
    }
    assert index["package_id"] == PACKAGE_ID
    assert index["logical_behavior_id"] == BEHAVIOR_ID
    assert index["logical_action_id"] == ACTION_ID
    assert index["provider_id"] == PROVIDER_ID
    assert [row["version"] for row in index["packages"]] == list(VERSIONS)
    trust_documents = [
        _load_document(FIXTURE_ROOT / name) for name in index["publisher_trust_files"]
    ]
    for trust in trust_documents:
        assert set(trust) == {
            "publisher_id",
            "key_id",
            "public_key",
            "provenance",
            "trusted_by",
        }
        assert len(base64.urlsafe_b64decode(str(trust["public_key"]) + "=")) == 32
    for document in (
        index,
        *trust_documents,
        *(_fixture_envelope(version) for version in VERSIONS),
    ):
        _assert_no_private_key_material(document)

    packages = []
    signatures = set()
    artifacts = set()
    for version in VERSIONS:
        envelope = _fixture_envelope(version)
        verified = _verified_fixture(version)
        row = _fixture_row(version)
        provider = verified.manifest.provider
        assert provider is not None
        assert verified.manifest.package_id == PACKAGE_ID
        assert verified.manifest.version == version
        assert verified.manifest.action_ids == (ACTION_ID,)
        assert verified.manifest.behavior_ids == (BEHAVIOR_ID,)
        assert provider.provider_id == PROVIDER_ID
        assert verified.package_digest == row["package_digest"]
        assert verified.content_digest == row["content_digest"]
        assert provider.artifact_sha256 == row["artifact_sha256"]
        assert provider.artifact_size == row["artifact_size"]
        assert verified.provider_artifact_bytes is not None

        artifact = verified.provider_artifact_bytes
        sections = _wasm_sections(artifact)
        assert set(sections) == {1, 3, 5, 7, 10, 11}
        assert 2 not in sections
        assert sections[1] == b"\x01\x60\x02\x7f\x7f\x01\x7e"
        assert _wasm_exports(sections[7]) == {
            "memory": (2, 0),
            "bluefire_provider_run_v1": (0, 0),
        }
        embedded = _embedded_provider_outputs(artifact)
        embedded_version = "2.0.0" if version == "3.0.0" else version
        assert [json.loads(item)["outputs"]["result"]["value"] for item in embedded] == [
            f"{embedded_version}|message=verify|repeat_count=2",
            f"{embedded_version}|message=probe|repeat_count=1",
        ]
        assert [len(item) for item in embedded] == [177, 176]
        artifact_digest = str(provider.artifact_sha256)
        reference_version = "3.0.0-output-limit" if version == "3.0.0" else version
        assert verified.manifest.provenance.to_dict() == {
            "publisher_id": "bluefire.fixture.provider-upgrade",
            "source": (
                "Deterministically assembled no-import WebAssembly fixture committed "
                "with BlueFire Nexus"
            ),
            "reference": (
                f"urn:bluefire:fixture:provider-upgrade:{reference_version}:" f"{artifact_digest}"
            ),
            "revision": artifact_digest,
        }
        expected_definition_reference = f"urn:bluefire:fixture:provider-upgrade:{artifact_digest}"
        assert verified.actions[0].definition.provenance.reference == (
            expected_definition_reference
        )
        assert verified.behaviors[0].provenance.reference == expected_definition_reference
        assert len(base64.urlsafe_b64decode(str(envelope["signature"]["value"]) + "==")) == 64

        packages.append(verified)
        signatures.add(envelope["signature"]["value"])
        artifacts.add(artifact)

    assert len(signatures) == 3
    assert len(artifacts) == 2
    assert len({package.package_digest for package in packages}) == 3
    assert len({package.content_digest for package in packages}) == 3
    assert (
        packages[0].manifest.provider.artifact_sha256
        != packages[1].manifest.provider.artifact_sha256
    )
    assert (
        packages[1].manifest.provider.artifact_sha256
        == packages[2].manifest.provider.artifact_sha256
    )
    limit_row = _fixture_row("3.0.0")
    limit_provider = packages[2].manifest.provider
    assert limit_provider is not None
    limit_output = _embedded_provider_outputs(packages[2].provider_artifact_bytes or b"")[0]
    assert len(limit_output) == limit_row["canonical_output_bytes"] == 177
    assert limit_provider.limits.max_output_bytes == limit_row["signed_max_output_bytes"] == 176
    assert len(limit_output) == limit_provider.limits.max_output_bytes + 1
    assert limit_row["limit_condition"] == "canonical_output_exceeds_signed_max_output_bytes"
    assert limit_row["expected_run_status"] == "incomplete"
    assert limit_row["expected_step_error_code"] == "provider_runtime_failed"
    assert packages[2].key_id != packages[1].key_id
    assert (
        packages[0].actions[0].program.action_contract_digest
        == packages[1].actions[0].program.action_contract_digest
        == packages[2].actions[0].program.action_contract_digest
    )


def test_provider_upgrade_changes_catalog_and_readiness_then_cleans_up(
    provider_upgrade_service: BlueFireService,
) -> None:
    service = provider_upgrade_service
    baseline_catalog = service.catalog()["action_package_catalog"]
    trust_response = service.trust_action_package_publisher(_trust_request())
    installed_v1 = _install(service, "1.0.0")
    assert installed_v1["catalog_changed"] is False
    assert installed_v1["package"]["status"] == "installed"

    activated_v1 = _activate(service, "1.0.0")
    assert activated_v1["operation"] == "activation"
    readiness_v1, row_v1 = _readiness_row(service)
    binding_v1 = row_v1["provider_bindings"][0]
    expected_v1 = _fixture_row("1.0.0")
    assert row_v1["action_id"] == ACTION_ID
    assert row_v1["package_version"] == "1.0.0"
    assert row_v1["package_digest"] == expected_v1["package_digest"]
    assert row_v1["content_digest"] == expected_v1["content_digest"]
    assert binding_v1["artifact_sha256"] == expected_v1["artifact_sha256"]
    assert readiness_v1["catalog_authority"]["generation"] == activated_v1["catalog"]["generation"]
    assert (
        readiness_v1["catalog_authority"]["catalog_digest"]
        == activated_v1["catalog"]["catalog_digest"]
    )

    installed_v2 = _install(service, "2.0.0")
    assert installed_v2["catalog_changed"] is False
    assert service._catalog_snapshot.generation == activated_v1["catalog"]["generation"]

    activated_v2 = _activate(service, "2.0.0")
    assert activated_v2["operation"] == "upgrade"
    assert activated_v2["catalog_before"] == readiness_v1["catalog_authority"]
    assert activated_v2["catalog"]["generation"] == activated_v1["catalog"]["generation"] + 1
    assert activated_v2["catalog"]["catalog_digest"] != activated_v1["catalog"]["catalog_digest"]
    assert len(activated_v2["catalog"]["packages"]) == 1
    active_v2 = activated_v2["catalog"]["packages"][0]
    expected_v2 = _fixture_row("2.0.0")
    assert active_v2["package_id"] == PACKAGE_ID
    assert active_v2["package_version"] == "2.0.0"
    assert active_v2["package_digest"] == expected_v2["package_digest"]
    assert active_v2["content_digest"] == expected_v2["content_digest"]

    readiness_v2, row_v2 = _readiness_row(service)
    binding_v2 = row_v2["provider_bindings"][0]
    assert readiness_v2["catalog_authority"]["generation"] == activated_v2["catalog"]["generation"]
    assert (
        readiness_v2["catalog_authority"]["catalog_digest"]
        == activated_v2["catalog"]["catalog_digest"]
    )
    assert row_v2["action_id"] == ACTION_ID
    assert row_v2["package_version"] == "2.0.0"
    assert row_v2["package_digest"] == expected_v2["package_digest"]
    assert row_v2["content_digest"] == expected_v2["content_digest"]
    assert binding_v2["artifact_sha256"] == expected_v2["artifact_sha256"]
    assert row_v2 != row_v1
    assert binding_v2["artifact_sha256"] != binding_v1["artifact_sha256"]
    assert binding_v2["package_digest"] != binding_v1["package_digest"]
    assert binding_v2["content_digest"] != binding_v1["content_digest"]
    assert binding_v2["action_contract_digest"] == binding_v1["action_contract_digest"]
    assert binding_v2["runtime_contract_digest"] == binding_v1["runtime_contract_digest"]

    deactivated = service.deactivate_action_package(
        PACKAGE_ID,
        "2.0.0",
        {
            "package_digest": expected_v2["package_digest"],
            "expected_catalog_generation": activated_v2["catalog"]["generation"],
            "expected_catalog_digest": activated_v2["catalog"]["catalog_digest"],
            "deactivated_by": "provider-fixture-operator",
            "reason": "prove exact provider-upgrade deactivation",
        },
    )
    assert deactivated["catalog"]["generation"] == activated_v2["catalog"]["generation"] + 1
    assert deactivated["catalog"]["packages"] == []
    assert deactivated["catalog"]["catalog_digest"] == baseline_catalog["catalog_digest"]
    assert deactivated["catalog"]["generation"] != baseline_catalog["generation"]
    assert ACTION_ID not in service.registry.action_ids

    removed_v2 = service.remove_action_package(
        PACKAGE_ID,
        "2.0.0",
        {
            "package_digest": expected_v2["package_digest"],
            "expected_catalog_generation": deactivated["catalog"]["generation"],
            "expected_catalog_digest": deactivated["catalog"]["catalog_digest"],
            "removed_by": "provider-fixture-operator",
            "reason": "remove exact upgraded provider fixture",
        },
    )
    removed_v1 = service.remove_action_package(
        PACKAGE_ID,
        "1.0.0",
        {
            "package_digest": expected_v1["package_digest"],
            "expected_catalog_generation": removed_v2["catalog"]["generation"],
            "expected_catalog_digest": removed_v2["catalog"]["catalog_digest"],
            "removed_by": "provider-fixture-operator",
            "reason": "remove superseded provider fixture",
        },
    )
    assert removed_v2["package"]["status"] == "removed"
    assert removed_v1["package"]["status"] == "removed"
    assert service.action_package(PACKAGE_ID, version="2.0.0")["package"]["status"] == "removed"
    assert service.action_package(PACKAGE_ID, version="1.0.0")["package"]["status"] == "removed"

    public_responses = (
        trust_response,
        installed_v1,
        activated_v1,
        readiness_v1,
        installed_v2,
        activated_v2,
        readiness_v2,
        deactivated,
        removed_v2,
        removed_v1,
        service.catalog(),
        service.action_packages(),
        service.action_package(PACKAGE_ID, version="1.0.0"),
        service.action_package(PACKAGE_ID, version="2.0.0"),
    )
    for response in public_responses:
        _assert_public_response(response)


def test_real_provider_lifecycle_traverses_authenticated_http_management(
    provider_upgrade_service: BlueFireService,
) -> None:
    service = provider_upgrade_service
    envelope = _fixture_envelope("1.0.0")
    row = _fixture_row("1.0.0")
    with running_server(service, max_request_body=1024 * 1024) as (server, _target):
        status, _, payload = request(
            server,
            "POST",
            "/api/v1/action-package-publishers",
            body=_trust_request(),
        )
        assert status == 201
        _assert_public_response(json_body(payload))

        status, _, payload = request(
            server,
            "POST",
            "/api/v1/action-packages",
            body={"envelope": envelope, "installed_by": "provider-http-operator"},
        )
        assert status == 201
        assert json_body(payload)["package"]["status"] == "installed"

        status, _, payload = request(
            server,
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/1.0.0/activate",
            body={
                "runner_profile_id": _execute_profile(service).id,
                "activated_by": "provider-http-operator",
                "reason": "Exercise the signed provider through authenticated HTTP management.",
            },
        )
        assert status == 200
        activated = json_body(payload)
        assert activated["operation"] == "activation"

        catalog = activated["catalog"]
        status, _, payload = request(
            server,
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/1.0.0/deactivate",
            body={
                "package_digest": row["package_digest"],
                "expected_catalog_generation": catalog["generation"],
                "expected_catalog_digest": catalog["catalog_digest"],
                "deactivated_by": "provider-http-operator",
                "reason": "Exercise exact HTTP provider deactivation authority.",
            },
        )
        assert status == 200
        deactivated = json_body(payload)
        assert deactivated["catalog"]["packages"] == []

        catalog = deactivated["catalog"]
        status, _, payload = request(
            server,
            "POST",
            f"/api/v1/action-packages/{PACKAGE_ID}/versions/1.0.0/remove",
            body={
                "package_digest": row["package_digest"],
                "expected_catalog_generation": catalog["generation"],
                "expected_catalog_digest": catalog["catalog_digest"],
                "removed_by": "provider-http-operator",
                "reason": "Exercise exact HTTP provider removal authority.",
            },
        )
        assert status == 200
        assert json_body(payload)["package"]["status"] == "removed"


def test_real_provider_lifecycle_traverses_cli_management(
    provider_upgrade_service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = provider_upgrade_service
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    trust = _trust_request()
    public_key_file = tmp_path / "provider-public-key.txt"
    provenance_file = tmp_path / "provider-provenance.json"
    public_key_file.write_text(str(trust["public_key"]), encoding="utf-8")
    provenance_file.write_text(json.dumps(trust["provenance"]), encoding="utf-8")
    envelope_file = FIXTURE_ROOT / str(_fixture_row("1.0.0")["file"])
    row = _fixture_row("1.0.0")

    trusted = _execute(
        parser.parse_args(
            [
                "packages",
                "trust-publisher",
                "--publisher-id",
                str(trust["publisher_id"]),
                "--key-id",
                str(trust["key_id"]),
                "--public-key-file",
                str(public_key_file),
                "--provenance-file",
                str(provenance_file),
                "--trusted-by",
                "provider-cli-operator",
            ]
        )
    )
    assert isinstance(trusted, Mapping)
    installed = _execute(
        parser.parse_args(
            [
                "packages",
                "install",
                str(envelope_file),
                "--installed-by",
                "provider-cli-operator",
            ]
        )
    )
    assert isinstance(installed, Mapping)
    assert installed["package"]["status"] == "installed"
    activated = _execute(
        parser.parse_args(
            [
                "packages",
                "activate",
                PACKAGE_ID,
                "1.0.0",
                "--profile",
                _execute_profile(service).id,
                "--activated-by",
                "provider-cli-operator",
                "--reason",
                "Exercise the signed provider through CLI management.",
            ]
        )
    )
    assert isinstance(activated, Mapping)
    assert activated["operation"] == "activation"

    catalog = activated["catalog"]
    deactivated = _execute(
        parser.parse_args(
            [
                "packages",
                "deactivate",
                PACKAGE_ID,
                "1.0.0",
                "--package-digest",
                str(row["package_digest"]),
                "--catalog-generation",
                str(catalog["generation"]),
                "--catalog-digest",
                str(catalog["catalog_digest"]),
                "--deactivated-by",
                "provider-cli-operator",
                "--reason",
                "Exercise exact CLI provider deactivation authority.",
            ]
        )
    )
    assert isinstance(deactivated, Mapping)
    assert deactivated["catalog"]["packages"] == []

    catalog = deactivated["catalog"]
    removed = _execute(
        parser.parse_args(
            [
                "packages",
                "remove",
                PACKAGE_ID,
                "1.0.0",
                "--package-digest",
                str(row["package_digest"]),
                "--catalog-generation",
                str(catalog["generation"]),
                "--catalog-digest",
                str(catalog["catalog_digest"]),
                "--removed-by",
                "provider-cli-operator",
                "--reason",
                "Exercise exact CLI provider removal authority.",
            ]
        )
    )
    assert isinstance(removed, Mapping)
    assert removed["package"]["status"] == "removed"
    for response in (trusted, installed, activated, deactivated, removed):
        _assert_public_response(response)


def test_provider_gate_main_sanitizes_service_api_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_sentinel = f"PRIVATE_SENTINEL:{ROOT}"

    def fail_journey(_repository: Path, _evidence_dir: Path) -> Any:
        raise APIError(409, "private_service_error", "unsafe", [private_sentinel])

    monkeypatch.setattr(provider_gate_helper, "run_provider_gate_journey", fail_journey)

    exit_code = provider_gate_helper.main(
        ["--repository", str(ROOT), "--evidence-dir", str(tmp_path)]
    )

    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert exit_code == 1
    assert output.err == ""
    assert summary == {
        "schema_version": provider_gate_helper.JOURNEY_SCHEMA,
        "status": "failed",
        "error_type": "APIError",
        "error_code": "provider_gate_internal_error",
        "message": "provider gate internal failure",
    }
    assert private_sentinel not in output.out


@pytest.mark.parametrize("report_name", ["structural", "journey"])
def test_provider_gate_rejects_artifact_hex_in_final_reports(
    report_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = b"\x00asm-private-provider-report-sentinel"
    packages = {"1.0.0": SimpleNamespace(provider_artifact_bytes=artifact)}
    safe_structural = {"passed": True}
    leaked_report: dict[str, Any] = {
        "passed": True,
        "diagnostic": artifact.hex(),
        "checks": {"limits_cleanup": {}},
    }
    monkeypatch.setattr(
        provider_gate_helper,
        "_fixture_set",
        lambda _repository: ({}, {}, packages),
    )
    monkeypatch.setattr(
        provider_gate_helper,
        "_structural_report",
        lambda *_args: leaked_report if report_name == "structural" else safe_structural,
    )
    monkeypatch.setattr(
        provider_gate_helper,
        "_journey_report",
        lambda *_args: leaked_report,
    )

    with pytest.raises(
        provider_gate_helper.ProviderGateError,
        match=rf"provider {report_name} report exposed private provider bytes",
    ):
        provider_gate_helper.run_provider_gate_journey(ROOT, tmp_path)

    assert not (tmp_path / f"provider-{report_name}-report.json").exists()


def _private_provider_store_paths(root: Path) -> tuple[Path, Path, Path]:
    database = root / "provider-product.sqlite3"
    return (
        database,
        database.with_name(database.name + "-wal"),
        database.with_name(database.name + "-shm"),
    )


def _write_private_provider_store_sentinels(root: Path) -> None:
    for path in _private_provider_store_paths(root):
        path.write_text("private provider state", encoding="utf-8")


def test_provider_gate_removes_private_store_after_service_constructor_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provider_gate_helper,
        "_runner_context",
        lambda *_args: (object(), {}),
    )

    def fail_constructor(**_kwargs: Any) -> Any:
        _write_private_provider_store_sentinels(tmp_path)
        raise APIError(500, "constructor_failed", "unsafe", ["PRIVATE_SENTINEL"])

    monkeypatch.setattr(provider_gate_helper, "BlueFireService", fail_constructor)

    with pytest.raises(APIError, match="PRIVATE_SENTINEL"):
        provider_gate_helper._journey_report(ROOT, tmp_path, _fixture_index(), {})

    assert not any(path.exists() for path in _private_provider_store_paths(tmp_path))


def test_provider_gate_removes_private_store_when_service_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provider_gate_helper,
        "_runner_context",
        lambda *_args: (object(), {}),
    )

    class CloseFailingService:
        def __init__(self, **_kwargs: Any) -> None:
            _write_private_provider_store_sentinels(tmp_path)

        def install_action_package(self, _request: Mapping[str, Any]) -> Any:
            raise RuntimeError("journey failure")

        def close(self) -> None:
            raise RuntimeError("service close failure")

    monkeypatch.setattr(provider_gate_helper, "BlueFireService", CloseFailingService)

    with pytest.raises(RuntimeError, match="service close failure"):
        provider_gate_helper._journey_report(ROOT, tmp_path, _fixture_index(), {})

    assert not any(path.exists() for path in _private_provider_store_paths(tmp_path))
