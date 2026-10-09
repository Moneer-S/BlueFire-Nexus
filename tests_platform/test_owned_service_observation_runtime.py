"""Authored metadata vectors only: no reviewed runtime, acquisition or effects."""

from __future__ import annotations

import json
import tempfile
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from bluefire.config import load_config
from bluefire.contracts import ContractError
from bluefire.native_tool_installations import NativeToolInstallation
from bluefire.owned_service_authority import (
    ADMISSION_SCHEMA,
    ADMISSION_SCHEMA_V2,
    GRANT_SCHEMA,
    GRANT_SCHEMA_V2,
    SCOPE_SCHEMA,
    SCOPE_SCHEMA_V2,
    OwnedServiceAdmission,
    OwnedServiceAuthorityError,
    OwnedServiceGrant,
    OwnedServiceScope,
    compile_owned_service_scope,
    mint_owned_service_grant,
    profile_policy_digest,
    validate_owned_service_grant_for_request,
)
from bluefire.owned_service_orchestration import service_grant_kwargs
from bluefire.owned_service_transport import make_authenticated_admission
from bluefire.runner_client import execution_task_identity
from bluefire.runner_contracts import build_runner_profile, seal_manifest, seal_profile
from bluefire.service_observation_runtime import (
    SCHEMA,
    SUPPORTED_CONTRACT_DIGESTS,
    canonical_observation_runtime,
    require_supported_observation_runtime,
)
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_owned_service_authority as legacy

NOW = datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc)
# This shared historical vector has a fixed method scope, independent of defaults.
V2_FIXTURE_ACTIONS = {
    "endpoint.discovery.processes.v1",
    "endpoint.discovery.system.v1",
    "sandbox.archive.tar.v1",
    "sandbox.cleanup.v1",
    "sandbox.collection.archive.v1",
    "sandbox.collection.records.v1",
    "sandbox.collection.stage.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.execution.native-canary.v1",
    "sandbox.export.local.v1",
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.network.loopback.v1",
    "sandbox.observability.variant.v1",
    "sandbox.peer.handoff.v1",
}


def _reference(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "installation_id": record["tool_id"],
        "path": record["installation_location"],
        "digest": NativeToolInstallation.from_mapping(record).digest,
        "content_sha256": record["content_sha256"],
    }


def _scope_input() -> tuple[dict[str, Any], dict[str, Any]]:
    profile = legacy._profile()
    value = legacy._scope(profile)
    references = {}
    for role, component, character in [
        ("broker", "broker", "1"),
        ("systemd_daemon", "systemd", "2"),
    ]:
        record = {
            **deepcopy(profile["native_tool_installations"][0]),
            "adapter_id": f"owned.service.observation.{component}.v1",
            "tool_id": f"owned.service.observation.{component}.binary.v1",
            "installation_location": f"/opt/authored-runtime/{component}",
            "content_sha256": "sha256:" + character * 64,
        }
        profile["native_tool_installations"].append(record)
        profile["enabled_actions"].append(record["adapter_id"])
        references[role] = _reference(record)
    value["schema_version"] = SCOPE_SCHEMA_V2
    value["observation_runtime"] = {
        "schema_version": SCHEMA,
        "contract_digest": "sha256:" + "3" * 64,
        "system_broker_uid": 102,
        "installations": references,
    }
    value["profile_policy_digest"] = profile_policy_digest(profile)
    return value, profile


def _authored() -> dict[str, Any]:
    value, configured = _scope_input()
    scope = compile_owned_service_scope(value, profile=configured)
    _, original, manifest, sealed, _ = legacy._grant_fixture("create_unit")
    sealed["native_tool_installations"] = deepcopy(configured["native_tool_installations"])
    task_id, _ = execution_task_identity(manifest, sealed)
    binding = legacy._binding(scope, "create_unit")
    document = original.to_dict()
    document.update(
        schema_version=GRANT_SCHEMA_V2,
        scope=scope.to_dict(),
        scope_digest=scope.digest,
        operation_binding=binding.to_dict(),
    )
    document["execution"].update(
        task_id=task_id,
        profile_digest=content_hash(sealed),
        operation_binding_digest=binding.digest,
    )
    grant = OwnedServiceGrant.from_mapping(document)
    admission = OwnedServiceAdmission.create(
        grant,
        issuer={
            "runner_id": "bluefire-rust-runner.v1",
            "client_id": "bluefire-client.v1",
            "enrollment_generation": "sha256:" + "7" * 64,
            "peer_fingerprint": "sha256:" + "8" * 64,
            "server_instance_id": "bluefire-server-instance.v1",
        },
    )
    return {
        "scope": scope,
        "configured": configured,
        "grant": grant,
        "admission": admission,
        "manifest": manifest,
        "sealed": sealed,
        "task_id": task_id,
    }


def _mint_arguments(data: dict[str, Any]) -> dict[str, Any]:
    document = data["grant"].to_dict()
    claim = document["claim"]
    approval = {
        key: claim[key]
        for key in (
            "state_digest",
            "plan_digest",
            "target_scope_digest",
            "profile_id",
            "maximum_tier",
        )
    }
    return {
        "scope": data["scope"],
        "claimed_approval": {
            **claim,
            "status": "claimed",
            "expires_at": claim["approval_expires_at"],
        },
        "approval_binding": {**approval, "owned_service_scope_digest": data["scope"].digest},
        "operation_binding": legacy._binding(data["scope"], "create_unit"),
        "run_id": document["run_id"],
        "manifest": data["manifest"],
        "sealed_profile": data["sealed"],
        "task_id": data["task_id"],
        "now": NOW,
    }


def build_native_v2_fixture() -> dict[str, Any]:
    """Generate an authored v2 vector through configured/sealed/minted types.

    Returns data; it never writes the shared fixture or executes a native tool.
    The temporary directory is only the ordinary profile builder's workspace.
    """
    root = Path(__file__).resolve().parents[1]
    original = json.loads(
        (root / "tests_platform/fixtures/owned_service_admission_v1.json").read_bytes()
    )
    runtime_scope, authored_profile = _scope_input()
    records = tuple(
        NativeToolInstallation.from_mapping(raw)
        for raw in authored_profile["native_tool_installations"]
    )
    configured = next(
        profile
        for profile in load_config(root / "config/bluefire.example.yaml").runner_profiles
        if profile.id == "sandbox-execute.v1"
    )
    configured = replace(
        configured,
        enabled_actions=tuple(
            sorted(
                V2_FIXTURE_ACTIONS
                | {
                    legacy.SERVICE_ACTION_ID,
                    *(record.to_dict()["adapter_id"] for record in records),
                }
            )
        ),
        capabilities=tuple(sorted(set(configured.capabilities) | {"native.execution"})),
        native_tool_installations=records,
    )
    with tempfile.TemporaryDirectory(prefix="owned-service-v2-fixture-") as directory:
        profile = build_runner_profile(
            configured,
            sandbox_root=Path(directory) / "workspace",
            platform="linux",
            filesystem_scope=("fixtures",),
        )
    profile["sandbox_root"] = legacy.WORKSPACE_ROOT
    profile = seal_profile(profile)
    value = deepcopy(original["admission"]["grant"]["scope"])
    value.update(
        schema_version=SCOPE_SCHEMA_V2,
        observation_runtime=runtime_scope["observation_runtime"],
        profile_policy_digest=profile_policy_digest(configured),
    )
    scope = compile_owned_service_scope(value, profile=configured)
    manifest = deepcopy(original["manifest"])
    manifest["policy_digest"] = profile["policy_digest"]
    manifest = seal_manifest(manifest)
    task_id, _ = execution_task_identity(manifest, profile)
    inputs = {
        "scope": scope,
        "grant": OwnedServiceGrant.from_mapping(original["admission"]["grant"]),
        "manifest": manifest,
        "sealed": profile,
        "task_id": task_id,
    }
    grant = mint_owned_service_grant(**_mint_arguments(inputs))
    validate_owned_service_grant_for_request(
        grant, manifest=manifest, profile=profile, task_id=task_id, now=NOW
    )
    admission = OwnedServiceAdmission.create(grant, issuer=original["admission"]["issuer"])
    return {
        "admission": admission.to_dict(),
        "manifest": manifest,
        "profile": profile,
        "now": original["now"],
    }


def test_existing_v1_fixture_bytes_and_digests_are_preserved() -> None:
    path = Path(__file__).parent / "fixtures/owned_service_admission_v1.json"
    raw = path.read_bytes()
    fixture = json.loads(raw)
    admission = OwnedServiceAdmission.from_mapping(fixture["admission"])
    assert admission.canonical_bytes() == canonical_json_bytes(fixture["admission"])
    grant = OwnedServiceGrant.from_mapping(fixture["admission"]["grant"])
    scope = OwnedServiceScope.from_mapping(grant.to_dict()["scope"])
    assert grant.digest == fixture["admission"]["grant_digest"]
    assert scope.digest == grant.to_dict()["scope_digest"]
    assert scope.canonical_bytes() == canonical_json_bytes(grant.to_dict()["scope"])
    validate_owned_service_grant_for_request(
        grant,
        manifest=fixture["manifest"],
        profile=fixture["profile"],
        task_id=grant.to_dict()["execution"]["task_id"],
        now=NOW,
    )
    assert path.read_bytes() == raw


def test_shared_v2_fixture_matches_actual_builders_and_validates_without_runtime_support() -> None:
    fixtures = Path(__file__).parent / "fixtures"
    legacy_path = fixtures / "owned_service_admission_v1.json"
    legacy_bytes = legacy_path.read_bytes()
    fixture = json.loads((fixtures / "owned_service_admission_v2.json").read_bytes())
    assert build_native_v2_fixture() == fixture
    admission = OwnedServiceAdmission.from_mapping(fixture["admission"])
    assert admission.canonical_bytes() == canonical_json_bytes(fixture["admission"])
    grant = OwnedServiceGrant.from_mapping(admission.to_dict()["grant"])
    scope = OwnedServiceScope.from_mapping(grant.to_dict()["scope"])
    assert admission.to_dict()["schema_version"] == ADMISSION_SCHEMA_V2
    assert grant.to_dict()["schema_version"] == GRANT_SCHEMA_V2
    assert scope.to_dict()["schema_version"] == SCOPE_SCHEMA_V2
    validate_owned_service_grant_for_request(
        grant,
        manifest=fixture["manifest"],
        profile=fixture["profile"],
        task_id=grant.to_dict()["execution"]["task_id"],
        now=datetime.fromisoformat(fixture["now"].replace("Z", "+00:00")),
    )
    assert SUPPORTED_CONTRACT_DIGESTS == frozenset()
    with pytest.raises(ContractError, match="unavailable"):
        require_supported_observation_runtime(scope.to_dict()["observation_runtime"])
    assert legacy_path.read_bytes() == legacy_bytes


def test_v2_metadata_roundtrip_mint_and_request_binding_do_not_claim_runtime_support() -> None:
    data = _authored()
    minted = mint_owned_service_grant(**_mint_arguments(data))
    assert minted.canonical_bytes() == data["grant"].canonical_bytes()
    assert data["scope"].to_dict()["schema_version"] == SCOPE_SCHEMA_V2
    assert minted.to_dict()["schema_version"] == GRANT_SCHEMA_V2
    assert data["admission"].to_dict()["schema_version"] == ADMISSION_SCHEMA_V2
    validate_owned_service_grant_for_request(
        minted, manifest=data["manifest"], profile=data["sealed"], task_id=data["task_id"], now=NOW
    )
    returned = data["scope"].to_dict()
    returned["observation_runtime"]["system_broker_uid"] = 999
    assert data["scope"].to_dict()["observation_runtime"]["system_broker_uid"] == 102
    assert SUPPORTED_CONTRACT_DIGESTS == frozenset()
    with pytest.raises(ContractError, match="unavailable"):
        require_supported_observation_runtime(data["scope"].to_dict()["observation_runtime"])


@pytest.mark.parametrize("uid", [0, 102, 1000, 2**32 - 2])
def test_system_broker_uid_is_explicit_bounded_metadata(uid: int) -> None:
    value, profile = _scope_input()
    value["observation_runtime"]["system_broker_uid"] = uid
    scope = compile_owned_service_scope(value, profile=profile)
    assert scope.to_dict()["observation_runtime"]["system_broker_uid"] == uid
    assert scope.to_dict()["manager"]["bus_identity"] == "unix:path=/run/user/1000/bus"


@pytest.mark.parametrize("uid", [-1, 2**32 - 1, True, False, 102.0, "102", None])
def test_invalid_broker_uid_refuses(uid: Any) -> None:
    value, _ = _scope_input()
    value["observation_runtime"]["system_broker_uid"] = uid
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize(
    "field", ["pid", "bus_identity", "topology", "deadline_ms", "acquired", "closure_files"]
)
def test_runtime_cannot_add_live_identity_transport_or_closure_authority(field: str) -> None:
    value, _ = _scope_input()
    value["observation_runtime"][field] = "authored"
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize(
    "field", ["schema_version", "contract_digest", "system_broker_uid", "installations"]
)
def test_every_runtime_field_is_required(field: str) -> None:
    value, _ = _scope_input()
    del value["observation_runtime"][field]
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize("replacement", ["unsupported", SCHEMA + ".extra", 1, None])
def test_runtime_schema_is_closed(replacement: Any) -> None:
    value, _ = _scope_input()
    value["observation_runtime"]["schema_version"] = replacement
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize(
    "role,source",
    [
        ("broker", "systemd_daemon"),
        ("systemd_daemon", "broker"),
        ("broker", "manager"),
        ("systemd_daemon", "payload"),
    ],
)
def test_runtime_roles_cannot_be_swapped_or_reuse_effect_roles(role: str, source: str) -> None:
    value, _ = _scope_input()
    references = value["observation_runtime"]["installations"]
    references[role] = deepcopy(
        (references if source in references else value["installations"])[source]
    )
    with pytest.raises(OwnedServiceAuthorityError, match="role"):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize("role", ["broker", "systemd_daemon", "extra"])
def test_runtime_role_inventory_is_exact(role: str) -> None:
    value, _ = _scope_input()
    references = value["observation_runtime"]["installations"]
    if role == "extra":
        references[role] = deepcopy(references["broker"])
    else:
        del references[role]
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("path", "relative"),
        ("path", "/opt/../broker"),
        ("path", "/opt//broker"),
        ("path", "/opt/broker\\other"),
        ("path", "/opt/secret\n"),
        ("digest", "sha256:" + "A" * 64),
        ("digest", "sha256:short"),
        ("content_sha256", None),
    ],
)
def test_runtime_references_preserve_strict_path_and_digest_shape(
    field: str, replacement: Any
) -> None:
    value, _ = _scope_input()
    value["observation_runtime"]["installations"]["broker"][field] = replacement
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize("sealed", [False, True], ids=["configured", "sealed"])
@pytest.mark.parametrize(
    "field,replacement",
    [
        ("installation_location", "/opt/changed"),
        ("content_sha256", "sha256:" + "9" * 64),
        ("tool_version", "2.0.0"),
        ("size_bytes", 8192),
    ],
)
def test_exact_reference_drift_refuses_in_both_profiles(
    sealed: bool, field: str, replacement: Any
) -> None:
    data = _authored()
    profile = deepcopy(data["sealed"] if sealed else data["configured"])
    profile["native_tool_installations"][2][field] = replacement
    if sealed:
        with pytest.raises(
            OwnedServiceAuthorityError, match="observation runtime installation differs"
        ):
            validate_owned_service_grant_for_request(
                data["grant"],
                manifest=data["manifest"],
                profile=profile,
                task_id=data["task_id"],
                now=NOW,
            )
    else:
        value = data["scope"].to_dict()
        value["profile_policy_digest"] = profile_policy_digest(profile)
        with pytest.raises(
            OwnedServiceAuthorityError, match="observation runtime installation differs"
        ):
            compile_owned_service_scope(value, profile=profile)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("adapter_id", "owned.service.manager.v1"),
        ("adapter_version", "2.0.0"),
        ("architecture", "aarch64"),
        ("platform", "windows"),
        ("tool_id", "owned.service.manager.binary.v1"),
    ],
)
def test_recomputed_metadata_digest_cannot_change_the_closed_runtime_binding(
    field: str, replacement: Any
) -> None:
    value, profile = _scope_input()
    record = profile["native_tool_installations"][2]
    record[field] = replacement
    with pytest.raises(ContractError):
        value["observation_runtime"]["installations"]["broker"] = _reference(record)
        value["profile_policy_digest"] = profile_policy_digest(profile)
        compile_owned_service_scope(value, profile=profile)


@pytest.mark.parametrize("case", ["missing", "duplicate", "too_many", "malformed"])
def test_runtime_profile_inventory_refuses_incomplete_or_ambiguous_records(case: str) -> None:
    value, profile = _scope_input()
    records = profile["native_tool_installations"]
    if case == "missing":
        records.pop()
    elif case == "duplicate":
        records.append(deepcopy(records[2]))
    elif case == "malformed":
        records.append({"secret": "unrecognized"})
    else:
        for index in range(13):
            records.append({**deepcopy(records[2]), "adapter_id": f"authored.extra{index}.v1"})
    value["profile_policy_digest"] = profile_policy_digest(profile)
    with pytest.raises(OwnedServiceAuthorityError):
        compile_owned_service_scope(value, profile=profile)


@pytest.mark.parametrize(
    "case",
    ["v1_grant_v2_scope", "v2_grant_v1_scope", "v1_admission_v2_grant", "v2_admission_v1_grant"],
)
def test_mixed_version_families_refuse_before_digest_rebinding(case: str) -> None:
    data = _authored()
    if case == "v1_grant_v2_scope":
        value = data["grant"].to_dict()
        value["schema_version"] = GRANT_SCHEMA
        parse = OwnedServiceGrant.from_mapping
    elif case == "v2_grant_v1_scope":
        value = legacy._grant_fixture("create_unit")[1].to_dict()
        value["schema_version"] = GRANT_SCHEMA_V2
        parse = OwnedServiceGrant.from_mapping
    else:
        value = data["admission"].to_dict()
        parse = OwnedServiceAdmission.from_mapping
        if case == "v1_admission_v2_grant":
            value["schema_version"] = ADMISSION_SCHEMA
        else:
            grant = legacy._grant_fixture("create_unit")[1]
            value.update(grant=grant.to_dict(), grant_digest=grant.digest)
    with pytest.raises(OwnedServiceAuthorityError, match="families differ"):
        parse(value)


@pytest.mark.parametrize("kind", ["scope", "grant", "admission"])
def test_unknown_outer_versions_refuse(kind: str) -> None:
    data = _authored()
    value = data[kind].to_dict()
    value["schema_version"] = "unrecognized.v3"
    with pytest.raises(OwnedServiceAuthorityError):
        type(data[kind]).from_mapping(value)


def test_v1_cannot_silently_acquire_runtime_fields() -> None:
    value, _ = _scope_input()
    value["schema_version"] = SCOPE_SCHEMA
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


def test_duplicate_json_and_oversized_runtime_scope_refuse() -> None:
    value, _ = _scope_input()
    encoded = canonical_json_bytes(value)
    assert encoded.count(b'"system_broker_uid":102') == 1
    duplicate = encoded.replace(
        b'"system_broker_uid":102', b'"system_broker_uid":102,"system_broker_uid":0'
    )
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_json(duplicate)
    value["observation_runtime"]["installations"]["broker"]["path"] = "/" + "x" * 20_000
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceScope.from_mapping(value)


@pytest.mark.parametrize("change", ["uid", "contract", "broker_path", "systemd_hash"])
def test_whole_runtime_mutation_cannot_reuse_the_existing_journal_binding(change: str) -> None:
    data = _authored()
    original = data["scope"]
    value = original.to_dict()
    runtime = value["observation_runtime"]
    if change == "uid":
        runtime["system_broker_uid"] = 103
    elif change == "contract":
        runtime["contract_digest"] = "sha256:" + "9" * 64
    elif change == "broker_path":
        runtime["installations"]["broker"]["path"] = "/opt/changed"
    else:
        runtime["installations"]["systemd_daemon"]["content_sha256"] = "sha256:" + "9" * 64
    changed = OwnedServiceScope.from_mapping(value)
    assert changed.digest != original.digest
    assert (
        changed.identity_mapping()["authorization_digest"]
        != original.identity_mapping()["authorization_digest"]
    )
    grant = data["grant"].to_dict()
    grant.update(scope=changed.to_dict(), scope_digest=changed.digest)
    with pytest.raises(OwnedServiceAuthorityError, match="claim does not match"):
        OwnedServiceGrant.from_mapping(grant)


def test_old_claim_and_changed_sealed_profile_cannot_mint_v2_grants() -> None:
    data = _authored()
    arguments = _mint_arguments(data)
    value = data["scope"].to_dict()
    value["observation_runtime"]["system_broker_uid"] = 103
    arguments["scope"] = OwnedServiceScope.from_mapping(value)
    arguments["operation_binding"] = legacy._binding(arguments["scope"], "create_unit")
    with pytest.raises(OwnedServiceAuthorityError, match="durable claim"):
        mint_owned_service_grant(**arguments)
    arguments = _mint_arguments(data)
    arguments["sealed_profile"] = deepcopy(data["sealed"])
    arguments["sealed_profile"]["native_tool_installations"].pop()
    with pytest.raises(
        OwnedServiceAuthorityError, match="observation runtime installation differs"
    ):
        mint_owned_service_grant(**arguments)


@pytest.mark.parametrize("digest", ["0", "a", "f"])
def test_no_well_formed_contract_digest_is_a_supported_production_runtime(digest: str) -> None:
    value, _ = _scope_input()
    runtime = value["observation_runtime"]
    runtime["contract_digest"] = "sha256:" + digest * 64
    assert canonical_observation_runtime(runtime) == runtime
    assert SUPPORTED_CONTRACT_DIGESTS == frozenset()
    with pytest.raises(ContractError, match="unavailable"):
        require_supported_observation_runtime(runtime)


class MetadataRunner:
    def __init__(self, grant_protocol: str, admission_protocol: str) -> None:
        self.owned_service_grant_protocol = grant_protocol
        self.owned_service_admission_protocol = admission_protocol
        self.calls: list[Any] = []

    def execute_task(
        self, *, owned_service_grant: Any = None, owned_service_admission: Any = None
    ) -> None:
        self.calls.append((owned_service_grant, owned_service_admission))
        raise AssertionError("metadata handoff must not dispatch")


def test_v1_advertisement_cannot_silently_handoff_a_v2_grant_or_admission() -> None:
    data = _authored()
    runner = MetadataRunner(GRANT_SCHEMA, ADMISSION_SCHEMA)
    with pytest.raises(ContractError, match="reviewed version"):
        service_grant_kwargs(runner, runner.execute_task, data["grant"])
    with pytest.raises(OwnedServiceAuthorityError, match="reviewed version"):
        make_authenticated_admission(
            runner,
            data["grant"],
            execute_task=runner.execute_task,
            issuer=data["admission"].to_dict()["issuer"],
        )
    assert runner.calls == []


@pytest.mark.parametrize("version", [1, 2])
def test_explicit_matching_advertisement_only_returns_metadata(version: int) -> None:
    data = _authored()
    grant = data["grant"] if version == 2 else legacy._grant_fixture("create_unit")[1]
    runner = MetadataRunner(
        GRANT_SCHEMA_V2 if version == 2 else GRANT_SCHEMA,
        ADMISSION_SCHEMA_V2 if version == 2 else ADMISSION_SCHEMA,
    )
    assert service_grant_kwargs(runner, runner.execute_task, grant) == {
        "owned_service_grant": grant.to_dict()
    }
    admission = make_authenticated_admission(
        runner,
        grant,
        execute_task=runner.execute_task,
        issuer=data["admission"].to_dict()["issuer"],
    )
    assert admission.to_dict()["schema_version"] == runner.owned_service_admission_protocol
    assert runner.calls == []
    assert SUPPORTED_CONTRACT_DIGESTS == frozenset()
