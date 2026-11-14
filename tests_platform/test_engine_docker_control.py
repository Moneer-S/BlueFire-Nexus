from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, replace
from typing import Any
from urllib.parse import quote, urlencode

import pytest

from bluefire.engine_container_custody import (
    V2_RUNTIME_PLATFORM,
    ContainerCustodyPlan,
    ContainerCustodyPlanV2,
    container_image_identity_digest,
)
from bluefire.engine_docker_control import (
    ControllerVerifiedImageAdmission,
    ControllerVerifiedImageRelation,
    DockerApiOperation,
    DockerApiPolicy,
    DockerApiPolicyV2,
    DockerApiRequest,
    DockerOwnership,
    DockerResponseContract,
    EngineDockerPolicyError,
    authorize_docker_api_request,
    validate_docker_container_namespace_proof,
)
from bluefire.engine_network_policy import EngineNetworkPlan, EngineNetworkPlanV2
from bluefire.strix_adapter import StrixBuildIdentity
from bluefire.strix_controlled_execution_identity import StrixControlledExecutionIdentityV2
from bluefire.strix_image_contract import (
    StrixImageAdmissionDecisionV2,
    StrixImageContractV2,
    proposed_image_runtime_profile,
)
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import content_hash
from tests_platform.test_strix_controlled_execution_identity import (
    _bind_contract,
    _identity,
    _public_image_contract,
)

ATTEMPT_ID = "engine-attempt-0123456789abcdef0123456789abcdef"
CONTAINER_ID = "1" * 64
OTHER_CONTAINER_ID = "2" * 64
EXEC_ID = "3" * 64
NETWORK_ID = "4" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
IMAGE_REFERENCE = "ghcr.io/usestrix/sandbox@" + IMAGE_DIGEST
DERIVED_IMAGE_REFERENCE = "ghcr.io/bluefire/derived-sandbox@sha256:" + "9" * 64
CHILD_MANIFEST = "sha256:" + "d" * 64
IMAGE_CONFIG = "sha256:" + "e" * 64
RELATION_RECEIPT = "sha256:" + "f" * 64
TMPFS_OPTIONS = "nodev,nosuid,rw,size=512m"
DAEMON_DIGEST = "sha256:" + "1" * 64
NOW = "2026-11-04T12:00:00Z"


def build() -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256="sha256:" + "a" * 64,
        package_sha256="sha256:" + "b" * 64,
        executable_sha256="sha256:" + "d" * 64,
        image_reference=IMAGE_REFERENCE,
        image_inventory_sha256="sha256:" + "e" * 64,
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )


def network() -> EngineNetworkPlan:
    return EngineNetworkPlan.create(
        attempt_id=ATTEMPT_ID,
        network_identity_ref="sha256:" + "f" * 64,
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=NOW,
    )


def custody(*, labels: dict[str, str] | None = None) -> ContainerCustodyPlan:
    plan = network()
    return ContainerCustodyPlan.from_mapping(
        {
            "schema_version": "bluefire.engine-container-custody.v1",
            "attempt_id": ATTEMPT_ID,
            "daemon_instance_digest": DAEMON_DIGEST,
            "disposable_boundary_ref": "sha256:" + "2" * 64,
            "baseline_inventory_digest": "sha256:" + "3" * 64,
            "required_labels": labels
            or {
                "bluefire.engine.attempt": ATTEMPT_ID,
                "strix-run-id": ATTEMPT_ID,
                "strix-run-type": "bluefire",
            },
            "sandbox_image_digest": IMAGE_DIGEST,
            "network_id": NETWORK_ID,
            "network_policy_digest": plan.policy_digest,
            "expected_mounts": [
                {
                    "mount_type": "tmpfs",
                    "source": "",
                    "destination": "/workspace",
                    "read_only": False,
                    "options_digest": content_hash({"options": TMPFS_OPTIONS}),
                }
            ],
            "expected_capabilities": ["NET_ADMIN", "NET_RAW"],
            "expected_user": "1000:1000",
            "memory_bytes": 2 * 1024**3,
            "nano_cpus": 2_000_000_000,
            "pids_limit": 512,
            "expected_container_count": 1,
        }
    )


def policy() -> DockerApiPolicy:
    return DockerApiPolicy.create(
        build=build(),
        network=network(),
        custody=custody(),
        api_version="v1.47",
        tmpfs_options={"/workspace": TMPFS_OPTIONS},
    )


class FakeControllerRelationVerifier:
    """Test-only injected controller capability; it does not authenticate receipts."""

    def __init__(self, *, outcome: str = "exact") -> None:
        self.outcome = outcome

    def verify_image_relation(
        self,
        *,
        image_reference: str,
        runtime_platform: str,
        platform_child_manifest_digest: str,
        image_config_digest: str,
        image_relation_receipt_ref: str,
    ) -> ControllerVerifiedImageRelation:
        if self.outcome == "false":
            return False  # type: ignore[return-value]
        if self.outcome == "raise":
            raise RuntimeError("receipt unavailable")
        return ControllerVerifiedImageRelation(
            image_reference=image_reference,
            runtime_platform=(
                "linux/arm64" if self.outcome == "wrong_platform" else runtime_platform
            ),
            platform_child_manifest_digest=platform_child_manifest_digest,
            image_config_digest=image_config_digest,
            image_relation_receipt_ref=(
                "sha256:" + "0" * 64 if self.outcome == "mismatch" else image_relation_receipt_ref
            ),
        )


class FakeControllerAdmissionVerifier:
    """Test-only injected controller capability; it does not authenticate receipts."""

    def __init__(self, *, outcome: str = "exact") -> None:
        self.outcome = outcome

    def verify_image_admission(
        self,
        *,
        image_contract_digest: str,
        image_admission_decision_ref: str,
        execution_identity_digest: str,
        protected_execution_identity_digest: str,
        runtime_qualification_ref: str,
    ) -> ControllerVerifiedImageAdmission:
        if self.outcome == "false":
            return False  # type: ignore[return-value]
        if self.outcome == "raise":
            raise RuntimeError("controller admission unavailable")
        return ControllerVerifiedImageAdmission(
            image_contract_digest=image_contract_digest,
            image_admission_decision_ref=(
                "sha256:" + "0" * 64 if self.outcome == "mismatch" else image_admission_decision_ref
            ),
            execution_identity_digest=execution_identity_digest,
            protected_execution_identity_digest=protected_execution_identity_digest,
            runtime_qualification_ref=(
                "sha256:" + "0" * 64
                if self.outcome == "wrong_runtime_qualification"
                else runtime_qualification_ref
            ),
            runtime_qualification_admitted=True,
            image_admitted_for_runtime=True,
            missing_checks=(),
        )


def v2_policy_inputs(
    *,
    child: str | None = None,
    config: str | None = None,
    receipt: str | None = None,
) -> dict[str, Any]:
    """Synthetic V2 declarations; the fake verifiers are tests, not real proofs."""

    identity_row = _identity()
    if child is not None:
        identity_row["platform_child_manifest_digest"] = child
    if config is not None:
        identity_row["image_config_digest"] = config
    if receipt is not None:
        identity_row["image_relation_receipt_ref"] = receipt
    v2_network = EngineNetworkPlanV2.create(
        attempt_id=identity_row["attempt_id"],
        network_id="a" * 64,
        network_identity_ref="sha256:" + "f" * 64,
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=NOW,
    )
    preliminary_contract = _public_image_contract(identity_row)
    contract_row = preliminary_contract.to_dict()
    contract_row["runtime_profile"] = proposed_image_runtime_profile(
        network_id=v2_network.network_id,
        network_name=v2_network.network_name,
        network_policy_digest=v2_network.policy_digest,
    )
    contract = StrixImageContractV2.from_mapping(contract_row)
    _bind_contract(identity_row, contract)
    decision = StrixImageAdmissionDecisionV2(
        contract_digest=contract.contract_digest,
        local_build_qualified=True,
        hosted_qualification_complete=True,
        image_admitted_for_runtime=True,
        missing_checks=(),
    )
    identity_row["derived_image_decision_ref"] = content_hash(
        {
            "schema_version": "bluefire.strix-image-admission-decision-ref.v2",
            "decision": asdict(decision),
        }
    )
    identity = StrixControlledExecutionIdentityV2.from_mapping(identity_row)
    image_identity = {
        "image_reference": identity_row["derived_image_reference"],
        "runtime_platform": V2_RUNTIME_PLATFORM,
        "platform_child_manifest_digest": identity_row["platform_child_manifest_digest"],
        "image_config_digest": identity_row["image_config_digest"],
        "image_relation_receipt_ref": identity_row["image_relation_receipt_ref"],
    }
    profile = contract.to_dict()["runtime_profile"]
    labels = {
        "bluefire.engine.attempt": identity_row["attempt_id"],
        "bluefire.engine.image-identity": container_image_identity_digest(**image_identity),
        "strix-run-id": identity_row["attempt_id"],
        "strix-run-type": "bluefire",
    }
    custody_row = {
        "schema_version": "bluefire.engine-container-custody.v2",
        "attempt_id": identity_row["attempt_id"],
        "daemon_instance_digest": DAEMON_DIGEST,
        "disposable_boundary_ref": "sha256:" + "2" * 64,
        "baseline_inventory_digest": "sha256:" + "3" * 64,
        "required_labels": dict(sorted(labels.items())),
        **image_identity,
        "network_id": v2_network.network_id,
        "network_policy_digest": v2_network.policy_digest,
        "expected_mounts": [
            {
                "mount_type": "tmpfs",
                "source": "",
                "destination": destination,
                "read_only": False,
                "options_digest": content_hash({"options": options}),
            }
            for destination, options in sorted(profile["tmpfs"].items())
        ],
        "expected_capabilities": [],
        "expected_user": profile["user"],
        "memory_bytes": profile["memory_bytes"],
        "nano_cpus": profile["nano_cpus"],
        "pids_limit": profile["pids_limit"],
        "expected_container_count": 1,
    }
    startup_build = StrixBuildIdentity(
        **{
            key: value
            for key, value in identity_row["startup_build_identity"].items()
            if key != "engine"
        }
    )
    return {
        "build": startup_build,
        "derived_image_reference": identity_row["derived_image_reference"],
        "network": v2_network,
        "custody": ContainerCustodyPlanV2.from_mapping(custody_row),
        "image_contract": contract,
        "execution_identity": identity,
        "protected_execution_identity_digest": identity.identity_digest,
        "image_admission_decision": decision,
        "controller_relation_verifier": FakeControllerRelationVerifier(),
        "controller_admission_verifier": FakeControllerAdmissionVerifier(),
        "api_version": "v1.47",
        "tmpfs_options": profile["tmpfs"],
    }


def policy_v2(
    *,
    child: str | None = None,
    config: str | None = None,
    receipt: str | None = None,
) -> DockerApiPolicyV2:
    return DockerApiPolicyV2.create(**v2_policy_inputs(child=child, config=config, receipt=receipt))


def ownership(*, container: bool = True, exec_id: bool = True) -> DockerOwnership:
    containers = (CONTAINER_ID,) if container else ()
    execs = ((EXEC_ID, CONTAINER_ID),) if container and exec_id else ()
    return DockerOwnership.create(
        daemon_instance_digest=DAEMON_DIGEST,
        container_ids=containers,
        exec_bindings=execs,
    )


def request(
    method: str,
    target: str,
    body: dict[str, object] | bytes | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> DockerApiRequest:
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":")).encode()
    else:
        raw = body or b""
    actual_headers = dict(headers or {})
    if raw:
        actual_headers.setdefault("content-type", "application/json")
        actual_headers.setdefault("content-length", str(len(raw)))
    return DockerApiRequest.create(method=method, target=target, headers=actual_headers, body=raw)


def create_body() -> dict[str, object]:
    plan = policy()
    return {
        "AttachStderr": False,
        "AttachStdin": False,
        "AttachStdout": False,
        "Cmd": ["tail", "-f", "/dev/null"],
        "Env": [],
        "HostConfig": {
            "AutoRemove": False,
            "Binds": [],
            "CapAdd": list(plan.expected_capabilities),
            "CapDrop": ["ALL"],
            "CgroupParent": plan.cgroup_parent,
            "DeviceRequests": [],
            "Devices": [],
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": [],
            "IpcMode": "private",
            "LogConfig": {
                "Config": {"max-file": "1", "max-size": "10m"},
                "Type": "json-file",
            },
            "Memory": plan.memory_bytes,
            "Mounts": [],
            "NanoCpus": plan.nano_cpus,
            "NetworkMode": plan.network_name,
            "OomKillDisable": False,
            "PidMode": "",
            "PidsLimit": plan.pids_limit,
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/workspace": TMPFS_OPTIONS},
            "UTSMode": "",
        },
        "Image": plan.image_reference,
        "Labels": dict(plan.required_labels),
        "NetworkDisabled": False,
        "NetworkingConfig": {
            "EndpointsConfig": {plan.network_name: {"Aliases": [], "NetworkID": plan.network_id}}
        },
        "OpenStdin": False,
        "StdinOnce": False,
        "Tty": False,
        "User": plan.expected_user,
    }


def create_body_v2(item: DockerApiPolicyV2 | None = None) -> dict[str, object]:
    plan = item or policy_v2()
    profile = plan.image_runtime_profile
    body = create_body()
    host = body["HostConfig"]
    assert isinstance(host, dict)
    body.update(
        {
            "Cmd": profile["command"],
            "Entrypoint": profile["entrypoint"],
            "Env": [
                f"{key}={profile['environment'][key]}" for key in sorted(profile["environment"])
            ],
            "Image": plan.image_reference,
            "Labels": dict(plan.required_labels),
            "NetworkingConfig": {
                "EndpointsConfig": {
                    plan.network_name: {"Aliases": [], "NetworkID": plan.network_id}
                }
            },
            "User": profile["user"],
            "WorkingDir": profile["working_directory"],
        }
    )
    host.update(
        {
            "CapAdd": profile["cap_add"],
            "CapDrop": profile["cap_drop"],
            "CgroupParent": plan.cgroup_parent,
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "NanoCpus": profile["nano_cpus"],
            "NetworkMode": plan.network_name,
            "PidsLimit": profile["pids_limit"],
            "Tmpfs": profile["tmpfs"],
        }
    )
    return body


def exec_body(*, command: list[str] | None = None) -> dict[str, object]:
    return {
        "AttachStderr": True,
        "AttachStdin": False,
        "AttachStdout": True,
        "Cmd": command or ["sh", "-lc", "id"],
        "DetachKeys": "",
        "Env": [],
        "Privileged": False,
        "Tty": False,
        "User": policy().expected_user,
        "WorkingDir": "/workspace",
    }


def authorize(
    method: str,
    target: str,
    body: dict[str, object] | bytes | None = None,
    *,
    owned: DockerOwnership | None = None,
) -> object:
    return authorize_docker_api_request(
        policy(), request(method, target, body), owned or ownership()
    )


def test_policy_binds_existing_plans_labels_image_network_and_tmpfs() -> None:
    item = policy()

    assert item.attempt_id == ATTEMPT_ID
    assert item.image_reference == IMAGE_REFERENCE
    assert item.network_policy_digest == network().policy_digest
    assert item.container_name.endswith(ATTEMPT_ID[-12:])
    assert item.policy_digest == content_hash(item.to_dict())
    assert (
        item.expected_ipc_mode,
        item.expected_pid_mode,
        item.expected_uts_mode,
    ) == ("private", "", "")
    assert item.to_dict()["expected_pid_mode"] == ""
    assert item.to_dict()["expected_uts_mode"] == ""
    assert dict(item.required_labels) == {
        "bluefire.engine.attempt": ATTEMPT_ID,
        "strix-run-id": ATTEMPT_ID,
        "strix-run-type": "bluefire",
    }


def test_v2_policy_binds_index_child_config_receipt_and_create_identity() -> None:
    item = policy_v2()
    row = item.to_dict()
    inputs = v2_policy_inputs()
    identity = inputs["execution_identity"]
    contract = inputs["image_contract"]
    decision = inputs["image_admission_decision"]
    assert row["schema_version"] == "bluefire.engine-docker-api-policy.v2"
    assert row["image_reference"] == identity.to_dict()["derived_image_reference"]
    assert row["runtime_platform"] == V2_RUNTIME_PLATFORM
    assert (
        row["platform_child_manifest_digest"]
        == identity.to_dict()["platform_child_manifest_digest"]
    )
    assert row["image_config_digest"] == identity.to_dict()["image_config_digest"]
    assert row["image_relation_receipt_ref"] == identity.to_dict()["image_relation_receipt_ref"]
    assert row["upstream_image_reference"] == inputs["build"].image_reference
    assert row["upstream_build_ref"] == identity.to_dict()["startup_build_ref"]
    assert row["image_contract_digest"] == contract.contract_digest
    assert row["execution_identity_digest"] == identity.identity_digest
    assert row["protected_execution_identity_digest"] == identity.identity_digest
    assert row["custody_plan_digest"] == inputs["custody"].plan_digest
    assert row["image_runtime_profile_digest"] == contract.runtime_profile_digest
    assert row["runtime_qualification_ref"] == identity.to_dict()["runtime_qualification_ref"]
    assert row["image_admission_decision_ref"] == identity.to_dict()["derived_image_decision_ref"]
    assert "image_digest" not in row
    assert row["required_labels"]["bluefire.engine.image-identity"] == item.image_identity_digest
    assert item.policy_digest == content_hash(row)
    different_child = policy_v2(child="sha256:" + "1" * 64)
    assert different_child.image_reference == item.image_reference
    assert different_child.image_config_digest == item.image_config_digest
    assert different_child.platform_child_manifest_digest != item.platform_child_manifest_digest
    assert different_child.policy_digest != item.policy_digest
    assert policy_v2(config="sha256:" + "2" * 64).policy_digest != item.policy_digest
    assert policy_v2(receipt="sha256:" + "3" * 64).policy_digest != item.policy_digest
    assert item.verified_relation.image_relation_receipt_ref == row["image_relation_receipt_ref"]
    assert (
        item.verified_admission.image_admission_decision_ref == row["image_admission_decision_ref"]
    )
    assert decision.image_admitted_for_runtime is True
    assert decision.production_runtime_admitted is False
    assert decision.live_execution_proven is False
    assert len(row["tmpfs"]) == 4
    assert row["pids_limit"] == 256
    assert row["expected_capabilities"] == []

    create = create_body_v2(item)
    authorized = authorize_docker_api_request(
        item,
        request("POST", f"/v1.47/containers/create?name={item.container_name}", create),
        ownership(container=False, exec_id=False),
    )
    assert authorized.policy_digest == item.policy_digest
    assert authorized.body_digest == content_hash(create)
    create["Labels"] = dict(policy().required_labels)
    with pytest.raises(EngineDockerPolicyError, match="Labels"):
        authorize_docker_api_request(
            item,
            request("POST", f"/v1.47/containers/create?name={item.container_name}", create),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize("outcome", ["false", "mismatch", "wrong_platform", "raise"])
def test_v2_policy_requires_exact_controller_relation(outcome: str) -> None:
    inputs = v2_policy_inputs()
    inputs["controller_relation_verifier"] = FakeControllerRelationVerifier(outcome=outcome)
    with pytest.raises(EngineDockerPolicyError, match="verification"):
        DockerApiPolicyV2.create(**inputs)


@pytest.mark.parametrize("outcome", ["false", "mismatch", "wrong_runtime_qualification", "raise"])
def test_v2_policy_requires_exact_controller_admission(outcome: str) -> None:
    inputs = v2_policy_inputs()
    inputs["controller_admission_verifier"] = FakeControllerAdmissionVerifier(outcome=outcome)
    with pytest.raises(EngineDockerPolicyError, match="verification"):
        DockerApiPolicyV2.create(**inputs)


@pytest.mark.parametrize("field", ["controller_relation_verifier", "controller_admission_verifier"])
def test_v2_policy_has_no_default_controller_verifier(field: str) -> None:
    inputs = v2_policy_inputs()
    inputs[field] = None
    with pytest.raises(EngineDockerPolicyError, match="unavailable"):
        DockerApiPolicyV2.create(**inputs)


def test_v2_direct_constructor_requires_matching_network_and_custody_plans() -> None:
    inputs = v2_policy_inputs()
    policy = DockerApiPolicyV2.create(**inputs)
    init_values = {
        "image_contract": inputs["image_contract"],
        "execution_identity": inputs["execution_identity"],
        "protected_execution_identity_digest": inputs["protected_execution_identity_digest"],
        "image_admission_decision": inputs["image_admission_decision"],
        "controller_relation_verifier": inputs["controller_relation_verifier"],
        "controller_admission_verifier": inputs["controller_admission_verifier"],
        "network": inputs["network"],
        "custody": inputs["custody"],
    }
    wrong_network = EngineNetworkPlanV2.create(
        attempt_id=policy.attempt_id,
        network_id="b" * 64,
        network_identity_ref="sha256:" + "f" * 64,
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=NOW,
    )
    with pytest.raises(EngineDockerPolicyError, match="network plan differs"):
        replace(policy, **{**init_values, "network": wrong_network})

    custody_row = inputs["custody"].to_dict()
    custody_row["daemon_instance_digest"] = "sha256:" + "9" * 64
    wrong_custody = ContainerCustodyPlanV2.from_mapping(custody_row)
    with pytest.raises(EngineDockerPolicyError, match="custody plan differs"):
        replace(policy, **{**init_values, "custody": wrong_custody})


def test_v2_policy_refuses_old_one_tmpfs_net_admin_pids_512_fixture() -> None:
    inputs = v2_policy_inputs()
    legacy = inputs["custody"].to_dict()
    legacy["expected_mounts"] = [
        {
            "mount_type": "tmpfs",
            "source": "",
            "destination": "/workspace",
            "read_only": False,
            "options_digest": content_hash({"options": TMPFS_OPTIONS}),
        }
    ]
    legacy["expected_capabilities"] = ["NET_ADMIN"]
    legacy["pids_limit"] = 512
    inputs["custody"] = ContainerCustodyPlanV2.from_mapping(legacy)
    inputs["tmpfs_options"] = {"/workspace": TMPFS_OPTIONS}
    with pytest.raises(EngineDockerPolicyError, match="qualified profile"):
        DockerApiPolicyV2.create(**inputs)


def test_v2_policy_rejects_upstream_build_and_contract_substitution() -> None:
    inputs = v2_policy_inputs()
    inputs["build"] = replace(
        inputs["build"],
        image_reference="registry.example/other-upstream@sha256:" + "9" * 64,
    )
    with pytest.raises(EngineDockerPolicyError, match="upstream build"):
        DockerApiPolicyV2.create(**inputs)

    inputs = v2_policy_inputs()
    other_contract_row = inputs["image_contract"].to_dict()
    other_contract_row["dockerfile_digest"] = "sha256:" + "9" * 64
    inputs["image_contract"] = StrixImageContractV2.from_mapping(other_contract_row)
    with pytest.raises(EngineDockerPolicyError, match="contract|identity"):
        DockerApiPolicyV2.create(**inputs)


def test_v2_policy_rejects_identity_and_protected_digest_mismatch() -> None:
    inputs = v2_policy_inputs()
    inputs["execution_identity"] = v2_policy_inputs(child="sha256:" + "9" * 64)[
        "execution_identity"
    ]
    with pytest.raises(EngineDockerPolicyError, match="contract|identity"):
        DockerApiPolicyV2.create(**inputs)

    inputs = v2_policy_inputs()
    inputs["protected_execution_identity_digest"] = "sha256:" + "9" * 64
    with pytest.raises(EngineDockerPolicyError, match="contract|identity"):
        DockerApiPolicyV2.create(**inputs)


@pytest.mark.parametrize(
    "changed",
    [
        {"image_admitted_for_runtime": False},
        {"missing_checks": ("hosted",)},
        {"production_runtime_admitted": True},
        {"live_execution_proven": True},
    ],
)
def test_v2_policy_rejects_unqualified_or_forged_positive_decision(
    changed: dict[str, object],
) -> None:
    inputs = v2_policy_inputs()
    inputs["image_admission_decision"] = replace(inputs["image_admission_decision"], **changed)
    with pytest.raises(EngineDockerPolicyError, match="decision|qualified"):
        DockerApiPolicyV2.create(**inputs)


@pytest.mark.parametrize(
    "reference",
    [
        "strix-controlled@sha256:" + "e" * 64,
        "registry.example:5000/strix-controlled@sha256:" + "e" * 64,
        "registry.example/strix-controlled:latest@sha256:" + "e" * 64,
        "registry.example/strix-controlled:latest",
        "https://registry.example/strix-controlled@sha256:" + "e" * 64,
    ],
)
def test_v2_custody_and_policy_refuse_noncanonical_image_references(reference: str) -> None:
    inputs = v2_policy_inputs()
    custody_row = inputs["custody"].to_dict()
    custody_row["image_reference"] = reference
    with pytest.raises(ValueError, match="reference"):
        ContainerCustodyPlanV2.from_mapping(custody_row)
    inputs["derived_image_reference"] = reference
    with pytest.raises(EngineDockerPolicyError, match="reference|contract"):
        DockerApiPolicyV2.create(**inputs)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("Env", ["HOME=/root"]),
        ("Cmd", ["sh", "-lc", "id"]),
        ("Entrypoint", ["/bin/sh"]),
        ("WorkingDir", "/tmp"),
        ("Image", "registry.example/other@sha256:" + "9" * 64),
    ],
)
def test_v2_create_refuses_runtime_command_and_environment_drift(
    field: str, replacement: object
) -> None:
    item = policy_v2()
    create = create_body_v2(item)
    create[field] = replacement
    with pytest.raises(EngineDockerPolicyError, match="runtime profile"):
        authorize_docker_api_request(
            item,
            request("POST", f"/v1.47/containers/create?name={item.container_name}", create),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("Memory", 1024**3),
        ("MemorySwap", 4 * 1024**3),
        ("NanoCpus", 1_000_000_000),
        ("PidsLimit", 512),
        ("CapAdd", ["NET_ADMIN"]),
        ("Tmpfs", {"/workspace": TMPFS_OPTIONS}),
        ("SecurityOpt", []),
        ("RestartPolicy", {"MaximumRetryCount": 0, "Name": "always"}),
        ("RestartPolicy", {"MaximumRetryCount": False, "Name": "no"}),
    ],
)
def test_v2_create_refuses_host_profile_drift(field: str, replacement: object) -> None:
    item = policy_v2()
    create = create_body_v2(item)
    host = create["HostConfig"]
    assert isinstance(host, dict)
    host[field] = replacement
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            item,
            request("POST", f"/v1.47/containers/create?name={item.container_name}", create),
            ownership(container=False, exec_id=False),
        )


def test_v2_policy_refuses_docker_pull_and_runtime_exec() -> None:
    item = policy_v2()
    with pytest.raises(EngineDockerPolicyError, match="not permitted"):
        authorize_docker_api_request(
            item, request("POST", "/v1.47/images/create?fromImage=alpine:latest"), ownership()
        )
    with pytest.raises(EngineDockerPolicyError, match="not admitted"):
        authorize_docker_api_request(
            item,
            request("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body()),
            ownership(),
        )


@pytest.mark.parametrize("missing", ["bluefire.engine.attempt", "strix-run-id", "strix-run-type"])
def test_policy_requires_both_controller_and_upstream_labels(missing: str) -> None:
    labels = {
        "bluefire.engine.attempt": ATTEMPT_ID,
        "strix-run-id": ATTEMPT_ID,
        "strix-run-type": "bluefire",
    }
    labels.pop(missing)
    # The custody contract rejects its own BlueFire label first; this policy
    # additionally requires the two upstream labels.
    with pytest.raises(ValueError, match="labels|bind"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(labels=labels),
            api_version="v1.47",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )


def test_policy_rejects_unpinned_api_and_tmpfs_bytes() -> None:
    with pytest.raises(EngineDockerPolicyError, match="API version"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(),
            api_version="latest",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )
    with pytest.raises(EngineDockerPolicyError, match="digest"):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=custody(),
            api_version="v1.47",
            tmpfs_options={"/workspace": "nosuid,rw"},
        )


@pytest.mark.parametrize(
    "changed,match",
    [
        ({"expected_user": "0:0"}, "non-root"),
        ({"expected_capabilities": ("NET_ADMIN", "SYS_ADMIN")}, "capability"),
        ({"expected_container_count": 2}, "exactly one"),
        ({"memory_bytes": 128 * 1024**2}, "tmpfs capacity"),
    ],
)
def test_policy_rejects_root_broad_capabilities_multiple_containers_and_large_tmpfs(
    changed: dict[str, object], match: str
) -> None:
    with pytest.raises(EngineDockerPolicyError, match=match):
        DockerApiPolicy.create(
            build=build(),
            network=network(),
            custody=replace(custody(), **changed),
            api_version="v1.47",
            tmpfs_options={"/workspace": TMPFS_OPTIONS},
        )


@pytest.mark.parametrize(
    "changed",
    [
        {"schema_version": "bluefire.engine-docker-api-policy.v2"},
        {"api_version": "latest"},
        {"expected_user": "root"},
        {"expected_capabilities": ("SYS_ADMIN",)},
        {"expected_ipc_mode": ""},
        {"expected_pid_mode": "private"},
        {"expected_uts_mode": "private"},
        {"tmpfs": ()},
        {"memory_bytes": 2.0 * 1024**3},
        {"expected_container_count": 2},
        {"cgroup_parent": "/"},
        {"exec_deadline_seconds": 0},
    ],
)
def test_direct_policy_construction_revalidates_every_internal_invariant(
    changed: dict[str, object],
) -> None:
    with pytest.raises(EngineDockerPolicyError):
        replace(policy(), **changed)


def test_direct_nested_tmpfs_construction_is_revalidated() -> None:
    item = policy().tmpfs[0]
    with pytest.raises(EngineDockerPolicyError):
        replace(item, size_bytes=item.size_bytes + 1)


@pytest.mark.parametrize(
    "method,target",
    [
        ("GET", "http://docker/version"),
        ("GET", "//docker/version"),
        ("GET", "/v1.47//info"),
        ("GET", "/v1.47/../info"),
        ("GET", "/v1.47/%2e%2e/info"),
        ("GET", "/version#fragment"),
        ("CONNECT", "/version"),
    ],
)
def test_request_parser_rejects_ambiguous_targets_and_methods(method: str, target: str) -> None:
    with pytest.raises(EngineDockerPolicyError):
        request(method, target)


def test_request_parser_rejects_authority_headers_and_length_smuggling() -> None:
    with pytest.raises(EngineDockerPolicyError, match="header"):
        request("GET", "/version", headers={"authorization": "secret"})
    with pytest.raises(EngineDockerPolicyError, match="host"):
        request("GET", "/version", headers={"host": "127.0.0.1"})
    with pytest.raises(EngineDockerPolicyError, match="length"):
        request(
            "POST",
            "/v1.47/containers/create?name=x",
            b"{}",
            headers={"content-length": "3", "content-type": "application/json"},
        )
    with pytest.raises(EngineDockerPolicyError, match="accept"):
        request("GET", "/version", headers={"accept": "text/html"})


def test_direct_request_construction_cannot_bypass_header_or_body_validation() -> None:
    with pytest.raises(EngineDockerPolicyError, match="header"):
        DockerApiRequest(
            method="GET",
            target="/version",
            headers=(("authorization", "secret"),),
            body=b"",
        )
    with pytest.raises(EngineDockerPolicyError, match="application/json"):
        DockerApiRequest(
            method="POST",
            target="/v1.47/build",
            headers=(),
            body=b"{}",
        )


@pytest.mark.parametrize(
    "method,target,operation,response",
    [
        ("GET", "/_ping", DockerApiOperation.PING, DockerResponseContract.PING),
        ("HEAD", "/_ping", DockerApiOperation.PING, DockerResponseContract.PING),
        (
            "GET",
            "/version",
            DockerApiOperation.VERSION,
            DockerResponseContract.VERSION_REDACTED,
        ),
        (
            "GET",
            "/v1.47/info",
            DockerApiOperation.INFO,
            DockerResponseContract.INFO_REDACTED,
        ),
    ],
)
def test_only_exact_negotiation_and_redacted_metadata_are_allowed(
    method: str,
    target: str,
    operation: DockerApiOperation,
    response: DockerResponseContract,
) -> None:
    result = authorize(method, target)
    assert result.operation is operation
    assert result.response_contract is response


def test_image_inspection_requires_the_exact_fully_encoded_digest_reference() -> None:
    encoded = quote(IMAGE_REFERENCE, safe="")
    result = authorize("GET", f"/v1.47/images/{encoded}/json")
    assert result.operation is DockerApiOperation.IMAGE_INSPECT
    assert result.response_contract is DockerResponseContract.EXACT_IMAGE

    for target in (
        "/v1.47/images/ghcr.io/usestrix/sandbox:latest/json",
        f"/v1.46/images/{encoded}/json",
        "/v1.47/images/json",
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize("GET", target)


def test_exact_container_create_requires_post_inspect_registration() -> None:
    plan = policy()
    result = authorize_docker_api_request(
        plan,
        request("POST", f"/v1.47/containers/create?name={plan.container_name}", create_body()),
        ownership(container=False, exec_id=False),
    )

    assert result.operation is DockerApiOperation.CONTAINER_CREATE
    assert result.response_contract is DockerResponseContract.REGISTER_PENDING_CONTAINER
    assert result.body_digest == content_hash(create_body())

    with pytest.raises(EngineDockerPolicyError, match="count"):
        authorize("POST", f"/v1.47/containers/create?name={plan.container_name}", create_body())


def test_moby_private_namespace_wire_values_are_exact_and_inspectable() -> None:
    plan = policy()
    row = create_body()
    host = row["HostConfig"]
    assert isinstance(host, dict)

    assert host["IpcMode"] == "private"
    assert host["PidMode"] == ""
    assert host["UTSMode"] == ""
    # A real inspect HostConfig contains many additional fields. The proof is
    # deliberately strict about these three namespace modes without pretending
    # that its small projection is the entire Moby response schema.
    inspected_host = dict(host)
    inspected_host["UsernsMode"] = ""
    validate_docker_container_namespace_proof(plan, inspected_host)


@pytest.mark.parametrize(
    "field,value",
    [
        ("IpcMode", ""),
        ("IpcMode", "host"),
        ("IpcMode", f"container:{CONTAINER_ID}"),
        ("IpcMode", None),
        ("IpcMode", False),
        ("PidMode", "private"),
        ("PidMode", "host"),
        ("PidMode", f"container:{CONTAINER_ID}"),
        ("PidMode", f"container:{OTHER_CONTAINER_ID}"),
        ("PidMode", "container:"),
        ("PidMode", "HOST"),
        ("PidMode", "host "),
        ("PidMode", None),
        ("PidMode", False),
        ("PidMode", 0),
        ("UTSMode", "private"),
        ("UTSMode", "host"),
        ("UTSMode", f"container:{CONTAINER_ID}"),
        ("UTSMode", "HOST"),
        ("UTSMode", "host "),
        ("UTSMode", None),
        ("UTSMode", False),
        ("UTSMode", 0),
    ],
)
def test_create_and_inspect_proof_refuse_namespace_sharing_and_invalid_modes(
    field: str, value: object
) -> None:
    row = create_body()
    host = row["HostConfig"]
    assert isinstance(host, dict)
    host[field] = value

    with pytest.raises(EngineDockerPolicyError, match="private namespace"):
        validate_docker_container_namespace_proof(policy(), host)
    with pytest.raises(EngineDockerPolicyError, match="private namespace"):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize("field", ["IpcMode", "PidMode", "UTSMode"])
def test_create_and_inspect_proof_require_all_namespace_fields(field: str) -> None:
    row = create_body()
    host = row["HostConfig"]
    assert isinstance(host, dict)
    host.pop(field)

    with pytest.raises(EngineDockerPolicyError, match="private namespace"):
        validate_docker_container_namespace_proof(policy(), host)
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


def test_every_authorization_is_bound_to_the_admitted_daemon_and_baseline() -> None:
    plan = policy()
    assert plan.daemon_instance_digest == DAEMON_DIGEST
    assert plan.disposable_boundary_ref == custody().disposable_boundary_ref
    assert plan.baseline_inventory_digest == custody().baseline_inventory_digest

    rotated = DockerOwnership.create(
        daemon_instance_digest="sha256:" + "9" * 64,
        container_ids=(CONTAINER_ID,),
        exec_bindings=((EXEC_ID, CONTAINER_ID),),
    )
    with pytest.raises(EngineDockerPolicyError, match="daemon identity changed"):
        authorize_docker_api_request(plan, request("GET", "/version"), rotated)

    changed = replace(plan, daemon_instance_digest="sha256:" + "9" * 64)
    assert changed.policy_digest != plan.policy_digest


def test_created_container_is_pending_until_exact_inspection() -> None:
    pending = DockerOwnership.create(
        daemon_instance_digest=DAEMON_DIGEST,
        pending_container_ids=(CONTAINER_ID,),
    )
    result = authorize_docker_api_request(
        policy(), request("GET", f"/v1.47/containers/{CONTAINER_ID}/json"), pending
    )
    assert result.response_contract is DockerResponseContract.VERIFY_AND_REGISTER_CONTAINER

    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(), request("POST", f"/v1.47/containers/{CONTAINER_ID}/start"), pending
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row["HostConfig"]["Binds"].append("/host:/workspace"),
        lambda row: row["HostConfig"]["Devices"].append({"PathOnHost": "/dev/kvm"}),
        lambda row: row["HostConfig"]["ExtraHosts"].append("host.docker.internal:host-gateway"),
        lambda row: row["HostConfig"].__setitem__("Privileged", True),
        lambda row: row["HostConfig"].__setitem__("ReadonlyRootfs", False),
        lambda row: row["HostConfig"].__setitem__("NetworkMode", "host"),
        lambda row: row["HostConfig"].__setitem__("PidMode", "host"),
        lambda row: row["HostConfig"].__setitem__("IpcMode", "host"),
        lambda row: row["HostConfig"].__setitem__("UTSMode", "host"),
        lambda row: row["HostConfig"].__setitem__("SecurityOpt", ["apparmor:unconfined"]),
        lambda row: row["HostConfig"].__setitem__("PortBindings", {"80/tcp": [{}]}),
        lambda row: row["HostConfig"].__setitem__("PublishAllPorts", True),
        lambda row: row["HostConfig"]["CapAdd"].append("SYS_ADMIN"),
        lambda row: row["HostConfig"].__setitem__("Memory", 0),
        lambda row: row["HostConfig"].__setitem__("NanoCpus", 0),
        lambda row: row["HostConfig"].__setitem__("PidsLimit", -1),
        lambda row: row["HostConfig"].__setitem__("CgroupParent", "/"),
        lambda row: row["HostConfig"].__setitem__("Tmpfs", {}),
        lambda row: row["HostConfig"].__setitem__(
            "RestartPolicy", {"MaximumRetryCount": 1, "Name": "always"}
        ),
        lambda row: row["HostConfig"].__setitem__("AutoRemove", True),
        lambda row: row.__setitem__("Env", ["AWS_ACCESS_KEY_ID=secret"]),
        lambda row: row.__setitem__("Cmd", ["sh", "-c", "host command"]),
        lambda row: row.__setitem__("Image", "sandbox:latest"),
        lambda row: row.__setitem__("User", "root"),
        lambda row: row["Labels"].pop("bluefire.engine.attempt"),
        lambda row: row["NetworkingConfig"]["EndpointsConfig"].__setitem__(
            "bridge", {"Aliases": [], "NetworkID": NETWORK_ID}
        ),
        lambda row: row.__setitem__("Hostname", "host"),
    ],
)
def test_container_create_rejects_escape_and_unreviewed_fields(mutator: object) -> None:
    row = create_body()
    mutator(row)  # type: ignore[operator]
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize("field", ["Memory", "NanoCpus", "PidsLimit"])
def test_container_create_rejects_float_limits_equal_to_reviewed_integers(field: str) -> None:
    row = create_body()
    row["HostConfig"][field] = float(row["HostConfig"][field])  # type: ignore[index]
    with pytest.raises(EngineDockerPolicyError, match="integer"):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


def test_ownership_requires_full_daemon_ids_and_cannot_be_constructed_directly() -> None:
    with pytest.raises(EngineDockerPolicyError):
        DockerOwnership.create(
            daemon_instance_digest=DAEMON_DIGEST,
            container_ids=(CONTAINER_ID[:12],),
        )
    with pytest.raises(EngineDockerPolicyError):
        DockerOwnership(
            daemon_instance_digest=DAEMON_DIGEST,
            pending_container_ids=(),
            container_ids=(CONTAINER_ID[:12],),
            exec_bindings=(),
        )


def test_raw_pinned_upstream_host_gateway_shape_is_explicitly_non_admitting() -> None:
    row = create_body()
    row["HostConfig"]["ExtraHosts"] = ["host.docker.internal:host-gateway"]  # type: ignore[index]
    row["Labels"].pop("bluefire.engine.attempt")  # type: ignore[union-attr]
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy(),
            request("POST", f"/v1.47/containers/create?name={policy().container_name}", row),
            ownership(container=False, exec_id=False),
        )


@pytest.mark.parametrize(
    "method,suffix,body,operation",
    [
        ("GET", "json", None, DockerApiOperation.CONTAINER_INSPECT),
        ("POST", "start", None, DockerApiOperation.CONTAINER_START),
        ("POST", "exec", exec_body(), DockerApiOperation.CONTAINER_EXEC_CREATE),
    ],
)
def test_container_operations_require_positive_ownership(
    method: str, suffix: str, body: dict[str, object] | None, operation: DockerApiOperation
) -> None:
    result = authorize(method, f"/v1.47/containers/{CONTAINER_ID}/{suffix}", body)
    assert result.operation is operation
    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(),
            request(method, f"/v1.47/containers/{OTHER_CONTAINER_ID}/{suffix}", body),
            ownership(),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("Privileged", True),
        ("Tty", True),
        ("AttachStdin", True),
        ("Env", ["TOKEN=secret"]),
        ("User", "root"),
        ("WorkingDir", "/"),
    ],
)
def test_exec_rejects_privilege_identity_environment_and_terminal_escalation(
    field: str, value: object
) -> None:
    row = exec_body()
    row[field] = value
    with pytest.raises(EngineDockerPolicyError):
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)


def test_exec_allows_bounded_model_chosen_commands_only_in_owned_sandbox() -> None:
    row = exec_body(command=["sh", "-lc", "find /workspace -maxdepth 2 -type f"])
    result = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)
    assert result.operation is DockerApiOperation.CONTAINER_EXEC_CREATE
    assert result.response_contract is DockerResponseContract.REGISTER_EXEC
    assert result.owner_container_id == CONTAINER_ID

    row = exec_body(command=["x" * 8193])
    with pytest.raises(EngineDockerPolicyError, match="command"):
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", row)

    for command in (["sh", "-lc", "echo one\necho two"], ["id\x7f"]):
        with pytest.raises(EngineDockerPolicyError, match="command"):
            authorize(
                "POST",
                f"/v1.47/containers/{CONTAINER_ID}/exec",
                exec_body(command=command),
            )


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/workspace", True),
        ("/workspace/", False),
        ("/workspace/.", False),
        ("/workspace/link", False),
        ("/workspace/results/report.json", False),
        ("/workspace//report.json", False),
        ("/workspace/%2e%2e/etc/passwd", False),
        ("/workspace/%2Fetc/passwd", False),
        ("/workspace/symlink/../../etc/passwd", False),
        ("/tmp/sandbox-docker-archive/bundle.tar", False),
        ("/etc/passwd", False),
        ("/workspace/../etc/passwd", False),
        ("/proc/self/root/workspace", False),
        ("/Workspace", False),
        ("workspace", False),
        ("/workspace\\link", False),
        ("/workspace\x00link", False),
        ("/tmp", False),
    ],
)
def test_archive_reads_are_limited_to_the_exact_admitted_mountpoint(
    path: str, allowed: bool
) -> None:
    target = f"/v1.47/containers/{CONTAINER_ID}/archive?{urlencode({'path': path})}"
    if allowed:
        result = authorize("GET", target)
        assert result.response_contract is DockerResponseContract.BOUNDED_ARCHIVE
    else:
        with pytest.raises(EngineDockerPolicyError):
            authorize("GET", target)


def test_logs_stop_kill_and_delete_require_exact_bounded_queries() -> None:
    logs = f"/v1.47/containers/{CONTAINER_ID}/logs?follow=0&stderr=1&stdout=1&tail=100&timestamps=1"
    assert authorize("GET", logs).operation is DockerApiOperation.CONTAINER_LOGS
    assert (
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/stop?t=30").operation
        is DockerApiOperation.CONTAINER_STOP
    )
    assert (
        authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/kill?signal=SIGKILL").operation
        is DockerApiOperation.CONTAINER_KILL
    )
    assert (
        authorize("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=1&v=1").operation
        is DockerApiOperation.CONTAINER_DELETE
    )

    for method, target in (
        ("GET", logs.replace("follow=0", "follow=1")),
        ("GET", logs.replace("tail=100", "tail=0100")),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/stop?t=31"),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/kill?signal=SIGHUP"),
        ("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=0&v=1"),
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize(method, target)


def test_exec_start_and_inspect_require_registered_exec_binding() -> None:
    start = authorize("POST", f"/v1.47/exec/{EXEC_ID}/start", {"Detach": False, "Tty": False})
    assert start.operation is DockerApiOperation.EXEC_START
    assert start.response_contract is DockerResponseContract.BOUNDED_EXEC_STREAM
    assert start.owner_container_id == CONTAINER_ID
    assert start.deadline_seconds == policy().exec_deadline_seconds
    assert start.response_byte_limit == policy().exec_response_byte_limit
    inspect = authorize("GET", f"/v1.47/exec/{EXEC_ID}/json")
    assert inspect.operation is DockerApiOperation.EXEC_INSPECT

    with pytest.raises(EngineDockerPolicyError, match="positively owned"):
        authorize_docker_api_request(
            policy(),
            request("GET", f"/v1.47/exec/{'9' * 64}/json"),
            ownership(),
        )


@pytest.mark.parametrize(
    "method,target,body",
    [
        ("POST", "/v1.47/images/create?fromImage=sandbox", None),
        ("POST", "/v1.47/build", {}),
        ("GET", "/v1.47/containers/json", None),
        ("GET", "/v1.47/networks", None),
        ("POST", "/v1.47/networks/create", {}),
        ("GET", "/v1.47/volumes", None),
        ("GET", "/v1.47/events", None),
        ("POST", f"/v1.47/containers/{CONTAINER_ID}/attach", {}),
        ("PUT", f"/v1.47/containers/{CONTAINER_ID}/archive?path=%2Fworkspace", b"x"),
        ("POST", "/v1.47/system/prune", {}),
        ("GET", "/v1.47/plugins", None),
        ("GET", "/v1.47/swarm", None),
    ],
)
def test_all_unreviewed_daemon_and_resource_routes_fail_closed(
    method: str, target: str, body: dict[str, object] | bytes | None
) -> None:
    with pytest.raises(EngineDockerPolicyError):
        authorize(method, target, body)


def test_json_duplicate_keys_nonfinite_values_bom_and_oversize_fail_closed() -> None:
    target = f"/v1.47/containers/{CONTAINER_ID}/exec"
    for raw in (
        b'{"Cmd":["id"],"Cmd":["whoami"]}',
        b'{"value":NaN}',
        b"\xef\xbb\xbf{}",
        b"{" + b" " * (64 * 1024) + b"}",
    ):
        with pytest.raises(EngineDockerPolicyError):
            authorize(target=target, method="POST", body=raw)


def test_decision_digests_are_stable_and_bind_policy_and_body() -> None:
    first = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body())
    second = authorize("POST", f"/v1.47/containers/{CONTAINER_ID}/exec", exec_body())
    changed = authorize(
        "POST",
        f"/v1.47/containers/{CONTAINER_ID}/exec",
        exec_body(command=["sh", "-lc", "pwd"]),
    )
    assert first == second
    assert first.policy_digest == policy().policy_digest
    assert first.body_digest != changed.body_digest


def test_test_mutations_do_not_change_shared_create_fixture() -> None:
    original = create_body()
    changed = deepcopy(original)
    changed["HostConfig"]["Binds"].append("/host:/workspace")  # type: ignore[index]
    assert original["HostConfig"]["Binds"] == []  # type: ignore[index]
