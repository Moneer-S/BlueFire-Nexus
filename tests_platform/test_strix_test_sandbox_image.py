"""The ephemeral test image stays distinct, exact, and non-production."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from bluefire import strix_test_sandbox_image as image
from bluefire.strix_image_contract import StrixImageContractError
from bluefire.util import canonical_json_bytes, content_hash


def _digest(label: str) -> str:
    return content_hash({"strix-test-image": label})


def _descriptor(label: str, role: str, *, platform: bool = False) -> dict[str, Any]:
    media = {
        "index": "application/vnd.oci.image.index.v1+json",
        "manifest": "application/vnd.oci.image.manifest.v1+json",
        "config": "application/vnd.oci.image.config.v1+json",
        "layer": "application/vnd.oci.image.layer.v1.tar+gzip",
    }[role]
    row: dict[str, Any] = {"media_type": media, "digest": _digest(label), "size": 4096}
    if platform:
        row["platform"] = dict(image.PLATFORM)
    return row


def _contract_document() -> dict[str, Any]:
    prelaunch_plan_ref = _digest("runtime-prelaunch-plan")
    fixed_exec_qualification_ref = _digest("runtime-fixed-exec-qualification")
    runtime_composite = content_hash(
        {
            "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
            "prelaunch_plan_ref": prelaunch_plan_ref,
            "fixed_exec_qualification_ref": fixed_exec_qualification_ref,
        }
    )
    provider_artifact = _digest("provider-source-artifact")
    index = _descriptor("index", "index")
    manifest = _descriptor("manifest", "manifest", platform=True)
    config = _descriptor("config", "config")
    return {
        "schema_version": image.SCHEMA_VERSION,
        "bluefire_source_revision": "a" * 40,
        "strix_source_revision": image.STRIX_SOURCE_REVISION,
        "platform": dict(image.PLATFORM),
        "base_image": copy.deepcopy(image.BASE_IMAGE),
        "package_lock": {
            "digest": image.package_lock_digest(),
            "document": image.package_lock_document(),
        },
        "runtime_closure": {
            "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
            "composite_ref": runtime_composite,
            "prelaunch_plan_ref": prelaunch_plan_ref,
            "fixed_exec_qualification_ref": fixed_exec_qualification_ref,
            "inventory_digest": _digest("runtime-inventory"),
            "interpreter_digest": _digest("python-3.12.14"),
            "entrypoint_digest": _digest("installed-worker-entrypoint"),
            "worker_invocation_digest": image.installed_worker_invocation_digest(),
            "worker_distribution": "bluefire-strix-worker",
            "worker_artifact_digest": _digest("bluefire-strix-worker"),
            "worker_record_digest": _digest("bluefire-strix-worker-record"),
            "worker_source_revision": "a" * 40,
            "installed_distributions_digest": _digest("installed-distributions"),
            "full_product_wheel_present": False,
            "strix_candidate_digest": _digest("strix-candidate"),
            "source_revision": image.STRIX_SOURCE_REVISION,
            "python_version": "3.12.14",
        },
        "test_provider": {
            "schema_version": "bluefire.test-caido-protocol-provider.v1",
            "module": image.TEST_PROVIDER_MODULE,
            "execution_location": "controller",
            "provider_source_digest": provider_artifact,
            "artifact_digest": provider_artifact,
            "invocation_digest": image.test_provider_invocation_digest(),
            "sdk_client_wheel_digest": image.CAIDO_SDK_CLIENT_WHEEL_DIGEST,
            "sdk_wire_fixture_digest": image.CAIDO_SDK_WIRE_FIXTURE_DIGEST,
            "sdk_project_document_digest": image.CAIDO_SDK_PROJECT_DOCUMENT_DIGEST,
            "strix_bootstrap_digest": image.STRIX_CAIDO_BOOTSTRAP_DIGEST,
            "host": image.TEST_PROVIDER_HOST,
            "port": image.TEST_PROVIDER_PORT,
            "test_provider": True,
            "live_caido_proof": False,
            "production_eligible": False,
            "caido_cli_or_server_present": False,
            "official_caido_image_present": False,
            "derived_caido_image_present": False,
        },
        "build": {
            "dockerfile_digest": _digest("dockerfile"),
            "context_digest": _digest("context"),
            "runtime_closure_digest": runtime_composite,
            "container_entrypoint_digest": _digest("container-entrypoint"),
            "self_test_digest": _digest("self-test"),
            "network_mode": "none",
            "pull": False,
            "runtime_installs": False,
        },
        "image": {
            "index_reference": f"localhost/bluefire/strix-test-sandbox@{index['digest']}",
            "index": index,
            "platform_child": manifest,
            "config": config,
            "layers": [
                _descriptor("base-layer", "layer"),
                _descriptor("runtime-layer", "layer"),
            ],
            "image_id": config["digest"],
            "imported_reference": (
                f"localhost/bluefire/strix-test-sandbox-amd64@{manifest['digest']}"
            ),
        },
        "runtime_profile": image.proposed_test_runtime_profile(),
        "qualification": {
            "qualification_ref": _digest("qualification"),
            "qualifier_revision": "b" * 40,
            "runner_os": "Linux",
            "runner_image": "ubuntu-24.04",
            "runner_architecture": "x86_64",
            "docker_server_digest": _digest("docker-server"),
            "sbom_digest": _digest("sbom"),
            "provenance_digest": _digest("provenance"),
            "notice_report_digest": _digest("notices"),
            "self_test_evidence_digest": _digest("self-test-evidence"),
            "image_built": True,
            "image_imported": True,
            "image_started": True,
            "self_test_passed": True,
            "cleanup_label": "bluefire.strix-test-sandbox." + "c" * 32,
        },
        "policy": {
            "test_only": True,
            "runner_private": True,
            "image_upload_allowed": False,
            "image_publish_allowed": False,
            "production_runtime_admitted": False,
            "live_engine_proof": False,
            "live_caido_proof": False,
            "redistribution_authorized": False,
        },
    }


def test_contract_binds_exact_test_image_without_promoting_other_proofs() -> None:
    contract = image.StrixTestSandboxImageContractV1.from_mapping(_contract_document())

    assert contract.canonical_bytes == canonical_json_bytes(contract.to_dict())
    assert contract.contract_digest.startswith("sha256:")
    assert contract.qualification_ref == _digest("qualification")
    assert contract.runtime_closure_ref == _contract_document()["runtime_closure"]["composite_ref"]
    assert contract.worker_identity_ref == content_hash(
        {
            "schema_version": "bluefire.strix-worker-identity.v1",
            "distribution": "bluefire-strix-worker",
            "artifact_digest": _digest("bluefire-strix-worker"),
            "record_digest": _digest("bluefire-strix-worker-record"),
            "source_revision": "a" * 40,
            "installed_distributions_digest": _digest("installed-distributions"),
        }
    )
    assert contract.image_reference.startswith("localhost/bluefire/strix-test-sandbox@sha256:")
    assert contract.to_dict()["policy"] == {
        "test_only": True,
        "runner_private": True,
        "image_upload_allowed": False,
        "image_publish_allowed": False,
        "production_runtime_admitted": False,
        "live_engine_proof": False,
        "live_caido_proof": False,
        "redistribution_authorized": False,
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("base_image", "repository"), "ghcr.io/usestrix/strix-sandbox"),
        (("base_image", "version_label"), "kali-rolling"),
        (("runtime_closure", "python_version"), "3.12.16"),
        (("runtime_closure", "composite_ref"), _digest("replacement-runtime")),
        (("runtime_closure", "worker_distribution"), "bluefire-nexus"),
        (("runtime_closure", "full_product_wheel_present"), True),
        (("runtime_closure", "worker_source_revision"), "d" * 40),
        (("test_provider", "artifact_digest"), _digest("replacement-provider")),
        (("test_provider", "live_caido_proof"), True),
        (("test_provider", "caido_cli_or_server_present"), True),
        (("build", "network_mode"), "default"),
        (("build", "pull"), True),
        (("runtime_profile", "docker_socket"), True),
        (("runtime_profile", "host_gateway"), True),
        (("policy", "image_upload_allowed"), True),
        (("policy", "production_runtime_admitted"), True),
        (("qualification", "self_test_passed"), False),
    ],
)
def test_contract_refuses_identity_scope_and_containment_drift(
    path: tuple[str, str], value: Any
) -> None:
    row = _contract_document()
    row[path[0]][path[1]] = value

    with pytest.raises(StrixImageContractError):
        image.StrixTestSandboxImageContractV1.from_mapping(row)


def test_contract_refuses_unbound_runtime_and_provider_dependencies() -> None:
    row = _contract_document()
    row["runtime_closure"].pop("fixed_exec_qualification_ref")
    with pytest.raises(StrixImageContractError, match="runtime closure fields"):
        image.StrixTestSandboxImageContractV1.from_mapping(row)

    row = _contract_document()
    row["test_provider"].pop("provider_source_digest")
    with pytest.raises(StrixImageContractError, match="test provider fields"):
        image.StrixTestSandboxImageContractV1.from_mapping(row)


def test_contract_refuses_noncanonical_encoding_and_overlapping_oci_roles() -> None:
    contract = image.StrixTestSandboxImageContractV1.from_mapping(_contract_document())
    with pytest.raises(StrixImageContractError, match="not canonical"):
        image.StrixTestSandboxImageContractV1(
            json.dumps(contract.to_dict(), indent=2).encode("utf-8")
        )

    row = _contract_document()
    row["image"]["config"]["digest"] = row["image"]["platform_child"]["digest"]
    row["image"]["image_id"] = row["image"]["config"]["digest"]
    with pytest.raises(StrixImageContractError, match="roles overlap"):
        image.StrixTestSandboxImageContractV1.from_mapping(row)


def test_package_lock_is_exact_offline_and_contains_only_required_added_tool() -> None:
    lock = image.package_lock_document()

    assert lock["build_network"] == "none"
    assert lock["runtime_package_manager_present"] is False
    assert lock["runtime_installs"] is False
    assert {item["name"] for item in lock["base_tools"]} == {
        "bash",
        "coreutils",
        "dash",
        "tar",
    }
    names = {item["name"] for item in lock["offline_packages"]}
    assert "curl" in names
    assert not names & {"caido", "docker", "git", "nmap", "python3", "wget"}
    assert len(names) == len(lock["offline_packages"])
    assert all(
        item["url"].startswith("https://deb.debian.org/debian/pool/")
        for item in lock["offline_packages"]
    )
    assert all(len(item["sha256"]) == 64 for item in lock["offline_packages"])


def test_downloaded_package_set_must_match_order_names_and_hashes() -> None:
    items = [
        {"filename": item["filename"], "sha256": item["sha256"]}
        for item in image.OFFLINE_CURL_CLOSURE
    ]
    image.validate_package_archive_digests(items)

    changed = copy.deepcopy(items)
    changed[0]["sha256"] = "0" * 64
    with pytest.raises(StrixImageContractError, match="offline package archives"):
        image.validate_package_archive_digests(changed)
    with pytest.raises(StrixImageContractError, match="offline package archives"):
        image.validate_package_archive_digests(list(reversed(items)))


def test_runtime_profile_has_one_private_writable_workspace_and_no_host_escape() -> None:
    profile = image.proposed_test_runtime_profile()

    assert profile["user"] == "1000:1000"
    assert profile["working_directory"] == "/workspace"
    assert profile["read_only_root"] is True
    assert set(profile["tmpfs"]) == {"/workspace"}
    assert profile["tmpfs"]["/workspace"].startswith("rw,nosuid,nodev,noexec,")
    assert profile["mounts"] == []
    assert profile["extra_hosts"] == []
    assert profile["docker_socket"] is False
    assert profile["host_gateway"] is False
    assert profile["cap_drop"] == ["ALL"]
    assert profile["network"]["public_egress"] is False
    assert profile["network"]["dns"] is False


def test_worker_and_test_provider_invocations_are_fixed_and_descriptor_owned() -> None:
    worker = image.installed_worker_invocation_document()
    provider = image.test_provider_invocation_document()

    assert worker["argv"] == [
        "/runtime/bin/python",
        "-I",
        "-S",
        "-B",
        "-X",
        "utf8",
        "/bootstrap/worker.py",
    ]
    assert worker["caller_arguments_allowed"] is False
    assert provider["argv"][-8:] == [
        "--manifest-fd",
        "<controller-owned-fd>",
        "--listener-fd",
        "<prebound-127.0.0.1:48080-fd>",
        "--audit-fd",
        "<controller-owned-fd>",
        "--ready-fd",
        "<controller-owned-fd>",
    ]
    assert provider["execution_location"] == "controller"
    assert provider["argv"][0] == "<controller-owned-python>"
    assert provider["socket_creation"] is False
    assert provider["socket_bind"] is False
    assert provider["socket_listen"] is False
    assert provider["socket_connect"] is False


def test_base_is_pinned_official_debian_and_not_an_upstream_strix_or_kali_image() -> None:
    base = json.dumps(image.BASE_IMAGE, sort_keys=True)

    assert image.BASE_IMAGE["index_reference"].startswith("docker.io/library/debian@sha256:")
    assert image.BASE_IMAGE["platform_child"]["platform"] == image.PLATFORM
    assert len(image.BASE_IMAGE["layers"]) == 1
    assert "usestrix" not in base
    assert "strix-sandbox" not in base
    assert "kali" not in base.lower()
    assert "caido" not in base.lower()


def test_cleanup_receipt_requires_exact_absence_for_all_private_material() -> None:
    contract = image.StrixTestSandboxImageContractV1.from_mapping(_contract_document())
    row = {
        "schema_version": image.CLEANUP_SCHEMA_VERSION,
        "contract_digest": contract.contract_digest,
        "qualification_ref": contract.qualification_ref,
        "cleanup_label": "bluefire.strix-test-sandbox." + "c" * 32,
        "container_absent": True,
        "network_absent": True,
        "image_absent": True,
        "build_context_absent": True,
        "oci_layout_absent": True,
        "docker_archive_absent": True,
        "runtime_stage_absent": True,
        "cleanup_evidence_digest": _digest("cleanup-evidence"),
    }
    receipt = image.StrixTestSandboxImageCleanupReceiptV1.from_mapping(row)
    assert receipt.receipt_digest.startswith("sha256:")

    for field in (
        "container_absent",
        "network_absent",
        "image_absent",
        "build_context_absent",
        "oci_layout_absent",
        "docker_archive_absent",
        "runtime_stage_absent",
    ):
        changed = dict(row)
        changed[field] = False
        with pytest.raises(StrixImageContractError, match="cleanup result"):
            image.StrixTestSandboxImageCleanupReceiptV1.from_mapping(changed)
