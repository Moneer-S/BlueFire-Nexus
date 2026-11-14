from __future__ import annotations

import copy
import json
from dataclasses import asdict
from typing import Any, Callable

import pytest

from bluefire.product_store_engine_execution_claims import _claim_reference
from bluefire.strix_controlled_backend import ControlledCreateRequest, ControlledRuntimeProfile
from bluefire.strix_controlled_bootstrap import _validate_environment
from bluefire.strix_controlled_execution_identity import StrixControlledExecutionIdentityV2
from bluefire.strix_controlled_runtime_admission import (
    ADMISSION_SCHEMA,
    FILESYSTEM_CONFORMANCE,
    StrixControlledLaunchPlanV2,
    StrixControlledRuntimeAdmissionError,
    StrixControlledRuntimeAdmissionV2,
    build_controlled_launch_plan,
)
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_engine_docker_control import v2_policy_inputs
from tests_platform.test_strix_controlled_backend import _manifest_document


def digest(label: str) -> str:
    return content_hash(label)


def admission_document(*, sandbox_uid: int = 1000, sandbox_gid: int = 1000) -> dict[str, Any]:
    """Synthetic declarations only: no controller verifier or authority is used."""
    inputs = v2_policy_inputs()
    identity = inputs["execution_identity"].to_dict()
    network = inputs["network"]
    custody = inputs["custody"]
    manifest = _manifest_document()
    manifest["environment"]["value"].update(
        STRIX_HOST_UID=str(sandbox_uid), STRIX_HOST_GID=str(sandbox_gid)
    )
    old_profile = identity["controlled_runtime_profile"]
    profile_values = {
        name: value
        for name, value in old_profile.items()
        if name
        not in {
            "schema_version",
            "source_revision",
            "profile_digest",
            "exec_timeout_seconds",
            "exec_output_limit_bytes",
            "workspace_object_limit_bytes",
            "write_chunk_bytes",
        }
    }
    profile_values.update(
        sandbox_uid=sandbox_uid,
        sandbox_gid=sandbox_gid,
        policy_digest=network.policy_digest,
        boundary_digest=custody.disposable_boundary_ref,
        manifest_digest=content_hash(manifest),
        tmpfs_contract_digest=content_hash(
            inputs["image_contract"].to_dict()["runtime_profile"]["tmpfs"]
        ),
    )
    profile = ControlledRuntimeProfile.create(**profile_values)
    identity["controlled_runtime_profile"] = asdict(profile)
    identity["controlled_runtime_profile_ref"] = profile.profile_digest
    execution = StrixControlledExecutionIdentityV2.from_mapping(identity)
    attempt = identity["attempt_id"]
    root = f"/var/lib/bluefire/private/{attempt}"
    binding = digest("binding")
    delegation = digest("delegation")
    claim = {
        "schema_version": "bluefire.engine-attempt-execution-claim.v1",
        "claim_ref": "",
        "job_id": "job-" + "b" * 32,
        "attempt_id": attempt,
        "experiment_id": "experiment-" + "c" * 32,
        "preparation_ref": digest("preparation"),
        "preparation_id": digest("preparation-id"),
        "preparation_record_digest": digest("preparation-record"),
        "acceptance_record_digest": digest("acceptance"),
        "binding_digest": binding,
        "delegation_digest": delegation,
        "submission_id": "engine-submission-" + "d" * 32,
        "intent_digest": digest("intent"),
        "job_request_digest": digest("request"),
        "runtime_resolution_ref": digest("resolution"),
        "preflight_revision": 2,
        "preflight_experiment_digest": digest("preflight"),
        "claimed_at": "2026-11-05T12:00:00Z",
    }
    claim["claim_ref"] = _claim_reference(claim)
    package = {
        "package": "bluefire-nexus",
        "version": "3.0.0",
        "artifact_digest": digest("bluefire-package"),
        "source_revision": "8" * 40,
    }
    return {
        "schema_version": ADMISSION_SCHEMA,
        "attempt_id": attempt,
        "binding_digest": binding,
        "delegation_digest": delegation,
        "objective_ref": digest("objective"),
        "environment_ref": digest("environment"),
        "execution_identity": execution.to_dict(),
        "execution_identity_ref": execution.identity_digest,
        "image_contract": inputs["image_contract"].to_dict(),
        "image_admission_decision": json.loads(
            json.dumps(asdict(inputs["image_admission_decision"]))
        ),
        "bootstrap_package_identity": {
            **package,
            "module": "bluefire.strix_controlled_bootstrap",
            "module_digest": profile.bootstrap_digest,
        },
        "backend_package_identity": {
            **package,
            "module": "bluefire.strix_controlled_backend",
            "module_digest": digest("backend-module"),
        },
        "sdk_package_identity": {
            "package": "openai-agents",
            "version": "0.19.0",
            "artifact_digest": profile.sdk_digest,
        },
        "network_plan": network.to_dict(),
        "custody_plan": custody.to_dict(),
        "scope": {
            "target": network.target.origin + "/",
            "resolved_addresses": [network.target.address],
            "target_snapshot_digest": digest("target"),
            "scope_digest": digest("scope"),
            "network_policy_digest": network.policy_digest,
            "network_name": network.network_name,
        },
        "gateway": {
            "model": "reviewed-model",
            "base_url": network.model_gateway.origin,
            "authorization_digest": digest("authorization"),
        },
        "budgets": {"wall_seconds": 120, "max_turns_per_agent": 4, "max_model_cost_usd": "1"},
        "controlled_manifest": manifest,
        "caido_relay_identity": {
            "schema_version": "bluefire.strix-caido-relay-identity.v2",
            "caido_version": "0.56.0",
            "caido_sdk_client_version": "0.2.0",
            "proxy_origin": "http://127.0.0.1:48080",
            "relay_digest": profile.relay_digest,
            "upstream_digest": profile.relay_upstream_digest,
            "channel_digest": profile.relay_channel_digest,
            "retry_digest": profile.relay_retry_digest,
            "model_gateway": network.model_gateway.to_dict(),
            "manifest_environment": manifest["environment"]["value"],
        },
        "private_workspace": {
            "schema_version": "bluefire.strix-private-workspace.v2",
            "attempt_id": attempt,
            "root": root,
            "home": root + "/home",
            "temporary": root + "/tmp",
            "config_directory": root + "/config",
            "config_file": root + "/config/cli-config.json",
            "mcp_file": root + "/config/mcp-servers.json",
            "objective_file": root + "/objective.txt",
            "workspace": root + "/workspace",
            "objective_sha256": digest("objective-bytes"),
            "workspace_receipt_ref": digest("private-workspace-receipt"),
            "directory_mode": "0700",
            "config_document": {"env": {}},
            "mcp_document": [],
            "credential_persistence": False,
            "docker_host": "unix://" + root + "/docker.sock",
        },
        "launch_executable": {
            "path": "/opt/bluefire/bin/strix-controlled",
            "sha256": digest("bootstrap-launcher"),
        },
        "path_environment": "/opt/bluefire/bin:/usr/bin:/bin",
        "accepted_execution_claim": claim,
        "accepted_execution_claim_ref": claim["claim_ref"],
        "filesystem_conformance": dict(FILESYSTEM_CONFORMANCE),
        "production_runtime_admitted": False,
        "live_execution_proven": False,
    }


def plan(admission: StrixControlledRuntimeAdmissionV2) -> StrixControlledLaunchPlanV2:
    return build_controlled_launch_plan(
        admission,
        expected_admission_ref=admission.admission_ref,
        expected_execution_claim_ref=admission.to_dict()["accepted_execution_claim_ref"],
    )


def test_canonical_admission_and_launch_roundtrip_and_copy_isolation() -> None:
    source = admission_document()
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(source)
    assert StrixControlledRuntimeAdmissionV2(admission.canonical_bytes) == admission
    assert (
        StrixControlledRuntimeAdmissionV2.from_mapping(dict(reversed(list(source.items()))))
        == admission
    )
    launch = plan(admission)
    assert StrixControlledLaunchPlanV2.from_mapping(launch.to_dict()) == launch
    assert StrixControlledLaunchPlanV2(launch.canonical_bytes) == launch
    assert launch.launch_digest == content_hash(launch.to_dict())
    source["private_workspace"]["root"] = "/changed"
    assert admission.to_dict()["private_workspace"]["root"] != "/changed"
    assert "/var/lib" not in repr(admission)
    assert "/var/lib" not in repr(launch)


def test_launch_selects_controlled_bootstrap_and_has_only_attempt_private_config() -> None:
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(admission_document())
    launch = plan(admission).to_dict()
    env = launch["environment"]
    bootstrap = _validate_environment(env)
    assert bootstrap.attempt_id == admission.to_dict()["attempt_id"]
    assert env["STRIX_RUNTIME_BACKEND"] == "bluefire-controlled"
    assert (
        env["STRIX_IMAGE"] == admission.to_dict()["execution_identity"]["derived_image_reference"]
    )
    assert launch["required_secret_environment"] == ["LLM_API_KEY"]
    assert "LLM_API_KEY" not in env
    assert "LLM_API_KEY" not in json.dumps(admission.to_dict())
    workspace = admission.to_dict()["private_workspace"]
    assert env["HOME"] == workspace["home"]
    assert env["XDG_CONFIG_HOME"] == workspace["config_directory"]
    assert launch["cwd"] == workspace["workspace"]
    assert workspace["config_file"] in launch["argv"]
    assert workspace["mcp_file"] in launch["argv"]
    assert launch["production_runtime_admitted"] is False


def test_matching_sandbox_user_binds_profile_image_custody_exports_and_create_request() -> None:
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(
        admission_document(sandbox_uid=1000, sandbox_gid=1000)
    )
    row = admission.to_dict()
    profile = ControlledRuntimeProfile(**row["execution_identity"]["controlled_runtime_profile"])
    request = ControlledCreateRequest.create(profile)
    environment = plan(admission).to_dict()["environment"]
    exported_user = (
        environment["BLUEFIRE_STRIX_SANDBOX_UID"] + ":" + environment["BLUEFIRE_STRIX_SANDBOX_GID"]
    )
    manifest_environment = row["controlled_manifest"]["environment"]["value"]
    manifest_user = (
        manifest_environment["STRIX_HOST_UID"] + ":" + manifest_environment["STRIX_HOST_GID"]
    )
    assert (
        profile.sandbox_user
        == row["image_contract"]["runtime_profile"]["user"]
        == row["custody_plan"]["expected_user"]
        == request.sandbox_user
        == exported_user
        == manifest_user
        == "1000:1000"
    )


@pytest.mark.parametrize("sandbox_uid,sandbox_gid", [(1001, 1001), (1001, 1000), (1000, 1001)])
def test_canonical_profile_user_mismatch_is_refused_before_launch(
    sandbox_uid: int, sandbox_gid: int
) -> None:
    row = admission_document(sandbox_uid=sandbox_uid, sandbox_gid=sandbox_gid)
    # The changed profile, manifest, and execution identity all have valid,
    # recomputed references. Their UID/GID still disagree with image/custody.
    identity = StrixControlledExecutionIdentityV2.from_mapping(row["execution_identity"])
    identity.require_expected_digest(row["execution_identity_ref"])
    profile = ControlledRuntimeProfile(**identity.to_dict()["controlled_runtime_profile"])
    assert profile.sandbox_user == f"{sandbox_uid}:{sandbox_gid}"
    assert row["image_contract"]["runtime_profile"]["user"] == "1000:1000"
    assert row["custody_plan"]["expected_user"] == "1000:1000"
    for parse in (
        lambda: StrixControlledRuntimeAdmissionV2.from_mapping(row),
        lambda: StrixControlledRuntimeAdmissionV2(canonical_json_bytes(row)),
    ):
        with pytest.raises(StrixControlledRuntimeAdmissionError):
            parse()
    launch = plan(StrixControlledRuntimeAdmissionV2.from_mapping(admission_document())).to_dict()
    launch.update(admission=row, admission_ref=content_hash(row))
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        StrixControlledLaunchPlanV2.from_mapping(launch)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(schema_version="bluefire.strix-runtime-admission.v1"),
        lambda r: r.update(attempt_id="attempt-" + "a" * 32),
        lambda r: r.update(execution_identity_ref=digest("other identity")),
        lambda r: r["image_admission_decision"].update(production_runtime_admitted=True),
        lambda r: r["image_admission_decision"].update(contract_digest=digest("other contract")),
        lambda r: r["sdk_package_identity"].update(version="0.20.0"),
        lambda r: r["bootstrap_package_identity"].update(module_digest=digest("other bootstrap")),
        lambda r: r["backend_package_identity"].update(artifact_digest=digest("other package")),
        lambda r: r["network_plan"].update(schema_version="bluefire.engine-network-plan.v1"),
        lambda r: r["custody_plan"].update(schema_version="bluefire.engine-container-custody.v1"),
        lambda r: r["scope"].update(network_name="other-network"),
        lambda r: r["scope"].update(target="http://localhost:8080/"),
        lambda r: r["gateway"].update(base_url="http://example.com:8000"),
        lambda r: r["caido_relay_identity"].update(channel_digest=digest("other channel")),
        lambda r: r["controlled_manifest"]["environment"]["value"].update(
            http_proxy="http://example.com:8080"
        ),
        lambda r: r["controlled_manifest"]["environment"]["value"].update(
            https_proxy="http://example.com:8080"
        ),
        lambda r: r["controlled_manifest"]["environment"]["value"].update(
            ALL_PROXY="http://example.com:8080"
        ),
        lambda r: r["private_workspace"].update(home="/home/shared"),
        lambda r: r["private_workspace"].update(root="/var/lib/../private/" + r["attempt_id"]),
        lambda r: r["private_workspace"].update(directory_mode="0755"),
        lambda r: r["launch_executable"].update(path=r["private_workspace"]["root"]),
        lambda r: r["launch_executable"].update(path=r["private_workspace"]["root"] + "/binary"),
        lambda r: r.update(path_environment=".:/usr/bin"),
        lambda r: r.update(path_environment=r["private_workspace"]["workspace"] + ":/usr/bin"),
        lambda r: r["private_workspace"].update(credential_persistence=True),
        lambda r: r["private_workspace"]["config_document"]["env"].update(
            LLM_API_KEY="never-save-this"
        ),
        lambda r: r["private_workspace"].update(docker_host="unix:///var/run/docker.sock"),
        lambda r: r["accepted_execution_claim"].update(binding_digest=digest("other binding")),
        lambda r: r.update(accepted_execution_claim_ref=digest("other claim")),
        lambda r: r["filesystem_conformance"].update(full_filesystem_tool_conformance=True),
        lambda r: r["filesystem_conformance"].update(tmp_mount_noexec=False),
        lambda r: r.update(production_runtime_admitted=True),
        lambda r: r.update(live_execution_proven=True),
        lambda r: r.update(transport="caller transport"),
    ],
)
def test_admission_rejects_tampered_cross_contract_material(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    row = admission_document()
    mutate(row)
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        StrixControlledRuntimeAdmissionV2.from_mapping(row)
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        StrixControlledRuntimeAdmissionV2(canonical_json_bytes(row))


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("schema_version", "bluefire.strix-launch-plan.v1"),
        ("exec_broker_binding_digest", digest("worker supplied digest")),
        ("required_secret_environment", []),
        ("production_runtime_admitted", True),
        ("cwd", "/shared"),
        ("wall_seconds", 3600),
    ],
)
def test_launch_roundtrip_revalidates_every_derived_field(field: str, replacement: Any) -> None:
    launch = plan(StrixControlledRuntimeAdmissionV2.from_mapping(admission_document())).to_dict()
    launch[field] = replacement
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        StrixControlledLaunchPlanV2.from_mapping(launch)


def test_no_caller_environment_or_secret_can_be_inserted_in_launch() -> None:
    launch = plan(StrixControlledRuntimeAdmissionV2.from_mapping(admission_document())).to_dict()
    for key, value in (
        ("STRIX_RUNTIME_BACKEND", "docker"),
        ("LLM_API_KEY", "never-save-this"),
        ("http_proxy", "http://worker.example:8080"),
    ):
        changed = copy.deepcopy(launch)
        changed["environment"][key] = value
        with pytest.raises(StrixControlledRuntimeAdmissionError):
            StrixControlledLaunchPlanV2.from_mapping(changed)


def test_protected_reference_checks_refuse_recomputed_unrelated_identity() -> None:
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(admission_document())
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        build_controlled_launch_plan(
            admission,
            expected_admission_ref=digest("other admission"),
            expected_execution_claim_ref=admission.to_dict()["accepted_execution_claim_ref"],
        )
    with pytest.raises(StrixControlledRuntimeAdmissionError):
        build_controlled_launch_plan(
            admission,
            expected_admission_ref=admission.admission_ref,
            expected_execution_claim_ref=digest("other claim"),
        )


def test_broker_digest_binds_controller_proxy_manifest_and_claim() -> None:
    original = admission_document()
    original_plan = plan(StrixControlledRuntimeAdmissionV2.from_mapping(original))
    changed = copy.deepcopy(original)
    changed["accepted_execution_claim"]["claimed_at"] = "2026-11-05T12:01:00Z"
    changed["accepted_execution_claim"]["claim_ref"] = _claim_reference(
        changed["accepted_execution_claim"]
    )
    changed["accepted_execution_claim_ref"] = changed["accepted_execution_claim"]["claim_ref"]
    changed_plan = plan(StrixControlledRuntimeAdmissionV2.from_mapping(changed))
    assert original_plan.exec_broker_binding_digest != changed_plan.exec_broker_binding_digest
    environment = original["caido_relay_identity"]["manifest_environment"]
    assert {environment[key] for key in ("http_proxy", "https_proxy", "ALL_PROXY")} == {
        "http://127.0.0.1:48080"
    }
    assert original["filesystem_conformance"]["status"] == "blocked-unverified"


def test_noncanonical_duplicate_oversized_and_extra_bytes_fail_closed() -> None:
    row = admission_document()
    raw = canonical_json_bytes(row)
    for payload in (
        raw + b"\n",
        json.dumps(row).encode(),
        b'{"schema_version":1,"schema_version":2}',
        b"x" * (128 * 1024 + 1),
        raw.replace(
            b'"production_runtime_admitted":false', b'"production_runtime_admitted":NaN', 1
        ),
    ):
        with pytest.raises(StrixControlledRuntimeAdmissionError):
            StrixControlledRuntimeAdmissionV2(payload)
