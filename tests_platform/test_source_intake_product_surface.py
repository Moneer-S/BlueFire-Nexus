from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from typing import Any

import pytest

import bluefire.cli as cli
import bluefire.service as service_module
from bluefire.api import APIError
from bluefire.runner_contracts import current_platform
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.service import BlueFireService
from bluefire.source_intake import SourceIntakeError
from bluefire.source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    INTAKE_ID,
    KEY_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    LICENSE_REFERENCE,
    LICENSE_SHA256,
    LICENSE_SIZE_BYTES,
    PACKAGE_ID,
    PACKAGE_VERSION,
    PUBLISHER_ID,
    REQUIRED_NOTICE,
    REVIEWED_OPCODE,
    SOURCE_SHA256,
    validate_gate09_intake_envelope,
)
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]
PROFILE_ID = "sandbox-windows-source-intake.v1"
OPERATOR_ID = "local-source-reviewer"


class SimulatedHardStop(BaseException):
    """Model abrupt process loss without running ordinary exception cleanup."""


class SurfaceInventoryRunner:
    def inventory(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "runner_id": "bluefire-source-intake-test-runner.v1",
            "runner_version": "test-1.0.0",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "platform": current_platform(),
            "actions": [
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": REVIEWED_OPCODE,
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[REVIEWED_OPCODE],
                    "readiness": "ready",
                }
            ],
        }


def _surface_request(destination_id: str) -> dict[str, str]:
    return {
        "destination_id": destination_id,
        "runner_profile_id": PROFILE_ID,
        "operator_id": OPERATOR_ID,
    }


def test_reviewed_opcode_is_enabled_only_by_windows_profiles(
    service: BlueFireService,
) -> None:
    profiles = [
        profile
        for profile in service.config.runner_profiles
        if REVIEWED_OPCODE in profile.enabled_actions
    ]

    assert [profile.id for profile in profiles] == [PROFILE_ID]
    assert profiles[0].platforms == ("windows",)


def test_new_destination_is_removed_when_private_pinning_fails(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_id = "private-pin-failure"
    original_enter = service_module._PinnedDirectory.__enter__

    def fail_destination_private_pin(
        directory: service_module._PinnedDirectory,
    ) -> service_module._PinnedDirectory:
        if directory.path.name == destination_id and directory.private:
            raise service_module.RunnerTrustError("injected private pin failure")
        return original_enter(directory)

    monkeypatch.setattr(
        service_module._PinnedDirectory,
        "__enter__",
        fail_destination_private_pin,
    )

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(_surface_request(destination_id))

    assert raised.value.code == "source_intake_destination_unsafe"
    assert not (service.store.root / "source-intakes" / destination_id).exists()


def _service_for_state(state_root: Path) -> BlueFireService:
    sandbox = state_root.parent / f"{state_root.name}-sandbox"
    sandbox.mkdir(exist_ok=True)
    runner = SurfaceInventoryRunner()
    return BlueFireService(
        project_root=ROOT,
        runs_dir=state_root,
        runner_factory=lambda _profile: (runner, sandbox),
    )


@pytest.fixture
def service(tmp_path: Path):
    instance = _service_for_state(tmp_path / "product-state")
    try:
        yield instance
    finally:
        instance.close()


def test_service_performs_reviewed_intake_in_caller_namespace(
    service: BlueFireService,
) -> None:
    destination_id = "operator-review-20260829"
    assert BEHAVIOR_ID not in service.registry.behavior_ids
    assert ACTION_ID not in service.registry.action_ids

    response = service.intake_reviewed_t1082(_surface_request(destination_id))

    envelope = validate_gate09_intake_envelope(response["envelope"])
    artifact = response["artifact"]
    artifact_path = service.store.root.joinpath(*artifact["state_ref"].split("/"))
    assert response["schema_version"] == "bluefire.reviewed-source-intake-result.v1"
    assert response["destination_id"] == destination_id
    assert artifact_path == (
        service.store.root / "source-intakes" / destination_id / f"{INTAKE_ID}.json"
    )
    assert artifact_path.is_relative_to(service.store.root)
    assert artifact_path.read_bytes() == canonical_json_bytes(envelope)
    assert artifact == {
        "media_type": "application/vnd.bluefire.source-intake+json",
        "sha256": content_hash(envelope),
        "size_bytes": len(canonical_json_bytes(envelope)),
        "state_ref": f"source-intakes/{destination_id}/{INTAKE_ID}.json",
    }
    assert response["intake"] == {
        "intake_id": INTAKE_ID,
        "record_sha256": envelope["record_sha256"],
        "output_sha256": envelope["record"]["transformation_history"][0]["output_sha256"],
        "execution_material_imported": False,
    }
    assert envelope["record"]["source"]["sha256"] == SOURCE_SHA256
    assert response["license_review"] == {
        "license_id": LICENSE_ID,
        "reference_url": LICENSE_REFERENCE,
        "sha256": LICENSE_SHA256,
        "size_bytes": LICENSE_SIZE_BYTES,
        "required_notice": REQUIRED_NOTICE,
        "status": "verified_packaged_bytes",
    }
    receipt = response["operation_receipt"]
    receipt_path = service.store.root.joinpath(*receipt["state_ref"].split("/"))
    receipt_record = receipt["record"]
    assert receipt_path == (
        service.store.root
        / "source-intakes"
        / destination_id
        / "intake.mitre-t1082.v1.operation-receipt.json"
    )
    assert receipt_path.read_bytes() == canonical_json_bytes(receipt_record)
    assert receipt == {
        "media_type": ("application/vnd.bluefire.reviewed-source-intake-operation-receipt+json"),
        "sha256": content_hash(receipt_record),
        "size_bytes": len(canonical_json_bytes(receipt_record)),
        "state_ref": (
            f"source-intakes/{destination_id}/intake.mitre-t1082.v1.operation-receipt.json"
        ),
        "record": receipt_record,
    }
    assert receipt_record == {
        "schema_version": "bluefire.reviewed-source-intake-operation-receipt.v1",
        "destination_id": destination_id,
        "operator_id": OPERATOR_ID,
        "runner_profile_id": PROFILE_ID,
        "intake": {
            "intake_id": INTAKE_ID,
            "record_sha256": envelope["record_sha256"],
            "output_sha256": envelope["record"]["transformation_history"][0]["output_sha256"],
        },
        "artifact": {
            "state_ref": artifact["state_ref"],
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
        },
        "package": {
            "package_id": PACKAGE_ID,
            "version": PACKAGE_VERSION,
            "package_digest": response["package_activation"]["package"]["package_digest"],
            "content_digest": response["package_activation"]["package"]["content_digest"],
        },
        "activation": {
            "operation": response["package_activation"]["operation"],
            "catalog_generation": response["package_activation"]["catalog_delta"][
                "generation_after"
            ],
            "catalog_digest": response["package_activation"]["catalog_delta"][
                "catalog_digest_after"
            ],
        },
        "completed_at": receipt_record["completed_at"],
    }
    assert receipt_record["completed_at"].endswith("Z")
    serialized = json.dumps(response, ensure_ascii=False)
    assert str(service.store.root) not in serialized
    activation = response["package_activation"]
    assert activation["schema_version"] == "bluefire.reviewed-source-intake-activation.v1"
    assert activation["operation"] == "installed_and_activated"
    assert activation["package"] == {
        "package_id": PACKAGE_ID,
        "version": PACKAGE_VERSION,
        "package_digest": activation["package"]["package_digest"],
        "content_digest": activation["package"]["content_digest"],
        "publisher_id": PUBLISHER_ID,
        "key_id": KEY_ID,
        "status": "active",
    }
    assert activation["catalog_delta"]["changed"] is True
    assert activation["catalog_delta"]["generation_after"] == (
        activation["catalog_delta"]["generation_before"] + 1
    )
    assert activation["catalog_delta"]["behavior_ids_added"] == [BEHAVIOR_ID]
    assert activation["catalog_delta"]["action_ids_added"] == [ACTION_ID]
    assert activation["availability"] == {
        "behavior_id": BEHAVIOR_ID,
        "behavior_available": True,
        "action_id": ACTION_ID,
        "action_available": True,
    }
    assert activation["runner"]["profile_id"] == PROFILE_ID
    assert activation["runner"]["activation_revalidated"] is True
    assert activation["persistence"] == {
        "installed_now": True,
        "activated_now": True,
        "durable_product_store": True,
        "signing_key_lifecycle": "generated_in_memory_and_not_persisted",
        "private_signing_key_persisted": False,
    }
    assert BEHAVIOR_ID in service.registry.behavior_ids
    assert ACTION_ID in service.registry.action_ids
    inventory = service.action_packages()
    assert [
        (item["package_id"], item["version"], item["status"]) for item in inventory["packages"]
    ] == [(PACKAGE_ID, PACKAGE_VERSION, "active")]


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({}, "source_intake_request_invalid"),
        (
            {**_surface_request("review"), "source": {"path": "arbitrary.json"}},
            "source_intake_request_invalid",
        ),
        (_surface_request("../escape"), "management_identifier_invalid"),
        (_surface_request("C:\\private\\escape"), "management_identifier_invalid"),
        (_surface_request("Uppercase"), "management_identifier_invalid"),
        (_surface_request("con"), "source_intake_destination_invalid"),
        (
            {**_surface_request("operator-review"), "operator_id": "\n"},
            "source_intake_operator_invalid",
        ),
    ],
)
def test_service_refuses_arbitrary_requests_and_destinations(
    service: BlueFireService,
    payload: dict[str, Any],
    code: str,
) -> None:
    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(payload)

    assert raised.value.status == 400
    assert raised.value.code == code
    assert not (service.store.root / "source-intakes").exists()


def test_service_refuses_empty_existing_destination_namespace(
    service: BlueFireService,
) -> None:
    intake_root = service.store.root / "source-intakes"
    intake_root.mkdir(mode=0o700)
    (intake_root / "existing-review").mkdir(mode=0o700)

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(_surface_request("existing-review"))

    assert raised.value.status == 422
    assert raised.value.code == "source_intake_rejected"
    assert list((intake_root / "existing-review").iterdir()) == []


def test_failed_intake_releases_exact_destination_for_retry(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service_module.perform_source_intake
    calls = 0

    def fail_once(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise SourceIntakeError("injected reviewed-source refusal")
        return original(*args, **kwargs)

    monkeypatch.setattr(service_module, "perform_source_intake", fail_once)
    request = _surface_request("retryable-review")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    destination = service.store.root / "source-intakes" / "retryable-review"
    assert raised.value.code == "source_intake_rejected"
    assert not destination.exists()

    response = service.intake_reviewed_t1082(request)
    assert response["destination_id"] == "retryable-review"
    assert destination.is_dir()


def test_failed_post_publication_validation_releases_artifact_for_retry(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service_module.source_intake_package.validate_gate09_intake_envelope
    calls = 0

    def fail_once(envelope: Any):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise service_module.source_intake_package.SourceIntakePackageError(
                "injected post-publication refusal"
            )
        return original(envelope)

    monkeypatch.setattr(
        service_module.source_intake_package,
        "validate_gate09_intake_envelope",
        fail_once,
    )
    request = _surface_request("post-publication-retry")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    destination = service.store.root / "source-intakes" / "post-publication-retry"
    assert raised.value.code == "source_intake_rejected"
    assert not destination.exists()

    response = service.intake_reviewed_t1082(request)
    assert response["destination_id"] == "post-publication-retry"
    assert destination.is_dir()


@pytest.mark.parametrize("failure", ["missing", "tampered"])
def test_service_refuses_missing_or_tampered_packaged_license(
    service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    real_root = service_module.files("bluefire.data")
    fake_license = tmp_path / f"{failure}-license.txt"
    if failure == "tampered":
        with (ROOT / "bluefire" / "data" / LICENSE_ASSET).open("rb") as source:
            payload = bytearray(source.read(LICENSE_SIZE_BYTES + 1))
        assert len(payload) == LICENSE_SIZE_BYTES
        payload[0] ^= 1
        fake_license.write_bytes(payload)

    class ResourceRoot:
        def joinpath(self, name: str):
            if name == LICENSE_ASSET:
                return fake_license
            return real_root.joinpath(name)

    monkeypatch.setattr(service_module, "files", lambda _package: ResourceRoot())
    destination_id = f"{failure}-license-review"

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(_surface_request(destination_id))

    assert raised.value.status == 422
    assert raised.value.code == "source_intake_rejected"
    assert not (service.store.root / "source-intakes" / destination_id).exists()
    assert str(tmp_path) not in json.dumps(raised.value.details)


def test_service_refuses_non_directory_product_intake_state(
    service: BlueFireService,
) -> None:
    (service.store.root / "source-intakes").write_text("occupied", encoding="utf-8")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(_surface_request("operator-review"))

    assert raised.value.status == 422
    assert raised.value.code == "source_intake_state_unavailable"


def test_absent_stage_read_does_not_create_or_retain_empty_directory(
    service: BlueFireService,
) -> None:
    stage_root = service.store.root / "source-intake-package-staging"
    assert not stage_root.exists()

    assert service_module._read_reviewed_t1082_package_stage(service.store.root) is None
    assert not stage_root.exists()

    stage_root.mkdir(mode=0o700)
    assert service_module._read_reviewed_t1082_package_stage(service.store.root) is None
    assert not stage_root.exists()


def test_valid_pretrust_stage_file_acl_failure_never_enrolls_its_signing_authority(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _surface_request("untrusted-preseed")

    def stop_before_trust(_request: dict[str, Any]) -> None:
        raise SimulatedHardStop("injected hard stop before publisher trust")

    monkeypatch.setattr(service, "trust_action_package_publisher", stop_before_trust)
    with pytest.raises(SimulatedHardStop):
        service.intake_reviewed_t1082(request)

    stage = (
        service.store.root
        / "source-intake-package-staging"
        / service_module._REVIEWED_T1082_STAGE_FILE
    )
    staged_bytes = stage.read_bytes()
    assert service.action_packages()["publishers"] == []
    monkeypatch.undo()
    original_read = service_module._PinnedDirectory.read_with_identity

    def refuse_stage_file(
        directory: service_module._PinnedDirectory,
        name: str,
        *,
        maximum: int,
        exclusive: bool = False,
    ) -> tuple[bytes, tuple[int, int], tuple[int, int, int, int, int]]:
        if name == service_module._REVIEWED_T1082_STAGE_FILE:
            raise service_module.RunnerTrustError("injected owner validation failure")
        return original_read(directory, name, maximum=maximum, exclusive=exclusive)

    monkeypatch.setattr(
        service_module._PinnedDirectory,
        "read_with_identity",
        refuse_stage_file,
    )

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    assert raised.value.code == "source_intake_rejected"
    assert service.action_packages()["publishers"] == []
    assert service.action_packages()["packages"] == []
    assert stage.read_bytes() == staged_bytes
    assert (service.store.root / "source-intakes" / "untrusted-preseed").exists()


@pytest.mark.parametrize("failure_point", ["partial_write", "fsync", "post_write"])
def test_stage_publication_failure_leaves_no_authoritative_file_and_retries(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    if failure_point == "partial_write":
        original = service_module._write_reviewed_state_payload

        def fail_partial(descriptor: int, payload: bytes, *, context: str) -> None:
            del context
            assert service_module.os.write(descriptor, payload[:17]) == 17
            raise OSError("injected partial stage write")

        monkeypatch.setattr(service_module, "_write_reviewed_state_payload", fail_partial)
        restore_name = "_write_reviewed_state_payload"
    elif failure_point == "fsync":
        original = service_module._fsync_reviewed_state_temporary

        def fail_fsync(_descriptor: int) -> None:
            raise OSError("injected stage fsync failure")

        monkeypatch.setattr(service_module, "_fsync_reviewed_state_temporary", fail_fsync)
        restore_name = "_fsync_reviewed_state_temporary"
    else:
        original = service_module._validate_reviewed_state_temporary

        def fail_post_write(**_kwargs: Any) -> None:
            raise OSError("injected post-write stage validation failure")

        monkeypatch.setattr(service_module, "_validate_reviewed_state_temporary", fail_post_write)
        restore_name = "_validate_reviewed_state_temporary"

    destination_id = f"stage-{failure_point.replace('_', '-')}"
    request = _surface_request(destination_id)
    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    stage_root = service.store.root / "source-intake-package-staging"
    assert raised.value.code == "source_intake_rejected"
    assert not (service.store.root / "source-intakes" / destination_id).exists()
    assert not stage_root.exists()
    assert service.action_packages()["publishers"] == []
    monkeypatch.setattr(service_module, restore_name, original)

    response = service.intake_reviewed_t1082(request)
    assert response["package_activation"]["operation"] == "installed_and_activated"
    assert response["operation_receipt"]["record"]["destination_id"] == destination_id


def test_tampered_receipt_shape_is_not_published_and_destination_retries(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service_module._build_reviewed_t1082_operation_receipt

    def tampered(**kwargs: Any) -> dict[str, Any]:
        record = dict(original(**kwargs))
        record["unexpected"] = True
        return record

    monkeypatch.setattr(service_module, "_build_reviewed_t1082_operation_receipt", tampered)
    request = _surface_request("receipt-shape-retry")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    destination = service.store.root / "source-intakes" / "receipt-shape-retry"
    assert raised.value.code == "source_intake_rejected"
    assert not destination.exists()
    assert service.action_packages()["packages"][0]["status"] == "active"
    monkeypatch.setattr(service_module, "_build_reviewed_t1082_operation_receipt", original)

    response = service.intake_reviewed_t1082(request)
    assert response["package_activation"]["operation"] == "already_active_revalidated"
    assert response["operation_receipt"]["record"]["destination_id"] == ("receipt-shape-retry")
    assert sorted(path.name for path in destination.iterdir()) == [
        "intake.mitre-t1082.v1.json",
        "intake.mitre-t1082.v1.operation-receipt.json",
    ]


def test_partial_receipt_write_leaves_no_destination_and_retries(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service.intake_reviewed_t1082(_surface_request("receipt-prerequisite"))
    original = service_module._write_reviewed_state_payload

    def fail_partial(descriptor: int, payload: bytes, *, context: str) -> None:
        assert context == "reviewed source operation receipt"
        assert service_module.os.write(descriptor, payload[:19]) == 19
        raise OSError("injected partial receipt write")

    monkeypatch.setattr(service_module, "_write_reviewed_state_payload", fail_partial)
    request = _surface_request("receipt-write-retry")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    destination = service.store.root / "source-intakes" / "receipt-write-retry"
    assert raised.value.code == "source_intake_rejected"
    assert not destination.exists()
    assert len(service.action_packages()["activation_events"]) == 1
    monkeypatch.setattr(service_module, "_write_reviewed_state_payload", original)

    response = service.intake_reviewed_t1082(request)
    assert response["package_activation"]["operation"] == "already_active_revalidated"
    assert response["operation_receipt"]["record"]["destination_id"] == ("receipt-write-retry")
    assert destination.is_dir()


def test_activation_failure_resumes_exact_installed_package_on_retry(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service.activate_action_package
    activation_calls = 0

    def fail_once(*args: Any, **kwargs: Any):
        nonlocal activation_calls
        activation_calls += 1
        if activation_calls == 1:
            raise APIError(
                409,
                "action_package_activation_refused",
                "Injected runner outage before activation publication.",
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "activate_action_package", fail_once)
    request = _surface_request("activation-retry")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    assert raised.value.code == "action_package_activation_refused"
    assert not (service.store.root / "source-intakes" / "activation-retry").exists()
    package = service.action_packages()["packages"]
    assert [(item["package_id"], item["status"]) for item in package] == [(PACKAGE_ID, "installed")]
    assert BEHAVIOR_ID not in service.registry.behavior_ids
    assert ACTION_ID not in service.registry.action_ids

    response = service.intake_reviewed_t1082(request)

    activation = response["package_activation"]
    assert activation["operation"] == "resumed_activation"
    assert activation["catalog_delta"]["changed"] is True
    assert activation["persistence"]["installed_now"] is False
    assert activation["persistence"]["activated_now"] is True
    assert activation["persistence"]["signing_key_lifecycle"] == (
        "existing_locally_trusted_package"
    )
    assert BEHAVIOR_ID in service.registry.behavior_ids
    assert ACTION_ID in service.registry.action_ids


def test_install_failure_resumes_staged_signature_without_new_trust(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service.install_action_package
    install_calls = 0

    def fail_once(*args: Any, **kwargs: Any):
        nonlocal install_calls
        install_calls += 1
        if install_calls == 1:
            raise APIError(
                422,
                "action_package_install_refused",
                "Injected durable-store interruption before package installation.",
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "install_action_package", fail_once)
    request = _surface_request("install-retry")

    with pytest.raises(APIError) as raised:
        service.intake_reviewed_t1082(request)

    assert raised.value.code == "action_package_install_refused"
    assert not (service.store.root / "source-intakes" / "install-retry").exists()
    interrupted_inventory = service.action_packages()
    assert interrupted_inventory["packages"] == []
    assert [
        (item["publisher_id"], item["key_id"], item["trust_state"])
        for item in interrupted_inventory["publishers"]
    ] == [(PUBLISHER_ID, KEY_ID, "trusted")]
    if os.name != "nt":
        stage_root = service.store.root / "source-intake-package-staging"
        stage = stage_root / service_module._REVIEWED_T1082_STAGE_FILE
        assert stat.S_IMODE(stage_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(stage.stat().st_mode) == 0o600

    response = service.intake_reviewed_t1082(request)

    activation = response["package_activation"]
    assert activation["operation"] == "installed_and_activated"
    assert activation["persistence"]["signing_key_lifecycle"] == (
        "resumed_recoverable_signed_envelope"
    )
    completed_inventory = service.action_packages()
    assert len(completed_inventory["packages"]) == 1
    assert len(completed_inventory["publishers"]) == 1
    assert len(completed_inventory["activation_events"]) == 1
    assert not (service.store.root / "source-intake-package-staging").exists()


def test_staged_signature_retry_requires_the_original_operator(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = service.install_action_package
    install_calls = 0

    def fail_once(*args: Any, **kwargs: Any):
        nonlocal install_calls
        install_calls += 1
        if install_calls == 1:
            raise APIError(
                422,
                "action_package_install_refused",
                "Injected interruption after publisher trust.",
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "install_action_package", fail_once)
    request = _surface_request("operator-bound-stage")

    with pytest.raises(APIError) as interrupted:
        service.intake_reviewed_t1082(request)

    assert interrupted.value.code == "action_package_install_refused"
    staged = service_module._read_reviewed_t1082_package_stage(service.store.root)
    assert staged is not None
    assert staged[0]["trust_actor"] == OPERATOR_ID
    different_operator = {**request, "operator_id": "different-local-reviewer"}

    with pytest.raises(APIError) as refused:
        service.intake_reviewed_t1082(different_operator)

    assert refused.value.status == 409
    assert refused.value.code == "source_intake_operator_conflict"
    assert install_calls == 1
    staged_after_refusal = service_module._read_reviewed_t1082_package_stage(service.store.root)
    assert staged_after_refusal is not None
    assert staged_after_refusal[1] == staged[1]
    assert service.action_packages()["packages"] == []

    completed = service.intake_reviewed_t1082(request)

    assert completed["package_activation"]["persistence"]["signing_key_lifecycle"] == (
        "resumed_recoverable_signed_envelope"
    )
    assert completed["operation_receipt"]["record"]["operator_id"] == OPERATOR_ID
    assert install_calls == 2
    assert not (service.store.root / "source-intake-package-staging").exists()


def test_already_active_package_is_revalidated_without_catalog_churn(
    service: BlueFireService,
) -> None:
    first = service.intake_reviewed_t1082(_surface_request("first-review"))
    first_inventory = service.action_packages()

    second = service.intake_reviewed_t1082(_surface_request("second-review"))
    second_inventory = service.action_packages()

    assert first["package_activation"]["operation"] == "installed_and_activated"
    activation = second["package_activation"]
    assert activation["operation"] == "already_active_revalidated"
    assert activation["catalog_delta"]["changed"] is False
    assert (
        activation["catalog_delta"]["generation_before"]
        == activation["catalog_delta"]["generation_after"]
    )
    assert (
        activation["catalog_delta"]["catalog_digest_before"]
        == activation["catalog_delta"]["catalog_digest_after"]
    )
    assert activation["catalog_delta"]["behavior_ids_added"] == []
    assert activation["catalog_delta"]["action_ids_added"] == []
    assert activation["persistence"]["installed_now"] is False
    assert activation["persistence"]["activated_now"] is False
    assert first["operation_receipt"]["state_ref"] != second["operation_receipt"]["state_ref"]
    assert first["operation_receipt"]["record"]["destination_id"] == "first-review"
    assert second["operation_receipt"]["record"]["destination_id"] == "second-review"
    assert second["operation_receipt"]["record"]["activation"]["operation"] == (
        "already_active_revalidated"
    )
    for result in (first, second):
        receipt_path = service.store.root.joinpath(
            *result["operation_receipt"]["state_ref"].split("/")
        )
        assert receipt_path.read_bytes() == canonical_json_bytes(
            result["operation_receipt"]["record"]
        )
    assert len(second_inventory["packages"]) == 1
    assert len(second_inventory["publishers"]) == 1
    assert len(second_inventory["activation_events"]) == 1
    assert first_inventory["catalog"] == second_inventory["catalog"]


def test_restart_resumes_an_artifact_only_hard_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "s"
    destination_id = "resume-a"
    request = _surface_request(destination_id)
    destination = state_root / "source-intakes" / destination_id
    first = _service_for_state(state_root)

    def hard_stop(*_args: Any, **_kwargs: Any) -> None:
        raise SimulatedHardStop("process stopped after artifact publication")

    monkeypatch.setattr(first, "_activate_reviewed_t1082_intake", hard_stop)
    try:
        with pytest.raises(SimulatedHardStop):
            first.intake_reviewed_t1082(request)
        assert sorted(path.name for path in destination.iterdir()) == [f"{INTAKE_ID}.json"]
        assert first.action_packages()["packages"] == []
    finally:
        first.close()

    restarted = _service_for_state(state_root)
    try:
        completed = restarted.intake_reviewed_t1082(request)

        assert completed["package_activation"]["operation"] == "installed_and_activated"
        assert completed["operation_receipt"]["record"]["destination_id"] == destination_id
        assert sorted(path.name for path in destination.iterdir()) == [
            f"{INTAKE_ID}.json",
            "intake.mitre-t1082.v1.operation-receipt.json",
        ]
        assert len(restarted.action_packages()["activation_events"]) == 1
    finally:
        restarted.close()


def test_restart_publishes_receipt_after_activation_hard_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "s"
    destination_id = "resume-b"
    request = _surface_request(destination_id)
    destination = state_root / "source-intakes" / destination_id
    first = _service_for_state(state_root)
    original_builder = service_module._build_reviewed_t1082_operation_receipt

    def hard_stop(**_kwargs: Any) -> None:
        raise SimulatedHardStop("process stopped after package activation")

    monkeypatch.setattr(
        service_module,
        "_build_reviewed_t1082_operation_receipt",
        hard_stop,
    )
    try:
        with pytest.raises(SimulatedHardStop):
            first.intake_reviewed_t1082(request)
        assert sorted(path.name for path in destination.iterdir()) == [f"{INTAKE_ID}.json"]
        assert len(first.action_packages()["activation_events"]) == 1
    finally:
        first.close()
    monkeypatch.setattr(
        service_module,
        "_build_reviewed_t1082_operation_receipt",
        original_builder,
    )

    restarted = _service_for_state(state_root)
    try:
        completed = restarted.intake_reviewed_t1082(request)

        assert completed["package_activation"]["operation"] == ("already_active_revalidated")
        assert completed["operation_receipt"]["record"]["activation"]["operation"] == (
            "already_active_revalidated"
        )
        assert len(restarted.action_packages()["activation_events"]) == 1
        assert sorted(path.name for path in destination.iterdir()) == [
            f"{INTAKE_ID}.json",
            "intake.mitre-t1082.v1.operation-receipt.json",
        ]
    finally:
        restarted.close()


def test_completed_destination_replays_receipt_without_activation_churn(
    service: BlueFireService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _surface_request("completed-replay")
    first = service.intake_reviewed_t1082(request)
    before = service.action_packages()

    def unexpected_activation(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("completed receipt replay dispatched activation")

    monkeypatch.setattr(service, "activate_action_package", unexpected_activation)
    second = service.intake_reviewed_t1082(request)
    after = service.action_packages()

    assert second["operation_receipt"] == first["operation_receipt"]
    assert second["package_activation"]["operation"] == (first["package_activation"]["operation"])
    assert after["activation_events"] == before["activation_events"]
    assert after["catalog"] == before["catalog"]


@pytest.mark.parametrize("tamper", ["artifact", "unexpected_entry"])
def test_restart_refuses_tampered_interrupted_destination_without_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    state_root = tmp_path / "s"
    destination_id = "tamper-a" if tamper == "artifact" else "tamper-u"
    request = _surface_request(destination_id)
    destination = state_root / "source-intakes" / destination_id
    first = _service_for_state(state_root)

    def hard_stop(*_args: Any, **_kwargs: Any) -> None:
        raise SimulatedHardStop("process stopped after artifact publication")

    monkeypatch.setattr(first, "_activate_reviewed_t1082_intake", hard_stop)
    try:
        with pytest.raises(SimulatedHardStop):
            first.intake_reviewed_t1082(request)
    finally:
        first.close()

    artifact = destination / f"{INTAKE_ID}.json"
    if tamper == "artifact":
        tampered_payload = bytearray(artifact.read_bytes())
        tampered_payload[-2] ^= 1
        artifact.write_bytes(tampered_payload)
    else:
        (destination / "unowned-state.json").write_bytes(b"{}")
    names_before = sorted(path.name for path in destination.iterdir())

    restarted = _service_for_state(state_root)
    try:
        with pytest.raises(APIError) as refused:
            restarted.intake_reviewed_t1082(request)

        assert refused.value.status == 422
        assert refused.value.code == "source_intake_rejected"
        assert restarted.action_packages()["packages"] == []
        assert sorted(path.name for path in destination.iterdir()) == names_before
    finally:
        restarted.close()


def test_concurrent_service_instances_serialize_the_same_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "s"
    request = _surface_request("race")
    first = _service_for_state(state_root)
    second = _service_for_state(state_root)
    entered_activation = threading.Event()
    allow_activation = threading.Event()
    second_done = threading.Event()
    original_activation = first._activate_reviewed_t1082_intake
    results: dict[str, Any] = {}
    failures: list[BaseException] = []

    def blocked_activation(*args: Any, **kwargs: Any):
        entered_activation.set()
        if not allow_activation.wait(10):
            raise AssertionError("timed out waiting to release the first activation")
        return original_activation(*args, **kwargs)

    def invoke(name: str, instance: BlueFireService) -> None:
        try:
            results[name] = instance.intake_reviewed_t1082(request)
        except BaseException as exc:  # pragma: no cover - asserted through failures
            failures.append(exc)
        finally:
            if name == "second":
                second_done.set()

    monkeypatch.setattr(first, "_activate_reviewed_t1082_intake", blocked_activation)
    first_thread = threading.Thread(target=invoke, args=("first", first), daemon=True)
    second_thread = threading.Thread(target=invoke, args=("second", second), daemon=True)
    try:
        first_thread.start()
        assert entered_activation.wait(5)
        second_thread.start()
        assert not second_done.wait(0.25)
        allow_activation.set()
        first_thread.join(10)
        second_thread.join(10)

        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        assert failures == []
        assert results["second"]["operation_receipt"] == results["first"]["operation_receipt"]
        assert results["second"]["package_activation"]["operation"] == ("installed_and_activated")
        inventory = second.action_packages()
        assert len(inventory["packages"]) == 1
        assert len(inventory["activation_events"]) == 1
        assert BEHAVIOR_ID in second.registry.behavior_ids
        assert ACTION_ID in second.registry.action_ids
    finally:
        allow_activation.set()
        first_thread.join(10)
        second_thread.join(10)
        first.close()
        second.close()


def test_activated_behavior_and_action_survive_service_restart(tmp_path: Path) -> None:
    state_root = tmp_path / "durable-product-state"
    first = _service_for_state(state_root)
    try:
        response = first.intake_reviewed_t1082(_surface_request("durable-review"))
        receipt_ref = response["operation_receipt"]["state_ref"]
        receipt_record = response["operation_receipt"]["record"]
        assert BEHAVIOR_ID in first.registry.behavior_ids
        assert ACTION_ID in first.registry.action_ids
    finally:
        first.close()

    restarted = _service_for_state(state_root)
    try:
        assert BEHAVIOR_ID in restarted.registry.behavior_ids
        assert ACTION_ID in restarted.registry.action_ids
        packages = restarted.action_packages()["packages"]
        assert [(item["package_id"], item["version"], item["status"]) for item in packages] == [
            (PACKAGE_ID, PACKAGE_VERSION, "active")
        ]
        receipt_path = restarted.store.root.joinpath(*receipt_ref.split("/"))
        assert receipt_path.read_bytes() == canonical_json_bytes(receipt_record)
    finally:
        restarted.close()


def test_cli_dispatches_exact_activation_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    class RecordingService:
        def intake_reviewed_t1082(self, request: dict[str, Any]) -> dict[str, Any]:
            calls.append(request)
            return {"schema_version": "bluefire.reviewed-source-intake-result.v1"}

    monkeypatch.setattr(cli, "_service", lambda _args: RecordingService())
    args = cli._parser().parse_args(
        [
            "research",
            "intake-t1082",
            "--destination-id",
            "operator-review",
            "--profile",
            PROFILE_ID,
            "--operator",
            OPERATOR_ID,
        ]
    )

    result = cli._execute(args)

    assert result == {"schema_version": "bluefire.reviewed-source-intake-result.v1"}
    assert calls == [_surface_request("operator-review")]
