from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path
from typing import Any

import pytest

import bluefire.cloud_identity_manual_smoke as manual_smoke
import bluefire.cloud_identity_pack as cloud_pack
import tools.run_aws_identity_lab_smoke as smoke_cli
from bluefire.cloud_identity_pack import (
    APPROVAL_SCHEMA,
    EXECUTE_REQUEST_SCHEMA,
    MANUAL_CONFIRMATION,
    MANUAL_SMOKE_SCHEMA,
    PACK_ID,
    PROFILE_ID,
    PROFILE_SCHEMA,
    SIMULATE_REQUEST_SCHEMA,
    AwsCommandResult,
    AwsIdentityLabApproval,
    AwsIdentityLabPack,
    AwsIdentityLabProfile,
    AwsManualSmokeError,
    AwsManualSmokeRequest,
    CloudIdentityPackError,
    DeterministicAwsIdentityBackend,
    ExecuteRequest,
    InMemoryCloudCredentialVault,
    SimulateRequest,
    build_aws_identity_lab_smoke_commands,
    run_aws_identity_lab_smoke,
    scan_bundle_for_secret_material,
    validate_cloud_identity_run_bundle,
)
from bluefire.run_store import RunStore

ACCOUNT_ID = "123456789012"
REGION = "us-east-2"
ROLE_NAME = "BlueFireDisposableIdentityLab"


def _binding(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {
        "acceptance_id": "gate03-cloud-pack-test",
        "gate_id": "GATE-03",
        "contract_sha256": "sha256:" + "3" * 64,
        "repository_commit": "4" * 40,
        "repository_tree": "5" * 40,
        "release": "true",
    }
    environment = {
        "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
        "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
        "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
        "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
        "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
        "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
    }
    for field, name in environment.items():
        monkeypatch.setenv(name, values[field])
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        **values,
    }


def _lab() -> tuple[
    bytes,
    InMemoryCloudCredentialVault,
    AwsIdentityLabProfile,
    AwsIdentityLabApproval,
    DeterministicAwsIdentityBackend,
    AwsIdentityLabPack,
]:
    credential = secrets.token_bytes(48)
    vault = InMemoryCloudCredentialVault()
    handle = vault.enroll(credential)
    profile = AwsIdentityLabProfile(
        account_id=ACCOUNT_ID,
        region=REGION,
        role_name=ROLE_NAME,
        credential_handle=handle,
    )
    approval = AwsIdentityLabApproval(
        approval_id="approval-gate03-cloud",
        account_id=ACCOUNT_ID,
        role_name=ROLE_NAME,
    )
    backend = DeterministicAwsIdentityBackend(
        account_id=ACCOUNT_ID,
        role_name=ROLE_NAME,
    )
    pack = AwsIdentityLabPack(credentials=vault, backend=backend)
    return credential, vault, profile, approval, backend, pack


def test_profile_and_requests_are_strict_round_trippable_contracts() -> None:
    _credential, _vault, profile, approval, _backend, _pack = _lab()

    assert profile.profile_id == PROFILE_ID
    assert profile.pack_id == PACK_ID
    assert AwsIdentityLabProfile.from_mapping(profile.to_dict()) == profile
    assert AwsIdentityLabApproval.from_mapping(approval.to_dict()) == approval

    simulated = SimulateRequest.from_mapping(
        {
            "schema_version": SIMULATE_REQUEST_SCHEMA,
            "operation_id": "operation-simulate",
            "profile": profile.to_dict(),
            "approval": approval.to_dict(),
        }
    )
    executed = ExecuteRequest.from_mapping(
        {
            "schema_version": EXECUTE_REQUEST_SCHEMA,
            "operation_id": "operation-execute",
            "profile": profile.to_dict(),
            "approval": approval.to_dict(),
        }
    )
    assert simulated.profile == executed.profile == profile

    invalid = profile.to_dict() | {"unexpected": "refused"}
    with pytest.raises(CloudIdentityPackError, match="fields do not match"):
        AwsIdentityLabProfile.from_mapping(invalid)


def test_credential_bytes_are_only_recoverable_through_the_opaque_process_handle() -> None:
    credential = secrets.token_bytes(64)
    vault = InMemoryCloudCredentialVault()
    handle = vault.enroll(credential)

    assert handle.startswith("credential-")
    assert credential not in handle.encode("ascii")
    assert credential.hex() not in handle
    assert base64.b64encode(credential).decode("ascii") not in handle
    with vault.open(handle) as recovered:
        assert recovered.readonly
        assert bytes(recovered) == credential
    assert vault.revoke(handle) is True
    assert vault.contains(handle) is False
    with pytest.raises(CloudIdentityPackError, match="unavailable"):
        with vault.open(handle):
            pass


def test_simulate_and_execute_create_bound_canonical_bundles_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_binding = _binding(monkeypatch)
    credential, vault, profile, approval, backend, pack = _lab()
    store = RunStore(tmp_path / "runs")

    simulated = pack.simulate(
        SimulateRequest("operation-cloud-simulate", profile, approval),
        store,
    )
    assert vault.contains(profile.credential_handle)
    executed = pack.execute(
        ExecuteRequest("operation-cloud-execute", profile, approval),
        store,
    )

    assert simulated.acceptance_binding == expected_binding
    assert executed.acceptance_binding == expected_binding
    assert simulated.secret_scan.files_scanned == 9
    assert executed.secret_scan.files_scanned == 9
    assert simulated.credential_revoked is False
    assert executed.credential_revoked is True
    assert not vault.contains(profile.credential_handle)
    assert backend.is_clean()
    for receipt in (simulated, executed):
        assert store.validate_bundle(receipt.run_id)["valid"] is True
        assert receipt.bundle_path.parent == store.root
        assert receipt.bundle_hash.startswith("sha256:")

    simulated_validation = validate_cloud_identity_run_bundle(
        store,
        simulated.run_id,
        expected_mode="simulate",
        expected_acceptance_binding=expected_binding,
    )
    executed_validation = validate_cloud_identity_run_bundle(
        store,
        executed.run_id,
        expected_mode="execute",
        expected_acceptance_binding=expected_binding,
    )
    assert simulated_validation["cleanup_verified"] is True
    assert executed_validation["audit_verified"] is True

    for bundle in (simulated.bundle_path, executed.bundle_path):
        payload = b"".join(path.read_bytes() for path in sorted(bundle.iterdir()))
        assert credential not in payload
        assert credential.hex().encode("ascii") not in payload
        assert base64.b64encode(credential) not in payload


def test_simulate_fixture_and_mock_enumeration_are_deterministic(tmp_path: Path) -> None:
    _credential, _vault, profile, approval, _backend, pack = _lab()
    store = RunStore(tmp_path / "runs")

    first = pack.simulate(SimulateRequest("same-operation", profile, approval), store)
    second = pack.simulate(SimulateRequest("same-operation", profile, approval), store)

    first_records = store.read_json(first.run_id, "evidence.json")["records"]
    second_records = store.read_json(second.run_id, "evidence.json")["records"]
    assert first_records == second_records
    enumeration = first_records[0]["enumeration"]
    assert enumeration["role_arns"] == sorted(enumeration["role_arns"])
    assert profile.role_arn in enumeration["role_arns"]


def test_approval_mismatch_refuses_before_creating_a_run(tmp_path: Path) -> None:
    _credential, vault, profile, _approval, backend, pack = _lab()
    store = RunStore(tmp_path / "runs")
    wrong = AwsIdentityLabApproval(
        approval_id="approval-wrong-target",
        account_id="999999999999",
        role_name=ROLE_NAME,
    )

    with pytest.raises(CloudIdentityPackError, match="does not bind"):
        ExecuteRequest("operation-refused", profile, wrong)
    assert list(store.root.iterdir()) == []
    assert vault.contains(profile.credential_handle)
    assert backend.is_clean()


class _BrokenAuditBackend(DeterministicAwsIdentityBackend):
    def observe_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> bool:
        super().observe_control(profile, credential, tag_value=tag_value)
        raise RuntimeError("injected-after-action failure")


def test_execute_failure_still_revokes_control_and_credential(tmp_path: Path) -> None:
    credential = secrets.token_bytes(48)
    vault = InMemoryCloudCredentialVault()
    profile = AwsIdentityLabProfile(
        account_id=ACCOUNT_ID,
        region=REGION,
        role_name=ROLE_NAME,
        credential_handle=vault.enroll(credential),
    )
    approval = AwsIdentityLabApproval("approval-cleanup", ACCOUNT_ID, ROLE_NAME)
    backend = _BrokenAuditBackend(account_id=ACCOUNT_ID, role_name=ROLE_NAME)
    pack = AwsIdentityLabPack(credentials=vault, backend=backend)
    store = RunStore(tmp_path / "runs")

    with pytest.raises(CloudIdentityPackError, match="failed closed"):
        pack.execute(ExecuteRequest("operation-cleanup", profile, approval), store)

    assert backend.is_clean()
    assert vault.contains(profile.credential_handle) is False
    assert list(store.root.iterdir()) == []
    assert [event["event_name"] for event in backend.audit_events()] == [
        "ListRoles",
        "TagRole",
        "ListRoleTags",
        "UntagRole",
        "GetRoleCleanupState",
    ]


def test_bundle_integrity_and_exact_inventory_fail_closed_on_tampering(tmp_path: Path) -> None:
    _credential, _vault, profile, approval, _backend, pack = _lab()
    store = RunStore(tmp_path / "runs")
    receipt = pack.simulate(SimulateRequest("operation-tamper", profile, approval), store)

    (receipt.bundle_path / "evidence.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(CloudIdentityPackError, match="integrity"):
        validate_cloud_identity_run_bundle(store, receipt.run_id, expected_mode="simulate")

    _credential2, _vault2, profile2, approval2, _backend2, pack2 = _lab()
    second = pack2.simulate(
        SimulateRequest("operation-extra-file", profile2, approval2),
        store,
    )
    (second.bundle_path / "extra.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(CloudIdentityPackError, match="inventory is not canonical"):
        validate_cloud_identity_run_bundle(store, second.run_id, expected_mode="simulate")


@pytest.mark.parametrize("encoding", ["raw", "hex", "base64", "base64url"])
def test_whole_bundle_scan_detects_runtime_secret_encodings(
    tmp_path: Path,
    encoding: str,
) -> None:
    secret = secrets.token_bytes(40)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    if encoding == "raw":
        leaked = secret
    elif encoding == "hex":
        leaked = secret.hex().encode("ascii")
    elif encoding == "base64":
        leaked = base64.b64encode(secret)
    else:
        leaked = base64.urlsafe_b64encode(secret).rstrip(b"=")
    (bundle / "evidence.bin").write_bytes(b"prefix:" + leaked + b":suffix")

    with pytest.raises(CloudIdentityPackError, match="credential material"):
        scan_bundle_for_secret_material(bundle, (secret,))


def _manual_request(**overrides: Any) -> AwsManualSmokeRequest:
    values: dict[str, Any] = {
        "credential_profile": "bluefire-disposable-lab",
        "account_id": ACCOUNT_ID,
        "role_name": ROLE_NAME,
        "region": REGION,
        "approval_id": "approval-manual-smoke",
        "approved_account_id": ACCOUNT_ID,
        "approved_role_name": ROLE_NAME,
        "confirmation": MANUAL_CONFIRMATION,
        "timeout_seconds": 7,
    }
    values.update(overrides)
    return AwsManualSmokeRequest(**values)


class _AwsFixtureInvoker:
    def __init__(self, *, fail_operation: str | None = None) -> None:
        self.operations: list[str] = []
        self.tag_value: str | None = None
        self.fail_operation = fail_operation

    def __call__(self, command: cloud_pack.AwsSmokeCommand, timeout: int) -> AwsCommandResult:
        assert timeout == 7
        self.operations.append(command.operation)
        if command.operation == self.fail_operation:
            return AwsCommandResult(9, b"", b"bounded failure")
        if command.operation == "GetCallerIdentity":
            value: dict[str, Any] = {
                "Account": ACCOUNT_ID,
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/bluefire-operator",
            }
        elif command.operation == "GetRole":
            value = {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}"}}
        elif command.operation == "ListRoleTagsBefore":
            value = {"Tags": []}
        elif command.operation == "TagRole":
            raw = command.argv[command.argv.index("--tags") + 1]
            self.tag_value = raw.split(",Value=", maxsplit=1)[1]
            value = {}
        elif command.operation == "ListRoleTagsAfter":
            value = {"Tags": [{"Key": cloud_pack.CONTROL_TAG_KEY, "Value": self.tag_value}]}
        elif command.operation == "UntagRole":
            self.tag_value = None
            value = {}
        elif command.operation == "ListRoleTagsCleanup":
            value = {"Tags": []}
        elif command.operation == "LookupEvents":
            value = {"Events": [{"EventName": "TagRole"}, {"EventName": "UntagRole"}]}
        else:
            raise AssertionError(f"unexpected operation {command.operation}")
        return AwsCommandResult(0, json.dumps(value).encode("utf-8"))


def test_manual_smoke_contract_is_fixed_argv_profile_only_and_bounded() -> None:
    request = _manual_request()
    commands = build_aws_identity_lab_smoke_commands(request)

    assert [command.phase for command in commands] == [
        "enumeration",
        "enumeration",
        "enumeration",
        "action",
        "audit",
        "revocation",
        "audit",
        "audit",
    ]
    assert [command.operation for command in commands] == [
        "GetCallerIdentity",
        "GetRole",
        "ListRoleTagsBefore",
        "TagRole",
        "ListRoleTagsAfter",
        "UntagRole",
        "ListRoleTagsCleanup",
        "LookupEvents",
    ]
    for command in commands:
        assert command.argv[0] == "aws"
        assert command.argv[command.argv.index("--profile") + 1] == request.credential_profile
        assert "--access-key" not in command.argv
        assert "--secret-key" not in command.argv
        assert len(command.argv) <= 20
    source = Path(manual_smoke.__file__).read_text(encoding="utf-8")
    assert "shell=False" in source
    assert "AWS_SECRET_ACCESS_KEY" in source


def test_manual_smoke_happy_path_reports_only_reference_and_verified_phases() -> None:
    request = _manual_request()
    invoker = _AwsFixtureInvoker()

    report = run_aws_identity_lab_smoke(request, invoker=invoker)

    assert report["schema_version"] == MANUAL_SMOKE_SCHEMA
    assert report["passed"] is True
    assert report["credential_reference"] == "aws-profile://bluefire-disposable-lab"
    assert report["phases"] == ["enumeration", "action", "revocation", "audit"]
    assert report["cleanup_verified"] is True
    assert report["audit_verified"] is True
    assert invoker.tag_value is None
    assert invoker.operations[-3:] == ["UntagRole", "ListRoleTagsCleanup", "LookupEvents"]


def test_manual_smoke_failure_after_action_still_runs_revocation() -> None:
    invoker = _AwsFixtureInvoker(fail_operation="ListRoleTagsAfter")

    with pytest.raises(AwsManualSmokeError, match="failed closed"):
        run_aws_identity_lab_smoke(_manual_request(), invoker=invoker)

    assert invoker.operations[-2:] == ["UntagRole", "ListRoleTagsCleanup"]
    assert invoker.tag_value is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("approved_account_id", "999999999999", "does not bind"),
        ("approved_role_name", "DifferentRole", "does not bind"),
        ("confirmation", "NO", "not explicitly confirmed"),
        ("timeout_seconds", 31, "timeout is invalid"),
    ],
)
def test_manual_smoke_refuses_unbound_or_unconfirmed_requests(
    field: str,
    value: Any,
    message: str,
) -> None:
    with pytest.raises(AwsManualSmokeError, match=message):
        _manual_request(**{field: value})


def test_manual_cli_exposes_no_credential_value_arguments_and_refuses_bad_confirmation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser_actions = {action.dest for action in smoke_cli._parser()._actions}
    assert "credential_profile" in parser_actions
    assert {"access_key", "secret_key", "session_token"}.isdisjoint(parser_actions)

    exit_code = smoke_cli.main(
        [
            "--credential-profile",
            "bluefire-disposable-lab",
            "--account-id",
            ACCOUNT_ID,
            "--role-name",
            ROLE_NAME,
            "--region",
            REGION,
            "--approval-id",
            "approval-cli",
            "--approve-account-id",
            ACCOUNT_ID,
            "--approve-role-name",
            ROLE_NAME,
            "--confirm-action",
            "REFUSE",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "not explicitly confirmed" in captured.err


def test_contract_constants_remain_canonical() -> None:
    assert PROFILE_SCHEMA == "bluefire.aws-identity-lab-profile.v1"
    assert APPROVAL_SCHEMA == "bluefire.aws-identity-lab-approval.v1"
    assert PROFILE_ID == "aws-identity-lab.v1"
    assert PACK_ID == "bluefire.aws-identity-lab.v1"
