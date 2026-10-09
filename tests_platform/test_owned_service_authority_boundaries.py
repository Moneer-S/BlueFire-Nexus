"""Approval and transport boundary witnesses; the runner is a no-effect software double."""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.owned_service_authority as authority
import bluefire.runner_transport as wire
from bluefire.approvals import (
    ApprovalError,
    execution_approval_binding,
    validate_claimed_approval,
)
from bluefire.config import AutonomyLevel, load_config
from bluefire.contracts import ContractError, ExecutionMode, load_scenario
from bluefire.owned_service_authority import (
    ADMISSION_SCHEMA,
    OwnedServiceAdmission,
    OwnedServiceAuthorityError,
    OwnedServiceGrant,
    OwnedServiceScope,
    mint_owned_service_grant,
    validate_owned_service_grant_for_request,
)
from bluefire.owned_service_orchestration import (
    mint_step_grant,
    service_grant_kwargs,
    validate_approval_scope_binding,
)
from bluefire.planner import DeterministicPlanner
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.registry import load_builtin_registry
from bluefire.runner_client import RunnerTransportError, execution_task_identity
from bluefire.runner_contracts import seal_manifest, seal_profile
from bluefire.runner_transport import AuthenticatedRunnerClient, AuthenticatedRunnerServer
from bluefire.runner_trust import create_local_enrollment, load_local_enrollment
from bluefire.secret_store import InMemorySecretProvider
from bluefire.tool_adapters.service_lifecycle import OwnedUserService
from bluefire.tool_adapters.service_operation_binding import ServiceOperationBinding
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_authenticated_runner_transport as transport_support

ROOT = Path(__file__).resolve().parents[1]
BINDING_FIELDS = (
    "state_digest",
    "plan_digest",
    "target_scope_digest",
    "profile_id",
    "maximum_tier",
)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _claim(store: ProductStore, binding: Mapping[str, str], *, expiry: str) -> dict[str, Any]:
    pending = store.create_approval_request(
        run_id="run-owned-service.v1",
        expires_at=expiry,
        **{key: binding[key] for key in BINDING_FIELDS},
    )
    expected = {f"expected_{key}": binding[key] for key in BINDING_FIELDS[:3]}
    approved = store.approve(
        pending["approval_id"], approved_by="synthetic-test-operator", **expected
    )
    store.consume_approval(approved["approval_id"], nonce=approved["nonce"], **expected)
    return dict(
        store.claim_consumed_approval(
            approved["approval_id"],
            nonce=approved["nonce"],
            approved_by="synthetic-test-operator",
            **expected,
            expected_profile_id=binding["profile_id"],
            expected_maximum_tier=binding["maximum_tier"],
        )
    )


@dataclass
class ClaimedCase:
    store: ProductStore
    scope: OwnedServiceScope
    binding: dict[str, str]
    claim: dict[str, Any]
    operation: ServiceOperationBinding
    manifest: dict[str, Any]
    profile: dict[str, Any]
    task_id: str
    now: datetime


@pytest.fixture
def claimed_case(tmp_path: Path) -> ClaimedCase:
    # Reuse the independently checked wire vector, but obtain a fresh real SQLite claim.
    vector = json.loads(
        (ROOT / "tests_platform/fixtures/owned_service_admission_v1.json").read_bytes()
    )
    original = vector["admission"]["grant"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scope_doc = deepcopy(original["scope"])
    scope_doc.update(
        created_at=_stamp(now - timedelta(minutes=1)),
        setup_expires_at=_stamp(now + timedelta(minutes=4)),
        cleanup_expires_at=_stamp(now + timedelta(minutes=30)),
    )
    scope = OwnedServiceScope.from_mapping(scope_doc)
    operation_doc = deepcopy(original["operation_binding"])
    operation_doc.update(
        identity=scope.identity_mapping(),
        identity_digest=OwnedUserService.from_mapping(scope.identity_mapping()).digest,
        reviewed_scope_digest=scope.digest,
    )
    operation = ServiceOperationBinding.from_mapping(operation_doc)
    binding = {key: original["claim"][key] for key in BINDING_FIELDS}
    binding["owned_service_scope_digest"] = scope.digest
    store = ProductStore(tmp_path / "approval.sqlite3")
    claim = _claim(store, binding, expiry=_stamp(now + timedelta(minutes=4)))
    manifest = deepcopy(vector["manifest"])
    manifest.update(requested_at=_stamp(now), expires_at=claim["expires_at"])
    manifest["approval"].update(
        approved_by=claim["approved_by"],
        approved_at=claim["approved_at"],
        expires_at=claim["expires_at"],
    )
    manifest = seal_manifest(manifest)
    task_id, _ = execution_task_identity(manifest, vector["profile"])
    return ClaimedCase(
        store,
        scope,
        binding,
        claim,
        operation,
        manifest,
        vector["profile"],
        task_id,
        datetime.now(timezone.utc),
    )


def _mint(case: ClaimedCase, **changes: Any) -> OwnedServiceGrant:
    arguments = {
        "scope": case.scope,
        "claimed_approval": case.claim,
        "approval_binding": case.binding,
        "operation_binding": case.operation,
        "run_id": case.manifest["run_id"],
        "manifest": case.manifest,
        "sealed_profile": case.profile,
        "task_id": case.task_id,
        "now": case.now,
    }
    arguments.update(changes)
    return mint_owned_service_grant(**arguments)


def _validate(case: ClaimedCase, grant: OwnedServiceGrant, **changes: Any) -> None:
    arguments = {
        "manifest": case.manifest,
        "profile": case.profile,
        "task_id": case.task_id,
        "now": case.now,
    }
    arguments.update(changes)
    validate_owned_service_grant_for_request(grant, **arguments)


def _cleanup(case: ClaimedCase, *, now: datetime | None = None) -> OwnedServiceGrant:
    operation = case.operation.to_dict()
    operation.update(operation="stop", operation_id="op-" + "9" * 32, journal_revision=3)
    return _mint(
        case, operation_binding=ServiceOperationBinding.from_mapping(operation), now=now or case.now
    )


def test_real_claim_is_single_use_and_grant_omits_approval_nonce(claimed_case: ClaimedCase) -> None:
    case = claimed_case
    grant = _mint(case)
    _validate(case, grant)
    reopened = ProductStore(case.store.path).get_approval_request(case.claim["approval_id"])
    assert reopened["status"] == "claimed"
    assert grant.to_dict()["claim"]["consumed_at"] == reopened["consumed_at"]
    assert grant.to_dict()["claim"]["approval_id"] == reopened["approval_id"]
    assert case.claim["nonce"].encode() not in grant.canonical_bytes()
    with pytest.raises(ProductStoreError, match="already claimed"):
        case.store.claim_consumed_approval(
            case.claim["approval_id"],
            nonce=case.claim["nonce"],
            approved_by=case.claim["approved_by"],
            **{f"expected_{key}": case.binding[key] for key in BINDING_FIELDS},
        )


def test_legacy_approval_cannot_acquire_service_scope(
    tmp_path: Path, claimed_case: ClaimedCase
) -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml")
    profile = next(
        p
        for p in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if p.id == "sandbox-execute.v1"
    )
    plan = DeterministicPlanner(registry).compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, autonomy=AutonomyLevel.OFF
    )
    inputs = dict(
        registry=registry,
        scenario=scenario,
        plan=plan.to_dict(),
        profile=profile,
        target_scope={"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]},
        autonomy=plan.autonomy,
        ai_provider=plan.ai_provider,
    )
    legacy = execution_approval_binding(**inputs)
    expanded = execution_approval_binding(
        **inputs, owned_service_scope_digest=claimed_case.scope.digest
    )
    claim = _claim(
        ProductStore(tmp_path / "legacy.sqlite3"),
        legacy,
        expiry=_stamp(claimed_case.now + timedelta(minutes=4)),
    )
    validate_claimed_approval(claim, binding=legacy, approved_by=claim["approved_by"])
    assert "owned_service_scope_digest" not in legacy
    assert expanded["state_digest"] != legacy["state_digest"]
    assert expanded["plan_digest"] == legacy["plan_digest"]
    with pytest.raises(ApprovalError, match="state_digest"):
        validate_claimed_approval(claim, binding=expanded, approved_by=claim["approved_by"])
    with pytest.raises(ContractError, match="exact owned-service scope"):
        validate_approval_scope_binding(legacy, claimed_case.scope)
    assert (
        mint_step_grant(
            None,
            approval_record=claim,
            approval_binding=legacy,
            operation_binding=None,
            run_id="run-legacy",
            step=plan.steps[0],
            manifest=claimed_case.manifest,
            sealed_profile=claimed_case.profile,
            task_id=claimed_case.task_id,
        )
        is None
    )
    assert service_grant_kwargs(object(), None, None) == {}


@pytest.mark.parametrize("field", (*BINDING_FIELDS, "owned_service_scope_digest"))
def test_claim_cannot_mint_for_changed_review_binding(
    claimed_case: ClaimedCase, field: str
) -> None:
    changed = dict(claimed_case.binding)
    changed[field] = {"profile_id": "different-profile.v1", "maximum_tier": "restricted"}.get(
        field, "sha256:" + "e" * 64
    )
    with pytest.raises(OwnedServiceAuthorityError):
        _mint(claimed_case, approval_binding=changed)
    assert (
        claimed_case.store.get_approval_request(claimed_case.claim["approval_id"])["status"]
        == "claimed"
    )


def test_changed_valid_scope_cannot_reuse_claim(claimed_case: ClaimedCase) -> None:
    document = claimed_case.scope.to_dict()
    document["limits"]["max_unit_bytes"] //= 2
    changed = OwnedServiceScope.from_mapping(document)
    assert changed.digest != claimed_case.scope.digest
    with pytest.raises(OwnedServiceAuthorityError):
        _mint(claimed_case, scope=changed)


@pytest.mark.parametrize(
    "section,path,value",
    [
        ("manifest", ("action_id",), "sandbox.fixture.create.v1"),
        ("manifest", ("step_id",), "different-step.v1"),
        ("manifest", ("params", "duration_seconds"), 11),
        ("manifest", ("params", "memory_max_bytes"), 128 * 1024 * 1024),
        ("manifest", ("target_scope", "filesystem"), ["elsewhere"]),
        ("manifest", ("limits", "timeout_ms"), 30001),
        ("profile", ("profile_id",), "different-profile.v1"),
        ("profile", ("sandbox_root",), "/tmp/another-reviewed-workspace"),
        ("profile", ("limits", "max_files"), 101),
    ],
)
def test_request_changes_cannot_reuse_claimed_grant(
    claimed_case: ClaimedCase, section: str, path: tuple[str, ...], value: Any
) -> None:
    case = claimed_case
    grant = _mint(case)
    changed = deepcopy(getattr(case, section))
    container = changed
    for key in path[:-1]:
        container = container[key]
    container[path[-1]] = value
    changed = seal_manifest(changed) if section == "manifest" else seal_profile(changed)
    with pytest.raises(OwnedServiceAuthorityError):
        _validate(case, grant, **{section: changed})


def test_setup_and_cleanup_have_distinct_windows_without_renewal(claimed_case: ClaimedCase) -> None:
    case = claimed_case
    after_setup = case.now + timedelta(minutes=6)
    setup, cleanup = _mint(case), _cleanup(case, now=after_setup)
    assert setup.to_dict()["scope_digest"] == cleanup.to_dict()["scope_digest"]
    assert setup.to_dict()["claim"] == cleanup.to_dict()["claim"]
    with pytest.raises(OwnedServiceAuthorityError, match="expired"):
        _validate(case, setup, now=after_setup)
    _validate(case, cleanup, now=after_setup)
    expiry = datetime.fromisoformat(
        case.scope.to_dict()["cleanup_expires_at"].replace("Z", "+00:00")
    )
    with pytest.raises(OwnedServiceAuthorityError, match="expired"):
        _validate(case, cleanup, now=expiry)
    # Recovery may inspect historical authority; it never renews the claimed row or dispatches.
    _validate(case, cleanup, now=expiry, check_expiry=False)
    assert (
        case.store.get_approval_request(case.claim["approval_id"])["expires_at"]
        == case.claim["expires_at"]
    )


@pytest.mark.parametrize("when", ["before_review", "at_setup_expiry", "after_setup_expiry"])
def test_cleanup_rejects_invalid_original_consumption(claimed_case: ClaimedCase, when: str) -> None:
    document = _cleanup(claimed_case).to_dict()
    scope = document["scope"]
    consumed = {
        "before_review": claimed_case.now - timedelta(minutes=2),
        "at_setup_expiry": datetime.fromisoformat(scope["setup_expires_at"].replace("Z", "+00:00")),
        "after_setup_expiry": claimed_case.now + timedelta(minutes=6),
    }[when]
    document["claim"].update(
        consumed_at=_stamp(consumed), approval_expires_at=scope["cleanup_expires_at"]
    )
    with pytest.raises(OwnedServiceAuthorityError, match="consumed inside"):
        OwnedServiceGrant.from_mapping(document)


@pytest.mark.parametrize("check_expiry", [True, False])
@pytest.mark.parametrize(
    "future", [timedelta(minutes=1), timedelta(microseconds=1)], ids=["minute", "microsecond"]
)
def test_future_consumption_is_refused_even_by_recovery(
    claimed_case: ClaimedCase, check_expiry: bool, future: timedelta
) -> None:
    document = _cleanup(claimed_case).to_dict()
    document["claim"]["consumed_at"] = (
        (claimed_case.now + future).isoformat().replace("+00:00", "Z")
    )
    grant = OwnedServiceGrant.from_mapping(document)
    with pytest.raises(OwnedServiceAuthorityError, match="consumed inside"):
        _validate(claimed_case, grant, check_expiry=check_expiry)


@pytest.mark.parametrize(
    "shape",
    [
        "unknown",
        "nested_unknown",
        "duplicate",
        "oversized",
        "array",
        "truncated",
        "invalid_utf8",
        "boolean_limit",
    ],
)
def test_grant_encoding_is_closed_and_bounded(claimed_case: ClaimedCase, shape: str) -> None:
    document = _mint(claimed_case).to_dict()
    if shape == "unknown":
        document["unreviewed"] = True
    elif shape == "nested_unknown":
        document["claim"]["permission"] = "expanded"
    elif shape == "boolean_limit":
        document["scope"]["limits"]["max_processes"] = True
    raw = canonical_json_bytes(document)
    raw = {
        "duplicate": b'{"scope_digest":"sha256:' + b"0" * 64 + b'",' + raw[1:],
        "oversized": b" " * (32 * 1024 + 1),
        "array": b"[]",
        "truncated": raw[:-1],
        "invalid_utf8": b"\xff",
    }.get(shape, raw)
    with pytest.raises(OwnedServiceAuthorityError):
        OwnedServiceGrant.from_json(raw)


class AdmissionRecordingRunner:
    """No service or subprocess is launched; records only the authenticated handoff."""

    owned_service_admission_protocol = ADMISSION_SCHEMA

    def __init__(self) -> None:
        self.admissions: list[OwnedServiceAdmission | None] = []

    def inventory(self) -> Mapping[str, Any]:
        return {**transport_support._inventory(), "platform": "linux"}

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
        owned_service_admission: OwnedServiceAdmission | None = None,
    ) -> Mapping[str, Any]:
        self.admissions.append(owned_service_admission)
        return transport_support._result(manifest, profile, call=len(self.admissions))


def test_authenticated_transport_preserves_grant_and_refuses_downgrade(
    tmp_path: Path, claimed_case: ClaimedCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = claimed_case
    grant = _mint(case)
    secrets = InMemorySecretProvider()
    enrollment_root = tmp_path / "transport-trust"
    create_local_enrollment(
        enrollment_root,
        runner_id=case.profile["runner_id"],
        client_id="test-service-client.v1",
        allowed_profile_ids=[case.profile["profile_id"]],
        secret_provider=secrets,
    )
    runner = AdmissionRecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root, runner, tmp_path / "transport.sqlite3", secret_provider=secrets
    ) as server:
        enrollment = load_local_enrollment(enrollment_root, secret_provider=secrets)
        client = transport_support._client(enrollment_root, server, secrets)
        args = dict(
            task_id=case.task_id,
            cancel_event=threading.Event(),
            durable_result_path=tmp_path / "client-result.json",
            owned_service_grant=grant,
        )
        first = client.execute_task(case.manifest, case.profile, **args)
        repeated = client.execute_task(case.manifest, case.profile, **args)
        assert first == repeated
        assert len(runner.admissions) == 1
        admission = runner.admissions[0]
        assert isinstance(admission, OwnedServiceAdmission)
        actual = admission.to_dict()
        assert actual["grant"] == grant.to_dict()
        assert actual["issuer"]["client_id"] == enrollment.client_id
        assert actual["issuer"]["peer_fingerprint"] == enrollment.metadata["client_fingerprint"]
        assert actual["issuer"]["server_instance_id"] == server.instance_id
        row = dict(server._execute_row(case.task_id))
        payload = json.loads(row["execute_payload_json"])
        assert payload["owned_service_grant"] == grant.to_dict()
        assert row["request_hash"] == content_hash(payload)
        assert server._stored_execute_payload(row)[2] == grant

        for change, expected_error in (
            ("drop", "request_invalid"),
            ("resign_change", "task_conflict"),
            ("unsigned_change", "authentication_failed"),
        ):
            altered = deepcopy(payload)
            if change == "drop":
                del altered["owned_service_grant"]
                # The legacy hash yields the SAME task identity: the action must forbid downgrade.
                assert wire._execute_task_id(content_hash(altered)) == case.task_id
            else:
                altered["owned_service_grant"]["claim"]["plan_digest"] = "sha256:" + "e" * 64
            unsigned = transport_support._unsigned_request(
                enrollment,
                operation="execute",
                task_id=case.task_id,
                payload=payload if change == "unsigned_change" else altered,
            )
            request = wire._sign_request(enrollment, unsigned)
            if change == "unsigned_change":
                request["payload"] = altered
                request["request_hash"] = content_hash(altered)
            response = transport_support._raw_exchange_enrollment(enrollment, server, request)
            with pytest.raises(wire.RunnerRemoteError) as error:
                AuthenticatedRunnerClient._validated_response(response, request, enrollment)
            assert error.value.code == expected_error
            assert len(runner.admissions) == 1
            with pytest.raises(wire.RunnerRemoteError) as recovery_error:
                client.recover(case.task_id, content_hash(altered))
            assert recovery_error.value.code == "task_identity_mismatch"
            # Copy a real persisted row; do not modify the live ledger or its historical evidence.
            damaged = {**row, "execute_payload_json": canonical_json_bytes(altered)}
            with pytest.raises(RunnerTransportError):
                server._stored_execute_payload(damaged)
            if change == "drop":
                damaged["request_hash"] = content_hash(altered)
                with pytest.raises(RunnerTransportError, match="grant is missing"):
                    server._stored_execute_payload(damaged)
        assert (
            dict(server._execute_row(case.task_id))["execute_payload_json"]
            == row["execute_payload_json"]
        )

        # A distinct, previously unattempted task must be refused before the fake dispatch edge
        # when the deterministic validation clock reaches the reviewed setup expiry.
        expired_manifest = deepcopy(case.manifest)
        expired_manifest["request_id"] = "request-expired-setup"
        expired_manifest = seal_manifest(expired_manifest)
        expired_task, _ = execution_task_identity(expired_manifest, case.profile)
        expired_grant = _mint(case, manifest=expired_manifest, task_id=expired_task)
        unsigned = transport_support._unsigned_request(
            enrollment,
            operation="execute",
            task_id=expired_task,
            payload={
                "manifest": expired_manifest,
                "profile": case.profile,
                "owned_service_grant": expired_grant.to_dict(),
            },
        )
        request = wire._sign_request(enrollment, unsigned)

        class AfterSetupClock(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> datetime:
                return (case.now + timedelta(minutes=6)).astimezone(tz)

        with monkeypatch.context() as clock_patch:
            clock_patch.setattr(authority, "datetime", AfterSetupClock)
            response = transport_support._raw_exchange_enrollment(enrollment, server, request)
        with pytest.raises(wire.RunnerRemoteError) as expired_error:
            AuthenticatedRunnerClient._validated_response(response, request, enrollment)
        assert expired_error.value.code == "request_invalid"
        assert len(runner.admissions) == 1
        assert dict(server._execute_row(expired_task))["effect_dispatched"] == 0
