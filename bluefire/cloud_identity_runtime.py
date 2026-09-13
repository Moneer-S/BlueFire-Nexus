"""Deterministic mock execution and RunStore production wiring for the AWS lab."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .cloud_identity_contracts import (
    CONTROL_ACTION,
    CONTROL_TAG_KEY,
    MIN_CREDENTIAL_BYTES,
    PACK_ID,
    PROFILE_ID,
    REVOCATION_ACTION,
    RUN_RESULT_SCHEMA,
    AwsIdentityExecuteBackend,
    AwsIdentityLabApproval,
    AwsIdentityLabProfile,
    CloudEnumeration,
    CloudIdentityPackError,
    CloudIdentityRunReceipt,
    ExecuteRequest,
    InMemoryCloudCredentialVault,
    SecretScanReport,
    SimulateRequest,
    control_tag_value,
    require,
    safe_identifier,
)
from .cloud_identity_validation import scan_bundle_for_secret_material
from .run_store import RunStore


class DeterministicAwsIdentityBackend:
    """Authenticated local AWS IAM model with deterministic enumeration and audit."""

    def __init__(self, *, account_id: str, role_name: str) -> None:
        from .cloud_identity_contracts import ACCOUNT_RE, ROLE_RE

        require(bool(ACCOUNT_RE.fullmatch(account_id)), "mock AWS account id is invalid")
        require(bool(ROLE_RE.fullmatch(role_name)), "mock AWS role name is invalid")
        self._account_id = account_id
        self._role_name = role_name
        target = f"arn:aws:iam::{account_id}:role/{role_name}"
        observer = f"arn:aws:iam::{account_id}:role/BlueFireReadOnlyFixture"
        self._roles = tuple(sorted({target, observer}))
        self._tags: dict[str, dict[str, str]] = {role: {} for role in self._roles}
        self._events: list[dict[str, Any]] = []

    def _authorize(self, profile: AwsIdentityLabProfile, credential: memoryview) -> None:
        require(
            profile.account_id == self._account_id and profile.role_name == self._role_name,
            "mock AWS backend does not bind the requested lab target",
        )
        require(
            isinstance(credential, memoryview)
            and credential.readonly
            and len(credential) >= MIN_CREDENTIAL_BYTES,
            "mock AWS authentication failed",
        )

    def _record(self, phase: str, event_name: str, profile: AwsIdentityLabProfile) -> None:
        self._events.append(
            {
                "sequence": len(self._events) + 1,
                "phase": phase,
                "event_name": event_name,
                "account_id": profile.account_id,
                "role_arn": profile.role_arn,
            }
        )

    def enumerate(self, profile: AwsIdentityLabProfile, credential: memoryview) -> CloudEnumeration:
        self._authorize(profile, credential)
        self._record("enumeration", "ListRoles", profile)
        return CloudEnumeration(
            account_id=self._account_id,
            principal_arn=(
                f"arn:aws:sts::{self._account_id}:assumed-role/{self._role_name}/bluefire-local"
            ),
            role_arns=self._roles,
        )

    def apply_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> Mapping[str, Any]:
        self._authorize(profile, credential)
        safe_identifier(tag_value, "cloud control tag value")
        target = self._tags[profile.role_arn]
        require(CONTROL_TAG_KEY not in target, "cloud control tag already exists")
        target[CONTROL_TAG_KEY] = tag_value
        self._record("action", "TagRole", profile)
        return {
            "action": CONTROL_ACTION,
            "role_arn": profile.role_arn,
            "tag_key": CONTROL_TAG_KEY,
            "tag_value": tag_value,
            "changed": True,
        }

    def observe_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> bool:
        self._authorize(profile, credential)
        self._record("audit", "ListRoleTags", profile)
        return self._tags[profile.role_arn].get(CONTROL_TAG_KEY) == tag_value

    def revoke_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> Mapping[str, Any]:
        self._authorize(profile, credential)
        target = self._tags[profile.role_arn]
        require(
            target.get(CONTROL_TAG_KEY) == tag_value,
            "cloud control state changed before revocation",
        )
        del target[CONTROL_TAG_KEY]
        self._record("revocation", "UntagRole", profile)
        return {
            "action": REVOCATION_ACTION,
            "role_arn": profile.role_arn,
            "tag_key": CONTROL_TAG_KEY,
            "removed": True,
        }

    def observe_cleanup(self, profile: AwsIdentityLabProfile, credential: memoryview) -> bool:
        self._authorize(profile, credential)
        self._record("audit", "GetRoleCleanupState", profile)
        return CONTROL_TAG_KEY not in self._tags[profile.role_arn]

    def audit_events(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(dict(event) for event in self._events)

    def is_clean(self) -> bool:
        return all(CONTROL_TAG_KEY not in tags for tags in self._tags.values())


class AwsIdentityLabPack:
    """Typed Simulate and Execute implementation for the official AWS lab pack."""

    def __init__(
        self,
        *,
        credentials: InMemoryCloudCredentialVault,
        backend: AwsIdentityExecuteBackend,
    ) -> None:
        if not isinstance(credentials, InMemoryCloudCredentialVault):
            raise CloudIdentityPackError("cloud credential vault is unsupported")
        if not isinstance(backend, AwsIdentityExecuteBackend):
            raise CloudIdentityPackError("cloud Execute backend is unsupported")
        self._credentials = credentials
        self._backend = backend

    def simulate(self, request: SimulateRequest, store: RunStore) -> CloudIdentityRunReceipt:
        if not isinstance(request, SimulateRequest):
            raise CloudIdentityPackError("cloud Simulate request is invalid")
        request.approval.assert_binds(request.profile)
        require(
            self._credentials.contains(request.profile.credential_handle),
            "opaque credential handle is unavailable",
        )
        enumeration = _deterministic_simulation_enumeration(request.profile)
        tag_value = control_tag_value(request.operation_id)
        evidence = (
            {
                "phase": "enumeration",
                "interface": "Simulate",
                "fixture": "deterministic-local-aws.v1",
                "enumeration": enumeration.to_dict(),
            },
            {
                "phase": "action",
                "interface": "Simulate",
                "action": CONTROL_ACTION,
                "role_arn": request.profile.role_arn,
                "tag_key": CONTROL_TAG_KEY,
                "tag_value": tag_value,
                "effect": "predicted",
            },
            {
                "phase": "revocation",
                "interface": "Simulate",
                "action": REVOCATION_ACTION,
                "effect": "predicted-clean",
            },
            {
                "phase": "audit",
                "interface": "Simulate",
                "expected_events": ["ListRoles", "TagRole", "ListRoleTags", "UntagRole"],
                "verified": True,
            },
        )
        handle = _finalize_cloud_run(
            store,
            mode="simulate",
            operation_id=request.operation_id,
            profile=request.profile,
            approval=request.approval,
            evidence=evidence,
            cleanup_verified=True,
            audit_verified=True,
            credential_revoked=False,
        )
        with self._credentials.open(request.profile.credential_handle) as credential:
            scan = scan_bundle_for_secret_material(handle.path, (credential,))
        return _receipt(
            store,
            handle.run_id,
            mode="simulate",
            cleanup_verified=True,
            audit_verified=True,
            credential_revoked=False,
            secret_scan=scan,
        )

    def execute(self, request: ExecuteRequest, store: RunStore) -> CloudIdentityRunReceipt:
        if not isinstance(request, ExecuteRequest):
            raise CloudIdentityPackError("cloud Execute request is invalid")
        request.approval.assert_binds(request.profile)
        tag_value = control_tag_value(request.operation_id)
        enumeration: CloudEnumeration | None = None
        action: Mapping[str, Any] | None = None
        revocation: Mapping[str, Any] | None = None
        scan: SecretScanReport | None = None
        bundle_run_id: str | None = None
        action_applied = False
        cleanup_verified = False
        audit_verified = False
        primary_error: BaseException | None = None
        credential_revoked = False

        try:
            with self._credentials.open(request.profile.credential_handle) as credential:
                try:
                    enumeration = self._backend.enumerate(request.profile, credential)
                    _validate_enumeration(enumeration, request.profile)
                    action = self._backend.apply_control(
                        request.profile,
                        credential,
                        tag_value=tag_value,
                    )
                    action_applied = True
                    require(
                        self._backend.observe_control(
                            request.profile,
                            credential,
                            tag_value=tag_value,
                        ),
                        "cloud control-plane action was not observed",
                    )
                except BaseException as exc:
                    primary_error = exc
                finally:
                    if action_applied:
                        try:
                            revocation = self._backend.revoke_control(
                                request.profile,
                                credential,
                                tag_value=tag_value,
                            )
                            cleanup_verified = self._backend.observe_cleanup(
                                request.profile, credential
                            )
                        except BaseException as cleanup_exc:
                            if primary_error is None:
                                primary_error = cleanup_exc
                if primary_error is not None:
                    raise CloudIdentityPackError(
                        "cloud Execute operation failed closed"
                    ) from primary_error
                require(cleanup_verified, "cloud identity cleanup was not observed")
                events = self._backend.audit_events()
                audit_verified = _validate_audit(events, request.profile)
                require(audit_verified, "cloud identity audit expectations were not met")
                if enumeration is None or action is None or revocation is None:
                    raise CloudIdentityPackError("cloud Execute evidence is incomplete")
                credential_revoked = self._credentials.revoke(request.profile.credential_handle)
                require(credential_revoked, "cloud credential handle was not revoked")

                evidence = (
                    {
                        "phase": "enumeration",
                        "interface": "Execute",
                        "backend": "deterministic-local-aws.v1",
                        "enumeration": enumeration.to_dict(),
                    },
                    {"phase": "action", "interface": "Execute", **dict(action)},
                    {"phase": "revocation", "interface": "Execute", **dict(revocation)},
                    {
                        "phase": "audit",
                        "interface": "Execute",
                        "events": [dict(event) for event in events],
                        "verified": True,
                    },
                )
                run = _finalize_cloud_run(
                    store,
                    mode="execute",
                    operation_id=request.operation_id,
                    profile=request.profile,
                    approval=request.approval,
                    evidence=evidence,
                    cleanup_verified=cleanup_verified,
                    audit_verified=audit_verified,
                    credential_revoked=True,
                )
                bundle_run_id = run.run_id
                scan = scan_bundle_for_secret_material(run.path, (credential,))
        finally:
            if not credential_revoked:
                credential_revoked = self._credentials.revoke(request.profile.credential_handle)

        require(
            bundle_run_id is not None and scan is not None, "cloud Execute produced no run bundle"
        )
        require(credential_revoked, "cloud credential handle was not revoked")
        return _receipt(
            store,
            bundle_run_id,
            mode="execute",
            cleanup_verified=cleanup_verified,
            audit_verified=audit_verified,
            credential_revoked=credential_revoked,
            secret_scan=scan,
        )


def _deterministic_simulation_enumeration(profile: AwsIdentityLabProfile) -> CloudEnumeration:
    roles = tuple(
        sorted(
            {
                profile.role_arn,
                f"arn:aws:iam::{profile.account_id}:role/BlueFireReadOnlyFixture",
            }
        )
    )
    return CloudEnumeration(
        account_id=profile.account_id,
        principal_arn=(
            f"arn:aws:sts::{profile.account_id}:assumed-role/{profile.role_name}/bluefire-simulate"
        ),
        role_arns=roles,
    )


def _validate_enumeration(enumeration: CloudEnumeration, profile: AwsIdentityLabProfile) -> None:
    require(
        isinstance(enumeration, CloudEnumeration)
        and enumeration.account_id == profile.account_id
        and profile.role_arn in enumeration.role_arns
        and tuple(sorted(set(enumeration.role_arns))) == enumeration.role_arns
        and enumeration.principal_arn.startswith(f"arn:aws:sts::{profile.account_id}:"),
        "cloud enumeration did not bind the approved account and role",
    )


def _validate_audit(events: Sequence[Mapping[str, Any]], profile: AwsIdentityLabProfile) -> bool:
    expected = (
        ("enumeration", "ListRoles"),
        ("action", "TagRole"),
        ("audit", "ListRoleTags"),
        ("revocation", "UntagRole"),
        ("audit", "GetRoleCleanupState"),
    )
    if len(events) != len(expected):
        return False
    for index, (event, expectation) in enumerate(zip(events, expected, strict=True), start=1):
        if (
            not isinstance(event, Mapping)
            or set(event) != {"sequence", "phase", "event_name", "account_id", "role_arn"}
            or event.get("sequence") != index
            or (event.get("phase"), event.get("event_name")) != expectation
            or event.get("account_id") != profile.account_id
            or event.get("role_arn") != profile.role_arn
        ):
            return False
    return True


def _finalize_cloud_run(
    store: RunStore,
    *,
    mode: str,
    operation_id: str,
    profile: AwsIdentityLabProfile,
    approval: AwsIdentityLabApproval,
    evidence: Sequence[Mapping[str, Any]],
    cleanup_verified: bool,
    audit_verified: bool,
    credential_revoked: bool,
):
    require(isinstance(store, RunStore), "cloud run store is invalid")
    require(mode in {"simulate", "execute"}, "cloud run mode is invalid")
    scenario = {
        "schema_version": "bluefire.aws-identity-lab-scenario.v1",
        "scenario_id": f"{PACK_ID}:{operation_id}",
        "pack_id": PACK_ID,
        "profile_id": PROFILE_ID,
        "mode": mode,
        "target": {"account_id": profile.account_id, "role_arn": profile.role_arn},
    }
    plan = {
        "schema_version": "bluefire.aws-identity-lab-plan.v1",
        "operation_id": operation_id,
        "mode": mode,
        "phases": ["enumeration", "action", "revocation", "audit"],
        "actions": ["iam:ListRoles", CONTROL_ACTION, "iam:ListRoleTags", REVOCATION_ACTION],
    }
    policy = {
        "schema_version": "bluefire.aws-identity-lab-policy.v1",
        "authorization": approval.to_dict(),
        "disposable_target_required": True,
        "cleanup_required": True,
        "raw_credentials_forbidden": True,
    }
    handle = store.create_run(
        scenario=scenario,
        plan=plan,
        policy=policy,
        profile=profile.to_dict(),
    )
    for record in evidence:
        phase = record.get("phase")
        require(isinstance(phase, str), "cloud run evidence phase is invalid")
        store.append_event(handle.run_id, f"cloud.{phase}", dict(record))
    manifest = store.finalize(
        handle.run_id,
        result={
            "schema_version": RUN_RESULT_SCHEMA,
            "status": "succeeded",
            "mode": mode,
            "pack_id": PACK_ID,
            "profile_id": PROFILE_ID,
            "operation_id": operation_id,
            "cleanup_verified": cleanup_verified,
            "audit_verified": audit_verified,
            "credential_revoked": credential_revoked,
        },
        evidence=evidence,
        detections=(),
    )
    require(
        isinstance(manifest.get("bundle_hash"), str),
        "cloud run bundle was not finalized",
    )
    return handle


def _receipt(
    store: RunStore,
    run_id: str,
    *,
    mode: str,
    cleanup_verified: bool,
    audit_verified: bool,
    credential_revoked: bool,
    secret_scan: SecretScanReport,
) -> CloudIdentityRunReceipt:
    validation = store.validate_bundle(run_id)
    require(validation.get("valid") is True, "cloud run bundle failed integrity validation")
    manifest = validation.get("manifest")
    if not isinstance(manifest, Mapping):
        raise CloudIdentityPackError("cloud run bundle manifest is invalid")
    result = store.read_json(run_id, "result.json")
    binding = result.get("acceptance_binding")
    require(binding is None or isinstance(binding, Mapping), "acceptance binding is invalid")
    return CloudIdentityRunReceipt(
        mode=mode,
        run_id=run_id,
        bundle_path=(store.root / run_id).resolve(),
        bundle_hash=str(manifest["bundle_hash"]),
        cleanup_verified=cleanup_verified,
        audit_verified=audit_verified,
        credential_revoked=credential_revoked,
        acceptance_binding=dict(binding) if isinstance(binding, Mapping) else None,
        secret_scan=secret_scan,
    )


__all__ = ["AwsIdentityLabPack", "DeterministicAwsIdentityBackend"]
