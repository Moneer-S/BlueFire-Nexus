from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from bluefire.engine_attempt_contract import AttemptRole, EngineAttemptBinding
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION
from bluefire.strix_adapter import StrixBuildIdentity
from bluefire.strix_engine_runtime import StrixRuntimeAdmission
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.strix_runtime_admission_resolver import (
    ControllerQualifiedStrixAdmissionResolver,
    ProtectedStrixQualificationManifestSource,
    StrixRuntimeAdmissionResolverError,
    StrixRuntimeAuthorityRecord,
)
from bluefire.strix_runtime_qualification import RUNTIME_QUALIFICATION_LIMITATIONS
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_owner_acl import apply_owner_private_acl_path

BLUEFIRE_REVISION = "1" * 40
ATTEMPT_ID = "engine-attempt-" + "a" * 32
EXPERIMENT_ID = "experiment-" + "b" * 32
RUN_ID = "run-20261104T120100Z-" + "c" * 16
ARTIFACT_KEY = "q" + "d" * 31
NOW = "2026-11-04T12:00:00Z"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def manifest() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.strix-runtime-admission.v1",
        "status": "qualified-installed-cli-startup-only",
        "bluefire_source_revision": BLUEFIRE_REVISION,
        "inputs": {
            "candidate_manifest_ref": digest("1"),
            "candidate_checksums_ref": digest("2"),
            "preparation_manifest_ref": digest("3"),
            "preparation_checksums_ref": digest("4"),
            "runtime_receipt_ref": digest("5"),
            "oci_inventory_ref": digest("9"),
            "transfer_bundle_ref": digest("a"),
            "threat_review_ref": digest("b"),
        },
        "runner": {
            "system": "Linux",
            "release": "6.11.0",
            "machine": "x86_64",
            "image_os": "ubuntu24",
            "image_version": "20261104.1",
        },
        "build_identity": {
            "engine": "strix",
            "package_version": "1.7.0",
            "source_revision": REVIEWED_SOURCE_REVISION,
            "source_tree_sha256": digest("6"),
            "package_sha256": digest("7"),
            "executable_sha256": digest("8"),
            "image_reference": (
                "ghcr.io/usestrix/strix-sandbox@"
                "sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
            ),
            "image_inventory_sha256": digest("9"),
            "prompt_upstream_sha256": f"sha256:{REVIEWED_PROMPT_SHA256}",
            "prompt_overlay_sha256": f"sha256:{OVERLAY_SHA256}",
            "prompt_patched_sha256": f"sha256:{PATCHED_PROMPT_SHA256}",
        },
        "probe": {
            "argv": ["--help"],
            "exit_code": 0,
            "stdout": {"bytes": 100, "sha256": digest("c")},
            "stderr": {"bytes": 0, "sha256": digest("d")},
            "elapsed_milliseconds": 100,
            "network_namespace": "isolated-empty",
            "process_namespace": "isolated",
            "mount_namespace": "isolated",
            "probe_uid": 65534,
            "probe_gid": 65534,
            "credential_environment": False,
            "help_tokens_verified": True,
            "runtime_unchanged": True,
            "owned_work_absent": True,
        },
        "execution": {
            "strix_imported": True,
            "strix_cli": True,
            "argv": ["--help"],
            "sidecar": False,
            "sandbox_container": False,
            "target": False,
            "model": False,
            "network": False,
        },
        "qualification": {
            "runtime_qualified": True,
            "production_runtime_admitted": False,
            "scope": "exact-installed-cli-startup-only",
            "reproducibility_proven": False,
            "containment_proven": False,
            "lifecycle_proven": False,
            "target_execution_proven": False,
            "model_execution_proven": False,
            "effectiveness_proven": False,
            "license_review_complete": False,
            "redistribution_authorized": False,
            "limitations": list(RUNTIME_QUALIFICATION_LIMITATIONS),
        },
    }


def write_manifest(root: Path, *, key: str = ARTIFACT_KEY) -> tuple[Path, bytes, str]:
    path = root / f"{key}.json"
    payload = canonical_json_bytes(manifest()) + b"\n"
    path.write_bytes(payload)
    if os.name == "posix":
        path.chmod(0o600)
    reference = "sha256:" + hashlib.sha256(payload).hexdigest()
    return path, payload, reference


class AuthoritySource:
    def __init__(self, current: StrixRuntimeAuthorityRecord) -> None:
        self.current = current
        self.reads = 0

    def read_current(self) -> StrixRuntimeAuthorityRecord:
        self.reads += 1
        return self.current


class AdmissionSource:
    def __init__(self, admission: StrixRuntimeAdmission | None) -> None:
        self.admission = admission
        self.calls: list[dict[str, str]] = []

    def reopen_exact(
        self,
        *,
        attempt_id: str,
        binding_digest: str,
        runtime_qualification_ref: str,
    ) -> StrixRuntimeAdmission | None:
        self.calls.append(
            {
                "attempt_id": attempt_id,
                "binding_digest": binding_digest,
                "runtime_qualification_ref": runtime_qualification_ref,
            }
        )
        return self.admission


@dataclass(slots=True)
class Case:
    root: Path
    artifact: Path
    payload: bytes
    manifest_ref: str
    build: StrixBuildIdentity
    binding: EngineAttemptBinding
    delegation: EngineCapabilityDelegation
    admission: StrixRuntimeAdmission
    authority: AuthoritySource
    admissions: AdmissionSource
    manifests: ProtectedStrixQualificationManifestSource
    resolver: ControllerQualifiedStrixAdmissionResolver


def make_case(tmp_path: Path) -> Case:
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    if os.name == "posix":
        root.chmod(0o700)
    artifact, payload, manifest_ref = write_manifest(root)
    if os.name == "nt":
        apply_owner_private_acl_path(root, directory=True)
        apply_owner_private_acl_path(artifact, directory=False)
    build_row = dict(manifest()["build_identity"])
    build_row.pop("engine")
    build = StrixBuildIdentity(**build_row)
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": ATTEMPT_ID,
            "run_id": RUN_ID,
            "role": AttemptRole.BASELINE.value,
            "objective_ref": digest("e"),
            "environment_ref": digest("f"),
            "target_snapshot_ref": digest("0"),
            "scope_ref": digest("1"),
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "engine_id": "strix",
            "engine_version": build.package_version,
            "engine_revision": build.source_revision,
            "engine_package_digest": build.package_sha256,
            "policy_overlay_digest": build.prompt_overlay_sha256,
            "model_provider": "provider.test",
            "model_id": "controlled-test-provider",
            "model_data_destination": "http://127.0.0.1:18443/v1",
            "model_authorization_ref": digest("2"),
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": "2026-11-04T12:01:00Z",
            "parent_attempt_id": None,
        }
    )
    delegation = EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "3" * 32,
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        parent_attempt_id=binding.parent_attempt_id,
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        target_snapshot_ref=binding.target_snapshot_ref,
        scope_ref=binding.scope_ref,
        scope_version=binding.scope_version,
        engine_id=binding.engine_id,
        engine_version=binding.engine_version,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        policy_overlay_digest=binding.policy_overlay_digest,
        model_authorization_ref=binding.model_authorization_ref,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_data_destination=binding.model_data_destination,
        network_policy_digest=digest("4"),
        custody_plan_digest=digest("5"),
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
        created_at=NOW,
        expires_at="2026-11-04T12:06:00Z",
    )
    marker = cast(Any, object())
    admission = StrixRuntimeAdmission(
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        runtime_qualification_ref=manifest_ref,
        runtime_qualified=True,
        build=build,
        scope=marker,
        gateway=marker,
        budgets=marker,
        limits=marker,
        workspace=marker,
        executable=tmp_path / "never-executed-strix",
        path_environment="/never/executed",
        control_root=tmp_path / "never-used-controller",
        network_plan=marker,
        network_snapshot=marker,
        network_verification=marker,
        custody_plan=marker,
        protected_roots=marker,
        containment=marker,
        custody=marker,
    )
    authority = AuthoritySource(
        StrixRuntimeAuthorityRecord(
            schema_version="bluefire.strix-runtime-authority.v1",
            generation=1,
            state="active",
            qualification_manifest_ref=manifest_ref,
            protected_artifact_key=ARTIFACT_KEY,
            installed_bluefire_revision=BLUEFIRE_REVISION,
            strix_build_digest=content_hash(build.to_dict()),
            threat_review_ref=digest("b"),
            recorded_at=NOW,
            revocation_reason=None,
        )
    )
    admissions = AdmissionSource(admission)
    manifests = ProtectedStrixQualificationManifestSource(root)
    resolver = ControllerQualifiedStrixAdmissionResolver(
        authority_source=authority,
        protected_manifest_source=manifests,
        persisted_admission_source=admissions,
        installed_bluefire_revision=BLUEFIRE_REVISION,
    )
    return Case(
        root=root,
        artifact=artifact,
        payload=payload,
        manifest_ref=manifest_ref,
        build=build,
        binding=binding,
        delegation=delegation,
        admission=admission,
        authority=authority,
        admissions=admissions,
        manifests=manifests,
        resolver=resolver,
    )


def test_valid_exact_case_returns_the_persisted_admission_without_recreation(
    tmp_path: Path,
) -> None:
    case = make_case(tmp_path)
    before = case.artifact.stat()

    resolved = case.resolver.resolve(case.binding, case.delegation)

    assert resolved is case.admission
    assert case.authority.reads == 1
    assert case.admissions.calls == [
        {
            "attempt_id": case.binding.attempt_id,
            "binding_digest": case.binding.binding_digest,
            "runtime_qualification_ref": case.manifest_ref,
        }
    ]
    after = case.artifact.stat()
    assert (after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("qualification_manifest_ref", digest("a"), "artifact is invalid"),
        ("installed_bluefire_revision", "2" * 40, "another BlueFire revision"),
        ("strix_build_digest", digest("a"), "differs from controller authority"),
        ("threat_review_ref", digest("a"), "differs from controller authority"),
    ],
)
def test_controller_anchor_mismatch_fails_closed(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    case = make_case(tmp_path)
    authority = case.authority.current.to_dict()
    authority[field] = value
    case.authority.current = StrixRuntimeAuthorityRecord.from_mapping(authority)

    with pytest.raises(StrixRuntimeAdmissionResolverError, match=message):
        case.resolver.resolve(case.binding, case.delegation)

    assert case.admissions.calls == []


def test_protected_root_substitution_is_rejected_even_with_identical_bytes(
    tmp_path: Path,
) -> None:
    case = make_case(tmp_path)
    displaced = tmp_path / "displaced"
    case.root.rename(displaced)
    case.root.mkdir(mode=0o700)
    if os.name == "posix":
        case.root.chmod(0o700)
    replacement = case.root / case.artifact.name
    replacement.write_bytes(case.payload)
    if os.name == "posix":
        replacement.chmod(0o600)

    with pytest.raises(StrixRuntimeAdmissionResolverError, match="root identity changed"):
        case.resolver.resolve(case.binding, case.delegation)

    assert case.admissions.calls == []


def test_symlinked_manifest_is_rejected(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(case.payload)
    if os.name == "posix":
        outside.chmod(0o600)
    case.artifact.unlink()
    try:
        case.artifact.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(StrixRuntimeAdmissionResolverError, match="private regular file"):
        case.resolver.resolve(case.binding, case.delegation)

    assert case.admissions.calls == []


def test_reparse_ancestor_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "protected" / "nested"
    root.mkdir(parents=True)
    original = Path.lstat
    selected = root.parent

    def reparse_for_selected(path: Path) -> Any:
        details = original(path)
        if path == selected:
            values = {
                name: getattr(details, name)
                for name in (
                    "st_mode",
                    "st_dev",
                    "st_ino",
                    "st_uid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            values["st_file_attributes"] = getattr(
                stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                0x400,
            )
            return SimpleNamespace(**values)
        return details

    monkeypatch.setattr(Path, "lstat", reparse_for_selected)

    with pytest.raises(StrixRuntimeAdmissionResolverError, match="unsafe ancestor"):
        ProtectedStrixQualificationManifestSource(root)


def test_hardlinked_manifest_is_rejected(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    alias = tmp_path / "qualification-alias.json"
    try:
        os.link(case.artifact, alias)
    except OSError as exc:
        pytest.skip(f"hardlink creation is unavailable: {exc}")
    if case.artifact.stat().st_nlink == 1:
        pytest.skip("filesystem does not report hardlink counts")

    with pytest.raises(StrixRuntimeAdmissionResolverError, match="private regular file"):
        case.resolver.resolve(case.binding, case.delegation)

    assert case.admissions.calls == []


def test_revoked_current_generation_overrides_stale_qualified_admission(
    tmp_path: Path,
) -> None:
    case = make_case(tmp_path)
    assert case.resolver.resolve(case.binding, case.delegation) is case.admission
    case.authority.current = replace(
        case.authority.current,
        generation=2,
        state="revoked",
        recorded_at="2026-11-04T12:02:00Z",
        revocation_reason="Threat review was withdrawn.",
    )

    revoked = case.resolver.resolve(case.binding, case.delegation)

    assert case.authority.reads == 2
    assert revoked is not case.admission
    assert revoked.runtime_qualified is False
    assert replace(revoked, runtime_qualified=True) == case.admission
    assert revoked.custody is case.admission.custody
    assert revoked.containment is case.admission.containment
    assert revoked.network_verification is case.admission.network_verification


def test_restart_reopens_exact_state_without_writes_or_runtime_effects(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    entries_before = sorted(path.name for path in case.root.iterdir())
    metadata_before = case.artifact.stat()
    restarted = ControllerQualifiedStrixAdmissionResolver(
        authority_source=case.authority,
        protected_manifest_source=ProtectedStrixQualificationManifestSource(case.root),
        persisted_admission_source=case.admissions,
        installed_bluefire_revision=BLUEFIRE_REVISION,
    )

    first = case.resolver.resolve(case.binding, case.delegation)
    second = restarted.resolve(case.binding, case.delegation)

    assert first is second is case.admission
    assert case.authority.reads == 2
    assert len(case.admissions.calls) == 2
    assert sorted(path.name for path in case.root.iterdir()) == entries_before
    metadata_after = case.artifact.stat()
    assert (
        metadata_after.st_size,
        metadata_after.st_mtime_ns,
        metadata_after.st_ctime_ns,
    ) == (
        metadata_before.st_size,
        metadata_before.st_mtime_ns,
        metadata_before.st_ctime_ns,
    )


def test_missing_persisted_admission_fails_without_recreation(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    case.admissions.admission = None

    with pytest.raises(StrixRuntimeAdmissionResolverError, match="admission is missing"):
        case.resolver.resolve(case.binding, case.delegation)

    assert len(case.admissions.calls) == 1


@pytest.mark.parametrize("mismatch", ["objective", "environment", "build", "reference"])
def test_persisted_admission_must_match_attempt_build_and_manifest(
    tmp_path: Path,
    mismatch: str,
) -> None:
    case = make_case(tmp_path)
    if mismatch == "objective":
        changed = replace(case.admission, objective_ref=digest("3"))
    elif mismatch == "environment":
        changed = replace(case.admission, environment_ref=digest("3"))
    elif mismatch == "build":
        changed = replace(
            case.admission,
            build=replace(case.build, package_sha256=digest("3")),
        )
    else:
        changed = replace(case.admission, runtime_qualification_ref=digest("3"))
    case.admissions.admission = changed

    with pytest.raises(
        StrixRuntimeAdmissionResolverError,
        match="differs from the exact attempt authority",
    ):
        case.resolver.resolve(case.binding, case.delegation)


def test_private_permissions_and_opaque_key_are_enforced(tmp_path: Path) -> None:
    case = make_case(tmp_path)
    with pytest.raises(StrixRuntimeAdmissionResolverError, match="artifact key is invalid"):
        case.manifests.load_exact(
            protected_artifact_key="../" + ARTIFACT_KEY,
            expected_ref=case.manifest_ref,
        )
    if os.name == "posix":
        case.artifact.chmod(0o640)
        with pytest.raises(StrixRuntimeAdmissionResolverError, match="controller-private"):
            case.resolver.resolve(case.binding, case.delegation)
