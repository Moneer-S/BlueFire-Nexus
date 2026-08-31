from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_cancellation_validation as cancellation_validation_module
import bluefire.cross_platform_gate as gate_module
import bluefire.cross_platform_gate_validation as validation_module
import bluefire.cross_platform_source_intake_probe as source_intake_validation
import bluefire.product_gates as product_gates
import tools.run_cross_platform_source_intake_posix_probe as source_intake_posix_probe
from bluefire.approvals import execution_intent_id
from bluefire.cross_platform_artifact_validation import (
    CrossPlatformArtifactValidationError,
    validate_transport_recovery_report,
)
from bluefire.cross_platform_gate_validation import (
    ASSERTION_REPORTS,
    CHECK_NAMES,
    LINUX_DEPENDENCIES_UNAVAILABLE_REASON,
    LINUX_REPORT,
    LINUX_UNAVAILABLE_REASON,
    REPORT_PATHS,
    CrossPlatformGateValidationError,
    validate_linux_typed_unavailable_report,
)
from bluefire.cross_platform_linux import (
    SOURCE_INTAKE_POSIX_PROBE_COUNT,
    SOURCE_INTAKE_POSIX_PROBE_IDS,
    SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256,
    SOURCE_INTAKE_POSIX_PROBE_SCHEMA,
    LinuxDependenciesUnavailableError,
    LinuxJourneyError,
    _stage_wheelhouse,
    linux_dependencies_unavailable_report,
    linux_unavailable_report,
)
from bluefire.cross_platform_observation_validation import (
    CrossPlatformObservationValidationError,
    validate_observed_filesystem_evidence,
)
from bluefire.cross_platform_readiness import WSL_DISTRIBUTION_ID
from bluefire.cross_platform_run_validation import (
    CrossPlatformRunValidationError,
    _event_payloads,
    _nested_evidence,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_acceptance import load_release_contract
from bluefire.util import content_hash


def _wsl_facts(state: str) -> Mapping[str, Any]:
    configured, version = {
        "absent": (False, None),
        "incompatible": (True, "1"),
        "ready": (True, "2"),
    }[state]
    facts = {
        "provider": "wsl2",
        "probe_state": state,
        "configured": configured,
        "distribution_id": WSL_DISTRIBUTION_ID,
        "version": version,
    }
    return {**facts, "facts_digest": content_hash(facts)}


def _write_report(path: Path, value: Mapping[str, Any]) -> None:
    path.write_bytes(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )


def _patch_linux_probe(
    monkeypatch: pytest.MonkeyPatch,
    facts: Mapping[str, Any],
    *,
    wheelhouse_unavailable: bool = True,
) -> None:
    monkeypatch.setattr(validation_module, "_reprobe_wsl", lambda: facts)
    monkeypatch.setattr(
        validation_module,
        "linux_wheelhouse_unavailable",
        lambda _repository: wheelhouse_unavailable,
    )


def test_gate11_locked_contract_matches_authoritative_workflow() -> None:
    gate = next(item for item in load_release_contract().gates if item.gate_id == "GATE-11")

    assert {assertion.assertion_id: assertion.proof for assertion in gate.assertions} == {
        assertion_id: details[0]
        for assertion_id, details in gate_module._EXPECTED_ASSERTIONS.items()
    }
    assert tuple(assertion.assertion_id for assertion in gate.assertions) == tuple(
        assertion_id for assertion_id, _kind, _report in ASSERTION_REPORTS
    )
    assert set(details[1] for details in gate_module._EXPECTED_ASSERTIONS.values()) == CHECK_NAMES
    assert gate_module._EXPECTED_SUITE_TESTS == tuple(sorted(gate_module._EXPECTED_SUITE_TESTS))
    assert product_gates._WORKFLOWS["GATE-11"] is product_gates._gate_11_workflow
    probe_report = {
        "schema_version": SOURCE_INTAKE_POSIX_PROBE_SCHEMA,
        "platform": "linux",
        "passed": True,
        "probe_count": SOURCE_INTAKE_POSIX_PROBE_COUNT,
        "passed_probe_ids": list(SOURCE_INTAKE_POSIX_PROBE_IDS),
        "passed_probe_ids_sha256": SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256,
    }
    assert SOURCE_INTAKE_POSIX_PROBE_COUNT == 3
    assert content_hash(list(SOURCE_INTAKE_POSIX_PROBE_IDS)) == (
        SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256
    )
    assert source_intake_posix_probe.SOURCE_INTAKE_POSIX_PROBE_IDS == (
        SOURCE_INTAKE_POSIX_PROBE_IDS
    )
    assert source_intake_posix_probe.SOURCE_INTAKE_POSIX_PROBE_COUNT == (
        SOURCE_INTAKE_POSIX_PROBE_COUNT
    )
    assert source_intake_posix_probe.SOURCE_INTAKE_POSIX_PROBE_SCHEMA == (
        SOURCE_INTAKE_POSIX_PROBE_SCHEMA
    )
    assert (
        source_intake_posix_probe.SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256
        == SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256
    )
    assert (
        source_intake_validation.validate_probe(probe_report, CrossPlatformGateValidationError)
        == probe_report
    )
    with pytest.raises(CrossPlatformGateValidationError, match="probe inventory"):
        source_intake_validation.validate_probe(
            {**probe_report, "passed_probe_ids": probe_report["passed_probe_ids"][:-1]},
            CrossPlatformGateValidationError,
        )


def test_gate11_execute_approval_identity_is_pre_run_intent_bound() -> None:
    binding = {
        "state_digest": "sha256:" + "1" * 64,
        "plan_digest": "sha256:" + "2" * 64,
        "target_scope_digest": "sha256:" + "3" * 64,
        "profile_id": "sandbox-endpoint-deep-lab.v1",
        "maximum_tier": "restricted",
    }

    intent_id = execution_intent_id(binding)

    assert intent_id == "intent-" + content_hash(binding).removeprefix("sha256:")[:32]
    assert not intent_id.startswith("run-")
    assert execution_intent_id({**binding, "state_digest": "sha256:" + "4" * 64}) != intent_id


def test_gate11_event_stream_uses_canonical_event_type() -> None:
    events = [
        {"type": "planner.decision", "data": {"source": "obsolete"}},
        {"event_type": "planner.decision", "data": {"source": "canonical"}},
    ]

    assert _event_payloads(events, "planner.decision") == [{"source": "canonical"}]


def test_gate11_report_binding_uses_exact_linux_transfer_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    repository.mkdir()
    evidence.mkdir()
    windows_id = "run-20260831T000000Z-0123456789abcdef"
    linux_id = "run-20260831T000001Z-fedcba9876543210"
    windows_reference = {"run_id": windows_id, "path": f"runs/{windows_id}"}
    linux_reference = {"run_id": linux_id, "path": f"runs/{linux_id}"}
    windows_facts_transfer = {
        "run_id": windows_id,
        "step_id": "authorized_peer_handoff",
        "runner_task_id": "execute-" + "1" * 64,
        "source_process_id": 10,
        "destination_process_id": 11,
        "authenticated": True,
        "bytes": 12,
        "sha256": "2" * 64,
    }
    windows_report_transfer = {**windows_facts_transfer, "sha256": "sha256:" + "2" * 64}
    linux_facts = {
        "transfer": {
            "run_id": linux_id,
            "step_id": "internal_transport",
            "runner_task_id": "execute-" + "3" * 64,
            "authenticated": True,
            "bytes": 13,
            "sha256": "4" * 64,
        }
    }
    linux_receiver = {
        "process_id": 14,
        "transfer": {
            **linux_facts["transfer"],
            "sha256": "4" * 64,
            "destination_process_id": 14,
        },
    }
    windows_facts = {
        "inventory_digest": "sha256:" + "5" * 64,
        "transfer": windows_facts_transfer,
    }
    monkeypatch.setattr(validation_module, "_read_report", lambda *_args: {})
    monkeypatch.setattr(validation_module, "validate_windows_wheel", lambda _root: {})
    monkeypatch.setattr(
        validation_module, "validate_linux_repository_runner", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(validation_module, "_reprobe_wsl", lambda: {})
    monkeypatch.setattr(
        validation_module,
        "_windows",
        lambda *_args: (windows_reference, {"run_id": windows_id}),
    )
    monkeypatch.setattr(
        validation_module,
        "_linux",
        lambda *_args, **_kwargs: (linux_reference, {"run_id": linux_id}, linux_receiver),
    )
    monkeypatch.setattr(validation_module, "_cancellation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        validation_module, "_receiver", lambda _report: {"transfer": windows_report_transfer}
    )
    monkeypatch.setattr(
        validation_module, "validate_transport_recovery_report", lambda _value: None
    )
    monkeypatch.setattr(
        validation_module,
        "_readiness",
        lambda *_args, **_kwargs: {
            "health": {"inventory_digest": windows_facts["inventory_digest"]}
        },
    )
    monkeypatch.setattr(
        validation_module, "validate_macos_structural_contract", lambda *_args: None
    )
    monkeypatch.setattr(validation_module, "_classification", lambda _report: None)
    monkeypatch.setattr(
        validation_module,
        "validated_run_bundle",
        lambda _root, _parent, reference, **_kwargs: (reference, {}),
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_run",
        lambda *_args, **kwargs: windows_facts if kwargs["platform"] == "windows" else linux_facts,
    )
    now = datetime.now(timezone.utc)

    checks, bundles = validation_module.validate_persisted_cross_platform_gate(
        repository,
        evidence,
        expected_binding={},
        not_before=now,
        not_after=now,
    )

    assert checks == {name: True for name in CHECK_NAMES}
    assert bundles == (windows_reference, linux_reference)


def test_gate11_observation_uses_canonical_filesystem_collector_contract() -> None:
    digest = "a" * 64
    path = "fixtures/input.jsonl"
    scope = "runner-profile:sandbox-execute.v1"
    outer = EvidenceRecord.create(
        run_id="run-test",
        step_id="create_fixture",
        behavior_id="sandbox.fixture.create.v1",
        action_id="sandbox.fixture.create.v1",
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="sandbox-execute.v1",
        content={
            "output": {"artifact": path, "sha256": digest, "size": 7},
            "runner_evidence": [{"details": {"receipt_ids": ["b" * 64]}}],
        },
        target_scope_ref=scope,
    )
    observed = EvidenceRecord.create(
        run_id=outer.run_id,
        step_id=outer.step_id,
        behavior_id=outer.behavior_id,
        action_id=outer.action_id,
        provenance=EvidenceProvenance.OBSERVED,
        producer="collector.filesystem.sandbox.v1",
        runner_profile_id="sandbox-execute.v1",
        environment={
            "environment_type": "disposable",
            "collector_id": "collector.filesystem.sandbox.v1",
            "collector_version": "1.0.0",
        },
        parent_evidence_ids=(outer.evidence_id,),
        content={
            "artifact_type": "collector_observation",
            "collector_id": "collector.filesystem.sandbox.v1",
            "mechanism": "independent-file-handle-read",
            "modified_ns": 1,
            "observation_key": "filesystem/path-utf8-" + path.encode().hex(),
            "observation_kind": "filesystem",
            "observed_fields": {"path": path, "sha256": digest, "size_bytes": 7},
            "path": path,
            "sha256": digest,
            "size_bytes": 7,
        },
        limitations=("independent filesystem metadata and digest observation only",),
        target_scope_ref=scope,
    )
    step = {
        "step_id": observed.step_id,
        "behavior_id": observed.behavior_id,
        "action_id": observed.action_id,
        "evidence_ids": [outer.evidence_id, observed.evidence_id],
        "receipts": ["b" * 64],
    }

    validate_observed_filesystem_evidence(observed, outer, step)
    persistence_outer = replace(
        outer,
        action_id="sandbox.restricted.persistence-marker.v1",
        content={
            **outer.content,
            "output": {"artifact": path, "sha256": "sha256:" + digest},
        },
    )
    persistence_observed = replace(
        observed,
        action_id="sandbox.restricted.persistence-marker.v1",
        parent_evidence_ids=(persistence_outer.evidence_id,),
    )
    persistence_step = {
        **step,
        "action_id": "sandbox.restricted.persistence-marker.v1",
        "evidence_ids": [persistence_outer.evidence_id, persistence_observed.evidence_id],
    }
    validate_observed_filesystem_evidence(persistence_observed, persistence_outer, persistence_step)

    tampered = (
        replace(observed, producer="sandbox-observer.v1"),
        replace(observed, parent_evidence_ids=()),
        replace(observed, environment={"environment_type": "disposable"}),
        replace(
            observed,
            content={**observed.content, "observation_key": "filesystem/path-utf8-00"},
        ),
        replace(
            observed,
            content={**observed.content, "observed_fields": {"path": path}},
        ),
    )
    for record in tampered:
        with pytest.raises(CrossPlatformObservationValidationError):
            validate_observed_filesystem_evidence(record, outer, step)


def test_gate11_runner_evidence_uses_sealed_profile_digest() -> None:
    request_digest = "sha256:" + "1" * 64
    profile_digest = "sha256:" + "2" * 64
    decision_digest = "sha256:" + "3" * 64
    output = {"artifact": "fixtures/input.jsonl"}
    stream = {"text": "", "total_bytes": 0, "truncated": False}
    step = {
        "action_id": "sandbox.fixture.create.v1",
        "behavior_id": "sandbox.fixture.create.v1",
        "policy": {"policy_digest": decision_digest},
        "receipts": [],
        "request_hash": request_digest,
        "runner_status": "success",
    }
    outer = EvidenceRecord.create(
        run_id="run-test",
        step_id="create_fixture",
        behavior_id=step["behavior_id"],
        action_id=step["action_id"],
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        content={
            "request_hash": request_digest,
            "policy_digest": profile_digest,
            "runner_status": "success",
            "output": output,
            "stdout": stream,
            "stderr": stream,
        },
        target_scope_ref="runner-profile:sandbox-execute.v1",
    )
    nested = {
        "evidence_id": "",
        "kind": "executed",
        "producer": "bluefire-rust-runner",
        "request_hash": request_digest,
        "policy_digest": profile_digest,
        "action_id": step["action_id"],
        "behavior_id": step["behavior_id"],
        "runner_id": "bluefire-rust-runner.v1",
        "runner_profile_id": "sandbox-execute.v1",
        "platform": "linux",
        "recorded_at": "2026-08-31T00:00:00Z",
        "references": [],
        "details": {
            "status": "success",
            "output_hash": content_hash(output),
            "receipt_ids": [],
            "stdout_total_bytes": 0,
            "stderr_total_bytes": 0,
        },
    }
    nested["evidence_id"] = content_hash(nested)

    _nested_evidence(
        nested,
        outer=outer,
        step=step,
        platform="linux",
        profile_id="sandbox-execute.v1",
    )
    tampered = {**nested, "policy_digest": "sha256:" + "4" * 64, "evidence_id": ""}
    tampered["evidence_id"] = content_hash(tampered)
    with pytest.raises(CrossPlatformRunValidationError):
        _nested_evidence(
            tampered,
            outer=outer,
            step=step,
            platform="linux",
            profile_id="sandbox-execute.v1",
        )


def test_gate11_publishes_only_acceptance_bundle_reference_fields() -> None:
    run_id = "run-20260829T120000Z-0123456789abcdef"
    validated = {
        "run_id": run_id,
        "path": f"runs/{run_id}",
        "manifest_sha256": "sha256:" + "a" * 64,
    }

    assert validation_module._receipt_run_reference(validated) == {
        "run_id": run_id,
        "path": f"runs/{run_id}",
    }


@pytest.mark.parametrize("state", ["absent", "incompatible"])
def test_linux_distribution_unavailability_is_exact_and_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    facts = _wsl_facts(state)
    _patch_linux_probe(monkeypatch, facts)
    _write_report(tmp_path / LINUX_REPORT, linux_unavailable_report(facts))

    assert validate_linux_typed_unavailable_report(tmp_path) == LINUX_UNAVAILABLE_REASON


def test_linux_dependency_unavailability_is_exact_and_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _wsl_facts("ready")
    _patch_linux_probe(monkeypatch, facts)
    _write_report(tmp_path / LINUX_REPORT, linux_dependencies_unavailable_report(facts))

    assert (
        validate_linux_typed_unavailable_report(tmp_path) == LINUX_DEPENDENCIES_UNAVAILABLE_REASON
    )


def test_gate11_fails_with_the_exact_typed_linux_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "gate-11"
    evidence.mkdir()
    facts = _wsl_facts("absent")
    _patch_linux_probe(monkeypatch, facts)

    def blocked(_repository: Path, destination: Path) -> Mapping[str, Any]:
        _write_report(destination / LINUX_REPORT, linux_unavailable_report(facts))
        return {
            "schema_version": gate_module.HELPER_SCHEMA,
            "status": "failed",
            "blocking_check": "linux_container_execute",
            "reports": list(REPORT_PATHS),
            "run_count": 0,
            "exit_code": 1,
            "command": [
                "{python}",
                "tools/run_cross_platform_gate_journey.py",
                "{fixed-arguments}",
            ],
            "protocol_valid": True,
            "passed": False,
        }

    monkeypatch.setattr(gate_module, "_run_helper", blocked)
    gate = next(item for item in load_release_contract().gates if item.gate_id == "GATE-11")
    outcome = gate_module.run_gate_11(
        gate,
        evidence,
        repository_root=Path(__file__).resolve().parents[1],
    )

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason == LINUX_UNAVAILABLE_REASON


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":NaN}\n',
        b'{"schema_version":"bluefire.cross-platform-linux-execute.v2"}',
    ],
    ids=("nonfinite", "noncanonical"),
)
def test_linux_report_reader_rejects_nonfinite_or_noncanonical_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    _patch_linux_probe(monkeypatch, _wsl_facts("absent"))
    (tmp_path / LINUX_REPORT).write_bytes(payload)

    with pytest.raises(CrossPlatformGateValidationError):
        validate_linux_typed_unavailable_report(tmp_path)


def test_boolean_only_recovery_claim_is_not_evidence() -> None:
    with pytest.raises(CrossPlatformArtifactValidationError, match="recovery"):
        validate_transport_recovery_report(
            {
                "schema_version": "bluefire.cross-platform-transport-recovery.v1",
                "passed": True,
                "proof_kind": "dynamic",
                "platform": "windows",
                "transport": {"multiprocess": True},
                "recovery": {"result_identical": True},
            }
        )

    facts = _wsl_facts("ready")
    boundary = {
        **facts,
        "source_distribution_persistent": True,
        "execution_distribution_id": "BlueFire-Gate11-Run-0123456789abcdef",
        "execution_distribution_disposable": True,
        "execution_distribution_removed": True,
        "distribution_storage_removed": True,
        "distribution_absence_probes": [
            {"delay_ms": delay, "registered": False} for delay in (0, 100, 250)
        ],
        "workspace_disposable": True,
        "workspace_removed": True,
        "worker_process_exited": True,
        "worker_process_id": 101,
        "process_group_id": 101,
        "session_id": 101,
        "worker_start_time_ticks": 202,
        "survivor_probes": [
            {"delay_ms": 0, "running": False},
            {"delay_ms": 100, "running": False},
            {"delay_ms": 250, "running": False},
        ],
    }
    boolean_only = {
        "workspace_absent": True,
        "process_identities_absent": True,
    }
    for claimed in (None, boolean_only):
        candidate = dict(boundary)
        if claimed is not None:
            candidate["cleanup_verification"] = claimed
        with pytest.raises(CrossPlatformGateValidationError):
            validation_module._linux_boundary(candidate, fresh_wsl=facts, ready=True)


def _cancellation_report(
    binary_digest: str,
    *,
    request_character: str = "a",
    parent_pid: int = 101,
    descendant_pid: int = 202,
) -> dict[str, Any]:
    request_hash = "sha256:" + request_character * 64
    parent = {"process_id": parent_pid, "creation_time_100ns": 1001}
    descendant = {"process_id": descendant_pid, "creation_time_100ns": 2002}
    identity_material = (f"{parent_pid}:1001\n{descendant_pid}:2002\n").encode("ascii")
    return {
        "schema_version": "bluefire.cross-platform-process-cancellation.v2",
        "passed": True,
        "proof_kind": "dynamic",
        "platform": "windows",
        "action_id": "sandbox.execution.process-tree-cancellation-witness.v1",
        "behavior_id": "sandbox.execution.process-tree-cancellation-witness.v1",
        "profile_id": "gate11-windows-cancellation-witness.v1",
        "containment": "windows-job-object-kill-on-close",
        "runner_binary_sha256": binary_digest,
        "cancellation": {
            "task_id": "execute-" + request_character * 64,
            "request_hash": request_hash,
            "terminal_state": "cancelled",
            "parent_process_identity": parent,
            "descendant_process_identity": descendant,
            "cooperative_requested": True,
            "cooperative_acknowledged": True,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
            "control_state_removed": True,
            "parent_was_running": True,
            "descendant_was_running": True,
            "survivor_probe_count": 3,
            "survivor_probes": [
                {"delay_ms": delay, "parent_running": False, "descendant_running": False}
                for delay in (0, 100, 250)
            ],
            "no_survivors": True,
            "identity_material_sha256": "sha256:" + hashlib.sha256(identity_material).hexdigest(),
        },
    }


def test_cancellation_validator_reprobes_exact_process_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary_digest = "sha256:" + "b" * 64
    report = _cancellation_report(binary_digest)
    cancellation = report["cancellation"]
    parent = cancellation["parent_process_identity"]
    descendant = cancellation["descendant_process_identity"]
    runner = {"binary_sha256": binary_digest}
    observed: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []

    def absent(
        reported_parent: Mapping[str, Any],
        reported_descendant: Mapping[str, Any],
    ) -> bool:
        observed.append((reported_parent, reported_descendant))
        return True

    monkeypatch.setattr(cancellation_validation_module, "process_identities_absent", absent)
    with pytest.raises(CrossPlatformGateValidationError, match="fresh validator-owned"):
        validation_module._cancellation(report, runner)
    assert observed == [(parent, descendant)]

    monkeypatch.setattr(
        cancellation_validation_module,
        "process_identities_absent",
        lambda *_args: False,
    )
    with pytest.raises(CrossPlatformGateValidationError, match="cancellation"):
        validation_module._cancellation(report, runner)


@pytest.mark.skipif(os.name != "nt", reason="the packaged cancellation witness is Windows-only")
def test_fresh_cancellation_validator_executes_exact_wheel_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = Path(__file__).resolve().parents[1]
    binary = (repository / "bluefire" / "native" / "bluefire-runner.exe").read_bytes()
    binary_digest = "sha256:" + hashlib.sha256(binary).hexdigest()
    binary_member = "bluefire_nexus-0.1.0.data/purelib/bluefire/native/bluefire-runner.exe"
    package = tmp_path / "evidence" / "package"
    package.mkdir(parents=True)
    wheel = package / "fresh-validator.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(binary_member, binary)
    wheel_bytes = wheel.read_bytes()
    runner = {
        "wheel_file": wheel.name,
        "wheel_sha256": "sha256:" + hashlib.sha256(wheel_bytes).hexdigest(),
        "binary_member": binary_member,
        "binary_sha256": binary_digest,
        "binary_size": len(binary),
    }
    target_report = _cancellation_report(
        binary_digest,
        parent_pid=2_000_000_001,
        descendant_pid=2_000_000_002,
    )
    trusted_temp = cancellation_validation_module.runtime_temp_parent()
    observed_temp_parents: list[Path] = []
    poisoned_temp = tmp_path / ("ambient-" + "x" * 80) / ("y" * 80)
    monkeypatch.setenv("TEMP", os.fspath(poisoned_temp))
    monkeypatch.setenv("TMP", os.fspath(poisoned_temp))

    def trusted_runtime_temp_parent() -> Path:
        observed_temp_parents.append(trusted_temp)
        return trusted_temp

    monkeypatch.setattr(
        cancellation_validation_module, "runtime_temp_parent", trusted_runtime_temp_parent
    )

    proof = cancellation_validation_module.run_fresh_cancellation_validation(
        repository,
        package.parent,
        runner,
        target_report,
    )

    cancellation_validation_module.validate_fresh_cancellation_proof(
        proof,
        expected_runner_digest=binary_digest,
        expected_report=target_report,
    )
    assert observed_temp_parents == [trusted_temp]
    assert not poisoned_temp.exists()
    unrelated_report = _cancellation_report(
        binary_digest,
        request_character="c",
        parent_pid=2_000_000_003,
        descendant_pid=2_000_000_004,
    )
    with pytest.raises(
        cancellation_validation_module.FreshCancellationValidationError,
        match="fresh validator-owned",
    ):
        cancellation_validation_module.validate_fresh_cancellation_proof(
            proof,
            expected_runner_digest=binary_digest,
            expected_report=unrelated_report,
        )


def test_invalid_committed_wheelhouse_lock_is_not_a_dependency_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    (repository / "bluefire" / "data").mkdir(parents=True)
    (repository / "bluefire" / "data" / "gate11_linux_wheelhouse.json").write_bytes(b"{}\n")
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.delenv("BLUEFIRE_GATE11_LINUX_WHEELHOUSE", raising=False)

    with pytest.raises(LinuxJourneyError, match="wheelhouse lock") as failure:
        _stage_wheelhouse(repository, staging)
    assert not isinstance(failure.value, LinuxDependenciesUnavailableError)


def test_gate11_new_production_modules_stay_within_the_locked_line_budget() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *sorted((root / "bluefire").glob("cross_platform*.py")),
        *sorted((root / "tools").glob("run_cross_platform*.py")),
    ]
    assert paths
    assert all(len(path.read_text(encoding="utf-8").splitlines()) <= 1_000 for path in paths)
