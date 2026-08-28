from __future__ import annotations

import io
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire.registry import load_builtin_registry
from bluefire.util import content_hash
from tools import install_gate_journey_support as support
from tools import run_install_gate_journey as journey

_RUN_ID = "run-20300101T000000Z-0123456789abcdef"
_APPROVAL_ID = "approval-0123456789abcdef0123456789abcdef"
_REPLAY_APPROVAL_ID = "approval-fedcba9876543210fedcba9876543210"
_JOB_ID = "job-0123456789abcdef0123456789abcdef"
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_C = "sha256:" + "c" * 64
_ARTIFACT_DIGEST = "sha256:" + "d" * 64


def _binding() -> dict[str, str]:
    return {
        "state_digest": _DIGEST_A,
        "plan_digest": content_hash(_seeded_plan()),
        "target_scope_digest": content_hash(support.SCOPE),
        "profile_id": support.PROFILE_ID,
        "maximum_tier": "restricted",
    }


def _seeded_plan() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.plan.v1",
        "scenario_id": support.SCENARIO_ID,
        "mode": "execute",
        "autonomy": "off",
        "runner_profile_id": support.PROFILE_ID,
        "steps": [
            {
                "step_id": "create_persistence_canary",
                "behavior_id": "sandbox.restricted.persistence-marker.v1",
                "action_id": "sandbox.restricted.persistence-marker.v1",
                "parameters": {"label": "persistence_detection_canary"},
            },
            {
                "step_id": "cleanup_workspace",
                "behavior_id": "sandbox.cleanup.v1",
                "action_id": "sandbox.cleanup.v1",
                "parameters": {"verify_removal": True},
            },
        ],
    }


def _catalog() -> dict[str, Any]:
    registry = load_builtin_registry()
    return {
        "behaviors": [item.to_dict() for item in registry.behaviors],
        "actions": [item.to_dict() for item in registry.actions],
    }


def _envelope_step(step_id: str, behavior_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    catalog = _catalog()
    behavior = next(row for row in catalog["behaviors"] if row["id"] == behavior_id)
    action = next(row for row in catalog["actions"] if row["id"] == behavior_id)
    return {
        "step_id": step_id,
        "options": [
            {
                "behavior_id": behavior_id,
                "is_primary": True,
                "contract_digest": content_hash(behavior),
                "contract": behavior,
                "resolved_parameters": parameters,
                "actions": [
                    {
                        "action_id": behavior_id,
                        "contract_digest": content_hash(action),
                        "contract": action,
                    }
                ],
            }
        ],
    }


def _preflight() -> dict[str, Any]:
    plan = _seeded_plan()
    envelope_body = {
        "schema_version": "bluefire.approval-envelope.v1",
        "scenario_id": support.SCENARIO_ID,
        "steps": [
            _envelope_step(
                "create_persistence_canary",
                "sandbox.restricted.persistence-marker.v1",
                {"label": "persistence_detection_canary"},
            ),
            _envelope_step(
                "cleanup_workspace",
                "sandbox.cleanup.v1",
                {"verify_removal": True},
            ),
        ],
    }
    binding = _binding()
    return {
        "status": "approval_required",
        "ready": False,
        "runner_profile": support.PROFILE_ID,
        "scope": support.SCOPE,
        "autonomy": "off",
        "approval": "required",
        "collectors": [support.COLLECTOR_ID],
        "collector_binding": {
            "schema_version": "bluefire.collector-binding.v1",
            "collectors": [support.COLLECTOR_ID],
            "authority": "declared-per-run-observable-artifacts",
        },
        "plan": plan,
        "approval_binding": binding,
        "approval_envelope": {
            **envelope_body,
            "envelope_digest": content_hash(envelope_body),
        },
    }


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    sandbox = tmp_path / "BlueFire Nexus" / "runtime" / "sandbox"
    workspace = sandbox / ".bluefire-executions" / _APPROVAL_ID
    workspace.mkdir(parents=True)
    return sandbox, workspace


def _run() -> dict[str, Any]:
    executed_id = "evidence-executed"
    observed_id = "evidence-observed"
    cleanup_id = "evidence-cleanup"
    records = [
        {
            "evidence_id": executed_id,
            "run_id": _RUN_ID,
            "runner_profile_id": support.PROFILE_ID,
            "producer": "bluefire-rust-runner",
            "provenance": "executed",
            "step_id": "create_persistence_canary",
            "behavior_id": "sandbox.restricted.persistence-marker.v1",
            "action_id": "sandbox.restricted.persistence-marker.v1",
            "content": {
                "output": {
                    "artifact": support.CANARY_PATH,
                    "sha256": _ARTIFACT_DIGEST,
                }
            },
        },
        {
            "evidence_id": observed_id,
            "run_id": _RUN_ID,
            "runner_profile_id": support.PROFILE_ID,
            "producer": support.COLLECTOR_ID,
            "provenance": "observed",
            "step_id": "create_persistence_canary",
            "behavior_id": "sandbox.restricted.persistence-marker.v1",
            "action_id": "sandbox.restricted.persistence-marker.v1",
            "parent_evidence_ids": [executed_id],
            "content": {
                "artifact_type": "file_observation",
                "collector_id": support.COLLECTOR_ID,
                "path": support.CANARY_PATH,
                "sha256": _ARTIFACT_DIGEST[7:],
                "size_bytes": 151,
            },
        },
        {
            "evidence_id": cleanup_id,
            "run_id": _RUN_ID,
            "runner_profile_id": support.PROFILE_ID,
            "producer": "bluefire-rust-runner",
            "provenance": "executed",
            "step_id": "cleanup_workspace",
            "behavior_id": "sandbox.cleanup.v1",
            "action_id": "sandbox.cleanup.v1",
            "parent_evidence_ids": [executed_id, observed_id],
            "content": {
                "output": {
                    "verification_performed": True,
                    "removed_paths": [support.CANARY_PATH, "restricted"],
                    "verified_receipts": 1,
                    "retained_paths": [],
                    "errors": [],
                }
            },
        },
    ]
    return {
        "run_id": _RUN_ID,
        "status": "completed",
        "mode": "execute",
        "autonomy": "off",
        "scenario_id": support.SCENARIO_ID,
        "runner_profile_id": support.PROFILE_ID,
        "authorized_target_scope": support.SCOPE,
        "objective_reached": True,
        "plan": _seeded_plan(),
        "steps": [
            {
                "step_id": "create_persistence_canary",
                "behavior_id": "sandbox.restricted.persistence-marker.v1",
                "action_id": "sandbox.restricted.persistence-marker.v1",
                "status": "success",
                "evidence_ids": [executed_id, observed_id],
                "artifacts": {
                    "marker": {
                        "path": support.CANARY_PATH,
                        "sha256": _ARTIFACT_DIGEST,
                    }
                },
            },
            {
                "step_id": "cleanup_workspace",
                "behavior_id": "sandbox.cleanup.v1",
                "action_id": "sandbox.cleanup.v1",
                "status": "success",
                "evidence_ids": [cleanup_id],
            },
        ],
        "cleanup": {"attempted": True, "success": True, "outstanding_receipt_count": 0},
        "approval": {
            "approval_id": _APPROVAL_ID,
            **_binding(),
            "status": "claimed",
            "approved_by": "gate01-release-operator",
        },
        "replay": None,
        "evidence": {"records": records},
    }


def test_preflight_requires_canonical_digests_envelope_and_collector_binding() -> None:
    report = _preflight()
    binding, envelope_digest = support.validate_preflight(report, _catalog())

    assert binding == report["approval_binding"]
    assert envelope_digest == report["approval_envelope"]["envelope_digest"]

    tampered = deepcopy(report)
    tampered["collector_binding"]["authority"] = "implicit"
    with pytest.raises(support.SupportError, match="approval envelope is invalid"):
        support.validate_preflight(tampered, _catalog())

    tampered = deepcopy(report)
    tampered["approval_envelope"]["envelope_digest"] = _DIGEST_C
    with pytest.raises(support.SupportError, match="envelope digest is invalid"):
        support.validate_preflight(tampered, _catalog())

    tampered = deepcopy(report)
    tampered["plan"]["steps"][0]["action_id"] = "sandbox.cleanup.v1"
    tampered["approval_binding"]["plan_digest"] = content_hash(tampered["plan"])
    with pytest.raises(support.SupportError, match="approval envelope is invalid"):
        support.validate_preflight(tampered, _catalog())

    tampered_catalog = deepcopy(_catalog())
    behavior = next(
        row
        for row in tampered_catalog["behaviors"]
        if row["id"] == "sandbox.restricted.persistence-marker.v1"
    )
    behavior["title"] = "untrusted replacement"
    with pytest.raises(support.SupportError, match="approval envelope is invalid"):
        support.validate_preflight(report, tampered_catalog)


def test_job_snapshots_cross_bind_the_immutable_approval_pointer() -> None:
    snapshots = [
        {
            "job_id": _JOB_ID,
            "request": {"approval_request_id": _APPROVAL_ID},
            "progress": {
                **({"approval_request_id": _APPROVAL_ID} if index else {}),
                **({"approval_ref": _APPROVAL_ID} if index >= 2 else {}),
            },
        }
        for index in range(4)
    ]

    proof = support.validate_job_approval_pointers(
        snapshots, job_id=_JOB_ID, approval_id=_APPROVAL_ID
    )

    assert proof == {
        "job_id": _JOB_ID,
        "request_approval_id": _APPROVAL_ID,
        "progress_approval_ref": _APPROVAL_ID,
        "snapshot_count": 4,
        "cross_bound": True,
    }
    tampered = deepcopy(snapshots)
    tampered[2]["progress"]["approval_ref"] = _REPLAY_APPROVAL_ID
    with pytest.raises(support.SupportError, match="every durable job snapshot"):
        support.validate_job_approval_pointers(tampered, job_id=_JOB_ID, approval_id=_APPROVAL_ID)


def test_replay_requires_a_fresh_context_bound_state_digest() -> None:
    replay_binding = {**_binding(), "state_digest": _DIGEST_C}
    support.validate_fresh_replay_approval(
        {"approval": {"approval_id": _APPROVAL_ID}},
        {"approval": {"approval_id": _REPLAY_APPROVAL_ID}},
        {"approval_id": _APPROVAL_ID},
        {"approval_binding": replay_binding},
        source_approval_id=_APPROVAL_ID,
        source_binding=_binding(),
    )

    with pytest.raises(support.SupportError, match="fresh context-bound approval"):
        support.validate_fresh_replay_approval(
            {"approval": {"approval_id": _APPROVAL_ID}},
            {"approval": {"approval_id": _REPLAY_APPROVAL_ID}},
            {"approval_id": _APPROVAL_ID},
            {"approval_binding": _binding()},
            source_approval_id=_APPROVAL_ID,
            source_binding=_binding(),
        )


def test_run_requires_exact_observer_lineage_and_real_workspace_cleanup(tmp_path: Path) -> None:
    sandbox, workspace = _workspace(tmp_path)
    run = _run()

    summary = support.validate_run(
        run,
        sandbox_root=sandbox,
        approval_binding=_binding(),
        approved_by="gate01-release-operator",
        replay_of=None,
    )

    assert summary["residual_canary_absent"] is True
    assert summary["observation"]["parent_linked"] is True

    different_plan = deepcopy(run)
    different_plan["plan"]["unreviewed"] = True
    with pytest.raises(support.SupportError, match="reviewed approval binding"):
        support.validate_run(
            different_plan,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )

    wrong_step = deepcopy(run)
    wrong_step["steps"][0]["action_id"] = "sandbox.cleanup.v1"
    with pytest.raises(support.SupportError, match="canonical profile and scope"):
        support.validate_run(
            wrong_step,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )

    duplicate = deepcopy(run)
    duplicate["steps"][0]["evidence_ids"] = ["evidence-executed", "evidence-executed"]
    with pytest.raises(support.SupportError, match="observer evidence"):
        support.validate_run(
            duplicate,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )

    wrong_observation_behavior = deepcopy(run)
    wrong_observation_behavior["evidence"]["records"][0]["behavior_id"] = "wrong.behavior"
    wrong_observation_behavior["evidence"]["records"][1]["behavior_id"] = "wrong.behavior"
    with pytest.raises(support.SupportError, match="observer evidence"):
        support.validate_run(
            wrong_observation_behavior,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )

    wrong_cleanup_behavior = deepcopy(run)
    wrong_cleanup_behavior["evidence"]["records"][2]["behavior_id"] = "wrong.behavior"
    with pytest.raises(support.SupportError, match="cleanup evidence"):
        support.validate_run(
            wrong_cleanup_behavior,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )

    marker = workspace / support.CANARY_PATH
    marker.parent.mkdir()
    marker.write_text("residual", encoding="utf-8")
    with pytest.raises(support.SupportError, match="survived cleanup"):
        support.validate_run(
            run,
            sandbox_root=sandbox,
            approval_binding=_binding(),
            approved_by="gate01-release-operator",
            replay_of=None,
        )


def test_residual_check_rejects_a_path_outside_the_lifecycle_runtime(tmp_path: Path) -> None:
    wrong = tmp_path / "BlueFire Nexus" / "sandbox"
    (wrong / ".bluefire-executions" / _APPROVAL_ID).mkdir(parents=True)

    with pytest.raises(support.SupportError, match="survived cleanup"):
        support.assert_canary_absent(wrong, _APPROVAL_ID)


def test_runtime_dom_probe_rejects_static_or_disconnected_assets() -> None:
    rendered = " ".join(
        (
            "Mission control",
            "Design the path. Observe the defense.",
            "Local service ready",
            'href="#/runs"',
            "Behavior contracts",
            "Registered actions",
        )
    )
    support.validate_rendered_dom(rendered)

    with pytest.raises(support.SupportError, match="authenticated API-backed root"):
        support.validate_rendered_dom('<div id="root"></div>')
    with pytest.raises(support.SupportError, match="authenticated API-backed root"):
        support.validate_rendered_dom(rendered + " Service unavailable")

    runs = (
        '<section aria-label="Guided local Execute">'
        "Preflight every path. Observe every decision. "
        "Runner ready to approved run Verify &amp; enroll local runner"
        "</section>"
    )
    support.validate_runs_dom(runs)
    with pytest.raises(support.SupportError, match="guided Execute route"):
        support.validate_runs_dom('<div id="root"></div>')


def test_ui_launch_containment_failure_terminates_the_started_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = SimpleNamespace(pid=123, stdout=io.StringIO(), stderr=io.StringIO())
    terminated: list[tuple[Any, Any]] = []

    def refuse_containment(_process: Any) -> int:
        raise support.SupportError("process_job_assign_failed", "containment failed")

    fake_support = SimpleNamespace(
        attach_process_tree=refuse_containment,
        terminate_process_tree=lambda item, handle: terminated.append((item, handle)),
    )
    monkeypatch.setattr(journey, "_SUPPORT", fake_support)
    monkeypatch.setattr(journey.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(support.SupportError, match="containment failed"):
        journey._launch_ui(evidence_dir=tmp_path, runs_dir=tmp_path / "runs")

    assert terminated == [(process, None)]


def test_cleanup_all_attempts_later_actions_before_bounded_failure() -> None:
    observed: list[str] = []

    def first() -> None:
        observed.append("first")
        raise OSError("private cleanup detail")

    def second() -> None:
        observed.append("second")

    with pytest.raises(support.SupportError, match="runtime cleanup was incomplete") as raised:
        support.cleanup_all(
            [first, second],
            code="journey_cleanup_failed",
            message="runtime cleanup was incomplete",
        )

    assert raised.value.code == "journey_cleanup_failed"
    assert observed == ["first", "second"]


def test_installed_distribution_version_must_match_imported_package() -> None:
    support.validate_package_version("0.1.0", "0.1.0")

    with pytest.raises(support.SupportError, match="versions differ") as raised:
        support.validate_package_version("0.1.0", "0.2.0")

    assert raised.value.code == "package_version_mismatch"


def test_support_loader_disables_bytecode_before_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    checkout = tmp_path / "checkout"
    evidence.mkdir()
    checkout.mkdir()
    support_copy = evidence / "i.py"
    support_copy.write_bytes(Path(support.__file__).read_bytes())
    monkeypatch.setattr(journey.sys, "dont_write_bytecode", False)

    loaded = journey._load_support(support_copy, evidence, checkout)

    assert loaded.SupportError is not None
    assert journey.sys.dont_write_bytecode is True
    assert not (evidence / "__pycache__").exists()
    assert not list(evidence.rglob("*.pyc"))
