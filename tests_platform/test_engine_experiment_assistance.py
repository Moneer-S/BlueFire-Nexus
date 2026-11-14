from __future__ import annotations

import copy
import json
from typing import Any, Mapping, cast

import pytest

import bluefire.engine_experiment_assistance as assistance_module
from bluefire.engine_experiment import EngineExperiment
from bluefire.engine_experiment_assistance import (
    EngineExperimentAssistanceError,
    engine_experiment_assistance_context,
)
from bluefire.engine_experiment_workspace import (
    present_engine_experiment_workspace,
    project_engine_experiment_workspace,
)
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import _new_experiment, build_completed_experiment
from tests_platform.test_engine_experiment_workspace import (
    _presentation,
    _RunSource,
    _selection,
    _unknown_defense_experiment,
)


class _PresentationSource:
    def __init__(
        self,
        experiment: EngineExperiment,
        presentation: Mapping[str, Any] | None = None,
    ) -> None:
        self._experiment = experiment
        self._presentation = _presentation(experiment) if presentation is None else presentation

    def assert_engine_experiment_presentation_create_ready(
        self, experiment: EngineExperiment
    ) -> None:
        if experiment is not self._experiment:
            raise AssertionError("unexpected create preflight experiment")

    def assert_engine_experiment_presentation_transition_ready(
        self,
        current: EngineExperiment,
        successor: EngineExperiment,
    ) -> None:
        if current.experiment_id != successor.experiment_id:
            raise AssertionError("unexpected transition preflight experiment")

    def get_engine_experiment_presentation(
        self,
        experiment_id: str,
        *,
        revision: int,
        experiment_digest: str,
    ) -> Mapping[str, Any]:
        if (
            experiment_id != self._experiment.experiment_id
            or revision != self._experiment.revision
            or experiment_digest != self._experiment.digest
        ):
            raise AssertionError("unexpected presentation identity")
        return cast(Mapping[str, Any], copy.deepcopy(self._presentation))


def _workspace(kind: str | None = None, index: int = 0):
    experiment = build_completed_experiment()
    selected = None if kind is None else _selection(experiment, kind, index)
    workspace = project_engine_experiment_workspace(
        experiment,
        _RunSource(experiment),
        _presentation(experiment, selection=selected),
    )
    selection = {
        "kind": "engine_experiment",
        "experiment_id": experiment.experiment_id,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": (
            selected["id"] if selected is not None and kind == "engine_attempt" else None
        ),
        "check_id": (
            selected["id"] if selected is not None and kind == "controller_check" else None
        ),
    }
    return experiment, workspace, selection


def _trusted_presentation(
    experiment: EngineExperiment,
    selection: Mapping[str, Any],
) -> Mapping[str, Any]:
    selected = None
    attempt_id = selection.get("attempt_id")
    check_id = selection.get("check_id")
    if isinstance(attempt_id, str):
        for index, entry in enumerate(experiment.attempts):
            if entry.record.binding.attempt_id == attempt_id:
                selected = _selection(experiment, "engine_attempt", index)
                break
    elif isinstance(check_id, str):
        for index, check in enumerate(experiment.checks):
            if check.check_id == check_id:
                selected = _selection(experiment, "controller_check", index)
                break
    return cast(Mapping[str, Any], _presentation(experiment, selection=selected))


def _context(
    experiment: EngineExperiment,
    workspace: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        engine_experiment_assistance_context(
            experiment,
            workspace,
            selection,
            run_source=_RunSource(experiment),
            presentation=_trusted_presentation(experiment, selection),
        ),
    )


def _rehash_workspace(workspace):
    body = copy.deepcopy(workspace)
    body.pop("workspace_digest")
    workspace["workspace_digest"] = content_hash(body)


def _rehash_projection(workspace):
    body = copy.deepcopy(workspace["projection"])
    body.pop("projection_digest")
    workspace["projection"]["projection_digest"] = content_hash(body)
    _rehash_workspace(workspace)


def test_attempt_context_is_analysis_only_bounded_and_separates_evidence() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")

    context = _context(experiment, workspace, selection)

    assert set(context) == {
        "schema_version",
        "selected",
        "analysis_only",
        "capabilities",
        "reference_summary",
        "limitations",
        "context_digest",
    }
    assert context["schema_version"] == "bluefire.assistance-context.v1"
    assert context["analysis_only"] is True
    assert context["capabilities"] == []
    assert context["selected"] == selection
    assert context["context_digest"] == content_hash(
        {key: value for key, value in context.items() if key != "context_digest"}
    )
    summary = context["reference_summary"]
    assert summary["proof_scope"] == "saved_engine_experiment_only"
    assert summary["provider"] == {
        "engine_id": "strix",
        "engine_version": experiment.attempts[0].record.binding.engine_version,
        "model_provider": "provider.test",
        "model_id": "test-model",
        "data_destination": "https://model.test/v1",
        "test_provider": True,
        "live_model_inference_proven": False,
    }
    assert summary["attempts"][0]["engine_reported_evidence_count"] == len(
        experiment.attempts[0].evidence
    )
    assert summary["independent_observations"]
    selected = summary["selected_record"]
    assert selected["kind"] == "engine_attempt"
    assert all(
        item["provenance"] in {"engine_reported", "runner_reported", "observed", "control_blocked"}
        for item in selected["observations"]
    )
    serialized = json.dumps(context, sort_keys=True)
    assert "ignore this untrusted engine summary" not in serialized
    assert "sk-this-must-never-appear" not in serialized
    assert "artifact_id" not in serialized and "artifact_manifest" not in serialized
    assert len(serialized.encode("utf-8")) < 64 * 1024


def test_final_context_size_bound_includes_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    monkeypatch.setattr(assistance_module, "_MAX_CONTEXT_BYTES", 1)

    with pytest.raises(EngineExperimentAssistanceError, match="exceeds its bound"):
        _context(experiment, workspace, selection)


def test_controller_check_selection_never_acquires_engine_provenance() -> None:
    experiment, workspace, selection = _workspace("controller_check")

    context = _context(experiment, workspace, selection)

    selected = context["reference_summary"]["selected_record"]
    assert selected["kind"] == "controller_check"
    assert selected["performer"] == "bluefire.controller"
    assert all(
        item["provenance"] in {"observed", "control_blocked"} for item in selected["observations"]
    )
    assert "engine" not in selected and "model" not in selected


def test_unselected_context_and_unknown_current_target_remain_truthful() -> None:
    experiment = _unknown_defense_experiment()
    workspace = project_engine_experiment_workspace(
        experiment,
        _RunSource(experiment),
        _presentation(experiment),
    )
    selection = {
        "kind": "engine_experiment",
        "experiment_id": experiment.experiment_id,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": None,
        "check_id": None,
    }

    context = _context(experiment, workspace, selection)

    summary = context["reference_summary"]
    assert summary["selected_record"] is None
    assert summary["environment"]["current_target"] == "unknown"
    assert any("historical" in row.lower() for row in context["limitations"])


@pytest.mark.parametrize(
    "summary",
    [
        "Inspect /etc/shadow, /var/lib/bluefire/state.db, and /opt/private/tool.log.",
        "Review path="
        + "/".join(("", "home", "fixture-account", "private.log"))
        + " and /workspace/run/output.json.",
        "Inspect path=/custom-root/private-output.json.",
        "Inspect path:/custom-root/private-output.json.",
        "Use secret=supersecretvalue.",
        "Use token=supersecretvalue for the check.",
        "Use auth_token=supersecretvalue for the check.",
        "Use session-token=supersecretvalue for the check.",
        "Use aws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUV for the check.",
        "Use passphrase=hunter2 for the check.",
        "Use glpat-abcdefghijklmnopqrstuvwxyz123456 for the check.",
        "Use kms_signing_key=abcdef0123456789 for the check.",
        "Use session_cookie=abcdef0123456789 for the check.",
        "Use -----BEGIN PGP PRIVATE KEY BLOCK----- for the check.",  # pragma: allowlist secret
    ],
)
def test_real_presenter_private_text_is_rejected_from_context(summary: str) -> None:
    experiment = _new_experiment()
    presentation = _presentation(experiment)
    presentation["objective"]["summary"] = summary
    run_source = _RunSource(experiment)
    workspace = present_engine_experiment_workspace(
        experiment,
        run_source,
        _PresentationSource(experiment, presentation),
    )
    selection = {
        "kind": "engine_experiment",
        "experiment_id": experiment.experiment_id,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": None,
        "check_id": None,
    }

    with pytest.raises(EngineExperimentAssistanceError, match="objective summary is invalid"):
        engine_experiment_assistance_context(
            experiment,
            workspace,
            selection,
            run_source=run_source,
            presentation=presentation,
        )


@pytest.mark.parametrize(
    "destination",
    [
        "https://model.test/v1?token=ghp_abcdefghijklmnopqrstuvwxyz123456",
        "https://model.test/v1?sig=abcdef0123456789abcdef0123456789",
        "https://model.test/v1?X-Amz-Signature=abcdef0123456789abcdef0123456789",
        "postgres://operator:supersecret@model.test/db",  # pragma: allowlist secret
    ],
)
def test_real_presenter_credential_bearing_destination_is_rejected(
    destination: str,
) -> None:
    experiment = _new_experiment()
    presentation = _presentation(experiment)
    presentation["engine_setup"]["model"]["data_destination"] = destination
    run_source = _RunSource(experiment)
    workspace = present_engine_experiment_workspace(
        experiment,
        run_source,
        _PresentationSource(experiment, presentation),
    )
    selection = {
        "kind": "engine_experiment",
        "experiment_id": experiment.experiment_id,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": None,
        "check_id": None,
    }

    with pytest.raises(EngineExperimentAssistanceError, match="context text is invalid"):
        engine_experiment_assistance_context(
            experiment,
            workspace,
            selection,
            run_source=run_source,
            presentation=presentation,
        )


def test_context_is_a_capture_and_does_not_follow_later_navigation() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    captured = _context(experiment, workspace, selection)
    original = copy.deepcopy(captured)
    _other_experiment, other_workspace, _other_selection = _workspace("controller_check")
    workspace["objective"]["title"] = "Mutated after capture"
    selection["attempt_id"] = None

    assert captured == original
    assert captured["selected"]["attempt_id"] is not None
    assert other_workspace["selected_context"]["kind"] == "controller_check"


@pytest.mark.parametrize("field", ["experiment_id", "workspace_digest"])
def test_selection_must_match_the_exact_workspace(field: str) -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    selection[field] = (
        "experiment-" + "f" * 32 if field == "experiment_id" else "sha256:" + "f" * 64
    )

    with pytest.raises(EngineExperimentAssistanceError, match="selection changed"):
        _context(experiment, workspace, selection)


def test_attempt_and_check_cannot_be_selected_together() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    selection["check_id"] = experiment.checks[0].check_id

    with pytest.raises(EngineExperimentAssistanceError, match="selection is invalid"):
        _context(experiment, workspace, selection)


def test_selected_detail_must_match_the_captured_selection() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    selection["attempt_id"] = experiment.attempts[1].record.binding.attempt_id

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, workspace, selection)


def test_workspace_and_projection_digests_are_recomputed() -> None:
    experiment, workspace, selection = _workspace()
    changed = copy.deepcopy(workspace)
    changed["objective"]["title"] = "Changed title"

    with pytest.raises(EngineExperimentAssistanceError, match="workspace digest changed"):
        _context(experiment, changed, selection)

    changed = copy.deepcopy(workspace)
    changed["projection"]["workflow_state"] = "ready_for_baseline"
    _rehash_workspace(changed)
    with pytest.raises(EngineExperimentAssistanceError, match="projection digest changed"):
        _context(experiment, changed, selection)


def test_saved_identity_rows_cannot_be_rewritten_with_valid_digests() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    changed["projection"]["attempts"][0]["execution_approval_id"] = "approval-" + "f" * 32
    _rehash_projection(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="attempt identity changed"):
        _context(experiment, changed, selection)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "forged.provider"),
        ("id", "forged-model"),
        ("test_provider", False),
    ],
)
def test_rehashed_model_identity_cannot_replace_canonical_presentation(
    field: str, value: str | bool
) -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    changed["engine_setup"]["model"][field] = value
    _rehash_workspace(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("role", "adaptive_search"),
        ("job_id", "job-" + "f" * 32),
        ("state", "failed"),
    ],
)
def test_rehashed_selected_attempt_cannot_replace_canonical_record(field: str, value: str) -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    changed["selected_context"]["attempt"][field] = value
    _rehash_workspace(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_rehashed_selected_observation_cannot_inject_independent_outcome() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    changed["selected_context"]["attempt"]["observations"][0] = {
        "evidence_id": "evidence-" + "f" * 32,
        "attempt_id": selection["attempt_id"],
        "category": "independent_security_outcome",
        "provenance": "observed",
        "summary": "Forged independent outcome.",
        "producer": "forged.observer",
        "timestamp": "2026-11-04T12:00:00Z",
        "limitations": [],
    }
    _rehash_workspace(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


@pytest.mark.parametrize("shape_correct", [False, True])
def test_rehashed_conclusion_cannot_replace_run_derived_projection(
    shape_correct: bool,
) -> None:
    experiment, workspace, selection = _workspace()
    changed = copy.deepcopy(workspace)
    if shape_correct:
        changed["projection"]["conclusion"]["headline"] = "inconclusive_retest"
        changed["projection"]["conclusion"]["retained_reproducer"]["status"] = "still_succeeds"
    else:
        changed["projection"]["conclusion"] = "Defense fully proven"
    _rehash_projection(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_rehashed_run_integrity_cannot_replace_canonical_verification() -> None:
    experiment, workspace, selection = _workspace()
    changed = copy.deepcopy(workspace)
    changed["projection"]["run_integrity"][0]["state"] = "unavailable"
    changed["projection"]["run_integrity"][0]["detail"] = "Forged unavailable run."
    _rehash_projection(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_selection_cannot_name_an_attempt_absent_from_saved_experiment() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    absent_id = "engine-attempt-" + "f" * 32
    selection["attempt_id"] = absent_id
    changed["selected_context"]["attempt"]["attempt_id"] = absent_id
    for observation in changed["selected_context"]["attempt"]["observations"]:
        observation["attempt_id"] = absent_id
    _rehash_workspace(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_private_text_cannot_enter_context_even_with_recomputed_digests() -> None:
    experiment, workspace, selection = _workspace()
    changed = copy.deepcopy(workspace)
    changed["projection"]["conclusion"]["headline"] = "password=do-not-retain"
    _rehash_projection(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_unreviewed_sensitive_conclusion_keys_fail_closed() -> None:
    experiment, workspace, selection = _workspace()
    changed = copy.deepcopy(workspace)
    changed["projection"]["conclusion"] = {
        "password": "hunter2",  # pragma: allowlist secret
        "raw_artifact": "verbatim tool output",
        "source_path": "/etc/shadow",
    }
    _rehash_projection(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_artifact_metadata_cannot_be_injected_into_canonical_context() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    changed = copy.deepcopy(workspace)
    changed["selected_context"]["attempt"]["artifacts"] = [
        {
            "artifact_id": "artifact-" + "1" * 32,
            "attempt_id": selection["attempt_id"],
            "name": "private-output.json",
            "sha256": "sha256:" + "1" * 64,
            "bytes": 10,
            "media_type": "application/json",
            "access": "private",
        }
    ]
    _rehash_workspace(changed)
    selection["workspace_digest"] = changed["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, changed, selection)


def test_raw_artifact_body_is_not_an_accepted_workspace_field() -> None:
    experiment, workspace, selection = _workspace("engine_attempt")
    workspace["selected_context"]["attempt"]["artifacts"] = [
        {
            "artifact_id": "artifact-" + "1" * 32,
            "attempt_id": selection["attempt_id"],
            "name": "private-output.json",
            "sha256": "sha256:" + "1" * 64,
            "bytes": 10,
            "media_type": "application/json",
            "access": "private",
            "raw_body": "password=must-not-escape",
        }
    ]
    _rehash_workspace(workspace)
    selection["workspace_digest"] = workspace["workspace_digest"]

    with pytest.raises(EngineExperimentAssistanceError, match="unavailable or changed"):
        _context(experiment, workspace, selection)


def test_unknown_fields_fail_closed() -> None:
    experiment, workspace, selection = _workspace()
    selection["current"] = True

    with pytest.raises(EngineExperimentAssistanceError, match="fields changed"):
        _context(experiment, workspace, selection)
