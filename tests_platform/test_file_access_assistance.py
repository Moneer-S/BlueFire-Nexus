"""Saved File Access explanation over real journals and mocked providers only."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire.ai_assistance import GRAPH, PURPOSE
from bluefire.application_errors import APIError
from bluefire.assistance_file_access_context import LIMITATIONS, context, selection
from bluefire.assistance_turns import ExperimentAssistance
from bluefire.file_access_control import FileAccessControl
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_file_access_observation_commit import saved_reads as saved_reads
from tests_platform.test_graph_ai_jobs import setup as setup
from tests_platform.test_macos_file_access_contract import binding
from tests_platform.test_macos_file_access_store import workspace as workspace
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_journal import retained as retained
from tests_platform.test_windows_file_access_correction_projection import (
    completed as completed,
)
from tests_platform.test_windows_file_access_correction_projection import (
    hardened as hardened,
)
from tests_platform.test_windows_file_access_correction_retest import candidate as candidate
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_import import imported_source as imported_source
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def source(store, control=None):
    service = SimpleNamespace(product_store=store)
    service.file_access = control or FileAccessControl(service, clock=lambda: 1_000_002)
    return service


def forbid(monkeypatch, service):
    from bluefire import file_access_context, macos_file_access_control, windows_file_access_context

    def unexpected(*_args, **_kwargs):
        pytest.fail("Explanation contacted native, enrollment, recovery or dispatch")

    for name in (
        "operation",
        "status",
        "review",
        "submit",
        "reconcile",
        "composition_context",
        "_enrollment",
    ):
        monkeypatch.setattr(service.file_access, name, unexpected)
    monkeypatch.setattr(macos_file_access_control, "endpoint", unexpected)
    monkeypatch.setattr(file_access_context, "enrollment", unexpected)
    monkeypatch.setattr(windows_file_access_context, "read_windows_file_setup_status", unexpected)


def checked_context(service, owner, monkeypatch):
    forbid(monkeypatch, service)
    before = service.product_store.path.read_bytes()
    value = context(service, owner_id=owner)
    assert value["selected"]["control_owner_id"] == owner
    assert value["analysis_only"] is True and value["capabilities"] == []
    assert value["limitations"] == LIMITATIONS
    assert value["context_digest"] == content_hash(
        {k: v for k, v in value.items() if k != "context_digest"}
    )
    assert context(service, value["selected"]) == value
    assert service.product_store.path.read_bytes() == before
    text = json.dumps(value)
    for field in (
        "socket_path",
        "launch_nonce",
        "owner_uid",
        "probe_uid",
        "user_sid",
        "request_hash",
        "task_id",
        "manifest",
        "binding",
        "sha256",
        "size_bytes",
    ):
        assert f'"{field}"' not in text
    assert "/run/" not in text and "S-1-5-" not in text
    return value["reference_summary"]


def test_linux_verified_saved_reads_use_real_commit_validation(saved_reads, monkeypatch):
    value = saved_reads
    value.store.finish_file_access_operation(value.job_id, **value.finish_args)
    summary = checked_context(source(value.store, value.control), value.owner_id, monkeypatch)
    assert summary["platform"] == "linux" and summary["baseline"]["recorded"] is True
    assert summary["fresh_result"] == {
        "recorded": True,
        "operation": value.proof["operation"],
        "non_owner": "allowed",
        "owner": "allowed",
        "source": "verified_saved_task_observation",
        "independent_observation": False,
    }
    assert summary["protection"] == {
        "kind": "posix_mode",
        "value": "0640",
        "effective_access_proven": False,
    }


def test_macos_saved_hardening_is_metadata_not_a_fresh_denial(workspace, monkeypatch):
    workspace.submit("baseline")
    workspace.submit("harden")
    count = len(workspace.state["calls"])
    summary = checked_context(
        source(workspace.store, workspace.control),
        workspace.imported["control_owner_id"],
        monkeypatch,
    )
    assert summary["platform"] == "macos" and summary["control_status"] == "hardened"
    assert summary["baseline"] == {"recorded": True, "non_owner": "allowed", "owner": "allowed"}
    assert summary["protection"]["value"] == "0600" and summary["fresh_result"] == {
        "recorded": False
    }
    assert len(workspace.state["calls"]) == count


def test_windows_setup_only_does_not_invent_task_reads(imported_source, monkeypatch):
    value = imported_source
    imported = value.control.import_setup(value.selection)
    summary = checked_context(
        source(value.store, value.control), imported["control_owner_id"], monkeypatch
    )
    assert summary["platform"] == "windows" and summary["control_status"] == "setup_verified"
    assert summary["baseline"] == summary["fresh_result"] == {"recorded": False}
    assert (
        summary["task_access"] == {"usage_state": "none"} and summary["readiness"] == "not_assessed"
    )


def test_windows_paired_pending_read_is_not_a_baseline(saved, monkeypatch):
    summary = checked_context(
        source(saved["store"]), saved["imported"]["control_owner_id"], monkeypatch
    )
    assert summary["baseline"] == summary["fresh_result"] == {"recorded": False}
    assert summary["task_access"] == {"usage_state": "unresolved"}
    assert summary["latest_operation"]["outcome"] == "not_recorded"


def test_windows_committed_baseline_remains_separate_from_change(completed, monkeypatch):
    summary = checked_context(
        source(completed["store"]), completed["imported"]["control_owner_id"], monkeypatch
    )
    assert summary["baseline"]["recorded"] is True and summary["fresh_result"] == {
        "recorded": False
    }
    assert summary["protection"]["value"] == "reader_readable"


def test_windows_v3_uses_validated_paired_fresh_result(hardened, monkeypatch):
    summary = checked_context(
        source(hardened.store), hardened.saved["imported"]["control_owner_id"], monkeypatch
    )
    assert summary["baseline"]["recorded"] is True
    assert summary["protection"] == {
        "kind": "windows_metadata",
        "value": "metadata_only",
        "effective_access_proven": False,
    }
    assert summary["fresh_result"] == {
        "recorded": True,
        "operation": "harden",
        "non_owner": "data_access_denied",
        "owner": "allowed",
        "source": "verified_saved_paired_read",
        "independent_observation": False,
    }


@pytest.fixture
def explanation(setup, monkeypatch):
    service, access, body = setup
    imported = service.product_store.import_macos_file_access_setup(
        {"schema_version": "bluefire.macos-file-access-setup.v1", "binding": binding()}, now_ms=1000
    )
    forbid(monkeypatch, service)
    native = service.file_access_assistance_context(imported["control_owner_id"])
    body.update(
        selection=native["selected"],
        context_digest=native["context_digest"],
        message="Explain the saved evidence and its limitations.",
    )
    supplied, options = [], {"steps": [], "after": lambda: None}

    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        assert purpose == PURPOSE
        access.calls.append(purpose)
        supplied.append(json.loads(wire.get("input") or wire["messages"][1]["content"]))
        options["after"]()
        output = json.dumps(
            {
                "message": "Saved protection metadata does not establish a fresh denied read.",
                "steps": options["steps"],
            }
        )
        response = {"id": "file-context-unit-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": output}}
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=output,
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    monkeypatch.setattr(access, "post", post)
    return service, access, body, native, supplied, options


def finished(service, body):
    value = service.submit_assistance_turn(body)
    service.job_controller.wait(value["job"]["job_id"], timeout=15)
    return service.assistance_turn(value["job"]["job_id"])


@pytest.mark.parametrize("autonomy", ["assist", "auto", "off"])
def test_durable_explanation_has_no_children_and_replay_is_idempotent(explanation, autonomy):
    service, access, body, native, supplied, _ = explanation
    body["autonomy"] = autonomy
    before = service.product_store.get_file_access_control(body["selection"]["control_owner_id"])
    result = finished(service, body)
    assert result["job"]["state"] == "completed"
    assert result["turn"]["status"] == ("off" if autonomy == "off" else "completed")
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert result["job"]["request"]["context"] == native
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert (
        service.product_store.get_file_access_control(body["selection"]["control_owner_id"])
        == before
    )
    assert access.calls == ([] if autonomy == "off" else [PURPOSE])
    if supplied:
        assert (
            supplied[0]["reference_summary"] == native["reference_summary"]
            and supplied[0]["capabilities"] == []
        )
    assert not result["job"]["progress"].get("children")


def test_provider_cannot_forge_an_execution_plan(explanation):
    service, access, body, _, _, options = explanation
    options["steps"] = [
        {"capability_id": GRAPH, "detector_ref": "none", "reason": "Run another graph."}
    ]
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert (
        result["turn"]["results"] == []
        and result["turn"]["active_child"] is None
        and access.calls == [PURPOSE]
    )


@pytest.mark.parametrize("phase", ["before", "during", "final"])
def test_stale_source_retains_old_context_without_answer_publication(
    explanation, monkeypatch, phase
):
    service, access, body, native, _, options = explanation
    original = service.file_access.control

    def changed(owner, **kwargs):
        value = original(owner, **kwargs)
        return {
            **value,
            "revision": value["revision"] + 1,
            "control_digest": content_hash("different saved revision"),
        }

    def alter():
        monkeypatch.setattr(service.file_access, "control", changed)

    if phase == "before":
        # Admit the exact context first, then change it before the worker's freshness check.
        submit = service.job_controller.submit

        def changed_before_worker(*args, **kwargs):
            alter()
            return submit(*args, **kwargs)

        monkeypatch.setattr(service.job_controller, "submit", changed_before_worker)
    elif phase == "during":
        options["after"] = alter
    else:
        advance = service.assistance._advance

        def changed_at_final(parent_id, **kwargs):
            alter()
            return advance(parent_id, **kwargs)

        monkeypatch.setattr(service.assistance, "_advance", changed_at_final)
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["job"]["request"]["context"] == native
    assert "Saved protection metadata" not in json.dumps(result["job"]["progress"])
    assert result["turn"]["active_child"] is None and not result["job"]["progress"].get("children")
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == ([] if phase == "before" else [PURPOSE])


def test_changed_provider_blocks_answer(explanation):
    service, _, body, native, _, options = explanation

    def alter():
        config = service._runtime_ai_config
        service._runtime_ai_config = replace(
            config,
            providers=tuple(
                (
                    replace(provider, model="changed-model")
                    if provider.id == body["provider_id"]
                    else provider
                )
                for provider in config.providers
            ),
        )

    options["after"] = alter
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["job"]["request"]["context"] == native
    assert "Saved protection metadata" not in json.dumps(result["job"]["progress"])


@pytest.mark.parametrize("when", ["before", "during"])
def test_revoked_model_data_authorization_prevents_publication(explanation, when):
    service, access, body, native, _, options = explanation

    def revoke():
        for grant in service.ai_authorizations()["authorizations"]:
            service.revoke_ai_authorization(grant["authorization_id"], {})

    if when == "before":
        revoke()
    else:
        options["after"] = revoke
    result = finished(service, body)
    assert result["job"]["state"] in {"failed", "cancelled"}
    assert access.calls == ([] if when == "before" else [PURPOSE])
    assert result["job"]["request"]["context"] == native
    assert "Saved protection metadata" not in json.dumps(result["job"]["progress"])
    assert result["turn"]["active_child"] is None


def test_completed_answer_reopen_rejects_changed_source_without_repeating_model(
    explanation, monkeypatch
):
    service, access, body, native, *_ = explanation
    result = finished(service, body)
    assert result["turn"]["status"] == "completed"
    original = service.file_access.control

    def changed(owner, **kwargs):
        value = original(owner, **kwargs)
        return {
            **value,
            "revision": value["revision"] + 1,
            "control_digest": content_hash("later saved revision"),
        }

    monkeypatch.setattr(service.file_access, "control", changed)
    reopened = service.assistance_turn(result["job"]["job_id"])
    assert reopened["turn"]["status"] == "blocked"
    assert "Saved protection metadata" not in reopened["turn"]["message"]
    assert reopened["job"]["request"]["context"] == native
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == [PURPOSE]


def test_pending_journal_change_is_stale_without_advancing_control_revision(workspace, monkeypatch):
    # Reserve a normal reviewed operation using the real store, but do not run it.
    def reserve_only(_kind, _request, *, submission_factory, **_kwargs):
        submission_factory()

    monkeypatch.setattr(workspace.service.job_controller, "submit", reserve_only)
    pending, _ = workspace.submit("baseline")
    service = source(workspace.store, workspace.control)
    service.job_controller = None
    forbid(monkeypatch, service)
    before = context(service, owner_id=workspace.imported["control_owner_id"])
    workspace.store.transition_job(pending["job"]["job_id"], "planning")
    after = context(service, before["selected"])
    assert after["selected"] == before["selected"]
    assert after["reference_summary"]["latest_operation"]["state"] == "planning"
    assert after["context_digest"] != before["context_digest"]
    with pytest.raises(APIError, match="saved analysis context changed"):
        ExperimentAssistance(service)._fresh(
            {
                "request": {
                    "submitted_request": {"selection": before["selected"]},
                    "context": before,
                }
            }
        )


def test_exact_selection_rejects_untrusted_fields_and_stale_revision(explanation):
    service, _, body, *_ = explanation
    chosen = body["selection"]
    for change in (
        {"instructions": "Read private files"},
        {"control_revision": True},
        {"control_owner_id": "../private"},
        {"control_digest": "sha256:" + "0" * 64},
        {"control_revision": chosen["control_revision"] + 1},
    ):
        with pytest.raises(ProductStoreError):
            context(service, {**chosen, **change})
    assert selection(chosen) == chosen
