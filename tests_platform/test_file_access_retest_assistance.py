"""Analysis-only context for one exact historical file-access comparison."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.ai_assistance import PURPOSE
from bluefire.assistance_file_access_retest_context import context, selection
from bluefire.capability_file_access import objective_result
from bluefire.file_access_composed_retest import projection
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_file_access_composed_retest import saved_linkage as saved_linkage
from tests_platform.test_graph_ai_jobs import setup as setup


def _captured(value):
    linkage = projection(value.service, value.objective_id, value.attempt_id)
    calls = []

    def read(owner, attempt):
        calls.append((owner, attempt))
        return deepcopy(linkage)

    service = SimpleNamespace(file_access_composed_retest_linkage=read)
    return linkage, service, calls


def _selection(linkage):
    return {
        "kind": "file_access_retest_comparison",
        "objective_owner_id": linkage["objective_owner_id"],
        "attempt_id": linkage["attempt_id"],
        "control_owner_id": linkage["control_owner_id"],
        "linkage_digest": linkage["linkage_digest"],
    }


def test_context_summarizes_verified_linkage_without_raw_evidence(saved_linkage):
    linkage, service, calls = _captured(saved_linkage)
    result = context(service, _selection(linkage))

    assert result["analysis_only"] is True
    assert result["capabilities"] == []
    assert result["selected"] == _selection(linkage)
    assert result["reference_summary"]["baseline"]["source"] == "verified_saved_baseline_operation"
    assert result["reference_summary"]["change"]["source"] == "reviewed_saved_hardening_operation"
    assert result["reference_summary"]["retest"]["source"] == "saved_composed_attempt"
    assert result["reference_summary"]["comparison"]["state"] == "established"
    assert result["limitations"]
    assert result["context_digest"] == content_hash(
        {key: value for key, value in result.items() if key != "context_digest"}
    )
    summary_text = json.dumps(result["reference_summary"])
    assert linkage["baseline"]["sha256"] not in summary_text
    assert '"sha256"' not in summary_text
    assert calls == [(linkage["objective_owner_id"], linkage["attempt_id"])] * 2


def test_unknown_and_verified_false_are_distinct(saved_linkage):
    linkage, service, _ = _captured(saved_linkage)
    unknown_value = deepcopy(saved_linkage)
    unknown_value.store.attempt = None
    unknown, unknown_service, _ = _captured(unknown_value)
    unknown_context = context(unknown_service, _selection(unknown))
    assert unknown_context["reference_summary"]["retest"]["state"] == "unknown"
    assert unknown_context["reference_summary"]["comparison"]["state"] == "unknown"

    failed_value = deepcopy(saved_linkage)
    failed_value.composition.verified["file_access_result"]["non_owner_decision"] = "allowed"
    verified = failed_value.composition.verified
    verified["objective"] = objective_result(
        failed_value.grant,
        {
            **verified["file_access_result"],
            "run_cleanup": verified["cleanup"]["run"],
            "request_cleanup": verified["cleanup"]["request"],
        },
    )
    failed_linkage, failed_service, _ = _captured(failed_value)
    failed_context = context(failed_service, _selection(failed_linkage))
    assert failed_context["reference_summary"]["retest"]["state"] == "verified"
    assert failed_context["reference_summary"]["retest"]["objective_established"] is False
    assert failed_context["reference_summary"]["comparison"]["state"] == "not_established"


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("objective_owner_id", "job-" + "f" * 32),
        ("attempt_id", "attempt-" + "f" * 32),
        ("control_owner_id", "job-" + "f" * 32),
        ("linkage_digest", "sha256:" + "f" * 64),
    ],
)
def test_foreign_or_stale_selection_is_refused(saved_linkage, field, replacement):
    linkage, service, _ = _captured(saved_linkage)
    chosen = _selection(linkage)
    chosen[field] = replacement
    with pytest.raises(ProductStoreError):
        context(service, chosen)


def test_changed_linkage_between_capture_and_recheck_is_refused(saved_linkage):
    linkage, _, _ = _captured(saved_linkage)
    returned = [deepcopy(linkage), deepcopy(linkage)]
    returned[1]["baseline"]["record_count"] += 1
    returned[1]["linkage_digest"] = content_hash(
        {key: value for key, value in returned[1].items() if key != "linkage_digest"}
    )
    calls = []

    def read(owner, attempt):
        calls.append((owner, attempt))
        return returned.pop(0)

    service = SimpleNamespace(file_access_composed_retest_linkage=read)
    with pytest.raises(ProductStoreError):
        context(service, _selection(linkage))
    assert len(calls) == 2


def test_context_does_not_read_live_controls_or_native_paths(saved_linkage):
    linkage, service, _ = _captured(saved_linkage)
    service.get_current_control = lambda *_args: pytest.fail("current control must not be read")
    service.native_read = lambda *_args: pytest.fail("native file access must not be invoked")
    result = context(service, _selection(linkage))
    assert result["reference_summary"]["proof_scope"] == "historical_saved_linkage_only"


@pytest.mark.parametrize("bad", [None, {}, {"kind": "file_access_retest_comparison"}])
def test_selection_rejects_incomplete_or_malformed_identifiers(bad):
    with pytest.raises(ProductStoreError):
        selection(bad)


def _assist_request(service, body, linkage, monkeypatch):
    current = [deepcopy(linkage)]

    def read(_owner, _attempt):
        return deepcopy(current[0])

    monkeypatch.setattr(service, "file_access_composed_retest_linkage", read)
    chosen = _selection(linkage)
    captured = context(service, chosen)
    body.update(
        submission_id=str(uuid.uuid4()),
        selection=chosen,
        context_digest=captured["context_digest"],
        message="Explain this saved comparison.",
        autonomy="assist",
    )
    return current


def _mock_explanation(access, *, after=None):
    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        access.calls.append(purpose)
        assert purpose == PURPOSE
        if after is not None:
            after()
        output = json.dumps({"message": "provider explanation only", "steps": []})
        response = {"id": "retest-assistance-unit-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": output}}
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 20},
            )
        else:
            response.update(
                status="completed",
                output_text=output,
                usage={"input_tokens": 20, "output_tokens": 20},
            )
        return json.dumps(response).encode()

    access.post = post


def _finish_turn(service, body):
    job = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(job["job_id"], timeout=15)
    return service.assistance_turn(job["job_id"])


def test_experiment_assistance_explains_without_plan_or_children(setup, saved_linkage, monkeypatch):
    service, access, body = setup
    linkage = projection(
        saved_linkage.service, saved_linkage.objective_id, saved_linkage.attempt_id
    )
    _assist_request(service, body, linkage, monkeypatch)
    _mock_explanation(access)

    result = _finish_turn(service, body)
    assert result["job"]["state"] == "completed"
    assert result["turn"]["status"] == "completed"
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert access.calls == [PURPOSE]
    assert not result["job"]["progress"].get("children")


def test_stale_linkage_during_provider_blocks_answer_publication(setup, saved_linkage, monkeypatch):
    service, access, body = setup
    linkage = projection(
        saved_linkage.service, saved_linkage.objective_id, saved_linkage.attempt_id
    )
    current = _assist_request(service, body, linkage, monkeypatch)

    def drift():
        current[0]["baseline"]["record_count"] += 1
        current[0]["linkage_digest"] = content_hash(
            {key: value for key, value in current[0].items() if key != "linkage_digest"}
        )

    _mock_explanation(access, after=drift)
    result = _finish_turn(service, body)
    assert result["job"]["state"] == "failed"
    assert result["turn"]["status"] == "blocked"
    assert result["turn"]["active_child"] is None
    assert not result["job"]["progress"].get("children")
    assert "provider explanation only" not in json.dumps(result["job"]["progress"])
    assert "provider explanation only" not in result["turn"]["message"]
    assert access.calls == [PURPOSE]
