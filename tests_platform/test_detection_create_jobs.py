"""Actual portable creation/evaluation transactions; no native execution or network."""

import json
import threading
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.ai_assistance import CREATE
from bluefire.ai_assistance import PURPOSE as PLAN_PURPOSE
from bluefire.ai_detection_create import PURPOSE
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.application_errors import APIError
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.test_api import request as http_request
from tests_platform.test_api import running_server
from tests_platform.test_detection_evaluations import observed_run

ROOT = Path(__file__).resolve().parents[1]
SQL = "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"


class Access:
    def __init__(self):
        self.calls = []
        self.transform = lambda value: value

    def readiness(self, config):
        return ProviderReadiness(True, "not_required", "ready", "Pure portable creation fixture")

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        request = json.loads(body)
        purpose = (
            request.get("text", {}).get("format") or request["response_format"]["json_schema"]
        )["name"]
        context = json.loads(request.get("input") or request["messages"][1]["content"])
        self.calls.append(purpose)
        if purpose == PLAN_PURPOSE:
            output = {
                "message": "Create a concrete rule for native review and development evaluation.",
                "steps": [
                    {
                        "capability_id": CREATE,
                        "detector_ref": "none",
                        "reason": "Use the explicitly selected verified run.",
                    }
                ],
            }
        else:
            assert purpose == PURPOSE
            output = self.transform(
                {
                    "title": "Collection observation rule",
                    "source": SQL,
                    "reason": "Use the supplied observed schema.",
                    "evidence_refs": [context["observations"][0]["evidence_id"]],
                    "limitations": [
                        "Portable deterministic fixture, not model-quality or held-out evidence."
                    ],
                }
            )
        if config.kind.value == "chat_completions":
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(output)},
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 40},
                }
            ).encode()
        return json.dumps(
            {
                "status": "completed",
                "output_text": json.dumps(output),
                "usage": {"input_tokens": 20, "output_tokens": 40},
            }
        ).encode()

    def close(self):
        pass


@pytest.fixture(params=["openai_responses", "chat_completions"])
def setup(tmp_path, request):
    access = Access()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(
        {
            "id": "provider.creation-test.v1",
            "kind": request.param,
            "model": "portable-model",
            "endpoint": (
                "http://127.0.0.1:8765/v1/responses"
                if request.param == "openai_responses"
                else "http://127.0.0.1:8765/v1/chat/completions"
            ),
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    run_id, rows = observed_run(service, tmp_path)
    discovered = service.detection_creation_source({"run_id": run_id})
    selected = {
        "kind": "run_detection",
        "run_id": run_id,
        "source_binding_digest": discovered["source_binding_digest"],
        "behavior_id": rows[0].behavior_id,
        "target_language": "sqlite",
        "case_role": "attack",
    }
    context = service.detection_creation_context({k: v for k, v in selected.items() if k != "kind"})
    request = {
        "submission_id": str(uuid.uuid4()),
        "selection": selected,
        "context_digest": context["context_digest"],
        "message": "Create a rule from this run.\nEvaluate only as a development case.",
        "autonomy": "assist",
        "provider_id": provider.id,
    }
    yield service, access, request
    service.close()


def proposal(setup):
    service, access, request = setup
    submitted = service.submit_assistance_turn(request)
    parent_id = submitted["job"]["job_id"]
    done = service.job_controller.wait(parent_id, timeout=20)
    assert done["state"] == "completed", done
    parent = service.assistance_turn(parent_id)
    assert parent["turn"]["active_child"], parent
    job_id = parent["turn"]["active_child"]["job_id"]
    done = service.job_controller.wait(job_id, timeout=20)
    assert done["state"] == "completed", done
    return parent_id, service.detection_create_job(job_id)


def decision(service, envelope, **edits):
    value = envelope["proposal"]
    body = {key: value[key] for key in ("proposal_digest", "title", "source")}
    body.update(edits)
    validated = service.validate_detection_create(envelope["job"]["job_id"], body)
    return {
        **body,
        "reviewed_digest": validated["reviewed_digest"],
        "decision": "accept",
        "reviewed_by": "Portable operator",
    }


def test_create_edited_source_and_actual_evaluation(setup, tmp_path):
    service, access, request = setup
    parent_id, envelope = proposal(setup)
    assert envelope["review_ready"]
    assert service.product_store.list_resources("detection") == []
    assert service.active_jobs()["jobs"] == []
    body = decision(
        service, envelope, title="Reviewed observed collection", source=SQL + " AND size_bytes > 0"
    )
    accepted = service.review_detection_create(envelope["job"]["job_id"], body)
    done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    assert done["state"] == "completed", done
    completed = service.detection_create_job(envelope["job"]["job_id"])
    assert completed["decision"] == body
    assert completed["proposal"] == envelope["proposal"]
    assert completed["application"]["operator_modified"] is True
    assert completed["evaluation"]["development_case"] is True
    assert completed["evaluation"]["backend"]["executed"] is True
    assert completed["evaluation"]["result"]["match_count"] == 1
    assert service.review_detection_create(envelope["job"]["job_id"], body) == completed
    parent = service.assistance_turn(parent_id)
    assert parent["turn"]["status"] == "completed", parent
    assert parent["turn"]["results"][0]["kind"] == "detection_created"
    assert access.calls == [PLAN_PURPOSE, PURPOSE]
    (tmp_path / "native-contract.json").write_text(
        json.dumps(
            {
                "source": service.detection_creation_source(
                    {"run_id": request["selection"]["run_id"]}
                ),
                "request": request,
                "proposal_envelope": envelope,
                "completed_envelope": completed,
                "parent": parent,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def test_off_has_no_model_or_native_child(setup):
    service, access, request = setup
    submitted = service.submit_assistance_turn({**request, "autonomy": "off"})
    service.job_controller.wait(submitted["job"]["job_id"], timeout=15)
    assert service.assistance_turn(submitted["job"]["job_id"])["turn"]["status"] == "off"
    assert access.calls == []


def test_auto_retains_proposal_never_accepts(setup):
    service, access, request = setup
    request["autonomy"] = "auto"
    parent_id, envelope = proposal(setup)
    assert envelope["review_ready"] and envelope["application_job"] is None
    assert service.assistance_turn(parent_id)["turn"]["status"] == "awaiting_review"
    assert service.product_store.list_resources("detection") == []


def test_sigma_initial_source_uses_real_converter_and_development_query(setup):
    service, access, request = setup
    discovered = service.detection_creation_source({"run_id": request["selection"]["run_id"]})
    if not next(row for row in discovered["languages"] if row["id"] == "sigma")["available"]:
        pytest.skip("Pinned Sigma SQLite adapter is unavailable in this environment.")
    sigma = """title: Collection Observation
status: test
logsource:
  category: file_event
detection:
  selection:
    artifact_type: collector_observation
  condition: selection
level: low
"""
    request["selection"]["target_language"] = "sigma"
    request["context_digest"] = service.detection_creation_context(
        {k: v for k, v in request["selection"].items() if k != "kind"}
    )["context_digest"]
    access.transform = lambda value: {**value, "source": sigma}
    _, envelope = proposal(setup)
    accepted = service.review_detection_create(
        envelope["job"]["job_id"], decision(service, envelope)
    )
    done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    assert done["state"] == "completed", done
    completed = service.detection_create_job(envelope["job"]["job_id"])
    assert completed["evaluation"]["backend"]["executed"] is True
    assert completed["evaluation"]["result"]["match_count"] == 1
    candidate = service.detection_candidate(completed["application"]["candidate_id"])["candidate"][
        "document"
    ]
    assert candidate["rule_source"] == sigma
    assert candidate["logsource"]["service"] == "normalized_run_observations"
    assert candidate["selection"]["query"] == candidate["validation"]["converted_query"]


def test_invalid_edit_does_not_save(setup):
    service, access, _ = setup
    _, envelope = proposal(setup)
    with pytest.raises(APIError) as error:
        decision(service, envelope, source="DELETE FROM logs")
    assert error.value.status == 422
    assert service.product_store.list_resources("detection") == []


def test_http_invalid_source_is_actionable_422_and_missing_job_404(setup):
    service, _, _ = setup
    _, envelope = proposal(setup)
    with running_server(service=service) as (server, _):
        status, _, body = http_request(
            server,
            "POST",
            f'/api/v1/ai/detection-create-jobs/{envelope["job"]["job_id"]}/validate',
            body={
                "proposal_digest": envelope["proposal"]["proposal_digest"],
                "title": "Invalid rule",
                "source": "DELETE FROM logs",
            },
        )
        assert status == 422, body
        assert json.loads(body)["error"]["code"] == "detection_creation_source_invalid"
        status, _, _ = http_request(
            server, "GET", "/api/v1/ai/detection-create-jobs/job-" + "f" * 32
        )
        assert status == 404
    assert service.product_store.list_resources("detection") == []


def test_exact_review_recovers_lost_application_submission(setup, monkeypatch):
    service, access, _ = setup
    _, envelope = proposal(setup)
    body = decision(service, envelope)
    original = service.detection_create._enqueue_application
    monkeypatch.setattr(service.detection_create, "_enqueue_application", lambda job: None)
    accepted = service.review_detection_create(envelope["job"]["job_id"], body)
    assert accepted["decision"] == body and accepted["application_job"] is None
    monkeypatch.setattr(service.detection_create, "_enqueue_application", original)
    recovered = service.review_detection_create(envelope["job"]["job_id"], body)
    assert (
        service.job_controller.wait(recovered["application_job"]["job_id"], timeout=20)["state"]
        == "completed"
    )
    assert len(service.product_store.list_resources("detection")) == 1
    assert access.calls == [PLAN_PURPOSE, PURPOSE]


@pytest.mark.parametrize("commit_first", [False, True])
def test_stop_and_atomic_commit_have_one_truthful_winner(setup, monkeypatch, commit_first):
    from bluefire import product_store_detection_create as records

    service, access, _ = setup
    parent_id, envelope = proposal(setup)
    body = decision(service, envelope)
    entered, release = threading.Event(), threading.Event()
    original = records.apply

    def held(*args, **kwargs):
        result = original(*args, **kwargs) if commit_first else None
        entered.set()
        assert release.wait(15)
        return result if commit_first else original(*args, **kwargs)

    monkeypatch.setattr(records, "apply", held)
    accepted = service.review_detection_create(envelope["job"]["job_id"], body)
    try:
        assert entered.wait(15)
        stopped = service.cancel_job(parent_id)
        assert stopped["progress"]["stopped"]
    finally:
        release.set()
    done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    assert done["state"] == ("completed" if commit_first else "cancelled"), done
    saved = service.detection_create_job(envelope["job"]["job_id"])
    assert bool(saved["application"]) is commit_first
    assert len(service.product_store.list_resources("detection")) == int(commit_first)
    assert access.calls == [PLAN_PURPOSE, PURPOSE]


def test_existing_executable_identity_never_overwritten(setup):
    service, access, request = setup
    _, envelope = proposal(setup)
    accepted = service.review_detection_create(
        envelope["job"]["job_id"], decision(service, envelope)
    )
    service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    original = service.product_store.list_resources("detection")
    request["submission_id"] = str(uuid.uuid4())
    _, another = proposal(setup)
    accepted = service.review_detection_create(
        another["job"]["job_id"],
        decision(service, another, title="A different title cannot overwrite the saved origin"),
    )
    done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    assert done["state"] == "failed", done
    assert done["progress"]["operation_error_code"] == "detection_creation_identity_exists"
    assert service.product_store.list_resources("detection") == original


def test_changed_provider_or_exact_edit_refuses_acceptance(setup):
    service, access, request = setup
    _, envelope = proposal(setup)
    body = decision(service, envelope)
    with pytest.raises(APIError):
        service.review_detection_create(
            envelope["job"]["job_id"], {**body, "source": SQL + " AND size_bytes > 0"}
        )
    config = service._runtime_ai_config
    provider = config.provider(request["provider_id"])
    service._runtime_ai_config = replace(
        config,
        providers=tuple(
            replace(row, model="changed-model") if row.id == provider.id else row
            for row in config.providers
        ),
    )
    with pytest.raises(APIError):
        service.review_detection_create(envelope["job"]["job_id"], body)
    assert service.product_store.list_resources("detection") == []


def test_stale_source_admission_is_durable_and_no_provider(setup):
    service, access, request = setup
    stale = {
        **request,
        "selection": {**request["selection"], "source_binding_digest": "sha256:" + "0" * 64},
    }
    submitted = service.submit_assistance_turn(stale)
    done = service.job_controller.wait(submitted["job"]["job_id"], timeout=15)
    assert done["state"] == "failed"
    assert service.assistance_turn(done["job_id"])["turn"]["can_start_new_turn"] is True
    assert service.submit_assistance_turn(stale)["job"]["job_id"] == done["job_id"]
    assert access.calls == []


def test_normal_lifecycle_change_preserves_immutable_creation_receipt(setup):
    service, access, _ = setup
    parent_id, envelope = proposal(setup)
    body = decision(service, envelope)
    accepted = service.review_detection_create(envelope["job"]["job_id"], body)
    service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
    before = service.detection_create_job(envelope["job"]["job_id"])
    service.reject_detection_candidate(
        before["application"]["candidate_id"],
        {"reason": "Useful development record, but this broad rule is unsuitable for deployment."},
    )
    after = service.detection_create_job(envelope["job"]["job_id"])
    assert (
        after["application"] == before["application"]
        and after["evaluation"] == before["evaluation"]
    )
    assert (
        service.review_detection_create(envelope["job"]["job_id"], body)["application"]
        == before["application"]
    )
    assert service.assistance_turn(parent_id)["turn"]["status"] == "completed"
    assert access.calls == [PLAN_PURPOSE, PURPOSE]


def test_unavailable_parser_refuses_before_planner_request(setup, monkeypatch):
    service, access, request = setup
    original = service.detection_lab.validator.health()
    monkeypatch.setattr(
        service.detection_lab.validator,
        "health",
        lambda: {**original, "pySigma": {**original["pySigma"], "ready": False}},
    )
    request["selection"]["target_language"] = "sigma"
    context = service.detection_creation_context(
        {k: v for k, v in request["selection"].items() if k != "kind"}
    )
    assert context["capabilities"][0]["available"] is False
    request["context_digest"] = context["context_digest"]
    job = service.submit_assistance_turn(request)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "failed"
    assert access.calls == []


def test_tampered_initial_snapshot_refuses_historical_result(setup):
    from bluefire.product_store_assistance import job_at, patch
    from bluefire.product_store_errors import ProductStoreError

    service, _, _ = setup
    _, envelope = proposal(setup)
    accepted = service.review_detection_create(
        envelope["job"]["job_id"], decision(service, envelope)
    )
    app_id = accepted["application_job"]["job_id"]
    service.job_controller.wait(app_id, timeout=20)
    with service.product_store._connection(write=True) as connection:
        app = job_at(service.product_store, connection, app_id)
        changed = {
            **app["progress"]["candidate_document"],
            "rule_source": SQL + " AND size_bytes > 0",
        }
        patch(connection, app, {"candidate_document": changed})
    with pytest.raises((ProductStoreError, ValueError)):
        service.detection_create_job(envelope["job"]["job_id"])


@pytest.mark.parametrize("location", ["proposal", "review"])
def test_credential_shaped_text_never_enters_job_progress(setup, location):
    import secrets

    service, access, _ = setup
    synthetic = "sk-" + secrets.token_urlsafe(32)
    if location == "proposal":
        access.transform = lambda value: {**value, "reason": synthetic}
        parent = service.submit_assistance_turn(setup[2])["job"]
        service.job_controller.wait(parent["job_id"], timeout=20)
        child_id = service.product_store.get_job(parent["job_id"])["progress"]["children"][
            "step-1"
        ]["job_id"]
        done = service.job_controller.wait(child_id, timeout=20)
        assert done["state"] == "failed"
        assert "proposal" not in done["progress"]
    else:
        _, envelope = proposal(setup)
        body = decision(service, envelope)
        with pytest.raises(APIError) as error:
            service.review_detection_create(
                envelope["job"]["job_id"], {**body, "reviewed_by": synthetic}
            )
        assert error.value.code == "detection_creation_content_refused"
        assert service.detection_create_job(envelope["job"]["job_id"])["decision"] is None
    with service.product_store._connection() as connection:
        rows = connection.execute(
            "SELECT request_json, progress_json, error_json FROM jobs"
        ).fetchall()
        assert all(synthetic not in str(tuple(row)) for row in rows)
    assert not service.product_store.list_resources("detection")


@pytest.mark.parametrize("point", ["before", "after"])
@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
def test_process_loss_application_reopens_exact_decision_without_provider(tmp_path, point, kind):
    import subprocess
    import sys

    program = r"""
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from tests_platform.test_detection_create_jobs import setup, proposal, decision
from bluefire import product_store_detection_create as records
root, kind, point = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
fixture = setup.__wrapped__(root, SimpleNamespace(param=kind))
data = next(fixture)
service, access, request = data
parent_id, envelope = proposal(data)
body = decision(service, envelope)
(root/'crash-receipt.json').write_text(json.dumps({'parent':parent_id,'proposal':envelope['job']['job_id'],'body':body,'provider':service._runtime_ai_config.provider(request['provider_id']).to_dict()}),encoding='utf-8')
original = records.apply
def crash(*args, **kwargs):
    if point == 'after': original(*args, **kwargs)
    os._exit(77)
records.apply = crash
accepted = service.review_detection_create(envelope['job']['job_id'], body)
service.job_controller.wait(accepted['application_job']['job_id'], timeout=20)
raise AssertionError('Expected process loss')
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path), kind, point],
        cwd=ROOT,
        capture_output=True,
        timeout=50,
        check=False,
    )
    assert process.returncode == 77, process.stderr.decode(errors="replace")
    saved = json.loads((tmp_path / "crash-receipt.json").read_text(encoding="utf-8"))
    access = Access()
    reopened = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(saved["provider"])
    reopened._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        reopened.config.ai.fallback_provider,
        (provider, *reopened.config.ai.providers),
    )
    try:
        native = reopened.detection_create_job(saved["proposal"])
        assert bool(native["application"]) is (point == "after")
        result = reopened.review_detection_create(saved["proposal"], saved["body"])
        if point == "before":
            assert result["application_job"]["job_id"] != native["application_job"]["job_id"]
            done = reopened.job_controller.wait(result["application_job"]["job_id"], timeout=20)
            assert done["state"] == "completed", done
        assert reopened.detection_create_job(saved["proposal"])["application"]
        assert len(reopened.product_store.list_resources("detection")) == 1
        assert reopened.assistance_turn(saved["parent"])["turn"]["status"] == "completed"
        assert access.calls == []
    finally:
        reopened.close()
