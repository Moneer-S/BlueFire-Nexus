"""Continuation receipt repair never reschedules the durable job or rolls back a newer link."""

import json
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest

import bluefire.assistance_turns as turns
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.test_graph_ai_jobs import Access, proposed
from tests_platform.test_graph_ai_jobs import setup as setup

ROOT = Path(__file__).resolve().parents[1]


def test_late_new_attachment_and_old_retry_preserve_newer_receipt(setup, monkeypatch):
    service, access, body = setup
    parent, _, _ = proposed(service, body)
    first = {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
    second = {**first, "submission_id": str(uuid.uuid4())}
    first_id, second_id = [
        "job-" + request["submission_id"].replace("-", "") for request in (first, second)
    ]
    entered, release = threading.Event(), threading.Event()
    original = turns.attach_continuation
    errors = []

    def held(store, parent_id, continuation_id):
        if continuation_id == first_id:
            entered.set()
            assert release.wait(10)
        original(store, parent_id, continuation_id)

    monkeypatch.setattr(turns, "attach_continuation", held)

    def submit_first():
        try:
            service.continue_assistance_turn(parent["job_id"], first)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=submit_first)
    thread.start()
    try:
        assert entered.wait(10)
        service.continue_assistance_turn(parent["job_id"], second)
        assert service.job_controller.wait(second_id, timeout=15)["state"] == "completed"
    finally:
        release.set()
        thread.join(timeout=15)
    assert not thread.is_alive() and errors == []
    assert service.job_controller.wait(first_id, timeout=15)["state"] == "completed"
    assert (
        service.continue_assistance_turn(parent["job_id"], first)["turn"]["continuation"]["job_id"]
        == second_id
    )
    assert len(access.calls) == 2


@pytest.mark.parametrize("phase,previous", [("interrupted", False), ("completed", True)])
def test_process_loss_before_attachment_recovers_exact_receipt_without_work(
    tmp_path, phase, previous, monkeypatch
):
    database, marker = tmp_path / "crash.sqlite3", tmp_path / "submitted.json"
    program = r"""
import json,os,sys,threading,uuid
from pathlib import Path
from bluefire.config import AIConfig,AIProviderConfig,AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.test_graph_ai_jobs import Access,proposed
database,marker,phase,previous=sys.argv[1:]
access=Access()
service=BlueFireService(project_root=Path.cwd(),runs_dir=Path(database).parent/'runs',product_db_path=database,ai_provider_access=access)
provider=AIProviderConfig.from_mapping({'id':'provider.continuation-crash.v1','kind':'openai_responses','model':'unit-model','endpoint':'http://127.0.0.1:8765/v1/responses'})
service._runtime_ai_config=AIConfig(AutonomyLevel.OFF,provider.id,service.config.ai.fallback_provider,(provider,*service.config.ai.providers))
context=service.assistance_graph_context()
body={'submission_id':str(uuid.uuid4()),'selection':context['selected'],'context_digest':context['context_digest'],'message':'Prepare a separate registered graph.','autonomy':'assist','provider_id':provider.id}
parent,child,_=proposed(service,body)
old_id=None
if previous=='True':
    old={'submission_id':str(uuid.uuid4()),'context_digest':body['context_digest']}
    service.continue_assistance_turn(parent['job_id'],old)
    old_id='job-'+old['submission_id'].replace('-','')
    assert service.job_controller.wait(old_id,timeout=15)['state']=='completed'
request={'submission_id':str(uuid.uuid4()),'context_digest':body['context_digest']}
entered=threading.Event()
if phase=='interrupted':
    def held(ctx,document):
        entered.set()
        threading.Event().wait(20)
        raise AssertionError('Expected process exit before callback resumes')
    service.assistance._continue=held
submit=service.job_controller.submit
def crash_after_submit(*args,**kwargs):
    continuation=submit(*args,**kwargs)
    if phase=='completed':
        assert service.job_controller.wait(continuation['job_id'],timeout=15)['state']=='completed'
    else:
        assert entered.wait(10)
    assert service.product_store.get_job(parent['job_id'])['progress'].get('continuation_job_id')==old_id
    Path(marker).write_text(json.dumps({'parent_id':parent['job_id'],'child_id':child['job_id'],'continuation_id':continuation['job_id'],'request':request,'provider':provider.to_dict(),'old_id':old_id,'calls':access.calls}),encoding='utf-8')
    os._exit(78)
service.job_controller.submit=crash_after_submit
service.continue_assistance_turn(parent['job_id'],request)
raise AssertionError('Expected owned process loss')
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(database), str(marker), phase, str(previous)],
        cwd=ROOT,
        capture_output=True,
        timeout=40,
        check=False,
    )
    assert process.returncode == 78, process.stderr.decode(errors="replace")
    retained = json.loads(marker.read_text(encoding="utf-8"))
    access = Access()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=database,
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(retained["provider"])
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    try:
        before = service.assistance_turn(retained["parent_id"])
        assert before["job"]["progress"].get("continuation_job_id") == retained["old_id"]
        durable = service.job(retained["continuation_id"])
        assert durable["state"] == phase

        def forbidden(*args, **kwargs):
            pytest.fail("Exact receipt repair must not submit or advance work")

        monkeypatch.setattr(service.job_controller, "submit", forbidden)
        monkeypatch.setattr(service.assistance, "_advance", forbidden)
        repaired = service.continue_assistance_turn(retained["parent_id"], retained["request"])
        continuation = repaired["turn"]["continuation"]
        assert continuation == {
            "job_id": retained["continuation_id"],
            "submission_id": retained["request"]["submission_id"],
            "state": phase,
            "context_digest": retained["request"]["context_digest"],
        }
        assert repaired["turn"]["status"] == "awaiting_review"
        assert service.job(retained["continuation_id"]) == durable
        assert (
            service.continue_assistance_turn(retained["parent_id"], retained["request"]) == repaired
        )
        service.cancel_job(retained["parent_id"])
        stopped = service.continue_assistance_turn(retained["parent_id"], retained["request"])
        assert stopped["turn"]["status"] == "cancelled"
        assert stopped["job"]["progress"]["stopped"] is True
        assert service.job(retained["continuation_id"]) == durable
        assert access.calls == [] and len(retained["calls"]) == 2
    finally:
        service.close()
