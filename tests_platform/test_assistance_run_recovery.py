"""Real process-loss recovery never redispatches a completed native run."""

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.assistance_run_recovery_diagnostics import process_loss_timeout_diagnostics
from tests_platform.test_graph_ai_jobs import Access

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
@pytest.mark.parametrize("boundary", ["run_link", "inspection_published"])
def test_process_loss_after_run_link_or_inspection_publication_resumes_only_retained_run(
    tmp_path, kind, boundary, monkeypatch
):
    database, marker = tmp_path / "crash.sqlite3", tmp_path / "marker.json"
    program = r"""
from tests_platform.assistance_run_recovery_diagnostics import record_child_failure, record_phase
record_phase('imports')
with record_child_failure():
 import json,os,sys,uuid
 from pathlib import Path
 from bluefire.config import AIConfig,AIProviderConfig,AutonomyLevel
 from bluefire.service import BlueFireService
 from tests_platform.ai_live_authorization_support import authorize_service
 from tests_platform.test_graph_ai_jobs import Access
 from tests_platform.test_assistance_saved_runs import run_context,prepared
 database,marker,kind,boundary=sys.argv[1:]
 record_phase('service_init')
 access=Access()
 service=BlueFireService(project_root=Path.cwd(),runs_dir=Path(database).parent/'runs',product_db_path=database,ai_provider_access=access)
 provider=AIProviderConfig.from_mapping({'id':'provider.graph-crash.v1','kind':kind,'model':'unit-model','endpoint':'http://127.0.0.1:8765/v1/'+('responses' if kind=='openai_responses' else 'chat/completions')})
 service._runtime_ai_config=AIConfig(AutonomyLevel.OFF,provider.id,service.config.ai.fallback_provider,(provider,*service.config.ai.providers))
 record_phase('authorization')
 authorize_service(service, provider)
 record_phase('graph_context')
 context=service.assistance_graph_context()
 body={'submission_id':str(uuid.uuid4()),'selection':context['selected'],'context_digest':context['context_digest'],'message':'Propose a registered graph for review.','autonomy':'assist','provider_id':provider.id}
 record_phase('graph_prepare')
 request=run_context(service,access,body)
 record_phase('run_prepare')
 parent,child,envelope=prepared(service,request)
 record_phase('hook_install')
 def crash():
  with record_child_failure():
   record_phase('crash_boundary')
   Path(marker).write_text(json.dumps({'parent_id':parent['job_id'],'child_id':child['job_id'],'provider':provider.to_dict(),'request':request}),encoding='utf-8')
   record_phase('marker_written')
   os._exit(77)
 if boundary=='run_link':
  service.assistance_runs._start_inspection=lambda *_a,**_k:crash()
 else:
  original=service.assistance_runs._inspect
  def inspected(ctx, request):
   with record_child_failure():
    record_phase('inspection')
    original(ctx,request)
   crash()
  service.assistance_runs._inspect=inspected
 record_phase('review')
 accepted=service.review_assistance_run(child['job_id'],{'decision':'accept','preparation_digest':envelope['preparation']['preparation_digest']})
 record_phase('run_wait')
 service.job_controller.wait(accepted['job']['progress']['run_job_id'],timeout=15)
 import threading
 record_phase('fallback_wait')
 threading.Event().wait(15)
 raise AssertionError('Expected process-loss boundary')
"""
    with process_loss_timeout_diagnostics():
        process = subprocess.run(
            [sys.executable, "-c", program, str(database), str(marker), kind, boundary],
            cwd=ROOT,
            capture_output=True,
            timeout=45,
            check=False,
        )
    assert process.returncode == 77, process.stderr.decode(errors="replace")
    receipt = json.loads(marker.read_text(encoding="utf-8"))
    access = Access()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=database,
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(receipt["provider"])
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    try:
        monkeypatch.setattr(
            service,
            "submit_run",
            lambda *_a, **_k: pytest.fail("Recovery cannot submit another run"),
        )
        before = service.assistance_run_job(receipt["child_id"])
        run_id = before["run_job"]["result_ref"]
        assert run_id
        recovery = service.continue_assistance_turn(
            receipt["parent_id"],
            {
                "submission_id": str(uuid.uuid4()),
                "context_digest": receipt["request"]["context_digest"],
            },
        )
        service.job_controller.wait(recovery["turn"]["continuation"]["job_id"], timeout=15)
        envelope = service.assistance_run_job(receipt["child_id"])
        assert envelope["inspection_job"]
        service.job_controller.wait(envelope["inspection_job"]["job_id"], timeout=15)
        envelope = service.assistance_run_job(receipt["child_id"])
        assert envelope["result"]["run_id"] == run_id
        assert service.assistance_turn(receipt["parent_id"])["turn"]["status"] == "completed"
        assert len(service.store.list_runs()) == 1 and access.calls == []
        if boundary == "inspection_published":
            assert envelope["inspection_job"]["job_id"] == before["inspection_job"]["job_id"]
    finally:
        service.close()
