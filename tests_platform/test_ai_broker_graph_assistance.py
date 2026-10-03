"""Graph planning and drafting traverse actual enrolled fixed-purpose framing."""

import json
import sys
import uuid
from pathlib import Path

import pytest

from bluefire.ai_assistance import PURPOSE
from bluefire.ai_method_comparison import PURPOSE as METHOD_PURPOSE
from bluefire.config import AIProviderKind
from bluefire.graph_ai_edit import PURPOSE as EDIT_PURPOSE
from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from tests_platform import test_ai_broker_channel as support
from tests_platform.ai_live_authorization_support import authorize_service
from tests_platform.test_graph_ai_jobs import Access, proposed
from tests_platform.test_graph_ai_step_edit import configure

pair = support.pair
ROOT = Path(__file__).resolve().parents[1]


def _timeout_evidence(
    phase, fixture, worker, errors, *, cleanup_completed=None, timeout=None, wait_stage=None
):
    """Bounded labels only; an optional timeout supplies its already-read job snapshot."""
    try:
        evidence = {"phase": phase}
        if timeout is not None:
            evidence["phase"] = phase if phase in {"before_cleanup", "cleanup_exit"} else "unknown"
            evidence["wait_stage"] = (
                wait_stage
                if type(wait_stage) is str and wait_stage in {"proposal_wait", "replay_wait"}
                else "unknown"
            )
            trace = timeout.__traceback__
            evidence["last_wait_job"] = {"available": False}
            for _ in range(32):
                if trace is None:
                    break
                if trace.tb_frame.f_code is RunJobController.wait_for_state.__code__:
                    snapshot = trace.tb_frame.f_locals.get("snapshot")
                    if type(snapshot) is dict:
                        progress = snapshot.get("progress")
                        progress = progress if type(progress) is dict else {}
                        states = {state.value for state in JobState}
                        labels = {
                            "state": (snapshot.get("state"), states),
                            "phase": (progress.get("phase"), states | {"cleanup", "finalizing"}),
                            "operation_phase": (
                                progress.get("operation_phase"),
                                {"choosing_method", "proposal_available", "comparing_detections"},
                            ),
                        }
                        evidence["last_wait_job"] = {
                            "available": True,
                            **{
                                key: value if type(value) is str and value in allowed else "unknown"
                                for key, (value, allowed) in labels.items()
                            },
                            "has_result_ref": snapshot.get("result_ref") is not None,
                            "has_comparison": "comparison" in progress,
                        }
                    break
                trace = trace.tb_next
        if phase == "before_cleanup":
            stacks = []
            for frame in list(sys._current_frames().values())[:32]:
                frames = []
                for _ in range(24):
                    if timeout is not None:
                        permitted_functions = {
                            "wait",
                            "join",
                            "_worker",
                            "run",
                            "_run_job",
                            "wait_for_state",
                            "_checkpoint",
                            "_transition",
                            "_execute_job",
                            "_execute_job_inner",
                            "_execute_replay_job",
                            "_review_replay_job",
                            "_replay_catalog_lease",
                            "_replay_locked",
                            "_resolve_replay_source_locked",
                            "_index_run",
                            "_simulate_step",
                            "before_replay",
                            "after_replay",
                            "_finish",
                            "_finish_checked",
                            "build",
                            "commit_comparison",
                            "build_run_evaluation",
                            "_source",
                            "compare_runs",
                            "validate_bundle",
                            "get_run",
                            "get_job",
                            "_connection",
                            "pinned_regular_file_identity",
                            "_owner_private_native_handle",
                            "serve_broker",
                            "recv",
                            "send",
                            "_read_exact",
                            "_write_all",
                        }
                        name = frame.f_code.co_name
                        frames.append(name if name in permitted_functions else "other")
                    else:
                        frames.append(
                            {
                                "file": Path(frame.f_code.co_filename).name,
                                "function": frame.f_code.co_name,
                                "line": frame.f_lineno,
                            }
                        )
                    frame = frame.f_back
                    if frame is None:
                        break
                stacks.append(frames)
            evidence["thread_functions" if timeout is not None else "thread_stacks"] = stacks
        permitted = {PURPOSE, EDIT_PURPOSE, "bluefire_ai_graph_draft"}
        if timeout is not None:
            permitted.add(METHOD_PURPOSE)
        error_types = [type(error).__name__ for error in errors[:16]]
        if timeout is not None:
            error_types = [
                (
                    name
                    if name
                    in {
                        "RuntimeError",
                        "ValueError",
                        "OSError",
                        "JobWaitTimeout",
                        "AIProviderError",
                        "AIProviderTransportError",
                        "AIProviderCancelled",
                    }
                    else "other"
                )
                for name in error_types
            ]
        evidence.update(
            purposes=[
                call if (timeout is None or type(call) is str) and call in permitted else "unknown"
                for call in fixture.calls[:16]
            ],
            broker_worker_alive=worker.is_alive(),
            broker_error_types=error_types,
        )
        if cleanup_completed is not None:
            evidence["cleanup_completed"] = cleanup_completed
        print("Broker timeout evidence: " + json.dumps(evidence, sort_keys=True), flush=True)
    except BaseException:
        # Diagnostics must not replace the original test failure, even if output fails.
        pass


@pytest.mark.parametrize("operation", ["new", "edit"])
@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_enrolled_graph_turn_and_proposal_retain_native_review_boundary(
    tmp_path, pair, kind, monkeypatch, operation
):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    fixture = Access()
    monkeypatch.setattr(
        transport,
        "post",
        lambda url, *, headers, body, timeout_seconds: fixture.post(
            provider, body=body, timeout_seconds=timeout_seconds
        ),
    )
    service = BlueFireService(
        project_root=ROOT,
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )
    authorize_service(service, provider)
    timed_out = False
    try:
        context = service.assistance_graph_context()
        body = {
            "submission_id": str(uuid.uuid4()),
            "selection": context["selected"],
            "context_digest": context["context_digest"],
            "message": "Propose a separate registered graph for native review.",
            "autonomy": "auto",
            "provider_id": provider.id,
        }
        if operation == "edit":
            configure(service, fixture, body, monkeypatch)
        parent, child, proposal = proposed(service, body)
        assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "awaiting_review"
        assert service.graph_ai_job(child["job_id"])["application"] is None
        assert proposal["provider"]["used_fallback"] is False
        assert fixture.calls == [
            PURPOSE,
            EDIT_PURPOSE if operation == "edit" else "bluefire_ai_graph_draft",
        ]
        assert service.store.list_runs() == []
    except JobWaitTimeout:
        timed_out = True
        _timeout_evidence("before_cleanup", fixture, worker, errors)
        raise
    finally:
        cleanup_completed = False
        try:
            service.close()
            worker.join(3)
            cleanup_completed = True
        finally:
            if timed_out:
                _timeout_evidence(
                    "cleanup_exit", fixture, worker, errors, cleanup_completed=cleanup_completed
                )
    assert not worker.is_alive() and errors == []
