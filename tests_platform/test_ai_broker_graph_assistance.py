"""Graph planning and drafting traverse actual enrolled fixed-purpose framing."""

import uuid
from pathlib import Path

import pytest

from bluefire.ai_assistance import PURPOSE
from bluefire.config import AIProviderKind
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from tests_platform import test_ai_broker_channel as support
from tests_platform.test_graph_ai_jobs import Access, proposed

pair = support.pair
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_enrolled_graph_turn_and_proposal_retain_native_review_boundary(
    tmp_path, pair, kind, monkeypatch
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
        parent, child, proposal = proposed(service, body)
        assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "awaiting_review"
        assert service.graph_ai_job(child["job_id"])["application"] is None
        assert proposal["provider"]["used_fallback"] is False
        assert fixture.calls == [PURPOSE, "bluefire_ai_graph_draft"]
        assert service.store.list_runs() == []
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []
