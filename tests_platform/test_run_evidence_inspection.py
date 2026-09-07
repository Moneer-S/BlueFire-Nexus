"""Both enrolled wire dialects validate exact observed references without raw values."""

import json
import threading

import pytest

from bluefire.ai_broker_contract import schema_identity
from bluefire.ai_run_inspection import OUTPUT_SCHEMA, PURPOSE, inspect
from bluefire.ai_wire import AIProviderError
from bluefire.config import AIProviderKind
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_broker_channel import pair as pair
from tests_platform.test_ai_broker_channel import start
from tests_platform.test_ai_wire_runtime import _envelope


def source():
    run_id = "run-20260907T000000Z-" + "1" * 16
    record = EvidenceRecord.create(
        run_id=run_id,
        step_id="inspect",
        behavior_id="sandbox.discovery.list.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="unit-collector",
        target_scope_ref="workspace",
        content={"retained_value_count": 6, "private_body": "private-content-must-not-leave"},
    )
    return {
        "run": {"run_id": run_id, "mode": "execute", "objective_reached": True},
        "records": [record],
        "observed": [record],
        "run_digest": content_hash({"synthetic": "unit"}),
        "cleanup_state": "complete",
    }


@pytest.mark.parametrize("kind", [AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS])
@pytest.mark.parametrize("invalid", [False, True])
def test_inspection_uses_exact_enrolled_schema_and_observed_reference_policy(pair, kind, invalid):
    provider, enrollment, access, transport, worker, errors = start(pair, kind)
    selected = source()

    def post(url, *, headers, body, timeout_seconds):
        assert headers["Authorization"] == "Bearer synthetic-broker-only"
        assert schema_identity(body, kind) == (PURPOSE, content_hash(OUTPUT_SCHEMA))
        wire = json.loads(body)
        transport.requests.append(wire)
        supplied = json.loads(
            wire["input"]
            if kind is AIProviderKind.OPENAI_RESPONSES
            else wire["messages"][1]["content"]
        )
        assert supplied["observations"] == [
            {
                "evidence_id": selected["observed"][0].evidence_id,
                "field_types": {"retained_value_count": "int", "private_body": "str"},
            }
        ]
        assert "private-content-must-not-leave" not in body.decode()
        output = {
            "summary": "The collector retained one observed record.",
            "findings": [
                {
                    "claim": "The observed record exposes a retained value count field.",
                    "evidence_refs": [
                        "evidence-" + "0" * 20 if invalid else selected["observed"][0].evidence_id
                    ],
                }
            ],
            "limitations": [
                "The field shape does not establish its exact value or defensive effectiveness."
            ],
        }
        return canonical_json_bytes(_envelope(kind, output))

    transport.post = post
    try:
        if invalid:
            with pytest.raises(AIProviderError, match="unavailable evidence"):
                inspect(
                    selected,
                    config=provider,
                    access=access,
                    cancel=threading.Event(),
                    objective="Inspect retained observations.",
                )
        else:
            report = inspect(
                selected,
                config=provider,
                access=access,
                cancel=threading.Event(),
                objective="Inspect retained observations.",
            )
            assert report["status"] == "supported" and report["model_interpretation"] is True
            assert report["observed_records"] == report["total_records"] == 1
            assert report["provider"]["provider_id"] == provider.id
        assert len(transport.requests) == 1
    finally:
        access.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("mode", ["execute", "simulate"])
def test_no_observations_are_insufficient_without_any_provider_access(mode):
    from tests_platform.test_ai_wire_runtime import _provider_config

    selected = source()
    selected["run"]["mode"] = mode
    selected["observed"] = []

    class Forbidden:
        def readiness(self, *_):
            pytest.fail("No observed evidence may not probe a provider")

        def post(self, *_, **__):
            pytest.fail("No observed evidence may not call a model")

    report = inspect(
        selected,
        config=_provider_config(AIProviderKind.CHAT_COMPLETIONS),
        access=Forbidden(),
        cancel=threading.Event(),
        objective="Inspect actual evidence.",
    )
    assert (
        report["status"] == "insufficient"
        and report["provider"] is None
        and not report["model_interpretation"]
    )
    if mode == "execute":
        assert not any("Simulate" in text for text in report["limitations"])
