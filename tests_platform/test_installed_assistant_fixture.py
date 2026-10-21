"""Pure contract tests for the optional installed Assistant loopback fixture."""

from __future__ import annotations

from copy import deepcopy

import pytest

from tools.verify_installed_browser import (
    _FIXTURE_MODEL,
    _FIXTURE_PURPOSES,
    _fixture_outputs,
    _fixture_request_allowed,
)


def request_for(purpose: str) -> dict[str, object]:
    return {
        "model": _FIXTURE_MODEL,
        "instructions": "Bounded fixture instructions",
        "input": "Bounded fixture input",
        "max_output_tokens": 64,
        "store": False,
        "parallel_tool_calls": False,
        "tools": [],
        "tool_choice": "none",
        "text": {
            "format": {
                "type": "json_schema",
                "name": purpose,
                "schema": {"type": "object"},
                "strict": True,
            }
        },
    }


def allowed(
    request: object,
    *,
    index: int,
    total_bytes: int = 0,
    auth: str | None = None,
    body_bytes: int = 100,
) -> bool:
    purpose = _FIXTURE_PURPOSES[index] if index < len(_FIXTURE_PURPOSES) else None
    model = request.get("model") if isinstance(request, dict) else None
    return _fixture_request_allowed(
        request,
        purpose=purpose,
        model=model,
        body_bytes=body_bytes,
        authorization=auth,
        request_index=index,
        accumulated_bytes=total_bytes,
    )


@pytest.mark.parametrize("index", [0, 1])
def test_fixture_accepts_only_the_two_ordered_structured_purposes(index: int) -> None:
    purpose = _FIXTURE_PURPOSES[index]
    assert allowed(request_for(purpose), index=index)


def test_fixture_rejects_purposes_in_the_wrong_order() -> None:
    assert not allowed(request_for(_FIXTURE_PURPOSES[1]), index=0)


@pytest.mark.parametrize(
    ("index", "mutation", "auth", "total_bytes"),
    [
        (0, lambda request: request.update(model="other-model"), None, 0),
        (
            0,
            lambda request: request["text"]["format"].update(name="bluefire_ai_graph_draft"),
            None,
            0,
        ),
        (0, lambda request: request.update(extra="field"), None, 0),
        (0, lambda request: request.update(store=True), None, 0),
        (0, lambda request: request.update(max_output_tokens=65), None, 0),
        (0, lambda request: None, "Bearer secret", 0),
        (0, lambda request: None, None, 2_097_053),
        (2, lambda request: None, None, 0),
    ],
)
def test_fixture_rejects_out_of_scope_envelopes(
    index: int, mutation, auth: str | None, total_bytes: int
) -> None:
    request = (
        deepcopy(request_for(_FIXTURE_PURPOSES[index])) if index < 2 else request_for("unexpected")
    )
    mutation(request)
    assert not allowed(request, index=index, auth=auth, total_bytes=total_bytes)


def test_fixture_output_is_two_registered_nonexecuting_proposals() -> None:
    outputs = _fixture_outputs()
    assert tuple(outputs) == _FIXTURE_PURPOSES
    assert (
        outputs[_FIXTURE_PURPOSES[0]]["steps"][0]["capability_id"] == "graph.propose_and_validate"
    )
    draft = outputs[_FIXTURE_PURPOSES[1]]
    assert len(draft["steps"]) == 2
    assert draft["steps"][0]["parameters"]["record_count"] == 4


def test_fixture_rejects_per_request_byte_limit() -> None:
    request = request_for(_FIXTURE_PURPOSES[0])
    assert not allowed(request, index=0, body_bytes=1_048_577)
    assert not allowed(request, index=0, body_bytes=0)
