from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from bluefire.strix_tool_capture import (
    MAX_CAPTURE_REQUEST_BYTES,
    ToolCaptureError,
    capture_tool_profile,
    verify_tool_profile_capture,
)
from bluefire.strix_tool_conformance import (
    APPROVED_PROFILE_DIGESTS,
    MODEL_ID,
    PROVIDER_ID,
    SDK_VERSION,
    SOURCE_COMMIT,
    SOURCE_TREE,
    OfflineRootToolProfile,
    ToolConformanceError,
    canonical_json,
    digest_json,
)
from tests_platform.strix_provider_profile_fixture import synthetic_tools

PROMPT = "private prompt and tool result must never be captured"
MATERIAL = "protected-bearer-fixture-material"  # pragma: allowlist secret


def _request() -> dict[str, Any]:
    return {
        "model": MODEL_ID,
        "messages": [{"role": "user", "content": PROMPT}],
        "tools": synthetic_tools(),
        "stream": True,
        "parallel_tool_calls": False,
        "stream_options": {"include_usage": True},
    }


def _source() -> dict[str, str]:
    return {
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "sdk_version": SDK_VERSION,
        "model_id": MODEL_ID,
        "provider_id": PROVIDER_ID,
    }


def _capture(request: dict[str, Any] | None = None) -> dict[str, Any]:
    return capture_tool_profile(
        canonical_json(_request() if request is None else request), **_source()
    )


def test_exact_descriptor_candidate_discards_prompts_and_requires_independent_review() -> None:
    request = _request()
    candidate = _capture(request)
    encoded = canonical_json(candidate)
    assert PROMPT.encode() not in encoded
    assert b'"messages"' not in encoded
    assert candidate["chat_completions_tools"] == request["tools"]
    assert candidate["tools_digest"] == digest_json(request["tools"])
    assert candidate["profile_digest"] == digest_json(candidate["profile"])
    assert candidate["source_provenance"] == {
        "identity_status": "caller_declared_pinned",
        **_source(),
    }
    assert candidate["approval_state"] == "independent_code_review_required"
    assert candidate["installed_runtime_proof"] is False
    assert candidate["live_model_proof"] is False
    digest_input = {key: value for key, value in candidate.items() if key != "candidate_digest"}
    assert candidate["candidate_digest"] == digest_json(digest_input)
    assert not APPROVED_PROFILE_DIGESTS
    with pytest.raises(ToolConformanceError, match="not independently enrolled"):
        OfflineRootToolProfile.from_mapping(candidate["profile"]).require_enrolled()
    verify_tool_profile_capture(candidate, canonical_json(request))


def test_candidate_is_deterministic_and_later_prompt_changes_are_not_schema_drift() -> None:
    request = _request()
    first = _capture(request)
    request["messages"] = [{"role": "user", "content": "different private content"}]
    assert first == _capture(request)
    verify_tool_profile_capture(first, canonical_json(request))
    first["chat_completions_tools"][0]["function"]["description"] = "mutated candidate"
    assert _capture(request)["chat_completions_tools"] == request["tools"]


@pytest.mark.parametrize("field", list(_source()))
def test_declared_source_identity_must_match_every_pin(field: str) -> None:
    source = _source()
    source[field] = "drifted"
    with pytest.raises(ToolCaptureError, match="source identity"):
        capture_tool_profile(canonical_json(_request()), **source)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda request: request.update(model="different-model"),
        lambda request: request.update(authorization=MATERIAL),
        lambda request: request.update(headers={"authorization": MATERIAL}),
        lambda request: request["tools"].reverse(),
        lambda request: request["tools"].pop(),
        lambda request: request["tools"][0]["function"].update(strict=False),
        lambda request: request["tools"][0]["function"].update(extra=MATERIAL),
        lambda request: request["tools"][0].update(credential=MATERIAL),
        lambda request: request["tools"][0]["function"].update(parameters=[]),
    ],
)
def test_capture_rejects_unreviewed_request_and_descriptor_shapes(mutation: Any) -> None:
    request = _request()
    mutation(request)
    with pytest.raises(ToolCaptureError) as caught:
        _capture(request)
    assert MATERIAL not in str(caught.value)
    assert PROMPT not in str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda request: request["tools"][0]["function"].update(description="schema changed"),
        lambda request: request["tools"][0]["function"]["parameters"].update(title="changed"),
        lambda request: request["tools"].reverse(),
    ],
)
def test_verification_rejects_exact_descriptor_or_order_drift(mutation: Any) -> None:
    request = _request()
    candidate = _capture(request)
    mutation(request)
    with pytest.raises(ToolCaptureError):
        verify_tool_profile_capture(candidate, canonical_json(request))


@pytest.mark.parametrize(
    "field,value",
    [
        ("installed_runtime_proof", True),
        ("approval_state", "approved"),
        ("candidate_digest", "sha256:" + "0" * 64),
        ("tools_digest", "sha256:" + "0" * 64),
        ("source_provenance", {}),
    ],
)
def test_verification_rejects_candidate_metadata_tampering(field: str, value: Any) -> None:
    request = _request()
    candidate = _capture(request)
    candidate[field] = value
    with pytest.raises(ToolCaptureError):
        verify_tool_profile_capture(candidate, canonical_json(request))


@pytest.mark.parametrize(
    "body",
    [
        b'{"model":1,"model":2}',
        b'{"model":NaN}',
        b'{"model":1e999}',
        b'{"model":"' + PROMPT.encode() + b'"',
        b"\xff",
        b"[]",
        b" ",
        b"x" * (MAX_CAPTURE_REQUEST_BYTES + 1),
        b'{"value":' * 40 + b"null" + b"}" * 40,
    ],
    ids=["duplicate", "nan", "overflow", "truncated", "utf8", "array", "empty", "large", "deep"],
)
def test_invalid_json_and_bounds_have_static_nonreflective_failures(body: bytes) -> None:
    with pytest.raises(ToolCaptureError) as caught:
        capture_tool_profile(body, **_source())
    assert PROMPT not in str(caught.value)
    assert caught.value.__context__ is None


def test_known_material_is_scanned_after_json_escape_decoding() -> None:
    request = _request()
    request["tools"][0]["function"]["description"] = MATERIAL
    encoded = json.dumps(request).replace(MATERIAL, "".join(f"\\u{ord(c):04x}" for c in MATERIAL))
    with pytest.raises(ToolCaptureError, match="protected material") as caught:
        capture_tool_profile(encoded.encode(), **_source(), forbidden_material=(MATERIAL,))
    assert MATERIAL not in str(caught.value)
    request["tools"][0]["function"]["description"] = "".join(
        f"\\u{ord(character):04x}" for character in MATERIAL
    )
    with pytest.raises(ToolCaptureError, match="protected material"):
        capture_tool_profile(canonical_json(request), **_source(), forbidden_material=(MATERIAL,))
    request = deepcopy(_request())
    request["tools"][0]["function"]["parameters"][MATERIAL] = "hidden in key"
    with pytest.raises(ToolCaptureError, match="protected material"):
        capture_tool_profile(canonical_json(request), **_source(), forbidden_material=(MATERIAL,))


@pytest.mark.parametrize("name", ["repeat_request", "apply_patch"])
@pytest.mark.parametrize("strict", [True, False, None])
def test_source_backed_custom_tool_strict_flag_presence_is_captured_exactly(
    name: str, strict: bool | None
) -> None:
    request = _request()
    function = next(
        tool["function"] for tool in request["tools"] if tool["function"]["name"] == name
    )
    if strict is None:
        function.pop("strict")
    else:
        function["strict"] = strict
    candidate = _capture(request)
    profile = OfflineRootToolProfile.from_mapping(candidate["profile"])
    binding = next(binding for binding in profile.tool_bindings if binding.name == name)
    assert binding.strict is strict
    profile.check_request_roster(request["tools"])
    verify_tool_profile_capture(candidate, canonical_json(request))
    if strict is None:
        function["strict"] = False
    elif strict is False:
        function.pop("strict")
    else:
        function["strict"] = False
    with pytest.raises(ToolCaptureError):
        verify_tool_profile_capture(candidate, canonical_json(request))


def test_blanket_nonstrict_and_explicit_null_strict_are_rejected() -> None:
    request = _request()
    for tool in request["tools"]:
        tool["function"]["strict"] = False
    with pytest.raises(ToolCaptureError):
        _capture(request)
    request = _request()
    repeat = next(
        tool["function"]
        for tool in request["tools"]
        if tool["function"]["name"] == "repeat_request"
    )
    repeat["strict"] = None
    with pytest.raises(ToolCaptureError):
        _capture(request)
