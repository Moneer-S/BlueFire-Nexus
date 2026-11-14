"""Replay reviewed tool-call data through real admission, without vendoring SDK code.

These are source-derived integration-shaped requests, not installed SDK or
Strix conformance. The fixture records that genuine-wheel qualification must
repeat both cases. Its complete source provenance and transformations are
bound by a reviewed content hash; tests make no network request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bluefire.strix_controlled_backend import STRIX_SOURCE_REVISION
from bluefire.util import content_hash
from tests_platform.test_engine_docker_exec_admission import (
    INSPECT,
    START,
    admission,
    create_exec,
    inspect_body,
)
from tests_platform.test_engine_docker_proxy import Cancel, raw_request, raw_response

_CAPTURE = Path(__file__).parent / "fixtures" / "strix_pinned_exec_source_capture.json"
_CAPTURE_REF = "sha256:0383dcc8ea5d5f4179acf5815b0556a0335224b829d88e4bccc7d000ba6718e0"
_SDK_COMMIT = "a2d82707d94bfcf2ffbcc62ea9746c5fb183804f"


def _capture() -> dict[str, Any]:
    value: dict[str, Any] = json.loads(_CAPTURE.read_text(encoding="utf-8"))
    assert content_hash(value) == _CAPTURE_REF
    assert value["capture_kind"] == "source_derived_static_call_chain"
    assert value["installed_qualification_complete"] is False
    assert "genuine pinned Strix wheel" in value["installed_qualification_requirement"]
    assert value["sources"][0]["revision"] == STRIX_SOURCE_REVISION
    assert all(item["revision"] == _SDK_COMMIT for item in value["sources"][1:])
    assert all(item["release_tag"] == "v0.19.0" for item in value["sources"][1:])
    return value


@pytest.mark.parametrize("case_id", ["default_login", "explicit_non_login"])
def test_pinned_wrapper_and_exec_command_source_capture_crosses_real_admission(
    case_id: str,
) -> None:
    case = next(item for item in _capture()["cases"] if item["case_id"] == case_id)
    tool_input = case["tool_input"]
    wrapped = case["wrapper_output"]
    sdk_args = case["sdk_validated_args"]
    session_call = case["session_exec"]
    controlled = case["controlled_exec"]

    # Check every recorded boundary rather than treating argv as a hand-picked
    # command constant. Strix supplies bash; the SDK preserves explicit login.
    assert "shell" not in tool_input
    assert wrapped == {**tool_input, "shell": "bash"}
    assert sdk_args == {"login": True, "workdir": None, "tty": False, **wrapped}
    assert sdk_args["max_output_tokens"] < case["strix_context"]["tool_output_max_tokens"]
    assert case["session_supports_pty"] is False
    expected_flag = "-lc" if tool_input.get("login", True) else "-c"
    assert session_call == {
        "command": tool_input["cmd"],
        "timeout_seconds": tool_input["yield_time_ms"] / 1000,
        "shell": ["bash", expected_flag],
        "user": None,
    }
    assert controlled["argv"] == [*session_call["shell"], session_call["command"]]
    assert controlled["timeout_seconds"] == session_call["timeout_seconds"]

    admitted = admission(
        argv=tuple(controlled["argv"]), timeout=float(controlled["timeout_seconds"])
    )
    assert admitted.request.working_directory == controlled["working_directory"]
    assert admitted.request.stdin_mode == controlled["stdin_mode"]
    assert admitted.request.pty is controlled["pty"] is False
    assert admitted.docker_create_body()["Cmd"] == controlled["argv"]
    item, transport, _audit, _clock, _admitted, created = create_exec(admitted=admitted)
    assert created.status_code == 201
    transport.response = raw_response(
        200, b"", content_type="application/vnd.docker.multiplexed-stream"
    )
    assert (
        item.handle(
            raw_request("POST", START, {"Detach": False, "Tty": False}),
            Cancel(),
            exec_admission=admitted,
        ).status_code
        == 200
    )
    transport.response = raw_response(200, inspect_body(admitted))
    assert (
        item.handle(raw_request("GET", INSPECT), Cancel(), exec_admission=admitted).status_code
        == 200
    )
    assert item.snapshot().v2_exec_bindings[0].phase == "complete"
    assert not item.snapshot().reconciliation_required
