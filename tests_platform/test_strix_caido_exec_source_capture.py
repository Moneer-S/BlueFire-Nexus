"""Exact controller-derived guest bootstrap; no installed conformance claim."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from bluefire.engine_docker_exec_admission import DockerExecAdmissionError
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


def _source_capture():
    path = Path(__file__).parent / "fixtures" / "strix_caido_bootstrap_source_capture.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_source_derived_caido_guest_login_crosses_guarded_exec_contract() -> None:
    captured = _source_capture()
    assert (
        content_hash(captured)
        == "sha256:05420eb2e5927fc0e32815175910d8938e95a6017fd343a26e4eed73de740baf"
    )
    assert captured["capture_kind"] == "source_derived_session_call"
    assert captured["installed_qualification_complete"] is False
    assert captured["source"]["revision"] == STRIX_SOURCE_REVISION
    call = captured["source_session_exec"]
    prepared = captured["sdk_prepared_exec"]
    assert prepared["argv"] == ["sh", "-lc", shlex.join(call["argv"])]
    assert call["timeout_seconds"] == 15 and call["attempts"] == 10
    admitted = admission(argv=tuple(prepared["argv"]), timeout=float(call["timeout_seconds"]))
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


@pytest.mark.parametrize(
    "index,value",
    [
        (1, "-sS"),
        (3, "GET"),
        (5, "Content-Type: text/plain"),
        (7, '{"query":"query { secrets }"}'),
        (8, "http://host.docker.internal:48080/graphql"),
        (8, "http://127.0.0.1:48080/other"),
    ],
)
def test_caido_bootstrap_refuses_general_curl_url_body_or_flag_drift(
    index: int, value: str
) -> None:
    argv = list(_source_capture()["source_session_exec"]["argv"])
    argv[index] = value
    with pytest.raises(DockerExecAdmissionError):
        admission(argv=tuple(argv), timeout=15)


def test_direct_caido_bootstrap_curl_is_refused_without_sdk_shell_preparation() -> None:
    with pytest.raises(DockerExecAdmissionError, match="grammar"):
        admission(argv=tuple(_source_capture()["source_session_exec"]["argv"]), timeout=15)
