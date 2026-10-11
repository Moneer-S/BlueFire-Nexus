"""Exact Windows Rust-serialized fake-backend corpus, not authenticated AD proof.

Retained r5 emitted bytes are copied unchanged. No native binary is run here and
no request identity/result is rewritten to fit a new operation.
"""

import hashlib
import json
from pathlib import Path

import pytest

from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbScope
from bluefire.ad_smb_receiver_results import context, result_record, stored_result
from bluefire.ad_smb_results import outcome, validate_execution
from bluefire.ad_smb_worker_wire import RECEIVER_RESULT_MAX, WorkerPacket
from bluefire.ad_smb_workspace_results import project_original
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_receiver import original
from tests_platform.test_ad_smb_worker_wire import terminal_row

CASES = (
    "inspect",
    "matched_write",
    "unknown_write",
    "matched_read",
    "denied_read",
    "partial_audit",
)


def corpus_case(name):
    root = Path(__file__).resolve().parents[1]
    input_bytes = (root / "runner/tests/fixtures/ad_smb_native_corpus_inputs.json").read_bytes()
    raw = (root / "tests_platform/fixtures/ad_smb_native_corpus.json").read_bytes()
    assert (
        hashlib.sha256(input_bytes).hexdigest()
        == "fa41abad7c00942b99dfbe653af7dc8c010fbb102e4ed0e19dd13785e8e08764"
    )
    assert (
        hashlib.sha256(raw).hexdigest()
        == "5ac68ce63d00b293dcc55a844cbb473085d8f194d5a4b73d403bee89db05c22b"
    )
    inputs, outputs = json.loads(input_bytes), json.loads(raw)
    assert (
        outputs["synthetic_only"] is True
        and outputs["fixture_sha256"] == hashlib.sha256(input_bytes).hexdigest()
    )
    saved, emitted = inputs["cases"][name], outputs["cases"][name]
    public = saved["packet"]
    request = public["manifest"]["params"]["ad_smb_request"]
    assert emitted["operation"] == request["step"] and emitted["request_digest"] == content_hash(
        request
    )
    assert emitted["synthetic_only"] is True
    _, old_channel = original(request["phase"], request["index"], CASES.index(name) + 1)
    scope = AdSmbScope.from_mapping(request["scope"])
    channel = AdSmbHostChannel.from_mapping(
        scope, {**old_channel.to_dict(), "scope_digest": scope.digest}
    )
    assert channel.digest == public["channel_digest"]
    packet = WorkerPacket(canonical_json_bytes(public))
    terminal = terminal_row(packet)
    terminal["result"] = emitted["result"]
    retained = result_record(
        packet,
        terminal,
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue=None,
        receiver_completed_at=saved["receiver_completed_at"],
    )
    original_task = context(public["manifest"], public["profile"])
    return request, original_task, channel, retained


@pytest.mark.parametrize("name", CASES)
def test_actual_native_serialized_fixture_survives_original_validation_and_projection(name):
    request, task, channel, retained = corpus_case(name)
    assert (
        stored_result(
            retained, task["manifest"], task["profile"], channel, maximum=RECEIVER_RESULT_MAX
        )
        == retained
    )
    projected = project_original(request, task, channel, retained)
    assert validate_execution(request, projected) == projected
    observed = projected["observation"]
    if name == "inspect":
        assert (
            observed["snapshot"]["descriptor"]
            == retained["terminal"]["result"]["share"]["descriptor"]
        )
        assert outcome("inspect", [projected])["state"] == "complete"
    elif name == "matched_write":
        assert observed["state"] == "readback_matched"
        assert outcome("harden", [projected])["state"] == "complete"
    elif name == "unknown_write":
        assert observed == {"state": "unknown", "snapshot": None}
        assert outcome("harden", [projected])["state"] == "unknown"
    elif name in {"matched_read", "denied_read"}:
        assert observed["state"] == (
            "bytes_matched" if name == "matched_read" else "open_access_denied"
        )
        assert observed["local_authentication_id"] == (
            "2000000000000001" if name == "matched_read" else "2000000000000002"
        )
        assert outcome("baseline", [projected])["state"] == "partial"
    else:
        assert observed["events"] == 1 and observed["truncated"] is True
        assert observed["authenticated_source"] is False
        assert observed["independent_observation"] is False
        assert outcome("audit", [projected])["audit_complete"] is False
