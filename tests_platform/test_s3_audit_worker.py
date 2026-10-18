"""Audit conversation bounds and closed credentials, using in-memory pipes only."""

import io
import json

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_contract import S3AccessError, timestamp
from bluefire.s3_access_wire import S3WorkerRequest, encode_frame
from bluefire.s3_access_worker import _Conversation, run_worker
from tests_platform.test_s3_access_worker import Parent
from tests_platform.test_s3_audit_sdk import RESERVATION_DIGEST, FakeAuditFactory
from tests_platform.test_s3_audit_wire import request_row


def channel():
    row = request_row()
    result = _Conversation(io.BytesIO(), io.BytesIO(), lambda: timestamp(row["audit"]["issued_at"]))
    result.request = S3WorkerRequest.from_mapping(row)
    return result


def test_audit_output_keeps_exact_complete_line_bound_and_aggregate_bound():
    conversation = channel()
    document = {"value": ""}
    overhead = len(encode_frame(document))
    document["value"] = "x" * (audit.MAX_FRAME_BYTES - overhead)
    for _ in range(4):
        conversation.write(document)
    assert conversation.output_bytes == 64 * 1024
    with pytest.raises(S3AccessError, match="output exceeds"):
        conversation.write({"value": ""})
    assert len(conversation.destination.getvalue()) == 64 * 1024


def test_audit_overlong_line_is_refused_before_any_output():
    conversation = channel()
    with pytest.raises(S3AccessError, match="output frame"):
        conversation.write({"value": "x" * audit.MAX_FRAME_BYTES})
    assert conversation.destination.getvalue() == b""


def test_audit_discovery_exchange_reads_only_one_bounded_ack():
    conversation = channel()
    conversation.source = io.BytesIO(b'{"kind":"discovery_committed"}\nextra\n')
    assert conversation.discovery({"kind": "discovery"}) == {"kind": "discovery_committed"}
    assert conversation.source.read() == b"extra\n"
    assert json.loads(conversation.destination.getvalue()) == {"kind": "discovery"}


def test_missing_native_audit_reservation_refuses_before_client_construction():
    row = request_row()
    parent = Parent(S3WorkerRequest.from_mapping(row))

    class NoFactory:
        def client(self, *args, **kwargs):
            pytest.fail("missing reservation must not reach SDK construction")

    assert (
        run_worker(
            parent,
            parent,
            factory=NoFactory(),
            clock=lambda: timestamp(row["audit"]["issued_at"]),
            process_id=123,
            creation_identity="456",
            nonce="9" * 64,
            expected_runtime_digest=row["runtime_digest"],
            expected_worker_generation=row["worker_generation"],
        )
        == 1
    )
    assert [frame["kind"] for frame in parent.frames] == ["ready", "closed"]
    assert parent.frames[-1]["problem"] == "worker_protocol_failed"


class AuditParent(Parent):
    def __init__(self, request, *, ack_mode="valid", object_mode="valid"):
        super().__init__(request)
        self.factory = FakeAuditFactory(
            request.to_dict(), ack_mode=ack_mode, object_mode=object_mode
        )

    def respond(self, frame):
        if frame["kind"] == "credentials":
            frame = {**frame, "reservation_digest": RESERVATION_DIGEST}
        super().respond(frame)

    def write(self, payload):
        before = len(self.frames)
        written = super().write(payload)
        for frame in self.frames[before:]:
            if frame["kind"] == "discovery":
                try:
                    self.respond(self.factory.commit_discovery(frame))
                except RuntimeError:
                    pass
        return written


@pytest.mark.parametrize("ack_mode", ["valid", "lost", "wrong"])
def test_complete_audit_worker_conversation_obeys_native_discovery_boundary(ack_mode):
    row = request_row()
    parent = AuditParent(S3WorkerRequest.from_mapping(row), ack_mode=ack_mode)
    assert (
        run_worker(
            parent,
            parent,
            factory=parent.factory,
            clock=lambda: timestamp(row["audit"]["issued_at"]),
            process_id=123,
            creation_identity="456",
            nonce="9" * 64,
            expected_runtime_digest=row["runtime_digest"],
            expected_worker_generation=row["worker_generation"],
        )
        == 0
    )
    kinds = [frame["kind"] for frame in parent.frames]
    assert kinds[:5] == ["ready"] + ["send"] * 4
    assert kinds[5] == "discovery"
    assert kinds[-1] == "result"
    assert kinds.count("send") == (5 if ack_mode == "valid" else 4)
    result = parent.frames[-1]["result"]
    assert result["outcome"] == ("observed" if ack_mode == "valid" else "failed")
    assert all(len(encode_frame(frame)) <= audit.MAX_FRAME_BYTES for frame in parent.frames)
    assert sum(len(encode_frame(frame)) for frame in parent.frames) <= 64 * 1024
    assert all(client.closed for client in parent.factory.clients)
    assert all(body.closed for transport in parent.factory.transports for body in transport.bodies)
