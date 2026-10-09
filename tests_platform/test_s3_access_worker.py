"""Fixed worker framing against a deterministic parent and fake SDK transport."""

import io
import json
from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire.s3_access_wire import encode_frame
from bluefire.s3_access_worker import run_worker
from tests_platform.test_s3_access_sdk import FakeFactory, worker_request
from tests_platform.test_s3_access_wire import NOW, credentials


class Parent:
    def __init__(self, request, *, alter=None):
        self.request = request
        self.pending = bytearray(encode_frame(request.to_dict()))
        self.output = bytearray()
        self.frames = []
        self.alter = alter
        self.read_sizes = []

    def readline(self, maximum):
        self.read_sizes.append(maximum)
        end = self.pending.find(b"\n") + 1
        size = min(end or len(self.pending), maximum)
        payload = bytes(self.pending[:size])
        del self.pending[:size]
        return payload

    def write(self, payload):
        self.output.extend(payload)
        while b"\n" in self.output:
            line, _, remainder = self.output.partition(b"\n")
            self.output = bytearray(remainder)
            frame = json.loads(line)
            self.frames.append(frame)
            if frame["kind"] == "ready":
                response = {**frame, "kind": "contained"}
                secret = credentials()
                credential = {
                    "kind": "credentials",
                    "request_digest": self.request.digest,
                    "nonce": frame["nonce"],
                    "credentials": {
                        "access_key": secret.access_key,
                        "secret_key": secret.secret_key,
                        "token": secret.token,
                        "expires_at": secret.expires_at.isoformat(),
                    },
                }
                self.respond(response)
                self.respond(credential)
            elif frame["kind"] == "send":
                self.respond(
                    {
                        "kind": "permit",
                        "request_digest": frame["request_digest"],
                        "sequence": frame["sequence"],
                        "send_digest": frame["send_digest"],
                    }
                )
        return len(payload)

    def respond(self, frame):
        row = deepcopy(frame)
        if self.alter:
            self.alter(row)
        self.pending.extend(encode_frame(row))

    def flush(self):
        pass


def serve(parent, factory=None, clock=lambda: NOW):
    return run_worker(
        parent,
        parent,
        factory=factory or FakeFactory(parent.request),
        clock=clock,
        process_id=123,
        creation_identity="456",
        nonce="9" * 64,
        expected_runtime_digest=parent.request.to_dict()["runtime_digest"],
        expected_worker_generation=parent.request.to_dict()["worker_generation"],
    )


@pytest.mark.parametrize(
    ("operation", "calls"),
    [
        ("inspect_policy", 2),
        ("reconcile_policy", 2),
        ("apply_policy", 4),
        ("rollback_policy", 4),
        ("probe_read", 4),
        ("legitimate_read", 5),
    ],
)
def test_fixed_worker_serves_one_complete_framed_operation(operation, calls):
    parent = Parent(worker_request(operation))
    factory = FakeFactory(parent.request)
    assert serve(parent, factory) == 0
    assert [frame["kind"] for frame in parent.frames] == ["ready"] + ["send"] * calls + ["result"]
    result = parent.frames[-1]["result"]
    assert result["outcome"] == "observed"
    assert result["send_permits_consumed"] == calls
    assert len(factory.calls) == calls
    assert all(client.closed for client in factory.clients)
    assert not parent.pending
    assert all(size <= 80 * 1024 + 1 for size in parent.read_sizes)
    rendered = json.dumps(parent.frames)
    assert credentials().secret_key not in rendered
    assert credentials().token not in rendered


@pytest.mark.parametrize("kind", ["contained", "credentials", "permit"])
def test_invalid_parent_frame_cannot_supply_a_send(kind):
    def alter(frame):
        if frame["kind"] == kind:
            frame["request_digest"] = "sha256:" + "0" * 64

    parent = Parent(worker_request(), alter=alter)
    factory = FakeFactory(parent.request)
    status = serve(parent, factory)
    assert not factory.calls
    if kind == "permit":
        assert status == 0
        assert parent.frames[-1]["result"]["outcome"] == "failed"
    else:
        assert status == 1
        assert parent.frames[-1]["kind"] == "closed"


@pytest.mark.parametrize(
    "payload",
    [b"", b"SECRET", b"SECRET\n", b"x" * (80 * 1024 + 1)],
    ids=["empty", "unterminated", "invalid-json", "oversized"],
)
def test_bad_initial_frame_has_bounded_sanitized_terminal_output(payload):
    output = io.BytesIO()
    status = run_worker(
        io.BytesIO(payload),
        output,
        factory=FakeFactory(worker_request()),
        clock=lambda: NOW,
        process_id=123,
        creation_identity="456",
        nonce="9" * 64,
        expected_runtime_digest=worker_request().to_dict()["runtime_digest"],
        expected_worker_generation=worker_request().to_dict()["worker_generation"],
    )
    assert status == 1
    assert json.loads(output.getvalue()) == {
        "kind": "closed",
        "request_digest": None,
        "problem": "worker_protocol_failed",
    }
    assert b"SECRET" not in output.getvalue()


def test_expired_request_closes_without_sdk_construction():
    parent = Parent(worker_request())
    factory = FakeFactory(parent.request)
    assert serve(parent, factory, lambda: NOW + timedelta(seconds=60)) == 1
    assert not factory.clients
    assert [frame["kind"] for frame in parent.frames] == ["closed"]


@pytest.mark.parametrize("field", ["expected_runtime_digest", "expected_worker_generation"])
def test_runtime_mismatch_refuses_before_ready_or_credentials(field):
    parent = Parent(worker_request())
    factory = FakeFactory(parent.request)
    identity = {"expected_runtime_digest": parent.request.to_dict()["runtime_digest"],
                "expected_worker_generation": parent.request.to_dict()["worker_generation"]}
    identity[field] = "sha256:" + "0" * 64
    assert run_worker(parent, parent, factory=factory, clock=lambda: NOW, process_id=123,
                      creation_identity="456", nonce="9" * 64, **identity) == 1
    assert [frame["kind"] for frame in parent.frames] == ["closed"]
    assert not factory.clients


def test_failure_after_put_permit_keeps_reconciliation_result():
    parent = Parent(worker_request("apply_policy"))
    factory = FakeFactory(
        parent.request,
        failure=lambda operation, count: (
            RuntimeError("SECRET") if operation == "PutBucketPolicy" else None
        ),
    )
    assert serve(parent, factory) == 0
    assert parent.frames[-1]["result"]["outcome"] == "reconcile_required"
    assert b"SECRET" not in json.dumps(parent.frames).encode()


def test_output_failure_does_not_invoke_sdk_or_echo_exception():
    parent = Parent(worker_request())
    factory = FakeFactory(parent.request)

    def unavailable(payload):
        raise OSError("SECRET")

    parent.write = unavailable
    assert serve(parent, factory) == 1
    assert not factory.clients
