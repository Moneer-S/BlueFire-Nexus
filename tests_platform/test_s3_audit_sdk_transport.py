"""Opt-in aggregate accounting for bounded official-SDK response bodies."""

import hashlib
import io
from types import SimpleNamespace

import pytest

from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_sdk_transport import (
    MAX_RESPONSE_BYTES,
    BoundedSdkBody,
    BoundedSdkTransport,
)


class Raw:
    def __init__(self, data):
        self.data = io.BytesIO(data)
        self.requests = []

    def read(self, amount, *, decode_content):
        assert type(amount) is int and 0 < amount <= 8192
        assert decode_content is False
        self.requests.append(amount)
        return self.data.read(amount)

    def close(self):
        self.data.close()


class Response:
    def __init__(self, data, headers=None):
        self.raw = Raw(data)
        self.headers = headers or {}
        self.status_code = 200
        self._content = None

    @property
    def content(self):
        if self._content is None:
            self._content = b"".join(self.raw.stream())
        return self._content


def make_transport(
    response,
    *,
    response_policy=None,
    response_observer=None,
    events=None,
    checkpoint=lambda: None,
):
    events = [] if events is None else events

    def send(request):
        events.append("sdk-send")
        assert request.stream_output is True
        return response

    session = SimpleNamespace(send=send, close=lambda: None)
    transport = BoundedSdkTransport(
        session,
        lambda request: events.append("claim-send"),
        checkpoint,
        response_policy=response_policy,
        response_observer=response_observer,
    )
    return transport, SimpleNamespace(stream_output=True), events


def test_legacy_body_default_remains_exactly_64_kibibytes():
    raw = Raw(b"x" * MAX_RESPONSE_BYTES)
    body = BoundedSdkBody(raw, lambda: None)
    assert body.read() == b"x" * MAX_RESPONSE_BYTES
    assert body.tell() == MAX_RESPONSE_BYTES
    assert body.closed

    over = Raw(b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(S3AccessError):
        BoundedSdkBody(over, lambda: None).read()
    assert over.data.closed


def test_policy_is_captured_before_send_and_exact_limit_is_allowed():
    response = Response(b"x" * 5)
    charged = []
    events = []

    def response_policy():
        events.append("policy")
        return 5, charged.append

    transport, request, events = make_transport(
        response, response_policy=response_policy, events=events
    )
    returned = transport.send(request)
    assert returned.raw.read() == b"x" * 5
    assert events == ["policy", "claim-send", "sdk-send"]
    assert charged == [5]
    assert returned.raw.complete
    assert returned.raw.body_sha256 == hashlib.sha256(b"x" * 5).hexdigest()
    assert response.raw.raw.data.closed


def test_overflow_bytes_are_charged_before_per_body_rejection():
    response = Response(b"x" * 6)
    charged = []
    transport, request, _ = make_transport(response, response_policy=lambda: (5, charged.append))
    returned = transport.send(request)
    with pytest.raises(S3AccessError, match="byte allowance"):
        returned.raw.read()
    assert charged == [6]
    assert not returned.raw.complete
    assert returned.raw.body_sha256 == hashlib.sha256(b"x" * 6).hexdigest()
    assert response.raw.raw.data.closed


def test_accounting_callback_exhaustion_is_shared_across_transports():
    total = 0

    def account_bytes(amount):
        nonlocal total
        total += amount
        if total > 5:
            raise S3AccessError("shared response budget exceeded")

    def policy():
        return MAX_RESPONSE_BYTES, account_bytes

    first_response = Response(b"abc")
    first, first_request, _ = make_transport(first_response, response_policy=policy)
    assert first.send(first_request).raw.read(3) == b"abc"
    assert total == 3

    second_response = Response(b"def")
    second, second_request, _ = make_transport(second_response, response_policy=policy)
    returned = second.send(second_request)
    with pytest.raises(S3AccessError, match="shared response budget"):
        returned.raw.read(3)
    assert total == 6
    assert second_response.raw.raw.data.closed


def test_content_length_uses_captured_body_limit_without_reading_body():
    response = Response(b"x" * 8, headers={"Content-Length": "7"})
    transport, request, _ = make_transport(
        response, response_policy=lambda: (6, lambda amount: None)
    )
    with pytest.raises(S3AccessError, match="response length"):
        transport.send(request)
    assert response.raw.raw.requests == []
    assert response.raw.raw.data.closed


@pytest.mark.parametrize(
    "policy",
    [
        lambda: (True, lambda amount: None),
        lambda: (0, lambda amount: None),
        lambda: (MAX_RESPONSE_BYTES + 1, lambda amount: None),
        lambda: (5, None),
        lambda: [5, lambda amount: None],
    ],
)
def test_invalid_policy_fails_before_claim_or_sdk_send(policy):
    response = Response(b"x")
    transport, request, events = make_transport(response, response_policy=policy)
    with pytest.raises(S3AccessError, match="response policy"):
        transport.send(request)
    assert events == []
    assert response.raw.requests == []
    assert not response.raw.data.closed


def test_accounting_callback_failure_closes_raw_body():
    response = Response(b"x")

    def fail(amount):
        raise RuntimeError("accounting unavailable")

    transport, request, _ = make_transport(response, response_policy=lambda: (5, fail))
    returned = transport.send(request)
    with pytest.raises(RuntimeError, match="accounting unavailable"):
        returned.raw.read()
    assert response.raw.raw.data.closed


def test_post_read_deadline_failure_does_not_refund_returned_bytes():
    response = Response(b"abc")
    charged = []
    checkpoints = 0

    def checkpoint():
        nonlocal checkpoints
        checkpoints += 1
        if checkpoints == 4:
            raise S3AccessError("deadline exceeded")

    transport, request, _ = make_transport(
        response,
        response_policy=lambda: (5, charged.append),
        checkpoint=checkpoint,
    )
    returned = transport.send(request)
    with pytest.raises(S3AccessError, match="deadline exceeded"):
        returned.raw.read(3)
    assert charged == [3]
    assert response.raw.raw.data.closed


def test_unbounded_body_read_is_served_as_bounded_chunks():
    response = Response(b"x" * 20000)
    transport, request, _ = make_transport(
        response, response_policy=lambda: (MAX_RESPONSE_BYTES, lambda amount: None)
    )
    returned = transport.send(request)
    assert returned.raw.read() == b"x" * 20000
    assert len(response.raw.raw.requests) == 4
    assert all(amount <= 8192 for amount in response.raw.raw.requests)


def test_observer_captures_exact_body_once_before_eager_read():
    response = Response(b"listed", headers={"Content-Length": "6"})
    observed = []

    def observe(body):
        assert body is response.raw
        assert body.total == 0
        assert not body.complete
        assert response.raw.raw.requests == []
        observed.append(body)

    transport, request, _ = make_transport(response, response_observer=observe)
    request.stream_output = False
    returned = transport.send(request)
    assert returned.content == b"listed"
    assert observed == [returned.raw]
    assert returned.raw.complete
    assert request.stream_output is False


def test_observer_failure_closes_body_and_restores_stream_flag():
    response = Response(b"listed")

    def fail(body):
        assert body is response.raw
        raise RuntimeError("capture unavailable")

    transport, request, _ = make_transport(response, response_observer=fail)
    request.stream_output = False
    with pytest.raises(RuntimeError, match="capture unavailable"):
        transport.send(request)
    assert request.stream_output is False
    assert response.raw.closed
    assert response.raw.raw.data.closed
