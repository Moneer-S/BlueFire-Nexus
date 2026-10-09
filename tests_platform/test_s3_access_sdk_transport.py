"""Fake raw streams verify byte bounds, not Botocore release compatibility."""

import io
from types import SimpleNamespace

import pytest

from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_sdk_transport import MAX_RESPONSE_BYTES, BoundedSdkBody, BoundedSdkTransport


class Raw:
    def __init__(self, data):
        self.data = io.BytesIO(data)
        self.requests = []

    def read(self, amount, *, decode_content):
        assert decode_content is False
        self.requests.append(amount)
        return self.data.read(amount)

    def close(self):
        self.data.close()


class Response:
    def __init__(self, data, headers=None, status=200):
        self.raw = Raw(data)
        self.headers = headers or {}
        self.status_code = status
        self._content = None

    @property
    def content(self):
        if self._content is None:
            self._content = b"".join(self.raw.stream())
        return self._content


def transport(response, checkpoint=lambda: None):
    sent, claimed = [], []

    def send(request):
        assert request.stream_output is True
        sent.append(request)
        return response

    session = SimpleNamespace(send=send, close=lambda: sent.append("closed"))
    return (
        BoundedSdkTransport(session, lambda request: claimed.append(request), checkpoint),
        sent,
        claimed,
    )


@pytest.mark.parametrize(
    "streaming,status,eager",
    [(False, 200, True), (True, 200, False), (True, 403, True), (True, 500, True)],
)
def test_transport_bounds_before_parser_restores_flag_and_closes_owned_streams(
    streaming, status, eager
):
    response = Response(b"x" * 9000, status=status)
    raw = response.raw
    wrapper, sent, claimed = transport(response)
    request = SimpleNamespace(stream_output=streaming)
    returned = wrapper.send(request)
    assert returned is response
    assert request.stream_output is streaming
    assert bool(raw.requests) is eager
    assert claimed == sent == [request]
    if eager:
        assert response.content == b"x" * 9000
        assert raw.data.closed
    else:
        assert response.raw.read(100000) == b"x" * 8192
    wrapper.close()
    assert raw.data.closed
    assert sent[-1] == "closed"
    assert all(size <= 8192 for size in raw.requests)


@pytest.mark.parametrize("length", [0, 1, MAX_RESPONSE_BYTES])
def test_body_reads_exact_bound_with_bounded_chunks(length):
    raw = Raw(b"x" * length)
    body = BoundedSdkBody(raw, lambda: None)
    assert body.read() == b"x" * length
    assert body.tell() == length
    assert body.closed and raw.data.closed
    assert all(0 < amount <= 8192 for amount in raw.requests)


def test_oversized_response_never_reaches_parser_and_closes():
    response = Response(b"x" * (MAX_RESPONSE_BYTES + 1))
    raw = response.raw
    wrapper, _, _ = transport(response)
    request = SimpleNamespace(stream_output=False)
    with pytest.raises(S3AccessError):
        wrapper.send(request)
    assert response._content is None
    assert raw.data.closed
    assert request.stream_output is False


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Length": "65537"},
        {"Content-Length": "-1"},
        {"Content-Length": "1.0"},
        {"Content-Length": 3},
        {"Content-Encoding": "gzip"},
        {"Content-Length": "9" * 100},
    ],
)
def test_unsupported_response_headers_refuse_without_body_read(headers):
    response = Response(b"x", headers=headers)
    raw = response.raw
    wrapper, _, _ = transport(response)
    with pytest.raises(S3AccessError):
        wrapper.send(SimpleNamespace(stream_output=True))
    assert raw.requests == []
    assert raw.data.closed


@pytest.mark.parametrize("fail_at", [1, 2, 3, 4])
def test_deadline_checks_surround_each_chunk_and_close(fail_at):
    count = 0

    def checkpoint():
        nonlocal count
        count += 1
        if count == fail_at:
            raise S3AccessError("deadline exceeded")

    raw = Raw(b"x" * 9000)
    body = BoundedSdkBody(raw, checkpoint)
    with pytest.raises(S3AccessError):
        body.read()
    assert raw.data.closed


def test_transport_deadline_after_response_closes_before_parsing():
    count = 0

    def checkpoint():
        nonlocal count
        count += 1
        if count == 2:
            raise S3AccessError("deadline exceeded")

    response = Response(b"x")
    raw = response.raw
    wrapper, _, _ = transport(response, checkpoint)
    with pytest.raises(S3AccessError):
        wrapper.send(SimpleNamespace(stream_output=False))
    assert raw.data.closed
    assert not raw.requests


def test_read_modes_cannot_bypass_byte_boundary():
    for kwargs in ({"amt": -1}, {"amt": True}, {"decode_content": True}, {"cache_content": True}):
        raw = Raw(b"x")
        with pytest.raises(S3AccessError):
            BoundedSdkBody(raw, lambda: None).read(**kwargs)
        assert raw.data.closed


def test_raw_error_after_partial_bytes_is_not_a_service_denial():
    class BrokenRaw(Raw):
        def read(self, amount, *, decode_content):
            if self.requests:
                raise OSError("private transport detail")
            return super().read(amount, decode_content=decode_content)

    raw = BrokenRaw(b"x" * 9000)
    body = BoundedSdkBody(raw, lambda: None)
    with pytest.raises(OSError):
        body.read()
    assert raw.data.closed


def test_unimplemented_raw_read_routes_are_not_delegated():
    body = BoundedSdkBody(Raw(b"x"), lambda: None)
    for attribute in ("readinto", "readline", "readlines", "__enter__"):
        assert not hasattr(body, attribute)
    body.close()


def test_overreturning_raw_stream_is_rejected_without_yielding():
    raw = SimpleNamespace(
        read=lambda *args, **kwargs: b"x" * (MAX_RESPONSE_BYTES + 1), close=lambda: None
    )
    body = BoundedSdkBody(raw, lambda: None)
    with pytest.raises(S3AccessError):
        next(body.stream())
    assert body.closed
