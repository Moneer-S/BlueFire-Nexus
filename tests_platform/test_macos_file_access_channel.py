"""Framing and original deadlines with fake sockets only, never child custody."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_channel as channel
from bluefire.macos_file_access_contract import MAX_MESSAGE, MacOSFileAccessContractError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_macos_file_access_contract import binding, observation, request


class Stream:
    family = 1  # Darwin AF_UNIX, represented only by this fake socket.

    def __init__(self, reply):
        self.reply = bytearray(reply)
        self.sent = bytearray()
        self.timeouts = []
        self.closed = False
        self.flags = 0
        self.ancillary = []
        self.inheritable = True
        self.fail_send = False
        self.fail_close = False
        self.close_calls = 0

    def getsockopt(self, *_args):
        return channel.socket.SOCK_STREAM

    def fileno(self):
        return 7

    def getpeername(self):
        return ""

    def set_inheritable(self, value):
        self.inheritable = value

    def settimeout(self, value):
        assert 0 < value <= 5
        self.timeouts.append(value)

    def send(self, raw):
        if self.fail_send:
            raise OSError("fake send failure")
        count = min(13, len(raw))
        self.sent.extend(raw[:count])
        return count

    def recvmsg(self, maximum, ancillary_size):
        assert ancillary_size == 0
        count = min(maximum, 11, len(self.reply))
        raw = bytes(self.reply[:count])
        del self.reply[:count]
        return raw, self.ancillary, self.flags, ""

    def close(self):
        self.close_calls += 1
        self.closed = True
        if self.fail_close:
            raise OSError("ambiguous fake close")


def frame(value):
    raw = canonical_json_bytes(value)
    return len(raw).to_bytes(4, "little") + raw


@pytest.fixture
def make(monkeypatch):
    monkeypatch.setattr(channel, "socket", SimpleNamespace(**vars(channel.socket)))
    monkeypatch.setattr(channel.socket, "AF_UNIX", Stream.family, raising=False)
    monkeypatch.setattr(channel, "time", SimpleNamespace(**vars(channel.time)))
    monkeypatch.setattr(channel.socket, "socket", Stream)
    monkeypatch.setattr(channel, "darwin_clock_ns", lambda: 1000)
    monkeypatch.setattr(channel.time, "time_ns", lambda: 1000_000_000)

    def build(reply=None, role="reader"):
        stream = Stream(frame(observation(request())) if reply is None else reply)
        return channel.MacOSPrimitiveChannel(stream, binding(), role=role), stream

    return build


def test_partial_io_roundtrip_does_not_mint_custody(make):
    transport, stream = make()
    observed = transport.exchange(request())
    assert observed["outcome"] == "allowed"
    assert observed["custody"] == "requires_original_creator_evidence"
    assert observed["prevention_proven"] is False
    assert stream.sent == frame(request())
    assert transport.usable and not stream.inheritable
    assert len(stream.timeouts) > 4


@pytest.mark.parametrize("earlier", ["wall", "monotonic"])
def test_blocking_io_uses_the_earlier_original_expiry(make, earlier):
    original = request()
    if earlier == "wall":
        original["expires_at_ms"] = original["issued_at_ms"] + 1
    else:
        original["deadline_ns"] = original["issued_monotonic_ns"] + 1_000_000
    transport, stream = make(frame(observation(original)))
    assert transport.exchange(original)["outcome"] == "allowed"
    assert stream.timeouts and set(stream.timeouts) == {0.001}


@pytest.mark.parametrize("size", [0, MAX_MESSAGE + 1, 2**32 - 1])
def test_invalid_length_poisoned_without_body_read(make, size):
    transport, stream = make(size.to_bytes(4, "little") + b"not consumed")
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not transport.usable
    assert stream.reply == b"not consumed"


@pytest.mark.parametrize("raw", [b"", b"\x01", b"\x03\x00\x00\x00{}"])
def test_eof_anywhere_is_not_success(make, raw):
    transport, stream = make(raw)
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not transport.usable


@pytest.mark.parametrize("kind", ["duplicate", "constant", "identity", "extra"])
def test_invalid_json_or_join_is_terminal(make, kind):
    value = observation(request())
    if kind == "identity":
        value["request_id"] = "9" * 64
    elif kind == "extra":
        value["extra"] = True
    raw = canonical_json_bytes(value)
    if kind == "duplicate":
        raw = raw[:-1] + b',"outcome":"allowed"}'
    elif kind == "constant":
        raw = b"NaN"
    transport, stream = make(len(raw).to_bytes(4, "little") + raw)
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not transport.usable


@pytest.mark.parametrize("field", ["flags", "ancillary"])
def test_unsolicited_ancillary_or_truncated_control_is_rejected(make, field):
    transport, stream = make()
    setattr(stream, field, 8 if field == "flags" else [(1, 1, b"unexpected")])
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not transport.usable


@pytest.mark.parametrize("change", ["role", "sequence", "generation", "expiry"])
def test_unbound_request_is_never_written(make, change):
    original = request()
    if change == "role":
        original["operation"] = "harden"
    elif change == "sequence":
        original["sequence"] = 2
    elif change == "generation":
        original["binding"]["generation"] = "file-generation-" + "a" * 32
    else:
        original["binding"]["original_deadline_ns"] += 1
    original["binding_digest"] = content_hash(original["binding"])
    transport, stream = make()
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(original)
    assert not stream.sent and stream.closed


def test_replayed_request_is_not_sent_twice(make):
    transport, stream = make()
    transport.exchange(request())
    prior = bytes(stream.sent)
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.sent == prior and stream.closed


def test_request_id_cannot_repeat_with_next_sequence(make):
    transport, stream = make()
    transport.exchange(request())
    original = request()
    original["sequence"] = 2
    prior = bytes(stream.sent)
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(original)
    assert stream.sent == prior


@pytest.mark.parametrize("clock", ["wall", "monotonic"])
def test_late_reply_rejected_without_renewing_request(make, monkeypatch, clock):
    transport, stream = make()
    original_recv = stream.recvmsg

    def receive(*args):
        result = original_recv(*args)
        if not stream.reply:
            if clock == "wall":
                monkeypatch.setattr(channel.time, "time_ns", lambda: 6000_000_000)
            else:
                monkeypatch.setattr(channel, "darwin_clock_ns", lambda: 5000001000)
        return result

    stream.recvmsg = receive
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not transport.usable


def test_clock_rollback_is_terminal(make, monkeypatch):
    transport, stream = make()
    ticks = iter([2000, 1999])
    monkeypatch.setattr(channel, "darwin_clock_ns", lambda: next(ticks))
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert not stream.sent and stream.closed


def test_send_failure_cannot_retry(make):
    transport, stream = make()
    stream.fail_send = True
    with pytest.raises(OSError):
        transport.exchange(request())
    stream.fail_send = False
    with pytest.raises(MacOSFileAccessContractError):
        transport.exchange(request())
    assert stream.closed and not stream.sent


@pytest.mark.parametrize("outcome", ["unknown", "refused"])
def test_valid_non_success_response_disables_further_exchange(make, outcome):
    value = observation(request())
    value.update(outcome=outcome, fresh_read=None, principal=None)
    transport, _stream = make(frame(value))
    assert transport.exchange(request())["outcome"] == outcome
    assert not transport.usable


def test_close_observation_only_closes_transport(make):
    original = request("close")
    value = observation(original)
    value.update(
        outcome="closed",
        principal=None,
        fresh_read=None,
        request_handle_cleanup="not_opened",
        held_handle_cleanup="closed",
    )
    transport, stream = make(frame(value))
    assert transport.exchange(original)["custody"] == "requires_original_creator_evidence"
    assert stream.closed and not transport.usable


def test_concurrent_call_is_not_queued_or_dispatched(make):
    transport, stream = make()
    transport._lock.acquire()
    try:
        with pytest.raises(MacOSFileAccessContractError):
            transport.exchange(request())
    finally:
        transport._lock.release()
    assert not stream.sent and transport.usable


def test_caller_request_not_mutated(make):
    original = request()
    before = deepcopy(original)
    transport, _stream = make()
    transport.exchange(original)
    assert original == before


def test_abandon_makes_no_cleanup_or_custody_claim(make):
    transport, stream = make()
    assert transport.abandon() is None
    assert stream.closed and not transport.usable


@pytest.mark.parametrize("during_exchange", [False, True])
def test_ambiguous_local_close_is_sticky_and_never_retried(make, during_exchange):
    transport, stream = make()
    stream.fail_close = True
    stream.fail_send = during_exchange
    with pytest.raises(OSError):
        if during_exchange:
            transport.exchange(request())
        else:
            transport.abandon()
    assert transport.local_cleanup_unknown and not transport.usable
    stream.fail_close = False
    transport.abandon()
    assert transport.local_cleanup_unknown and stream.close_calls == 1
