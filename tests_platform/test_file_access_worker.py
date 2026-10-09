from __future__ import annotations

import errno
import json
import stat
import struct
from types import SimpleNamespace

import pytest

from bluefire import file_access_probe as probe
from bluefire.file_access_closure import validate_closed_response
from bluefire.file_access_contract import FileAccessContractError, request_challenge
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.file_access_fixtures import binding


def principal(document):
    return {
        key: document["worker"][key] for key in ("uid", "gid", "pid", "start_ticks", "namespaces")
    }


def result(document):
    return {
        "outcome": "allowed",
        **{
            key: document["resource"][key]
            for key in ("sha256", "size", "record_count", "device", "inode")
        },
        "mode": document["mode"],
        "principal": principal(document),
        "read_handles_closed": True,
    }


def request(document, operation="read"):
    request_hash = "sha256:" + "8" * 64
    return {
        "schema_version": probe.REQUEST_SCHEMA,
        "operation": operation,
        "launch_nonce": document["worker"]["launch_nonce"],
        "request_hash": request_hash,
        "challenge": request_challenge(document, request_hash),
        "binding": document,
    }


class Endpoint:
    def __init__(self, request):
        self.request = request
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, value):
        assert 0 < value <= 5

    def sendmsg(self, rows):
        self.sent.append(json.loads(rows[0]))
        return len(rows[0])


def serve(monkeypatch, requests):
    document = binding()
    endpoints = [Endpoint(value) for value in requests]
    queue = iter(endpoints)
    listener = SimpleNamespace(settimeout=lambda _: None, accept=lambda: (next(queue), None))
    monkeypatch.setattr(probe, "MAX_REQUESTS", len(endpoints))
    monkeypatch.setattr(probe.time, "time_ns", lambda: 1_000_000_000_000)
    monkeypatch.setattr(probe, "process_facts", lambda: principal(document))
    monkeypatch.setattr(probe, "_receive", lambda endpoint: endpoint.request)
    calls = []
    monkeypatch.setattr(probe, "fresh_read", lambda value: calls.append(value) or result(value))
    definition = {
        key: document[key]
        for key in ("enrollment_id", "resource_id", "resource_generation", "expires_at_ms")
    }
    definition.update(
        root=document["resource"]["root"],
        socket_path=document["worker"]["socket_path"],
        launch_nonce=document["worker"]["launch_nonce"],
    )
    probe.serve(listener, definition)
    return calls, [endpoint.sent[0] for endpoint in endpoints]


def test_closure_cache_does_not_repeat_read(monkeypatch):
    document = binding()
    calls, responses = serve(
        monkeypatch, [request(document), request(document, "closure"), request(document)]
    )
    assert len(calls) == 1
    assert responses[0] == responses[1]
    assert responses[2]["error"] == "probe_unavailable"
    attestation = validate_closed_response(
        responses[1], binding=document, request_hash=request(document)["request_hash"]
    )
    assert attestation["read_handles_closed"] is True
    assert "outcome" not in attestation


def test_missing_closure_never_causes_read(monkeypatch):
    calls, responses = serve(monkeypatch, [request(binding(), "closure")])
    assert calls == []
    assert responses[0]["error"] == "probe_unavailable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_hash", "sha256:" + "7" * 64),
        ("challenge", "0" * 64),
        ("binding_digest", "sha256:" + "0" * 64),
    ],
)
def test_closure_cannot_be_rebound(field, value):
    document = binding()
    sent = request(document)
    response = {
        "schema_version": probe.RESPONSE_SCHEMA,
        "request_hash": sent["request_hash"],
        "challenge": sent["challenge"],
        "binding_digest": content_hash(document),
        "result": result(document),
    }
    response[field] = value
    with pytest.raises(FileAccessContractError):
        validate_closed_response(response, binding=document, request_hash=sent["request_hash"])


def fake_stat(inode, mode, size=0):
    return SimpleNamespace(
        st_dev=3,
        st_ino=inode,
        st_mode=mode,
        st_uid=1000,
        st_gid=1002,
        st_nlink=1,
        st_size=size,
        st_mtime_ns=1,
        st_ctime_ns=1,
    )


@pytest.mark.parametrize(
    "failure,denied",
    [(errno.EACCES, True), (errno.ENOENT, False), (errno.ELOOP, False), (errno.EPERM, False)],
)
def test_only_final_file_eacces_is_denial(monkeypatch, failure, denied):
    document = binding()
    monkeypatch.setattr(probe, "process_facts", lambda: principal(document))
    monkeypatch.setattr(probe, "_directory", lambda _: 10)
    monkeypatch.setattr(probe.os, "O_PATH", 0, raising=False)
    monkeypatch.setattr(probe.os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(probe.os, "O_DIRECTORY", 0, raising=False)
    monkeypatch.setattr(probe.os, "O_CLOEXEC", 0, raising=False)
    monkeypatch.setattr(probe.os, "O_NONBLOCK", 0, raising=False)
    details = {10: fake_stat(101, stat.S_IFDIR | 0o2710), 11: fake_stat(102, stat.S_IFDIR | 0o2710)}
    file = fake_stat(103, stat.S_IFREG | 0o640, 100)
    closed = []
    monkeypatch.setattr(probe.os, "fstat", details.__getitem__)
    monkeypatch.setattr(probe.os, "stat", lambda *_, **__: file)
    monkeypatch.setattr(probe.os, "close", closed.append)

    def opened(name, *_args, **_kwargs):
        if name == "fixtures":
            return 11
        raise OSError(failure, "test final-file refusal")

    monkeypatch.setattr(probe.os, "open", opened)
    if denied:
        answer = probe.fresh_read(document)
        assert answer["outcome"] == "permission_denied"
        assert answer["read_handles_closed"] is True
        assert answer["sha256"] is None and answer["record_count"] is None
    else:
        with pytest.raises(OSError):
            probe.fresh_read(document)
    assert closed == [11, 10]


def test_traversal_denial_is_not_file_denial(monkeypatch):
    monkeypatch.setattr(probe, "process_facts", lambda: principal(binding()))
    monkeypatch.setattr(
        probe, "_directory", lambda _: (_ for _ in ()).throw(PermissionError(errno.EACCES, "root"))
    )
    with pytest.raises(PermissionError):
        probe.fresh_read(binding())


def test_pid_reuse_is_not_a_matching_reader(monkeypatch):
    monkeypatch.setattr(probe, "process_facts", lambda: principal(binding()) | {"start_ticks": 43})
    with pytest.raises(FileAccessContractError, match="launch identity"):
        probe.fresh_read(binding())


@pytest.mark.parametrize("kind", ["wrong_uid", "wrong_pid", "rights", "truncated"])
def test_peer_and_descriptor_rejection_without_native_socket(monkeypatch, kind):
    constants = {
        "SO_PASSCRED": 16,
        "SO_PEERCRED": 17,
        "SCM_CREDENTIALS": 18,
        "SCM_RIGHTS": 19,
        "MSG_CMSG_CLOEXEC": 20,
        "MSG_TRUNC": 32,
        "MSG_CTRUNC": 64,
    }
    for name, value in constants.items():
        monkeypatch.setattr(probe.socket, name, value, raising=False)
    monkeypatch.setattr(probe.socket, "CMSG_SPACE", lambda size: size + 8, raising=False)
    peer = (25, 1000, 1000)
    sent = (
        (25, 1002, 1002)
        if kind == "wrong_uid"
        else (26, 1000, 1000) if kind == "wrong_pid" else peer
    )
    ancillary = [(probe.socket.SOL_SOCKET, constants["SCM_CREDENTIALS"], struct.pack("3i", *sent))]
    if kind == "rights":
        ancillary.append((probe.socket.SOL_SOCKET, constants["SCM_RIGHTS"], struct.pack("i", 77)))
    closed = []
    monkeypatch.setattr(probe.os, "close", closed.append)
    endpoint = SimpleNamespace(
        setsockopt=lambda *_: None,
        getsockopt=lambda *_: struct.pack("3i", *peer),
        recvmsg=lambda *_: (
            canonical_json_bytes(request(binding())),
            ancillary,
            constants["MSG_TRUNC"] if kind == "truncated" else 0,
            None,
        ),
    )
    with pytest.raises(FileAccessContractError):
        probe._receive(endpoint)
    assert closed == ([77] if kind == "rights" else [])
