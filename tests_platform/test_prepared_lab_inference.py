"""Portable process/descriptor substitutes; no namespace, socket or native effects."""

from __future__ import annotations

import array
import struct
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire import ai_broker_bootstrap as bootstrap
from bluefire import prepared_lab_broker as broker
from bluefire import prepared_lab_product as product
from bluefire import prepared_lab_ui_bootstrap as ui_bootstrap
from bluefire.ai_wire import AIProviderTransportError
from bluefire.config import AIProviderKind
from bluefire.prepared_lab_enrollment import enroll, enrollment_document
from tests_platform.test_ai_wire_runtime import _provider_config


class Endpoint:
    def __init__(self, descriptor=51):
        self.descriptor = descriptor
        self.closed = False

    def fileno(self):
        return self.descriptor

    def close(self):
        self.closed = True

    def set_inheritable(self, value):
        assert value is False


@pytest.mark.parametrize(
    ("code", "cleanup_ok"),
    [
        ("broker_session_expired", True),
        ("broker_session_expired", False),
        ("broker_unavailable", True),
        ("expiry_exit_race", True),
    ],
)
def test_expected_session_expiry_explains_restart_but_still_requires_cleanup(
    monkeypatch, binding, capsys, code, cleanup_ok
):
    closed = []
    owner = SimpleNamespace(
        channels=[],
        spawn=lambda *_args: SimpleNamespace(pid=17),
        close=lambda: (closed.append(True) or cleanup_ok),
        containment=SimpleNamespace(exited_without_reap=lambda _process: True),
    )
    monkeypatch.setattr(broker, "_RETAINED", [])
    monkeypatch.setattr(broker, "verify_installation", lambda: None)
    monkeypatch.setattr(broker, "uid", lambda: 0)
    monkeypatch.setattr(broker, "enroll", lambda *_args, **_kwargs: binding)
    monkeypatch.setattr(broker, "OwnedProcesses", lambda: owner)
    monkeypatch.setattr(broker, "bootstrap_pair", lambda: (Endpoint(), Endpoint()))
    monkeypatch.setattr(broker.socket, "socketpair", lambda *_args: (Endpoint(), Endpoint()))
    monkeypatch.setattr(broker, "_grant", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(broker, "_target_child", lambda *_args: 18)
    monkeypatch.setattr(broker, "STOP_FILE", SimpleNamespace(exists=lambda: False))

    checks = []
    expiry = code in {"broker_session_expired", "expiry_exit_race"}

    def expired(*_args):
        checks.append(True)
        if code == "expiry_exit_race" and len(checks) == 1:
            return
        raise AIProviderTransportError(
            "private diagnostic", retryable=False, code="broker_session_expired" if expiry else code
        )

    monkeypatch.setattr(type(binding), "require_current", expired)
    definition = {
        "configuration": binding.config.to_dict(),
        "credential": "synthetic",
        "destination_policy": "explicit_endpoint",
        "max_nodes": 8,
        "max_edges": 16,
    }
    if expiry and cleanup_ok:
        broker.supervise(8777, definition, stop=threading.Event())
    else:
        with pytest.raises(AIProviderTransportError) as caught:
            broker.supervise(8777, definition, stop=threading.Event())
        assert caught.value.code == "broker_unavailable"
    assert closed == [True]
    output = capsys.readouterr().out
    assert "private diagnostic" not in output
    assert "session expires at" in output
    assert ("No work is restarted automatically" in output) == expiry
    assert len(checks) == (2 if code == "expiry_exit_race" else 1)


@pytest.mark.parametrize("boundary", ["broker", "ui"])
def test_failed_cleanup_owner_refuses_restart_before_resources_are_adopted(monkeypatch, boundary):
    retained = object()

    def unexpected(*args, **kwargs):
        pytest.fail("retained ownership must refuse before acquiring a new resource")

    if boundary == "broker":
        monkeypatch.setattr(broker, "_RETAINED", [retained])
        monkeypatch.setattr(broker, "verify_installation", unexpected)

        def invoke():
            broker.supervise(8777, {}, stop=threading.Event())

        registry = broker._RETAINED
    else:
        monkeypatch.setattr(ui_bootstrap, "_RETAINED", [retained])
        monkeypatch.setattr(ui_bootstrap, "adopt_bootstrap", unexpected)

        def invoke():
            ui_bootstrap.start_ui(8777, 51, "a" * 64)

        registry = ui_bootstrap._RETAINED
    with pytest.raises(AIProviderTransportError) as caught:
        invoke()
    assert caught.value.code == "broker_unavailable"
    assert registry == [retained]


@pytest.fixture
def binding():
    return enroll(
        replace(_provider_config(AIProviderKind.CHAT_COMPLETIONS), max_retries=0),
        "explicit_endpoint",
    )


@pytest.mark.parametrize(
    "fault",
    [None, "uid", "pid", "descriptor_count", "missing_descriptor", "truncated", "duplicate_json"],
)
def test_received_descriptor_requires_exact_kernel_peer_and_closes_refused_rights(
    monkeypatch, fault
):
    for name, value in {
        "SCM_CREDENTIALS": 2,
        "MSG_CMSG_CLOEXEC": 0x40000000,
        "SCM_RIGHTS": 1,
        "SOL_SOCKET": 1,
        "MSG_TRUNC": 32,
        "MSG_CTRUNC": 8,
    }.items():
        monkeypatch.setattr(bootstrap.socket, name, value, raising=False)
    monkeypatch.setattr(bootstrap.socket, "CMSG_SPACE", lambda value: value + 16, raising=False)
    monkeypatch.setattr(bootstrap, "_ready", lambda *_a: None)
    closed = []
    monkeypatch.setattr(bootstrap.os, "close", closed.append)
    rights = [61, 62] if fault == "descriptor_count" else [61]
    if fault == "missing_descriptor":
        rights = []
    ancillary = [
        (1, 2, struct.pack("3i", 8 if fault == "pid" else 7, 9 if fault == "uid" else 1000, 1000)),
        (1, 1, array.array("i", rights).tobytes()),
    ]
    payload = b'{"kind":1,"kind":2}' if fault == "duplicate_json" else b'{"kind":"grant"}'
    endpoint = SimpleNamespace(
        recvmsg=lambda *_args: (payload, ancillary, 8 if fault == "truncated" else 0, None)
    )
    if fault:
        with pytest.raises(AIProviderTransportError):
            bootstrap.receive_bootstrap(
                endpoint, expected_uid=1000, expected_pid=7, descriptor_required=True
            )
        assert closed == rights
    else:
        assert bootstrap.receive_bootstrap(
            endpoint, expected_uid=1000, expected_pid=7, descriptor_required=True
        ) == ({"kind": "grant"}, 61)
        assert closed == []


@pytest.mark.parametrize(
    "fault", [None, "before_grant", "before_admit", "wrong_start", "wrong_bound"]
)
def test_parent_grants_and_admits_only_exact_protected_process(monkeypatch, binding, fault):
    identity = (7, 33, 7, 7)
    monkeypatch.setattr(
        broker.LinuxPrivateProcessContainment, "process_identity", lambda _pid: identity
    )
    identities = [identity, identity]
    if fault == "before_grant":
        identities[0] = (7, 34, 7, 7)
    if fault == "before_admit":
        identities[1] = (7, 34, 7, 7)
    monkeypatch.setattr(broker, "protected_identity", lambda *_a: identities.pop(0))
    frames = [
        (
            {
                "kind": "armed",
                "launch_id": "a" * 64,
                "process_id": 1,
                "creation_identity": 34 if fault == "wrong_start" else 33,
            },
            None,
        ),
        (
            {
                "kind": "bound",
                "launch_id": "a" * 64,
                "enrollment_digest": "wrong" if fault == "wrong_bound" else binding.digest,
            },
            None,
        ),
    ]
    peers = []

    def receive(_endpoint, **kwargs):
        peers.append(kwargs)
        return frames.pop(0)

    sent = []
    monkeypatch.setattr(broker, "receive_bootstrap", receive)
    monkeypatch.setattr(
        broker, "send_bootstrap", lambda _endpoint, value, **kwargs: sent.append((value, kwargs))
    )

    def call():
        broker._grant(
            Endpoint(),
            uid=1000,
            pid=7,
            launch="a" * 64,
            document={"enrollment": enrollment_document(binding)},
            inference=Endpoint(88),
            namespace_pid=1,
        )

    if fault:
        with pytest.raises(AIProviderTransportError):
            call()
        assert not any(value["kind"] == "admit" for value, _ in sent)
    else:
        call()
        assert [value["kind"] for value, _ in sent] == ["grant", "admit"]
        assert sent[0][1] == {"descriptor": 88} and sent[1][1] == {}
    assert all(peer == {"expected_uid": 1000, "expected_pid": 7} for peer in peers)


@pytest.mark.parametrize("admitted", [True, False])
def test_final_exec_ui_protects_before_channel_and_waits_for_admission_before_cli(
    monkeypatch, binding, admitted
):
    events = []
    endpoint = Endpoint()
    inference = Endpoint(88)
    monkeypatch.setattr(
        product, "protect_process", lambda *a, **k: events.append(("protect", a, k))
    )
    monkeypatch.setattr(
        product, "adopt_bootstrap", lambda fd: (events.append(("bootstrap", fd)) or endpoint)
    )
    monkeypatch.setattr(
        product.LinuxPrivateProcessContainment, "process_identity", lambda _pid: (7, 33, 7, 7)
    )
    monkeypatch.setattr(
        product, "send_bootstrap", lambda _e, value: events.append(("send", value["kind"]))
    )
    frames = [
        ({"kind": "grant", "launch_id": "a" * 64, "enrollment": enrollment_document(binding)}, 88),
        (
            {
                "kind": "admit",
                "launch_id": "a" * 64,
                "enrollment_digest": binding.digest if admitted else "wrong",
            },
            None,
        ),
    ]

    def receive(_endpoint, **kwargs):
        assert kwargs["expected_uid"] == 1000 and kwargs["expected_pid"] == 1
        events.append(("receive", frames[0][0]["kind"]))
        return frames.pop(0)

    monkeypatch.setattr(product, "receive_bootstrap", receive)
    monkeypatch.setattr(
        product, "adopt_inference", lambda fd: (events.append(("inference", fd)) or inference)
    )
    monkeypatch.setattr(product, "SocketBrokerChannel", lambda endpoint: endpoint)

    def cli(argv, **kwargs):
        events.append(("cli",))
        assert endpoint.closed
        assert kwargs["ai_provider_access"].enrollment.digest == binding.digest
        assert kwargs["config"].ai.provider() == binding.config
        assert argv[-5:] == ["ui", "--host", "127.0.0.1", "--port", "8767"]
        return 0

    monkeypatch.setattr("bluefire.cli.main", cli)
    if admitted:
        assert product.run(8767, 51, "a" * 64) == 0
        assert events[-1] == ("cli",)
    else:
        with pytest.raises(AIProviderTransportError):
            product.run(8767, 51, "a" * 64)
        assert ("cli",) not in events
    assert events[0] == ("protect", (1000,), {"parent": 1})
    assert events.index(("receive", "admit")) > events.index(("send", "bound"))
    assert endpoint.closed and inference.closed


def test_internal_cli_binding_has_no_public_descriptor_or_environment_option():
    from bluefire.cli import _parser

    parser = _parser()
    for option in ("--inference-fd", "--broker-fd", "--ai-provider-access"):
        with pytest.raises(SystemExit):
            parser.parse_args([option, "51", "ui"])


def test_enrollment_rehydration_rejects_changed_public_identity(binding):
    from bluefire.prepared_lab_enrollment import read_enrollment

    value = enrollment_document(binding)
    assert read_enrollment(value) == binding
    value["configuration"]["endpoint"] = "http://127.0.0.1:9999/v1/changed"
    with pytest.raises(AIProviderTransportError):
        read_enrollment(value)
    assert "credential" not in enrollment_document(binding)


def test_failed_channel_close_still_drains_processes_and_retains_exact_failed_owners(monkeypatch):
    owner = broker.OwnedProcesses()
    calls = []
    first = Endpoint(51)
    second = Endpoint(52)
    process = SimpleNamespace(pid=7)
    owner.channels = [first, second]
    owner.processes = [process]
    fail = [True]

    def close_first():
        calls.append("first")
        if fail[0]:
            raise OSError("private close detail")

    monkeypatch.setattr(first, "close", close_first)
    monkeypatch.setattr(second, "close", lambda: calls.append("second"))
    monkeypatch.setattr(owner.containment, "contains", lambda _p: True)
    monkeypatch.setattr(
        owner.containment,
        "release",
        lambda p, **_k: (calls.append(("release", p.pid)) or not fail[0]),
    )
    try:
        assert owner.close() is False
        assert calls == ["first", "second", ("release", 7)]
        assert (
            owner in broker._RETAINED and owner.channels == [first] and owner.processes == [process]
        )
        fail[0] = False
        assert owner.close() is True
        assert owner not in broker._RETAINED and not owner.channels and not owner.processes
    finally:
        if owner in broker._RETAINED:
            broker._RETAINED.remove(owner)


@pytest.mark.parametrize("fault", [None, "dumpable", "capability", "privilege"])
def test_protection_reads_back_dumpability_and_requires_dropped_privileges(monkeypatch, fault):
    calls = []

    def prctl(option, *_args):
        calls.append(option)
        return 1 if option == 3 and fault == "dumpable" else 0

    monkeypatch.setattr(bootstrap.sys, "platform", "linux")
    monkeypatch.setattr(bootstrap.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(bootstrap.os, "getgid", lambda: 1000, raising=False)
    monkeypatch.setattr(bootstrap.os, "getgroups", lambda: [], raising=False)
    monkeypatch.setattr(bootstrap.ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace(prctl=prctl))
    status = "NoNewPrivs: " + ("0" if fault == "privilege" else "1") + "\n"
    status += "\n".join(
        key + ": " + ("1" if fault == "capability" and key == "CapEff" else "0")
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    )
    monkeypatch.setattr(bootstrap.Path, "read_text", lambda _p: status)
    if fault:
        with pytest.raises(AIProviderTransportError):
            bootstrap.protect_process(1000)
    else:
        bootstrap.protect_process(1000)
    assert calls == [4, 3]


@pytest.mark.parametrize("uid,mode", [(1000, 0o100644), (0, 0o100664), (0, 0o100646)])
def test_installed_entry_or_interpreter_target_must_be_root_owned_and_nonwritable(
    monkeypatch, uid, mode
):
    from pathlib import Path

    from bluefire.prepared_lab_installation import _root_owned

    path = Path("installed") / "bin" / "python"
    monkeypatch.setattr(Path, "lstat", lambda _path: SimpleNamespace(st_uid=uid, st_mode=mode))
    with pytest.raises(ValueError, match="root-owned"):
        _root_owned(path)
