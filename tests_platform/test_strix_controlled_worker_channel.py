"""Adversarial, effect-free tests for the controlled Strix worker wire contract."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Awaitable, TypeVar, cast

import pytest

from bluefire import strix_controlled_backend as backend
from bluefire import strix_controlled_worker_channel as channel
from bluefire.util import content_hash
from tests_platform.test_strix_controlled_backend import FakeTransport, _profile

_T = TypeVar("_T")


def _complete(awaitable: Awaitable[_T]) -> _T:
    """Drive an immediately completing fake coroutine without an OS event loop."""
    iterator = awaitable.__await__()
    try:
        next(iterator)
    except StopIteration as finished:
        return cast(_T, finished.value)
    raise AssertionError("fake transport unexpectedly suspended")


def _binding(profile: backend.ControlledRuntimeProfile) -> channel.ControlledWorkerBinding:
    return channel.ControlledWorkerBinding(
        attempt_id=profile.attempt_id,
        claim_digest="sha256:" + "a" * 64,
        plan_digest="sha256:" + "b" * 64,
        profile_digest=profile.profile_digest,
        identity_digest=profile.identity_digest,
        controller_fence="sha256:" + "c" * 64,
        deadline_ns=100_000,
        nonce="d" * 32,
    )


def _pair() -> tuple[channel.WorkerChannel, channel.ControllerChannel, FakeTransport]:
    profile = _profile()
    binding = _binding(profile)
    return (
        channel.WorkerChannel(profile, binding),
        channel.ControllerChannel(profile, binding),
        FakeTransport().bind(profile),
    )


def _request(
    method: str,
    profile: backend.ControlledRuntimeProfile,
    handle: backend.ControlledSandboxHandle | None,
    *,
    exec_digest: str | None = None,
    operation_id: str | None = None,
) -> Any:
    spec = channel.METHODS[method]
    operation = operation_id or "operation-" + (
        "f" if method in {"begin_write_exact", "write_chunk_exact", "commit_write_exact", "reconcile_write_exact", "abort_write_exact"}
        else "a" if method == "persist_exact"
        else "b" if method == "hydrate_exact"
        else "e"
    ) * 32
    observation = "observation-" + "f" * 32
    transfer = "transfer-" + "d" * 32
    data = b"written"
    data_digest = backend._sha256_bytes(data)
    common = {
        "schema_version": f"bluefire.strix-controlled-{spec.kind}-request.v1",
        "request_digest": "sha256:" + "0" * 64,
        "identity_digest": profile.identity_digest,
    }
    if method == "create_exact":
        return backend.ControlledCreateRequest.create(profile)
    if method in {"reconcile_create", "cancel_exact", "running_exact", "delete_exact"}:
        values: dict[str, Any] = dict(
            attempt_id=profile.attempt_id,
            relay_digest=profile.relay_digest,
            relay_upstream_digest=profile.relay_upstream_digest,
            relay_channel_digest=profile.relay_channel_digest,
            relay_retry_digest=profile.relay_retry_digest,
            observation_id=observation if method == "running_exact" else None,
            handle=None if method == "reconcile_create" else handle,
            operation_digest=exec_digest if method == "cancel_exact" else backend.ControlledCreateRequest.create(profile).request_digest if method == "reconcile_create" else None,
        )
    elif method == "exec_exact":
        values = dict(operation_id=operation, handle=handle, argv=("echo", "hello"), timeout_seconds=120.0, working_directory="/workspace", stdin_mode="disabled", pty=False)
    elif method == "read_exact":
        values = dict(observation_id=observation, handle=handle, workspace_path="/workspace/read.txt", byte_limit=backend.MAX_WORKSPACE_OBJECT_BYTES)
    elif method == "begin_write_exact":
        values = dict(operation_id=operation, handle=handle, workspace_path="/workspace/out.txt", content_size=len(data), content_digest=data_digest, chunk_size=backend.WRITE_CHUNK_BYTES)
    elif method == "write_chunk_exact":
        values = dict(operation_id=operation, handle=handle, transfer_id=transfer, index=0, offset=0, total_size=len(data), content_digest=data_digest, chunk_digest=data_digest, chunk=data)
    elif method == "commit_write_exact":
        values = dict(operation_id=operation, handle=handle, transfer_id=transfer, workspace_path="/workspace/out.txt", content_size=len(data), content_digest=data_digest)
    elif method == "reconcile_write_exact":
        values = dict(operation_id=operation, handle=handle, transfer_id=transfer, workspace_path="/workspace/out.txt", content_size=len(data), content_digest=data_digest)
    elif method == "abort_write_exact":
        values = dict(operation_id=operation, handle=handle, transfer_id=transfer)
    elif method == "persist_exact":
        values = dict(operation_id=operation, handle=handle, byte_limit=backend.MAX_WORKSPACE_OBJECT_BYTES, archive=None, archive_digest=None)
    elif method == "hydrate_exact":
        archive = b"sealed-workspace-archive"
        values = dict(operation_id=operation, handle=handle, byte_limit=backend.MAX_WORKSPACE_OBJECT_BYTES, archive=archive, archive_digest=backend._sha256_bytes(archive))
    elif method == "resolve_caido_exact":
        values = dict(handle=handle, container_port=backend.CAIDO_PORT, relay_digest=profile.relay_digest, upstream_digest=profile.relay_upstream_digest, channel_digest=profile.relay_channel_digest, retry_contract_digest=profile.relay_retry_digest)
    else:
        raise AssertionError(method)
    draft = spec.request_type(**common, **values)
    digest = backend._request_digest(spec.kind, profile, channel._request_body(spec, draft))
    return replace(draft, request_digest=digest)


def _mutate(frame: bytes, change: Any) -> bytes:
    value = channel.decode_frame(frame)
    change(value)
    return channel.encode_frame(value)


def _create(worker: channel.WorkerChannel, controller: channel.ControllerChannel, transport: FakeTransport) -> backend.ControlledSandboxHandle:
    request = backend.ControlledCreateRequest.create(worker.profile)
    frame = worker.request("create_exact", request, request_id="1" * 32, now_ns=100)
    method, request_id, decoded = controller.request(frame, now_ns=100)
    assert method == "create_exact" and decoded == request
    receipt = _complete(transport.create_exact(decoded))
    response = controller.response(request_id, receipt, now_ns=101)
    _method, _id, worker_receipt = worker.response(response, now_ns=101)
    assert worker_receipt.handle.opaque_ref is not transport.handle.opaque_ref
    return cast(backend.ControlledSandboxHandle, worker_receipt.handle)


def test_exact_fifteen_method_table_and_all_roundtrips() -> None:
    assert set(channel.METHODS) == set(backend._TRANSPORT_METHODS)
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    dispatcher = channel.ControllerDispatcher(controller, transport)
    methods = (
        "reconcile_create", "exec_exact", "read_exact",
        "begin_write_exact", "write_chunk_exact", "commit_write_exact",
        "reconcile_write_exact", "abort_write_exact", "running_exact",
        "persist_exact", "hydrate_exact", "resolve_caido_exact", "delete_exact",
    )
    for index, method in enumerate(methods, 2):
        request = _request(method, worker.profile, handle)
        request_id = f"{index:032x}"
        tick = index * 10
        frame = worker.request(method, request, request_id=request_id, now_ns=tick + 100)
        response = _complete(dispatcher.dispatch(frame, received_ns=tick + 100, replied_ns=tick + 101))
        if method != "reconcile_create":
            assert transport.calls[-1][1].handle is transport.handle
        observed_method, observed_id, observed = worker.response(response, now_ns=tick + 101)
        assert (observed_method, observed_id) == (method, request_id)
        assert type(observed) is channel.METHODS[method].receipt_type
    assert worker.pending_count == controller.pending_count == 0
    assert worker.usable and controller.usable


def test_literal_dispatcher_uses_original_handle_and_sanitizes_effect_error() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    dispatcher = channel.ControllerDispatcher(controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    response = _complete(dispatcher.dispatch(frame, received_ns=200, replied_ns=201))
    assert worker.response(response, now_ns=201)[2].stdout == b"stdout"
    assert transport.calls[-1][1].handle is transport.handle
    transport.exec_failure = RuntimeError("SENSITIVE_EXCEPTION_TEXT")
    request = _request("exec_exact", worker.profile, handle, operation_id="operation-" + "1" * 32)
    frame = worker.request("exec_exact", request, request_id="3" * 32, now_ns=300)
    with pytest.raises(channel.ControlledWorkerChannelError) as failure:
        _complete(dispatcher.dispatch(frame, received_ns=300, replied_ns=301))
    assert "SENSITIVE_EXCEPTION_TEXT" not in str(failure.value)
    assert failure.value.__context__ is None
    assert not controller.usable


@pytest.mark.parametrize("field", ["claim_digest", "plan_digest", "profile_digest", "identity_digest", "controller_fence", "attempt_id", "nonce", "deadline_ns"])
def test_crossed_binding_or_fence_poisoned(field: str) -> None:
    worker, controller, _transport = _pair()
    frame = worker.request("create_exact", backend.ControlledCreateRequest.create(worker.profile), request_id="1" * 32, now_ns=100)

    def forge(value: dict[str, Any]) -> None:
        value["binding"][field] = 123 if field == "deadline_ns" else "forged"

    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(_mutate(frame, forge), now_ns=100)
    assert not controller.usable


def test_float_for_integer_binding_and_reply_sequence_are_refused() -> None:
    worker, controller, transport = _pair()
    request = backend.ControlledCreateRequest.create(worker.profile)
    frame = worker.request("create_exact", request, request_id="1" * 32, now_ns=100)
    forged = _mutate(frame, lambda value: value["binding"].update(deadline_ns=100_000.0))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(forged, now_ns=100)
    worker, controller, transport = _pair()
    frame = worker.request("create_exact", request, request_id="1" * 32, now_ns=100)
    _method, request_id, decoded = controller.request(frame, now_ns=100)
    response = controller.response(request_id, _complete(transport.create_exact(decoded)), now_ns=101)
    forged_reply = _mutate(response, lambda value: value.update(reply_to_sequence=1.0))
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.response(forged_reply, now_ns=101)
    assert not worker.usable


@pytest.mark.parametrize("change", ["extra", "missing", "duplicate", "spacing", "nan", "wrong_sequence", "unknown_method", "wrong_request_digest"])
def test_noncanonical_unknown_or_unjoined_request_poisoned(change: str) -> None:
    worker, controller, _transport = _pair()
    frame = worker.request("create_exact", backend.ControlledCreateRequest.create(worker.profile), request_id="1" * 32, now_ns=100)
    if change in {"duplicate", "spacing", "nan"}:
        raw = frame[4:]
        if change == "duplicate":
            raw = raw[:-1] + b',"sequence":1}'
        elif change == "spacing":
            raw = b" " + raw
        else:
            raw = raw[:-1] + b',"extra":NaN}'
        frame = len(raw).to_bytes(4, "little") + raw
    else:
        def alter(value: dict[str, Any]) -> None:
            if change == "extra":
                value["extra"] = "secret"
            elif change == "missing":
                del value["binding"]
            elif change == "wrong_sequence":
                value["sequence"] = 2
            elif change == "unknown_method":
                value["method"] = "arbitrary_host_command"
            else:
                value["payload"]["request_digest"] = "sha256:" + "0" * 64
        frame = _mutate(frame, alter)
    with pytest.raises(channel.ControlledWorkerChannelError) as failure:
        controller.request(frame, now_ns=100)
    assert "secret" not in str(failure.value)
    assert not controller.usable


def test_oversized_header_refused_before_body_and_partial_eof_poisoned() -> None:
    decoder = channel.FrameDecoder()
    with pytest.raises(channel.ControlledWorkerChannelError):
        decoder.feed((channel.MAX_FRAME_BYTES + 1).to_bytes(4, "little") + b"secret")
    assert decoder.poisoned and not decoder._buffer
    decoder = channel.FrameDecoder()
    assert decoder.feed(b"\x20\x00") == []
    with pytest.raises(channel.ControlledWorkerChannelError):
        decoder.eof()
    assert decoder.poisoned
    with pytest.raises(channel.ControlledWorkerChannelError):
        channel.decode_frame((channel.MAX_FRAME_BYTES + 1).to_bytes(4, "little"))


def test_replay_request_id_and_lost_response_poison_channel() -> None:
    worker, controller, _transport = _pair()
    frame = worker.request("create_exact", backend.ControlledCreateRequest.create(worker.profile), request_id="1" * 32, now_ns=100)
    controller.request(frame, now_ns=100)
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(frame, now_ns=101)
    assert not controller.usable
    worker.eof()
    assert not worker.usable and worker.pending_count == 1
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("create_exact", backend.ControlledCreateRequest.create(worker.profile), request_id="2" * 32, now_ns=102)
    second_worker, _second_controller, _transport = _pair()
    second_worker.request("create_exact", backend.ControlledCreateRequest.create(second_worker.profile), request_id="1" * 32, now_ns=100)
    second_worker.timeout()
    assert not second_worker.usable
    third_worker, _third_controller, _transport = _pair()
    third_worker.request("create_exact", backend.ControlledCreateRequest.create(third_worker.profile), request_id="1" * 32, now_ns=100)
    third_worker.partial()
    assert not third_worker.usable and third_worker.pending_count == 1


def test_fresh_request_id_cannot_replay_create_or_exec() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    create = backend.ControlledCreateRequest.create(worker.profile)
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("create_exact", create, request_id="2" * 32, now_ns=200)
    execution = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", execution, request_id="2" * 32, now_ns=201)
    controller.request(frame, now_ns=201)
    replay = _mutate(frame, lambda value: value.update(sequence=3, request_id="3" * 32))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(replay, now_ns=202)
    assert not controller.usable and len(transport.calls) == 1


def test_only_exec_and_its_cancel_may_overlap() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("read_exact", worker.profile, handle)
    frame = worker.request("read_exact", request, request_id="2" * 32, now_ns=200)
    controller.request(frame, now_ns=200)
    another = _request("exec_exact", worker.profile, handle)
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("exec_exact", another, request_id="3" * 32, now_ns=201)
    assert worker.pending_count == controller.pending_count == 1


def test_channel_request_budget_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    monkeypatch.setattr(channel, "MAX_REQUESTS", 1)
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("read_exact", _request("read_exact", worker.profile, handle), request_id="2" * 32, now_ns=200)
    assert worker.usable and worker.pending_count == 0


def test_cancel_can_complete_before_in_flight_exec() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    execution = _request("exec_exact", worker.profile, handle)
    cancellation = _request("cancel_exact", worker.profile, handle, exec_digest=execution.request_digest)
    exec_frame = worker.request("exec_exact", execution, request_id="2" * 32, now_ns=200)
    cancel_frame = worker.request("cancel_exact", cancellation, request_id="3" * 32, now_ns=201)
    _m, exec_id, server_exec = controller.request(exec_frame, now_ns=200)
    _m, cancel_id, server_cancel = controller.request(cancel_frame, now_ns=201)
    assert worker.pending_count == controller.pending_count == 2
    cancel_receipt = _complete(transport.cancel_exact(server_cancel))
    cancel_response = controller.response(cancel_id, cancel_receipt, now_ns=202)
    assert worker.response(cancel_response, now_ns=202)[0] == "cancel_exact"
    exec_receipt = _complete(transport.exec_exact(server_exec))
    exec_response = controller.response(exec_id, exec_receipt, now_ns=203)
    assert worker.response(exec_response, now_ns=203)[0] == "exec_exact"
    assert worker.pending_count == controller.pending_count == 0


def test_forged_response_join_and_payload_bound_poison() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = controller.request(frame, now_ns=200)
    receipt = _complete(transport.exec_exact(decoded))
    response = controller.response(request_id, receipt, now_ns=201)

    def forge(value: dict[str, Any]) -> None:
        value["reply_to_sequence"] = 100
        value["payload"]["stdout"] = "SENSITIVE_TEXT"

    with pytest.raises(channel.ControlledWorkerChannelError) as failure:
        worker.response(_mutate(response, forge), now_ns=201)
    assert "SENSITIVE_TEXT" not in str(failure.value)
    assert not worker.usable
    with pytest.raises(channel.ControlledWorkerChannelError):
        channel._decode_bytes("A" * (4 * ((backend.WRITE_CHUNK_BYTES + 2) // 3) + 4), backend.WRITE_CHUNK_BYTES)


def test_invalid_local_receipt_poisons_controller_after_effect() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = controller.request(frame, now_ns=200)
    receipt = _complete(transport.exec_exact(decoded))
    bad_receipt = replace(receipt, stdout_digest="sha256:" + "0" * 64)
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.response(request_id, bad_receipt, now_ns=201)
    assert not controller.usable and controller.pending_count == 1


def test_opaque_reference_never_serialized_or_rendered() -> None:
    class Secret:
        def __repr__(self) -> str:
            return "SENSITIVE_OPAQUE_REF"

    worker, controller, transport = _pair()
    transport.handle = backend.ControlledSandboxHandle(
        attempt_id=worker.profile.attempt_id,
        resource_id="sandbox-" + "b" * 32,
        resource_digest="sha256:" + "c" * 64,
        opaque_ref=Secret(),
    )
    handle = _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    assert b"opaque_ref" not in frame and b"SENSITIVE_OPAQUE_REF" not in frame
    assert "SENSITIVE_OPAQUE_REF" not in repr(channel.decode_frame(frame))
    assert "SENSITIVE_OPAQUE_REF" not in repr(handle)


def test_digest_forgery_and_noncanonical_path_rejected_before_dispatch() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("read_exact", worker.profile, handle)
    bad = replace(request, workspace_path="/workspace/../secrets")
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("read_exact", bad, request_id="2" * 32, now_ns=200)
    assert worker.usable and controller.usable
    valid = worker.request("read_exact", request, request_id="2" * 32, now_ns=201)
    forged = _mutate(valid, lambda value: value["payload"]["handle"].update({"resource_digest": content_hash("secrets")}))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(forged, now_ns=201)
    assert not controller.usable


def test_worker_refuses_controller_opaque_handle() -> None:
    worker, controller, transport = _pair()
    _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, transport.handle)
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    assert worker.usable and worker.pending_count == 0


@pytest.mark.parametrize("method", ["write_chunk_exact", "hydrate_exact"])
def test_raw_bytes_are_verified_separately_from_request_digest(method: str) -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    if method == "write_chunk_exact":
        begin = _request("begin_write_exact", worker.profile, handle)
        begin_frame = worker.request("begin_write_exact", begin, request_id="4" * 32, now_ns=150)
        _begin_method, begin_id, decoded_begin = controller.request(begin_frame, now_ns=150)
        begin_receipt = _complete(transport.begin_write_exact(decoded_begin))
        begin_response = controller.response(begin_id, begin_receipt, now_ns=151)
        worker.response(begin_response, now_ns=151)
    request = _request(method, worker.profile, handle)
    frame = worker.request(method, request, request_id="2" * 32, now_ns=200)
    field = "chunk" if method == "write_chunk_exact" else "archive"
    forged = _mutate(frame, lambda value: value["payload"].update({field: "Y2hhbmdlZA=="}))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(forged, now_ns=200)
    assert not controller.usable


@pytest.mark.parametrize("value", [True, 120, 0.0, 121.0])
def test_exec_timeout_requires_exact_finite_float(value: Any) -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    forged = _mutate(frame, lambda envelope: envelope["payload"].update({"timeout_seconds": value}))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(forged, now_ns=200)


def test_nonfinite_json_and_expired_reply_poison() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("exec_exact", worker.profile, handle)
    frame = worker.request("exec_exact", request, request_id="2" * 32, now_ns=200)
    raw = frame[4:].replace(b"120.0", b"1e999")
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(len(raw).to_bytes(4, "little") + raw, now_ns=200)
    assert not controller.usable
    second_worker, second_controller, second_transport = _pair()
    second_handle = _create(second_worker, second_controller, second_transport)
    second_request = _request("exec_exact", second_worker.profile, second_handle)
    request_frame = second_worker.request("exec_exact", second_request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = second_controller.request(request_frame, now_ns=200)
    receipt = _complete(second_transport.exec_exact(decoded))
    response = second_controller.response(request_id, receipt, now_ns=201)
    with pytest.raises(channel.ControlledWorkerChannelError):
        second_worker.response(response, now_ns=second_worker.binding.deadline_ns)
    assert not second_worker.usable


def test_exposed_port_rejects_float_and_unknown_outcome_latches_both_sides() -> None:
    worker, controller, transport = _pair()
    frame = worker.request("create_exact", backend.ControlledCreateRequest.create(worker.profile), request_id="1" * 32, now_ns=100)
    forged = _mutate(frame, lambda value: value["payload"].update(exposed_ports=[48080.0]))
    with pytest.raises(channel.ControlledWorkerChannelError):
        controller.request(forged, now_ns=100)
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    transport.lifecycle = "unknown"
    request = _request("running_exact", worker.profile, handle)
    frame = worker.request("running_exact", request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = controller.request(frame, now_ns=200)
    receipt = _complete(transport.running_exact(decoded))
    response = controller.response(request_id, receipt, now_ns=201)
    assert not controller.usable
    worker.response(response, now_ns=201)
    assert not worker.usable


def test_verified_delete_retires_handle_before_another_effect() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    request = _request("delete_exact", worker.profile, handle)
    frame = worker.request("delete_exact", request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = controller.request(frame, now_ns=200)
    response = controller.response(request_id, _complete(transport.delete_exact(decoded)), now_ns=201)
    worker.response(response, now_ns=201)
    assert worker.usable and controller.usable
    with pytest.raises(channel.ControlledWorkerChannelError):
        worker.request("exec_exact", _request("exec_exact", worker.profile, handle), request_id="3" * 32, now_ns=202)
    assert not controller._handles


def test_unverified_delete_poisons_without_retirement_claim() -> None:
    worker, controller, transport = _pair()
    handle = _create(worker, controller, transport)
    transport.delete_relay_lifecycle = "active"
    request = _request("delete_exact", worker.profile, handle)
    frame = worker.request("delete_exact", request, request_id="2" * 32, now_ns=200)
    _method, request_id, decoded = controller.request(frame, now_ns=200)
    response = controller.response(request_id, _complete(transport.delete_exact(decoded)), now_ns=201)
    assert not controller.usable and controller._handles
    worker.response(response, now_ns=201)
    assert not worker.usable


def test_create_reconciliation_uses_exact_digest_on_fresh_channel() -> None:
    profile = _profile()
    binding = replace(_binding(profile), nonce="e" * 32)
    worker = channel.WorkerChannel(profile, binding)
    controller = channel.ControllerChannel(profile, binding)
    transport = FakeTransport().bind(profile)
    request = _request("reconcile_create", profile, None)
    frame = worker.request("reconcile_create", request, request_id="1" * 32, now_ns=100)
    _method, request_id, decoded = controller.request(frame, now_ns=100)
    response = controller.response(request_id, _complete(transport.reconcile_create(decoded)), now_ns=101)
    assert worker.response(response, now_ns=101)[2].lifecycle == "absent"
