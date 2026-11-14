from __future__ import annotations

import struct
from dataclasses import asdict, replace
from typing import Any, cast

import pytest

from bluefire.engine_docker_control import (
    DockerApiOperation,
    DockerApiPolicyV2,
    EngineDockerPolicyError,
    authorize_docker_api_request,
)
from bluefire.engine_docker_exec_admission import (
    DockerExecAdmissionError,
    DockerExecAdmissionV2,
    DockerExecBindingV2,
    validate_strix_exec_argv,
)
from bluefire.engine_docker_proxy import DockerDaemonExchange
from bluefire.strix_controlled_backend import (
    ControlledExecRequest,
    ControlledRuntimeProfile,
    ControlledSandboxHandle,
)
from bluefire.util import content_hash
from tests_platform.docker_exec_runtime_fixture import runtime_resources
from tests_platform.test_engine_docker_control import policy_v2, request, v2_policy_inputs
from tests_platform.test_engine_docker_proxy import (
    CONTAINER_ID,
    EXEC_ID,
    OTHER_CONTAINER_ID,
    Cancel,
    Clock,
    Transport,
    ownership,
    proxy,
    raw_request,
    raw_response,
)

CREATE = f"/v1.47/containers/{CONTAINER_ID}/exec"
START = f"/v1.47/exec/{EXEC_ID}/start"
INSPECT = f"/v1.47/exec/{EXEC_ID}/json"
SHELL = ("sh", "-lc", "printf '%s\\n' value")
BASH_SHELL = ("bash", "-lc", "printf '%s\\n' value")


def admission(
    *,
    policy: DockerApiPolicyV2 | None = None,
    profile: ControlledRuntimeProfile | None = None,
    argv: tuple[str, ...] = SHELL,
    operation_id: str = "operation-" + "a" * 32,
    timeout: float = 5.0,
    container_id: str = CONTAINER_ID,
) -> DockerExecAdmissionV2:
    actual_policy = policy or policy_v2()
    actual_profile = profile or ControlledRuntimeProfile(
        **v2_policy_inputs()["execution_identity"].to_dict()["controlled_runtime_profile"]
    )
    handle = ControlledSandboxHandle(
        attempt_id=actual_profile.attempt_id,
        resource_id="sandbox-" + "b" * 32,
        resource_digest=content_hash({"owned_container": container_id}),
        opaque_ref=object(),
    )
    body = {
        "schema_version": "bluefire.strix-controlled-exec-request.v1",
        "identity_digest": actual_profile.identity_digest,
        "attempt_id": actual_profile.attempt_id,
        "profile_digest": actual_profile.profile_digest,
        "resource_digest": handle.resource_digest,
        "operation_id": operation_id,
        "argv": list(argv),
        "timeout_seconds": float(timeout),
        "working_directory": "/workspace",
        "stdin_mode": "disabled",
        "pty": False,
    }
    controlled = ControlledExecRequest(
        schema_version="bluefire.strix-controlled-exec-request.v1",
        request_digest=content_hash(body),
        identity_digest=actual_profile.identity_digest,
        operation_id=operation_id,
        handle=handle,
        argv=argv,
        timeout_seconds=timeout,
        working_directory="/workspace",
    )
    return DockerExecAdmissionV2(
        actual_policy.policy_digest,
        actual_policy.execution_identity_digest,
        container_id,
        actual_profile,
        controlled,
    )


def exec_body(admitted: DockerExecAdmissionV2) -> dict[str, Any]:
    return {
        "AttachStderr": True,
        "AttachStdin": False,
        "AttachStdout": True,
        "Cmd": list(admitted.request.argv),
        "DetachKeys": "",
        "Env": list(admitted.environment),
        "Privileged": False,
        "Tty": False,
        "User": "1000:1000",
        "WorkingDir": "/workspace",
    }


def inspect_body(admitted: DockerExecAdmissionV2) -> dict[str, Any]:
    return {
        "ID": EXEC_ID,
        "ContainerID": CONTAINER_ID,
        "Running": False,
        "ExitCode": 0,
        "OpenStdin": False,
        "OpenStdout": True,
        "OpenStderr": True,
        "ProcessConfig": {
            "arguments": list(admitted.request.argv[1:]),
            "entrypoint": admitted.request.argv[0],
            "privileged": False,
            "tty": False,
            "user": "1000:1000",
        },
    }


def create_exec(
    transport: Transport | None = None,
    *,
    admitted: DockerExecAdmissionV2 | None = None,
    clock: Clock | None = None,
):
    current = admitted or admission()
    actual_transport = transport or Transport(raw_response(201, {"Id": EXEC_ID}))
    resources = runtime_resources(current, clock=clock)
    item, audit, actual_clock = proxy(
        actual_transport,
        policy_value=policy_v2(),
        owned=ownership(container=True),
        clock=resources.clock,
        exec_runtime=resources.runtime,
        exec_cancellation=resources.cancellation,
    )
    cast(Any, item)._test_exec_resources = resources
    reply = item.handle(
        raw_request("POST", CREATE, exec_body(current)), Cancel(), exec_admission=current
    )
    return item, actual_transport, audit, actual_clock, current, reply


@pytest.mark.parametrize("argv", [SHELL, BASH_SHELL])
@pytest.mark.parametrize("timeout", [5.0, 120.0])
def test_exact_create_start_inspect_registers_complete_request_bound_operation(
    argv: tuple[str, ...],
    timeout: float,
) -> None:
    bounds: list[dict[str, Any]] = []

    class BoundedTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            bounds.append(kwargs)
            return super().exchange(*args, **kwargs)

    item, transport, audit, _clock, admitted, created = create_exec(
        BoundedTransport(raw_response(201, {"Id": EXEC_ID})),
        admitted=admission(argv=argv, timeout=timeout),
    )
    assert created.status_code == 201
    state = item.snapshot()
    initial_deadline = state.v2_exec_bindings[0].deadline_monotonic_ns
    assert initial_deadline is not None
    initial_started = audit.records[0].started_monotonic_ns
    assert initial_deadline - initial_started == int(timeout * 1_000_000_000)
    assert bounds[0]["deadline_monotonic_ns"] == initial_started + int(
        min(timeout, 10) * 1_000_000_000
    )
    assert state.ownership.exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert state.v2_exec_bindings == (
        DockerExecBindingV2(EXEC_ID, admitted, deadline_monotonic_ns=initial_deadline),
    )
    stream = struct.pack(">BxxxI", 1, 6) + b"value\n"
    transport.response = raw_response(
        200, stream, content_type="application/vnd.docker.multiplexed-stream"
    )
    started = item.handle(
        raw_request("POST", START, {"Detach": False, "Tty": False}),
        Cancel(),
        exec_admission=admitted,
    )
    assert started.status_code == 200 and started.body == stream
    assert bounds[-1]["response_byte_limit"] == admitted.profile.exec_output_limit_bytes
    assert bounds[-1]["deadline_monotonic_ns"] <= initial_deadline
    assert item.snapshot().v2_exec_bindings[0].deadline_monotonic_ns == initial_deadline
    assert item.snapshot().v2_exec_bindings[0].phase == "started"
    transport.response = raw_response(200, inspect_body(admitted))
    assert (
        item.handle(raw_request("GET", INSPECT), Cancel(), exec_admission=admitted).status_code
        == 200
    )
    final = item.snapshot()
    assert final.v2_exec_bindings[0].deadline_monotonic_ns == initial_deadline
    assert all(bound["deadline_monotonic_ns"] <= initial_deadline for bound in bounds)
    assert final.v2_exec_bindings[0].phase == "complete"
    assert not final.reconciliation_required
    assert [row.operation for row in audit.records if row.phase == "published"] == [
        "container_exec_create",
        "exec_start",
        "exec_inspect",
    ]
    assert admitted.to_dict()["request_digest"] == admitted.request.request_digest
    assert admitted.to_dict()["command_digest"] == content_hash({"argv": list(argv)})


@pytest.mark.parametrize(
    "argv",
    [
        SHELL,
        BASH_SHELL,
        ("bash", "-c", "first\nsecond\tvalue"),
        ("bash", "-lc", "first\nsecond\tvalue"),
        ("sh", "-c", "first\nsecond\tvalue"),
        ("mkdir", "-p", "/workspace"),
    ],
)
def test_reviewed_shell_envelope_and_workspace_startup_grammar_are_admitted(
    argv: tuple[str, ...],
) -> None:
    admitted = admission(argv=argv)
    decision = authorize_docker_api_request(
        policy_v2(),
        request("POST", CREATE, exec_body(admitted)),
        ownership(container=True),
        exec_admission=admitted,
    )
    assert decision.operation is DockerApiOperation.CONTAINER_EXEC_CREATE


@pytest.mark.parametrize(
    "argv",
    [
        ("python3", "-c", "print(1)"),
        ("bash", "-ic", "true"),
        ("/bin/bash", "-lc", "true"),
        ("bash", "--login", "-c", "true"),
        ("bash", "-lc", "true", "extra"),
        ("zsh", "-lc", "true"),
        ("sh", "-lc", "true", "extra"),
        ("mkdir", "-p", "/tmp"),
        ("sudo", "-u", "root", "sh", "-lc", "true"),
        ("sh", "-c", "x" * 8192),
        ("sh", "-c", "a\rb"),
        ("sh", "-c", "a\x00b"),
        ("sh", "-c", "a\x7fb"),
    ],
)
def test_unreviewed_direct_helpers_shells_and_out_of_bound_commands_are_refused(
    argv: tuple[str, ...],
) -> None:
    with pytest.raises(DockerExecAdmissionError):
        validate_strix_exec_argv(argv)


@pytest.mark.parametrize(
    "drifted_argv",
    [
        ["sh", "-lc", BASH_SHELL[2]],
        ["bash", "-c", BASH_SHELL[2]],
        ["bash", "-lc", BASH_SHELL[2], "extra"],
        ["bash", "-lc", "different model command"],
    ],
)
def test_pinned_bash_shell_request_refuses_shell_flag_argument_and_script_drift(
    drifted_argv: list[str],
) -> None:
    admitted = admission(argv=BASH_SHELL)
    body = exec_body(admitted)
    body["Cmd"] = drifted_argv
    transport = Transport(raw_response(201, {"Id": EXEC_ID}))
    item, _audit, _clock = proxy(
        transport, policy_value=policy_v2(), owned=ownership(container=True)
    )
    assert (
        item.handle(
            raw_request("POST", CREATE, body), Cancel(), exec_admission=admitted
        ).status_code
        == 503
    )
    assert not transport.seen
    assert not item.snapshot().reconciliation_required


@pytest.mark.parametrize(
    "method,target,body",
    [
        ("POST", CREATE, "create"),
        ("POST", START, "start"),
        ("GET", INSPECT, "inspect"),
    ],
)
def test_v2_exec_remains_blanket_refused_without_explicit_admission(
    method: str, target: str, body: str
) -> None:
    admitted = admission()
    payload: dict[str, object] | None = (
        exec_body(admitted)
        if body == "create"
        else ({"Detach": False, "Tty": False} if body == "start" else None)
    )
    transport = Transport(raw_response(201, {"Id": EXEC_ID}))
    item, _audit, _clock = proxy(
        transport, policy_value=policy_v2(), owned=ownership(container=True, exec_id=True)
    )
    assert item.handle(raw_request(method, target, payload), Cancel()).status_code == 503
    assert not transport.seen
    assert not item.snapshot().reconciliation_required


@pytest.mark.parametrize(
    "field,value",
    [
        ("Env", []),
        ("Env", ["http_proxy=http://host.docker.internal:48080"]),
        ("AttachStdin", True),
        ("AttachStdout", False),
        ("AttachStderr", False),
        ("Privileged", True),
        ("Tty", True),
        ("DetachKeys", "ctrl-p,ctrl-q"),
        ("User", "root"),
        ("User", "1001:1001"),
        ("WorkingDir", "/tmp"),
        ("Cmd", ["sh", "-lc", "different"]),
    ],
)
def test_exec_create_refuses_command_environment_and_execution_option_drift(
    field: str, value: Any
) -> None:
    admitted = admission()
    body = exec_body(admitted)
    body[field] = value
    transport = Transport(raw_response(201, {"Id": EXEC_ID}))
    item, _audit, _clock = proxy(
        transport, policy_value=policy_v2(), owned=ownership(container=True)
    )
    assert (
        item.handle(
            raw_request("POST", CREATE, body), Cancel(), exec_admission=admitted
        ).status_code
        == 503
    )
    assert not transport.seen


def test_exec_create_requires_environment_field_and_cannot_accept_added_fields() -> None:
    admitted = admission()
    for change in ("missing", "extra"):
        body = exec_body(admitted)
        if change == "missing":
            del body["Env"]
        else:
            body["Detach"] = True
        with pytest.raises(EngineDockerPolicyError):
            authorize_docker_api_request(
                policy_v2(),
                request("POST", CREATE, body),
                ownership(container=True),
                exec_admission=admitted,
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_digest", "sha256:" + "0" * 64),
        ("operation_id", "operation-invalid"),
        ("identity_digest", "sha256:" + "0" * 64),
        ("timeout_seconds", 121.0),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", True),
        ("working_directory", "/tmp"),
        ("stdin_mode", "enabled"),
        ("pty", True),
    ],
)
def test_public_request_cannot_change_without_valid_contract_and_digest(
    field: str, value: Any
) -> None:
    admitted = admission()
    with pytest.raises(DockerExecAdmissionError):
        replace(admitted, request=replace(admitted.request, **{field: value}))


@pytest.mark.parametrize(
    "field", ["policy_digest", "execution_identity_digest", "container_id", "profile"]
)
def test_admission_must_bind_exact_policy_profile_execution_and_owned_container(field: str) -> None:
    admitted = admission()
    value: Any = "sha256:" + "0" * 64
    if field == "container_id":
        value = OTHER_CONTAINER_ID
    if field == "profile":
        row = asdict(admitted.profile)
        row["manifest_digest"] = "sha256:" + "0" * 64
        del row["profile_digest"]
        profile = ControlledRuntimeProfile(**row, profile_digest=content_hash(row))
        changed = admission(profile=profile)
    else:
        changed = replace(admitted, **{field: value})
    with pytest.raises(EngineDockerPolicyError):
        authorize_docker_api_request(
            policy_v2(),
            request("POST", CREATE, exec_body(changed)),
            ownership(container=True),
            exec_admission=changed,
        )


@pytest.mark.parametrize("drift", ["operation", "command", "resource"])
def test_start_and_inspect_require_same_admission_as_registered_create(drift: str) -> None:
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
    if drift == "operation":
        changed = admission(operation_id="operation-" + "c" * 32)
    elif drift == "command":
        changed = admission(argv=("sh", "-lc", "different"))
    else:
        handle = replace(admitted.request.handle, resource_digest="sha256:" + "d" * 64)
        row = admitted.request
        digest = content_hash(
            {
                "schema_version": row.schema_version,
                "identity_digest": row.identity_digest,
                "attempt_id": admitted.profile.attempt_id,
                "profile_digest": admitted.profile.profile_digest,
                "resource_digest": handle.resource_digest,
                "operation_id": row.operation_id,
                "argv": list(row.argv),
                "timeout_seconds": float(row.timeout_seconds),
                "working_directory": "/workspace",
                "stdin_mode": "disabled",
                "pty": False,
            }
        )
        changed = replace(admitted, request=replace(row, handle=handle, request_digest=digest))
    requests: tuple[tuple[str, str, dict[str, object] | None], ...] = (
        ("POST", START, {"Detach": False, "Tty": False}),
        ("GET", INSPECT, None),
    )
    for method, target, body in requests:
        assert (
            item.handle(
                raw_request(method, target, body), Cancel(), exec_admission=changed
            ).status_code
            == 503
        )
    assert len(transport.seen) == 1
    assert not item.snapshot().reconciliation_required


def test_exec_create_and_start_cannot_be_replayed_or_overlap_unsettled_operation() -> None:
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
    assert (
        item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        ).status_code
        == 503
    )
    next_operation = admission(operation_id="operation-" + "c" * 32)
    assert (
        item.handle(
            raw_request("POST", CREATE, exec_body(next_operation)),
            Cancel(),
            exec_admission=next_operation,
        ).status_code
        == 503
    )
    transport.response = raw_response(
        200, b"", content_type="application/vnd.docker.multiplexed-stream"
    )
    start = raw_request("POST", START, {"Detach": False, "Tty": False})
    assert item.handle(start, Cancel(), exec_admission=admitted).status_code == 200
    assert item.handle(start, Cancel(), exec_admission=admitted).status_code == 503
    assert len(transport.seen) == 2


@pytest.mark.parametrize("field", ["Detach", "Tty"])
def test_start_refuses_detach_and_tty_before_transport(field: str) -> None:
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
    body: dict[str, object] = {"Detach": False, "Tty": False}
    body[field] = True
    assert (
        item.handle(raw_request("POST", START, body), Cancel(), exec_admission=admitted).status_code
        == 503
    )
    assert len(transport.seen) == 1
    assert not item.snapshot().reconciliation_required


def test_owned_legacy_exec_binding_cannot_substitute_for_v2_operation_binding() -> None:
    admitted = admission()
    transport = Transport(raw_response(200, inspect_body(admitted)))
    item, _audit, _clock = proxy(
        transport, policy_value=policy_v2(), owned=ownership(container=True, exec_id=True)
    )
    requests: tuple[tuple[str, str, dict[str, object] | None], ...] = (
        ("POST", START, {"Detach": False, "Tty": False}),
        ("GET", INSPECT, None),
    )
    for method, target, body in requests:
        assert (
            item.handle(
                raw_request(method, target, body), Cancel(), exec_admission=admitted
            ).status_code
            == 503
        )
    assert not transport.seen
    assert not item.snapshot().reconciliation_required


@pytest.mark.parametrize(
    "field,value",
    [
        ("Running", True),
        ("ExitCode", -1),
        ("OpenStdin", True),
        ("OpenStdout", False),
        ("OpenStderr", False),
        ("ContainerID", OTHER_CONTAINER_ID),
        ("ProcessConfig", {"entrypoint": "bash"}),
    ],
)
def test_inspect_refuses_running_or_drifted_process_and_requires_reconciliation(
    field: str, value: Any
) -> None:
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
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
    body = inspect_body(admitted)
    body[field] = value
    transport.response = raw_response(200, body)
    assert (
        item.handle(raw_request("GET", INSPECT), Cancel(), exec_admission=admitted).status_code
        == 503
    )
    assert item.snapshot().reconciliation_required
    assert item.snapshot().v2_exec_bindings[0].phase == "started"


def test_pretransport_cancellation_never_creates_exec_or_requires_reconciliation() -> None:
    admitted = admission()
    cancel = Cancel()
    cancel.value = True
    transport = Transport(raw_response(201, {"Id": EXEC_ID}))
    item, audit, _clock = proxy(
        transport, policy_value=policy_v2(), owned=ownership(container=True)
    )
    assert (
        item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), cancel, exec_admission=admitted
        ).status_code
        == 503
    )
    assert not transport.seen
    assert not item.snapshot().v2_exec_bindings
    assert not item.snapshot().reconciliation_required
    assert audit.records[-1].outcome == "cancelled"


def test_cancelled_create_preserves_discovered_exec_in_quarantine_without_publishing() -> None:
    admitted = admission()
    cancel = Cancel()

    class CancellingTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            response = super().exchange(*args, **kwargs)
            cancel.value = True
            return response

    transport = CancellingTransport(raw_response(201, {"Id": EXEC_ID}))
    resources = runtime_resources(admitted)
    item, _audit, _clock = proxy(
        transport,
        policy_value=policy_v2(),
        owned=ownership(container=True),
        clock=resources.clock,
        exec_runtime=resources.runtime,
        exec_cancellation=resources.cancellation,
    )
    cast(Any, item)._test_exec_resources = resources
    assert (
        item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), cancel, exec_admission=admitted
        ).status_code
        == 503
    )
    state = item.snapshot()
    assert state.reconciliation_required
    assert state.quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert not state.ownership.exec_bindings and not state.v2_exec_bindings


@pytest.mark.parametrize("failure", ["cancel", "timeout", "lost_response", "oversized_output"])
def test_uncertain_start_quarantines_known_exec_blocks_replay_and_preserves_original_binding(
    failure: str,
) -> None:
    clock = Clock()
    item, transport, _audit, _clock, admitted, reply = create_exec(clock=clock)
    assert reply.status_code == 201
    original_binding = item.snapshot().v2_exec_bindings[0]
    cancel = Cancel()
    original_exchange = transport.exchange

    def exchange(*args: Any, **kwargs: Any) -> DockerDaemonExchange:
        if failure == "lost_response":
            raise RuntimeError("response lost after request may have reached daemon")
        result = original_exchange(*args, **kwargs)
        if failure == "cancel":
            cancel.value = True
        if failure == "timeout":
            clock.value += 6_000_000_000
        return cast(DockerDaemonExchange, result)

    transport.exchange = exchange  # type: ignore[method-assign]
    output = (
        b"x" * (admitted.profile.exec_output_limit_bytes + 1)
        if failure == "oversized_output"
        else b""
    )
    transport.response = raw_response(
        200, output, content_type="application/vnd.docker.multiplexed-stream"
    )
    start = raw_request("POST", START, {"Detach": False, "Tty": False})
    assert item.handle(start, cancel, exec_admission=admitted).status_code == (
        504 if failure == "timeout" else 503
    )
    state = item.snapshot()
    assert state.reconciliation_required
    assert state.quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert state.v2_exec_bindings[0] == original_binding
    assert item.handle(start, Cancel(), exec_admission=admitted).status_code == 503
    assert item.snapshot() == state


def test_unknown_exec_create_effect_blocks_followup_without_inventing_exec_identity() -> None:
    class UnknownTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            raise RuntimeError("request sent; no response")

    admitted = admission()
    resources = runtime_resources(admitted)
    item, _audit, _clock = proxy(
        UnknownTransport(b""),
        policy_value=policy_v2(),
        owned=ownership(container=True),
        clock=resources.clock,
        exec_runtime=resources.runtime,
        exec_cancellation=resources.cancellation,
    )
    cast(Any, item)._test_exec_resources = resources
    raw = raw_request("POST", CREATE, exec_body(admitted))
    assert item.handle(raw, Cancel(), exec_admission=admitted).status_code == 503
    state = item.snapshot()
    assert state.reconciliation_required
    assert not state.ownership.exec_bindings and not state.v2_exec_bindings
    assert item.handle(raw, Cancel(), exec_admission=admitted).status_code == 503
    assert item.snapshot() == state


def test_exec_start_and_inspect_share_deadline_from_before_create_transport() -> None:
    clock = Clock()
    started_ns = clock.value
    deadlines: list[int] = []

    class AdvancingTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            deadlines.append(kwargs["deadline_monotonic_ns"])
            return super().exchange(*args, **kwargs)

    transport = AdvancingTransport(
        raw_response(201, {"Id": EXEC_ID}), clock=clock, advance_ns=2_000_000_000
    )
    item, _transport, audit, _clock, admitted, reply = create_exec(transport, clock=clock)
    assert reply.status_code == 201
    assert clock.value == started_ns + 2_000_000_000
    expected_deadline = item.snapshot().v2_exec_bindings[0].deadline_monotonic_ns
    assert expected_deadline is not None
    assert expected_deadline - audit.records[0].started_monotonic_ns == 5_000_000_000
    assert deadlines[0] == expected_deadline
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
    transport.advance_ns = 0
    transport.response = raw_response(200, inspect_body(admitted))
    assert (
        item.handle(raw_request("GET", INSPECT), Cancel(), exec_admission=admitted).status_code
        == 200
    )
    assert deadlines == [expected_deadline, expected_deadline, expected_deadline]
    assert item.snapshot().v2_exec_bindings[0].phase == "complete"


def test_exec_inspect_preserves_nonzero_exit_for_the_same_bound_exec() -> None:
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
    stream = struct.pack(">BxxxI", 2, 7) + b"failed\n"
    transport.response = raw_response(
        200, stream, content_type="application/vnd.docker.multiplexed-stream"
    )
    assert (
        item.handle(
            raw_request("POST", START, {"Detach": False, "Tty": False}),
            Cancel(),
            exec_admission=admitted,
        ).status_code
        == 200
    )
    terminal = inspect_body(admitted)
    terminal["ExitCode"] = 17
    transport.response = raw_response(200, terminal)
    inspected = item.handle(raw_request("GET", INSPECT), Cancel(), exec_admission=admitted)
    assert inspected.status_code == 200
    assert b'"ExitCode":17' in inspected.body
    assert item.snapshot().v2_exec_bindings[0].phase == "complete"


@pytest.mark.parametrize("reason", ["expired", "cancelled"])
def test_expiry_or_cancellation_after_create_quarantines_without_start_exchange(
    reason: str,
) -> None:
    clock = Clock()
    item, transport, audit, _clock, admitted, reply = create_exec(clock=clock)
    assert reply.status_code == 201
    original_binding = item.snapshot().v2_exec_bindings[0]
    cancel = Cancel()
    if reason == "expired":
        clock.value += 5_000_000_000
    else:
        cancel.value = True
    start = raw_request("POST", START, {"Detach": False, "Tty": False})
    assert item.handle(start, cancel, exec_admission=admitted).status_code == (
        504 if reason == "expired" else 503
    )
    assert len(transport.seen) == 1
    state = item.snapshot()
    assert state.reconciliation_required
    assert state.quarantined_container_ids == (CONTAINER_ID,)
    assert state.quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert state.v2_exec_bindings == (original_binding,)
    assert audit.records[-1].outcome == (
        "deadline_exceeded" if reason == "expired" else "cancelled"
    )
    assert item.handle(start, Cancel(), exec_admission=admitted).status_code == 503
    assert len(transport.seen) == 1


def test_completed_then_deleted_exec_keeps_operation_history_and_refuses_replay_on_replacement() -> (
    None
):
    item, transport, _audit, _clock, admitted, reply = create_exec()
    assert reply.status_code == 201
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
    transport.response = raw_response(204, content_type=None)
    assert (
        item.handle(
            raw_request("DELETE", f"/v1.47/containers/{CONTAINER_ID}?force=1&v=1"), Cancel()
        ).status_code
        == 204
    )
    deleted = item.snapshot()
    assert not deleted.ownership.container_ids
    assert not deleted.ownership.exec_bindings and not deleted.v2_exec_bindings
    assert deleted.v2_exec_operation_ids == (admitted.request.operation_id,)

    # Simulate custody separately establishing a replacement owned container;
    # the attempt's operation history must survive that resource transition.
    item._state = replace(
        deleted,
        ownership=replace(deleted.ownership, container_ids=(OTHER_CONTAINER_ID,)),
        generation=deleted.generation + 1,
    )
    replacement = admission(container_id=OTHER_CONTAINER_ID)
    assert replacement.request.operation_id == admitted.request.operation_id
    assert replacement.request.request_digest != admitted.request.request_digest
    before_count = len(transport.seen)
    transport.response = raw_response(201, {"Id": "9" * 64})
    assert (
        item.handle(
            raw_request(
                "POST", f"/v1.47/containers/{OTHER_CONTAINER_ID}/exec", exec_body(replacement)
            ),
            Cancel(),
            exec_admission=replacement,
        ).status_code
        == 503
    )
    assert len(transport.seen) == before_count
    assert item.snapshot().v2_exec_operation_ids == (admitted.request.operation_id,)
    assert not item.snapshot().v2_exec_bindings


@pytest.mark.parametrize("fault", ["clock", "cancellation"])
def test_failed_clock_or_cancellation_probe_quarantines_known_exec_before_start_exchange(
    fault: str,
) -> None:
    class UnavailableClock(Clock):
        unavailable = False

        def __call__(self) -> int:
            if self.unavailable:
                raise RuntimeError("clock unavailable")
            return super().__call__()

    class UnavailableCancellation(Cancel):
        def is_cancelled(self) -> bool:
            raise RuntimeError("cancellation status unavailable")

    clock = UnavailableClock()
    item, transport, _audit, _clock, admitted, reply = create_exec(clock=clock)
    assert reply.status_code == 201
    original_binding = item.snapshot().v2_exec_bindings[0]
    clock.unavailable = fault == "clock"
    cancel = UnavailableCancellation() if fault == "cancellation" else Cancel()
    start = raw_request("POST", START, {"Detach": False, "Tty": False})
    assert item.handle(start, cancel, exec_admission=admitted).status_code == 503
    assert len(transport.seen) == 1
    state = item.snapshot()
    assert state.reconciliation_required
    assert state.quarantined_container_ids == (CONTAINER_ID,)
    assert state.quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
    assert state.v2_exec_bindings == (original_binding,)
    clock.unavailable = False
    assert item.handle(start, Cancel(), exec_admission=admitted).status_code == 503
    assert len(transport.seen) == 1
