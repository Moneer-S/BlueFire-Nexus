"""Proxy integration with durable dispatch and independent custody cancellation.

All controller authority and custody observations below are explicit test
fakes. The journal, dispatch gate, cancellation lane and proxy are real; these
tests neither connect to Docker nor claim installed Strix conformance.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import closing, contextmanager
from dataclasses import replace
from typing import Any, cast

import pytest

from bluefire.engine_docker_exec_cancellation import (
    DockerExecCancellationReceiptV2,
    DockerExecCancellationWatchV2,
)
from bluefire.engine_docker_exec_dispatch import DockerExecDispatchRuntimeV2
from bluefire.engine_docker_exec_journal import SQLiteDockerExecOperationJournal
from bluefire.engine_docker_proxy import DockerDaemonExchange
from tests_platform.docker_exec_runtime_fixture import runtime_resources
from tests_platform.test_engine_docker_control import create_body_v2, policy_v2
from tests_platform.test_engine_docker_exec_admission import (
    CREATE,
    START,
    admission,
    create_exec,
    exec_body,
)
from tests_platform.test_engine_docker_proxy import (
    CONTAINER_ID,
    EXEC_ID,
    Cancel,
    Transport,
    ownership,
    proxy,
    raw_request,
    raw_response,
)


def _journal_row(resources: Any, admitted: Any) -> Any:
    return resources.journal.snapshot(
        attempt_id=admitted.profile.attempt_id,
        operation_id=admitted.request.operation_id,
    )


@pytest.mark.parametrize("missing", ["runtime", "cancellation", "both"])
def test_missing_dispatch_or_cleanup_authority_refuses_before_transport_and_is_audited(
    missing: str,
) -> None:
    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        transport = Transport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=None if missing in {"runtime", "both"} else resources.runtime,
            exec_cancellation=(
                None if missing in {"cancellation", "both"} else resources.cancellation
            ),
        )
        reply = item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        )
        assert reply.status_code == 503
        assert transport.seen == []
        assert _journal_row(resources, admitted) is None
        assert [(record.phase, record.outcome) for record in audit.records] == [
            ("refused", "exec_runtime_unavailable")
        ]
        assert not item.snapshot().reconciliation_required


def test_transport_that_ignores_send_gate_cannot_publish_and_requires_reconciliation() -> None:
    class UngatedTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            kwargs.pop("dispatch_gate")
            return super().exchange(*args, **kwargs)

    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        transport = UngatedTransport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        reply = item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        )
        assert reply.status_code == 503
        assert len(transport.seen) == 1, [record.to_dict() for record in audit.records]
        assert not any(record.phase == "published" for record in audit.records)
        assert audit.records[-1].outcome == "exec_dispatch_refused"
        state = item.snapshot()
        assert state.reconciliation_required
        assert state.quarantined_container_ids == (CONTAINER_ID,)
        assert not state.ownership.exec_bindings
        assert _journal_row(resources, admitted)["phase"] == "uncertain"
        receipt = item.cancel_exec(admitted)
        assert isinstance(receipt, DockerExecCancellationReceiptV2)
        assert receipt.verified_absent and receipt.audited


def test_missing_continuous_owner_refuses_before_durable_reservation_or_write() -> None:
    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        missing_owner_runtime = DockerExecDispatchRuntimeV2(
            authority=resources.authority,
            journal=resources.journal,
            monotonic_ns=resources.clock,
        )
        assert missing_owner_runtime.continuous_custody is None
        transport = Transport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=missing_owner_runtime,
            exec_cancellation=resources.cancellation,
        )
        reply = item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        )
        assert reply.status_code == 503
        assert _journal_row(resources, admitted) is None
        assert transport.seen == []
        assert audit.records[-1].outcome == "exec_custody_unavailable"
        assert not any(record.phase == "published" for record in audit.records)


def test_ambiguous_create_survives_proxy_and_runtime_reconstruction_without_any_replay() -> None:
    class LostCreateTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            super().exchange(*args, **kwargs)
            raise OSError("create write completed; response was lost")

    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        transport = LostCreateTransport(raw_response(201, {"Id": EXEC_ID}))
        original, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        assert (
            original.handle(
                raw_request("POST", CREATE, exec_body(admitted)),
                Cancel(),
                exec_admission=admitted,
            ).status_code
            == 503
        )
        assert len(transport.seen) == 1
        assert original.snapshot().reconciliation_required
        assert audit.records[-1].outcome == "transport_failed"
        saved = _journal_row(resources, admitted)
        assert saved["phase"] == "uncertain"

        with closing(sqlite3.connect(resources.path, check_same_thread=False)) as connection:
            reconstructed_journal = SQLiteDockerExecOperationJournal(connection)
            for candidate in (
                admitted,
                admission(operation_id="operation-" + "e" * 32),
            ):
                candidate = replace(
                    candidate,
                    request=replace(candidate.request, handle=admitted.request.handle),
                )
                reconstructed_runtime = DockerExecDispatchRuntimeV2(
                    authority=resources.authority,
                    journal=reconstructed_journal,
                    monotonic_ns=resources.clock,
                    continuous_custody=resources.runtime.continuous_custody,
                )
                assert reconstructed_runtime.continuous_custody is not None
                fresh_transport = Transport(raw_response(201, {"Id": "f" * 64}))
                fresh, fresh_audit, _clock = proxy(
                    fresh_transport,
                    policy_value=policy_v2(),
                    owned=ownership(container=True),
                    clock=resources.clock,
                    exec_runtime=reconstructed_runtime,
                    exec_cancellation=resources.cancellation,
                )
                assert not fresh.snapshot().v2_exec_operation_ids
                assert (
                    fresh.handle(
                        raw_request("POST", CREATE, exec_body(candidate)),
                        Cancel(),
                        exec_admission=candidate,
                    ).status_code
                    == 503
                )
                assert fresh_transport.seen == []
                assert fresh_audit.records[-1].outcome == "exec_reservation_failed"
                assert not any(record.phase == "published" for record in fresh_audit.records)
                assert fresh.snapshot().reconciliation_required
                assert fresh.snapshot().quarantined_container_ids == (CONTAINER_ID,)
                assert resources.custody.stopped.is_set() and resources.custody.inspected.is_set()
                assert any(
                    record.operation_id == candidate.request.operation_id
                    and record.phase == "absence_verified"
                    for record in resources.audit.records
                )
            reloaded = reconstructed_journal.snapshot(
                attempt_id=admitted.profile.attempt_id,
                operation_id=admitted.request.operation_id,
            )
            assert reloaded is not None
            assert reloaded["reservation_ref"] == saved["reservation_ref"]
            assert [call[0] for call in resources.custody.calls] == [
                "stop_owned",
                "inspect",
                "stop_owned",
                "inspect",
            ]


def test_transient_probe_and_delayed_uncertainty_fence_cannot_publish_after_cleanup() -> None:
    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        watchers: list[Any] = []
        original_watch = resources.cancellation.watch

        @contextmanager
        def capture_watch(*args: Any, **kwargs: Any):
            with original_watch(*args, **kwargs) as watcher:
                watchers.append(watcher)
                yield watcher

        cast(Any, resources.cancellation).watch = capture_watch

        class TransientProbe:
            def __init__(self) -> None:
                self.armed = False
                self.failed = False

            def is_cancelled(self) -> bool:
                if self.armed and not self.failed:
                    self.failed = True
                    raise RuntimeError("transient probe fault")
                return False

        signal = TransientProbe()

        class WaitForCleanupTransport(Transport):
            def exchange(self, raw_request: bytes, **kwargs: Any) -> DockerDaemonExchange:
                with kwargs["dispatch_gate"].before_send():
                    self.seen.append(raw_request)
                signal.armed = True
                assert resources.custody.inspected.wait(2), "cleanup did not inspect absence"
                return DockerDaemonExchange(
                    request_digest=kwargs["dispatch_gate"].request_digest,
                    daemon_instance_digest=policy_v2().daemon_instance_digest,
                    raw_response=raw_response(201, {"Id": EXEC_ID}),
                )

        transport = WaitForCleanupTransport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        original_fence = item._fence_exec
        callback_started = threading.Event()
        callback_release = threading.Event()
        callback_finished = threading.Event()

        def delayed_fence(current: Any) -> None:
            callback_started.set()
            callback_release.wait(2)
            try:
                original_fence(current)
            finally:
                callback_finished.set()

        cast(Any, item)._fence_exec = delayed_fence
        try:
            reply = item.handle(
                raw_request("POST", CREATE, exec_body(admitted)),
                signal,
                exec_admission=admitted,
            )
            assert callback_started.is_set()
            assert resources.custody.inspected.is_set()
            assert watchers[0].receipt is not None
            assert watchers[0].receipt.issue == "uncertainty_callback_failed"
            assert reply.status_code == 503
            assert not any(
                record.phase == "published" and record.outcome == "accepted"
                for record in audit.records
            )
            assert not callback_release.is_set() and not callback_finished.is_set()
            assert _journal_row(resources, admitted)["phase"] == "uncertain"
        finally:
            callback_release.set()
            assert callback_finished.wait(2)


@pytest.mark.parametrize(
    ("reason", "outcome", "status"),
    [
        ("cancelled", "cancelled", 503),
        ("deadline_exceeded", "deadline_exceeded", 504),
        ("cancellation_probe_failed", "cancellation_probe_failed", 503),
        ("clock_probe_failed", "clock_probe_failed", 503),
        ("watcher_timeout", "watcher_timeout", 503),
        ("operator_requested", "exec_custody_triggered", 503),
    ],
)
def test_terminal_watch_receipt_preserves_exact_known_reason_and_status(
    reason: str, outcome: str, status: int
) -> None:
    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:

        @contextmanager
        def terminal_watch(*args: Any, **kwargs: Any):
            watcher = DockerExecCancellationWatchV2()
            yield watcher
            watcher._publish(resources.cancellation.cancel(admitted, reason))

        cast(Any, resources.cancellation).watch = terminal_watch
        transport = Transport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        reply = item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        )
        assert reply.status_code == status
        assert audit.records[-1].phase == "suppressed"
        assert audit.records[-1].outcome == outcome
        assert not any(record.phase == "published" for record in audit.records)
        assert item.snapshot().reconciliation_required
        assert _journal_row(resources, admitted)["phase"] == "uncertain"


@pytest.mark.parametrize("invalid_probe", [None, 0, [], {}], ids=["none", "zero", "list", "dict"])
def test_falsey_nonboolean_probe_after_watch_close_cannot_publish(invalid_probe: Any) -> None:
    class MutableProbe:
        value: Any = False

        def is_cancelled(self) -> Any:
            return self.value

    admitted = admission()
    signal = MutableProbe()
    with closing(runtime_resources(admitted)) as resources:
        original_watch = resources.cancellation.watch

        @contextmanager
        def change_probe_after_watch_close(*args: Any, **kwargs: Any):
            with original_watch(*args, **kwargs) as watcher:
                yield watcher
            # Dispatch and watcher probes have all returned exact False. The
            # invalid value appears only in the proxy's final publication path.
            signal.value = invalid_probe

        cast(Any, resources.cancellation).watch = change_probe_after_watch_close
        transport = Transport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        reply = item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), signal, exec_admission=admitted
        )
        assert len(transport.seen) == 1
        assert reply.status_code == 503
        assert not any(
            record.phase == "published" and record.outcome == "accepted" for record in audit.records
        )
        assert item.snapshot().reconciliation_required
        assert item.snapshot().quarantined_container_ids == (CONTAINER_ID,)
        assert _journal_row(resources, admitted)["phase"] == "uncertain"
        assert [call[0] for call in resources.custody.calls] == ["stop_owned", "inspect"]


def test_cancellation_stops_owned_container_and_verifies_absence_while_attach_is_blocked() -> None:
    entered = threading.Event()
    release = threading.Event()
    inspected = threading.Event()
    calls: list[tuple[str, str, dict[str, Any], int]] = []
    replies: list[Any] = []
    failures: list[BaseException] = []

    class BlockingAttachTransport(Transport):
        def exchange(self, *args: Any, **kwargs: Any) -> DockerDaemonExchange:
            if b"/start " not in args[0]:
                return super().exchange(*args, **kwargs)
            with kwargs["dispatch_gate"].before_send():
                self.seen.append(args[0])
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test failed to release attached I/O")
            return DockerDaemonExchange(
                request_digest=kwargs["dispatch_gate"].request_digest,
                daemon_instance_digest=policy_v2().daemon_instance_digest,
                raw_response=raw_response(
                    200, b"", content_type="application/vnd.docker.raw-stream"
                ),
            )

    admitted = admission()
    with closing(runtime_resources(admitted)) as resources:
        original_stop = resources.custody.stop_owned
        original_inspect = resources.custody.inspect

        def stop(attempt: str, **kwargs: Any) -> Any:
            calls.append(("stop_owned", attempt, kwargs, threading.get_ident()))
            return original_stop(attempt, **kwargs)

        def inspect(attempt: str, **kwargs: Any) -> Any:
            calls.append(("inspect", attempt, kwargs, threading.get_ident()))
            observed = original_inspect(attempt, **kwargs)
            inspected.set()
            return observed

        cast(Any, resources.custody).stop_owned = stop
        cast(Any, resources.custody).inspect = inspect
        transport = BlockingAttachTransport(raw_response(201, {"Id": EXEC_ID}))
        item, audit, _clock = proxy(
            transport,
            policy_value=policy_v2(),
            owned=ownership(container=True),
            clock=resources.clock,
            exec_runtime=resources.runtime,
            exec_cancellation=resources.cancellation,
        )
        assert (
            item.handle(
                raw_request("POST", CREATE, exec_body(admitted)),
                Cancel(),
                exec_admission=admitted,
            ).status_code
            == 201
        )
        cancel = Cancel()

        def attach() -> None:
            try:
                replies.append(
                    item.handle(
                        raw_request("POST", START, {"Detach": False, "Tty": False}),
                        cancel,
                        exec_admission=admitted,
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=attach, name="test-blocked-exec-attach")
        thread.start()
        try:
            assert entered.wait(2), "attach never reached its socket write"
            cancel.value = True
            assert inspected.wait(2), "custody inspection waited for attached I/O"
            assert thread.is_alive() and not replies
            assert [call[0] for call in calls] == ["stop_owned", "inspect"]
            current_policy = policy_v2()
            for _method, attempt, kwargs, thread_id in calls:
                assert thread_id != thread.ident
                assert attempt == admitted.profile.attempt_id
                assert kwargs["custody_identity_digest"] == current_policy.custody_plan_digest
                assert kwargs["network_policy_digest"] == current_policy.network_policy_digest
                assert 0 < kwargs["timeout_seconds"] <= 10
            receipt = item.cancel_exec(admitted)
            assert isinstance(receipt, DockerExecCancellationReceiptV2)
            assert receipt.container_id == CONTAINER_ID
            assert receipt.verified_absent and receipt.audited
            assert item.snapshot().reconciliation_required
            assert item.snapshot().quarantined_exec_bindings == ((EXEC_ID, CONTAINER_ID),)
        finally:
            release.set()
            thread.join(2)
        assert not thread.is_alive() and not failures
        assert len(replies) == 1 and replies[0].status_code == 503
        assert not any(
            record.operation == "exec_start" and record.phase == "published"
            for record in audit.records
        )
        assert _journal_row(resources, admitted)["phase"] == "uncertain"


def test_replay_deadline_and_preloaded_image_refusals_retain_exact_audit_outcomes() -> None:
    item, transport, audit, _clock, admitted, created = create_exec()
    assert created.status_code == 201
    before = len(transport.seen)
    assert (
        item.handle(
            raw_request("POST", CREATE, exec_body(admitted)), Cancel(), exec_admission=admitted
        ).status_code
        == 503
    )
    assert len(transport.seen) == before
    assert audit.records[-1].phase == "refused"
    assert audit.records[-1].outcome == "exec_operation_replayed_or_unsettled"

    state = item.snapshot()
    item._state = replace(
        state,
        v2_exec_bindings=(replace(state.v2_exec_bindings[0], deadline_monotonic_ns=None),),
        generation=state.generation + 1,
    )
    assert (
        item.handle(
            raw_request("POST", START, {"Detach": False, "Tty": False}),
            Cancel(),
            exec_admission=admitted,
        ).status_code
        == 503
    )
    assert len(transport.seen) == before
    assert audit.records[-1].phase == "refused"
    assert audit.records[-1].outcome == "exec_deadline_unavailable"

    current_policy = policy_v2()
    empty_transport = Transport(raw_response(201, {"Id": CONTAINER_ID, "Warnings": []}))
    empty, image_audit, _clock = proxy(empty_transport, policy_value=current_policy)
    assert (
        empty.handle(
            raw_request(
                "POST",
                f"/v1.47/containers/create?name={current_policy.container_name}",
                create_body_v2(current_policy),
            ),
            Cancel(),
        ).status_code
        == 503
    )
    assert empty_transport.seen == []
    assert [(record.phase, record.outcome) for record in image_audit.records] == [
        ("refused", "image_inspect_required")
    ]
