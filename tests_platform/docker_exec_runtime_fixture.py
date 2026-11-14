"""Explicit controller fakes around real durable exec dispatch and cleanup."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from bluefire.engine_docker_exec_admission import DockerExecAdmissionV2
from bluefire.engine_docker_exec_cancellation import DockerExecCancellationLaneV2
from bluefire.engine_docker_exec_dispatch import DockerExecDispatchRuntimeV2
from bluefire.engine_docker_exec_journal import SQLiteDockerExecOperationJournal
from bluefire.engine_worker_runtime import ResourceCustodySnapshot, ResourceCustodyState
from bluefire.util import content_hash


class TestAuthority:
    __test__ = False
    authority_ref = "sha256:" + "a" * 64
    claim_ref = "sha256:" + "b" * 64
    controller_fence = "sha256:" + "c" * 64

    def __init__(self, admitted: DockerExecAdmissionV2) -> None:
        self.admitted = admitted
        self.active = True
        self.cleanup_active = True
        self.lock = threading.RLock()
        self.execution_calls: list[tuple[str, int]] = []
        self.cleanup_calls: list[tuple[str, int]] = []

    def _require_mapping(self, admitted: DockerExecAdmissionV2) -> None:
        expected = self.admitted
        assert admitted.policy_digest == expected.policy_digest
        assert admitted.execution_identity_digest == expected.execution_identity_digest
        assert admitted.profile.profile_digest == expected.profile.profile_digest
        assert admitted.container_id == expected.container_id
        assert admitted.request.handle == expected.request.handle
        assert admitted.request.handle.opaque_ref is expected.request.handle.opaque_ref

    @contextmanager
    def execution_scope(self, admitted: DockerExecAdmissionV2):
        with self.lock:
            if not self.active:
                raise RuntimeError("test execution authority revoked")
            self._require_mapping(admitted)
            self.execution_calls.append((admitted.admission_digest, threading.get_ident()))
            yield

    @contextmanager
    def cleanup_scope(self, admitted: DockerExecAdmissionV2):
        with self.lock:
            if not self.cleanup_active:
                raise RuntimeError("test cleanup authority revoked")
            self._require_mapping(admitted)
            self.cleanup_calls.append((admitted.admission_digest, threading.get_ident()))
            yield


class CleanupAudit:
    def __init__(self) -> None:
        self.records: list[Any] = []
        self._lock = threading.Lock()

    def append(self, record: Any) -> str:
        with self._lock:
            self.records.append(record)
        return content_hash(record.to_dict())


class TestCustody:
    __test__ = False

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.thread_ids: list[int] = []
        self.stopped = threading.Event()
        self.inspected = threading.Event()
        self._lock = threading.Lock()

    def _observe(self, method: str, attempt_id: str, **kwargs: Any) -> ResourceCustodySnapshot:
        with self._lock:
            self.calls.append((method, attempt_id, kwargs))
            self.thread_ids.append(threading.get_ident())
        if method == "stop_owned":
            self.stopped.set()
        else:
            self.inspected.set()
        return ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)

    def stop_owned(self, attempt_id: str, **kwargs: Any) -> ResourceCustodySnapshot:
        return self._observe("stop_owned", attempt_id, **kwargs)

    def inspect(self, attempt_id: str, **kwargs: Any) -> ResourceCustodySnapshot:
        return self._observe("inspect", attempt_id, **kwargs)


def _close_resources(
    connection: sqlite3.Connection, directory: tempfile.TemporaryDirectory
) -> None:
    connection.close()
    directory.cleanup()


class TestContinuousCustody:
    """Unit contract proof only; no external watchdog qualification."""

    __test__ = False

    def require_live(self, **context: Any) -> Any:
        from bluefire.engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2

        admitted = context["admission"]
        return VerifiedExecLifetimeCustodyV2(
            admission_digest=admitted.admission_digest,
            attempt_id=admitted.profile.attempt_id,
            operation_id=admitted.request.operation_id,
            container_id=admitted.container_id,
            claim_ref=context["claim_ref"],
            controller_fence=context["controller_fence"],
            custody_plan_digest=context["custody_plan_digest"],
            network_policy_digest=context["network_policy_digest"],
            operation_deadline_monotonic_ns=context["operation_deadline_monotonic_ns"],
            controller_instance_ref="sha256:" + "d" * 64,
            supervisor_instance_ref="sha256:" + "e" * 64,
            lease_ref=content_hash({"unit_lease": admitted.admission_digest}),
            lease_generation=1,
            deadline_stop_enforced=True,
            controller_loss_stop_enforced=True,
        )


class RuntimeResources:
    def __init__(self, admitted: DockerExecAdmissionV2, *, clock: Any, audit: Any = None) -> None:
        self.clock = clock
        temporary_root = Path(__file__).resolve().parents[1] / ".pytest-exec-runtime-resources"
        temporary_root.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="case-", dir=temporary_root)
        self.path = Path(self.directory.name) / "exec.sqlite"
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.journal = SQLiteDockerExecOperationJournal(self.connection)
        self.authority = TestAuthority(admitted)
        self.runtime = DockerExecDispatchRuntimeV2(
            authority=self.authority,
            journal=self.journal,
            monotonic_ns=clock,
            continuous_custody=TestContinuousCustody(),
        )
        self.custody = TestCustody()
        self.audit = audit or CleanupAudit()
        from tests_platform.test_engine_docker_control import policy_v2

        policy = policy_v2()
        self.custody_plan_digest = policy.custody_plan_digest
        self.network_policy_digest = policy.network_policy_digest
        self.cancellation = DockerExecCancellationLaneV2(
            custody=self.custody,
            authority=self.authority,
            custody_plan_digest=self.custody_plan_digest,
            network_policy_digest=self.network_policy_digest,
            audit=self.audit,
            monotonic_ns=clock,
            cleanup_timeout_seconds=0.5,
        )
        self._finalizer = weakref.finalize(self, _close_resources, self.connection, self.directory)

    def close(self) -> None:
        self._finalizer()


def runtime_resources(
    admitted: DockerExecAdmissionV2, *, clock: Any = None, audit: Any = None
) -> RuntimeResources:
    return RuntimeResources(admitted, clock=clock or time.monotonic_ns, audit=audit)
