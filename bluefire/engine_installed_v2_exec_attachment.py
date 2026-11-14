"""Controller-owned Docker exec attachment for an installed Strix attempt.

This module joins the admitted V2 launch to the durable Docker proxy. The
controller refreshes an inspected network placement before a target-capable
exec request. The receipt is a point-in-time placement observation, not a
claim that the target responded or that the network will remain unchanged.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, ContextManager, Iterator, cast

from .engine_docker_cancellation_audit_store import ProductStoreDockerExecCancellationAuditV2
from .engine_docker_control import DockerApiPolicyV2
from .engine_docker_custody import (
    DockerCustodyProductStore,
    ProductStoreDockerProxyCustody,
    ReopenedDockerProxyCustody,
)
from .engine_docker_exec_admission import DockerExecAdmissionV2
from .engine_docker_exec_cancellation import DockerExecCancellationLaneV2
from .engine_docker_exec_dispatch import (
    ControllerExecDispatchAuthorityV2,
    DockerExecDispatchRuntimeV2,
)
from .engine_docker_exec_journal import SQLiteDockerExecOperationJournal
from .engine_docker_proxy import (
    DockerPolicyProxy,
    DockerProxyCancellation,
    DockerProxyCustody,
    DockerProxyReply,
    DockerV2EffectiveNetworkBinding,
    DockerV2EffectiveNetworkReceipt,
    parse_docker_http_request,
)
from .engine_docker_transport import LinuxDockerDaemonEndpoint, LinuxUnixDockerDaemonTransport
from .engine_exec_operation_supervisor import (
    ControllerOwnedExecOperationCustodyV2,
    ExecLifetimeSupervisorBindingV2,
)
from .engine_installed_v2_authority import InstalledStrixV2ActivationReceipt
from .engine_installed_v2_exec_terminal import (
    ExecAttachmentTerminalReceiptV2,
    InstalledV2ExecAttachmentError,
    RetainedExecAttachmentTerminalV2,
    _ExecAttachmentTerminalStore,
)
from .engine_worker_runtime import ResourceCustodySnapshot, ResourceCustodyState
from .linux_exec_lifetime_supervisor import (
    LinuxExecLifetimeSupervisorProfileV2,
    LinuxExternalExecLifetimeSupervisorV2,
)
from .linux_exec_supervisor_docker import (
    ControllerOwnedDockerCleanupCancellation,
    FixedDockerExecCleanup,
    SupervisorDockerCleanupResult,
    SupervisorDockerContainerIdentity,
)
from .strix_controlled_runtime_admission import StrixControlledLaunchPlanV2
from .util import content_hash

_CONTAINER_EXEC_CREATE = re.compile(r"/v1\.[0-9]{2}/containers/[0-9a-f]{64}/exec\Z")
_EXEC_START = re.compile(r"/v1\.[0-9]{2}/exec/[0-9a-f]{64}/start\Z")
_ATTACHMENT_CONSTRUCTION_TOKEN = object()


class _GuardedDockerTransportView:
    """Retained identity view that cannot bypass the controller proxy."""

    def exchange(self, *_args: object, **_kwargs: object) -> None:
        raise InstalledV2ExecAttachmentError(
            "raw Docker exchange is unavailable outside the installed attachment"
        )


def _require_published_container_provenance(
    restored: ReopenedDockerProxyCustody, *, container_id: str
) -> None:
    """Refuse an owned ID that was merely seeded into an initial state."""

    if type(restored) is not ReopenedDockerProxyCustody:
        raise InstalledV2ExecAttachmentError("V2 Docker custody source is unavailable")
    owned = restored.state.ownership
    if (
        restored.state.reconciliation_required
        or owned.pending_container_ids
        or owned.container_ids != (container_id,)
        or restored.unresolved_operations
        or container_id not in restored.known_container_ids
    ):
        raise InstalledV2ExecAttachmentError("V2 Docker container ownership is unsettled")
    published = [
        (index, row.operation)
        for index, row in enumerate(restored.audits)
        if row.phase == "published" and row.outcome == "accepted"
    ]
    created = [index for index, operation in published if operation == "container_create"]
    inspected = [index for index, operation in published if operation == "container_inspect"]
    if not created or not inspected or min(inspected) <= min(created):
        raise InstalledV2ExecAttachmentError(
            "V2 owned container lacks published create and inspect provenance"
        )


class FixedDockerV2ResourceCustody:
    """Exact live-daemon absence checks for the one owned sandbox container.

    The second call is a fresh daemon observation after the first cleanup. The
    source results remain available to the attachment for retained settlement;
    a generic ``ResourceCustodySnapshot`` alone is not source evidence.
    """

    def __init__(
        self,
        *,
        attempt_id: str,
        policy: DockerApiPolicyV2,
        custody_plan_digest: str,
        network_policy_digest: str,
        identity: SupervisorDockerContainerIdentity,
        cleanup: FixedDockerExecCleanup,
    ) -> None:
        if (
            type(identity) is not SupervisorDockerContainerIdentity
            or type(cleanup) is not FixedDockerExecCleanup
            or type(policy) is not DockerApiPolicyV2
            or not isinstance(attempt_id, str)
            or re.fullmatch(r"engine-attempt-[0-9a-f]{32}", attempt_id) is None
            or policy.attempt_id != attempt_id
            or identity.policy_digest != policy.policy_digest
            or identity.container_name != policy.container_name
            or identity.image_config_digest != policy.image_config_digest
            or identity.image_reference != policy.image_reference
            or identity.required_labels != policy.required_labels
            or identity.execution_identity_digest != policy.execution_identity_digest
            or identity.profile_digest != policy.image_runtime_profile_digest
            or custody_plan_digest != policy.custody_plan_digest
            or network_policy_digest != policy.network_policy_digest
            or not isinstance(network_policy_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", network_policy_digest) is None
        ):
            raise InstalledV2ExecAttachmentError("V2 fixed Docker cleanup binding is invalid")
        self._attempt_id = attempt_id
        self._custody_plan_digest = custody_plan_digest
        self._network_policy_digest = network_policy_digest
        self._identity = identity
        self._cleanup = cleanup
        self._results: list[SupervisorDockerCleanupResult] = []
        self._lock = threading.RLock()

    @property
    def source_results(self) -> tuple[SupervisorDockerCleanupResult, ...]:
        with self._lock:
            return tuple(self._results)

    def _observe(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        if (
            attempt_id != self._attempt_id
            or custody_identity_digest != self._custody_plan_digest
            or network_policy_digest != self._network_policy_digest
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 10
        ):
            raise InstalledV2ExecAttachmentError("V2 fixed Docker cleanup scope changed")
        with self._lock:
            deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
            result = self._cleanup.cleanup(
                self._identity,
                deadline_monotonic_ns=deadline,
                cancellation=ControllerOwnedDockerCleanupCancellation(),
            )
            if (
                type(result) is not SupervisorDockerCleanupResult
                or result.container_id != self._identity.container_id
                or result.container_identity_digest != self._identity.identity_digest
                or result.live_daemon_proof is not True
                or result.absent_verified is not True
                or result.cleanup_uncertain is not False
            ):
                raise InstalledV2ExecAttachmentError("V2 Docker absence is unverified")
            self._results.append(result)
            return ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)

    def stop_owned(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        return self._observe(
            attempt_id,
            custody_identity_digest=custody_identity_digest,
            network_policy_digest=network_policy_digest,
            timeout_seconds=timeout_seconds,
        )

    def inspect(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        return self._observe(
            attempt_id,
            custody_identity_digest=custody_identity_digest,
            network_policy_digest=network_policy_digest,
            timeout_seconds=timeout_seconds,
        )

    def observe_absence_twice(self) -> tuple[SupervisorDockerCleanupResult, ...]:
        """Keep the two final daemon observations adjacent to one another."""

        with self._lock:
            failures: list[Exception] = []
            for method in (self.stop_owned, self.inspect):
                try:
                    method(
                        self._attempt_id,
                        custody_identity_digest=self._custody_plan_digest,
                        network_policy_digest=self._network_policy_digest,
                        timeout_seconds=5.0,
                    )
                except Exception as exc:
                    failures.append(exc)
            if failures:
                raise InstalledV2ExecAttachmentError(
                    "V2 independent Docker absence checks are incomplete"
                ) from failures[0]
            return tuple(self._results[-2:])


class ControllerOwnedV2NetworkDispatch:
    """One serialized controller route through the durable V2 Docker proxy.

    ``require_active_activation`` must reopen the committed ProductStore
    transaction as well as its immutable activation. A retained activation
    alone is insufficient while resource allocation is still pending.
    """

    def __init__(
        self,
        *,
        proxy: DockerPolicyProxy,
        policy: DockerApiPolicyV2,
        launch_plan: StrixControlledLaunchPlanV2,
        claim_ref: str,
        controller_fence: str,
        require_active_activation: Callable[[], InstalledStrixV2ActivationReceipt],
        hold_active_scope: Callable[[], ContextManager[InstalledStrixV2ActivationReceipt]],
    ) -> None:
        if (
            type(proxy) is not DockerPolicyProxy
            or type(policy) is not DockerApiPolicyV2
            or type(launch_plan) is not StrixControlledLaunchPlanV2
            or not callable(require_active_activation)
            or not callable(hold_active_scope)
        ):
            raise InstalledV2ExecAttachmentError("V2 exec attachment is incomplete")
        plan = launch_plan.to_dict()
        admission = plan.get("admission")
        if not isinstance(admission, dict) or set(admission) < {"scope", "network_plan"}:
            raise InstalledV2ExecAttachmentError("V2 target plan is unavailable")
        target_plan_digest = content_hash(
            {"scope": admission["scope"], "network_plan": admission["network_plan"]}
        )
        binding = DockerV2EffectiveNetworkBinding(
            attempt_id=policy.attempt_id,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            network_policy_digest=policy.network_policy_digest,
            target_plan_digest=target_plan_digest,
        )
        if policy.attempt_id != admission.get("attempt_id"):
            raise InstalledV2ExecAttachmentError("V2 Docker policy belongs to another attempt")
        self._proxy = proxy
        self._policy = policy
        self._launch_plan = launch_plan
        self._binding = binding
        self._require_active_activation = require_active_activation
        self._hold_active_scope = hold_active_scope
        self._lock = threading.RLock()

    @property
    def target_plan_digest(self) -> str:
        return self._binding.target_plan_digest

    def _active(self) -> InstalledStrixV2ActivationReceipt:
        try:
            activation = self._require_active_activation()
        except Exception:
            raise InstalledV2ExecAttachmentError("V2 active transaction is unavailable") from None
        binding = self._binding
        if (
            type(activation) is not InstalledStrixV2ActivationReceipt
            or activation.claim_ref != binding.claim_ref
            or activation.controller_fence != binding.controller_fence
            or activation.network_policy_digest != binding.network_policy_digest
            or activation.controlled_launch_digest != self._launch_plan.launch_digest
        ):
            raise InstalledV2ExecAttachmentError("V2 active execution identity changed")
        return activation

    def _inspect_under_hold(
        self,
        *,
        container_id: str,
        cancellation: DockerProxyCancellation,
    ) -> DockerV2EffectiveNetworkReceipt:
        """Publish one fresh exact inspect before an admitted exec request."""

        if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            raise InstalledV2ExecAttachmentError("V2 owned container identity is invalid")
        request = (
            f"GET /{self._policy.api_version}/containers/{container_id}/json HTTP/1.1\r\n"
            "Host: docker\r\n\r\n"
        ).encode("ascii")
        reply = self._proxy.handle(request, cancellation)
        if type(reply) is not DockerProxyReply or reply.status_code != 200:
            raise InstalledV2ExecAttachmentError("V2 effective network inspection failed")
        receipt = self._proxy.effective_network_receipt()
        if type(receipt) is not DockerV2EffectiveNetworkReceipt:
            raise InstalledV2ExecAttachmentError("V2 effective network is unverified")
        try:
            receipt.require(
                binding=self._binding,
                policy=self._policy,
                state=self._proxy.snapshot(),
            )
        except Exception:
            raise InstalledV2ExecAttachmentError("V2 effective network changed") from None
        if receipt.container_id != container_id:
            raise InstalledV2ExecAttachmentError("V2 inspected another container")
        return receipt

    def refresh_network_receipt(
        self, *, container_id: str, cancellation: DockerProxyCancellation
    ) -> DockerV2EffectiveNetworkReceipt:
        with self._lock, self._hold_active_scope() as held:
            if held != self._active():
                raise InstalledV2ExecAttachmentError("V2 held activation changed")
            receipt = self._inspect_under_hold(container_id=container_id, cancellation=cancellation)
            if held != self._active():
                raise InstalledV2ExecAttachmentError("V2 held activation changed")
            return receipt

    @contextmanager
    def with_network_dispatch_gate(
        self, *, container_id: str, cancellation: DockerProxyCancellation
    ) -> Iterator[DockerV2EffectiveNetworkReceipt]:
        """Hold the same active scope across inspect and a target relay send."""

        with self._lock, self._hold_active_scope() as held:
            if held != self._active():
                raise InstalledV2ExecAttachmentError("V2 held activation changed")
            receipt = self._inspect_under_hold(container_id=container_id, cancellation=cancellation)
            if held != self._active():
                raise InstalledV2ExecAttachmentError("V2 held activation changed")
            yield receipt

    def handle(
        self,
        raw_request: bytes,
        cancellation: DockerProxyCancellation,
        *,
        exec_admission: DockerExecAdmissionV2 | None = None,
    ) -> DockerProxyReply:
        """Serialize fresh placement inspection with a target-capable exec."""

        with self._lock, self._hold_active_scope() as held:
            if held != self._active():
                raise InstalledV2ExecAttachmentError("V2 held activation changed")
            try:
                request = parse_docker_http_request(raw_request)
            except Exception:
                return self._proxy.handle(raw_request, cancellation, exec_admission=exec_admission)
            target_capable = request.method == "POST" and (
                _CONTAINER_EXEC_CREATE.fullmatch(request.target) is not None
                or _EXEC_START.fullmatch(request.target) is not None
            )
            if target_capable:
                if type(exec_admission) is not DockerExecAdmissionV2:
                    raise InstalledV2ExecAttachmentError("V2 target exec admission is unavailable")
                self._inspect_under_hold(
                    container_id=exec_admission.container_id,
                    cancellation=cancellation,
                )
                if held != self._active():
                    raise InstalledV2ExecAttachmentError("V2 held activation changed")
            reply = self._proxy.handle(raw_request, cancellation, exec_admission=exec_admission)
            return reply


class ControllerOwnedStrixV2ExecAttachment:
    """Installed join of exact Docker custody, dispatch, and external guardian.

    The caller supplies already reviewed policy and accepted dispatch authority.
    This owner constructs the actual Linux transport, durable journals, cleanup
    path, supervisor, cancellation lane, and private proxy. It exposes only the
    guarded proxy route to the worker controller.
    """

    def __init__(
        self,
        *,
        policy: DockerApiPolicyV2,
        launch_plan: StrixControlledLaunchPlanV2,
        container_identity: SupervisorDockerContainerIdentity,
        transaction_ref: str,
        owner_ref: str,
        dispatch_authority: ControllerExecDispatchAuthorityV2,
        operation_watchdog: ControllerOwnedExecOperationCustodyV2,
        dispatch_runtime: DockerExecDispatchRuntimeV2,
        docker_transport: LinuxUnixDockerDaemonTransport,
        cancellation_authority: DockerExecCancellationLaneV2,
        cancellation_audit: ProductStoreDockerExecCancellationAuditV2,
        docker_custody: ProductStoreDockerProxyCustody,
        resource_custody: FixedDockerV2ResourceCustody,
        network_dispatch: ControllerOwnedV2NetworkDispatch,
        journal_connection: sqlite3.Connection,
        terminal_store: _ExecAttachmentTerminalStore,
        _token: object,
    ) -> None:
        if _token is not _ATTACHMENT_CONSTRUCTION_TOKEN:
            raise InstalledV2ExecAttachmentError(
                "V2 installed exec attachment requires its protected opener"
            )
        self._policy = policy
        self._plan = launch_plan
        self._identity = container_identity
        self._transaction_ref = transaction_ref
        self._owner_ref = owner_ref
        self._authority = dispatch_authority
        self._watchdog = operation_watchdog
        self._runtime = dispatch_runtime
        self._transport = docker_transport
        self._transport_view = _GuardedDockerTransportView()
        self._cancellation = cancellation_authority
        self._cancellation_audit = cancellation_audit
        self._docker_custody = docker_custody
        self._resource_custody = resource_custody
        self._network_dispatch = network_dispatch
        self._journal_connection = journal_connection
        self._terminal_store = terminal_store
        self._terminal_receipt: ExecAttachmentTerminalReceiptV2 | None = None
        self._cleanup_uncertain = False
        self._closed = False
        self._lock = threading.RLock()
        self._cancellation_ref = content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-exec-cancellation.v1",
                "attempt_id": policy.attempt_id,
                "claim_ref": dispatch_authority.claim_ref,
                "controller_fence": dispatch_authority.controller_fence,
                "transaction_ref": transaction_ref,
                "owner_ref": owner_ref,
                "owner_binding_ref": launch_plan.exec_broker_binding_digest,
                "custody_plan_digest": policy.custody_plan_digest,
                "network_policy_digest": policy.network_policy_digest,
            }
        )

    @classmethod
    def open(
        cls,
        *,
        store: DockerCustodyProductStore,
        policy: DockerApiPolicyV2,
        launch_plan: StrixControlledLaunchPlanV2,
        container_identity: SupervisorDockerContainerIdentity,
        daemon_endpoint: LinuxDockerDaemonEndpoint,
        state_directory: Path,
        transaction_ref: str,
        owner_ref: str,
        controller_instance_ref: str,
        supervisor_qualification_ref: str,
        dispatch_authority: ControllerExecDispatchAuthorityV2,
        require_active_activation: Callable[[], InstalledStrixV2ActivationReceipt],
        hold_active_scope: Callable[[], ContextManager[InstalledStrixV2ActivationReceipt]],
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> ControllerOwnedStrixV2ExecAttachment:
        """Attach after the exact container is durably owned, before effects."""

        if (
            type(policy) is not DockerApiPolicyV2
            or type(launch_plan) is not StrixControlledLaunchPlanV2
            or type(container_identity) is not SupervisorDockerContainerIdentity
            or type(daemon_endpoint) is not LinuxDockerDaemonEndpoint
            or type(dispatch_authority) is not ControllerExecDispatchAuthorityV2
            or not isinstance(state_directory, Path)
            or not state_directory.is_absolute()
            or not callable(require_active_activation)
            or not callable(hold_active_scope)
            or not callable(monotonic_ns)
            or any(
                not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                for item in (
                    transaction_ref,
                    owner_ref,
                    controller_instance_ref,
                    supervisor_qualification_ref,
                )
            )
        ):
            raise InstalledV2ExecAttachmentError("V2 installed exec inputs are incomplete")
        if (
            launch_plan.to_dict()["admission"]["attempt_id"] != policy.attempt_id
            or dispatch_authority.claim_ref
            != launch_plan.to_dict()["admission"]["accepted_execution_claim"]["claim_ref"]
            or dispatch_authority.controller_fence is None
            or daemon_endpoint.daemon_instance_digest != policy.daemon_instance_digest
            or container_identity.container_name != policy.container_name
            or container_identity.image_reference != policy.image_reference
            or container_identity.image_config_digest != policy.image_config_digest
            or container_identity.required_labels != policy.required_labels
            or container_identity.policy_digest != policy.policy_digest
            or container_identity.execution_identity_digest != policy.execution_identity_digest
            or container_identity.profile_digest != policy.image_runtime_profile_digest
        ):
            raise InstalledV2ExecAttachmentError("V2 installed exec identity changed")
        docker_custody = ProductStoreDockerProxyCustody(store, policy=policy)
        restored = docker_custody.reopen()
        owned = restored.state.ownership
        _require_published_container_provenance(
            restored, container_id=container_identity.container_id
        )
        fixed_cleanup = FixedDockerExecCleanup.open(daemon_endpoint, api_version="v1.43")
        resource_custody = FixedDockerV2ResourceCustody(
            attempt_id=policy.attempt_id,
            policy=policy,
            custody_plan_digest=policy.custody_plan_digest,
            network_policy_digest=policy.network_policy_digest,
            identity=container_identity,
            cleanup=fixed_cleanup,
        )
        cancellation_audit = ProductStoreDockerExecCancellationAuditV2(
            store,
            attempt_id=policy.attempt_id,
            claim_ref=dispatch_authority.claim_ref,
            controller_fence=dispatch_authority.controller_fence,
            transaction_ref=transaction_ref,
            owner_ref=owner_ref,
            owner_binding_ref=launch_plan.exec_broker_binding_digest,
        )
        profile = LinuxExecLifetimeSupervisorProfileV2(
            state_directory=state_directory,
            daemon_endpoint=daemon_endpoint,
            api_version="v1.43",
            containers=(container_identity,),
            supervisor_qualification_ref=supervisor_qualification_ref,
        )
        binding = ExecLifetimeSupervisorBindingV2(
            attempt_id=policy.attempt_id,
            claim_ref=dispatch_authority.claim_ref,
            controller_fence=dispatch_authority.controller_fence,
            custody_plan_digest=policy.custody_plan_digest,
            network_policy_digest=policy.network_policy_digest,
            controller_instance_ref=controller_instance_ref,
            supervisor_qualification_ref=supervisor_qualification_ref,
        )
        watchdog: ControllerOwnedExecOperationCustodyV2 | None = None
        journal_connection: sqlite3.Connection | None = None
        try:
            watchdog = ControllerOwnedExecOperationCustodyV2.open(
                binding=binding,
                supervisor=LinuxExternalExecLifetimeSupervisorV2.new(profile),
            )
            journal_connection = sqlite3.connect(
                str(state_directory / "docker-exec-operations-v2.sqlite"),
                check_same_thread=False,
            )
            journal = SQLiteDockerExecOperationJournal(journal_connection)
            runtime = DockerExecDispatchRuntimeV2(
                authority=dispatch_authority,
                journal=journal,
                monotonic_ns=monotonic_ns,
                continuous_custody=watchdog,
            )
            cancellation = DockerExecCancellationLaneV2(
                custody=resource_custody,
                authority=dispatch_authority,
                custody_plan_digest=policy.custody_plan_digest,
                network_policy_digest=policy.network_policy_digest,
                audit=cancellation_audit,
                monotonic_ns=monotonic_ns,
            )
            transport = LinuxUnixDockerDaemonTransport(daemon_endpoint)
            plan = launch_plan.to_dict()["admission"]
            proxy = DockerPolicyProxy(
                policy=policy,
                ownership=owned,
                transport=transport,
                audit=docker_custody,
                custody=cast(DockerProxyCustody, docker_custody),
                restore_from_custody=True,
                monotonic_ns=monotonic_ns,
                exec_runtime=runtime,
                exec_cancellation=cancellation,
                effective_network_binding=DockerV2EffectiveNetworkBinding(
                    attempt_id=policy.attempt_id,
                    claim_ref=dispatch_authority.claim_ref,
                    controller_fence=dispatch_authority.controller_fence,
                    network_policy_digest=policy.network_policy_digest,
                    target_plan_digest=content_hash(
                        {"scope": plan["scope"], "network_plan": plan["network_plan"]}
                    ),
                ),
            )
            network_dispatch = ControllerOwnedV2NetworkDispatch(
                proxy=proxy,
                policy=policy,
                launch_plan=launch_plan,
                claim_ref=dispatch_authority.claim_ref,
                controller_fence=dispatch_authority.controller_fence,
                require_active_activation=require_active_activation,
                hold_active_scope=hold_active_scope,
            )
            terminal_store = _ExecAttachmentTerminalStore(
                store,
                attempt_id=policy.attempt_id,
                claim_ref=dispatch_authority.claim_ref,
                controller_fence=dispatch_authority.controller_fence,
                transaction_ref=transaction_ref,
                owner_ref=owner_ref,
                owner_binding_ref=launch_plan.exec_broker_binding_digest,
                container_id=container_identity.container_id,
            )
            return cls(
                policy=policy,
                launch_plan=launch_plan,
                container_identity=container_identity,
                transaction_ref=transaction_ref,
                owner_ref=owner_ref,
                dispatch_authority=dispatch_authority,
                operation_watchdog=watchdog,
                dispatch_runtime=runtime,
                docker_transport=transport,
                cancellation_authority=cancellation,
                cancellation_audit=cancellation_audit,
                docker_custody=docker_custody,
                resource_custody=resource_custody,
                network_dispatch=network_dispatch,
                journal_connection=journal_connection,
                terminal_store=terminal_store,
                _token=_ATTACHMENT_CONSTRUCTION_TOKEN,
            )
        except Exception as exc:
            failures: list[Exception] = []
            if watchdog is not None:
                try:
                    watchdog.close()
                except Exception as cleanup_error:
                    failures.append(cleanup_error)
            if journal_connection is not None:
                journal_connection.close()
            # The guardian does not own the window before its first arm.
            try:
                resource_custody.stop_owned(
                    policy.attempt_id,
                    custody_identity_digest=policy.custody_plan_digest,
                    network_policy_digest=policy.network_policy_digest,
                    timeout_seconds=5.0,
                )
            except Exception as cleanup_error:
                failures.append(cleanup_error)
            if failures:
                raise InstalledV2ExecAttachmentError(
                    "V2 exec attachment startup cleanup is uncertain"
                ) from failures[0]
            raise InstalledV2ExecAttachmentError("V2 exec attachment could not open") from exc

    @property
    def exec_broker_binding_digest(self) -> str:
        return self._plan.exec_broker_binding_digest

    @property
    def dispatch_authority_ref(self) -> str:
        return self._authority.authority_ref

    @property
    def dispatch_authority(self) -> ControllerExecDispatchAuthorityV2:
        return self._authority

    @property
    def dispatch_runtime(self) -> DockerExecDispatchRuntimeV2:
        return self._runtime

    @property
    def docker_transport(self) -> _GuardedDockerTransportView:
        return self._transport_view

    @property
    def cancellation_ref(self) -> str:
        return self._cancellation_ref

    @property
    def cancellation_authority(self) -> DockerExecCancellationLaneV2:
        return self._cancellation

    @property
    def operation_watchdog_ref(self) -> str:
        return self._watchdog.activation_ref

    @property
    def operation_watchdog(self) -> ControllerOwnedExecOperationCustodyV2:
        return self._watchdog

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain or self._watchdog.cleanup_uncertain

    def handle(
        self,
        raw_request: bytes,
        cancellation: DockerProxyCancellation,
        *,
        exec_admission: DockerExecAdmissionV2 | None = None,
    ) -> DockerProxyReply:
        with self._lock:
            if self._closed or self.cleanup_uncertain:
                raise InstalledV2ExecAttachmentError("V2 exec attachment is unavailable")
            return self._network_dispatch.handle(
                raw_request, cancellation, exec_admission=exec_admission
            )

    def refresh_network_receipt(
        self, *, cancellation: DockerProxyCancellation
    ) -> DockerV2EffectiveNetworkReceipt:
        with self._lock:
            if self._closed or self.cleanup_uncertain:
                raise InstalledV2ExecAttachmentError("V2 exec attachment is unavailable")
            return self._network_dispatch.refresh_network_receipt(
                container_id=self._identity.container_id, cancellation=cancellation
            )

    def dispatch_target(
        self,
        callback: Callable[[DockerV2EffectiveNetworkReceipt], Any],
        *,
        cancellation: DockerProxyCancellation,
    ) -> Any:
        """Invoke one target relay send under inspected placement and active scope."""

        if not callable(callback):
            raise InstalledV2ExecAttachmentError("V2 target dispatch callback is unavailable")
        with self._lock:
            if self._closed or self.cleanup_uncertain:
                raise InstalledV2ExecAttachmentError("V2 exec attachment is unavailable")
            with self._network_dispatch.with_network_dispatch_gate(
                container_id=self._identity.container_id,
                cancellation=cancellation,
            ) as receipt:
                return callback(receipt)

    def close_and_observe(self) -> ExecAttachmentTerminalReceiptV2:
        """Close the guardian, then prove exact owned-container absence twice."""

        with self._lock:
            if self._terminal_receipt is not None:
                return self._terminal_receipt
            if self._closed:
                raise InstalledV2ExecAttachmentError("V2 exec cleanup remains uncertain")
            self._closed = True
            failures: list[Exception] = []
            try:
                pending_leases = self._watchdog.recovery.operation_leases
            except Exception as exc:
                pending_leases = ()
                failures.append(exc)
            try:
                self._watchdog.close()
            except Exception as exc:
                failures.append(exc)
            # The guardian does not cover the container before its first arm.
            try:
                source_results = self._resource_custody.observe_absence_twice()
            except Exception as exc:
                source_results = ()
                failures.append(exc)
            try:
                custody = self._docker_custody.reopen()
                audits = self._cancellation_audit.reopen()
                if custody.unresolved_operations or custody.state.reconciliation_required:
                    raise InstalledV2ExecAttachmentError("V2 Docker custody remains unresolved")
                if len(source_results) != 2 or pending_leases:
                    # The present supervisor close API discards receipts for
                    # leases it terminates. Until it retains those receipts,
                    # whole-container absence alone cannot settle that join.
                    raise InstalledV2ExecAttachmentError(
                        "V2 exec terminal operation evidence is incomplete"
                    )
                if failures:
                    raise InstalledV2ExecAttachmentError("V2 exec cleanup is uncertain")
                receipt = ExecAttachmentTerminalReceiptV2.from_sources(
                    attempt_id=self._policy.attempt_id,
                    claim_ref=self._authority.claim_ref,
                    controller_fence=self._authority.controller_fence,
                    transaction_ref=self._transaction_ref,
                    owner_ref=self._owner_ref,
                    owner_binding_ref=self.exec_broker_binding_digest,
                    container_identity=self._identity,
                    supervisor_activation_ref=self._watchdog.activation_ref,
                    docker_custody_journal_ref=custody.journal_digest,
                    cancellation_audit_tail_ref=(audits[-1].entry_ref if audits else None),
                    source_results=source_results,
                )
                self._terminal_store.retain(receipt)
                self._terminal_receipt = receipt
                return receipt
            except Exception as exc:
                self._cleanup_uncertain = True
                raise InstalledV2ExecAttachmentError("V2 exec cleanup is unverified") from exc
            finally:
                self._journal_connection.close()

    def reopen_terminal(
        self, receipt_ref: str | None = None
    ) -> RetainedExecAttachmentTerminalV2 | None:
        """Read the immutable source receipt without launching another worker."""

        return self._terminal_store.reopen(receipt_ref)

    @classmethod
    def reopen_terminal_source(
        cls,
        *,
        store: DockerCustodyProductStore,
        attempt_id: str,
        claim_ref: str,
        controller_fence: str,
        transaction_ref: str,
        owner_ref: str,
        owner_binding_ref: str,
        container_id: str,
        receipt_ref: str | None = None,
    ) -> RetainedExecAttachmentTerminalV2 | None:
        """Recovery-only source read; no Docker or worker process is launched."""

        source = _ExecAttachmentTerminalStore.reopen_existing(
            store,
            attempt_id=attempt_id,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            transaction_ref=transaction_ref,
            owner_ref=owner_ref,
            owner_binding_ref=owner_binding_ref,
            container_id=container_id,
        )
        return source.reopen(receipt_ref)

    def close(self) -> None:
        self.close_and_observe()


__all__ = [
    "ControllerOwnedStrixV2ExecAttachment",
    "ControllerOwnedV2NetworkDispatch",
    "ExecAttachmentTerminalReceiptV2",
    "FixedDockerV2ResourceCustody",
    "InstalledV2ExecAttachmentError",
    "RetainedExecAttachmentTerminalV2",
]
