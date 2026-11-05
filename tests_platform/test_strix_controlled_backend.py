from __future__ import annotations

import asyncio
import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import pytest

from bluefire import strix_controlled_backend as controlled
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
DIGESTS = {
    name: "sha256:" + character * 64
    for name, character in (
        ("build", "1"),
        ("policy", "2"),
        ("relay", "3"),
        ("relay_upstream", "a"),
        ("relay_channel", "b"),
        ("relay_retry", "c"),
        ("boundary", "4"),
        ("admission", "5"),
        ("image", "6"),
        ("sdk", "7"),
        ("bootstrap", "8"),
        ("tmpfs", "9"),
    )
}
IMAGE = "ghcr.io/bluefire/strix-sandbox@" + DIGESTS["image"]


def _environment() -> dict[str, str]:
    proxy = "http://127.0.0.1:48080"
    return {
        "PYTHONUNBUFFERED": "1",
        "HOST_GATEWAY": "host.docker.internal",
        "STRIX_HOST_UID": "1000",
        "STRIX_HOST_GID": "1000",
        "http_proxy": proxy,
        "https_proxy": proxy,
        "ALL_PROXY": proxy,
        "NO_PROXY": "localhost,127.0.0.1",
    }


def _manifest_document() -> dict[str, Any]:
    return {
        "version": 1,
        "root": "/workspace",
        "entries": {},
        "environment": {"value": _environment()},
        "users": [],
        "groups": [],
        "extra_path_grants": [],
        "remote_mount_command_allowlist": list(controlled._DEFAULT_REMOTE_COMMAND_ALLOWLIST),
    }


class FakeManifest:
    def __init__(self, document: dict[str, Any] | None = None) -> None:
        self.document = document or _manifest_document()
        self.version = self.document["version"]
        self.root = self.document["root"]
        self.entries = self.document["entries"]
        self.environment = SimpleNamespace(value=self.document["environment"]["value"])
        self.users = self.document["users"]
        self.groups = self.document["groups"]
        self.extra_path_grants = self.document["extra_path_grants"]
        self.remote_mount_command_allowlist = self.document["remote_mount_command_allowlist"]

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return self.document


def _profile() -> controlled.ControlledRuntimeProfile:
    return controlled.ControlledRuntimeProfile.create(
        attempt_id=ATTEMPT,
        build_digest=DIGESTS["build"],
        policy_digest=DIGESTS["policy"],
        relay_digest=DIGESTS["relay"],
        relay_upstream_digest=DIGESTS["relay_upstream"],
        relay_channel_digest=DIGESTS["relay_channel"],
        relay_retry_digest=DIGESTS["relay_retry"],
        boundary_digest=DIGESTS["boundary"],
        admission_digest=DIGESTS["admission"],
        image_reference=IMAGE,
        image_digest=DIGESTS["image"],
        manifest_digest=content_hash(_manifest_document()),
        sdk_digest=DIGESTS["sdk"],
        bootstrap_digest=DIGESTS["bootstrap"],
        tmpfs_contract_digest=DIGESTS["tmpfs"],
        sandbox_uid=1000,
        sandbox_gid=1000,
    )


class FakeState:
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def model_validate(cls, payload: dict[str, object]) -> "FakeState":
        return cls(**payload)

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return dict(vars(self))


class FakeBaseSession:
    state: Any

    async def start(self) -> None:
        await self._ensure_backend_started()
        self.state.workspace_root_ready = True

    async def _ensure_backend_started(self) -> None:  # pragma: no cover - public shape only
        return None

    async def _exec_internal(
        self, *command: str | Path, timeout: float | None = None
    ) -> object:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def read(
        self, path: Path, *, user: Any = None
    ) -> io.IOBase:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def write(
        self, path: Path, data: io.IOBase, *, user: Any = None
    ) -> None:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def running(self) -> bool:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def persist_workspace(self) -> io.IOBase:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def hydrate_workspace(
        self, data: io.IOBase
    ) -> None:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def resolve_exposed_port(self, port: int) -> object:
        if port not in self.state.exposed_ports:
            raise ValueError("not configured")
        return await self._resolve_exposed_port(port)

    async def _resolve_exposed_port(self, port: int) -> object:
        _ = port
        raise NotImplementedError


class FakeBaseClient:
    def __init__(self) -> None:
        pass

    async def create(
        self, *, snapshot: Any = None, manifest: Any = None, options: Any
    ) -> object:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def delete(self, session: Any) -> object:  # pragma: no cover - public shape only
        raise NotImplementedError

    async def resume(self, state: Any) -> object:  # pragma: no cover - public shape only
        raise NotImplementedError

    def deserialize_session_state(
        self, payload: dict[str, object]
    ) -> object:  # pragma: no cover - public shape only
        raise NotImplementedError

    def serialize_session_state(self, state: FakeState) -> dict[str, object]:
        return state.model_dump(mode="json")


class FakeExecResult:
    def __init__(self, *, stdout: bytes, stderr: bytes, exit_code: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class FakeEndpoint:
    def __init__(self, *, host: str, port: int, tls: bool, query: str) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.query = query


def _module_loader(name: str) -> Any:
    if name == "agents.sandbox.session":
        return SimpleNamespace(
            BaseSandboxClient=FakeBaseClient,
            BaseSandboxSession=FakeBaseSession,
            SandboxSessionState=FakeState,
        )
    if name == "agents.sandbox.snapshot":
        return SimpleNamespace(resolve_snapshot=lambda _spec, identifier: {"id": identifier})
    if name == "agents.sandbox.types":
        return SimpleNamespace(ExecResult=FakeExecResult, ExposedPortEndpoint=FakeEndpoint)
    raise ImportError(name)


def _version(package: str) -> str:
    assert package == "openai-agents"
    return "0.19.0"


class FakeTransport:
    def __init__(self) -> None:
        self.profile: controlled.ControlledRuntimeProfile | None = None
        self.calls: list[tuple[str, Any]] = []
        self.handle = controlled.ControlledSandboxHandle(
            attempt_id=ATTEMPT,
            resource_id="sandbox-" + "b" * 32,
            resource_digest="sha256:" + "c" * 64,
            opaque_ref=object(),
        )
        self.files: dict[str, bytes] = {"/workspace/read.txt": b"read-result"}
        self.transfers: dict[str, bytearray] = {}
        self.transfer_meta: dict[str, tuple[str, int, str]] = {}
        self.lifecycle: Literal["running", "absent", "unknown"] = "running"
        self.exec_stdout = b"stdout"
        self.exec_stderr = b"stderr"
        self.exec_exit = 7
        self.drift_exec_digest = False
        self.drift_read_digest = False
        self.create_failure: BaseException | None = None
        self.create_started: asyncio.Event | None = None
        self.create_gate: asyncio.Event | None = None
        self.delete_unknown = False
        self.delete_relay_lifecycle: Literal["active", "absent", "unknown"] = "absent"
        self.caido_host = "127.0.0.1"
        self.caido_tls = False
        self.caido_retry_count = 0
        self.exec_started: asyncio.Event | None = None
        self.exec_gate: asyncio.Event | None = None
        self.fail_chunk_index: int | None = None
        self.commit_response_loss = False
        self.exec_failure: BaseException | None = None
        self.hydrate_failure: BaseException | None = None
        self.write_reconcile_outcome: Literal["published", "not_published", "unknown"] | None = None
        self.running_relay_lifecycle: (
            Literal["active", "absent", "not_applicable", "unknown"] | None
        ) = None
        self.running_operation_lifecycle: Literal["terminal", "not_applicable", "unknown"] = (
            "not_applicable"
        )

    def bind(self, profile: controlled.ControlledRuntimeProfile) -> "FakeTransport":
        self.profile = profile
        return self

    def _identity(self, request: Any) -> dict[str, Any]:
        assert self.profile is not None
        return {
            "request_digest": request.request_digest,
            "identity_digest": self.profile.identity_digest,
            "resource_digest": self.handle.resource_digest,
        }

    async def create_exact(
        self, request: controlled.ControlledCreateRequest
    ) -> controlled.ControlledCreateReceipt:
        self.calls.append(("create", request))
        if self.create_started is not None:
            self.create_started.set()
        if self.create_gate is not None:
            await self.create_gate.wait()
        if self.create_failure is not None:
            raise self.create_failure
        assert request.stdin_mode if hasattr(request, "stdin_mode") else True
        return controlled.ControlledCreateReceipt(
            schema_version="bluefire.strix-controlled-create-receipt.v1",
            request_digest=request.request_digest,
            identity_digest=request.identity_digest,
            handle=self.handle,
            lifecycle="running",
        )

    async def reconcile_create(
        self, request: controlled.ControlledLifecycleRequest
    ) -> controlled.ControlledLifecycleReceipt:
        self.calls.append(("reconcile_create", request))
        return controlled.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            request_digest=request.request_digest,
            identity_digest=request.identity_digest,
            resource_digest=None,
            lifecycle="absent",
            relay_lifecycle="absent",
            operation_lifecycle="terminal",
        )

    async def exec_exact(
        self, request: controlled.ControlledExecRequest
    ) -> controlled.ControlledExecReceipt:
        self.calls.append(("exec", request))
        if self.exec_started is not None:
            self.exec_started.set()
        if self.exec_gate is not None:
            await self.exec_gate.wait()
        if self.exec_failure is not None:
            raise self.exec_failure
        stdout_digest = controlled._sha256_bytes(self.exec_stdout)
        if self.drift_exec_digest:
            stdout_digest = "sha256:" + "0" * 64
        return controlled.ControlledExecReceipt(
            schema_version="bluefire.strix-controlled-exec-receipt.v1",
            **self._identity(request),
            exit_code=self.exec_exit,
            stdout_digest=stdout_digest,
            stderr_digest=controlled._sha256_bytes(self.exec_stderr),
            stdout=self.exec_stdout,
            stderr=self.exec_stderr,
        )

    async def cancel_exact(
        self, request: controlled.ControlledLifecycleRequest
    ) -> controlled.ControlledLifecycleReceipt:
        self.calls.append(("cancel", request))
        return controlled.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            **self._identity(request),
            lifecycle="cancelled",
            relay_lifecycle="active",
            operation_lifecycle="terminal",
        )

    async def read_exact(
        self, request: controlled.ControlledReadRequest
    ) -> controlled.ControlledReadReceipt:
        self.calls.append(("read", request))
        content = self.files[request.workspace_path]
        digest = controlled._sha256_bytes(content)
        if self.drift_read_digest:
            digest = "sha256:" + "0" * 64
        return controlled.ControlledReadReceipt(
            schema_version="bluefire.strix-controlled-read-receipt.v1",
            **self._identity(request),
            workspace_path=request.workspace_path,
            content_digest=digest,
            content=content,
        )

    async def begin_write_exact(
        self, request: controlled.ControlledWriteBeginRequest
    ) -> controlled.ControlledWriteBeginReceipt:
        self.calls.append(("write_begin", request))
        transfer = "transfer-" + "d" * 32
        self.transfers[transfer] = bytearray()
        self.transfer_meta[transfer] = (
            request.workspace_path,
            request.content_size,
            request.content_digest,
        )
        return controlled.ControlledWriteBeginReceipt(
            schema_version="bluefire.strix-controlled-write-begin-receipt.v1",
            **self._identity(request),
            transfer_id=transfer,
            next_offset=0,
        )

    async def write_chunk_exact(
        self, request: controlled.ControlledWriteChunkRequest
    ) -> controlled.ControlledWriteChunkReceipt:
        self.calls.append(("write_chunk", request))
        if request.index == self.fail_chunk_index:
            raise controlled.ControlledTransportError("chunk transport failed")
        target = self.transfers[request.transfer_id]
        assert request.offset == len(target)
        target.extend(request.chunk)
        return controlled.ControlledWriteChunkReceipt(
            schema_version="bluefire.strix-controlled-write-chunk-receipt.v1",
            **self._identity(request),
            transfer_id=request.transfer_id,
            chunk_digest=request.chunk_digest,
            next_offset=len(target),
        )

    async def commit_write_exact(
        self, request: controlled.ControlledWriteCommitRequest
    ) -> controlled.ControlledWriteCommitReceipt:
        self.calls.append(("write_commit", request))
        payload = bytes(self.transfers[request.transfer_id])
        path, size, digest = self.transfer_meta[request.transfer_id]
        assert (path, size, digest) == (
            request.workspace_path,
            request.content_size,
            request.content_digest,
        )
        assert controlled._sha256_bytes(payload) == digest
        self.files[path] = payload
        if self.commit_response_loss:
            raise controlled.ControlledTransportError("commit response lost")
        return controlled.ControlledWriteCommitReceipt(
            schema_version="bluefire.strix-controlled-write-commit-receipt.v1",
            **self._identity(request),
            transfer_id=request.transfer_id,
            workspace_path=path,
            content_size=size,
            content_digest=digest,
            atomically_published=True,
        )

    async def reconcile_write_exact(
        self, request: controlled.ControlledWriteReconcileRequest
    ) -> controlled.ControlledWriteReconcileReceipt:
        self.calls.append(("write_reconcile", request))
        observed = self.files.get(request.workspace_path)
        outcome: Literal["published", "not_published", "unknown"] = "not_published"
        if observed is not None and controlled._sha256_bytes(observed) == request.content_digest:
            outcome = "published"
        if self.write_reconcile_outcome is not None:
            outcome = self.write_reconcile_outcome
        return controlled.ControlledWriteReconcileReceipt(
            schema_version="bluefire.strix-controlled-write-reconcile-receipt.v1",
            **self._identity(request),
            operation_id=request.operation_id,
            workspace_path=request.workspace_path,
            content_size=request.content_size,
            content_digest=request.content_digest,
            outcome=outcome,
            transfer_lifecycle="absent",
        )

    async def abort_write_exact(
        self, request: controlled.ControlledWriteAbortRequest
    ) -> controlled.ControlledLifecycleReceipt:
        self.calls.append(("write_abort", request))
        self.transfers.pop(request.transfer_id, None)
        return controlled.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            **self._identity(request),
            lifecycle="absent",
            relay_lifecycle="not_applicable",
            operation_lifecycle="terminal",
        )

    async def running_exact(
        self, request: controlled.ControlledLifecycleRequest
    ) -> controlled.ControlledLifecycleReceipt:
        self.calls.append(("running", request))
        return controlled.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            **self._identity(request),
            lifecycle=self.lifecycle,
            relay_lifecycle=(
                self.running_relay_lifecycle
                if self.running_relay_lifecycle is not None
                else "active"
                if self.lifecycle == "running"
                else self.lifecycle
            ),
            operation_lifecycle=self.running_operation_lifecycle,
        )

    async def persist_exact(
        self, request: controlled.ControlledWorkspaceBlobRequest
    ) -> controlled.ControlledWorkspaceBlobReceipt:
        self.calls.append(("persist", request))
        archive = b"sealed-workspace-archive"
        return controlled.ControlledWorkspaceBlobReceipt(
            schema_version="bluefire.strix-controlled-persist-receipt.v1",
            **self._identity(request),
            archive_digest=controlled._sha256_bytes(archive),
            archive_size=len(archive),
            archive=archive,
        )

    async def hydrate_exact(
        self, request: controlled.ControlledWorkspaceBlobRequest
    ) -> controlled.ControlledHydrateReceipt:
        self.calls.append(("hydrate", request))
        if self.hydrate_failure is not None:
            raise self.hydrate_failure
        assert request.archive is not None
        assert controlled._sha256_bytes(request.archive) == request.archive_digest
        return controlled.ControlledHydrateReceipt(
            schema_version="bluefire.strix-controlled-hydrate-receipt.v1",
            **self._identity(request),
            archive_digest=request.archive_digest,
            applied=True,
        )

    async def resolve_caido_exact(
        self, request: controlled.ControlledPortRequest
    ) -> controlled.ControlledPortReceipt:
        self.calls.append(("port", request))
        assert request.container_port == 48080
        return controlled.ControlledPortReceipt(
            schema_version="bluefire.strix-controlled-port-receipt.v1",
            **self._identity(request),
            container_port=48080,
            relay_digest=request.relay_digest,
            upstream_digest=request.upstream_digest,
            channel_digest=request.channel_digest,
            retry_contract_digest=request.retry_contract_digest,
            retry_count=self.caido_retry_count,
            host=self.caido_host,
            port=41837,
            tls=self.caido_tls,
            published_host_port=False,
        )

    async def delete_exact(
        self, request: controlled.ControlledLifecycleRequest
    ) -> controlled.ControlledLifecycleReceipt:
        self.calls.append(("delete", request))
        lifecycle: Literal["unknown", "absent"] = "unknown" if self.delete_unknown else "absent"
        if lifecycle == "absent":
            self.lifecycle = "absent"
        return controlled.ControlledLifecycleReceipt(
            schema_version="bluefire.strix-controlled-lifecycle-receipt.v1",
            **self._identity(request),
            lifecycle=lifecycle,
            relay_lifecycle=("unknown" if lifecycle == "unknown" else self.delete_relay_lifecycle),
            operation_lifecycle="not_applicable",
        )


async def _open(
    transport: FakeTransport | None = None,
) -> tuple[Any, Any, FakeTransport, controlled.ControlledRuntimeProfile]:
    profile = _profile()
    fake = (transport or FakeTransport()).bind(profile)
    backend = controlled.create_registered_backend(
        profile,
        fake,
        version_getter=_version,
        module_loader=_module_loader,
    )
    client, session = await backend(
        image=IMAGE,
        manifest=FakeManifest(),
        exposed_ports=(48080,),
        bind_mounts=[],
    )
    return client, session, fake, profile


def test_backend_opens_exact_one_shot_session_and_refuses_generic_replay() -> None:
    async def run() -> None:
        client, session, transport, profile = await _open()
        assert session.state.type == "bluefire-controlled"
        assert session.state.identity_digest == profile.identity_digest
        assert session.state.workspace_root_ready is True
        assert [name for name, _ in transport.calls[:2]] == ["create", "running"]
        with pytest.raises(controlled.ControlledBackendError, match="creation is disabled"):
            await client.create(options=object())
        with pytest.raises(controlled.ControlledBackendError, match="resume is disabled"):
            await client.resume(session.state)
        with pytest.raises(controlled.ControlledBackendError, match="cannot be replayed"):
            await client.open_live_session(FakeManifest())

    asyncio.run(run())


def test_registered_backend_refuses_sequential_and_concurrent_replay() -> None:
    async def invoke(backend: Any) -> Any:
        return await backend(
            image=IMAGE,
            manifest=FakeManifest(),
            exposed_ports=(48080,),
            bind_mounts=[],
        )

    async def sequential() -> None:
        profile = _profile()
        transport = FakeTransport().bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=_module_loader,
        )
        client, session = await invoke(backend)
        with pytest.raises(controlled.ControlledBackendError, match="cannot be replayed"):
            await invoke(backend)
        assert [name for name, _ in transport.calls].count("create") == 1
        await client.delete(session)

    async def concurrent() -> None:
        profile = _profile()
        transport = FakeTransport().bind(profile)
        transport.create_started = asyncio.Event()
        transport.create_gate = asyncio.Event()
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=_module_loader,
        )
        first = asyncio.create_task(invoke(backend))
        await transport.create_started.wait()
        with pytest.raises(controlled.ControlledBackendError, match="cannot be replayed"):
            await invoke(backend)
        transport.create_gate.set()
        client, session = await first
        assert [name for name, _ in transport.calls].count("create") == 1
        await client.delete(session)

    asyncio.run(sequential())
    asyncio.run(concurrent())


@pytest.mark.parametrize(
    ("image", "ports", "mounts", "manifest", "message"),
    [
        ("ghcr.io/other/image@" + DIGESTS["image"], (48080,), [], FakeManifest(), "image"),
        (IMAGE, (48081,), [], FakeManifest(), "Caido"),
        (
            IMAGE,
            (48080,),
            [{"source": "C:/private", "target": "/workspace/private"}],
            FakeManifest(),
            "bind mounts",
        ),
        (
            IMAGE,
            (48080,),
            [],
            FakeManifest({**_manifest_document(), "root": "/tmp/workspace"}),
            "manifest root",
        ),
    ],
)
def test_backend_refuses_wrong_image_port_mount_or_manifest(
    image: str,
    ports: tuple[int, ...],
    mounts: list[dict[str, str]],
    manifest: FakeManifest,
    message: str,
) -> None:
    async def run() -> None:
        profile = _profile()
        transport = FakeTransport().bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=_module_loader,
        )
        with pytest.raises(controlled.ControlledBackendError, match=message):
            await backend(
                image=image,
                manifest=manifest,
                exposed_ports=ports,
                bind_mounts=mounts,
            )
        assert transport.calls == []

    asyncio.run(run())


def test_exec_is_bounded_and_receipt_digest_is_verified() -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        result = await session._exec_internal("printf", "%s", "value", timeout=5)
        assert (result.stdout, result.stderr, result.exit_code) == (b"stdout", b"stderr", 7)
        request = next(value for name, value in transport.calls if name == "exec")
        assert request.stdin_mode == "disabled"
        assert request.pty is False
        assert request.working_directory == "/workspace"
        second = await session._exec_internal("printf", "%s", "value", timeout=5)
        assert second.exit_code == 7
        requests = [value for name, value in transport.calls if name == "exec"]
        assert requests[0].operation_id != requests[1].operation_id
        assert requests[0].request_digest != requests[1].request_digest
        assert "printf" not in repr(request)
        with pytest.raises(controlled.ControlledBackendError, match="deadline"):
            await session._exec_internal("true", timeout=121)
        multiline = await session._exec_internal("sh", "-lc", "first\nsecond\tvalue", timeout=1)
        assert multiline.exit_code == 7
        with pytest.raises(controlled.ControlledBackendError, match="argument"):
            await session._exec_internal("printf", "secret\rvalue", timeout=1)
        transport.drift_exec_digest = True
        with pytest.raises(controlled.ControlledTransportError, match="exec receipt"):
            await session._exec_internal("true", timeout=1)

    asyncio.run(run())


def test_exec_cancellation_uses_controller_cancel_without_replay() -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        transport.exec_started = asyncio.Event()
        transport.exec_gate = asyncio.Event()
        task = asyncio.create_task(session._exec_internal("long-running", timeout=10))
        await transport.exec_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert [name for name, _ in transport.calls].count("exec") == 1
        cancel = next(value for name, value in transport.calls if name == "cancel")
        operation = next(value for name, value in transport.calls if name == "exec")
        assert cancel.operation_digest == operation.request_digest

    asyncio.run(run())


def test_partial_chunked_write_aborts_private_transfer() -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        transport.fail_chunk_index = 1
        payload = b"z" * (controlled.WRITE_CHUNK_BYTES + 1)
        with pytest.raises(controlled.ControlledTransportError, match="chunk transport"):
            await session.write(Path("partial.bin"), io.BytesIO(payload))
        assert "/workspace/partial.bin" not in transport.files
        assert [name for name, _ in transport.calls].count("write_abort") == 1

    asyncio.run(run())


def test_lost_write_commit_response_reconciles_exact_publish_without_replay() -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        transport.commit_response_loss = True
        payload = b"exact-published-content"
        await session.write(Path("published.bin"), io.BytesIO(payload))
        assert transport.files["/workspace/published.bin"] == payload
        assert [name for name, _ in transport.calls].count("write_reconcile") == 1
        first = next(value for name, value in transport.calls if name == "write_begin")

        transport.commit_response_loss = False
        await session.write(Path("published.bin"), io.BytesIO(payload))
        starts = [value for name, value in transport.calls if name == "write_begin"]
        assert starts[0].operation_id == first.operation_id
        assert starts[1].operation_id != starts[0].operation_id
        assert starts[1].request_digest != starts[0].request_digest

    asyncio.run(run())


def test_unreceipted_mutations_quarantine_until_verified_delete() -> None:
    async def exec_unknown() -> None:
        client, session, transport, _profile_value = await _open()
        transport.exec_failure = controlled.ControlledTransportError("exec response lost")
        with pytest.raises(controlled.ControlledTransportError, match="exec response"):
            await session._exec_internal("touch", "marker")
        with pytest.raises(controlled.ControlledBackendError, match="not available"):
            await session._exec_internal("touch", "marker")
        await client.delete(session)

    async def write_unknown() -> None:
        client, session, transport, _profile_value = await _open()
        transport.fail_chunk_index = 0
        transport.write_reconcile_outcome = "unknown"
        with pytest.raises(controlled.ControlledTransportError, match="write outcome"):
            await session.write(Path("unknown.bin"), io.BytesIO(b"value"))
        with pytest.raises(controlled.ControlledBackendError, match="not available"):
            await session.write(Path("other.bin"), io.BytesIO(b"value"))
        await client.delete(session)

    async def hydrate_unknown() -> None:
        client, session, transport, _profile_value = await _open()
        transport.hydrate_failure = controlled.ControlledTransportError("hydrate response lost")
        with pytest.raises(controlled.ControlledTransportError, match="hydrate response"):
            await session.hydrate_workspace(io.BytesIO(b"archive"))
        with pytest.raises(controlled.ControlledBackendError, match="not available"):
            await session._exec_internal("true")
        await client.delete(session)

    asyncio.run(exec_unknown())
    asyncio.run(write_unknown())
    asyncio.run(hydrate_unknown())


def test_sandbox_absence_without_relay_absence_remains_unknown() -> None:
    async def run() -> None:
        client, session, transport, _profile_value = await _open()
        assert await session.running() is True
        observations = [value for name, value in transport.calls if name == "running"]
        assert observations[0].observation_id != observations[1].observation_id
        assert observations[0].request_digest != observations[1].request_digest
        transport.lifecycle = "absent"
        transport.running_relay_lifecycle = "active"
        with pytest.raises(controlled.ControlledTransportError, match="running state"):
            await session.running()
        await client.delete(session)
        assert [name for name, _ in transport.calls].count("delete") == 1

    asyncio.run(run())


def test_running_refuses_unknown_operation_custody() -> None:
    async def run() -> None:
        client, session, transport, _profile_value = await _open()
        transport.running_operation_lifecycle = "unknown"
        with pytest.raises(controlled.ControlledTransportError, match="running state"):
            await session.running()
        with pytest.raises(controlled.ControlledBackendError, match="not available"):
            await session._exec_internal("true")
        await client.delete(session)

    asyncio.run(run())


def test_resolved_relay_requires_fresh_active_custody() -> None:
    async def run() -> None:
        transport = FakeTransport()
        transport.running_relay_lifecycle = "not_applicable"
        client, session, transport, _profile_value = await _open(transport)
        await session.resolve_exposed_port(48080)
        with pytest.raises(controlled.ControlledTransportError, match="running state"):
            await session.running()
        await client.delete(session)

    asyncio.run(run())


def test_chunked_write_read_persist_hydrate_and_caido_relay() -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        payload = b"x" * (controlled.WRITE_CHUNK_BYTES + 17)
        await session.write(Path("nested/result.bin"), io.BytesIO(payload))
        assert transport.files["/workspace/nested/result.bin"] == payload
        assert [name for name, _ in transport.calls].count("write_chunk") == 2
        for name, request in transport.calls:
            if name == "write_chunk":
                assert "x" * 100 not in repr(request)

        content = await session.read(Path("read.txt"))
        assert content.read() == b"read-result"
        second_content = await session.read(Path("read.txt"))
        assert second_content.read() == b"read-result"
        reads = [value for name, value in transport.calls if name == "read"]
        assert reads[0].observation_id != reads[1].observation_id
        assert reads[0].request_digest != reads[1].request_digest
        archive = await session.persist_workspace()
        assert archive.read() == b"sealed-workspace-archive"
        await session.hydrate_workspace(io.BytesIO(b"restored-archive"))
        endpoint = await session.resolve_exposed_port(48080)
        assert (endpoint.host, endpoint.port, endpoint.tls, endpoint.query) == (
            "127.0.0.1",
            41837,
            False,
            "",
        )
        port_request = next(value for name, value in transport.calls if name == "port")
        assert port_request.container_port == 48080

        with pytest.raises(controlled.ControlledBackendError, match="workspace path"):
            await session.read(Path("../secret"))
        with pytest.raises(controlled.ControlledBackendError, match="canonical"):
            await session.read("nested//result.bin")
        with pytest.raises(controlled.ControlledBackendError, match="canonical"):
            await session.read("nested/./result.bin")
        with pytest.raises(ValueError, match="not configured"):
            await session.resolve_exposed_port(80)

        transport.drift_read_digest = True
        with pytest.raises(controlled.ControlledTransportError, match="read receipt"):
            await session.read(Path("read.txt"))

    asyncio.run(run())


@pytest.mark.parametrize(
    ("attribute", "value"),
    [("caido_tls", True), ("caido_host", "::1"), ("caido_retry_count", 1)],
)
def test_caido_receipt_drift_deletes_sandbox_and_relay(attribute: str, value: object) -> None:
    async def run() -> None:
        _client, session, transport, _profile_value = await _open()
        setattr(transport, attribute, value)
        with pytest.raises(controlled.ControlledTransportError, match="Caido relay"):
            await session.resolve_exposed_port(48080)
        assert [name for name, _ in transport.calls].count("delete") == 1
        assert transport.lifecycle == "absent"

    asyncio.run(run())


def test_delete_is_active_idempotent_and_unknown_never_reports_success() -> None:
    async def idempotent() -> None:
        client, session, transport, _profile_value = await _open()
        await client.delete(session)
        await client.delete(session)
        assert [name for name, _ in transport.calls].count("delete") == 1
        assert await session.running() is False

    async def unknown() -> None:
        client, session, transport, _profile_value = await _open()
        transport.delete_unknown = True
        with pytest.raises(controlled.ControlledTransportError, match="unverified"):
            await client.delete(session)
        with pytest.raises(controlled.ControlledBackendError, match="not available"):
            await session._exec_internal("true")

    async def relay_still_present() -> None:
        client, session, transport, _profile_value = await _open()
        transport.delete_relay_lifecycle = "active"
        with pytest.raises(controlled.ControlledTransportError, match="unverified"):
            await client.delete(session)

    asyncio.run(idempotent())
    asyncio.run(unknown())
    asyncio.run(relay_still_present())


def test_partial_create_is_reconciled_and_sdk_drift_fails_before_effects() -> None:
    async def partial() -> None:
        profile = _profile()
        transport = FakeTransport()
        transport.create_failure = controlled.ControlledTransportError("create failed")
        transport.bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=_module_loader,
        )
        with pytest.raises(controlled.ControlledTransportError, match="create failed"):
            await backend(
                image=IMAGE,
                manifest=FakeManifest(),
                exposed_ports=(48080,),
                bind_mounts=[],
            )
        assert [name for name, _ in transport.calls] == ["create", "reconcile_create"]

    async def drift() -> None:
        profile = _profile()
        transport = FakeTransport().bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=lambda _package: "0.19.1",
            module_loader=_module_loader,
        )
        with pytest.raises(controlled.ControlledBackendError, match="version"):
            await backend(
                image=IMAGE,
                manifest=FakeManifest(),
                exposed_ports=(48080,),
                bind_mounts=[],
            )
        assert transport.calls == []

    async def abi_drift() -> None:
        class ChangedSession(FakeBaseSession):
            async def read(
                self, path: Path, *, user: Any = None, changed: bool = False
            ) -> io.IOBase:
                _ = (path, user, changed)
                raise NotImplementedError

        def changed_loader(name: str) -> Any:
            if name == "agents.sandbox.session":
                return SimpleNamespace(
                    BaseSandboxClient=FakeBaseClient,
                    BaseSandboxSession=ChangedSession,
                    SandboxSessionState=FakeState,
                )
            return _module_loader(name)

        profile = _profile()
        transport = FakeTransport().bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=changed_loader,
        )
        with pytest.raises(controlled.ControlledBackendError, match="contract changed"):
            await backend(
                image=IMAGE,
                manifest=FakeManifest(),
                exposed_ports=(48080,),
                bind_mounts=[],
            )
        assert transport.calls == []

    asyncio.run(partial())
    asyncio.run(drift())
    asyncio.run(abi_drift())


@pytest.mark.parametrize("failure_point", ["snapshot", "state"])
def test_post_create_sdk_initialization_failure_deletes_exact_handle(
    failure_point: str,
) -> None:
    async def run() -> None:
        class FailingState(FakeState):
            def __init__(self, **kwargs: Any) -> None:
                if failure_point == "state":
                    raise RuntimeError("injected state failure")
                super().__init__(**kwargs)

        def fail_snapshot(_spec: Any, _identifier: str) -> object:
            raise RuntimeError("injected snapshot failure")

        def failing_loader(name: str) -> Any:
            if name == "agents.sandbox.session":
                return SimpleNamespace(
                    BaseSandboxClient=FakeBaseClient,
                    BaseSandboxSession=FakeBaseSession,
                    SandboxSessionState=FailingState,
                )
            if name == "agents.sandbox.snapshot" and failure_point == "snapshot":
                return SimpleNamespace(resolve_snapshot=fail_snapshot)
            return _module_loader(name)

        profile = _profile()
        transport = FakeTransport().bind(profile)
        backend = controlled.create_registered_backend(
            profile,
            transport,
            version_getter=_version,
            module_loader=failing_loader,
        )
        with pytest.raises(RuntimeError, match=f"injected {failure_point} failure"):
            await backend(
                image=IMAGE,
                manifest=FakeManifest(),
                exposed_ports=(48080,),
                bind_mounts=[],
            )
        assert [name for name, _ in transport.calls] == ["create", "delete"]
        assert transport.lifecycle == "absent"

    asyncio.run(run())


def test_receipts_and_errors_do_not_render_opaque_refs_or_payloads() -> None:
    profile = _profile()
    handle = controlled.ControlledSandboxHandle(
        attempt_id=ATTEMPT,
        resource_id="sandbox-" + "e" * 32,
        resource_digest="sha256:" + "f" * 64,
        opaque_ref="top-secret-controller-token",
    )
    request = controlled.ControlledExecRequest(
        schema_version="bluefire.strix-controlled-exec-request.v1",
        request_digest="sha256:" + "0" * 64,
        identity_digest=profile.identity_digest,
        operation_id="operation-" + "1" * 32,
        handle=handle,
        argv=("true",),
        timeout_seconds=1,
        working_directory="/workspace",
    )
    assert "top-secret-controller-token" not in repr(handle)
    assert "top-secret-controller-token" not in repr(request)
    assert "DOCKER_HOST" not in repr(profile)
