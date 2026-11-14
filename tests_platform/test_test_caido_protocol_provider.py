"""Test-only public-wire provider; no Caido application is acquired or run."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib.metadata
import json
import os
import socket
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire import test_caido_protocol_provider as provider
from bluefire import test_caido_protocol_server as provider_server
from bluefire.util import content_hash


def digest(character: str) -> str:
    return "sha256:" + character * 64


def binding(*, listener: socket.socket | None = None) -> provider.TestCaidoListenerBinding:
    device, inode = (7, 11)
    netns_device, netns_inode = (6, 7)
    netns_cookie = 8
    if listener is not None:
        info = os.fstat(listener.fileno())
        device, inode = info.st_dev, info.st_ino
        namespace = os.stat("/proc/self/ns/net")
        netns_device, netns_inode = namespace.st_dev, namespace.st_ino
        netns_cookie = int.from_bytes(
            listener.getsockopt(socket.SOL_SOCKET, provider.SO_NETNS_COOKIE, 8), sys.byteorder
        )
    return provider.TestCaidoListenerBinding(
        attempt_id="engine-attempt-" + "a" * 32,
        container_ref=digest("1"),
        provider_generation_ref=digest("2"),
        owner_process_ref=digest("3"),
        listener_ref=digest("4"),
        custody_ref=digest("5"),
        netns_device=netns_device,
        netns_inode=netns_inode,
        netns_cookie=netns_cookie,
        listener_device=device,
        listener_inode=inode,
    )


def manifest(*, listener: socket.socket | None = None) -> provider.TestCaidoProviderManifest:
    return provider.TestCaidoProviderManifest(
        accepted_claim_digest=digest("a"),
        runtime_admission_digest=digest("b"),
        controlled_profile_digest=digest("c"),
        authorization_digest=digest("d"),
        provider_source_digest=provider.provider_source_digest(),
        binding=binding(listener=listener),
    )


def request(
    method: str,
    target: str,
    *,
    body: bytes = b"",
    token: str | None = None,
    sdk: bool = False,
) -> bytes:
    headers = [
        f"{method} {target} HTTP/1.1",
        "Host: 127.0.0.1:48080",
        "Accept: */*",
    ]
    if sdk:
        headers += [
            "Accept-Encoding: gzip, deflate",
            "User-Agent: Python/3.12 aiohttp/3.14.5",
        ]
    else:
        headers.append("User-Agent: curl/8.14.1")
    if token is not None:
        headers.append("Authorization: Bearer " + token)
    if body:
        headers += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


def body(raw: bytes) -> dict[str, Any]:
    return json.loads(raw.partition(b"\r\n\r\n")[2])


def exchange(raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", 48080), timeout=2) as connection:
        connection.sendall(raw)
        blocks: list[bytes] = []
        while block := connection.recv(8192):
            blocks.append(block)
    return b"".join(blocks)


def login(runtime: provider.TestCaidoProtocolRuntime) -> tuple[bytes, str]:
    raw = request(
        "POST",
        "/graphql",
        body=json.dumps({"query": provider._LOGIN_QUERY}, separators=(",", ":")).encode("utf-8"),
    )
    response = runtime.handle(raw)
    token = body(response)["data"]["loginAsGuest"]["token"]["accessToken"]
    return raw, token


def test_identity_is_explicitly_test_only_and_production_ineligible() -> None:
    value = manifest()
    descriptor = provider.provider_descriptor()

    assert value.test_provider is True
    assert value.live_caido_proof is False
    assert value.production_eligible is False
    assert value.activation_mode == "installed_deterministic_test"
    assert descriptor["provider_kind"] == "bluefire-test-caido-protocol"
    assert descriptor["test_provider"] is True
    assert descriptor["live_caido_proof"] is False
    assert descriptor["production_eligible"] is False
    assert descriptor["caido_server_auth_version"] == "0.1.2"
    assert descriptor["listener"] == {
        "host": "127.0.0.1",
        "port": 48080,
        "prebound": True,
    }
    root = Path(provider.__file__).resolve().parent
    expected_files = []
    for name in (
        "bluefire/test_caido_protocol_entry.py",
        "bluefire/test_caido_protocol_provider.py",
        "bluefire/test_caido_protocol_server.py",
    ):
        payload = (root / Path(name).name).read_bytes()
        expected_files.append(
            {"name": name, "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}"}
        )
    assert descriptor["provider_source_digest"] == content_hash(
        {
            "schema_version": "bluefire.test-caido-protocol-provider-source.v1",
            "files": expected_files,
        }
    )
    assert "caido" not in descriptor.get("version", "").lower()

    with pytest.raises(provider.TestCaidoProviderError, match="manifest_identity_invalid"):
        replace(value, production_eligible=True)
    with pytest.raises(provider.TestCaidoProviderError, match="manifest_identity_invalid"):
        replace(value, live_caido_proof=True)
    with pytest.raises(provider.TestCaidoProviderError, match="manifest_identity_invalid"):
        replace(value, activation_mode="production")


def test_provider_sources_have_no_outbound_or_listener_creation_primitive() -> None:
    root = Path(provider.__file__).resolve().parent
    sources = [Path(provider.__file__).resolve(), root / "test_caido_protocol_server.py"]
    forbidden_socket_calls = {"socket", "create_connection", "socketpair"}
    forbidden_endpoint_calls = {"bind", "listen", "connect", "connect_ex"}
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "socket"
                and node.func.attr in forbidden_socket_calls
            ):
                raise AssertionError(f"{source.name} creates a socket with {node.func.attr}")
            assert node.func.attr not in forbidden_endpoint_calls


def test_exact_login_is_attempt_local_replay_safe_and_secret_free_in_audit() -> None:
    audit = provider.MemoryTestCaidoAuditSink()
    runtime = provider.TestCaidoProtocolRuntime(manifest(), audit)
    raw, token = login(runtime)

    replay = runtime.handle(raw)
    assert body(replay)["data"]["loginAsGuest"]["token"]["accessToken"] == token
    assert replay == runtime.handle(raw)
    retained = json.dumps([record.as_mapping() for record in audit.records], sort_keys=True)
    assert token not in retained
    assert "Bearer" not in retained
    assert [record.outcome for record in audit.records[:3]] == [
        "prepared",
        "committed",
        "replayed",
    ]


def test_health_requires_the_exact_sdk_boundary_and_never_claims_live_caido() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    response = runtime.handle(request("GET", "/health", sdk=True))
    result = body(response)

    assert result == {
        "name": "BlueFire Test Caido protocol provider",
        "version": "caido-sdk-client-wire-0.2.0-test",
        "ready": True,
        "test_provider": True,
        "live_caido_proof": False,
    }
    with pytest.raises(provider.TestCaidoProviderError, match="health_invalid"):
        runtime.handle(request("GET", "/health"))


def test_project_state_machine_is_exact_replay_safe_and_stale_after_delete() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    _raw, _token = login(runtime)
    create_digest = digest("6")
    create = runtime._create_project(  # noqa: SLF001 - exact internal effect contract
        {"input": {"name": "sandbox", "temporary": True}}, create_digest
    )
    project = body(create)["data"]["createProject"]["project"]
    assert (
        runtime._create_project(  # noqa: SLF001
            {"input": {"name": "sandbox", "temporary": True}}, create_digest
        )
        == create
    )

    selected = runtime._select_project(  # noqa: SLF001
        {"id": project["id"]}, digest("7")
    )
    assert body(selected)["data"]["selectProject"]["currentProject"]["project"] == project
    deleted = runtime._delete_project(  # noqa: SLF001
        {"id": project["id"]}, digest("8")
    )
    assert body(deleted)["data"]["deleteProject"]["deletedId"] == project["id"]
    assert (
        runtime._delete_project(  # noqa: SLF001
            {"id": project["id"]}, digest("8")
        )
        == deleted
    )
    with pytest.raises(provider.TestCaidoProviderError, match="mutation_stale"):
        runtime._select_project({"id": project["id"]}, digest("7"))  # noqa: SLF001


def test_wrong_bearer_and_arbitrary_graphql_never_mutate() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    _raw, _token = login(runtime)
    unknown = json.dumps(
        {"query": "query Introspection { __schema { types { name } } }", "variables": {}},
        separators=(",", ":"),
    ).encode("utf-8")
    response = runtime.handle(request("POST", "/graphql", body=unknown, token="wrong", sdk=True))
    assert body(response)["errors"][0]["extensions"]["CAIDO"] == {
        "code": "AUTHORIZATION",
        "reason": "INVALID_TOKEN",
    }

    _raw, token = login(runtime)
    with pytest.raises(provider.TestCaidoProviderError, match="graphql_document_refused"):
        runtime.handle(request("POST", "/graphql", body=unknown, token=token, sdk=True))
    assert runtime._project is None  # noqa: SLF001


def test_authorization_refusal_budget_revokes_cached_login_response() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    login(runtime)
    runtime._refusals = 0  # noqa: SLF001
    unknown = b'{"query":"query Unknown { __typename }","variables":{}}'
    response = runtime.handle(request("POST", "/graphql", body=unknown, token="wrong", sdk=True))
    assert body(response)["errors"][0]["extensions"]["CAIDO"]["code"] == "AUTHORIZATION"
    assert runtime.state is provider.RuntimeState.REVOKED
    assert runtime._token is None  # noqa: SLF001
    assert runtime._journal == {}  # noqa: SLF001


def test_cancellation_revokes_bearer_and_drain_clears_attempt_state() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    login(runtime)
    runtime._create_project(  # noqa: SLF001
        {"input": {"name": "sandbox", "temporary": True}}, digest("6")
    )

    runtime.cancel()
    assert runtime.state is provider.RuntimeState.REVOKED
    with pytest.raises(provider.TestCaidoProviderError, match="state_refused"):
        runtime.handle(request("GET", "/health", sdk=True))
    runtime.drain()
    assert runtime.state is provider.RuntimeState.DRAINED
    assert runtime._token is None  # noqa: SLF001
    assert runtime._project is None  # noqa: SLF001
    assert runtime._journal == {}  # noqa: SLF001


def test_file_audit_is_durable_bounded_and_contains_no_protocol_payload(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    sink = provider.FileDescriptorTestCaidoAuditSink(descriptor)
    runtime = provider.TestCaidoProtocolRuntime(manifest(), sink)
    _raw, token = login(runtime)
    sink.close()

    retained = path.read_text(encoding="utf-8")
    assert token not in retained
    assert provider._LOGIN_QUERY not in retained
    assert '"test_provider":true' in retained
    assert '"live_caido_proof":false' in retained


def test_audit_refuses_nonempty_file_instead_of_overwriting_history(tmp_path: Path) -> None:
    path = tmp_path / "existing-audit.jsonl"
    path.write_text('{"retained":true}\n', encoding="utf-8")
    descriptor = os.open(path, os.O_APPEND | os.O_WRONLY)
    with pytest.raises(provider.TestCaidoProviderError, match="audit_descriptor_invalid"):
        provider.FileDescriptorTestCaidoAuditSink(descriptor)
    os.close(descriptor)
    assert path.read_text(encoding="utf-8") == '{"retained":true}\n'


@pytest.mark.skipif(os.name != "posix", reason="descriptor flag inspection is POSIX-only")
def test_audit_requires_append_descriptor_and_private_file(tmp_path: Path) -> None:
    nonappend = tmp_path / "nonappend.jsonl"
    descriptor = os.open(nonappend, os.O_CREAT | os.O_WRONLY, 0o600)
    with pytest.raises(provider.TestCaidoProviderError, match="audit_descriptor_invalid"):
        provider.FileDescriptorTestCaidoAuditSink(descriptor)
    os.close(descriptor)

    readonly = tmp_path / "readonly.jsonl"
    readonly.touch(mode=0o600)
    descriptor = os.open(readonly, os.O_RDONLY | os.O_APPEND)
    with pytest.raises(provider.TestCaidoProviderError, match="audit_descriptor_invalid"):
        provider.FileDescriptorTestCaidoAuditSink(descriptor)
    os.close(descriptor)

    shared = tmp_path / "shared.jsonl"
    descriptor = os.open(shared, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o640)
    with pytest.raises(provider.TestCaidoProviderError, match="audit_descriptor_invalid"):
        provider.FileDescriptorTestCaidoAuditSink(descriptor)
    os.close(descriptor)


def test_cancel_purges_bearer_response_even_when_lifecycle_audit_and_drain_fail() -> None:
    class FailingLifecycleAudit(provider.MemoryTestCaidoAuditSink):
        def append(self, record: provider.TestCaidoAuditRecord) -> None:
            if record.operation == "lifecycle":
                raise OSError("bounded test failure")
            super().append(record)

    runtime = provider.TestCaidoProtocolRuntime(manifest(), FailingLifecycleAudit())
    _raw, token = login(runtime)
    assert token.encode("ascii") in runtime._journal["LoginAsGuest"].response  # noqa: SLF001

    with pytest.raises(provider.TestCaidoProviderError, match="audit_write_unknown"):
        runtime.cancel()
    assert runtime.state is provider.RuntimeState.UNKNOWN
    assert runtime._token is None  # noqa: SLF001
    assert runtime._project is None  # noqa: SLF001
    assert runtime._journal == {}  # noqa: SLF001

    with pytest.raises(provider.TestCaidoProviderError, match="audit_write_unknown"):
        runtime.drain()
    assert runtime.state is provider.RuntimeState.UNKNOWN
    assert runtime._journal == {}  # noqa: SLF001


def test_login_commit_audit_failure_purges_bearer_response() -> None:
    class FailingCommitAudit(provider.MemoryTestCaidoAuditSink):
        def append(self, record: provider.TestCaidoAuditRecord) -> None:
            if record.operation == "LoginAsGuest" and record.outcome == "committed":
                raise OSError("bounded test failure")
            super().append(record)

    runtime = provider.TestCaidoProtocolRuntime(manifest(), FailingCommitAudit())
    with pytest.raises(provider.TestCaidoProviderError, match="audit_write_unknown"):
        login(runtime)
    assert runtime.state is provider.RuntimeState.UNKNOWN
    assert runtime._token is None  # noqa: SLF001
    assert runtime._journal == {}  # noqa: SLF001


@pytest.mark.parametrize("exhaustion", ["bytes", "requests", "refusals"])
def test_budget_revocation_purges_bearer_response(exhaustion: str) -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    login(runtime)
    if exhaustion == "bytes":
        runtime._bytes = 0  # noqa: SLF001
    elif exhaustion == "requests":
        runtime._requests = 0  # noqa: SLF001
    else:
        runtime._refusals = 0  # noqa: SLF001
    with pytest.raises(provider.TestCaidoProviderError):
        runtime.handle(request("GET", "/unknown" if exhaustion == "refusals" else "/health"))
    assert runtime.state is provider.RuntimeState.REVOKED
    assert runtime._token is None  # noqa: SLF001
    assert runtime._journal == {}  # noqa: SLF001


def test_deep_or_nonstandard_json_is_refused_without_escaping_runtime() -> None:
    runtime = provider.TestCaidoProtocolRuntime(manifest())
    deep = b'{"query":"x","variables":' + b"[" * 30 + b"0" + b"]" * 30 + b"}"
    with pytest.raises(provider.TestCaidoProviderError, match="json_invalid"):
        runtime.handle(request("POST", "/graphql", body=deep, sdk=True))
    nonstandard = b'{"query":"x","variables":{"value":NaN}}'
    with pytest.raises(provider.TestCaidoProviderError, match="json_invalid"):
        runtime.handle(request("POST", "/graphql", body=nonstandard, sdk=True))


def test_preparse_refusal_consumes_request_and_byte_reservations() -> None:
    audit = provider.MemoryTestCaidoAuditSink()
    runtime = provider.TestCaidoProtocolRuntime(manifest(), audit)
    with pytest.raises(provider.TestCaidoProviderError, match="request_deadline"):
        runtime.record_refusal("request_deadline", 17)
    record = audit.records[-1]
    assert record.request_budget_remaining == runtime.manifest.request_budget - 1
    assert record.byte_budget_remaining == runtime.manifest.byte_budget - 17


@pytest.mark.skipif(sys.platform != "linux", reason="network namespace custody is Linux-only")
def test_prebound_numeric_listener_reaches_ready_and_drains_without_target_authority() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 48080))
    listener.listen(4)
    runtime = provider.TestCaidoProtocolRuntime(manifest(listener=listener))
    server = provider_server.TestCaidoProtocolServer(runtime, listener)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        raw = request(
            "POST",
            "/graphql",
            body=json.dumps({"query": provider._LOGIN_QUERY}, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        result = body(exchange(raw))
        assert result["data"]["loginAsGuest"]["token"]["accessToken"].startswith("bft_")
    finally:
        server.cancel()
        worker.join(timeout=3)
        receipt = server.drain()
    assert not worker.is_alive()
    assert receipt.listener_absent is True
    assert receipt.bearer_absent is True
    assert receipt.project_state_absent is True
    assert receipt.target_cleanup_verified is False


@pytest.mark.skipif(sys.platform != "linux", reason="network namespace custody is Linux-only")
def test_listener_rejects_mismatched_socket_network_namespace_cookie() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 48080))
        listener.listen(4)
        valid = manifest(listener=listener)
        wrong = replace(
            valid,
            binding=replace(valid.binding, netns_cookie=valid.binding.netns_cookie + 1),
        )
        runtime = provider.TestCaidoProtocolRuntime(wrong)
        with pytest.raises(provider.TestCaidoProviderError, match="listener_custody_invalid"):
            provider_server.TestCaidoProtocolServer(runtime, listener)
    finally:
        listener.close()


@pytest.mark.skipif(sys.version_info[:2] != (3, 12), reason="pinned SDK requires CPython 3.12")
@pytest.mark.skipif(sys.platform != "linux", reason="network namespace custody is Linux-only")
def test_exact_pinned_sdk_connect_create_select_delete_against_prebound_provider() -> None:
    sdk = pytest.importorskip(
        "caido_sdk_client", reason="exact pinned SDK closure is not installed"
    )
    if importlib.metadata.version("caido-sdk-client") != "0.2.0":
        pytest.skip("exact caido-sdk-client 0.2.0 is not installed")
    if importlib.metadata.version("aiohttp") != "3.14.5":
        pytest.skip("exact pinned aiohttp transport is not installed")
    if importlib.metadata.version("gql") != "4.0.0":
        pytest.skip("exact pinned gql transport is not installed")
    if importlib.metadata.version("caido-server-auth") != provider.CAIDO_SERVER_AUTH_VERSION:
        pytest.skip("exact pinned caido-server-auth is not installed")
    wheel_value = os.environ.get("BLUEFIRE_CAIDO_SDK_CLIENT_WHEEL")
    if wheel_value is None:
        pytest.skip("the exact SDK wheel artifact was not supplied")
    wheel = Path(wheel_value).resolve(strict=True)
    assert wheel.is_file() and not wheel.is_symlink()
    assert "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() == (
        provider.CAIDO_SDK_CLIENT_WHEEL_DIGEST
    )
    auth_wheel_value = os.environ.get("BLUEFIRE_CAIDO_SERVER_AUTH_WHEEL")
    if auth_wheel_value is None:
        pytest.skip("the exact SDK authentication wheel artifact was not supplied")
    auth_wheel = Path(auth_wheel_value).resolve(strict=True)
    assert auth_wheel.is_file() and not auth_wheel.is_symlink()
    assert "sha256:" + hashlib.sha256(auth_wheel.read_bytes()).hexdigest() == (
        provider.CAIDO_SERVER_AUTH_WHEEL_DIGEST
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 48080))
    listener.listen(4)
    runtime = provider.TestCaidoProtocolRuntime(manifest(listener=listener))
    server = provider_server.TestCaidoProtocolServer(runtime, listener)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        raw = request(
            "POST",
            "/graphql",
            body=json.dumps({"query": provider._LOGIN_QUERY}, separators=(",", ":")).encode(
                "utf-8"
            ),
        )
        response = exchange(raw)
        token = body(response)["data"]["loginAsGuest"]["token"]["accessToken"]

        async def exercise() -> None:
            from caido_sdk_client import Client, TokenAuthOptions
            from caido_sdk_client.types import CreateProjectOptions

            client = Client(
                "http://127.0.0.1:48080",
                auth=TokenAuthOptions(token=token),
            )
            await client.connect()
            project = await client.project.create(
                CreateProjectOptions(name="sandbox", temporary=True)
            )
            selected = await client.project.select(project.id)
            assert selected.id == project.id
            await client.project.delete(project.id)
            await client.aclose()

        asyncio.run(exercise())
    finally:
        server.cancel()
        worker.join(timeout=3)
        receipt = server.drain()
    assert not worker.is_alive()
    assert receipt.state is provider.RuntimeState.DRAINED
    assert receipt.listener_absent is True
    assert receipt.bearer_absent is True
    assert receipt.target_cleanup_verified is False
    assert sdk is not None
