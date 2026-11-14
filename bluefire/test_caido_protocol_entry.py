"""Process entry for the controller-owned Test Caido protocol provider."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import select
import signal
import socket
import stat
import threading
from typing import Any, Mapping, Sequence

from .test_caido_protocol_provider import (
    MAX_MANIFEST_BYTES,
    READY_SCHEMA,
    FileDescriptorTestCaidoAuditSink,
    TestCaidoProtocolRuntime,
    TestCaidoProviderError,
    TestCaidoProviderManifest,
    _canonical,
    provider_descriptor,
)
from .test_caido_protocol_server import TestCaidoProtocolServer


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    if type(descriptor) is not int or descriptor < 0:
        raise TestCaidoProviderError("descriptor_invalid")
    try:
        os.set_inheritable(descriptor, False)
        value = bytearray()
        while len(value) <= maximum:
            block = os.read(descriptor, min(8192, maximum + 1 - len(value)))
            if not block:
                break
            value.extend(block)
        os.close(descriptor)
    except OSError:
        raise TestCaidoProviderError("descriptor_invalid") from None
    if not value or len(value) > maximum:
        raise TestCaidoProviderError("descriptor_invalid")
    return bytes(value)


def _write_descriptor(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = _canonical(value) + b"\n"
    try:
        os.set_inheritable(descriptor, False)
        remaining = memoryview(payload)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise OSError
            remaining = remaining[count:]
        os.close(descriptor)
    except OSError:
        raise TestCaidoProviderError("descriptor_write_unknown") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BlueFire Test Caido protocol provider")
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--manifest-fd", type=int)
    parser.add_argument("--listener-fd", type=int)
    parser.add_argument("--audit-fd", type=int)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--owner-fd", type=int)
    parser.add_argument("--activate-fd", type=int)
    return parser


def _load_manifest(descriptor: int) -> TestCaidoProviderManifest:
    try:
        value = json.loads(_read_descriptor(descriptor, MAX_MANIFEST_BYTES).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TestCaidoProviderError("manifest_invalid") from None
    return TestCaidoProviderManifest.from_mapping(value)


def _verify_owner_descriptor(descriptor: int) -> None:
    try:
        info = os.fstat(descriptor)
        fcntl = importlib.import_module("fcntl")
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if not stat.S_ISFIFO(info.st_mode) or (flags & (os.O_WRONLY | os.O_RDWR)) != os.O_RDONLY:
            raise OSError
        os.set_inheritable(descriptor, False)
    except OSError:
        raise TestCaidoProviderError("owner_descriptor_invalid") from None


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.describe:
        if any(
            value is not None
            for value in (
                arguments.manifest_fd,
                arguments.listener_fd,
                arguments.audit_fd,
                arguments.ready_fd,
                arguments.owner_fd,
                arguments.activate_fd,
            )
        ):
            raise TestCaidoProviderError("describe_arguments_refused")
        print(json.dumps(provider_descriptor(), sort_keys=True, separators=(",", ":")))
        return 0
    if any(
        type(value) is not int
        for value in (
            arguments.manifest_fd,
            arguments.listener_fd,
            arguments.audit_fd,
            arguments.ready_fd,
            arguments.owner_fd,
            arguments.activate_fd,
        )
    ):
        raise TestCaidoProviderError("required_descriptor_missing")
    descriptors = (
        arguments.manifest_fd,
        arguments.listener_fd,
        arguments.audit_fd,
        arguments.ready_fd,
        arguments.owner_fd,
        arguments.activate_fd,
    )
    if len(set(descriptors)) != len(descriptors) or any(value < 3 for value in descriptors):
        raise TestCaidoProviderError("descriptor_alias_refused")
    _verify_owner_descriptor(arguments.owner_fd)
    _verify_owner_descriptor(arguments.activate_fd)
    manifest = _load_manifest(arguments.manifest_fd)
    audit = FileDescriptorTestCaidoAuditSink(arguments.audit_fd)
    adopt = getattr(socket, "fromfd", None)
    if not callable(adopt):
        raise TestCaidoProviderError("listener_adoption_unavailable")
    try:
        listener = adopt(arguments.listener_fd, socket.AF_INET, socket.SOCK_STREAM)
        os.close(arguments.listener_fd)
    except OSError:
        raise TestCaidoProviderError("listener_adoption_unknown") from None
    runtime = TestCaidoProtocolRuntime(manifest, audit)
    try:
        server = TestCaidoProtocolServer(runtime, listener)
    except Exception:
        listener.close()
        audit.close()
        raise
    stopped = threading.Event()

    # The controller keeps the write end of this one-way pipe.  An abrupt
    # controller exit closes it in the kernel and revokes the provider even
    # when no signal can be delivered by its former parent.
    def watch_owner() -> None:
        try:
            os.set_inheritable(arguments.owner_fd, False)
            os.read(arguments.owner_fd, 1)
        finally:
            stopped.set()
            os.close(arguments.owner_fd)

    owner_watch = threading.Thread(target=watch_owner, name="caido-owner", daemon=True)
    owner_watch.start()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, stop)
    try:
        _write_descriptor(
            arguments.ready_fd,
            {
                "schema_version": READY_SCHEMA,
                "attempt_id": manifest.binding.attempt_id,
                "provider_identity_ref": manifest.identity_ref,
                "listener_ref": manifest.binding.listener_ref,
                "provider_source_digest": manifest.provider_source_digest,
                "test_provider": True,
                "live_caido_proof": False,
                "production_eligible": False,
                "ready": True,
            },
        )
        # Readiness means the exact source and listener were adopted. It is
        # deliberately not permission to answer SDK requests. The controller
        # sends this one-use byte only after the durable V2 active check.
        activated = False
        while not stopped.is_set():
            readable, _, _ = select.select([arguments.activate_fd], [], [], 0.05)
            if readable:
                activated = os.read(arguments.activate_fd, 2) == b"\x01"
                break
        os.close(arguments.activate_fd)
        if activated and not stopped.is_set():
            server.serve_forever(stopped)
    finally:
        try:
            server.drain()
        finally:
            audit.close()
    return 0
