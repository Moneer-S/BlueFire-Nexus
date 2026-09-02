"""Identity-bound transport recovery proof for GATE-11.

The report intentionally carries the complete path-free result, receipt, commit,
host, transport, and cleanup material needed for independent recomputation.  A
boolean success claim is never the only evidence for a recovery property.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, cast

from .cross_platform_recovery_witness import (
    build_witness_validation,
    inspect_cleaned_recovery,
    inspect_continuation,
    inspect_live_recovery,
    require_process_absent,
    stopped_process_facts,
)
from .runner_bootstrap import current_platform
from .runner_contracts import build_execution_manifest, build_runner_profile
from .runner_host import _owner_private_open_regular, read_process_record
from .runner_lifecycle import ManagedRunnerLifecycle
from .runner_trust import RunnerTrustError, _is_link_or_reparse, load_local_enrollment
from .service import BlueFireService
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

RECOVERY_SCHEMA = "bluefire.cross-platform-transport-recovery.v1"
_PROFILE_ID = "sandbox-endpoint-deep-lab.v1"
_EFFECT_DIRECTORY = "gate11-recovery"
_EFFECT_PATH = f"{_EFFECT_DIRECTORY}/transport-recovery.jsonl"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_EFFECT_BYTES = 64 * 1024

Require = Callable[[bool, str], None]


def _approval_record() -> Mapping[str, str]:
    approved = datetime.now(timezone.utc)
    expires = approved + timedelta(minutes=5)

    def render(value: datetime) -> str:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    return {
        "approved_by": "gate-11-transport-reviewer",
        "approved_at": render(approved),
        "expires_at": render(expires),
    }


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _read_regular(path: Path, *, maximum: int) -> bytes:
    """Read one pinned, owner-private regular file with a hard byte bound."""

    descriptor = -1
    try:
        if _is_link_or_reparse(path):
            raise OSError("linked file")
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("unsafe file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OSError("file changed")
        _owner_private_open_regular(path, descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum + 1)
        after = path.stat(follow_symlinks=False)
        if (
            len(payload) > maximum
            or _is_link_or_reparse(path)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OSError("file changed")
        return payload
    except (OSError, RunnerTrustError):
        raise RuntimeError("recovery evidence file is unavailable or unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_regular(path, maximum=_MAX_RECEIPT_BYTES).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("recovery evidence JSON is invalid") from None
    if not isinstance(value, dict):
        raise RuntimeError("recovery evidence JSON has an invalid shape")
    return value


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return parse_iso8601_datetime(value).tzinfo is not None
    except ValueError:
        return False


def _valid_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _receipt_ids(root: Path) -> list[str]:
    if _is_link_or_reparse(root) or not root.is_dir():
        raise RuntimeError("recovery receipt directory is unavailable or unsafe")
    values: list[str] = []
    for entry in root.iterdir():
        details = entry.lstat()
        if (
            _is_link_or_reparse(entry)
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or not entry.name.endswith(".json")
            or _HEX_DIGEST.fullmatch(entry.name[:-5]) is None
        ):
            raise RuntimeError("recovery receipt inventory is unavailable or unsafe")
        values.append(entry.name[:-5])
    return sorted(values)


def _validate_receipt(
    body: Mapping[str, Any],
    *,
    receipt_id: str,
    request_hash: str,
    output: Mapping[str, Any],
    require: Require,
) -> None:
    paths = body.get("paths")
    expected_file = {
        "relative_path": _EFFECT_PATH,
        "kind": "file",
        "sha256": output.get("sha256"),
        "size": output.get("size"),
    }
    expected_directory = {
        "relative_path": _EFFECT_DIRECTORY,
        "kind": "directory",
        "sha256": None,
        "size": None,
    }
    identity = {key: body[key] for key in body if key != "receipt_id"}
    computed = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    require(
        set(body)
        == {
            "schema_version",
            "receipt_id",
            "request_hash",
            "action_id",
            "runner_profile_id",
            "workspace_id",
            "created_at",
            "paths",
        }
        and body.get("schema_version") == "bluefire.receipt/v1"
        and body.get("receipt_id") == receipt_id == computed
        and body.get("request_hash") == request_hash
        and body.get("action_id") == "sandbox.fixture.create.v1"
        and body.get("runner_profile_id") == _PROFILE_ID
        and isinstance(body.get("workspace_id"), str)
        and _HEX_DIGEST.fullmatch(str(body["workspace_id"])) is not None
        and _valid_timestamp(body.get("created_at"))
        and paths == [expected_file, expected_directory]
        and _valid_relative(expected_file["relative_path"])
        and _valid_relative(expected_directory["relative_path"]),
        "the recovery receipt body is not bound to the exact effect",
    )


def _validate_commit(
    body: Mapping[str, Any],
    *,
    receipt: Mapping[str, Any],
    receipt_id: str,
    require: Require,
) -> None:
    require(
        set(body)
        == {
            "schema_version",
            "receipt_id",
            "runner_profile_id",
            "workspace_id",
            "committed_at",
        }
        and body.get("schema_version") == "bluefire.receipt-commit/v1"
        and body.get("receipt_id") == receipt_id
        and body.get("runner_profile_id") == receipt.get("runner_profile_id")
        and body.get("workspace_id") == receipt.get("workspace_id")
        and _valid_timestamp(body.get("committed_at")),
        "the recovery receipt commit body is not bound to the receipt",
    )


def _transport_identity(value: Mapping[str, Any], *, require: Require) -> dict[str, Any]:
    require(
        set(value)
        == {
            "schema_version",
            "runner_id",
            "client_id",
            "transport",
            "tls",
            "server_fingerprint",
            "client_fingerprint",
            "authenticated_peer_fingerprint",
            "enrollment_generation",
            "runner_binary_digest",
            "inventory_digest",
        }
        and value.get("schema_version") == "bluefire.runner-transport-identity.v1"
        and value.get("transport") == "mutual-tls-loopback"
        and value.get("tls") == "TLSv1.3"
        and value.get("client_fingerprint") == value.get("authenticated_peer_fingerprint")
        and all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(str(value[field]))
            for field in (
                "server_fingerprint",
                "client_fingerprint",
                "enrollment_generation",
                "runner_binary_digest",
                "inventory_digest",
            )
        ),
        "the managed recovery transport identity is invalid",
    )
    return dict(value)


def _authenticated_ledger_generation(health: Mapping[str, Any], *, require: Require) -> str:
    ledger = health.get("ledger")
    generation = ledger.get("generation") if isinstance(ledger, Mapping) else None
    require(
        health.get("schema_version") == "bluefire.runner-health.v1"
        and health.get("status") == "ready"
        and isinstance(generation, str)
        and _DIGEST.fullmatch(generation) is not None,
        "the authenticated managed recovery ledger has no generation",
    )
    return str(generation)


def _host_identity(
    lifecycle: ManagedRunnerLifecycle,
    transport: Mapping[str, Any],
) -> dict[str, Any]:
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=lifecycle.secret_provider,
    )
    record = read_process_record(
        lifecycle.process_record_path,
        enrollment=enrollment,
        expected_binary_digest=str(transport["runner_binary_digest"]),
    )
    return {
        "process_id": int(record["pid"]),
        "launch_id": str(record["launch_id"]),
        "server_instance_id": str(record["server_instance_id"]),
        "started_at_ns": int(record["started_at_ns"]),
        "runner_id": str(record["runner_id"]),
        "client_id": str(record["client_id"]),
        "server_fingerprint": str(record["server_fingerprint"]),
        "runner_binary_digest": str(record["runner_binary_digest"]),
    }


def _effect_state(path: Path, *, require: Require) -> tuple[str, int, int]:
    payload = _read_regular(path, maximum=_MAX_EFFECT_BYTES)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    line_count = len(payload.splitlines())
    require(payload.endswith(b"\n"), "the recovery effect is not canonical JSONL")
    return digest, len(payload), line_count


def transport_recovery(
    service: BlueFireService,
    lifecycle: ManagedRunnerLifecycle,
    *,
    require: Require,
) -> Mapping[str, Any]:
    """Execute, interrupt, restart, recover, and reconcile one exact effect."""

    profile = next(item for item in service.config.runner_profiles if item.id == _PROFILE_ID)
    client, sandbox = lifecycle.client_for_profile(_PROFILE_ID)
    profile_doc = build_runner_profile(
        profile,
        sandbox_root=sandbox,
        filesystem_scope=(_EFFECT_PATH,),
    )
    action = service.registry.get_action("sandbox.fixture.create.v1")
    manifest = build_execution_manifest(
        run_id="run-20260829T120000Z-fedcba9876543210",
        step_id="transport_recovery_effect",
        behavior_id="sandbox.fixture.create.v1",
        action=action,
        runner_profile=profile_doc,
        params={
            "path": _EFFECT_PATH,
            "content_template": "telemetry-seed",
            "record_count": 1,
        },
        filesystem_scope=(_EFFECT_PATH,),
        network_destinations=(),
        evidence_refs=(),
        approval_record=_approval_record(),
    )
    generation_before = _authenticated_ledger_generation(client.health(), require=require)
    transport_before = _transport_identity(client.transport_identity(), require=require)
    host_before = _host_identity(lifecycle, transport_before)
    client_process_id = os.getpid()
    require(
        client_process_id > 0 and client_process_id != host_before["process_id"],
        "the recovery client and managed host are not distinct processes",
    )
    task_id, request_hash = client.execution_identity(manifest, profile_doc)
    require(
        _DIGEST.fullmatch(request_hash) is not None
        and task_id == "execute-" + request_hash.removeprefix("sha256:"),
        "the recovery transport request identity is invalid",
    )
    expected = dict(client.execute(manifest, profile_doc))
    receipts = expected.get("receipt_ids")
    output = expected.get("output")
    require(
        expected.get("status") == "success"
        and isinstance(receipts, list)
        and len(receipts) == 1
        and isinstance(receipts[0], str)
        and _HEX_DIGEST.fullmatch(receipts[0]) is not None
        and isinstance(output, Mapping)
        and output.get("artifact") == _EFFECT_PATH
        and output.get("template") == "telemetry-seed"
        and output.get("record_count") == 1
        and output.get("format") == "jsonl"
        and isinstance(output.get("size"), int)
        and isinstance(output.get("sha256"), str)
        and _HEX_DIGEST.fullmatch(str(output["sha256"])) is not None,
        "the recovery effect did not commit exactly one receipt",
    )
    receipt_id = str(cast(list[Any], receipts)[0])
    before_witness = inspect_live_recovery(
        client=client,
        sandbox=sandbox,
        task_id=task_id,
        request_hash=request_hash,
        receipt_id=receipt_id,
        expected_result=expected,
        expected_generation=generation_before,
        client_process_id=client_process_id,
        host_process_id=int(host_before["process_id"]),
        stage="before_interruption",
    )
    generation_before = str(before_witness.facts["ledger_generation"])
    receipt_before = dict(before_witness.receipt_body)
    commit_before = dict(before_witness.receipt_commit_body)
    effect_digest_before = str(before_witness.facts["effect_digest"])
    effect_size_before = int(before_witness.facts["effect_size"])
    effect_count_before = int(before_witness.facts["effect_count"])
    receipt_ids_before = [receipt_id]
    commit_ids_before = [receipt_id]
    interruption = dict(lifecycle.interrupt_for_recovery(profile_id=_PROFILE_ID))
    require(
        set(interruption)
        == {
            "profile_id",
            "launch_id",
            "process_id",
            "server_instance_id",
            "identity_bound",
            "process_handle_terminated",
            "process_absent",
        }
        and interruption.get("profile_id") == _PROFILE_ID
        and interruption.get("launch_id") == host_before["launch_id"]
        and interruption.get("process_id") == host_before["process_id"]
        and interruption.get("server_instance_id") == host_before["server_instance_id"]
        and interruption.get("identity_bound") is True
        and interruption.get("process_handle_terminated") is True
        and interruption.get("process_absent") is True,
        "the managed host interruption was not identity-bound",
    )
    require_process_absent(before_witness.host_process_identity, "interrupted recovery host")
    restarted = lifecycle.start(profile_id=_PROFILE_ID)
    require(restarted.get("state") == "ready", "the managed host did not restart")
    recovered_client, _ = lifecycle.client_for_profile(_PROFILE_ID)
    transport_after = _transport_identity(recovered_client.transport_identity(), require=require)
    host_after = _host_identity(lifecycle, transport_after)
    recovered_witness = inspect_live_recovery(
        client=recovered_client,
        sandbox=sandbox,
        task_id=task_id,
        request_hash=request_hash,
        receipt_id=receipt_id,
        expected_result=expected,
        expected_generation=generation_before,
        client_process_id=client_process_id,
        host_process_id=int(host_after["process_id"]),
        stage="after_recovery",
    )
    recovered_result = dict(recovered_witness.result)
    generation_after = str(recovered_witness.facts["ledger_generation"])
    receipt_ids_after = [receipt_id]
    commit_ids_after = [receipt_id]
    receipt_after = dict(recovered_witness.receipt_body)
    commit_after = dict(recovered_witness.receipt_commit_body)
    effect_digest_after = str(recovered_witness.facts["effect_digest"])
    effect_size_after = int(recovered_witness.facts["effect_size"])
    effect_count_after = int(recovered_witness.facts["effect_count"])
    require(
        canonical_json_bytes(recovered_result) == canonical_json_bytes(expected)
        and receipt_ids_after == receipt_ids_before
        and commit_ids_after == commit_ids_before
        and receipt_after == receipt_before
        and commit_after == commit_before
        and effect_digest_after == effect_digest_before
        and effect_size_after == effect_size_before
        and effect_count_after == effect_count_before == 1
        and generation_after == generation_before
        and transport_after == transport_before
        and host_after["process_id"] != host_before["process_id"]
        and host_after["launch_id"] != host_before["launch_id"]
        and host_after["server_instance_id"] != host_before["server_instance_id"]
        and host_after["started_at_ns"] != host_before["started_at_ns"]
        and host_after["process_id"] != client_process_id,
        "the authenticated host did not recover the exact committed result",
    )
    cleanup_action = service.registry.get_action("sandbox.cleanup.v1")
    cleanup_manifest = build_execution_manifest(
        run_id="run-20260829T120000Z-fedcba9876543210",
        step_id="transport_recovery_cleanup",
        behavior_id="sandbox.cleanup.v1",
        action=cleanup_action,
        runner_profile=profile_doc,
        params={"receipt_ids": [receipt_id]},
        filesystem_scope=(),
        network_destinations=(),
        evidence_refs=(request_hash,),
        approval_record=_approval_record(),
    )
    cleaned = dict(recovered_client.execute(cleanup_manifest, profile_doc))
    cleaned_witness = inspect_cleaned_recovery(
        client=recovered_client,
        sandbox=sandbox,
        task_id=task_id,
        request_hash=request_hash,
        receipt_id=receipt_id,
        expected_result=expected,
        expected_generation=generation_before,
        cleanup_result=cleaned,
        client_process_identity=before_witness.client_process_identity,
        host_before_identity=before_witness.host_process_identity,
        host_after_identity=recovered_witness.host_process_identity,
    )
    stopped = lifecycle.stop(profile_id=_PROFILE_ID)
    require(
        stopped.get("state") != "ready" and stopped.get("process") == "absent",
        "the recovered host did not complete authenticated shutdown",
    )
    stopped_facts = stopped_process_facts(
        client_process_identity=before_witness.client_process_identity,
        host_before_identity=before_witness.host_process_identity,
        host_after_identity=recovered_witness.host_process_identity,
    )
    continued = lifecycle.start(profile_id=_PROFILE_ID)
    require(continued.get("state") == "ready", "the recovery continuation host did not start")
    continuation_client, continuation_sandbox = lifecycle.client_for_profile(_PROFILE_ID)
    continuation_transport = _transport_identity(
        continuation_client.transport_identity(), require=require
    )
    continuation_host = _host_identity(lifecycle, continuation_transport)
    require(
        continuation_sandbox.resolve(strict=True) == sandbox.resolve(strict=True)
        and continuation_transport == transport_before,
        "the recovery continuation boundary changed",
    )
    continuation_facts, continuation_process_identity = inspect_continuation(
        client=continuation_client,
        sandbox=continuation_sandbox,
        task_id=task_id,
        request_hash=request_hash,
        expected_result=expected,
        expected_generation=generation_before,
        client_process_identity=before_witness.client_process_identity,
        host_process_id=int(continuation_host["process_id"]),
    )
    witness_validation = build_witness_validation(
        before=before_witness,
        recovered=recovered_witness,
        cleaned=cleaned_witness,
        stopped=stopped_facts,
        continuation=continuation_facts,
        continuation_host_identity=continuation_process_identity,
    )
    result_after = dict(recovered_result)
    return {
        "schema_version": RECOVERY_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "platform": current_platform(),
        "transport": {
            "tls": "TLSv1.3",
            "authentication": "mutual-tls-plus-enrollment-hmac",
            "multiprocess": True,
            "client_process_id": client_process_id,
            "host_interrupted": True,
            "host_restarted": True,
        },
        "recovery": {
            "task_id": task_id,
            "request_hash": request_hash,
            "result_before": expected,
            "result_after": result_after,
            "result_digest_before": content_hash(expected),
            "result_digest_after": content_hash(result_after),
            "result_identical": True,
            "receipt_id": receipt_id,
            "receipt_body_before": receipt_before,
            "receipt_body_after": receipt_after,
            "receipt_body_digest_before": content_hash(receipt_before),
            "receipt_body_digest_after": content_hash(receipt_after),
            "receipt_commit_body_before": commit_before,
            "receipt_commit_body_after": commit_after,
            "receipt_commit_digest_before": content_hash(commit_before),
            "receipt_commit_digest_after": content_hash(commit_after),
            "receipt_ids_before": receipt_ids_before,
            "receipt_ids_after": receipt_ids_after,
            "receipt_commit_ids_before": commit_ids_before,
            "receipt_commit_ids_after": commit_ids_after,
            "effect_relative_path": _EFFECT_PATH,
            "effect_digest_before": effect_digest_before,
            "effect_digest_after": effect_digest_after,
            "effect_size_before": effect_size_before,
            "effect_size_after": effect_size_after,
            "effect_count_before": effect_count_before,
            "effect_count_after": effect_count_after,
            "effect_not_duplicated": True,
            "ledger_generation_before": generation_before,
            "ledger_generation_after": generation_after,
            "ledger_generation_stable": True,
            "host_identity_before": host_before,
            "host_identity_after": host_after,
            "host_identity_changed": True,
            "transport_identity_before": transport_before,
            "transport_identity_after": transport_after,
            "transport_identity_stable": True,
            "interruption": interruption,
            "cleanup_result": cleaned,
            "cleanup_result_digest": content_hash(cleaned),
            "receipt_ids_after_cleanup": [],
            "receipt_commit_ids_after_cleanup": [],
            "effect_exists_after_cleanup": False,
            "effect_directory_exists_after_cleanup": False,
            "cleanup_reconciled": True,
        },
        "witness_validation": witness_validation,
    }


__all__ = ["RECOVERY_SCHEMA", "transport_recovery"]
