"""Paired provenance over in-memory setup only; no native account or credential calls."""

import hashlib
import io
import json
import threading
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import windows_file_access_admission as v1
from bluefire import windows_file_access_enrollment_setup as setup
from bluefire import windows_file_access_pair_admission as pair
from bluefire import windows_file_access_setup_child as child
from bluefire import windows_file_access_setup_process as process
from bluefire.file_access_contract import FileAccessContractError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_setup_lifecycle import (
    GENERATION,
    ISSUED,
    source_facts,
)
from tests_platform.test_windows_file_access_setup_lifecycle import (
    lifecycle as lifecycle,
)
from tests_platform.test_windows_file_access_setup_process import (
    clocks as clocks,
)
from tests_platform.test_windows_file_access_setup_process import (
    fake as fake,
)
from tests_platform.test_windows_file_access_setup_process import (
    frame,
    request,
    terminal,
)


def pair_source():
    source = source_facts()
    source["native_image"].update(
        worker_schema="bluefire.windows-file-worker-request.v2",
        read_schema="bluefire.windows-fixed-read-pair.v2",
    )
    source["capability"].update(
        schema_version="bluefire.windows-file-worker-capability.v2",
        worker_command="windows-file-baseline-worker",
        worker_schema="bluefire.windows-file-worker-request.v2",
        read_schema="bluefire.windows-fixed-read-pair.v2",
        action_id="private.windows.file_read_pair.v2",
        capability="windows_file_read_pair",
        max_data_opens=2,
        max_bytes_per_read=1048576,
        max_total_read_bytes=2097152,
        max_execution_ms=5000,
    )
    return source


def run_pair(backend, gate):
    return setup._run_setup_for(
        backend,
        pair_source(),
        backend.owner,
        gate,
        generation=GENERATION,
        issued=ISSUED,
        protocol=v1._PAIR_SETUP,
    )


@pytest.fixture
def paired(lifecycle):
    backend, gate = lifecycle
    result = run_pair(backend, gate)
    checked = object.__new__(pair.VerifiedWindowsPairSetup)
    object.__setattr__(checked, "_raw", backend.files[v1.ANCHOR_PATH])
    object.__setattr__(checked, "_receipt", backend.files[setup._RECEIPT_PATH])
    return backend, checked, result


def original_review(saved):
    context = pair.baseline_context(saved)
    body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": "baseline",
        "control_owner_id": saved["control_owner_id"],
        "control_digest": content_hash(saved),
        "context_digest": content_hash(context),
        "enrollment_digest": content_hash(saved["enrollment"]),
        "expires_at_ms": ISSUED + 8000,
        "effect": "Synthetic reviewed paired baseline",
    }
    review = {**body, "review_digest": content_hash(body)}
    submitted = {
        "submission_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "review": {"operation": "baseline", "control_owner_id": saved["control_owner_id"]},
        "review_digest": review["review_digest"],
        "reviewed_by": "synthetic-operator",
    }
    return {
        "submitted_request": submitted,
        "review": review,
        "review_context": context,
        "enrollment_digest": body["enrollment_digest"],
        "created_at_ms": ISSUED + 1,
    }


def test_pair_lifecycle_is_new_explicit_provenance_not_v1_upgrade(paired):
    backend, checked, result = paired
    row, receipt = pair.checked_provenance(checked)
    intent = json.loads(backend.files[setup._INTENT_PATH])
    assert row["schema_version"] == "bluefire.windows-file-access-enrollment.v2"
    assert intent["schema_version"] == "bluefire.windows-file-setup-intent.v2"
    assert receipt["schema_version"] == "bluefire.windows-file-setup-receipt.v2"
    assert result["schema_version"] == "bluefire.windows-file-local-setup-result.v2"
    assert result["context_available"] is result["settled"] is False
    assert row["expires_at_ms"] == ISSUED + 900000
    assert row["limits"] == {
        "max_reader_reads": 1,
        "max_owner_reads": 1,
        "max_data_opens": 2,
        "max_bytes_per_read": 1048576,
        "max_total_read_bytes": 2097152,
        "per_request_ms": 5000,
    }
    assert receipt["private_profile"]["allowed_actions"] == ["private.windows.file_read_pair.v2"]
    assert receipt["private_profile"]["capabilities"] == ["windows_file_read_pair"]
    assert row["host"]["runner_profile_id"] == "windows-file-pair-" + GENERATION
    expected_purpose = content_hash(
        {
            "schema_version": "bluefire.windows-file-reader-purpose.v2",
            "enrollment_id": row["enrollment_id"],
            "generation": GENERATION,
            "host": row["host"],
            "owner_sid": row["resource"]["owner_sid"],
            "reader_sid": row["resource"]["reader_sid"],
            "operation": "read_generated_pair",
        }
    )
    assert row["credential_reference"]["purpose_digest"] == backend.purpose == expected_purpose
    assert expected_purpose != v1._purpose(row)
    assert setup._load_pair_receipt(backend) == checked._receipt
    assert backend.credentials[0].wiped
    assert backend.events.index("publish:" + setup._INTENT_PATH) < backend.events.index("account")
    assert backend.events.index("publish:" + setup._RECEIPT_PATH) < backend.events.index(
        "publish:" + v1.ANCHOR_PATH
    )
    with pytest.raises(v1.wire.NativeWireError):
        setup._load_receipt(backend)
    with pytest.raises(v1.wire.NativeWireError):
        v1._document(checked._raw)
    with pytest.raises(v1.wire.NativeWireError):
        v1.checked_provenance(checked)
    with pytest.raises(TypeError):
        pair.VerifiedWindowsPairSetup()


def test_preparation_preserves_review_job_full_pair_and_original_time(paired):
    _, checked, _ = paired
    saved = pair.import_document(checked, now_ms=ISSUED + 1)
    original = original_review(saved)
    job = "job-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
    prepared = pair.build_preparation(job, original, saved, issued_at_ms=ISSUED + 2)
    assert prepared["schema_version"] == pair.PREPARATION_SCHEMA
    assert prepared["expires_at_ms"] == ISSUED + 5002
    manifest = prepared["original"]["manifest"]
    assert manifest["step_id"] == "read_generated_pair"
    assert manifest["action_id"] == "private.windows.file_read_pair.v2"
    assert manifest["approval"]["approved_by"] == "synthetic-operator"
    assert (
        manifest["params"]["windows_file_read_request"]["schema_version"]
        == "bluefire.windows-file-worker-operation.v2"
    )
    from bluefire.windows_file_access_native_wire import validate_pair_original_reservation

    validate_pair_original_reservation(
        prepared["original"], expected_binding=prepared["expected_binding"]
    )
    assert pair.validate_preparation(prepared, original, saved, now_ms=ISSUED + 3) == prepared
    assert pair.validate_retained_preparation(prepared, original, saved) == prepared
    with pytest.raises(v1.ProductStoreError):
        pair.validate_preparation(prepared, original, saved, now_ms=prepared["expires_at_ms"])
    with pytest.raises(v1.wire.NativeWireError):
        v1.validate_import(saved)
    with pytest.raises(v1.wire.NativeWireError):
        pair.build_preparation("job-" + "0" * 32, original, saved, issued_at_ms=ISSUED + 2)


@pytest.mark.parametrize(
    "field",
    [
        "schema",
        "worker",
        "read",
        "reference",
        "purpose",
        "limits",
        "bool_limit",
        "extra",
        "full_id",
    ],
)
def test_pair_closed_record_rejects_mixed_versions_and_geometry(paired, field):
    _, checked, _ = paired
    row = json.loads(checked._raw)
    if field == "schema":
        row["schema_version"] = v1.SCHEMA
    elif field == "worker":
        row["native_image"]["worker_schema"] = v1.wire.REQUEST_SCHEMA
    elif field == "read":
        row["native_image"]["read_schema"] = v1.wire.PROOF_SCHEMA
    elif field == "reference":
        row["credential_reference"]["schema_version"] = "bluefire.windows-file-reader-reference.v1"
    elif field == "purpose":
        row["credential_reference"]["purpose_digest"] = v1._purpose(row)
    elif field == "limits":
        row["limits"] = v1._READER_SETUP.limits()
    elif field == "bool_limit":
        row["limits"]["max_owner_reads"] = True
    elif field == "extra":
        row["verified"] = True
    else:
        row["resource"]["file_identity"]["file_id"] = "f" * 16
    with pytest.raises(v1.wire.NativeWireError):
        pair._document(row)


@pytest.mark.parametrize(
    "field", ["schema", "command", "action", "capability", "limit", "bool", "extra"]
)
def test_pair_capability_cannot_be_inferred_from_v1_or_claimed_limits(field):
    value = pair_source()["capability"]
    if field == "schema":
        value["schema_version"] = "bluefire.windows-file-worker-capability.v1"
    elif field == "command":
        value["worker_command"] = "windows-file-worker"
    elif field == "action":
        value["action_id"] = v1.wire.ACTION
    elif field == "capability":
        value["capability"] = v1.wire.CAPABILITY
    elif field == "limit":
        value["max_execution_ms"] = 5001
    elif field == "bool":
        value["max_data_opens"] = True
    else:
        value["authenticated"] = True
    with pytest.raises(v1.wire.NativeWireError):
        v1._capability_for(canonical_json_bytes(value), "0.1.0", v1._PAIR_SETUP)


def test_copied_protocol_descriptor_is_not_a_third_supported_version():
    rogue = replace(v1._PAIR_SETUP)
    with pytest.raises(v1.wire.NativeWireError):
        v1._private_profile_for(GENERATION, rogue)
    with pytest.raises(v1.wire.NativeWireError):
        rogue.schema("access-enrollment")


@pytest.mark.parametrize("schema", [v1.SCHEMA, "bluefire.windows-file-access-enrollment.v3", None])
def test_pair_parser_has_no_fallback(paired, schema):
    _, checked, _ = paired
    row = json.loads(checked._raw)
    row["schema_version"] = schema
    with pytest.raises(FileAccessContractError):
        pair.parse_windows_pair_enrollment_candidate(row, now_ms=ISSUED + 1)


@pytest.mark.parametrize(
    "fault", ["account", "protect", "publish:" + setup._RECEIPT_PATH, "cleanup"]
)
def test_pair_partial_effects_remain_unknown_without_replay(lifecycle, fault):
    backend, gate = lifecycle
    backend.fail = fault
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        run_pair(backend, gate)
    assert caught.value.bootstrap_mutated and caught.value.intent_persisted
    assert all(item.wiped for item in backend.credentials)
    assert backend.events.count("account") <= 1


@pytest.mark.parametrize("handoff", [True, False])
@pytest.mark.parametrize("main", [False, True])
def test_pair_child_requires_os_handoff_and_fixed_request_version(
    clocks, monkeypatch, handoff, main
):
    row = request()
    row["schema_version"] = "bluefire.windows-file-setup-child-request.v2"
    output, calls = io.BytesIO(), []

    def admit(value):
        if not handoff:
            raise RuntimeError("synthetic missing Job/parent/pipe proof")
        calls.append("handoff")
        return nullcontext()

    def derive(value, protocol):
        assert protocol is v1._PAIR_SETUP and value == row
        calls.append("derive")
        return {
            **terminal()["result"],
            "schema_version": "bluefire.windows-file-local-setup-result.v2",
        }

    monkeypatch.setattr(child.binding, "require_child_handoff", admit)
    monkeypatch.setattr(child, "_derive_for", derive)
    if main:
        monkeypatch.setattr(
            child,
            "sys",
            SimpleNamespace(
                platform="win32",
                flags=SimpleNamespace(isolated=1),
                argv=[child.__file__, "--pair-baseline-v2"],
                stdin=SimpleNamespace(buffer=io.BytesIO(frame(row))),
                stdout=SimpleNamespace(buffer=output),
            ),
        )
        monkeypatch.setattr(child, "__package__", "")
        code = child.main()
    else:
        code = child._run_for(io.BytesIO(frame(row)), output, v1._PAIR_SETUP)
    assert code == (0 if handoff else 4)
    assert calls == (["handoff", "derive"] if handoff else [])
    assert (
        json.loads(output.getvalue()[4:])["schema_version"]
        == "bluefire.windows-file-setup-child-result.v2"
    )
    with pytest.raises(v1.wire.NativeWireError):
        child._request(canonical_json_bytes(row))


def test_pair_supervisor_uses_same_cleanup_and_rejects_v1_terminal(fake):
    native, _ = fake
    outcome = process.run_pair_setup_process(
        "existing-source", cancellation_event=threading.Event()
    )
    assert outcome.terminal is None and outcome.process_cleanup == "verified"
    assert outcome.dispatch == "unknown" and outcome.issue
    assert native._handle.closed


@pytest.mark.parametrize("cleanup", [True, False])
def test_pair_supervisor_requires_selected_terminal_and_complete_cleanup(fake, cleanup):
    native, owners = fake
    expected = terminal()
    expected["schema_version"] = "bluefire.windows-file-setup-child-result.v2"
    expected["result"]["schema_version"] = "bluefire.windows-file-local-setup-result.v2"
    native.stdout = io.BytesIO(frame(expected))
    native._handle.fail = not cleanup
    outcome = process.run_pair_setup_process(
        "existing-source", cancellation_event=threading.Event()
    )
    assert outcome.terminal == (expected if cleanup else None) and outcome.settled is False
    assert owners[0].protocol is v1._PAIR_SETUP and owners[0].terminal == expected
    assert outcome.process_cleanup == ("verified" if cleanup else "unknown")
    assert (outcome.cleanup_owner is None) is cleanup


@pytest.mark.parametrize("old_capability", [False, True])
def test_pair_setup_queries_actual_pinned_image_fixed_capability(
    lifecycle, monkeypatch, old_capability
):
    from bluefire import runner_bootstrap
    from bluefire.runner_lifecycle import ManagedRunnerLifecycle

    backend, gate = lifecycle
    payload = b"synthetic image only, never executed"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    source = pair_source()
    source["transport"]["runner_binary_digest"] = digest
    image = Path(r"C:\synthetic\bluefire-runner.exe")
    backend.files[str(image)], backend.held = payload, [777]
    chunks = [payload, b""]
    monkeypatch.setattr(setup.os, "read", lambda descriptor, size: chunks.pop(0))
    controller = object.__new__(ManagedRunnerLifecycle)
    controller._load_active_enrollment = lambda: object()
    controller._load_bootstrap = lambda enrollment: SimpleNamespace(
        source="packaged",
        managed_binary=True,
        binary_digest=digest,
        binary_path=image,
        runner_version="0.1.0",
    )
    channel_calls = []

    def channel():
        channel_calls.append(True)
        return dict(source["transport"])

    controller.client_for_profile = lambda profile: (
        SimpleNamespace(transport_identity=channel),
        None,
    )
    monkeypatch.setattr(
        runner_bootstrap,
        "load_runner_manifest",
        lambda **kwargs: SimpleNamespace(
            sha256=digest[7:],
            size=len(payload),
            runner_version="0.1.0",
        ),
    )
    queried = []

    def query(command, **kwargs):
        assert command == [str(image), "windows-file-baseline-worker-capability"]
        assert kwargs["shell"] is False and kwargs["stdin"] == setup.subprocess.DEVNULL
        queried.append(True)
        record = source_facts()["capability"] if old_capability else source["capability"]
        kwargs["stdout"].write(canonical_json_bytes(record) + b"\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", query)
    gate.deadline = 105.0
    monkeypatch.setattr(setup.time, "monotonic", lambda: 100.0)
    if old_capability:
        with pytest.raises(v1.wire.NativeWireError):
            setup._source_for(controller, "existing-source", backend, gate, v1._PAIR_SETUP)
    else:
        result = setup._source_for(controller, "existing-source", backend, gate, v1._PAIR_SETUP)
        assert result["native_image"]["worker_schema"] == "bluefire.windows-file-worker-request.v2"
        assert result["native_image"]["sha256"] == digest and len(channel_calls) == 2
    assert queried == [True] and "account" not in backend.events
    assert setup._INTENT_PATH not in backend.files


def test_pair_cli_is_fixed_and_rejects_overrides_before_service(monkeypatch):
    calls = []
    monkeypatch.setattr(
        process,
        "setup_windows_file_baseline_local",
        lambda profile: calls.append(profile) or {"publication": "complete"},
    )
    args = SimpleNamespace(
        command="runner",
        runner_command="windows-file-baseline-setup",
        confirm_create_local_reader=True,
        config=None,
        runs_dir=None,
        profile="existing-source",
    )
    assert cli._execute(args) == {"publication": "complete"}
    assert calls == ["existing-source"]
    args.config = "caller-config"
    with pytest.raises(ValueError):
        cli._execute(args)
    assert calls == ["existing-source"]
