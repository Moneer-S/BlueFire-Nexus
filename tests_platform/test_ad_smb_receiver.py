"""Real SQLite reservations/private results; fake trust/child, no listener or AD calls."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest

from bluefire import ad_smb_receiver as receiver
from bluefire import runner_transport as transport
from bluefire.ad_smb_acl import plan_hardening
from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.ad_smb_receiver_results import (
    native_generation,
    result_record,
    stored_result,
)
from bluefire.ad_smb_worker_process import WorkerOutcome
from bluefire.ad_smb_worker_wire import prepare_packet
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_acl import fixture as acl_fixture
from tests_platform.test_ad_smb_channel import enrollment
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_native_results import fixture as native_fixture
from tests_platform.test_ad_smb_worker_wire import fixture, rebind_context, terminal_row


def original(phase="inspect", index=0, serial=1):
    old, channel = fixture(phase, index)
    row = channel.to_dict()
    row["runner_id"] = old["profile"]["runner_id"]
    channel = AdSmbHostChannel.from_mapping(
        AdSmbScope.from_mapping(old["manifest"]["params"]["ad_smb_request"]["scope"]), row
    )
    host = {
        **old["transport_identity"],
        "channel_digest": channel.digest,
        "native_generation": native_generation(channel),
    }
    changes = dict(host=host, operation_job_id=f"job-{serial:032x}")
    if phase in {"harden", "retest", "rollback"}:
        scope, before, after = acl_fixture()
        changes["change"] = plan_hardening(scope, before, after).to_dict()
    if phase == "audit":
        changes["requested_at"] = (NOW + timedelta(seconds=1)).isoformat()
    value = rebind_context(old, **changes)
    request = value["manifest"]["params"]["ad_smb_request"]
    # request_id depends on the operation/index, so regenerate it before seal.
    import hashlib

    request["request_id"] = hashlib.sha256(
        f"{request['operation_job_id']}:{index}".encode()
    ).hexdigest()[:32]
    value = rebind_context(value)
    value["transport_identity"] = host
    return value, channel


def request(value, nonce=1):
    return {
        "operation": "execute",
        "profile_id": value["profile"]["profile_id"],
        "task_id": value["task_id"],
        "request_hash": value["transport_request_hash"],
        "nonce": f"{nonce:064x}",
        "payload": {"manifest": value["manifest"], "profile": value["profile"]},
    }


@pytest.fixture
def server(tmp_path, monkeypatch):
    old, channel = original()
    value = object.__new__(receiver.AdSmbReceiver)
    value.channel = channel
    value.instance_id = "1" * 32
    value.max_frame_bytes = transport.DEFAULT_MAX_FRAME_BYTES
    value.max_ledger_rows = 32
    value.max_terminal_rows = 16
    value.control_reserve_rows = 4
    value.control_reserve_bytes = 4 * value.max_frame_bytes
    value.max_ledger_bytes = 128 * 1024 * 1024
    value.terminal_retention_ns = 10**18
    value._accepting_execute = True
    value._dispatch_state_lock = threading.Lock()
    value._task_cancellations_lock = threading.Lock()
    value._task_cancellations = {}
    value.result_root = tmp_path / "results"
    value.result_root.mkdir(mode=0o700)
    value._runner_binary = Path("C:/fixed/runner.exe")
    database = sqlite3.connect(tmp_path / "receiver.sqlite3", check_same_thread=False)
    database.row_factory = sqlite3.Row
    database.execute(transport._TRANSPORT_TASKS_SQL)
    database.execute(transport._TRANSPORT_TASKS_NONCE_INDEX_SQL)
    database.commit()
    lock = threading.RLock()

    @contextmanager
    def connection(*, write=False):
        with lock:
            yield database

    @contextmanager
    def binary():
        yield channel.to_dict()["runner_binary_digest"]

    value._database = connection
    value._verified_runner_binary_guard = binary
    value._verified_runner_binary_digest = lambda: value.channel.to_dict()["runner_binary_digest"]
    value._active_enrollment = lambda: enrollment(value.channel)
    monkeypatch.setattr(receiver, "_now", lambda: NOW + timedelta(seconds=2))
    yield value
    assert not value._task_cancellations
    database.close()


def binding(server):
    return transport._enrollment_binding(enrollment(server.channel), pin("9"))


def reserve(server, value, nonce=1):
    submitted = request(value, nonce)
    server._begin_request(submitted, binding(server))
    return submitted


def packet(value, channel):
    read = channel.to_dict()["role"] == "client"
    return prepare_packet(
        value,
        channel,
        challenge="f" * 64,
        credential_binding_digest=pin("9") if read else None,
        expected_upn_sha256=pin("b") if read else None,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(seconds=2),
    )


def record(value, channel, *, error=True):
    public = packet(value, channel)
    terminal = terminal_row(public)
    if not error:
        terminal["result"] = {"synthetic_only": True}
    return result_record(
        public,
        terminal,
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue="native_error" if error else None,
    )


def test_default_public_receiver_execute_is_still_unavailable(server):
    assert server.ad_smb_execution_available is False
    assert (
        receiver.AdSmbReceiver._validated_request is receiver.EnrolledAdSmbServer._validated_request
    )


def test_concurrent_different_hashes_cannot_reserve_same_slot(server):
    one, _ = original(serial=1)
    two, _ = original(serial=2)
    barrier = threading.Barrier(2)

    def claim(item):
        value, nonce = item
        barrier.wait()
        try:
            reserve(server, value, nonce)
            return "reserved"
        except transport._RequestRefusal as error:
            return error.code

    with ThreadPoolExecutor(2) as pool:
        result = list(pool.map(claim, [(one, 1), (two, 2)]))
    assert sorted(result) == ["request_invalid", "reserved"]
    with server._database() as database:
        assert database.execute("SELECT count(*) FROM transport_tasks").fetchone()[0] == 1


def test_six_read_reservations_are_durable_and_seventh_concurrent_attempts_refused(server):
    for slot, (phase, index) in enumerate(receiver._READS):
        value, channel = original(phase, index, slot + 1)
        server.channel = channel
        reserve(server, value, slot + 1)
        server._fail_request(value["task_id"], "runner_failure")
    with ThreadPoolExecutor(2) as pool:

        def overflow(serial):
            value, _ = original("retest", 2, serial)
            with pytest.raises(transport._RequestRefusal):
                reserve(server, value, serial)

        list(pool.map(overflow, [7, 8]))
    with server._database() as database:
        assert database.execute("SELECT count(*) FROM transport_tasks").fetchone()[0] == 6


def test_ordinary_noop_hook_preserves_replay_and_control_semantics(server):
    server._validate_execute_reservation = lambda connection, request: transport.AuthenticatedRunnerServer._validate_execute_reservation(
        server, connection, request
    )
    value, _ = original()
    reserved = reserve(server, value)
    with pytest.raises(transport._RequestRefusal) as replay:
        server._begin_request(reserved, binding(server))
    assert replay.value.code == "replay_detected"
    other = dict(reserved, nonce="2" * 64)
    with pytest.raises(transport._RequestRefusal) as duplicate:
        server._begin_request(other, binding(server))
    assert duplicate.value.code == "duplicate_request"
    control = {
        **other,
        "operation": "health",
        "task_id": "health-only",
        "payload": {},
        "request_hash": content_hash({}),
    }
    server._begin_request(control, binding(server))
    server._complete_request("health-only", {"synthetic": True})
    assert server._execute_row("health-only")["state"] == "completed"


def test_hook_refusal_rolls_back_reclaimed_control_rows(server):
    value, _ = original()
    control = {
        **request(value),
        "operation": "health",
        "task_id": "health-only",
        "payload": {},
        "request_hash": content_hash({}),
    }
    server._begin_request(control, binding(server))
    server._complete_request("health-only", {})
    original_usage = server._ledger_byte_usage

    def pressured(connection):
        if connection.execute(
            "SELECT 1 FROM transport_tasks WHERE task_id='health-only'"
        ).fetchone():
            return 0, server.max_ledger_bytes
        return original_usage(connection)

    server._ledger_byte_usage = pressured

    def refuse(connection, request):
        assert connection.execute("SELECT count(*) FROM transport_tasks").fetchone()[0] == 0
        raise transport._RequestRefusal("request_invalid")

    server._validate_execute_reservation = refuse
    with pytest.raises(transport._RequestRefusal):
        reserve(server, value, 2)
    assert server._execute_row("health-only")["state"] == "completed"


@pytest.mark.parametrize("descriptor", [{}, {"fixture_only": "not-ad-authority"}])
def test_receiver_refuses_managed_correction_descriptor_before_ad_context(monkeypatch, descriptor):
    def unexpected(*args, **kwargs):
        pytest.fail("another protected protocol must not reach AD context or dispatch")

    monkeypatch.setattr(receiver.AdSmbReceiver, "_context", unexpected)
    monkeypatch.setattr(receiver, "run_worker", unexpected)
    target = object.__new__(receiver.AdSmbReceiver)
    with pytest.raises(transport._RequestRefusal) as failure:
        target._execute_payload(
            {},
            enrollment(original()[1]),
            {},
            {},
            peer_fingerprint=pin("9"),
            windows_correction_descriptor=descriptor,
            enrollment_binding={"fixture_only": "ordinary-binding"},
        )
    assert failure.value.code == "request_invalid"


def test_fixed_worker_checks_original_twice_and_commits_failure_truthfully(server, monkeypatch):
    value, channel = original()
    submitted = reserve(server, value)
    calls = []

    def worker(public, **kwargs):
        kwargs["revalidate_original"]()
        calls.append("initial")
        kwargs["revalidate_original"]()
        calls.append("ready")
        assert kwargs["credential"] is None
        return WorkerOutcome(terminal_row(public), "attempted", "verified", "native_error")

    monkeypatch.setattr(receiver, "run_worker", worker)
    result, completed = server._execute_payload(
        submitted,
        enrollment(channel),
        value["manifest"],
        value["profile"],
        peer_fingerprint=pin("9"),
        enrollment_binding=binding(server),
    )
    assert not completed and calls == ["initial", "ready"]
    assert result["result"]["issue"] == "native_error"
    server._complete_request(value["task_id"], result)
    assert (
        server._recover_durable_result(value["task_id"], value["manifest"], value["profile"])
        == result["result"]
    )


@pytest.mark.parametrize(
    "issue,cleanup", [("deadline", "verified"), ("cleanup_unknown", "unknown")]
)
def test_unresolved_dispatch_remains_indeterminate_and_never_replays(
    server, monkeypatch, issue, cleanup
):
    value, channel = original()
    submitted = reserve(server, value)
    monkeypatch.setattr(
        receiver,
        "run_worker",
        lambda *args, **kwargs: WorkerOutcome(None, "attempted", cleanup, issue),
    )
    with pytest.raises(transport._RequestRefusal) as failure:
        server._execute_payload(
            submitted,
            enrollment(channel),
            value["manifest"],
            value["profile"],
            peer_fingerprint=pin("9"),
        )
    assert failure.value.code == "outcome_indeterminate"
    monkeypatch.setattr(
        receiver, "run_worker", lambda *args, **kwargs: pytest.fail("recovery cannot launch")
    )
    recovered = server._recover_payload(
        submitted,
        {
            "original_task_id": value["task_id"],
            "original_request_hash": value["transport_request_hash"],
        },
        binding(server),
    )
    assert recovered["state"] == "indeterminate" and recovered["result"] is None


def test_original_terminal_survives_completion_crash_and_expiry_without_execution(
    server, monkeypatch
):
    value, channel = original()
    submitted = reserve(server, value)
    assert server._enter_effect_dispatch(value["task_id"], None)
    saved = record(value, channel)
    server._commit_durable_result(value["task_id"], saved)
    server.instance_id = "2" * 32
    monkeypatch.setattr(receiver, "_now", lambda: NOW + timedelta(days=1))
    monkeypatch.setattr(
        receiver, "run_worker", lambda *args, **kwargs: pytest.fail("recovery cannot launch")
    )
    result = server._recover_payload(
        submitted,
        {
            "original_task_id": value["task_id"],
            "original_request_hash": value["transport_request_hash"],
        },
        binding(server),
    )
    assert result["state"] == "completed" and result["result"] == saved


@pytest.mark.parametrize(
    "field,bad",
    [
        ("cleanup", "unknown"),
        ("issue", None),
        ("native_digest", pin("e")),
        ("dispatch", "not_started"),
    ],
)
def test_stored_failure_requires_exact_cleanup_and_implementation(field, bad):
    value, channel = original()
    saved = record(value, channel, error=True)
    saved[field] = bad
    with pytest.raises(AdSmbError):
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4 * 1024 * 1024)


def test_missing_prior_read_result_blocks_fresh_context_without_resolver(server):
    first, channel = original("baseline", 0, 1)
    server.channel = channel
    reserve(server, first, 1)
    second, _ = original("baseline", 1, 2)
    reserve(server, second, 2)
    with pytest.raises(AdSmbError):
        server._prior_luids(second["task_id"])


def test_changed_original_hash_cannot_recover_durable_result(server):
    value, _ = original()
    submitted = reserve(server, value)
    with pytest.raises(transport._RequestRefusal) as failure:
        server._recover_payload(
            submitted,
            {"original_task_id": value["task_id"], "original_request_hash": pin("e")},
            binding(server),
        )
    assert failure.value.code == "task_identity_mismatch"


def read_record(value, channel, luid, prior=()):
    public = prepare_packet(
        value,
        channel,
        challenge="f" * 64,
        credential_binding_digest=pin("9"),
        expected_upn_sha256=pin("b"),
        prior_local_authentication_ids=list(prior),
        clock=NOW + timedelta(seconds=2),
    )
    request = public.request
    target = request["target"]
    _, raw = native_fixture()
    raw.update(
        request_id=request["request_id"],
        scope_digest=request["scope_digest"],
        reader=target["reader"],
        purpose=target["file"]["purpose"],
        expected_remote_sid=target["expected_remote_sid"],
        client_identity_digest=public.to_dict()["client_identity_digest"],
        credential_binding_digest=pin("9"),
        hardened_unc_receipt_digest=target["hardened_unc_receipt_digest"],
        expected_volume_serial=int(target["file"]["volume_serial"], 16),
        observed_volume_serial=int(target["file"]["volume_serial"], 16),
        observed_file_id=target["file"]["file_id"],
        observed_sha256=target["file"]["sha256"],
        bytes_read=target["file"]["size_bytes"],
    )
    raw["local_logon"]["authentication_id"] = luid
    row = terminal_row(public)
    row["result"] = raw
    return result_record(
        public, row, native_digest=channel.to_dict()["runner_binary_digest"], issue=None
    )


@pytest.mark.parametrize("change", [None, "duplicate", "history", "cleanup", "missing"])
def test_prior_luids_only_come_from_exact_original_native_results(server, change):
    ids = [11, 12]
    for index in range(2):
        value, channel = original("baseline", index, index + 1)
        server.channel = channel
        reserve(server, value, index + 1)
        saved = read_record(value, channel, ids[index], [f"{ids[0]:016x}"] if index else [])
        if index == 1:
            if change == "duplicate":
                saved["terminal"]["result"]["local_logon"]["authentication_id"] = ids[0]
            elif change == "history":
                saved = read_record(value, channel, ids[index])
            elif change == "cleanup":
                saved["terminal"]["result"]["cleanup"]["token_closed"] = False
        if change != "missing" or index == 0:
            server._commit_durable_result(value["task_id"], saved)
        server._complete_request(value["task_id"], {"result": saved})
    value, _ = original("baseline", 2, 3)
    reserve(server, value, 3)
    if change is None:
        assert server._prior_luids(value["task_id"]) == [f"{luid:016x}" for luid in ids]
    else:
        with pytest.raises((AdSmbError, transport.RunnerTransportError)):
            server._prior_luids(value["task_id"])


def test_recipe_predecessors_ignore_reversed_creation_times(server):
    for index in range(2):
        value, channel = original("baseline", index, index + 1)
        server.channel = channel
        reserve(server, value, index + 1)
        saved = read_record(value, channel, index + 11, [f"{11:016x}"] if index else [])
        server._commit_durable_result(value["task_id"], saved)
        server._complete_request(value["task_id"], {"result": saved})
        with server._database(write=True) as database:
            database.execute(
                "UPDATE transport_tasks SET created_at=? WHERE task_id=?",
                (100 - index, value["task_id"]),
            )
            database.commit()
    value, _ = original("baseline", 2, 3)
    reserve(server, value, 3)
    with server._database(write=True) as database:
        database.execute(
            "UPDATE transport_tasks SET created_at=1 WHERE task_id=?", (value["task_id"],)
        )
        database.commit()
    assert server._prior_luids(value["task_id"]) == [f"{11:016x}", f"{12:016x}"]


@pytest.mark.parametrize(
    "phase,index", [("baseline", 0), ("inspect", 0), ("audit", 0), ("harden", 0), ("rollback", 0)]
)
def test_unknown_non_error_native_payload_cannot_be_completed(phase, index):
    value, channel = original(phase, index)
    saved = record(value, channel, error=False)
    with pytest.raises(AdSmbError):
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4 * 1024 * 1024)


@pytest.mark.parametrize("milliseconds", [1, 1001, 60000])
def test_exact_millisecond_historical_packet_is_recoverable(milliseconds):
    value, channel = original()
    request = value["manifest"]["params"]["ad_smb_request"]
    from bluefire.ad_smb_contract import timestamp

    if milliseconds == 60000:
        value = rebind_context(value, deadline=(NOW + timedelta(seconds=60)).isoformat())
        request = value["manifest"]["params"]["ad_smb_request"]
    public = prepare_packet(
        value,
        channel,
        challenge="f" * 64,
        credential_binding_digest=None,
        expected_upn_sha256=None,
        prior_local_authentication_ids=[],
        clock=timestamp(request["deadline"]) - timedelta(milliseconds=milliseconds),
    )
    assert public.to_dict()["remaining_ms"] == milliseconds
    saved = result_record(
        public,
        terminal_row(public),
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue="native_error",
    )
    assert (
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4 * 1024 * 1024)
        == saved
    )


@pytest.mark.parametrize("character", [chr(1), chr(34), chr(92), chr(0x1F600)])
def test_derived_audit_allowance_retains_escaped_partial_original(character):
    value, channel = original("audit")
    public = packet(value, channel)
    remaining = public.audit_byte_limit
    unit = len(character.encode("utf-8"))
    events = []
    while remaining >= unit:
        count = min(65536, remaining) // unit
        events.append(character * count)
        remaining -= count * unit
    terminal = terminal_row(public)
    terminal["result"] = {
        "schema_version": "bluefire.ad-smb-native-audit-capture.v1",
        "channel": "Security",
        "window_start": "2026-10-09T00:00:00.0000000Z",
        "window_end": "2026-10-09T00:00:01.0000000Z",
        "state": "byte_limit",
        "raw_events": events,
        "utf8_bytes": sum(len(item.encode("utf-8")) for item in events),
        "system_error": None,
        "handles_closed": True,
        "log_continuity_verified": False,
        "authenticated_source_claim": False,
        "independent_evidence_claim": False,
        "effective_access_claim": False,
    }
    saved = result_record(
        public, terminal, native_digest=channel.to_dict()["runner_binary_digest"], issue=None
    )
    assert len(canonical_json_bytes(terminal)) <= public.output_limit
    assert len(canonical_json_bytes(saved)) <= 4194304 - 4096
    observed = stored_result(
        saved, value["manifest"], value["profile"], channel, maximum=4194304 - 4096
    )
    assert observed["terminal"]["result"]["state"] == "byte_limit"
    assert observed["terminal"]["result"]["raw_events"] == events
    observed["terminal"]["result"]["raw_events"].append("x" * (remaining + 1))
    observed["terminal"]["result"]["utf8_bytes"] += remaining + 1
    with pytest.raises(AdSmbError):
        stored_result(
            observed, value["manifest"], value["profile"], channel, maximum=4194304 - 4096
        )


def test_original_escaped_capture_overflow_is_not_silently_completed():
    value, channel = original("audit")
    saved = record(value, channel, error=False)
    saved["terminal"]["result"] = {"raw_events": [chr(34) * 65536] * 31 + [chr(34) * 65184]}
    assert len(canonical_json_bytes(saved)) > 4194304 - 4096
    with pytest.raises(AdSmbError):
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4194304 - 4096)


def test_completion_compare_and_swap_retries_without_dispatch(server, monkeypatch):
    value, channel = original()
    reserve(server, value)
    assert server._enter_effect_dispatch(value["task_id"], None)
    saved = record(value, channel)
    server._commit_durable_result(value["task_id"], saved)
    original_complete = server._set_reconciled_completion
    attempts = []

    def race(*args, **kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            with server._database(write=True) as database:
                database.execute(
                    "UPDATE transport_tasks SET updated_at=updated_at+1 WHERE task_id=?",
                    (value["task_id"],),
                )
                database.commit()
        return original_complete(*args, **kwargs)

    server._set_reconciled_completion = race
    monkeypatch.setattr(receiver, "run_worker", lambda *args, **kwargs: pytest.fail("no replay"))
    assert server._reconcile_execute_task(value["task_id"])["result"] == saved
    assert len(attempts) == 2


@pytest.mark.parametrize("change", ["generation", "workflow", "scope", "channel"])
def test_new_distinct_task_cannot_change_bound_scope_or_workflow(server, change):
    value, _ = original()
    reserve(server, value)
    second, _ = original("audit", serial=2)
    changes = {}
    if change == "generation":
        changes["host"] = {**second["transport_identity"], "native_generation": pin("e")}
    elif change == "channel":
        changes["host"] = {**second["transport_identity"], "channel_digest": pin("e")}
    elif change == "workflow":
        changes["workflow_job_id"] = "job-" + "c" * 32
    else:
        changes["scope_digest"] = pin("e")
    second = rebind_context(second, **changes)
    if "host" in changes:
        second["transport_identity"] = changes["host"]
    with pytest.raises(transport._RequestRefusal):
        reserve(server, second, 2)


@pytest.mark.parametrize(
    "timeout,deadline_us,clock_us", [(1000, 30000000, 100000), (60000, 30000500, 9999700)]
)
def test_historical_packet_uses_valid_original_instant_before_channel_expiry(
    timeout, deadline_us, clock_us
):
    value, channel = fixture(
        limits={
            "timeout_ms": timeout,
            "max_stdout_bytes": 4259840,
            "max_stderr_bytes": 65536,
            "max_artifact_bytes": 1048576,
            "max_files": 2,
        }
    )
    scope = AdSmbScope.from_mapping(value["manifest"]["params"]["ad_smb_request"]["scope"])
    row = channel.to_dict()
    row["expires_at"] = "2026-10-09T00:00:10Z"
    channel = AdSmbHostChannel.from_mapping(scope, row)
    host = {
        **value["transport_identity"],
        "channel_digest": channel.digest,
        "native_generation": native_generation(channel),
    }
    value = rebind_context(
        value, host=host, deadline=(NOW + timedelta(microseconds=deadline_us)).isoformat()
    )
    value["transport_identity"] = host
    prepared = prepare_packet(
        value,
        channel,
        challenge="f" * 64,
        credential_binding_digest=None,
        expected_upn_sha256=None,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(microseconds=clock_us),
    )
    saved = result_record(
        prepared,
        terminal_row(prepared),
        native_digest=row["runner_binary_digest"],
        issue="native_error",
    )
    assert (
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4190208) == saved
    )


def test_impossible_historical_remaining_still_refused():
    value, channel = original()
    saved = record(value, channel)
    saved["packet"]["remaining_ms"] = 60000
    with pytest.raises(AdSmbError):
        stored_result(saved, value["manifest"], value["profile"], channel, maximum=4190208)
