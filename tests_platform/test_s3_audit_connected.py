"""Opt-in connected synthetic application/native/worker acceptance.

No credentials, TLS enrollment, protected-runtime installation or AWS acceptance
is inferred. Both production gates stay closed. The test-only collection branch
is explicit in this fixture and in one ignored native unit test; all original
business receipts and collection receipts come from actual native supervision.
"""

import hashlib
import io
import json
import os
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_executor as executor_module
from bluefire import s3_audit_reviews as reviews
from bluefire import s3_audit_workflow as workflow
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.runner_contracts import seal_profile
from bluefire.s3_access_admission import S3HostAdmission
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_host_config import public_environments
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.util import content_hash
from tests_platform import s3_audit_connected_bridge as bridge_module
from tests_platform.s3_audit_connected_bridge import (
    create_json,
    digest,
    invoke_native,
    load_tools,
    pinned,
    read_file,
)
from tests_platform.s3_profile_fixtures import managed_profile
from tests_platform.test_s3_access_jobs import stage, through_baseline
from tests_platform.test_s3_access_sdk import DATA
from tests_platform.test_s3_access_wire import NOW, credential_row
from tests_platform.test_s3_audit_admission import audit_admitted, original_context
from tests_platform.test_s3_audit_collection_contract import source_row
from tests_platform.test_s3_audit_workflow_jobs import submit

OPT_IN = sys.platform == "linux" and bool(
    os.environ.get("BLUEFIRE_S3_CONNECTED_TOOLS")
    and os.environ.get("BLUEFIRE_S3_CONNECTED_TOOLS_SHA256")
)
connected = pytest.mark.skipif(
    not OPT_IN, reason="requires explicit reviewed native test binary/tool/source pins on Linux"
)


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def native_utc_time(value):
    return value.isoformat().replace("+00:00", "Z")


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    if not OPT_IN:
        pytest.skip("native bridge is not implicitly built or started")
    tools_path = Path(os.environ["BLUEFIRE_S3_CONNECTED_TOOLS"])
    tools_hash = os.environ["BLUEFIRE_S3_CONNECTED_TOOLS_SHA256"]
    load_tools(tools_path, tools_hash)
    assert workflow.DISPATCH_RELEASED is False
    value = audit_admitted()
    configuration = value["configuration"]
    entry = configuration["environments"][0]
    entry["profile"]["sandbox_root"] = str(tmp_path)
    entry["profile"] = seal_profile(entry["profile"])
    profile = entry["profile"]
    managed = managed_profile(profile["profile_id"])
    entry["managed_profile_digest"] = content_hash(managed.to_dict())
    for obj, payload in zip(entry["scope"]["objects"], DATA, strict=True):
        obj.update(sha256="sha256:" + hashlib.sha256(payload).hexdigest(), size_bytes=len(payload))
    scope = S3AccessScope.from_mapping(entry["scope"])
    entry["audit_source"] = {
        **source_row(scope),
        "managed_profile_digest": entry["managed_profile_digest"],
        "protected_runtime_digest": entry["runtime_digest"],
        "worker_generation": entry["worker_generation"],
    }
    ledger = tmp_path / "native-ledger"
    ledger.mkdir(mode=0o700)
    entry["ledger_root"] = str(ledger)
    create_json(tmp_path / "sdk-policy.json", entry["baseline_policy"])
    discovery = {
        "environment": public_environments(configuration)[0],
        "profile": profile,
        "managed_profile_digest": entry["managed_profile_digest"],
        "runtime_digest": entry["runtime_digest"],
        "worker_generation": entry["worker_generation"],
        "available": True,
        "problem": None,
    }
    _request, original = original_context(audit_admitted())
    identity = original["transport_identity"]
    identity["runner_id"] = profile["runner_id"]

    class Client:
        def __init__(self):
            self.calls = []
            self.recovered = []
            self.receipts = {}
            self.fault = "none"
            self.ready = True

        def transport_identity(self):
            return deepcopy(identity)

        def s3_access_environments(self):
            return [{**deepcopy(discovery), "available": self.ready}]

        def execute_task(self, manifest, selected_profile, **kwargs):
            assert selected_profile == profile
            assert not kwargs["cancel_event"].is_set()
            assert len(self.calls) < 16
            task_id = kwargs["task_id"]
            assert task_id not in self.receipts, "original task must never be redispatched"
            request_hash = content_hash({"manifest": manifest, "profile": selected_profile})
            credentials = credential_row()
            admitted = S3HostAdmission.issue(
                configuration=configuration,
                manifest=manifest,
                profile=selected_profile,
                issuer=value["issuer"],
                task_id=task_id,
                runner_digest=value["runner_digest"],
                credential_digest=content_hash(credentials),
                owner_uid=os.getuid(),
                now=NOW,
            )
            packet = {
                "schema_version": "bluefire.s3-connected-test-input.v1",
                "admission": admitted.to_dict(),
                "manifest": manifest,
                "profile": selected_profile,
                "now": native_utc_time(NOW),
                "credentials": credentials,
                "task_id": task_id,
                "request_hash": request_hash,
                "fault": (
                    self.fault
                    if manifest["params"]["worker_request"]["operation"] == "collect_audit"
                    else "none"
                ),
            }
            directory = tmp_path / f"operation-{len(self.calls):02d}"
            self.calls.append(deepcopy(packet))
            retained = invoke_native(tools_path, tools_hash, directory, packet)
            self.receipts[task_id] = (directory / "result.json", retained)
            return deepcopy(retained["result"])

        def recover(self, task_id, request_hash):
            self.recovered.append((task_id, request_hash))
            path, retained = self.receipts[task_id]
            reopened = json.loads(read_file(path))
            assert reopened == retained
            assert reopened["task_id"] == task_id and reopened["request_hash"] == request_hash
            return {
                "original_task_id": task_id,
                "original_request_hash": request_hash,
                "state": "completed",
                "result": reopened["result"],
                "error_code": None,
                "cancellation_requested": False,
                "receipt_ids": [],
                "cleanup_required": False,
            }

    client = Client()
    monkeypatch.setattr(executor_module, "AuthenticatedRunnerClient", Client)
    monkeypatch.setattr(executor_module, "datetime", Clock)
    # Explicit test-only application gate; there is no product factory or release switch.
    monkeypatch.setattr(workflow, "DISPATCH_RELEASED", True)
    store = ProductStore(tmp_path / "product.db")
    runs = RunStore(tmp_path / "runs")
    with RunJobController(store, max_workers=1) as controller:
        service = SimpleNamespace(
            product_store=store,
            store=runs,
            job_controller=controller,
            runner_lifecycle=SimpleNamespace(
                client_for_profile=lambda *args, **kwargs: (client, tmp_path)
            ),
            config=SimpleNamespace(runner_profiles=()),
            _runner_profiles=lambda: (managed,),
        )
        executor = executor_module.configured_executor(service)
        jobs = S3AccessJobs(service, executor, clock=lambda: NOW)
        yield SimpleNamespace(
            jobs=jobs,
            client=client,
            executor=executor,
            service=service,
            root=tmp_path,
            ledger=ledger,
        )


def native_execution(client, packet):
    return client.receipts[packet["task_id"]][1]["result"]["output"]["s3_execution"]


@connected
def test_connected_pair_uses_actual_original_runs_and_native_discovery(bridge):
    jobs, client = bridge.jobs, bridge.client
    owner = through_baseline(jobs)
    stage(jobs, owner, "audit_baseline")
    stage(jobs, owner, "apply")
    stage(jobs, owner, "retest")
    final, _ = stage(jobs, owner, "audit_retest")
    history = reviews.list_reviews(jobs, owner)
    assert [row["phase"] for row in history["collections"]] == ["baseline", "retest"]
    assert final["audit"] == "authenticated_retrieval" and final["live_outcome_verified"] is False
    calls_before = deepcopy(client.calls)
    for row in history["collections"]:
        detail = reviews.read_review(jobs, owner, row["review_id"])
        collection = next(
            packet
            for packet in client.calls
            if packet["manifest"]["run_id"] == detail["collection_run_id"]
        )
        execution = native_execution(client, collection)
        assert client.receipts[collection["task_id"]][1]["discovery_ack_checked"] is True
        assert detail["receipt"] == execution
        assert execution["cleanup"] == "verified"
        assert (
            execution["result"]["data"]["discovery"]["reservation_digest"]
            == execution["reservation_digest"]
        )
        assert execution["result"]["data"]["objects"]
        assert execution["result"]["data"]["delivery_state"] == "incomplete"
        assert detail["log_integrity_proven"] is False and detail["effective_access_claim"] is False
        for original in collection["manifest"]["params"]["worker_request"]["audit"][
            "original_pair"
        ]["reads"]:
            actual = next(
                packet
                for packet in client.calls
                if packet["manifest"]["run_id"] == original["run_id"]
            )
            actual_execution = native_execution(client, actual)
            assert original["manifest_digest"] == content_hash(actual["manifest"])
            assert original["result"] == actual_execution["result"]
            assert original["reservation_digest"] == actual_execution["reservation_digest"]
    reopened = S3AccessJobs(bridge.service, bridge.executor, clock=lambda: NOW)
    assert reopened.read(owner) == final
    assert reviews.list_reviews(reopened, owner) == history
    assert client.calls == calls_before


@connected
@pytest.mark.parametrize("fault", ["append_refused", "lost_ack"])
def test_connected_discovery_fault_never_sends_selected_get_or_replaces_slot(bridge, fault):
    jobs, client = bridge.jobs, bridge.client
    owner = through_baseline(jobs)
    client.fault = fault
    state, _ = stage(jobs, owner, "audit_baseline")
    packet = client.calls[-1]
    path, retained = client.receipts[packet["task_id"]]
    execution = native_execution(client, packet)
    assert execution["result"] is None
    assert retained["discovery_committed"] is (fault == "lost_ack")
    assert retained["lost_ack_observed"] is (fault == "lost_ack")
    assert retained["discovery_ack_checked"] is (fault == "lost_ack")
    assert retained["child_reaped"] is True and retained["group_absent"] is True
    trace = [json.loads(line) for line in read_file(path.parent / "sdk-trace.jsonl").splitlines()]
    assert "ListObjectsV2" in [row["operation"] for row in trace]
    assert "GetObject" not in [row["operation"] for row in trace]
    assert execution["send_debits"] == len(trace)
    assert state["audit_collection"]["slots"][0]["state"] == "failed"
    assert state["audit_collection"]["reserved"]["api_calls"] == 9
    assert reviews.list_reviews(jobs, owner)["collections"] == []
    before = deepcopy(client.calls)
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "audit_baseline"})
    assert jobs.read(owner) == state
    assert client.calls == before


@connected
def test_connected_original_recovery_after_publication_failure_never_executes_again(
    bridge, monkeypatch
):
    jobs, client = bridge.jobs, bridge.client
    owner = through_baseline(jobs)
    publish = jobs._publish_run

    def interrupted(run_id, owner_id, operation_id, request, execution):
        if request.to_dict()["operation"] == "collect_audit":
            raise RuntimeError("test-only publication interruption after native retained result")
        return publish(run_id, owner_id, operation_id, request, execution)

    monkeypatch.setattr(jobs, "_publish_run", interrupted)
    child, _ = submit(jobs, owner, "audit_baseline")
    assert child["state"] == "failed"
    original_requests = deepcopy(child["request"]["worker_requests"])
    original_contexts = deepcopy(child["progress"]["original_tasks"])
    before = deepcopy(client.calls)
    journal = read_file(bridge.ledger / "reservations.jsonl")
    assert jobs.read(owner)["saved_result_recovery_available"] is True
    jobs.stop(owner, {})
    client.ready = False
    monkeypatch.setattr(jobs, "_publish_run", publish)
    jobs.clock = lambda: NOW + timedelta(hours=2)
    state = jobs.recover(owner, {})
    assert state["stopped"] is True and state["active_job"] is None
    assert state["audit"] == "authenticated_retrieval"
    assert len(client.recovered) == 1 and client.calls == before
    assert read_file(bridge.ledger / "reservations.jsonl") == journal
    retained = jobs.store.get_job(child["job_id"])
    assert retained["request"]["worker_requests"] == original_requests
    assert retained["progress"]["original_tasks"] == original_contexts
    jobs.recover(owner, {})
    assert len(client.recovered) == 1 and client.calls == before


@pytest.mark.parametrize(
    "microsecond,expected",
    [(0, "2026-10-09T00:00:00Z"), (123456, "2026-10-09T00:00:00.123456Z")],
)
def test_connected_clock_uses_native_canonical_utc_without_launching(microsecond, expected):
    assert native_utc_time(NOW.replace(microsecond=microsecond)) == expected


def test_connected_bridge_is_opt_in_and_production_collection_remains_closed():
    assert workflow.DISPATCH_RELEASED is False
    source = (Path(__file__).parents[1] / "runner/src/s3_access_binding.rs").read_text(
        encoding="utf-8"
    )
    assert 'Err("S3 audit collector dispatch is not connected")' in source
    registration = (Path(__file__).parents[1] / "runner/src/s3_reservation.rs").read_text(
        encoding="utf-8"
    )
    assert (
        '#[cfg(all(test, target_os = "linux"))]\n#[path = "s3_audit_connected_tests.rs"]'
        in registration
    )
    native = (Path(__file__).parents[1] / "runner/src/s3_audit_connected_tests.rs").read_text(
        encoding="utf-8"
    )
    assert (
        '#[ignore = "explicit pinned test-only Python/application bridge; never part of ordinary tests"]'
        in native
    )
    assert "S3ReservationStore::open(&admission).is_err()" in native


def test_connected_tools_refuse_unreviewed_command_fields_without_launching(tmp_path):
    path = tmp_path / "tools.json"
    path.write_bytes(
        json.dumps(
            {"schema_version": "bluefire.s3-connected-test-tools.v1", "command": ["unreviewed"]}
        ).encode()
    )
    with pytest.raises(ValueError, match="packet shape"):
        load_tools(path, digest(read_file(path)))


def test_connected_executable_pin_detects_substituted_bytes_without_launching(tmp_path):
    path = tmp_path / "inert-tool.txt"
    path.write_bytes(b"first synthetic tool bytes")
    row = {"path": str(path), "sha256": digest(read_file(path))}
    assert pinned(row) == path
    path.write_bytes(b"substituted synthetic tool bytes")
    with pytest.raises(ValueError, match="pin differs"):
        pinned(row)


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 131072])
def test_connected_native_pin_reads_in_small_chunks_under_large_ceiling(
    tmp_path, monkeypatch, size
):
    path = tmp_path / "inert-native-tool"
    raw = b"x" * size
    requests = []

    class BoundedReader(io.BytesIO):
        def read(self, amount):
            requests.append(amount)
            if not 0 < amount <= 64 * 1024:
                raise MemoryError("test read exceeds the worker-safe chunk bound")
            return super().read(amount)

    def open_inert(selected, mode):
        assert selected == path and mode == "rb"
        return BoundedReader(raw)

    monkeypatch.setattr(Path, "open", open_inert)
    assert pinned({"path": str(path), "sha256": digest(raw)}, 512 * 1024 * 1024) == path
    assert requests and max(requests) <= 64 * 1024


def test_connected_native_pin_never_assembles_the_full_binary(tmp_path, monkeypatch):
    path = tmp_path / "inert-native-tool"
    raw = b"synthetic native bytes"
    path.write_bytes(raw)

    def refuse_full_read(*args, **kwargs):
        raise AssertionError("binary pin must be hashed incrementally")

    monkeypatch.setattr(bridge_module, "read_file", refuse_full_read)
    assert pinned({"path": str(path), "sha256": digest(raw)}, 512 * 1024 * 1024) == path
    with pytest.raises(ValueError, match="finite bound"):
        pinned({"path": str(path), "sha256": digest(raw)}, len(raw) - 1)


@pytest.mark.parametrize("size", [0, 63, 64, 65])
def test_connected_chunked_read_preserves_short_reads_and_exact_ceiling(
    tmp_path, monkeypatch, size
):
    path = tmp_path / "inert-short-reader"
    raw = b"x" * size
    consumed = []

    class ShortReader(io.BytesIO):
        def read(self, amount):
            piece = super().read(min(amount, 7))
            consumed.append(len(piece))
            return piece

    def open_inert(selected, mode):
        assert selected == path and mode == "rb"
        return ShortReader(raw)

    monkeypatch.setattr(Path, "open", open_inert)
    if size > 64:
        with pytest.raises(ValueError, match="finite bound"):
            read_file(path, 64)
    else:
        assert read_file(path, 64) == raw
    assert sum(consumed) == size


@pytest.mark.parametrize("extra", [0, 1])
def test_connected_source_read_has_separate_finite_bound(tmp_path, extra):
    source = tmp_path / "generated_module.py"
    raw = b"#" * (bridge_module.MAX_SOURCE_FILE_BYTES + extra)
    source.write_bytes(raw)
    with pytest.raises(ValueError, match="finite bound"):
        read_file(source)
    if extra:
        with pytest.raises(ValueError, match="finite bound"):
            read_file(source, bridge_module.MAX_SOURCE_FILE_BYTES)
    else:
        assert read_file(source, bridge_module.MAX_SOURCE_FILE_BYTES) == raw


def _source_tools_packet(tmp_path):
    root = Path(bridge_module.__file__).resolve().parents[1]
    source = root / "bluefire" / "service.py"
    source_bytes = read_file(source, bridge_module.MAX_SOURCE_FILE_BYTES)
    python = tmp_path / "python-tool"
    native = tmp_path / "native-tool"
    python.write_bytes(b"pinned python tool")
    native.write_bytes(b"pinned native tool")
    value = {
        "schema_version": "bluefire.s3-connected-test-tools.v1",
        "python": {"path": str(python), "sha256": digest(read_file(python))},
        "native": {"path": str(native), "sha256": digest(read_file(native))},
        "helper": {
            "path": str(Path(bridge_module.__file__).resolve()),
            "sha256": digest(read_file(bridge_module.__file__)),
        },
        "source_root": str(root),
        "source_files": {"bluefire/service.py": digest(source_bytes)},
    }
    packet = tmp_path / "tools.json"
    packet.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    return packet, source, source_bytes


def test_connected_source_inventory_accepts_large_exact_hash_without_launching(
    tmp_path, monkeypatch
):
    packet, source, source_bytes = _source_tools_packet(tmp_path)
    assert bridge_module.LIMIT < len(source_bytes) <= bridge_module.MAX_SOURCE_FILE_BYTES
    source_reads = []
    original = bridge_module.read_file

    def capture(path, maximum=bridge_module.LIMIT):
        if Path(path) == source:
            source_reads.append(maximum)
        return original(path, maximum)

    monkeypatch.setattr(bridge_module, "read_file", capture)
    loaded = load_tools(packet, digest(read_file(packet)))
    assert loaded["source_files"]["bluefire/service.py"] == digest(source_bytes)
    assert source_reads == [bridge_module.MAX_SOURCE_FILE_BYTES]


@pytest.mark.parametrize("mode", ["over_cap", "hash_mismatch"])
def test_connected_source_inventory_refuses_large_or_changed_bytes_without_launching(
    tmp_path, monkeypatch, mode
):
    packet, source, source_bytes = _source_tools_packet(tmp_path)
    original = bridge_module.read_file

    def substitute(path, maximum=bridge_module.LIMIT):
        if Path(path) == source:
            assert maximum == bridge_module.MAX_SOURCE_FILE_BYTES
            if mode == "over_cap":
                raise ValueError("test input exceeds finite bound")
            return source_bytes[:-1] + bytes([source_bytes[-1] ^ 1])
        return original(path, maximum)

    monkeypatch.setattr(bridge_module, "read_file", substitute)
    expected = digest(read_file(packet))
    if mode == "over_cap":
        with pytest.raises(ValueError, match="finite bound"):
            load_tools(packet, expected)
    else:
        with pytest.raises(ValueError, match="source inventory changed"):
            load_tools(packet, expected)


@pytest.mark.parametrize("matches", [True, False])
def test_connected_local_loader_compiles_only_the_captured_pinned_bytes(
    tmp_path, monkeypatch, matches
):
    source = tmp_path / "bluefire" / "synthetic.py"
    original = b"SYNTHETIC_ONLY = 'pinned'\n" + b"#" * (300 * 1024)
    changed = b"SYNTHETIC_ONLY = 'substituted'\n" + b"#" * (300 * 1024)
    reads = []
    compiled = []
    code_marker = object()
    spec = SimpleNamespace(origin=str(source), loader=None)

    def read_once(path, maximum=bridge_module.LIMIT):
        assert path == source
        assert maximum == bridge_module.MAX_SOURCE_FILE_BYTES
        reads.append(path)
        return original if len(reads) == 1 else changed

    def capture_compile(raw, filename, mode):
        compiled.append((raw, filename, mode))
        return code_marker

    monkeypatch.setattr(bridge_module, "read_file", read_once)
    monkeypatch.setattr(bridge_module, "compile", capture_compile, raising=False)
    monkeypatch.setattr(
        bridge_module.importlib.machinery.PathFinder, "find_spec", lambda fullname, path: spec
    )
    monkeypatch.setattr(
        bridge_module.importlib.machinery,
        "SourceFileLoader",
        lambda fullname, path: SimpleNamespace(),
    )
    finder = bridge_module.LocalSourcePins(
        {
            "source_root": str(tmp_path),
            "source_files": {"bluefire/synthetic.py": digest(original if matches else changed)},
        }
    )
    if not matches:
        with pytest.raises(ImportError, match="frozen source inventory"):
            finder.find_spec("bluefire.synthetic")
        assert compiled == [] and spec.loader is None
    else:
        found = finder.find_spec("bluefire.synthetic")
        assert found.loader.get_code("bluefire.synthetic") is code_marker
        assert found.loader.get_code("bluefire.synthetic") is code_marker
        assert compiled == [(original, str(source), "exec"), (original, str(source), "exec")]
    assert reads == [source]


def test_connected_local_loader_refuses_over_cap_source_before_compile(tmp_path, monkeypatch):
    source = tmp_path / "bluefire" / "synthetic.py"
    spec = SimpleNamespace(origin=str(source), loader=None)
    compiled = []

    def over_cap(path, maximum=bridge_module.LIMIT):
        assert path == source
        assert maximum == bridge_module.MAX_SOURCE_FILE_BYTES
        raise ValueError("test input exceeds finite bound")

    monkeypatch.setattr(bridge_module, "read_file", over_cap)
    monkeypatch.setattr(
        bridge_module.importlib.machinery.PathFinder, "find_spec", lambda fullname, path: spec
    )
    monkeypatch.setattr(
        bridge_module, "compile", lambda *args: compiled.append(args), raising=False
    )
    finder = bridge_module.LocalSourcePins(
        {
            "source_root": str(tmp_path),
            "source_files": {"bluefire/synthetic.py": digest(b"unused")},
        }
    )
    with pytest.raises(ValueError, match="finite bound"):
        finder.find_spec("bluefire.synthetic")
    assert compiled == [] and spec.loader is None


@pytest.fixture
def simulated_prctl(monkeypatch):
    state = {"value": 0, "failure": None}
    calls = []
    types = bridge_module.ctypes

    class Prctl:
        argtypes = None
        restype = None

        def __call__(self, command, argument, third, fourth, fifth):
            assert self.argtypes == [
                types.c_int,
                types.c_ulong,
                types.c_ulong,
                types.c_ulong,
                types.c_ulong,
            ]
            assert self.restype is types.c_int
            assert (third, fourth, fifth) == (0, 0, 0)
            calls.append((command, argument))
            if command == 37:
                assert isinstance(argument, int) and argument > 1
                if state["failure"] == "read":
                    return -1
                types.cast(types.c_void_p(argument), types.POINTER(types.c_int)).contents.value = (
                    state["value"]
                )
            elif command == 36:
                assert type(argument) is int and argument in (0, 1)
                if state["failure"] == "write":
                    return -1
                state["value"] = argument
            else:
                raise AssertionError("unexpected prctl command")
            return 0

    function = Prctl()

    def library(name, *, use_errno):
        assert name is None and use_errno is True
        return SimpleNamespace(prctl=function)

    monkeypatch.setattr(types, "CDLL", library)
    monkeypatch.setattr(types, "get_errno", lambda: 5)
    return SimpleNamespace(state=state, calls=calls)


@pytest.mark.parametrize("initial", [0, 1])
def test_connected_subreaper_uses_read_pointer_and_integer_write_abi(simulated_prctl, initial):
    fixture = simulated_prctl
    fixture.state["value"] = initial
    assert bridge_module.subreaper() == initial
    assert fixture.state["value"] == initial
    assert [row[0] for row in fixture.calls] == [37]
    assert bridge_module.subreaper(1 - initial) == initial
    assert fixture.state["value"] == 1 - initial
    assert [row[0] for row in fixture.calls] == [37, 37, 36]
    assert fixture.calls[-1] == (36, 1 - initial)
    assert bridge_module.subreaper() == 1 - initial
    assert [row[0] for row in fixture.calls] == [37, 37, 36, 37]


@pytest.mark.parametrize(
    "failure,commands,message",
    [
        ("read", [37], "state unavailable"),
        ("write", [37, 36], "state change failed"),
    ],
)
def test_connected_subreaper_reports_read_and_write_failures_without_state_change(
    simulated_prctl, failure, commands, message
):
    fixture = simulated_prctl
    fixture.state["failure"] = failure
    with pytest.raises(OSError, match=message) as error:
        bridge_module.subreaper(1)
    assert error.value.errno == 5
    assert fixture.state["value"] == 0
    assert [row[0] for row in fixture.calls] == commands


@pytest.fixture
def simulated_session(tmp_path, monkeypatch):
    """No process, signal, prctl, /proc read, or platform-specific write is performed."""
    native = (100, 10, 100, 100)
    descendant = (101, 11, 101, 100)
    identities = {100: native, 101: descendant}
    events = []
    records = []
    state = {"subreaper": 0}

    def identity(pid):
        if pid not in identities:
            raise ProcessLookupError(pid)
        return identities[pid]

    def set_subreaper(value=None):
        previous = state["subreaper"]
        if value is not None:
            events.append(("subreaper", value))
            state["subreaper"] = value
        return previous

    def waitid(which, pid, flags):
        assert which == 1 and pid == 100 and flags == 7
        events.append(("observe_unreaped", pid))
        return SimpleNamespace(si_pid=pid)

    def waitpid(pid, flags):
        assert pid == 101 and flags == 2
        events.append(("reap_member", pid))
        identities.pop(pid)
        return pid, 0

    def signal_identity(row, signum):
        assert identity(row[0]) == row
        events.append(("signal", row[0], signum))
        return True

    process = SimpleNamespace(pid=100, returncode=None, stdout=None, stderr=None)

    def wait(timeout):
        assert timeout > 0 and list(identities) == [100]
        events.append(("reap_native", 100))
        identities.pop(100)
        process.returncode = 0
        return 0

    process.wait = wait
    owner = bridge_module.OwnedSession.__new__(bridge_module.OwnedSession)
    owner.containment = SimpleNamespace(process_identity=identity, _signal_identity=signal_identity)
    owner.directory = tmp_path
    owner.process = process
    owner.leader = native
    owner.previous_subreaper = None
    owner.locked = False
    owner.reaped_members = 0
    owner.observed_members = {}

    def members(_deadline):
        rows = list(identities.values())
        for row in rows:
            owner.observed_members[row[:2]] = row
        return rows

    owner.members = members
    monkeypatch.setattr(
        bridge_module,
        "os",
        SimpleNamespace(P_PID=1, WEXITED=1, WNOHANG=2, WNOWAIT=4, waitid=waitid, waitpid=waitpid),
    )
    monkeypatch.setattr(bridge_module, "signal", SimpleNamespace(SIGKILL=9))
    monkeypatch.setattr(bridge_module, "subreaper", set_subreaper)
    monkeypatch.setattr(
        bridge_module, "create_json", lambda path, value: records.append((path, value))
    )
    monkeypatch.setattr(bridge_module.time, "sleep", lambda _duration: None)
    return SimpleNamespace(
        owner=owner,
        process=process,
        identities=identities,
        events=events,
        records=records,
        state=state,
        native=native,
        descendant=descendant,
    )


@pytest.mark.parametrize("previous", [0, 1])
def test_connected_parent_reaps_separate_worker_group_after_native_exit(
    simulated_session, previous
):
    fixture = simulated_session
    fixture.state["subreaper"] = previous
    with fixture.owner:
        assert fixture.owner.exited() is True
        assert fixture.process.returncode is None
    assert fixture.identities == {}
    assert fixture.events.index(("reap_member", 101)) < fixture.events.index(("reap_native", 100))
    assert ("signal", 101, 9) in fixture.events
    assert fixture.state["subreaper"] == previous
    assert fixture.records[0][1] == {
        "schema_version": "bluefire.s3-connected-parent-cleanup.v2",
        "cleanup": "verified",
        "native_reaped": True,
        "adopted_members_reaped": 1,
        "native_identity": fixture.native,
        "observed_members": [fixture.native, fixture.descendant],
        "live_owned_members": [],
        "subreaper_restored": True,
        "body_failed": False,
    }


def test_connected_parent_owns_child_before_identity_setup_failure(simulated_session, monkeypatch):
    fixture = simulated_session
    owner = fixture.owner
    owner.process = None
    original = owner.pin_leader
    attempts = []

    def fail_first_pin():
        attempts.append(True)
        if len(attempts) == 1:
            raise RuntimeError("simulated setup failure")
        return original()

    monkeypatch.setattr(owner, "pin_leader", fail_first_pin)
    monkeypatch.setattr(bridge_module.subprocess, "Popen", lambda *args, **kwargs: fixture.process)
    with pytest.raises(RuntimeError, match="simulated setup failure"):
        with owner:
            owner.spawn(["not-launched"], {})
    assert fixture.identities == {}
    assert fixture.records[0][1]["cleanup"] == "verified"
    assert fixture.records[0][1]["live_owned_members"] == []
    assert fixture.records[0][1]["body_failed"] is True
    assert fixture.state["subreaper"] == 0


def test_connected_parent_refuses_unknown_cleanup_and_restores_subreaper(simulated_session):
    fixture = simulated_session
    with pytest.raises(RuntimeError, match="cleanup is unknown"):
        with fixture.owner:
            fixture.identities[100] = (100, 99, 100, 100)
    assert fixture.process.returncode is None
    assert not any(row[0] in {"signal", "reap_member", "reap_native"} for row in fixture.events)
    assert fixture.state["subreaper"] == 0
    assert fixture.records[0][1]["cleanup"] == "unknown"
    assert fixture.records[0][1]["live_owned_members"] is None


def test_connected_parent_refuses_replaced_descendant_before_reap(simulated_session):
    fixture = simulated_session
    fixture.identities[101] = (101, 99, 101, 100)
    with pytest.raises(RuntimeError, match="descendant identity changed"):
        fixture.owner.reap_member(fixture.descendant)
    assert not any(row[0] == "reap_member" for row in fixture.events)


def test_connected_parent_records_unknown_if_subreaper_restore_fails(
    simulated_session, monkeypatch
):
    fixture = simulated_session
    original = bridge_module.subreaper

    def fail_restore(value=None):
        if value == 0:
            raise OSError("simulated restore refusal")
        return original(value)

    monkeypatch.setattr(bridge_module, "subreaper", fail_restore)
    with pytest.raises(RuntimeError, match="cleanup is unknown"):
        with fixture.owner:
            pass
    assert fixture.records[0][1]["cleanup"] == "unknown"
    assert fixture.records[0][1]["live_owned_members"] is None
    assert fixture.records[0][1]["native_reaped"] is True
    assert fixture.records[0][1]["subreaper_restored"] is False
    assert fixture.owner.locked is False


def test_connected_parent_inventory_is_finitely_bounded(simulated_session, monkeypatch):
    fixture = simulated_session
    fixture.identities[200] = (200, 20, 200, 200)
    fixture.identities[201] = (201, 21, 201, 201)

    class Inventory:
        def __enter__(self):
            return iter(
                SimpleNamespace(name=str(pid), stat=lambda **kwargs: SimpleNamespace(st_uid=42))
                for pid in (100, 200, 201)
            )

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(bridge_module.os, "scandir", lambda path: Inventory(), raising=False)
    monkeypatch.setattr(bridge_module.os, "getuid", lambda: 42, raising=False)
    monkeypatch.setattr(bridge_module, "MAX_PROCESSES", 2)
    with pytest.raises(RuntimeError, match="inventory exceeded finite bound"):
        bridge_module.OwnedSession.members(fixture.owner, bridge_module.time.monotonic() + 2)
    assert not any(row[0] in {"signal", "reap_member", "reap_native"} for row in fixture.events)
