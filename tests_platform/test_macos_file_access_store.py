"""Owner SQLite and normal control flow with a fixed fake private transport."""

import sqlite3
from copy import deepcopy
from threading import Event
from types import SimpleNamespace

import pytest

from bluefire import file_access_context
from bluefire import macos_file_access_bridge as bridge
from bluefire import macos_file_access_clock as clock
from bluefire import macos_file_access_control as macos_control
from bluefire import product_store_macos_file_access as macos
from bluefire.execution_contracts import execution_task_identity
from bluefire.file_access_control import FileAccessControl
from bluefire.macos_file_access_contract import REQUEST_SCHEMA
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_macos_file_access_contract import binding, observation


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    store = ProductStore(tmp_path / "owner.db")
    initial = binding()
    state = {
        "binding": deepcopy(initial),
        "phase": "created",
        "calls": [],
        "budget": 0,
        "counter": 0,
        "run": 0,
        "failure": None,
        "lost": False,
        "corrupt": None,
        "monotonic": 1000,
        "sequence": {"reader": 0, "owner": 0, "control": 0},
    }

    class Endpoint:
        def assert_current(self):
            if state["lost"]:
                raise OSError("fake lost original custody")
            return 1.0

        def current_setup(self):
            self.assert_current()
            return {"schema_version": macos.SETUP_SCHEMA, "binding": deepcopy(initial)}

        def review_context(self, operation):
            self.assert_current()
            body = {
                "schema_version": "bluefire.macos-file-access-creator-context.v1",
                "operation": operation,
                "state": state["phase"],
                "binding": deepcopy(state["binding"]),
                "probe_digest": None,
            }
            return {**body, "context_digest": content_hash(body)}

    selected = Endpoint()
    monkeypatch.setattr(macos_control, "endpoint", lambda _service: selected)
    monkeypatch.setattr(file_access_context, "is_macos_host", lambda: True)
    monkeypatch.setattr(clock, "darwin_clock_ns", lambda: state["monotonic"])

    def run_id():
        state["run"] += 1
        return "run-fake-" + str(state["run"])

    service = SimpleNamespace(product_store=store, store=SimpleNamespace(_new_run_id=run_id))
    control = FileAccessControl(service, clock=lambda: 1000)

    class Jobs:
        def submit(self, _kind, _request, *, submission_factory, callback, **_options):
            job, _created = submission_factory()
            store.transition_job(job["job_id"], "planning")
            store.transition_job(job["job_id"], "running")
            cancellation = Event()

            def checkpoint():
                if cancellation.is_set():
                    raise ProductStoreError("fake cancelled")

            ctx = SimpleNamespace(
                job_id=job["job_id"], cancellation_event=cancellation, checkpoint=checkpoint
            )
            try:
                callback(ctx, None)
            except BaseException:
                store.transition_job(job["job_id"], "failed")
                raise
            store.transition_job(job["job_id"], "completed")

    service.job_controller = Jobs()

    class Transport:
        def __init__(self, endpoint, journal):
            assert endpoint is selected and journal is store

        def execute_task(self, manifest, profile, *, task_id, cancel_event):
            assert not cancel_event.is_set()
            transport_hash = execution_task_identity(manifest, profile)[1]
            # A separate SQLite connection sees the committed claim before the
            # fake transport attempts its dispatch marker or any primitive.
            with sqlite3.connect(store.path) as independent:
                assert independent.execute(
                    "SELECT 1 FROM file_access_task_claims WHERE task_id=?", (task_id,)
                ).fetchone()
            if state["failure"] == "before_marker":
                raise OSError("fake refusal before dispatch")
            frame = store.begin_macos_file_access_dispatch(
                task_id,
                transport_hash,
                now_ms=6000 if state["failure"] == "expiry_equality" else 1000,
            )
            with sqlite3.connect(store.path) as independent:
                assert independent.execute(
                    "SELECT 1 FROM file_access_task_evidence WHERE task_id=? AND stage='macos_dispatch'",
                    (task_id,),
                ).fetchone()
            if state["failure"] == "after_marker":
                state["lost"] = True
                raise OSError("fake lost dispatch response")
            op = frame["intent"]["operation"]
            state["calls"].append(op)
            before = state["binding"]["control_revision"]
            rows, terminals = [], []
            for primitive in macos.PLANS[op]:
                role = (
                    "control"
                    if primitive in ("harden", "rollback")
                    else "reader" if primitive == "read_reader" else "owner"
                )
                state["sequence"][role] += 1
                state["budget"] += 1
                request = {
                    "schema_version": REQUEST_SCHEMA,
                    "binding": deepcopy(state["binding"]),
                    "binding_digest": content_hash(state["binding"]),
                    "request_id": f"{state['budget']:064x}",
                    "sequence": state["sequence"][role],
                    "operation": primitive,
                    **{
                        key: frame["intent"][key]
                        for key in (
                            "issued_at_ms",
                            "expires_at_ms",
                            "issued_monotonic_ns",
                            "deadline_ns",
                        )
                    },
                }
                terminal = observation(request)
                terminal["fresh_read"]["mode"] = request["binding"]["mode"]
                if role != "reader":
                    terminal["principal"] = request["binding"]["owner"]
                if role == "control":
                    target = "0600" if primitive == "harden" else "0640"
                    terminal.update(
                        outcome="mode_changed",
                        fresh_read=None,
                        request_handle_cleanup="not_opened",
                        held_control={
                            **{
                                key: request["binding"]["resource"][key]
                                for key in (
                                    "device",
                                    "inode",
                                    "size_bytes",
                                    "record_count",
                                    "sha256",
                                )
                            },
                            "before_mode": request["binding"]["mode"],
                            "after_mode": target,
                        },
                    )
                    state["binding"]["mode"] = target
                    state["binding"]["control_revision"] += 1
                rows.append(
                    {
                        "request_id": request["request_id"],
                        "sequence": request["sequence"],
                        "operation": primitive,
                        "request_digest": content_hash(request),
                    }
                )
                terminals.append(terminal)
            if op == "baseline":
                state["binding"]["control_revision"] += 1
            state["phase"] = {
                "baseline": "baseline_verified",
                "harden": "hardened",
                "rollback": "rolled_back",
            }[op]
            receipt = {
                "schema_version": "bluefire.macos-file-access-task-receipt.v1",
                **{
                    key: frame["intent"][key]
                    for key in (
                        "task_id",
                        "transport_request_hash",
                        "context_digest",
                        "binding_digest",
                        "operation",
                    )
                },
                "state": "complete",
                "dispatch": "attempted",
                "producer_request_usage": "settled",
                "settlement_scope": "producer_local_only",
                "original_workers": "retained",
                "namespace": "original_creator_held",
                "whole_enrollment_cleanup": False,
                "control_revision_before": before,
                "control_revision_after": state["binding"]["control_revision"],
                "requests": rows,
                "terminals": terminals,
                "shared_request_budget_used": state["budget"],
            }
            if state["corrupt"] == "reader_denied":
                terminals[0].update(
                    outcome="denied", fresh_read=None, request_handle_cleanup="not_opened"
                )
            if state["failure"] == "cancel_after_response":
                cancel_event.set()
            return {
                "schema_version": "bluefire.runner-result.v1",
                "status": "success",
                "request_hash": manifest["request_hash"],
                "output": {"macos_receipt": receipt},
                "artifacts": {},
                "receipt_ids": [],
                "telemetry": [],
                "error": None,
            }

    monkeypatch.setattr(bridge, "MacOSWorkspaceTaskTransport", Transport)
    setup = selected.current_setup()
    imported = control.import_setup(
        {
            "enrollment_id": initial["enrollment_id"],
            "enrollment_digest": content_hash(macos.enrollment_document(setup)),
        }
    )

    def submit(operation):
        state["counter"] += 1
        review = control.review(
            {"operation": operation, "control_owner_id": imported["control_owner_id"]}
        )
        request = {
            "submission_id": f"{state['counter']:08x}-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "review": {"operation": operation, "control_owner_id": imported["control_owner_id"]},
            "review_digest": review["review_digest"],
            "reviewed_by": "Fake operator",
        }
        return control.submit(request), request

    return SimpleNamespace(
        store=store, control=control, state=state, imported=imported, submit=submit, service=service
    )


def test_normal_control_lifecycle_commits_before_dispatch_and_never_replays(workspace):
    status = workspace.control.status()
    assert status["platform"] == "macos" and status["available"] is True
    for operation, mode, revision in (
        ("baseline", "0640", 2),
        ("harden", "0600", 3),
        ("rollback", "0640", 4),
    ):
        result, request = workspace.submit(operation)
        assert result["control"]["revision"] == revision
        assert result["control"]["resource"]["mode"] == mode
        count = len(workspace.state["calls"])
        assert workspace.control.submit(request)["job"]["job_id"] == result["job"]["job_id"]
        assert len(workspace.state["calls"]) == count
        records = workspace.store.file_access_operation_records(result["job"]["job_id"])
        assert records["outcome"]["state"] == "complete"
        receipt = records["tasks"][0]["terminal"]["result"]["output"]["macos_receipt"]
        assert (
            receipt["settlement_scope"] == "producer_local_only"
            and not receipt["whole_enrollment_cleanup"]
        )
    assert workspace.state["calls"] == ["baseline", "harden", "rollback"]
    assert workspace.state["budget"] == 6
    assert "reset" not in result["control"]["allowed_operations"]


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("before_marker", "refused_no_effect"),
        ("expiry_equality", "refused_no_effect"),
        ("after_marker", "unknown"),
    ],
)
def test_dispatch_ambiguity_is_durable_and_reopening_cannot_adopt(workspace, failure, expected):
    workspace.state["failure"] = failure
    with pytest.raises((OSError, ProductStoreError)):
        workspace.submit("baseline")
    job = workspace.store.list_jobs()[0]
    reopened = ProductStore(workspace.store.path)
    records = reopened.file_access_operation_records(job["job_id"])
    assert records["outcome"]["state"] == expected
    assert macos.has_dispatch(reopened, job["job_id"]) is (failure == "after_marker")
    claim = records["tasks"][0]["task"]
    with pytest.raises(ProductStoreError):
        reopened.begin_macos_file_access_dispatch(
            claim["task_id"], claim["transport_request_hash"], now_ms=1000
        )
    assert workspace.state["calls"] == []


@pytest.mark.parametrize("failure", ["reader_denied", "cancel_after_response"])
def test_wrong_baseline_or_cancellation_never_publishes_success(workspace, failure):
    if failure == "reader_denied":
        workspace.state["corrupt"] = failure
    else:
        workspace.state["failure"] = failure
    with pytest.raises(ProductStoreError):
        workspace.submit("baseline")
    job = workspace.store.list_jobs()[0]
    records = workspace.store.file_access_operation_records(job["job_id"])
    assert records["outcome"]["state"] == "unknown"
    retained = workspace.store.get_file_access_control(workspace.imported["control_owner_id"])
    assert retained["document"]["revision"] == 1 and retained["pending_operation"]
    assert (
        workspace.control.control(workspace.imported["control_owner_id"])["allowed_operations"]
        == []
    )


def test_original_terminal_and_closure_are_immutable(workspace):
    result, _ = workspace.submit("baseline")
    records = workspace.store.file_access_operation_records(result["job"]["job_id"])
    claim, terminal = records["tasks"][0]["task"], records["tasks"][0]["terminal"]
    wrong = deepcopy(terminal["result"])
    wrong["output"]["macos_receipt"]["terminals"][0]["principal"]["saved_uid"] = 503
    with pytest.raises(ValueError):
        workspace.store.record_file_access_task_terminal(
            claim["task_id"], request_hash=claim["request_hash"], result=wrong
        )
    with pytest.raises(ProductStoreError):
        workspace.store.record_file_access_worker_closure(
            claim["task_id"],
            request_hash=claim["request_hash"],
            proof={
                "state": "verified_closed",
                "binding_digest": "sha256:" + "0" * 64,
                "evidence_digest": content_hash(terminal["result"]),
            },
        )


def test_transport_hash_and_cross_platform_preparation_cannot_be_substituted(workspace):
    result, _ = workspace.submit("baseline")
    records = workspace.store.file_access_operation_records(result["job"]["job_id"])
    claim = records["tasks"][0]["task"]
    assert claim["request_hash"] != claim["transport_request_hash"]
    with pytest.raises(ProductStoreError):
        workspace.store.file_access_task_record(claim["task_id"], claim["request_hash"])
    with pytest.raises(ProductStoreError):
        workspace.control.review(
            {"operation": "reset", "control_owner_id": workspace.imported["control_owner_id"]}
        )


@pytest.mark.parametrize("write", ["terminal", "closure", "revision"])
def test_original_monotonic_expiry_during_journal_writes_cannot_commit_success(
    workspace, monkeypatch, write
):
    delayed = []

    def expire(job_id):
        prepared = workspace.store.file_access_preparation(job_id)["document"]
        workspace.state["monotonic"] = prepared["deadline_ns"]
        delayed.append(prepared)

    if write in ("terminal", "closure"):
        name = (
            "record_file_access_task_terminal"
            if write == "terminal"
            else "record_file_access_worker_closure"
        )
        original = getattr(workspace.store, name)

        def late_write(task_id, **options):
            result = original(task_id, **options)
            job_id = workspace.store.list_jobs()[0]["job_id"]
            prepared = workspace.store.file_access_preparation(job_id)["document"]
            assert (
                execution_task_identity(prepared["manifest"], prepared["runner_profile"])[0]
                == task_id
            )
            expire(job_id)
            return result

        monkeypatch.setattr(workspace.store, name, late_write)
    else:
        original_finish = workspace.store.finish_file_access_operation
        canonical = macos.canonical_json
        active = {}

        def finish(job_id, **options):
            if options["outcome"]["state"] == "complete":
                active["prepared"] = workspace.store.file_access_preparation(job_id)["document"]
            try:
                return original_finish(job_id, **options)
            finally:
                active.clear()

        def slow_revision(document):
            if active and document.get("schema_version") == macos.CONTROL_SCHEMA:
                prepared = active["prepared"]
                workspace.state["monotonic"] = prepared["deadline_ns"]
                delayed.append(prepared)
            return canonical(document)

        monkeypatch.setattr(workspace.store, "finish_file_access_operation", finish)
        monkeypatch.setattr(macos, "canonical_json", slow_revision)

    with pytest.raises(ProductStoreError):
        workspace.submit("baseline")
    job = workspace.store.list_jobs()[0]
    records = workspace.store.file_access_operation_records(job["job_id"])
    assert delayed and workspace.control.clock() == 1000
    assert workspace.state["monotonic"] == delayed[0]["deadline_ns"]
    assert records["outcome"]["state"] == "unknown" and macos.has_dispatch(
        workspace.store, job["job_id"]
    )
    retained = workspace.store.get_file_access_control(workspace.imported["control_owner_id"])
    assert retained["document"]["revision"] == 1 and retained["pending_operation"]
    view = workspace.control.operation(job["job_id"])
    assert view["reconciliation"]["state"] == "unknown" and not view["reconciliation"]["available"]
    assert view["control"]["allowed_operations"] == []
    assert workspace.state["calls"] == ["baseline"]


def test_unknown_darwin_reconciliation_is_read_only_and_not_advertised(workspace):
    workspace.state["failure"] = "after_marker"
    with pytest.raises(OSError):
        workspace.submit("baseline")
    status = workspace.control.status()
    assert status["platform"] == "macos" and status["available"] is False
    job_id = workspace.store.list_jobs()[0]["job_id"]
    view = workspace.control.operation(job_id)
    assert view["reconciliation"]["state"] == "unknown"
    assert view["reconciliation"]["available"] is False
    assert view["control"]["allowed_operations"] == []
    with pytest.raises(ProductStoreError, match="read-only"):
        workspace.control.reconcile(job_id, {})
    assert workspace.state["calls"] == []
